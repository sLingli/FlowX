use std::collections::VecDeque;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant as SmolInstant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::outbound::RelayStream;

use super::packet::{EmittedIpPacket, OutboundTcpQueueItem, PacketInterfaceMeta};

pub(super) const BRIDGE_BUFFER_LIMIT: usize = 512 * 1024;

/// 跨 Async Tokio 任务与 `NetstackEngine` 工作线程的唤醒信箱（零轮询低延迟）
pub struct NetstackSignal {
    state: Mutex<SignalState>,
    cv: Condvar,
}

#[derive(Default)]
struct SignalState {
    outbound_tcp: VecDeque<OutboundTcpQueueItem>,
    closed_tcp_endpoints: VecDeque<(IpAddr, u16)>,
    pump_needed: bool,
    closed: bool,
}

impl Default for NetstackSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl NetstackSignal {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(SignalState::default()),
            cv: Condvar::new(),
        }
    }

    pub fn push_outbound_tcp(&self, raw_ip: Vec<u8>, meta: PacketInterfaceMeta, pid: Option<u32>) {
        self.push_outbound_tcp_with_fragments(raw_ip, meta, pid, None);
    }

    pub fn push_outbound_tcp_with_fragments(
        &self,
        raw_ip: Vec<u8>,
        meta: PacketInterfaceMeta,
        pid: Option<u32>,
        orig_fragments: Option<Vec<EmittedIpPacket>>,
    ) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if guard.closed {
            return;
        }
        guard.outbound_tcp.push_back(OutboundTcpQueueItem {
            raw_ip,
            meta,
            pid,
            orig_fragments,
        });
        self.cv.notify_one();
    }

    /// 通知协议栈线程某个本地 TCP 端点已关闭，用于立即清理可能因端口复用失效的旁路缓存
    pub fn push_closed_tcp_endpoint(&self, local_ip: IpAddr, local_port: u16) {
        if local_port == 0 {
            return;
        }
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if guard.closed {
            return;
        }
        guard
            .closed_tcp_endpoints
            .push_back((local_ip.to_canonical(), local_port));
        self.cv.notify_one();
    }

    #[inline]
    pub fn wake_pump(&self) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.pump_needed = true;
        self.cv.notify_one();
    }

    pub fn close(&self) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.closed = true;
        self.cv.notify_all();
    }

    /// 供工作线程等待下一批报文、端点关闭通知或异步写事件（最多阻塞 `max_wait` 以便推进 smoltcp 定时器）
    pub fn wait_drain_or_timeout(
        &self,
        max_wait: Duration,
        out_packets: &mut Vec<OutboundTcpQueueItem>,
        out_closed_endpoints: &mut Vec<(IpAddr, u16)>,
    ) -> bool {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if guard.outbound_tcp.is_empty()
            && guard.closed_tcp_endpoints.is_empty()
            && !guard.pump_needed
            && !guard.closed
        {
            let (new_guard, _) = self
                .cv
                .wait_timeout(guard, max_wait)
                .unwrap_or_else(|e| e.into_inner());
            guard = new_guard;
        }
        guard.pump_needed = false;
        while let Some(item) = guard.outbound_tcp.pop_front() {
            out_packets.push(item);
        }
        while let Some(ep) = guard.closed_tcp_endpoints.pop_front() {
            out_closed_endpoints.push(ep);
        }
        !guard.closed
    }
}

pub(super) struct BridgeInner {
    pub(super) to_app: VecDeque<u8>,
    pub(super) to_socket: VecDeque<u8>,
    pub(super) socket_eof_to_app: bool,
    pub(super) socket_errored: bool,
    pub(super) socket_closed: bool,
    pub(super) app_read_closed: bool,
    pub(super) app_write_closed: bool,
    pub(super) write_half_dropped: bool,
    pub(super) graceful_shutdown: bool,
    pub(super) fin_sent_to_socket: bool,
    pub(super) read_waker: Option<Waker>,
    pub(super) write_waker: Option<Waker>,
    pub(super) flush_waker: Option<Waker>,
}

impl Default for BridgeInner {
    fn default() -> Self {
        Self {
            to_app: VecDeque::with_capacity(4096),
            to_socket: VecDeque::with_capacity(4096),
            socket_eof_to_app: false,
            socket_errored: false,
            socket_closed: false,
            app_read_closed: false,
            app_write_closed: false,
            write_half_dropped: false,
            graceful_shutdown: false,
            fin_sent_to_socket: false,
            read_waker: None,
            write_waker: None,
            flush_waker: None,
        }
    }
}

fn take_all_wakers(
    inner: &mut BridgeInner,
    wake_read: &mut Option<Waker>,
    wake_write: &mut Option<Waker>,
    wake_flush: &mut Option<Waker>,
) {
    if wake_read.is_none() {
        *wake_read = inner.read_waker.take();
    }
    if wake_write.is_none() {
        *wake_write = inner.write_waker.take();
    }
    if wake_flush.is_none() {
        *wake_flush = inner.flush_waker.take();
    }
}

pub(super) fn close_bridge_and_collect_wakers(
    inner: &mut BridgeInner,
    errored: bool,
    wake_read: &mut Option<Waker>,
    wake_write: &mut Option<Waker>,
    wake_flush: &mut Option<Waker>,
) {
    if errored {
        inner.to_socket.clear();
        inner.socket_errored = true;
    }
    inner.socket_closed = true;
    inner.socket_eof_to_app = true;
    take_all_wakers(inner, wake_read, wake_write, wake_flush);
}

pub(super) struct SmoltcpBridge {
    pub(super) inner: Mutex<BridgeInner>,
    signal: Arc<NetstackSignal>,
}

impl SmoltcpBridge {
    pub(super) fn new(signal: Arc<NetstackSignal>) -> Self {
        Self {
            inner: Mutex::new(BridgeInner::default()),
            signal,
        }
    }
}

/// 面向 Dispatcher 的全双工用户态 TCP 流（支持独立读/写半关闭）
pub struct SmoltcpStream {
    pub(super) read: SmoltcpReadHalf,
    pub(super) write: SmoltcpWriteHalf,
}

impl SmoltcpStream {
    pub(super) fn from_bridge(bridge: Arc<SmoltcpBridge>) -> Self {
        Self {
            read: SmoltcpReadHalf {
                bridge: Arc::clone(&bridge),
            },
            write: SmoltcpWriteHalf { bridge },
        }
    }
}

pub struct SmoltcpReadHalf {
    pub(super) bridge: Arc<SmoltcpBridge>,
}

pub struct SmoltcpWriteHalf {
    pub(super) bridge: Arc<SmoltcpBridge>,
}

impl Drop for SmoltcpReadHalf {
    fn drop(&mut self) {
        {
            let mut inner = self.bridge.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.app_read_closed = true;
            inner.to_app.clear();
            inner.read_waker = None;
        }
        self.bridge.signal.wake_pump();
    }
}

impl Drop for SmoltcpWriteHalf {
    fn drop(&mut self) {
        {
            let mut inner = self.bridge.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.app_write_closed = true;
            inner.write_half_dropped = true;
            inner.write_waker = None;
            inner.flush_waker = None;
        }
        self.bridge.signal.wake_pump();
    }
}

impl AsyncRead for SmoltcpReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let mut wake_netstack = false;
        let res = {
            let mut inner = self.bridge.inner.lock().unwrap_or_else(|e| e.into_inner());
            if !inner.to_app.is_empty() {
                let to_copy = buf.remaining().min(inner.to_app.len());
                let (head, tail) = inner.to_app.as_slices();
                if to_copy <= head.len() {
                    buf.put_slice(&head[..to_copy]);
                } else {
                    buf.put_slice(head);
                    let rem = to_copy - head.len();
                    buf.put_slice(&tail[..rem]);
                }
                inner.to_app.drain(..to_copy);
                if inner.to_app.len() < BRIDGE_BUFFER_LIMIT / 2 {
                    wake_netstack = true;
                }
                Poll::Ready(Ok(()))
            } else if inner.socket_errored {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Transparent TCP connection reset by local peer",
                )))
            } else if inner.socket_eof_to_app || inner.socket_closed {
                Poll::Ready(Ok(()))
            } else {
                inner.read_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        };

        if wake_netstack {
            self.bridge.signal.wake_pump();
        }
        res
    }
}

impl AsyncWrite for SmoltcpWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let res = {
            let mut inner = self.bridge.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.socket_errored {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Transparent TCP connection reset during write",
                )));
            }
            if inner.socket_closed || inner.app_write_closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Transparent TCP write half already closed",
                )));
            }
            let avail = BRIDGE_BUFFER_LIMIT.saturating_sub(inner.to_socket.len());
            if avail == 0 {
                inner.write_waker = Some(cx.waker().clone());
                Poll::Pending
            } else {
                let n = buf.len().min(avail);
                inner.to_socket.extend(&buf[..n]);
                Poll::Ready(Ok(n))
            }
        };

        self.bridge.signal.wake_pump();
        res
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.bridge.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.socket_errored {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "Transparent TCP connection reset during flush",
            )));
        }
        if inner.to_socket.is_empty() {
            return Poll::Ready(Ok(()));
        }
        if inner.socket_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Transparent TCP connection closed before flush completed",
            )));
        }
        inner.flush_waker = Some(cx.waker().clone());
        drop(inner);
        self.bridge.signal.wake_pump();
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let wake_now = {
            let mut inner = self.bridge.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.app_write_closed = true;
            if inner.socket_errored {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Transparent TCP connection reset during shutdown",
                )));
            }
            if inner.to_socket.is_empty() && (inner.fin_sent_to_socket || inner.socket_closed) {
                // 仅在写缓冲已完全排空且 FIN 已送入协议栈（或连接已关闭）时才标记 graceful_shutdown，
                // 避免缓冲非空时 future 被取消并丢弃句柄后跳过 sock.abort() 导致槽位永久泄漏
                inner.graceful_shutdown = true;
                return Poll::Ready(Ok(()));
            }
            if inner.socket_closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Transparent TCP connection closed before shutdown completed",
                )));
            }
            inner.flush_waker = Some(cx.waker().clone());
            true
        };
        if wake_now {
            self.bridge.signal.wake_pump();
        }
        Poll::Pending
    }
}

impl AsyncRead for SmoltcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, buf)
    }
}

impl AsyncWrite for SmoltcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.write).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write).poll_shutdown(cx)
    }
}

impl RelayStream for SmoltcpStream {
    type ReadHalf = SmoltcpReadHalf;
    type WriteHalf = SmoltcpWriteHalf;

    fn split_stream(self) -> (Self::ReadHalf, Self::WriteHalf) {
        (self.read, self.write)
    }
}

/// 纯 L3 虚拟网卡实现，通过 `Checksum::Tx` 豁免 Windows TX 校验和卸载的入站包校验同时由 smoltcp 自动计算发往本机的校验和
pub(super) struct VirtualIpDevice {
    pub(super) rx_queue: VecDeque<Vec<u8>>,
    pub(super) tx_queue: VecDeque<Vec<u8>>,
}

impl VirtualIpDevice {
    pub(super) fn new() -> Self {
        Self {
            rx_queue: VecDeque::with_capacity(256),
            tx_queue: VecDeque::with_capacity(256),
        }
    }
}

pub(super) struct VirtualRxToken(Vec<u8>);

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

pub(super) struct VirtualTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let res = f(&mut buf);
        self.0.push_back(buf);
        res
    }
}

impl Device for VirtualIpDevice {
    type RxToken<'a>
        = VirtualRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = VirtualTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx_queue.pop_front()?;
        Some((VirtualRxToken(pkt), VirtualTxToken(&mut self.tx_queue)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken(&mut self.tx_queue))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps.checksum.ipv4 = Checksum::Tx;
        caps.checksum.udp = Checksum::Tx;
        caps.checksum.tcp = Checksum::Tx;
        caps.checksum.icmpv4 = Checksum::Tx;
        caps.checksum.icmpv6 = Checksum::Tx;
        caps
    }
}
