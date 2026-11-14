use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TcpHeader, TransportSlice};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{self, SocketBuffer};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpListenEndpoint, Ipv4Address, Ipv6Address};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::dns::FakeIpPool;
use crate::interceptor::process::ProcessTracker;
use crate::outbound::bypass::is_tcp_port_bypassed;
use crate::outbound::RelayStream;
use crate::router::{Action, DomainNeedDecision, RuleEngine};

const BRIDGE_BUFFER_LIMIT: usize = 512 * 1024;
const SMOLTCP_RX_BUF: usize = 128 * 1024;
const SMOLTCP_TX_BUF: usize = 128 * 1024;
const MAX_INTERCEPTED_FLOWS: usize = 4096;
const MAX_PASSTHROUGH_FLOWS: usize = 16_384;
const PASSTHROUGH_TTL: Duration = Duration::from_secs(120);
const SYN_RECEIVED_TIMEOUT: Duration = Duration::from_secs(15);

/// 网络接口路由元数据，确保通过 WinDivert 注回本机时使用与原出站包一致的接口索引及卸载标志
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PacketInterfaceMeta {
    pub if_idx: u32,
    pub sub_if_idx: u32,
    pub loopback: bool,
    pub is_ipv6: bool,
    pub bitfield: u32,
}

/// 待由宿主注入回 Windows 网络栈的原始 IP 报文及其接口目标元数据
#[derive(Debug, Clone)]
pub struct EmittedIpPacket {
    pub data: Vec<u8>,
    pub meta: PacketInterfaceMeta,
}

/// TCP 四元组标准化键（IP 统一规范化）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpFlowKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl TcpFlowKey {
    pub fn new(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        Self {
            src_ip: src_ip.to_canonical(),
            src_port,
            dst_ip: dst_ip.to_canonical(),
            dst_port,
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::new(self.src_ip, self.src_port)
    }

    pub fn orig_dst(&self) -> SocketAddr {
        SocketAddr::new(self.dst_ip, self.dst_port)
    }
}

/// 解析后的出站 TCP 原始 IP 报文关键字段
#[derive(Debug, Clone, Copy)]
pub struct ParsedTcpPacket {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack_num: u32,
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub payload_len: usize,
    pub is_ipv6: bool,
}

impl ParsedTcpPacket {
    pub fn flow_key(&self) -> TcpFlowKey {
        TcpFlowKey::new(self.src_ip, self.src_port, self.dst_ip, self.dst_port)
    }
}

/// 解析原始 IPv4/IPv6 TCP 报文；自动忽略分片报文与非 TCP 报文
pub fn parse_tcp_packet(raw_ip: &[u8]) -> Option<ParsedTcpPacket> {
    let sliced = SlicedPacket::from_ip(raw_ip).ok()?;
    let (src_ip, dst_ip, is_ipv6) = match sliced.net? {
        NetSlice::Ipv4(ipv4) => {
            if ipv4.is_payload_fragmented() {
                return None;
            }
            let hdr = ipv4.header();
            (
                IpAddr::V4(hdr.source_addr()),
                IpAddr::V4(hdr.destination_addr()),
                false,
            )
        }
        NetSlice::Ipv6(ipv6) => {
            if ipv6.is_payload_fragmented() {
                return None;
            }
            let hdr = ipv6.header();
            (
                IpAddr::V6(hdr.source_addr()),
                IpAddr::V6(hdr.destination_addr()),
                true,
            )
        }
        _ => return None,
    };

    let TransportSlice::Tcp(tcp) = sliced.transport? else {
        return None;
    };

    Some(ParsedTcpPacket {
        src_ip: src_ip.to_canonical(),
        dst_ip: dst_ip.to_canonical(),
        src_port: tcp.source_port(),
        dst_port: tcp.destination_port(),
        seq: tcp.sequence_number(),
        ack_num: tcp.acknowledgment_number(),
        syn: tcp.syn(),
        ack: tcp.ack(),
        fin: tcp.fin(),
        rst: tcp.rst(),
        payload_len: tcp.payload().len(),
        is_ipv6,
    })
}

/// 当规则立即命中 `Action::Block` 时，为本地 SYN 或数据包构造合法 RFC 793 `RST/ACK` 以秒级通知应用拒绝连接
pub fn build_synthetic_tcp_rst(raw_ip: &[u8]) -> Option<Vec<u8>> {
    let pkt = parse_tcp_packet(raw_ip)?;
    if pkt.rst {
        return None;
    }

    let mut hdr = if pkt.ack {
        let mut h = TcpHeader::new(pkt.dst_port, pkt.src_port, pkt.ack_num, 0);
        h.rst = true;
        h
    } else {
        let ack_target = pkt
            .seq
            .wrapping_add(if pkt.syn || pkt.fin { 1 } else { 0 })
            .wrapping_add(pkt.payload_len as u32);
        let mut h = TcpHeader::new(pkt.dst_port, pkt.src_port, 0, 0);
        h.rst = true;
        h.ack = true;
        h.acknowledgment_number = ack_target;
        h
    };
    hdr.window_size = 0;

    match (pkt.dst_ip, pkt.src_ip) {
        (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => {
            let builder = PacketBuilder::ipv4(src_v4.octets(), dst_v4.octets(), 64).tcp_header(hdr);
            let mut out = Vec::with_capacity(builder.size(0));
            builder.write(&mut out, &[]).ok()?;
            Some(out)
        }
        (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => {
            let builder = PacketBuilder::ipv6(src_v6.octets(), dst_v6.octets(), 64).tcp_header(hdr);
            let mut out = Vec::with_capacity(builder.size(0));
            builder.write(&mut out, &[]).ok()?;
            Some(out)
        }
        _ => None,
    }
}

/// 跨 Async Tokio 任务与 `NetstackEngine` 工作线程的唤醒信箱（零轮询低延迟）
pub struct NetstackSignal {
    state: Mutex<SignalState>,
    cv: Condvar,
}

#[derive(Default)]
struct SignalState {
    outbound_tcp: VecDeque<(Vec<u8>, PacketInterfaceMeta, Option<u32>)>,
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

    pub fn push_outbound_tcp(
        &self,
        raw_ip: Vec<u8>,
        meta: PacketInterfaceMeta,
        pid: Option<u32>,
    ) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if guard.closed {
            return;
        }
        guard.outbound_tcp.push_back((raw_ip, meta, pid));
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

    /// 供工作线程等待下一批报文或异步写事件（最多阻塞 `max_wait` 以便推进 smoltcp 定时器）
    pub fn wait_drain_or_timeout(
        &self,
        max_wait: Duration,
        out_packets: &mut Vec<(Vec<u8>, PacketInterfaceMeta, Option<u32>)>,
    ) -> bool {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if guard.outbound_tcp.is_empty() && !guard.pump_needed && !guard.closed {
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
        !guard.closed
    }
}

struct BridgeInner {
    to_app: VecDeque<u8>,
    to_socket: VecDeque<u8>,
    socket_eof_to_app: bool,
    socket_errored: bool,
    app_read_closed: bool,
    app_write_closed: bool,
    fin_sent_to_socket: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    flush_waker: Option<Waker>,
}

impl Default for BridgeInner {
    fn default() -> Self {
        Self {
            to_app: VecDeque::with_capacity(4096),
            to_socket: VecDeque::with_capacity(4096),
            socket_eof_to_app: false,
            socket_errored: false,
            app_read_closed: false,
            app_write_closed: false,
            fin_sent_to_socket: false,
            read_waker: None,
            write_waker: None,
            flush_waker: None,
        }
    }
}

struct SmoltcpBridge {
    inner: Mutex<BridgeInner>,
    signal: Arc<NetstackSignal>,
}

impl SmoltcpBridge {
    fn new(signal: Arc<NetstackSignal>) -> Self {
        Self {
            inner: Mutex::new(BridgeInner::default()),
            signal,
        }
    }
}

/// 面向 Dispatcher 的全双工用户态 TCP 流（支持独立读/写半关闭）
pub struct SmoltcpStream {
    read: SmoltcpReadHalf,
    write: SmoltcpWriteHalf,
}

impl SmoltcpStream {
    fn from_bridge(bridge: Arc<SmoltcpBridge>) -> Self {
        Self {
            read: SmoltcpReadHalf {
                bridge: Arc::clone(&bridge),
            },
            write: SmoltcpWriteHalf { bridge },
        }
    }
}

pub struct SmoltcpReadHalf {
    bridge: Arc<SmoltcpBridge>,
}

pub struct SmoltcpWriteHalf {
    bridge: Arc<SmoltcpBridge>,
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
            } else if inner.socket_eof_to_app {
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
            if inner.app_write_closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Transparent TCP write half already shut down",
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
        inner.flush_waker = Some(cx.waker().clone());
        drop(inner);
        self.bridge.signal.wake_pump();
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let wake_now = {
            let mut inner = self.bridge.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.app_write_closed = true;
            if inner.socket_errored || (inner.to_socket.is_empty() && inner.fin_sent_to_socket) {
                return Poll::Ready(Ok(()));
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
struct VirtualIpDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
}

impl VirtualIpDevice {
    fn new() -> Self {
        Self {
            rx_queue: VecDeque::with_capacity(256),
            tx_queue: VecDeque::with_capacity(256),
        }
    }
}

struct VirtualRxToken(Vec<u8>);

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct VirtualTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

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
    type RxToken<'a> = VirtualRxToken where Self: 'a;
    type TxToken<'a> = VirtualTxToken<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
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

/// 已进入 `smoltcp` 的新连接上下文，交由异步调度器执行域名嗅探或直连/代理转发
pub struct AcceptedTcpFlow {
    pub stream: SmoltcpStream,
    pub peer_addr: SocketAddr,
    pub orig_dst: SocketAddr,
    pub pid_hint: Option<u32>,
    pub needs_domain_sniff: bool,
}

#[derive(Debug)]
pub enum TcpIngestOutcome {
    Intercepted,
    Passthrough(EmittedIpPacket),
    InjectRst(EmittedIpPacket),
}

struct InterceptedSession {
    handle: SocketHandle,
    bridge: Arc<SmoltcpBridge>,
    meta: PacketInterfaceMeta,
    created_at: Instant,
    ever_established: bool,
}

/// 单所有权用户态 TCP/IP 协议栈引擎：负责四元组流分拣、孤立 Listen 握手防碰撞、双向缓冲泵送及异常连接清理
pub struct NetstackEngine {
    iface: Interface,
    device: VirtualIpDevice,
    sockets: SocketSet<'static>,
    intercepted: HashMap<TcpFlowKey, InterceptedSession>,
    passthrough: HashMap<TcpFlowKey, Instant>,
    signal: Arc<NetstackSignal>,
    start_instant: Instant,
    last_prune: Instant,
}

impl NetstackEngine {
    pub fn new(signal: Arc<NetstackSignal>) -> Self {
        let mut device = VirtualIpDevice::new();
        let now_std = Instant::now();
        let now = SmolInstant::from_millis(0);
        let mut cfg = Config::new(HardwareAddress::Ip);
        cfg.random_seed = (std::process::id() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xA5A5_5A5A;

        let mut iface = Interface::new(cfg, &mut device, now);
        iface.set_any_ip(true);
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1));
        let _ = iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));

        Self {
            iface,
            device,
            sockets: SocketSet::new(vec![]),
            intercepted: HashMap::new(),
            passthrough: HashMap::new(),
            signal,
            start_instant: now_std,
            last_prune: now_std,
        }
    }

    pub fn signal(&self) -> &Arc<NetstackSignal> {
        &self.signal
    }

    pub fn active_flow_count(&self) -> usize {
        self.intercepted.len()
    }

    #[inline]
    fn smol_now(&self) -> SmolInstant {
        let elapsed_ms = self.start_instant.elapsed().as_millis();
        let clamped = i64::try_from(elapsed_ms).unwrap_or(i64::MAX / 2);
        SmolInstant::from_millis(clamped)
    }

    fn maybe_prune_passthrough(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_prune) < Duration::from_secs(10)
            && self.passthrough.len() <= MAX_PASSTHROUGH_FLOWS
        {
            return;
        }
        self.last_prune = now;
        self.passthrough
            .retain(|_, ts| now.saturating_duration_since(*ts) <= PASSTHROUGH_TTL);
        if self.passthrough.len() > MAX_PASSTHROUGH_FLOWS {
            let mut items: Vec<_> = self.passthrough.iter().map(|(k, v)| (*k, *v)).collect();
            items.sort_unstable_by_key(|(_, ts)| *ts);
            let remove_cnt = self.passthrough.len().saturating_sub(MAX_PASSTHROUGH_FLOWS * 3 / 4);
            for (k, _) in items.into_iter().take(remove_cnt) {
                self.passthrough.remove(&k);
            }
        }
    }

    /// 处理一条从 WinDivert NETWORK 层截获的出站 TCP 原始 IP 报文，并返回需注入、放行或合成 RST 的结果
    #[allow(clippy::too_many_arguments)]
    pub fn ingest_outbound_tcp(
        &mut self,
        raw_ip: Vec<u8>,
        meta: PacketInterfaceMeta,
        pid: Option<u32>,
        rule_engine: Option<&RuleEngine>,
        tracker: Option<&ProcessTracker>,
        fake_ip_pool: Option<&FakeIpPool>,
        accepted_out: &mut Vec<AcceptedTcpFlow>,
        tx_out: &mut Vec<EmittedIpPacket>,
    ) -> TcpIngestOutcome {
        let Some(pkt) = parse_tcp_packet(&raw_ip) else {
            return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
        };

        let key = pkt.flow_key();
        let now = Instant::now();
        self.maybe_prune_passthrough(now);

        // 1. 最先检查 FlowX 自身绕过端口或当前进程 PID，避免代理出口自回环
        if is_tcp_port_bypassed(pkt.src_port) || pid.is_some_and(|p| p != 0 && p == std::process::id())
        {
            self.passthrough.insert(key, now);
            return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
        }

        // 2. 属于已登记劫持会话的后续报文（ACK / PSH / FIN / RST）：直接送入 smoltcp
        if let Some(session) = self.intercepted.get_mut(&key) {
            session.meta = meta;
            self.device.rx_queue.push_back(raw_ip);
            self.pump_internal(now, tx_out);
            return TcpIngestOutcome::Intercepted;
        }

        // 3. 属于已缓存直连流或开启前已建立的存量连接（非 SYN 首包）：绝不强行劫持，平滑放行
        if self.passthrough.contains_key(&key) || !pkt.syn || pkt.ack {
            return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
        }

        // 4. 忽略未指定/多播/广播目标
        let is_broadcast = matches!(pkt.dst_ip, IpAddr::V4(v4) if v4.is_broadcast());
        if pkt.dst_ip.is_multicast() || pkt.dst_ip.is_unspecified() || is_broadcast {
            self.passthrough.insert(key, now);
            return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
        }

        // 5. 全新 SYN 首包路由裁决
        let is_fake_ip = fake_ip_pool.is_some_and(|pool| pool.is_fake_ip_addr(pkt.dst_ip));
        let needs_domain_sniff = if is_fake_ip {
            // Fake-IP 在 DNS 阶段已绑定真实域名；由 Dispatcher 还原域名后立即走规则裁决，不空等 120ms 嗅探
            false
        } else if let Some(re) = rule_engine {
            let proc_info = pid.and_then(|p| tracker.and_then(|t| t.resolve_pid(p)));
            let proc_path = proc_info.as_ref().map(|i| i.path.as_str());
            let proc_name = proc_info.as_ref().map(|i| i.name.as_str());
            match re.needs_domain_for_routing(proc_path, proc_name, Some(pkt.dst_ip), pkt.dst_port)
            {
                DomainNeedDecision::Immediate(Action::Direct) => {
                    self.passthrough.insert(key, now);
                    return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
                }
                DomainNeedDecision::Immediate(Action::Block) => {
                    if let Some(rst) = build_synthetic_tcp_rst(&raw_ip) {
                        return TcpIngestOutcome::InjectRst(EmittedIpPacket { data: rst, meta });
                    }
                    return TcpIngestOutcome::Intercepted;
                }
                DomainNeedDecision::Immediate(Action::Proxy(_) | Action::Chain(_)) => false,
                DomainNeedDecision::NeedsDomainSniff => true,
            }
        } else {
            // 测试或无规则引擎时的安全回退：接入用户态协议栈
            false
        };

        if self.intercepted.len() >= MAX_INTERCEPTED_FLOWS {
            if let Some(rst) = build_synthetic_tcp_rst(&raw_ip) {
                return TcpIngestOutcome::InjectRst(EmittedIpPacket { data: rst, meta });
            }
            self.passthrough.insert(key, now);
            return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
        }

        // 6. 原子 Listen + 单 SYN 入队并立即 poll，确保 SocketSet 中绝不残留重叠的 Listen 句柄
        let mut sock = tcp::Socket::new(
            SocketBuffer::new(vec![0u8; SMOLTCP_RX_BUF]),
            SocketBuffer::new(vec![0u8; SMOLTCP_TX_BUF]),
        );
        let listen_ep = IpListenEndpoint {
            addr: Some(IpAddress::from(pkt.dst_ip)),
            port: pkt.dst_port,
        };
        if sock.listen(listen_ep).is_err() {
            self.passthrough.insert(key, now);
            return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
        }
        let handle = self.sockets.add(sock);
        self.device.rx_queue.push_back(raw_ip);

        let smol_now = self.smol_now();
        self.iface
            .poll(smol_now, &mut self.device, &mut self.sockets);

        let post_state = self.sockets.get::<tcp::Socket>(handle).state();
        if post_state == tcp::State::Listen {
            // SYN 未能被 smoltcp 接受：立即清理并退回 Passthrough
            self.sockets.remove(handle);
            self.drain_tx_packets(&meta, tx_out);
            self.passthrough.insert(key, now);
            return TcpIngestOutcome::Intercepted;
        }

        let bridge = Arc::new(SmoltcpBridge::new(Arc::clone(&self.signal)));
        let stream = SmoltcpStream::from_bridge(Arc::clone(&bridge));
        self.intercepted.insert(
            key,
            InterceptedSession {
                handle,
                bridge,
                meta,
                created_at: now,
                ever_established: matches!(post_state, tcp::State::Established),
            },
        );
        self.drain_tx_with_lookup(meta, tx_out);

        accepted_out.push(AcceptedTcpFlow {
            stream,
            peer_addr: key.local_addr(),
            orig_dst: key.orig_dst(),
            pid_hint: pid,
            needs_domain_sniff,
        });

        TcpIngestOutcome::Intercepted
    }

    /// 推送双向桥接缓冲与 smoltcp 定时器/发送队列，返回下一次建议等待的最大时间
    pub fn pump(&mut self, tx_out: &mut Vec<EmittedIpPacket>) -> Duration {
        let now = Instant::now();
        self.maybe_prune_passthrough(now);
        self.pump_internal(now, tx_out);

        let smol_now = self.smol_now();
        match self.iface.poll_delay(smol_now, &self.sockets) {
            Some(d) => Duration::from_millis(d.total_millis()).clamp(Duration::from_millis(1), Duration::from_millis(50)),
            None => Duration::from_millis(50),
        }
    }

    fn pump_internal(&mut self, now: Instant, tx_out: &mut Vec<EmittedIpPacket>) {
        // 先行运行一轮 poll 消化可能尚在 rx_queue 的控制包
        let smol_now = self.smol_now();
        self.iface
            .poll(smol_now, &mut self.device, &mut self.sockets);

        let mut closed_keys = Vec::new();
        let mut temp_rx = [0u8; 16 * 1024];

        for (&key, session) in self.intercepted.iter_mut() {
            let sock = self.sockets.get_mut::<tcp::Socket>(session.handle);
            let state = sock.state();
            if matches!(
                state,
                tcp::State::Established | tcp::State::CloseWait | tcp::State::FinWait1 | tcp::State::FinWait2
            ) {
                session.ever_established = true;
            }

            let mut wake_read: Option<Waker> = None;
            let mut wake_write: Option<Waker> = None;
            let mut wake_flush: Option<Waker> = None;
            let mut remove_session = false;

            {
                let mut inner = session.bridge.inner.lock().unwrap_or_else(|e| e.into_inner());

                // A. socket -> to_app
                if !inner.app_read_closed {
                    while sock.can_recv() && inner.to_app.len() < BRIDGE_BUFFER_LIMIT {
                        let room = BRIDGE_BUFFER_LIMIT - inner.to_app.len();
                        let max_read = room.min(temp_rx.len());
                        match sock.recv_slice(&mut temp_rx[..max_read]) {
                            Ok(n) if n > 0 => {
                                inner.to_app.extend(&temp_rx[..n]);
                                if wake_read.is_none() {
                                    wake_read = inner.read_waker.take();
                                }
                            }
                            _ => break,
                        }
                    }
                }

                // B. 检测远端（本地应用）是否已发送 FIN 或异常重置
                if !sock.may_recv() && !sock.can_recv() && !inner.socket_eof_to_app {
                    inner.socket_eof_to_app = true;
                    if wake_read.is_none() {
                        wake_read = inner.read_waker.take();
                    }
                }

                // C. to_socket -> socket
                while !inner.to_socket.is_empty() && sock.can_send() {
                    let (head, _) = inner.to_socket.as_slices();
                    if head.is_empty() {
                        break;
                    }
                    match sock.send_slice(head) {
                        Ok(n) if n > 0 => {
                            inner.to_socket.drain(..n);
                            if inner.to_socket.len() < BRIDGE_BUFFER_LIMIT && wake_write.is_none() {
                                wake_write = inner.write_waker.take();
                            }
                        }
                        _ => break,
                    }
                }

                // D. 优雅半关闭写端：待 `to_socket` 完全冲刷入 smoltcp 后触发 TCP FIN
                if inner.app_write_closed && inner.to_socket.is_empty() && !inner.fin_sent_to_socket
                {
                    sock.close();
                    inner.fin_sent_to_socket = true;
                }

                if inner.to_socket.is_empty() && inner.flush_waker.is_some() {
                    wake_flush = inner.flush_waker.take();
                }

                // E. 若双向均已关闭且未经正常 FIN 发送，直接中止清理
                if inner.app_read_closed
                    && inner.app_write_closed
                    && inner.to_socket.is_empty()
                    && !inner.fin_sent_to_socket
                    && state != tcp::State::Closed
                {
                    sock.abort();
                    remove_session = true;
                }

                // F. 检测异常关闭或长时间停滞在 SynReceived 的半开扫描连接
                let syn_timed_out = !session.ever_established
                    && state == tcp::State::SynReceived
                    && now.saturating_duration_since(session.created_at) >= SYN_RECEIVED_TIMEOUT;
                if syn_timed_out {
                    sock.abort();
                    inner.socket_errored = true;
                    inner.socket_eof_to_app = true;
                    if wake_read.is_none() {
                        wake_read = inner.read_waker.take();
                    }
                    if wake_write.is_none() {
                        wake_write = inner.write_waker.take();
                    }
                    if wake_flush.is_none() {
                        wake_flush = inner.flush_waker.take();
                    }
                    remove_session = true;
                } else if state == tcp::State::Closed {
                    if !inner.socket_eof_to_app {
                        // 对端直接 RST 而未经 FIN 时标注 socket_errored
                        if !session.ever_established {
                            inner.socket_errored = true;
                        }
                        inner.socket_eof_to_app = true;
                    }
                    if wake_read.is_none() {
                        wake_read = inner.read_waker.take();
                    }
                    if wake_write.is_none() {
                        wake_write = inner.write_waker.take();
                    }
                    if wake_flush.is_none() {
                        wake_flush = inner.flush_waker.take();
                    }
                    remove_session = true;
                }
            }

            if let Some(w) = wake_read {
                w.wake();
            }
            if let Some(w) = wake_write {
                w.wake();
            }
            if let Some(w) = wake_flush {
                w.wake();
            }
            if remove_session {
                closed_keys.push(key);
            }
        }

        // 第二轮 poll：立即将刚写入 smoltcp 发送队列或 close() FIN/RST 发成 IP 包吐出
        let smol_now = self.smol_now();
        self.iface
            .poll(smol_now, &mut self.device, &mut self.sockets);
        self.drain_tx_with_lookup(PacketInterfaceMeta::default(), tx_out);

        for key in closed_keys {
            if let Some(sess) = self.intercepted.remove(&key) {
                self.sockets.remove(sess.handle);
            }
        }
    }

    fn drain_tx_packets(&mut self, meta: &PacketInterfaceMeta, tx_out: &mut Vec<EmittedIpPacket>) {
        while let Some(pkt) = self.device.tx_queue.pop_front() {
            tx_out.push(EmittedIpPacket {
                data: pkt,
                meta: *meta,
            });
        }
    }

    /// 精确为每一条由 `smoltcp` 吐出的入站注入报文还原来源四元组所属的网络接口元数据
    fn drain_tx_with_lookup(
        &mut self,
        fallback_meta: PacketInterfaceMeta,
        tx_out: &mut Vec<EmittedIpPacket>,
    ) {
        while let Some(pkt) = self.device.tx_queue.pop_front() {
            let meta = if let Some(parsed) = parse_tcp_packet(&pkt) {
                // TX 报文的源地址是远端目标，目的地址是本地应用，反转查回原出站四元组
                let lookup_key = TcpFlowKey::new(
                    parsed.dst_ip,
                    parsed.dst_port,
                    parsed.src_ip,
                    parsed.src_port,
                );
                self.intercepted
                    .get(&lookup_key)
                    .map(|s| s.meta)
                    .unwrap_or(PacketInterfaceMeta {
                        is_ipv6: parsed.is_ipv6,
                        ..fallback_meta
                    })
            } else {
                fallback_meta
            };
            tx_out.push(EmittedIpPacket { data: pkt, meta });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::outbound::bypass::{register_bypass_port, BypassProtocol};
    use crate::router::Rule;

    fn build_syn(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, seq: u32) -> Vec<u8> {
        let mut hdr = TcpHeader::new(sport, dport, seq, 65535);
        hdr.syn = true;
        let builder = PacketBuilder::ipv4(src, dst, 64).tcp_header(hdr);
        let mut out = Vec::with_capacity(builder.size(0));
        builder.write(&mut out, &[]).unwrap();
        out
    }

    fn build_ack(
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        seq: u32,
        ack: u32,
        fin: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut hdr = TcpHeader::new(sport, dport, seq, 65535);
        hdr.ack = true;
        hdr.acknowledgment_number = ack;
        hdr.fin = fin;
        if !payload.is_empty() {
            hdr.psh = true;
        }
        let builder = PacketBuilder::ipv4(src, dst, 64).tcp_header(hdr);
        let mut out = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut out, payload).unwrap();
        out
    }

    fn build_syn_v6(
        src: Ipv6Addr,
        sport: u16,
        dst: Ipv6Addr,
        dport: u16,
        seq: u32,
    ) -> Vec<u8> {
        let mut hdr = TcpHeader::new(sport, dport, seq, 65535);
        hdr.syn = true;
        let builder = PacketBuilder::ipv6(src.octets(), dst.octets(), 64).tcp_header(hdr);
        let mut out = Vec::with_capacity(builder.size(0));
        builder.write(&mut out, &[]).unwrap();
        out
    }

    #[test]
    fn test_build_synthetic_tcp_rst_ipv4_and_ipv6() {
        let syn_v4 = build_syn([10, 0, 0, 2], 51000, [1, 1, 1, 1], 443, 0x1000_0000);
        let rst_v4 = build_synthetic_tcp_rst(&syn_v4).expect("IPv4 SYN should yield RST+ACK");
        let parsed = parse_tcp_packet(&rst_v4).unwrap();
        assert_eq!(parsed.src_ip, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(parsed.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(parsed.src_port, 443);
        assert_eq!(parsed.dst_port, 51000);
        assert!(parsed.rst);
        assert!(parsed.ack);
        assert_eq!(parsed.ack_num, 0x1000_0001);

        let src6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let dst6 = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let syn_v6 = build_syn_v6(src6, 52000, dst6, 8443, 0x2000_0000);
        let rst_v6 = build_synthetic_tcp_rst(&syn_v6).expect("IPv6 SYN should yield RST+ACK");
        let parsed6 = parse_tcp_packet(&rst_v6).unwrap();
        assert!(parsed6.is_ipv6);
        assert!(parsed6.rst && parsed6.ack);
        assert_eq!(parsed6.ack_num, 0x2000_0001);
    }

    #[test]
    fn test_netstack_untracked_non_syn_bypass_and_direct_block_decisions() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);
        let mut accepted = Vec::new();
        let mut tx = Vec::new();
        let meta = PacketInterfaceMeta {
            if_idx: 7,
            sub_if_idx: 0,
            loopback: false,
            is_ipv6: false,
            bitfield: 0,
        };

        // 1. 存量连接（无 SYN 标志）未经追踪 -> 立即平滑放行
        let ack_pkt = build_ack([192, 168, 1, 10], 40010, [93, 184, 216, 34], 443, 100, 200, false, b"hi");
        assert!(matches!(
            engine.ingest_outbound_tcp(ack_pkt, meta, Some(99999), None, None, None, &mut accepted, &mut tx),
            TcpIngestOutcome::Passthrough(_)
        ));
        assert!(accepted.is_empty());

        // 2. BypassPortRegistry 已登记出站 TCP 端口或自身 PID -> 首包 SYN 直接放行
        let syn_bypass = build_syn([192, 168, 1, 10], 40011, [93, 184, 216, 34], 443, 500);
        {
            let _guard = register_bypass_port(BypassProtocol::Tcp, 40011);
            assert!(matches!(
                engine.ingest_outbound_tcp(syn_bypass.clone(), meta, Some(99999), None, None, None, &mut accepted, &mut tx),
                TcpIngestOutcome::Passthrough(_)
            ));
        }
        assert!(matches!(
            engine.ingest_outbound_tcp(
                build_syn([192, 168, 1, 10], 40012, [93, 184, 216, 34], 443, 500),
                meta,
                Some(std::process::id()),
                None,
                None,
                None,
                &mut accepted,
                &mut tx,
            ),
            TcpIngestOutcome::Passthrough(_)
        ));

        // 3. Action::Block 规则命中 -> 秒级注入 RST，不创建用户态 socket
        let block_engine = RuleEngine::new(vec![], Action::Block);
        let syn_block = build_syn([192, 168, 1, 10], 40013, [1, 2, 3, 4], 443, 700);
        match engine.ingest_outbound_tcp(
            syn_block,
            meta,
            Some(99999),
            Some(&block_engine),
            None,
            None,
            &mut accepted,
            &mut tx,
        ) {
            TcpIngestOutcome::InjectRst(rst_pkt) => {
                assert!(parse_tcp_packet(&rst_pkt.data).unwrap().rst);
            }
            other => panic!("Expected InjectRst, got {:?}", other),
        }

        // 4. NeedsDomainSniff 标记传播验证
        let domain_engine = RuleEngine::new(
            vec![Rule::from_raw(
                "sniff-rule",
                true,
                None,
                Some("*.openai.com"),
                None,
                Action::Proxy(1),
            )],
            Action::Direct,
        );
        let syn_sniff = build_syn([192, 168, 1, 10], 40014, [104, 18, 1, 1], 443, 900);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn_sniff,
                meta,
                Some(99999),
                Some(&domain_engine),
                None,
                None,
                &mut accepted,
                &mut tx,
            ),
            TcpIngestOutcome::Intercepted
        ));
        assert_eq!(accepted.len(), 1);
        assert!(accepted[0].needs_domain_sniff);
        assert_eq!(tx.len(), 1);
        let syn_ack = parse_tcp_packet(&tx[0].data).unwrap();
        assert!(syn_ack.syn && syn_ack.ack);
    }

    #[tokio::test]
    async fn test_netstack_full_tcp_handshake_data_and_half_close_roundtrip() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(Arc::clone(&signal));
        let mut accepted = Vec::new();
        let mut tx = Vec::new();
        let meta = PacketInterfaceMeta {
            if_idx: 11,
            sub_if_idx: 2,
            loopback: false,
            is_ipv6: false,
            bitfield: 0,
        };

        let src = [10, 1, 2, 3];
        let sport = 55555;
        let dst = [93, 184, 216, 34];
        let dport = 80;
        let client_isn = 1000;

        // 1. Client SYN -> smoltcp emits SYN+ACK
        let syn = build_syn(src, sport, dst, dport, client_isn);
        assert!(matches!(
            engine.ingest_outbound_tcp(syn, meta, Some(88888), None, None, None, &mut accepted, &mut tx),
            TcpIngestOutcome::Intercepted
        ));
        assert_eq!(accepted.len(), 1);
        let flow = accepted.pop().unwrap();
        assert_eq!(flow.orig_dst, SocketAddr::new(IpAddr::V4(Ipv4Addr::from(dst)), dport));

        assert_eq!(tx.len(), 1);
        assert_eq!(tx[0].meta.if_idx, 11);
        let syn_ack = parse_tcp_packet(&tx.pop().unwrap().data).unwrap();
        assert!(syn_ack.syn && syn_ack.ack);
        let server_isn = syn_ack.seq;
        assert_eq!(syn_ack.ack_num, client_isn + 1);

        // 2. Client ACK + GET payload + FIN (测试客户端发完请求立即半关闭写端!)
        let req_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let ack_data_fin = build_ack(
            src,
            sport,
            dst,
            dport,
            client_isn + 1,
            server_isn + 1,
            true,
            req_payload,
        );
        assert!(matches!(
            engine.ingest_outbound_tcp(
                ack_data_fin,
                meta,
                Some(88888),
                None,
                None,
                None,
                &mut accepted,
                &mut tx,
            ),
            TcpIngestOutcome::Intercepted
        ));

        let (mut rd, mut wr) = flow.stream.split_stream();
        let reader_handle = tokio::spawn(async move {
            let mut buf = Vec::new();
            rd.read_to_end(&mut buf).await.unwrap();
            buf
        });

        let read_req = reader_handle.await.unwrap();
        assert_eq!(read_req, req_payload);

        // 3. 在客户端已 FIN（CloseWait）后，下游依旧正常回传完整 HTTP 响应并优雅 shutdown 发送 FIN
        let resp_payload = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
        let writer_handle = tokio::spawn(async move {
            wr.write_all(resp_payload).await.unwrap();
            wr.shutdown().await.unwrap();
        });

        // 推进 pump 直到 writer 完成并收集 smoltcp 吐出的所有响应+FIN 报文
        let mut received_from_smoltcp = Vec::new();
        let mut saw_server_fin = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            engine.pump(&mut tx);
            for pkt_out in tx.drain(..) {
                if let Some(parsed) = parse_tcp_packet(&pkt_out.data) {
                    let sliced = SlicedPacket::from_ip(&pkt_out.data).unwrap();
                    if let Some(TransportSlice::Tcp(t)) = sliced.transport {
                        received_from_smoltcp.extend_from_slice(t.payload());
                    }
                    if parsed.fin {
                        saw_server_fin = true;
                    }
                }
            }
            if writer_handle.is_finished() && saw_server_fin {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "Timed out waiting for smoltcp response & FIN");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        writer_handle.await.unwrap();
        assert_eq!(received_from_smoltcp, resp_payload);
        assert!(saw_server_fin);
    }

    #[test]
    fn test_netstack_ipv6_and_lso_oversized_segment_accepted() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);
        let mut accepted = Vec::new();
        let mut tx = Vec::new();
        let meta = PacketInterfaceMeta {
            if_idx: 5,
            sub_if_idx: 0,
            loopback: false,
            is_ipv6: true,
            bitfield: 0,
        };

        let src6 = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6);
        let dst6 = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let syn6 = build_syn_v6(src6, 61111, dst6, 443, 5000);
        assert!(matches!(
            engine.ingest_outbound_tcp(syn6, meta, Some(77777), None, None, None, &mut accepted, &mut tx),
            TcpIngestOutcome::Intercepted
        ));
        assert_eq!(tx.len(), 1);
        let syn_ack6 = parse_tcp_packet(&tx.pop().unwrap().data).unwrap();
        assert!(syn_ack6.is_ipv6 && syn_ack6.syn && syn_ack6.ack);

        // 模拟 Windows LSO 大包（>1500B）入站到 smoltcp 不应被 MTU 丢弃
        let large_payload = vec![b'A'; 2400];
        let mut hdr = TcpHeader::new(61111, 443, 5001, 65535);
        hdr.ack = true;
        hdr.acknowledgment_number = syn_ack6.seq + 1;
        let builder = PacketBuilder::ipv6(src6.octets(), dst6.octets(), 64).tcp_header(hdr);
        let mut lso_pkt = Vec::with_capacity(builder.size(large_payload.len()));
        builder.write(&mut lso_pkt, &large_payload).unwrap();

        assert!(matches!(
            engine.ingest_outbound_tcp(lso_pkt, meta, Some(77777), None, None, None, &mut accepted, &mut tx),
            TcpIngestOutcome::Intercepted
        ));
        let flow = accepted.pop().unwrap();
        // 数据应完整进入 bridge.to_app
        let inner = flow.stream.read.bridge.inner.lock().unwrap();
        assert_eq!(inner.to_app.len(), 2400);
    }
}
