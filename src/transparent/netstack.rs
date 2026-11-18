use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TcpHeader, TcpHeaderSlice, TransportSlice};
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
const MAX_SMOLTCP_TCP_SEG_PAYLOAD: usize = 32_768;
const MAX_INTERCEPTED_FLOWS: usize = 4096;
const MAX_PASSTHROUGH_FLOWS: usize = 16_384;
const PASSTHROUGH_TTL: Duration = Duration::from_secs(120);
const SYN_RECEIVED_TIMEOUT: Duration = Duration::from_secs(15);
const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const TIME_WAIT_REAP_TIMEOUT: Duration = Duration::from_secs(2);

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

struct ParsedTcpRaw<'a> {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    is_ipv6: bool,
    fast_path_ok: bool,
    tcp_hdr: TcpHeaderSlice<'a>,
    payload: &'a [u8],
}

fn ipv6_ext_len(nh: u8, slice: &[u8]) -> Option<usize> {
    if slice.len() < 2 {
        return None;
    }
    match nh {
        0 | 43 | 60 | 135 | 139 | 140 => Some(((slice[1] as usize) + 1) * 8),
        51 => Some(((slice[1] as usize) + 2) * 4),
        _ => None,
    }
}

fn parse_lso_or_standard_tcp_packet(raw_ip: &[u8]) -> Option<ParsedTcpRaw<'_>> {
    let ver = raw_ip.first()? >> 4;
    match ver {
        4 => {
            if raw_ip.len() < 20 {
                return None;
            }
            let ihl = ((raw_ip[0] & 0x0F) as usize) * 4;
            if ihl < 20 || raw_ip.len() < ihl {
                return None;
            }
            let flags_frag = u16::from_be_bytes([raw_ip[6], raw_ip[7]]);
            if (flags_frag & 0x2000) != 0 || (flags_frag & 0x1FFF) != 0 {
                return None;
            }
            if raw_ip[9] != 6 {
                return None;
            }
            let hdr_total_len = u16::from_be_bytes([raw_ip[2], raw_ip[3]]) as usize;
            let (ip_end, fast_path_ok) = if hdr_total_len == 0 || raw_ip.len() > u16::MAX as usize {
                (raw_ip.len(), false)
            } else if hdr_total_len >= ihl && hdr_total_len <= raw_ip.len() {
                (hdr_total_len, hdr_total_len == raw_ip.len())
            } else {
                return None;
            };

            let tcp_slice = &raw_ip[ihl..ip_end];
            let tcp_hdr = TcpHeaderSlice::from_slice(tcp_slice).ok()?;
            let payload = &tcp_slice[tcp_hdr.slice().len()..];
            let src_ip =
                IpAddr::V4(Ipv4Addr::new(raw_ip[12], raw_ip[13], raw_ip[14], raw_ip[15]))
                    .to_canonical();
            let dst_ip =
                IpAddr::V4(Ipv4Addr::new(raw_ip[16], raw_ip[17], raw_ip[18], raw_ip[19]))
                    .to_canonical();

            Some(ParsedTcpRaw {
                src_ip,
                dst_ip,
                is_ipv6: false,
                fast_path_ok,
                tcp_hdr,
                payload,
            })
        }
        6 => {
            if raw_ip.len() < 40 {
                return None;
            }
            let hdr_payload_len = u16::from_be_bytes([raw_ip[4], raw_ip[5]]) as usize;
            let lso_override =
                (hdr_payload_len == 0 && raw_ip.len() > 40) || raw_ip.len() > 40 + u16::MAX as usize;
            let ip_end = if lso_override {
                raw_ip.len()
            } else {
                let end = 40usize.checked_add(hdr_payload_len)?;
                if end > raw_ip.len() || hdr_payload_len == 0 {
                    return None;
                }
                end
            };

            let mut next_hdr = raw_ip[6];
            let mut pos = 40usize;
            for _ in 0..8 {
                if next_hdr == 6 {
                    break;
                }
                if next_hdr == 44 {
                    return None;
                }
                let ext_len = ipv6_ext_len(next_hdr, &raw_ip[pos..ip_end])?;
                if pos + ext_len > ip_end {
                    return None;
                }
                next_hdr = raw_ip[pos];
                pos += ext_len;
            }
            if next_hdr != 6 || pos >= ip_end {
                return None;
            }

            let tcp_slice = &raw_ip[pos..ip_end];
            let tcp_hdr = TcpHeaderSlice::from_slice(tcp_slice).ok()?;
            let payload = &tcp_slice[tcp_hdr.slice().len()..];
            let src_octets: [u8; 16] = raw_ip[8..24].try_into().ok()?;
            let dst_octets: [u8; 16] = raw_ip[24..40].try_into().ok()?;
            let src_ip = IpAddr::V6(Ipv6Addr::from(src_octets)).to_canonical();
            let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_octets)).to_canonical();
            let fast_path_ok = !lso_override
                && pos == 40
                && ip_end == raw_ip.len()
                && !matches!((src_ip, dst_ip), (IpAddr::V4(_), _) | (_, IpAddr::V4(_)));

            Some(ParsedTcpRaw {
                src_ip,
                dst_ip,
                is_ipv6: true,
                fast_path_ok,
                tcp_hdr,
                payload,
            })
        }
        _ => None,
    }
}

/// 将标准或 LSO >65KB / header length=0 的出站 TCP 报文规范切片并入队 `smoltcp`，
/// 防止大于 65,535B 的 NDIS LSO 大包被忽略截断或 `total_len=0` 引发解析失败。
fn enqueue_tcp_for_smoltcp(rx_queue: &mut VecDeque<Vec<u8>>, raw_ip: Vec<u8>) {
    let Some(parsed) = parse_lso_or_standard_tcp_packet(&raw_ip) else {
        rx_queue.push_back(raw_ip);
        return;
    };

    if parsed.fast_path_ok && parsed.payload.len() <= MAX_SMOLTCP_TCP_SEG_PAYLOAD {
        rx_queue.push_back(raw_ip);
        return;
    }

    let base_hdr = parsed.tcp_hdr.to_header();
    let emit_segment = |rx_queue: &mut VecDeque<Vec<u8>>, hdr: TcpHeader, data: &[u8]| match (
        parsed.src_ip,
        parsed.dst_ip,
    ) {
        (IpAddr::V4(s4), IpAddr::V4(d4)) => {
            let builder = PacketBuilder::ipv4(s4.octets(), d4.octets(), 64).tcp_header(hdr);
            let mut out = Vec::with_capacity(builder.size(data.len()));
            if builder.write(&mut out, data).is_ok() {
                rx_queue.push_back(out);
            }
        }
        (IpAddr::V6(s6), IpAddr::V6(d6)) => {
            let builder = PacketBuilder::ipv6(s6.octets(), d6.octets(), 64).tcp_header(hdr);
            let mut out = Vec::with_capacity(builder.size(data.len()));
            if builder.write(&mut out, data).is_ok() {
                rx_queue.push_back(out);
            }
        }
        _ => {}
    };

    if parsed.payload.is_empty() {
        emit_segment(rx_queue, base_hdr, &[]);
        return;
    }

    let total_chunks = parsed.payload.len().div_ceil(MAX_SMOLTCP_TCP_SEG_PAYLOAD);
    let mut offset = 0usize;
    for (idx, chunk) in parsed.payload.chunks(MAX_SMOLTCP_TCP_SEG_PAYLOAD).enumerate() {
        let mut hdr = base_hdr.clone();
        hdr.sequence_number = base_hdr.sequence_number.wrapping_add(offset as u32);
        if idx > 0 {
            hdr.syn = false;
        }
        if idx + 1 < total_chunks {
            hdr.fin = false;
            hdr.psh = false;
        }
        offset += chunk.len();
        emit_segment(rx_queue, hdr, chunk);
    }
}

/// 解析原始 IPv4/IPv6 TCP 报文（兼容 Windows NDIS LSO 大包及 length=0 卸载包）；自动忽略分片报文与非 TCP 报文
pub fn parse_tcp_packet(raw_ip: &[u8]) -> Option<ParsedTcpPacket> {
    if let Some(raw) = parse_lso_or_standard_tcp_packet(raw_ip) {
        return Some(ParsedTcpPacket {
            src_ip: raw.src_ip,
            dst_ip: raw.dst_ip,
            src_port: raw.tcp_hdr.source_port(),
            dst_port: raw.tcp_hdr.destination_port(),
            seq: raw.tcp_hdr.sequence_number(),
            ack_num: raw.tcp_hdr.acknowledgment_number(),
            syn: raw.tcp_hdr.syn(),
            ack: raw.tcp_hdr.ack(),
            fin: raw.tcp_hdr.fin(),
            rst: raw.tcp_hdr.rst(),
            payload_len: raw.payload.len(),
            is_ipv6: raw.is_ipv6,
        });
    }
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

/// 投递至用户态协议栈工作线程的出站 TCP 队列项（若由分片重组而来则随附原始分片供直连透传回退）
#[derive(Debug, Clone)]
pub struct OutboundTcpQueueItem {
    pub raw_ip: Vec<u8>,
    pub meta: PacketInterfaceMeta,
    pub pid: Option<u32>,
    pub orig_fragments: Option<Vec<EmittedIpPacket>>,
}

/// 当 `ingest_outbound_tcp` 返回 `TcpIngestOutcome::Passthrough` 时，若该包来自 IP 分片重组，
/// 则优先回退发射原始分片序列（完整保留 IPv6 扩展头与各片原始链路 MTU），否则发射单个直连报文。
pub fn select_passthrough_packets(
    single_pkt: EmittedIpPacket,
    orig_fragments: Option<Vec<EmittedIpPacket>>,
) -> Vec<EmittedIpPacket> {
    match orig_fragments {
        Some(frags) if !frags.is_empty() => frags,
        _ => vec![single_pkt],
    }
}

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

    pub fn push_outbound_tcp(
        &self,
        raw_ip: Vec<u8>,
        meta: PacketInterfaceMeta,
        pid: Option<u32>,
    ) {
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

struct BridgeInner {
    to_app: VecDeque<u8>,
    to_socket: VecDeque<u8>,
    socket_eof_to_app: bool,
    socket_errored: bool,
    socket_closed: bool,
    app_read_closed: bool,
    app_write_closed: bool,
    graceful_shutdown: bool,
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
            socket_closed: false,
            app_read_closed: false,
            app_write_closed: false,
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

fn close_bridge_and_collect_wakers(
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
            inner.graceful_shutdown = true;
            if inner.socket_errored {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Transparent TCP connection reset during shutdown",
                )));
            }
            if inner.to_socket.is_empty() && (inner.fin_sent_to_socket || inner.socket_closed) {
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

#[derive(Debug, Clone, Copy)]
struct PassthroughEntry {
    last_seen: Instant,
    syn_seq: Option<u32>,
}

struct InterceptedSession {
    handle: SocketHandle,
    bridge: Arc<SmoltcpBridge>,
    meta: PacketInterfaceMeta,
    created_at: Instant,
    syn_seq: u32,
    ever_established: bool,
    last_state: tcp::State,
    teardown_since: Option<Instant>,
    time_wait_since: Option<Instant>,
}

/// 单所有权用户态 TCP/IP 协议栈引擎：负责四元组流分拣、孤立 Listen 握手防碰撞、双向缓冲泵送及异常连接清理
pub struct NetstackEngine {
    iface: Interface,
    device: VirtualIpDevice,
    sockets: SocketSet<'static>,
    intercepted: HashMap<TcpFlowKey, InterceptedSession>,
    passthrough: HashMap<TcpFlowKey, PassthroughEntry>,
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
            .retain(|_, entry| now.saturating_duration_since(entry.last_seen) <= PASSTHROUGH_TTL);
        if self.passthrough.len() > MAX_PASSTHROUGH_FLOWS {
            let mut items: Vec<_> = self.passthrough.iter().map(|(k, v)| (*k, v.last_seen)).collect();
            items.sort_unstable_by_key(|(_, ts)| *ts);
            let remove_cnt = self.passthrough.len().saturating_sub(MAX_PASSTHROUGH_FLOWS * 3 / 4);
            for (k, _) in items.into_iter().take(remove_cnt) {
                self.passthrough.remove(&k);
            }
        }
    }

    /// 当 SOCKET 层上报本地 TCP 端点关闭时，立即失效关联的直连旁路缓存以防止同端口复用穿透规则
    pub fn invalidate_passthrough_for_local_endpoint(&mut self, local_ip: IpAddr, local_port: u16) {
        if local_port == 0 {
            return;
        }
        let canonical = local_ip.to_canonical();
        let wildcard = canonical.is_unspecified();
        self.passthrough.retain(|key, _| {
            if key.src_port != local_port {
                return true;
            }
            if wildcard {
                return false;
            }
            match (key.src_ip, canonical) {
                (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                    key.src_ip != canonical
                }
                _ => true,
            }
        });
    }

    /// 四元组复用时静默移除退场中的旧劫持会话，不向宿主注入额外 RST 以免误伤刚刚发起的新连接
    fn retire_session_silently(&mut self, key: TcpFlowKey) {
        let Some(old_sess) = self.intercepted.remove(&key) else {
            return;
        };
        let mut wake_read = None;
        let mut wake_write = None;
        let mut wake_flush = None;
        {
            let mut inner = old_sess
                .bridge
                .inner
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            close_bridge_and_collect_wakers(
                &mut inner,
                false,
                &mut wake_read,
                &mut wake_write,
                &mut wake_flush,
            );
        }
        self.sockets.remove(old_sess.handle);
        if let Some(w) = wake_read {
            w.wake();
        }
        if let Some(w) = wake_write {
            w.wake();
        }
        if let Some(w) = wake_flush {
            w.wake();
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
            if pkt.rst {
                self.passthrough.remove(&key);
            } else {
                self.passthrough.insert(
                    key,
                    PassthroughEntry {
                        last_seen: now,
                        syn_seq: (pkt.syn && !pkt.ack).then_some(pkt.seq),
                    },
                );
            }
            return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
        }

        // 2. 属于已登记劫持会话的后续报文（ACK / PSH / FIN / RST）：直接送入 smoltcp；
        //    若旧会话已在挥手退场且迎来不同 ISN 的全新 SYN，则静默退休旧会话让位给新连接
        let mut retire_old_session = false;
        if let Some(session) = self.intercepted.get_mut(&key) {
            let state = self.sockets.get::<tcp::Socket>(session.handle).state();
            if pkt.syn
                && !pkt.ack
                && pkt.seq != session.syn_seq
                && matches!(
                    state,
                    tcp::State::Listen
                        | tcp::State::FinWait1
                        | tcp::State::FinWait2
                        | tcp::State::Closing
                        | tcp::State::LastAck
                        | tcp::State::TimeWait
                        | tcp::State::Closed
                )
            {
                retire_old_session = true;
            } else {
                session.meta = meta;
                enqueue_tcp_for_smoltcp(&mut self.device.rx_queue, raw_ip);
                self.pump_internal(now, tx_out);
                return TcpIngestOutcome::Intercepted;
            }
        }
        if retire_old_session {
            self.retire_session_silently(key);
        }

        // 3. 属于已缓存直连流或开启前已建立的存量连接（非 SYN 首包）：绝不强行劫持，平滑放行；
        //    若遭遇 RST 或不同 seq 的全新 SYN（四元组快速复用），立即失效旧旁路缓存并重走规则判断
        if let Some(entry) = self.passthrough.get_mut(&key) {
            if pkt.rst {
                self.passthrough.remove(&key);
                return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
            }
            if pkt.syn && !pkt.ack {
                if entry.syn_seq == Some(pkt.seq) {
                    entry.last_seen = now;
                    return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
                }
                self.passthrough.remove(&key);
            } else {
                entry.last_seen = now;
                return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
            }
        }
        if !pkt.syn || pkt.ack {
            return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
        }

        let insert_syn_passthrough = |passthrough: &mut HashMap<TcpFlowKey, PassthroughEntry>| {
            passthrough.insert(
                key,
                PassthroughEntry {
                    last_seen: now,
                    syn_seq: Some(pkt.seq),
                },
            );
        };

        // 4. 忽略未指定/多播/广播目标
        let is_broadcast = matches!(pkt.dst_ip, IpAddr::V4(v4) if v4.is_broadcast());
        if pkt.dst_ip.is_multicast() || pkt.dst_ip.is_unspecified() || is_broadcast {
            insert_syn_passthrough(&mut self.passthrough);
            return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
        }

        // 5. 全新 SYN 首包路由裁决
        let is_fake_ip = fake_ip_pool.is_some_and(|pool| pool.is_fake_ip_addr(pkt.dst_ip));
        let needs_domain_sniff = if is_fake_ip {
            // Fake-IP 在 DNS 阶段已绑定真实域名；由 Dispatcher 还原域名后立即走规则裁决，不空等 120ms 嗅探
            false
        } else if let Some(re) = rule_engine {
            let proc_info = pid.and_then(|p| tracker.and_then(|t| t.resolve_pid(p)));
            let proc_unresolved = pid.is_none() || (tracker.is_some() && proc_info.is_none());
            let proc_path = proc_info.as_ref().map(|i| i.path.as_str());
            let proc_name = proc_info.as_ref().map(|i| i.name.as_str());
            match re.needs_domain_for_routing(proc_path, proc_name, Some(pkt.dst_ip), pkt.dst_port)
            {
                DomainNeedDecision::Immediate(Action::Direct) => {
                    if proc_unresolved
                        && re.has_reachable_app_scoped_override(Some(pkt.dst_ip), pkt.dst_port)
                    {
                        // 首包阶段 PID 或进程名解析缺失但前方存在应用级非 Direct 规则（如 DevProxy）：接入协议栈交由 Dispatcher 异步复核进程归属，绝不盲目永久旁路
                        false
                    } else {
                        insert_syn_passthrough(&mut self.passthrough);
                        return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
                    }
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
            insert_syn_passthrough(&mut self.passthrough);
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
            insert_syn_passthrough(&mut self.passthrough);
            return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
        }
        let handle = self.sockets.add(sock);
        let syn_backup = raw_ip.clone();
        enqueue_tcp_for_smoltcp(&mut self.device.rx_queue, raw_ip);

        let smol_now = self.smol_now();
        self.iface
            .poll(smol_now, &mut self.device, &mut self.sockets);

        let post_state = self.sockets.get::<tcp::Socket>(handle).state();
        if post_state == tcp::State::Listen {
            // SYN 未能被 smoltcp 接受：立即清理并用原 SYN 退回 Passthrough（同时按四元组冲刷并发 TX），严禁静默吞包
            self.sockets.remove(handle);
            self.drain_tx_with_lookup(meta, tx_out);
            insert_syn_passthrough(&mut self.passthrough);
            return TcpIngestOutcome::Passthrough(EmittedIpPacket {
                data: syn_backup,
                meta,
            });
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
                syn_seq: pkt.seq,
                ever_established: matches!(post_state, tcp::State::Established),
                last_state: post_state,
                teardown_since: None,
                time_wait_since: None,
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

                // A. socket -> to_app（先消费缓冲区残余数据）
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

                // F0. Closed 或 SynReceived 遭 RST 退回的 Listen 均表示连接已终止，
                //     必须先于 Step B 处理以免误标干净 EOF 并杜绝僵尸 Listen 槽位劫持后续连接
                if matches!(state, tcp::State::Closed | tcp::State::Listen) {
                    let non_graceful_closed = state == tcp::State::Listen
                        || !matches!(
                            session.last_state,
                            tcp::State::TimeWait
                                | tcp::State::LastAck
                                | tcp::State::Closing
                                | tcp::State::Closed
                        );
                    close_bridge_and_collect_wakers(
                        &mut inner,
                        non_graceful_closed,
                        &mut wake_read,
                        &mut wake_write,
                        &mut wake_flush,
                    );
                    remove_session = true;
                } else {
                    // B. 检测远端（本地应用）是否已发送正常 FIN
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
                                if inner.to_socket.len() < BRIDGE_BUFFER_LIMIT
                                    && wake_write.is_none()
                                {
                                    wake_write = inner.write_waker.take();
                                }
                            }
                            _ => break,
                        }
                    }

                    // E. 非优雅关闭中止检查（先于 Step D！）：双端已弃用且未触发 shutdown() 时立刻 abort 发 RST 并释放槽位
                    let ungraceful_drop = inner.app_read_closed
                        && inner.app_write_closed
                        && !inner.graceful_shutdown
                        && !inner.fin_sent_to_socket;
                    let syn_timed_out = !session.ever_established
                        && state == tcp::State::SynReceived
                        && now.saturating_duration_since(session.created_at)
                            >= SYN_RECEIVED_TIMEOUT;

                    if ungraceful_drop || syn_timed_out {
                        sock.abort();
                        close_bridge_and_collect_wakers(
                            &mut inner,
                            true,
                            &mut wake_read,
                            &mut wake_write,
                            &mut wake_flush,
                        );
                        remove_session = true;
                    } else {
                        // D. 优雅半关闭写端：待 `to_socket` 完全冲刷入 smoltcp 后触发 TCP FIN
                        if inner.app_write_closed
                            && inner.to_socket.is_empty()
                            && !inner.fin_sent_to_socket
                        {
                            sock.close();
                            inner.fin_sent_to_socket = true;
                        }

                        if inner.to_socket.is_empty() && inner.flush_waker.is_some() {
                            wake_flush = inner.flush_waker.take();
                        }

                        // F1. 收割长期滞留的 FinWait1/FinWait2/Closing/LastAck/TimeWait 半关连接，防止 4096 槽位耗尽
                        if state == tcp::State::TimeWait {
                            session.teardown_since = None;
                            let tw_since = *session.time_wait_since.get_or_insert(now);
                            if now.saturating_duration_since(tw_since) >= TIME_WAIT_REAP_TIMEOUT {
                                close_bridge_and_collect_wakers(
                                    &mut inner,
                                    false,
                                    &mut wake_read,
                                    &mut wake_write,
                                    &mut wake_flush,
                                );
                                remove_session = true;
                            }
                        } else if (matches!(state, tcp::State::FinWait1 | tcp::State::FinWait2)
                            && inner.app_read_closed
                            && inner.app_write_closed)
                            || matches!(state, tcp::State::Closing | tcp::State::LastAck)
                        {
                            session.time_wait_since = None;
                            let td_since = *session.teardown_since.get_or_insert(now);
                            if now.saturating_duration_since(td_since) >= TEARDOWN_TIMEOUT {
                                sock.abort();
                                close_bridge_and_collect_wakers(
                                    &mut inner,
                                    true,
                                    &mut wake_read,
                                    &mut wake_write,
                                    &mut wake_flush,
                                );
                                remove_session = true;
                            }
                        } else {
                            session.teardown_since = None;
                            session.time_wait_since = None;
                        }
                    }
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

        // 第二轮 poll：立即将刚写入 smoltcp 发送队列或 close()/abort() FIN/RST 发成 IP 包吐出
        let smol_now = self.smol_now();
        self.iface
            .poll(smol_now, &mut self.device, &mut self.sockets);
        self.drain_tx_with_lookup(PacketInterfaceMeta::default(), tx_out);

        for key in closed_keys {
            if let Some(sess) = self.intercepted.remove(&key) {
                self.sockets.remove(sess.handle);
            }
        }
        for session in self.intercepted.values_mut() {
            session.last_state = self.sockets.get::<tcp::Socket>(session.handle).state();
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

    #[allow(clippy::too_many_arguments)]
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

    fn build_rst(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, seq: u32, ack: u32) -> Vec<u8> {
        let mut hdr = TcpHeader::new(sport, dport, seq, 65535);
        hdr.rst = true;
        hdr.ack = true;
        hdr.acknowledgment_number = ack;
        let builder = PacketBuilder::ipv4(src, dst, 64).tcp_header(hdr);
        let mut out = Vec::with_capacity(builder.size(0));
        builder.write(&mut out, &[]).unwrap();
        out
    }

    fn establish_ipv4_flow(
        engine: &mut NetstackEngine,
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
    ) -> (AcceptedTcpFlow, ParsedTcpPacket) {
        let mut accepted = Vec::new();
        let mut tx = Vec::new();
        let meta = PacketInterfaceMeta {
            if_idx: 3,
            sub_if_idx: 0,
            loopback: false,
            is_ipv6: false,
            bitfield: 0,
        };
        let syn = build_syn(src, sport, dst, dport, 1000);
        assert!(matches!(
            engine.ingest_outbound_tcp(syn, meta, Some(9001), None, None, None, &mut accepted, &mut tx),
            TcpIngestOutcome::Intercepted
        ));
        let syn_ack = parse_tcp_packet(&tx.pop().unwrap().data).unwrap();
        assert!(syn_ack.syn && syn_ack.ack);

        let ack = build_ack(src, sport, dst, dport, 1001, syn_ack.seq + 1, false, &[]);
        assert!(matches!(
            engine.ingest_outbound_tcp(ack, meta, Some(9001), None, None, None, &mut accepted, &mut tx),
            TcpIngestOutcome::Intercepted
        ));
        let flow = accepted.pop().unwrap();
        (flow, syn_ack)
    }

    #[test]
    fn test_netstack_ungraceful_drop_aborts_with_rst_and_frees_slot() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);
        let (flow, _syn_ack) = establish_ipv4_flow(
            &mut engine,
            [192, 168, 1, 20],
            55100,
            [93, 184, 216, 34],
            443,
        );
        assert_eq!(engine.active_flow_count(), 1);

        // 模拟 Dispatcher 因 Action::Block / 拨号失败直接丢弃双端流（未调用 shutdown）
        drop(flow);

        let mut tx = Vec::new();
        engine.pump(&mut tx);

        assert!(
            tx.iter()
                .filter_map(|p| parse_tcp_packet(&p.data))
                .any(|p| p.rst),
            "ungraceful stream drop must emit TCP RST instead of silently sticking in FinWait2"
        );
        assert_eq!(engine.active_flow_count(), 0);
    }

    #[tokio::test]
    async fn test_netstack_reaps_stalled_fin_wait_2_slot_after_teardown_timeout() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);
        let src = [192, 168, 1, 21];
        let dst = [93, 184, 216, 34];
        let sport = 55101;
        let dport = 80;
        let (flow, syn_ack) = establish_ipv4_flow(&mut engine, src, sport, dst, dport);

        let (rd, mut wr) = flow.stream.split_stream();
        drop(rd);

        let writer = tokio::spawn(async move {
            wr.shutdown().await.unwrap();
        });

        // 推进 pump 直到 smoltcp 发送 FIN 并让 writer.shutdown() 完成（进入 FinWait1）
        let mut tx = Vec::new();
        let mut fin_pkt = None;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            engine.pump(&mut tx);
            for p in tx.drain(..) {
                if let Some(parsed) = parse_tcp_packet(&p.data)
                    && parsed.fin
                {
                    fin_pkt = Some(parsed);
                }
            }
            if writer.is_finished() && fin_pkt.is_some() {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "Timed out waiting for graceful FIN");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        writer.await.unwrap();

        // 客户端仅 ACK 我方 FIN 而不回 FIN -> smoltcp 进入 FinWait2
        let fin_parsed = fin_pkt.unwrap();
        let ack_only = build_ack(
            src,
            sport,
            dst,
            dport,
            1001,
            fin_parsed.seq.wrapping_add(1),
            false,
            &[],
        );
        let mut accepted = Vec::new();
        let _ = engine.ingest_outbound_tcp(
            ack_only,
            PacketInterfaceMeta::default(),
            Some(9001),
            None,
            None,
            None,
            &mut accepted,
            &mut tx,
        );
        tx.clear();

        let t0 = Instant::now();
        engine.pump_internal(t0, &mut tx);
        assert_eq!(engine.active_flow_count(), 1);
        let key = TcpFlowKey::new(IpAddr::from(src), sport, IpAddr::from(dst), dport);
        assert_eq!(
            engine
                .sockets
                .get::<tcp::Socket>(engine.intercepted.get(&key).unwrap().handle)
                .state(),
            tcp::State::FinWait2
        );

        // 超过 TEARDOWN_TIMEOUT 后应自动 abort 并回收 FinWait2 槽位
        engine.pump_internal(t0 + TEARDOWN_TIMEOUT + Duration::from_millis(50), &mut tx);
        assert_eq!(engine.active_flow_count(), 0);
        assert!(
            tx.iter()
                .filter_map(|p| parse_tcp_packet(&p.data))
                .any(|p| p.rst)
        );
        let _ = syn_ack;
    }

    #[tokio::test]
    async fn test_netstack_established_rst_wakes_and_fails_write_flush_shutdown_and_read() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);
        let src = [192, 168, 1, 22];
        let dst = [93, 184, 216, 34];
        let sport = 55102;
        let dport = 443;
        let (flow, syn_ack) = establish_ipv4_flow(&mut engine, src, sport, dst, dport);
        let (mut rd, mut wr) = flow.stream.split_stream();

        // 先写入超过桥梁+窗口容量的数据并等待 write_all 因背压进入 Poll::Pending
        let fill = vec![b'Z'; BRIDGE_BUFFER_LIMIT];
        wr.write_all(&fill).await.unwrap();

        let (tx_wr_done, rx_wr_done) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let w_res = wr.write_all(&[b'Q'; 32]).await;
            let s_res = wr.shutdown().await;
            let _ = tx_wr_done.send((w_res, s_res));
        });
        tokio::task::yield_now().await;

        let (tx_rd_done, rx_rd_done) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut buf = [0u8; 16];
            let r_res = rd.read(&mut buf).await;
            let _ = tx_rd_done.send(r_res);
        });
        tokio::task::yield_now().await;

        // 已建连会话收到客户端 RST：必须立即唤醒并报错，绝不能挂起到 120s 空闲超时
        let rst = build_rst(src, sport, dst, dport, 1001, syn_ack.seq + 1);
        let mut accepted = Vec::new();
        let mut tx = Vec::new();
        let _ = engine.ingest_outbound_tcp(
            rst,
            PacketInterfaceMeta::default(),
            Some(9001),
            None,
            None,
            None,
            &mut accepted,
            &mut tx,
        );

        let (w_res, s_res) = tokio::time::timeout(Duration::from_secs(1), rx_wr_done)
            .await
            .expect("poll_write / poll_shutdown must wake immediately on RST")
            .unwrap();
        assert_eq!(w_res.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(s_res.unwrap_err().kind(), io::ErrorKind::ConnectionReset);

        let r_res = tokio::time::timeout(Duration::from_secs(1), rx_rd_done)
            .await
            .expect("poll_read must wake immediately on RST")
            .unwrap();
        assert_eq!(r_res.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(engine.active_flow_count(), 0);
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

    #[test]
    fn test_netstack_unknown_pid_does_not_bypass_app_scoped_proxy_rule() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);
        let engine_rules = RuleEngine::new(
            vec![
                Rule::from_raw(
                    "LocalBypass",
                    true,
                    None,
                    Some("192.168.0.0/16"),
                    None,
                    Action::Direct,
                ),
                Rule::from_raw(
                    "DevProxy",
                    true,
                    Some("chrome.exe"),
                    None,
                    None,
                    Action::Proxy(101),
                ),
            ],
            Action::Direct,
        );

        let meta = PacketInterfaceMeta::default();
        let mut accepted = Vec::new();
        let mut tx = Vec::new();

        // 1. pid = None 访问 192.168/16：无条件全局 Direct 已命中，允许直接 Passthrough
        let syn_lan = build_syn([10, 0, 0, 2], 51200, [192, 168, 1, 5], 80, 100);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn_lan,
                meta,
                None,
                Some(&engine_rules),
                None,
                None,
                &mut accepted,
                &mut tx,
            ),
            TcpIngestOutcome::Passthrough(_)
        ));

        // 2. pid = None 访问公网 8.8.8.8:443：因前方存在 DevProxy (chrome.exe -> Proxy)，绝不盲目放行写入 passthrough
        let syn_pub = build_syn([10, 0, 0, 2], 51201, [8, 8, 8, 8], 443, 200);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn_pub,
                meta,
                None,
                Some(&engine_rules),
                None,
                None,
                &mut accepted,
                &mut tx,
            ),
            TcpIngestOutcome::Intercepted
        ));
        assert_eq!(engine.active_flow_count(), 1);

        // 3. 当提供真实 ProcessTracker 但 PID = Some(999999) 已退出无法解析进程路径/名称时，
        //    proc_unresolved 必须生效并接入协议栈复核，不得误写 passthrough 绕过 DevProxy
        let real_tracker = ProcessTracker::new();
        let syn_dead_pid = build_syn([10, 0, 0, 2], 51202, [8, 8, 8, 8], 443, 300);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn_dead_pid,
                meta,
                Some(999_999),
                Some(&engine_rules),
                Some(&real_tracker),
                None,
                &mut accepted,
                &mut tx,
            ),
            TcpIngestOutcome::Intercepted
        ));
        assert_eq!(engine.active_flow_count(), 2);
    }

    #[test]
    fn test_netstack_listen_fallback_returns_original_syn_and_preserves_tx_meta() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);

        // 先建立一条来自接口 7 的活跃流并写入下行响应，使 device.tx_queue 或 pump 期间有不同接口元数据
        let meta_existing = PacketInterfaceMeta {
            if_idx: 7,
            sub_if_idx: 1,
            loopback: false,
            is_ipv6: false,
            bitfield: 1,
        };
        let mut accepted = Vec::new();
        let mut tx = Vec::new();
        let syn_ok = build_syn([10, 0, 0, 2], 52001, [1, 1, 1, 1], 443, 100);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn_ok,
                meta_existing,
                Some(9001),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        let syn_ack = parse_tcp_packet(&tx.pop().unwrap().data).unwrap();
        let ack_ok = build_ack(
            [10, 0, 0, 2],
            52001,
            [1, 1, 1, 1],
            443,
            101,
            syn_ack.seq + 1,
            false,
            b"PING",
        );
        assert!(matches!(
            engine.ingest_outbound_tcp(
                ack_ok,
                meta_existing,
                Some(9001),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        let flow = accepted.pop().unwrap();
        {
            let mut inner = flow.stream.write.bridge.inner.lock().unwrap();
            inner.to_socket.extend(b"PONG");
        }
        // 在 smoltcp 下一次 poll 前故意触发 tx_queue 仅待 pump 时由另一流退回 Listen
        let flow_tx_before_listen = {
            // 将待发数据注入 smoltcp socket 缓冲区（不立即 poll 以便在 Listen fallback poll 中一并吐出）
            let key_existing = TcpFlowKey::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                52001,
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                443,
            );
            let sess = engine.intercepted.get(&key_existing).unwrap();
            let sock = engine.sockets.get_mut::<tcp::Socket>(sess.handle);
            let sent = sock.send_slice(b"RESP").unwrap();
            assert_eq!(sent, 4);
            true
        };
        assert!(flow_tx_before_listen);

        // 构造一条 etherparse 可解析、但包含非法 TCP MSS 选项长度（kind=2, len=1）导致 smoltcp 拒收留在 Listen 的 SYN
        let mut hdr = TcpHeader::new(52002, 80, 777, 65535);
        hdr.syn = true;
        hdr.set_options_raw(&[2, 1, 0, 0]).unwrap();
        let builder = PacketBuilder::ipv4([10, 0, 0, 9], [93, 184, 216, 34], 64).tcp_header(hdr);
        let mut malformed_syn = Vec::with_capacity(builder.size(0));
        builder.write(&mut malformed_syn, &[]).unwrap();
        let expected_syn_bytes = malformed_syn.clone();

        let meta_bad_syn = PacketInterfaceMeta {
            if_idx: 19,
            sub_if_idx: 2,
            loopback: false,
            is_ipv6: false,
            bitfield: 9,
        };
        tx.clear();
        let outcome = engine.ingest_outbound_tcp(
            malformed_syn,
            meta_bad_syn,
            Some(9002),
            None,
            None,
            None,
            &mut accepted,
            &mut tx,
        );
        // P1-5 修复断言 1：不得静默丢弃 SYN，必须原样以 Passthrough(syn_backup) 返回
        let TcpIngestOutcome::Passthrough(emitted) = outcome else {
            panic!("expected Passthrough fallback when smoltcp rejects malformed SYN");
        };
        assert_eq!(emitted.data, expected_syn_bytes);
        assert_eq!(emitted.meta.if_idx, 19);
        assert!(accepted.is_empty());
        // 仅应保留第一条已建连会话，失败 Listen 句柄必须已销毁
        assert_eq!(engine.active_flow_count(), 1);
        // P1-5 修复断言 2：并发期间经由 drain_tx_with_lookup 冲刷的第一条流报文必须保留其接口 7 元数据而非混用接口 19
        let resp_pkt = tx
            .iter()
            .find(|p| parse_tcp_packet(&p.data).is_some_and(|t| t.dst_port == 52001))
            .expect("expected existing flow TX packet flushed during fallback poll");
        assert_eq!(resp_pkt.meta.if_idx, 7);
    }

    #[test]
    fn test_netstack_passthrough_invalidated_on_rst_new_syn_seq_and_socket_close() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);
        let direct_rules = RuleEngine::new(vec![], Action::Direct);
        let proxy_rules = RuleEngine::new(vec![], Action::Proxy(101));

        let meta = PacketInterfaceMeta::default();
        let mut accepted = Vec::new();
        let mut tx = Vec::new();

        let src = [10, 0, 0, 2];
        let sport = 53100;
        let dst = [93, 184, 216, 34];
        let dport = 443;

        // 1. 首次 Direct 命中，记录 passthrough (syn_seq = 1000)
        let syn1 = build_syn(src, sport, dst, dport, 1000);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn1.clone(),
                meta,
                Some(1234),
                Some(&direct_rules),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Passthrough(_)
        ));
        // 同 seq 重传 SYN 即使切了 Proxy 规则仍保持同一连接快路径放行
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn1,
                meta,
                Some(1234),
                Some(&proxy_rules),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Passthrough(_)
        ));

        // 2. 端口快速复用发起不同 ISN (seq = 2000) 的全新 SYN：必须失效旧 passthrough 并按新规则接入劫持
        let syn2 = build_syn(src, sport, dst, dport, 2000);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn2,
                meta,
                Some(1234),
                Some(&proxy_rules),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        assert_eq!(engine.active_flow_count(), 1);
        accepted.clear();
        tx.clear();

        // 3. 测试 RST 立即清除 passthrough（改用端口 53101）
        let syn3 = build_syn(src, 53101, dst, dport, 3000);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn3.clone(),
                meta,
                Some(1234),
                Some(&direct_rules),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Passthrough(_)
        ));
        let rst = build_rst(src, 53101, dst, dport, 3001, 0);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                rst,
                meta,
                Some(1234),
                Some(&proxy_rules),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Passthrough(_)
        ));
        // Even same seq after RST must re-evaluate rules and intercept under proxy_rules
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn3,
                meta,
                Some(1234),
                Some(&proxy_rules),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));

        // 4. 测试 SOCKET 层 SocketClose 通知按本地端点精确清缓存（端口 53102）
        let syn4 = build_syn(src, 53102, dst, dport, 4000);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn4.clone(),
                meta,
                Some(1234),
                Some(&direct_rules),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Passthrough(_)
        ));
        engine.invalidate_passthrough_for_local_endpoint(IpAddr::V4(Ipv4Addr::from(src)), 53102);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn4,
                meta,
                Some(1234),
                Some(&proxy_rules),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
    }

    #[tokio::test]
    async fn test_netstack_intercepted_teardown_flow_retired_on_fresh_syn() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(Arc::clone(&signal));
        let src = [10, 0, 0, 2];
        let sport = 54000;
        let dst = [93, 184, 216, 34];
        let dport = 443;

        let (flow1, syn_ack1) = establish_ipv4_flow(&mut engine, src, sport, dst, dport);
        let (mut rd1, mut wr1) = flow1.stream.split_stream();
        // 客户端先发 FIN，应用端发 FIN（进入 TimeWait/FinWait2/LastAck 退场期）
        let meta = PacketInterfaceMeta::default();
        let mut accepted = Vec::new();
        let mut tx = Vec::new();
        let mut fin_hdr = TcpHeader::new(sport, dport, 1001, 65535);
        fin_hdr.ack = true;
        fin_hdr.fin = true;
        fin_hdr.acknowledgment_number = syn_ack1.seq + 1;
        let builder = PacketBuilder::ipv4(src, dst, 64).tcp_header(fin_hdr);
        let mut fin_pkt = Vec::with_capacity(builder.size(0));
        builder.write(&mut fin_pkt, &[]).unwrap();
        assert!(matches!(
            engine.ingest_outbound_tcp(fin_pkt, meta, Some(9001), None, None, None, &mut accepted, &mut tx),
            TcpIngestOutcome::Intercepted
        ));

        let sh = tokio::spawn(async move {
            wr1.shutdown().await.unwrap();
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while !sh.is_finished() {
            tx.clear();
            engine.pump(&mut tx);
            assert!(tokio::time::Instant::now() < deadline, "Timed out waiting for shutdown pump");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        sh.await.unwrap();
        let mut buf = [0u8; 32];
        assert_eq!(rd1.read(&mut buf).await.unwrap(), 0);

        // 在 TIME_WAIT_REAP_TIMEOUT (2s) 到期前，立即以同一四元组和全新 ISN (seq = 9000) 建连
        tx.clear();
        accepted.clear();
        let syn2 = build_syn(src, sport, dst, dport, 9000);
        assert!(matches!(
            engine.ingest_outbound_tcp(syn2, meta, Some(9001), None, None, None, &mut accepted, &mut tx),
            TcpIngestOutcome::Intercepted
        ));
        // 不得生成延迟 RST 误伤新生 SYN，应直接返回新 SYN/ACK 且接受新连接
        assert!(!tx.iter().any(|p| parse_tcp_packet(&p.data).is_some_and(|t| t.rst)));
        let syn_ack2 = tx
            .iter()
            .filter_map(|p| parse_tcp_packet(&p.data))
            .find(|t| t.syn && t.ack)
            .expect("expected fresh SYN/ACK on reused 4-tuple");
        assert_eq!(syn_ack2.ack_num, 9001);
        assert_eq!(accepted.len(), 1);
        assert_eq!(engine.active_flow_count(), 1);
    }

    #[test]
    fn test_netstack_signal_wakes_and_drains_closed_tcp_endpoints() {
        let signal = Arc::new(NetstackSignal::new());
        let local_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        signal.push_closed_tcp_endpoint(local_ip, 55123);
        let mut pkts = Vec::new();
        let mut closed = Vec::new();
        assert!(signal.wait_drain_or_timeout(Duration::from_millis(50), &mut pkts, &mut closed));
        assert!(pkts.is_empty());
        assert_eq!(closed, vec![(local_ip, 55123)]);
    }

    #[tokio::test]
    async fn test_netstack_syn_received_rst_reverts_to_listen_is_reaped_and_does_not_hijack_next_syn() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);
        let meta = PacketInterfaceMeta::default();
        let mut accepted = Vec::new();
        let mut tx = Vec::new();

        let src = [10, 0, 0, 2];
        let sport = 54111;
        let dst = [93, 184, 216, 34];
        let dport = 443;

        // 1. 仅完成 SYN -> SYN/ACK，使 socket 停留在 SynReceived（非零 listen_ep）
        let syn1 = build_syn(src, sport, dst, dport, 1000);
        assert!(matches!(
            engine.ingest_outbound_tcp(syn1, meta, Some(9001), None, None, None, &mut accepted, &mut tx),
            TcpIngestOutcome::Intercepted
        ));
        let syn_ack1 = parse_tcp_packet(&tx.pop().unwrap().data).unwrap();
        let flow1 = accepted.pop().unwrap();
        assert_eq!(engine.active_flow_count(), 1);

        // 2. 客户端在 SynReceived 阶段发送 RST（如 Chrome 取消预连接）：smoltcp 会将该句柄重置回 State::Listen
        let rst = build_rst(src, sport, dst, dport, 1001, syn_ack1.seq + 1);
        assert!(matches!(
            engine.ingest_outbound_tcp(rst, meta, Some(9001), None, None, None, &mut accepted, &mut tx),
            TcpIngestOutcome::Intercepted
        ));

        // 必须立即触发 Step F0 摘除该僵尸 Listen 槽位并向调度器唤醒报错，而非误标 EOF 或泄露槽位
        assert_eq!(engine.active_flow_count(), 0);
        assert!(engine.sockets.iter().count() == 0);

        let (mut rd, mut wr) = flow1.stream.split_stream();
        let mut buf = [0u8; 16];
        let rerr = rd.read(&mut buf).await.unwrap_err();
        assert_eq!(rerr.kind(), io::ErrorKind::ConnectionReset);
        let werr = wr.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap_err();
        assert_eq!(werr.kind(), io::ErrorKind::ConnectionReset);

        // 3. 不同源端口再连同一个 (dst_ip, dst_port)：不得被僵尸 Listen 句柄抢占触发回退 Passthrough
        tx.clear();
        accepted.clear();
        let syn2 = build_syn(src, 54112, dst, dport, 2000);
        assert!(matches!(
            engine.ingest_outbound_tcp(syn2, meta, Some(9001), None, None, None, &mut accepted, &mut tx),
            TcpIngestOutcome::Intercepted
        ));
        assert_eq!(accepted.len(), 1);
        assert_eq!(engine.active_flow_count(), 1);
        let syn_ack2 = parse_tcp_packet(&tx.pop().unwrap().data).unwrap();
        assert!(syn_ack2.syn && syn_ack2.ack && syn_ack2.ack_num == 2001);
    }

    #[test]
    fn test_netstack_lso_over_64kb_and_zero_header_len_ipv4_and_ipv6() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);

        // 1. IPv4 70,000B LSO 包（Total Length = 0，总长 > 65,535，启用 WSCALE 窗口扩大以容纳 >64KB 单次突发）
        let meta4 = PacketInterfaceMeta {
            if_idx: 3,
            sub_if_idx: 0,
            loopback: false,
            is_ipv6: false,
            bitfield: 0,
        };
        let mut accepted = Vec::new();
        let mut tx = Vec::new();
        let mut syn4_hdr = TcpHeader::new(56001, 443, 1000, 65535);
        syn4_hdr.syn = true;
        syn4_hdr.set_options_raw(&[3, 3, 8, 1]).unwrap();
        let syn4_b = PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64).tcp_header(syn4_hdr);
        let mut syn4 = Vec::with_capacity(syn4_b.size(0));
        syn4_b.write(&mut syn4, &[]).unwrap();
        assert!(matches!(
            engine.ingest_outbound_tcp(syn4, meta4, Some(8888), None, None, None, &mut accepted, &mut tx),
            TcpIngestOutcome::Intercepted
        ));
        let syn_ack4 = parse_tcp_packet(&tx.pop().unwrap().data).unwrap();
        let ack4 = build_ack([10, 0, 0, 2], 56001, [1, 1, 1, 1], 443, 1001, syn_ack4.seq + 1, false, &[]);
        assert!(matches!(
            engine.ingest_outbound_tcp(ack4, meta4, Some(8888), None, None, None, &mut accepted, &mut tx),
            TcpIngestOutcome::Intercepted
        ));
        let flow4 = accepted.pop().unwrap();

        let payload4 = vec![0x5Au8; 70_000];
        let mut hdr4 = TcpHeader::new(56001, 443, 1001, 65535);
        hdr4.ack = true;
        hdr4.psh = true;
        hdr4.acknowledgment_number = syn_ack4.seq + 1;
        let lso4 = PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64).tcp_header(hdr4);
        let mut pkt4 = Vec::with_capacity(20 + 20 + payload4.len());
        lso4.write(&mut pkt4, &payload4[..1000]).unwrap();
        // 手动拼接完整 70,000 字节并按 NDIS LSO 规范将 IPv4 Total Length 置 0
        pkt4.extend_from_slice(&payload4[1000..]);
        pkt4[2..4].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(pkt4.len(), 20 + 20 + 70_000);

        let parsed4 = parse_tcp_packet(&pkt4).expect("IPv4 LSO >64KB with total_len=0 must parse");
        assert_eq!(parsed4.payload_len, 70_000);

        tx.clear();
        accepted.clear();
        assert!(matches!(
            engine.ingest_outbound_tcp(
                pkt4,
                meta4,
                Some(8888),
                None,
                None,
                None,
                &mut accepted,
                &mut tx,
            ),
            TcpIngestOutcome::Intercepted
        ));
        {
            let inner = flow4.stream.read.bridge.inner.lock().unwrap();
            assert_eq!(inner.to_app.len(), 70_000);
            assert!(inner.to_app.iter().all(|&b| b == 0x5A));
        }

        // 2. IPv6 70,000B LSO 包（Payload Length = 0，总长 > 65,575）
        let src6 = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6);
        let dst6 = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let meta6 = PacketInterfaceMeta {
            if_idx: 2,
            is_ipv6: true,
            ..Default::default()
        };
        let mut syn6_hdr = TcpHeader::new(61122, 443, 8000, 65535);
        syn6_hdr.syn = true;
        syn6_hdr.set_options_raw(&[3, 3, 8, 1]).unwrap();
        let syn6_b = PacketBuilder::ipv6(src6.octets(), dst6.octets(), 64).tcp_header(syn6_hdr);
        let mut syn6 = Vec::with_capacity(syn6_b.size(0));
        syn6_b.write(&mut syn6, &[]).unwrap();
        tx.clear();
        accepted.clear();
        assert!(matches!(
            engine.ingest_outbound_tcp(syn6, meta6, Some(8889), None, None, None, &mut accepted, &mut tx),
            TcpIngestOutcome::Intercepted
        ));
        let syn_ack6 = parse_tcp_packet(&tx.pop().unwrap().data).unwrap();
        let mut ack6_hdr = TcpHeader::new(61122, 443, 8001, 65535);
        ack6_hdr.ack = true;
        ack6_hdr.acknowledgment_number = syn_ack6.seq + 1;
        let ack6_builder =
            PacketBuilder::ipv6(src6.octets(), dst6.octets(), 64).tcp_header(ack6_hdr);
        let mut ack6 = Vec::with_capacity(ack6_builder.size(0));
        ack6_builder.write(&mut ack6, &[]).unwrap();
        assert!(matches!(
            engine.ingest_outbound_tcp(ack6, meta6, Some(8889), None, None, None, &mut accepted, &mut tx),
            TcpIngestOutcome::Intercepted
        ));
        let flow6 = accepted.pop().unwrap();

        let payload6 = vec![0x3Cu8; 70_000];
        let mut hdr6 = TcpHeader::new(61122, 443, 8001, 65535);
        hdr6.ack = true;
        hdr6.psh = true;
        hdr6.acknowledgment_number = syn_ack6.seq + 1;
        let lso6 = PacketBuilder::ipv6(src6.octets(), dst6.octets(), 64).tcp_header(hdr6);
        let mut pkt6 = Vec::with_capacity(40 + 20 + payload6.len());
        lso6.write(&mut pkt6, &payload6[..1000]).unwrap();
        pkt6.extend_from_slice(&payload6[1000..]);
        pkt6[4..6].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(pkt6.len(), 40 + 20 + 70_000);

        let parsed6 = parse_tcp_packet(&pkt6).expect("IPv6 LSO >64KB with payload_len=0 must parse");
        assert_eq!(parsed6.payload_len, 70_000);
        assert!(matches!(
            engine.ingest_outbound_tcp(pkt6, meta6, Some(8889), None, None, None, &mut accepted, &mut tx),
            TcpIngestOutcome::Intercepted
        ));
        {
            let inner = flow6.stream.read.bridge.inner.lock().unwrap();
            assert_eq!(inner.to_app.len(), 70_000);
            assert!(inner.to_app.iter().all(|&b| b == 0x3C));
        }
    }

    #[test]
    fn test_fragmented_tcp_passthrough_preserves_original_fragments_and_ext_headers() {
        use crate::transparent::fragment::{FragmentOutcome, FragmentTracker};

        let src6 = Ipv6Addr::new(0x2001, 0xdb8, 10, 20, 0, 0, 0, 1);
        let dst6 = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);

        let mut syn_hdr = TcpHeader::new(59111, 443, 123456, 65535);
        syn_hdr.syn = true;
        let payload = vec![0xABu8; 16];
        let builder = PacketBuilder::ipv6(src6.octets(), dst6.octets(), 64).tcp_header(syn_hdr);
        let mut base_tcp = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut base_tcp, &payload).unwrap();
        let tcp_seg = &base_tcp[40..];

        // 构造带后置 DestOpt (nh=60 -> TCP 6) 扩展头的两片 IPv6 分片包
        let mut fragmentable = Vec::with_capacity(8 + tcp_seg.len());
        fragmentable.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
        fragmentable.extend_from_slice(tcp_seg);

        let make_frag = |off: usize, mf: bool, chunk: &[u8]| -> Vec<u8> {
            let mut out = Vec::with_capacity(40 + 8 + chunk.len());
            out.extend_from_slice(&[0x60, 0, 0, 0]);
            out.extend_from_slice(&((8 + chunk.len()) as u16).to_be_bytes());
            out.push(44);
            out.push(64);
            out.extend_from_slice(&src6.octets());
            out.extend_from_slice(&dst6.octets());
            out.push(60); // post-Fragment DestOpt
            out.push(0);
            let off_m = ((off as u16) & 0xFFF8) | if mf { 1 } else { 0 };
            out.extend_from_slice(&off_m.to_be_bytes());
            out.extend_from_slice(&0x5566_7788u32.to_be_bytes());
            out.extend_from_slice(chunk);
            out
        };
        let frag0 = make_frag(0, true, &fragmentable[..24]);
        let frag1 = make_frag(24, false, &fragmentable[24..]);

        let frag_meta = PacketInterfaceMeta {
            if_idx: 7,
            sub_if_idx: 2,
            loopback: false,
            is_ipv6: true,
            bitfield: 0x0100,
        };
        let mut tracker = FragmentTracker::new();
        assert!(matches!(
            tracker.ingest(&frag0, frag_meta, None),
            FragmentOutcome::Pending
        ));
        let FragmentOutcome::Reassembled {
            full_packet,
            orig_fragments,
        } = tracker.ingest(&frag1, frag_meta, None)
        else {
            panic!("expected reassembled IPv6 TCP packet");
        };
        assert_eq!(orig_fragments.len(), 2);

        // 模拟 NetRxContext -> NetstackSignal -> NetstackEngine(Action::Direct -> Passthrough)
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(Arc::clone(&signal));
        signal.push_outbound_tcp_with_fragments(
            full_packet,
            frag_meta,
            Some(9999),
            Some(orig_fragments.clone()),
        );
        let mut drained = Vec::new();
        let mut closed = Vec::new();
        assert!(signal.wait_drain_or_timeout(Duration::from_millis(50), &mut drained, &mut closed));
        assert_eq!(drained.len(), 1);
        let item = drained.pop().unwrap();

        let re = RuleEngine::new(Vec::new(), Action::Direct);
        let mut accepted = Vec::new();
        let mut tx = Vec::new();
        let outcome = engine.ingest_outbound_tcp(
            item.raw_ip,
            item.meta,
            item.pid,
            Some(&re),
            None,
            None,
            &mut accepted,
            &mut tx,
        );
        let TcpIngestOutcome::Passthrough(single_pkt) = outcome else {
            panic!("Direct rule must return TcpIngestOutcome::Passthrough");
        };
        assert!(accepted.is_empty());

        let emitted = select_passthrough_packets(single_pkt, item.orig_fragments);
        assert_eq!(emitted.len(), 2, "must emit exact original fragments instead of stripped single packet");
        assert_eq!(emitted[0].data, frag0);
        assert_eq!(emitted[1].data, frag1);
        assert_eq!(emitted[0].meta.if_idx, 7);
        assert_eq!(emitted[0].meta.sub_if_idx, 2);
        assert_eq!(emitted[0].data[6], 44, "original Fragment header must stay intact");
        assert_eq!(emitted[0].data[40], 60, "original DestOpt extension header must stay intact");
    }
}
