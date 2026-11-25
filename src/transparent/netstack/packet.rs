use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use etherparse::{
    NetSlice, PacketBuilder, SlicedPacket, TcpHeader, TcpHeaderSlice, TransportSlice,
};

pub(super) const MAX_SMOLTCP_TCP_SEG_PAYLOAD: usize = 32_768;

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
            let src_ip = IpAddr::V4(Ipv4Addr::new(
                raw_ip[12], raw_ip[13], raw_ip[14], raw_ip[15],
            ))
            .to_canonical();
            let dst_ip = IpAddr::V4(Ipv4Addr::new(
                raw_ip[16], raw_ip[17], raw_ip[18], raw_ip[19],
            ))
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
            let lso_override = (hdr_payload_len == 0 && raw_ip.len() > 40)
                || raw_ip.len() > 40 + u16::MAX as usize;
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
pub(super) fn enqueue_tcp_for_smoltcp(rx_queue: &mut VecDeque<Vec<u8>>, raw_ip: Vec<u8>) {
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
    for (idx, chunk) in parsed
        .payload
        .chunks(MAX_SMOLTCP_TCP_SEG_PAYLOAD)
        .enumerate()
    {
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
