use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use etherparse::PacketBuilder;

use crate::dns::FakeIpPool;
use crate::dns::server::{
    DnsPacketParser, DnsQuestion, observe_passive_dns_response, peek_dns_response_key,
};
use crate::interceptor::process::ProcessTracker;
use crate::outbound::bypass::is_udp_port_bypassed_for_family;
use crate::router::{Action, DnsHijackDecision, DomainNeedDecision, RuleEngine};

const MAX_PENDING_INSPECT_DNS: usize = 4096;
const PENDING_INSPECT_DNS_TTL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct InspectDnsKey {
    client_ip: IpAddr,
    server_ip: IpAddr,
    client_port: u16,
    server_port: u16,
    tx_id: u16,
    qtype: u16,
}

#[derive(Debug, Clone)]
struct PendingInspectEntry {
    question: DnsQuestion,
    recorded_at: Instant,
}

/// 严格被动观测表：记录放行（`emit_passthrough`）的出站 `InspectDns` 查询元组，
/// 由独立的 `DNS_INSPECT_LAYER_FLAGS = 0` 入站内联观测线程（依赖 WinDivert 2.2 原生入站分片重组）匹配真实 DNS 响应、
/// 同步学习 `real_ip -> domain` 后再无条件原样重注入 OS，绝不篡改或丢弃超长 EDNS0 或 VPN/多宿主/`fe80::` DNS 响应。
#[derive(Debug, Default)]
pub struct PendingInspectDnsTable {
    entries: Mutex<HashMap<InspectDnsKey, PendingInspectEntry>>,
}

impl PendingInspectDnsTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_outbound_query(
        &self,
        client_ip: IpAddr,
        server_ip: IpAddr,
        client_port: u16,
        server_port: u16,
        query_payload: &[u8],
    ) -> bool {
        self.record_outbound_query_at(
            Instant::now(),
            client_ip,
            server_ip,
            client_port,
            server_port,
            query_payload,
        )
    }

    pub(crate) fn record_outbound_query_at(
        &self,
        now: Instant,
        client_ip: IpAddr,
        server_ip: IpAddr,
        client_port: u16,
        server_port: u16,
        query_payload: &[u8],
    ) -> bool {
        let Ok((tx_id, question)) = DnsPacketParser::parse_question(query_payload) else {
            return false;
        };
        if !matches!(question.qtype, 1 | 28) || question.qclass != 1 {
            return false;
        }
        let key = InspectDnsKey {
            client_ip: client_ip.to_canonical(),
            server_ip: server_ip.to_canonical(),
            client_port,
            server_port,
            tx_id,
            qtype: question.qtype,
        };
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_PENDING_INSPECT_DNS && !map.contains_key(&key) {
            map.retain(|_, v| {
                now.saturating_duration_since(v.recorded_at) <= PENDING_INSPECT_DNS_TTL
            });
            if map.len() >= MAX_PENDING_INSPECT_DNS
                && let Some(oldest_key) = map
                    .iter()
                    .min_by_key(|(_, v)| v.recorded_at)
                    .map(|(k, _)| *k)
            {
                map.remove(&oldest_key);
            }
        }
        map.insert(
            key,
            PendingInspectEntry {
                question,
                recorded_at: now,
            },
        );
        true
    }

    pub fn observe_inbound_response(
        &self,
        server_ip: IpAddr,
        client_ip: IpAddr,
        server_port: u16,
        client_port: u16,
        resp_payload: &[u8],
        fake_ip_pool: &FakeIpPool,
    ) -> bool {
        self.observe_inbound_response_at(
            Instant::now(),
            server_ip,
            client_ip,
            server_port,
            client_port,
            resp_payload,
            fake_ip_pool,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn observe_inbound_response_at(
        &self,
        now: Instant,
        server_ip: IpAddr,
        client_ip: IpAddr,
        server_port: u16,
        client_port: u16,
        resp_payload: &[u8],
        fake_ip_pool: &FakeIpPool,
    ) -> bool {
        let Some((tx_id, qname_lower, qtype, qclass)) = peek_dns_response_key(resp_payload) else {
            return false;
        };
        if !matches!(qtype, 1 | 28) || qclass != 1 {
            return false;
        }
        let key = InspectDnsKey {
            client_ip: client_ip.to_canonical(),
            server_ip: server_ip.to_canonical(),
            client_port,
            server_port,
            tx_id,
            qtype,
        };
        let entry = {
            let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            let matched = map.get(&key).is_some_and(|e| {
                now.saturating_duration_since(e.recorded_at) <= PENDING_INSPECT_DNS_TTL
                    && e.question.name.eq_ignore_ascii_case(&qname_lower)
            });
            if matched {
                map.remove(&key)
            } else {
                if map.get(&key).is_some_and(|e| {
                    now.saturating_duration_since(e.recorded_at) > PENDING_INSPECT_DNS_TTL
                }) {
                    map.remove(&key);
                }
                None
            }
        };
        let Some(entry) = entry else {
            return false;
        };
        observe_passive_dns_response(fake_ip_pool, tx_id, &entry.question, resp_payload)
    }
}

/// 同步观测一条由 WinDivert 交付的完整入站 IP 报文（含 WinDivert 2.2 在 `flags = 0` 下原生重组后的大包 EDNS0/DNSSEC UDP/53 应答）。
/// 调用方必须在完成本函数调用后再将原始报文 `raw` 原样重注入系统网络栈，从而建立严格的 `happens-before` 顺序，
/// 彻底消除高并发下「入站 DNS 应答落盘 vs 业务进程 TCP SYN」竞态；无论返回 `true` 或 `false`，调用方都无条件原样重注入。
pub fn observe_inbound_dns_packet_for_inspect(
    raw: &[u8],
    inspect_table: &PendingInspectDnsTable,
    fake_ip_pool: &FakeIpPool,
) -> bool {
    let Some(udp) = parse_udp_packet(raw) else {
        return false;
    };
    if udp.src_port != 53 {
        return false;
    }
    inspect_table.observe_inbound_response(
        udp.src_ip,
        udp.dst_ip,
        udp.src_port,
        udp.dst_port,
        udp.payload,
        fake_ip_pool,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpDecision {
    Passthrough,
    DropQuic,
    DropFakeIp,
    HandleDns,
    InspectDns,
}

/// 识别代表系统共享 DNS 解析器（如 Windows `svchost.exe` DNS Client）发起 UDP/53 查询的进程
pub fn is_shared_system_dns_process(
    process_path: Option<&str>,
    process_name: Option<&str>,
) -> bool {
    let base = process_name.filter(|s| !s.trim().is_empty()).or_else(|| {
        process_path.and_then(|p| p.rsplit(['\\', '/']).next().filter(|s| !s.is_empty()))
    });
    let Some(name) = base.map(str::trim) else {
        return false;
    };
    name.eq_ignore_ascii_case("svchost.exe")
        || name.eq_ignore_ascii_case("svchost")
        || name.eq_ignore_ascii_case("dnscache")
}

/// 从原始 IP 数据包中解析出的轻量 UDP 视图（兼容 IPv4 与 IPv6，自动剔除分片报文）
#[derive(Debug, Clone, Copy)]
pub struct ParsedUdpPacket<'a> {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
    pub is_ipv6: bool,
}

#[inline]
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

/// 解析原始 IPv4/IPv6 UDP 报文（支持 IPv6 扩展头 0/43/51/60/135/139/140 及 Windows 卸载 `length == 0` 包）；
/// 分片包、截断畸形包或非 UDP 报文返回 `None`
pub fn parse_udp_packet(raw_ip: &[u8]) -> Option<ParsedUdpPacket<'_>> {
    let ver = raw_ip.first()? >> 4;
    let (src_ip, dst_ip, udp_slice, is_ipv6) = match ver {
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
            if raw_ip[9] != 17 {
                return None;
            }
            let hdr_total_len = u16::from_be_bytes([raw_ip[2], raw_ip[3]]) as usize;
            let ip_end = if hdr_total_len == 0 || raw_ip.len() > u16::MAX as usize {
                raw_ip.len()
            } else if hdr_total_len >= ihl && hdr_total_len <= raw_ip.len() {
                hdr_total_len
            } else {
                return None;
            };
            let src = IpAddr::V4(Ipv4Addr::new(
                raw_ip[12], raw_ip[13], raw_ip[14], raw_ip[15],
            ));
            let dst = IpAddr::V4(Ipv4Addr::new(
                raw_ip[16], raw_ip[17], raw_ip[18], raw_ip[19],
            ));
            (src, dst, &raw_ip[ihl..ip_end], false)
        }
        6 => {
            if raw_ip.len() < 40 {
                return None;
            }
            let hdr_payload_len = u16::from_be_bytes([raw_ip[4], raw_ip[5]]) as usize;
            let offload_override = (hdr_payload_len == 0 && raw_ip.len() > 40)
                || raw_ip.len() > 40 + u16::MAX as usize;
            let ip_end = if offload_override {
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
                if next_hdr == 17 {
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
            if next_hdr != 17 || pos >= ip_end {
                return None;
            }

            let src_octets: [u8; 16] = raw_ip[8..24].try_into().ok()?;
            let dst_octets: [u8; 16] = raw_ip[24..40].try_into().ok()?;
            let src = IpAddr::V6(Ipv6Addr::from(src_octets));
            let dst = IpAddr::V6(Ipv6Addr::from(dst_octets));
            (src, dst, &raw_ip[pos..ip_end], true)
        }
        _ => return None,
    };

    if udp_slice.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([udp_slice[0], udp_slice[1]]);
    let dst_port = u16::from_be_bytes([udp_slice[2], udp_slice[3]]);
    let udp_len = u16::from_be_bytes([udp_slice[4], udp_slice[5]]) as usize;
    let payload = if udp_len == 0 {
        // Windows UDP 校验和/长度卸载（USO / offload）或 IPv6 Jumbogram UDP length == 0
        &udp_slice[8..]
    } else if udp_len >= 8 && udp_len <= udp_slice.len() {
        &udp_slice[8..udp_len]
    } else {
        return None;
    };

    Some(ParsedUdpPacket {
        src_ip: src_ip.to_canonical(),
        dst_ip: dst_ip.to_canonical(),
        src_port,
        dst_port,
        payload,
        is_ipv6,
    })
}

/// 构造伪装原 DNS 服务器返回给本机的 UDP 应答原始 IP 包（自动计算 IP/UDP 校验和）
pub fn build_udp_reply_ip_packet(
    req: &ParsedUdpPacket<'_>,
    reply_payload: &[u8],
) -> io::Result<Vec<u8>> {
    if reply_payload.len() > 65_000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP DNS response payload exceeds single IP packet capacity",
        ));
    }

    match (req.dst_ip, req.src_ip) {
        (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => {
            let builder = PacketBuilder::ipv4(src_v4.octets(), dst_v4.octets(), 64)
                .udp(req.dst_port, req.src_port);
            let mut out = Vec::with_capacity(builder.size(reply_payload.len()));
            builder
                .write(&mut out, reply_payload)
                .map_err(|e| io::Error::other(format!("Failed to build IPv4 UDP reply: {e}")))?;
            Ok(out)
        }
        (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => {
            let builder = PacketBuilder::ipv6(src_v6.octets(), dst_v6.octets(), 64)
                .udp(req.dst_port, req.src_port);
            let mut out = Vec::with_capacity(builder.size(reply_payload.len()));
            builder
                .write(&mut out, reply_payload)
                .map_err(|e| io::Error::other(format!("Failed to build IPv6 UDP reply: {e}")))?;
            Ok(out)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Mismatched IP address family while building UDP DNS reply",
        )),
    }
}

/// 判定出站 UDP 报文动作：自环/放行端口直通、UDP/53 选择性劫持或被动观测、UDP/443 QUIC 选择性丢弃降级 TCP
pub fn decide_udp_packet(
    pkt: &ParsedUdpPacket<'_>,
    pid: Option<u32>,
    hijack_dns: bool,
    block_quic_for_proxied: bool,
    rule_engine: Option<&RuleEngine>,
    tracker: Option<&ProcessTracker>,
    fake_ip_pool: Option<&FakeIpPool>,
) -> UdpDecision {
    decide_udp_packet_with_if_idx(
        pkt,
        pid,
        hijack_dns,
        block_quic_for_proxied,
        rule_engine,
        tracker,
        fake_ip_pool,
        0,
    )
}

/// 携带网络接口索引 `if_idx` 的出站 UDP 裁决入口：
/// 当 `if_idx != 0`（真实网卡发出的报文，采用无侵入放行+入站旁路嗅探）时，`fe80::` 链路本地 IPv6 DNS 也可进入 `InspectDns` 被动学习真实 IP 映射。
#[allow(clippy::too_many_arguments)]
pub fn decide_udp_packet_with_if_idx(
    pkt: &ParsedUdpPacket<'_>,
    pid: Option<u32>,
    hijack_dns: bool,
    block_quic_for_proxied: bool,
    rule_engine: Option<&RuleEngine>,
    tracker: Option<&ProcessTracker>,
    fake_ip_pool: Option<&FakeIpPool>,
    if_idx: u32,
) -> UdpDecision {
    // 第一优先防回环：本进程注册的同地址族绕过 UDP 端口或当前进程发出的流量绝对放行
    if is_udp_port_bypassed_for_family(pkt.src_port, pkt.is_ipv6)
        || pid.is_some_and(|p| p != 0 && p == std::process::id())
    {
        return UdpDecision::Passthrough;
    }

    // 广播、多播与未指定地址不做透明劫持
    let is_broadcast = matches!(pkt.dst_ip, IpAddr::V4(v4) if v4.is_broadcast());
    if pkt.dst_ip.is_multicast() || pkt.dst_ip.is_unspecified() || is_broadcast {
        return UdpDecision::Passthrough;
    }

    // 发往 Fake-IP 地址段的任意非 53 端口 UDP（443 QUIC、8443、游戏/STUN 等）均无法直接穿透公网，必须全部拦截丢弃
    if pkt.dst_port != 53 && fake_ip_pool.is_some_and(|pool| pool.is_fake_ip_addr(pkt.dst_ip)) {
        return if pkt.dst_port == 443 {
            UdpDecision::DropQuic
        } else {
            UdpDecision::DropFakeIp
        };
    }

    match pkt.dst_port {
        53 => {
            if !hijack_dns || pkt.payload.len() < 12 {
                return UdpDecision::Passthrough;
            }
            let Ok((_, question)) = DnsPacketParser::parse_question(pkt.payload) else {
                return UdpDecision::Passthrough;
            };
            let Some(re) = rule_engine else {
                return UdpDecision::HandleDns;
            };

            let proc_info = pid.and_then(|p| tracker.and_then(|t| t.resolve_pid(p)));
            let proc_unresolved = pid.is_none() || (tracker.is_some() && proc_info.is_none());
            let proc_path = proc_info.as_ref().map(|i| i.path.as_str());
            let proc_name = proc_info.as_ref().map(|i| i.name.as_str());
            let is_shared = proc_unresolved || is_shared_system_dns_process(proc_path, proc_name);

            match re.classify_dns_query(proc_path, proc_name, &question.name, is_shared) {
                DnsHijackDecision::Hijack => UdpDecision::HandleDns,
                DnsHijackDecision::Passthrough => {
                    let unscoped_link_local_v6_dns = if_idx == 0
                        && matches!(
                            pkt.dst_ip.to_canonical(),
                            IpAddr::V6(v6) if v6.is_unicast_link_local()
                        );
                    if is_shared
                        && !unscoped_link_local_v6_dns
                        && re.should_inspect_shared_dns(proc_path, proc_name, &question.name)
                    {
                        UdpDecision::InspectDns
                    } else {
                        UdpDecision::Passthrough
                    }
                }
            }
        }
        443 => {
            if !block_quic_for_proxied {
                return UdpDecision::Passthrough;
            }
            let Some(re) = rule_engine else {
                return UdpDecision::DropQuic;
            };
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
                        UdpDecision::DropQuic
                    } else {
                        UdpDecision::Passthrough
                    }
                }
                DomainNeedDecision::Immediate(_) | DomainNeedDecision::NeedsDomainSniff => {
                    UdpDecision::DropQuic
                }
            }
        }
        _ => UdpDecision::Passthrough,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    use crate::dns::server::DnsServer;
    use crate::outbound::bypass::{BypassProtocol, register_bypass_port};
    use crate::router::Rule;

    fn build_sample_dns_query(id: u16, host: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(64);
        pkt.extend_from_slice(&id.to_be_bytes());
        pkt.extend_from_slice(&0x0100u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        for label in host.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt
    }

    fn build_engine(rules: Vec<Rule>, default_action: Action) -> RuleEngine {
        RuleEngine::new(rules, default_action)
    }

    fn rule_with(name: &str, apps: Option<&str>, targets: Option<&str>, action: Action) -> Rule {
        Rule::from_raw(name, true, apps, targets, None, action)
    }

    #[tokio::test]
    async fn test_ipv4_and_ipv6_dns_udp_packet_roundtrip_via_dns_server() {
        let pool = Arc::new(FakeIpPool::new_default());
        let server = DnsServer::new(
            "127.0.0.1:0".parse().unwrap(),
            Arc::clone(&pool),
            "223.5.5.5:53".parse().unwrap(),
            true,
        );
        let query_payload = build_sample_dns_query(0x4242, "hijack.example", 1);

        // IPv4 DNS 请求 -> DnsServer 处理 -> 反向伪造 UDP/IPv4 响应包
        let mut raw_v4 = Vec::new();
        PacketBuilder::ipv4([192, 168, 1, 20], [8, 8, 8, 8], 64)
            .udp(55123, 53)
            .write(&mut raw_v4, &query_payload)
            .unwrap();
        let parsed_v4 = parse_udp_packet(&raw_v4).expect("IPv4 UDP packet should parse");
        assert!(!parsed_v4.is_ipv6);
        assert_eq!(parsed_v4.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)));
        assert_eq!(parsed_v4.dst_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(parsed_v4.src_port, 55123);
        assert_eq!(parsed_v4.dst_port, 53);

        let dns_resp = server
            .process_query_bytes(parsed_v4.payload)
            .await
            .expect("DNS server should return Fake-IP response");
        let reply_ip_v4 =
            build_udp_reply_ip_packet(&parsed_v4, &dns_resp).expect("reply build should succeed");
        let parsed_reply_v4 = parse_udp_packet(&reply_ip_v4).expect("reply IP packet should parse");
        assert_eq!(
            parsed_reply_v4.src_ip,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
        );
        assert_eq!(
            parsed_reply_v4.dst_ip,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))
        );
        assert_eq!(parsed_reply_v4.src_port, 53);
        assert_eq!(parsed_reply_v4.dst_port, 55123);
        assert_eq!(&parsed_reply_v4.payload[0..2], &[0x42, 0x42]);
        let assigned_ip = Ipv4Addr::new(
            parsed_reply_v4.payload[parsed_reply_v4.payload.len() - 4],
            parsed_reply_v4.payload[parsed_reply_v4.payload.len() - 3],
            parsed_reply_v4.payload[parsed_reply_v4.payload.len() - 2],
            parsed_reply_v4.payload[parsed_reply_v4.payload.len() - 1],
        );
        assert_eq!(
            pool.restore_ip(IpAddr::V4(assigned_ip)).as_deref(),
            Some("hijack.example")
        );

        // IPv6 DNS 请求 -> 反向伪造 UDP/IPv6 响应包
        let src_v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
        let dst_v6 = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        let aaaa_query = build_sample_dns_query(0x7788, "hijack.example", 28);
        let mut raw_v6 = Vec::new();
        PacketBuilder::ipv6(src_v6.octets(), dst_v6.octets(), 64)
            .udp(60001, 53)
            .write(&mut raw_v6, &aaaa_query)
            .unwrap();
        let parsed_v6 = parse_udp_packet(&raw_v6).expect("IPv6 UDP packet should parse");
        assert!(parsed_v6.is_ipv6);
        let aaaa_resp = server.process_query_bytes(parsed_v6.payload).await.unwrap();
        let reply_ip_v6 = build_udp_reply_ip_packet(&parsed_v6, &aaaa_resp).unwrap();
        let parsed_reply_v6 = parse_udp_packet(&reply_ip_v6).unwrap();
        assert!(parsed_reply_v6.is_ipv6);
        assert_eq!(parsed_reply_v6.src_ip, IpAddr::V6(dst_v6));
        assert_eq!(parsed_reply_v6.dst_ip, IpAddr::V6(src_v6));
        assert_eq!(parsed_reply_v6.src_port, 53);
        assert_eq!(parsed_reply_v6.dst_port, 60001);
        assert_eq!(&parsed_reply_v6.payload[0..2], &[0x77, 0x88]);
    }

    #[test]
    fn test_udp_decisions_respect_bypass_self_pid_and_selective_quic() {
        let query_payload = build_sample_dns_query(0x1122, "example.com", 1);
        let mut dns_pkt = Vec::new();
        PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
            .udp(40001, 53)
            .write(&mut dns_pkt, &query_payload)
            .unwrap();
        let parsed_dns = parse_udp_packet(&dns_pkt).unwrap();

        // 当前进程 PID 自身或 BypassPortRegistry 已登记端口 -> 无条件放行防止自循环
        assert_eq!(
            decide_udp_packet(
                &parsed_dns,
                Some(std::process::id()),
                true,
                true,
                None,
                None,
                None
            ),
            UdpDecision::Passthrough
        );
        {
            let _guard = register_bypass_port(BypassProtocol::Udp, 40001);
            assert_eq!(
                decide_udp_packet(&parsed_dns, Some(99999), true, true, None, None, None),
                UdpDecision::Passthrough
            );
        }

        // 有域名代理规则 (*.google.com) 时：无关域名 example.com 放行真实 DNS，命中域名 mail.google.com 才劫持
        let domain_engine = build_engine(
            vec![rule_with(
                "proxy-google",
                None,
                Some("*.google.com"),
                Action::Proxy(1),
            )],
            Action::Direct,
        );
        assert_eq!(
            decide_udp_packet(
                &parsed_dns,
                Some(99999),
                true,
                true,
                Some(&domain_engine),
                None,
                None
            ),
            UdpDecision::Passthrough
        );
        let google_dns_payload = build_sample_dns_query(0x1123, "mail.google.com", 1);
        let mut google_dns_pkt = Vec::new();
        PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
            .udp(40005, 53)
            .write(&mut google_dns_pkt, &google_dns_payload)
            .unwrap();
        let parsed_google_dns = parse_udp_packet(&google_dns_pkt).unwrap();
        assert_eq!(
            decide_udp_packet(
                &parsed_google_dns,
                Some(99999),
                true,
                true,
                Some(&domain_engine),
                None,
                None
            ),
            UdpDecision::HandleDns
        );

        let mut quic_pkt = Vec::new();
        PacketBuilder::ipv4([10, 0, 0, 2], [142, 250, 1, 1], 64)
            .udp(40002, 443)
            .write(&mut quic_pkt, &[0xC0, 0x00, 0x00, 0x01])
            .unwrap();
        let parsed_quic = parse_udp_packet(&quic_pkt).unwrap();
        assert_eq!(
            decide_udp_packet(
                &parsed_quic,
                Some(99999),
                true,
                true,
                Some(&domain_engine),
                None,
                None
            ),
            UdpDecision::DropQuic
        );

        // 纯直连规则集（无域名/代理规则）：UDP/53 与 QUIC UDP/443 均直接放行
        let direct_only_engine = build_engine(vec![], Action::Direct);
        assert_eq!(
            decide_udp_packet(
                &parsed_dns,
                Some(99999),
                true,
                true,
                Some(&direct_only_engine),
                None,
                None
            ),
            UdpDecision::Passthrough
        );
        assert_eq!(
            decide_udp_packet(
                &parsed_quic,
                Some(99999),
                true,
                true,
                Some(&direct_only_engine),
                None,
                None
            ),
            UdpDecision::Passthrough
        );

        // 即使规则引擎未匹配 Proxy（且哪怕 block_quic_for_proxied=false），发往 Fake-IP 的任意非 53 UDP 也必须拦截丢弃
        let pool = FakeIpPool::new_default();
        let fake_ip = pool.allocate("custom.internal");
        let mut fake_quic = Vec::new();
        PacketBuilder::ipv4([10, 0, 0, 2], fake_ip.octets(), 64)
            .udp(40003, 443)
            .write(&mut fake_quic, &[0xC0, 0x00, 0x00, 0x01])
            .unwrap();
        let parsed_fake_quic = parse_udp_packet(&fake_quic).unwrap();
        assert_eq!(
            decide_udp_packet(
                &parsed_fake_quic,
                Some(99999),
                true,
                false,
                Some(&direct_only_engine),
                None,
                Some(&pool),
            ),
            UdpDecision::DropQuic
        );

        let mut fake_game_udp = Vec::new();
        PacketBuilder::ipv4([10, 0, 0, 2], fake_ip.octets(), 64)
            .udp(40004, 7777)
            .write(&mut fake_game_udp, &[0x01, 0x02, 0x03])
            .unwrap();
        let parsed_fake_game = parse_udp_packet(&fake_game_udp).unwrap();
        assert_eq!(
            decide_udp_packet(
                &parsed_fake_game,
                Some(99999),
                true,
                false,
                Some(&direct_only_engine),
                None,
                Some(&pool),
            ),
            UdpDecision::DropFakeIp
        );

        // 验证共享系统 DNS 进程识别辅助函数
        assert!(is_shared_system_dns_process(
            Some(r"C:\Windows\System32\svchost.exe"),
            Some("svchost.exe")
        ));
        assert!(is_shared_system_dns_process(
            Some(r"C:\Windows\System32\svchost.exe"),
            None
        ));
        assert!(!is_shared_system_dns_process(
            Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            Some("chrome.exe")
        ));

        // 传入了一个已消逝或权限受限的 PID (Some(999999)) 且搭配真实 ProcessTracker 时，
        // resolve_pid 返回 None => proc_unresolved 必须激活，拦截前导应用级规则 DevProxy 上的 QUIC 防止绕过
        let real_tracker = ProcessTracker::new();
        let app_proxy_engine = build_engine(
            vec![
                rule_with("LocalBypass", None, Some("192.168.0.0/16"), Action::Direct),
                rule_with("DevProxy", Some("chrome.exe"), None, Action::Proxy(101)),
            ],
            Action::Direct,
        );
        assert_eq!(
            decide_udp_packet(
                &parsed_quic,
                Some(999_999),
                true,
                true,
                Some(&app_proxy_engine),
                Some(&real_tracker),
                None,
            ),
            UdpDecision::DropQuic
        );

        // 共享/未解析系统 DNS 发起外部域名查询且存在 DevProxy（target_domains=None）时应进入 InspectDns
        assert_eq!(
            decide_udp_packet(
                &parsed_dns,
                Some(999_999),
                true,
                true,
                Some(&app_proxy_engine),
                Some(&real_tracker),
                None,
            ),
            UdpDecision::InspectDns
        );
        // 纯直连策略下即便是共享/未解析系统 DNS 也应直接 Passthrough
        assert_eq!(
            decide_udp_packet(
                &parsed_dns,
                Some(999_999),
                true,
                true,
                Some(&direct_only_engine),
                Some(&real_tracker),
                None,
            ),
            UdpDecision::Passthrough
        );

        // 本地域名与私有内网/VPN 后缀和显式前置全局直连域名（*.cn -> Direct）不进入 InspectDns
        for local_domain in [
            "localhost",
            "printer.local",
            "nas.home",
            "box.ts.net",
            "wiki.corp",
            "srv.localdomain",
        ] {
            let local_query = build_sample_dns_query(0x3344, local_domain, 1);
            let mut local_pkt = Vec::new();
            PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
                .udp(40010, 53)
                .write(&mut local_pkt, &local_query)
                .unwrap();
            let parsed_local = parse_udp_packet(&local_pkt).unwrap();
            assert_eq!(
                decide_udp_packet(
                    &parsed_local,
                    Some(999_999),
                    true,
                    true,
                    Some(&app_proxy_engine),
                    Some(&real_tracker),
                    None,
                ),
                UdpDecision::Passthrough,
                "local/private domain {} must remain Passthrough",
                local_domain
            );
        }

        // 发往 fe80:: 链路本地 IPv6 DNS 服务器的 InspectDns 应直接 Passthrough，交由内核带原生 scope_id 发送
        let mut ll_v6_dns_pkt = Vec::new();
        PacketBuilder::ipv6(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2).octets(),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).octets(),
            64,
        )
        .udp(40012, 53)
        .write(&mut ll_v6_dns_pkt, &query_payload)
        .unwrap();
        let parsed_ll_v6_dns = parse_udp_packet(&ll_v6_dns_pkt).unwrap();
        assert_eq!(
            decide_udp_packet(
                &parsed_ll_v6_dns,
                Some(999_999),
                true,
                true,
                Some(&app_proxy_engine),
                Some(&real_tracker),
                None,
            ),
            UdpDecision::Passthrough
        );

        // P1-2：上层“应用+域名+端口”规则叠加下层全局同域 Direct 规则，在共享系统 DNS 下必须进入 InspectDns
        let layered_engine = RuleEngine::new(
            vec![
                Rule::from_raw(
                    "SshCorpProxy",
                    true,
                    Some("ssh.exe"),
                    Some("*.corp.example"),
                    Some("22"),
                    Action::Proxy(101),
                ),
                Rule::from_raw(
                    "GlobalCorpDirect",
                    true,
                    None,
                    Some("*.corp.example"),
                    None,
                    Action::Direct,
                ),
            ],
            Action::Direct,
        );
        let corp_query = build_sample_dns_query(0x3366, "git.corp.example", 1);
        let mut corp_pkt = Vec::new();
        PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
            .udp(40013, 53)
            .write(&mut corp_pkt, &corp_query)
            .unwrap();
        let parsed_corp = parse_udp_packet(&corp_pkt).unwrap();
        assert_eq!(
            decide_udp_packet(
                &parsed_corp,
                Some(999_999),
                true,
                true,
                Some(&layered_engine),
                Some(&real_tracker),
                None,
            ),
            UdpDecision::InspectDns
        );

        let cn_override_engine = build_engine(
            vec![
                rule_with("DirectCN", None, Some("*.cn"), Action::Direct),
                rule_with("DevProxy", Some("chrome.exe"), None, Action::Proxy(101)),
            ],
            Action::Direct,
        );
        let cn_query = build_sample_dns_query(0x3355, "example.cn", 1);
        let mut cn_pkt = Vec::new();
        PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64)
            .udp(40011, 53)
            .write(&mut cn_pkt, &cn_query)
            .unwrap();
        let parsed_cn = parse_udp_packet(&cn_pkt).unwrap();
        assert_eq!(
            decide_udp_packet(
                &parsed_cn,
                Some(999_999),
                true,
                true,
                Some(&cn_override_engine),
                Some(&real_tracker),
                None,
            ),
            UdpDecision::Passthrough
        );

        // P1-3: 当具备真实网卡接口索引 (if_idx != 0) 时，fe80:: 链路本地 IPv6 DNS 进入无侵入被动 InspectDns
        assert_eq!(
            decide_udp_packet_with_if_idx(
                &parsed_ll_v6_dns,
                Some(999_999),
                true,
                true,
                Some(&app_proxy_engine),
                Some(&real_tracker),
                None,
                7,
            ),
            UdpDecision::InspectDns
        );
    }

    #[test]
    fn test_p1_4_parse_udp_packet_with_ipv6_mobility_hip_shim6_and_offload_zero_len() {
        let src6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let payload = build_sample_dns_query(0xCAFE, "ext-hdr-udp.example", 1);

        // 1. P1-4: 未分片 IPv6 UDP 携带 135 (Mobility) -> 139 (HIP) -> 140 (SHIM6) 扩展头，必须完整解析而非掉入 FragmentTracker 丢弃
        let mut udp_hdr = Vec::with_capacity(8 + payload.len());
        udp_hdr.extend_from_slice(&51234u16.to_be_bytes());
        udp_hdr.extend_from_slice(&53u16.to_be_bytes());
        udp_hdr.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp_hdr.extend_from_slice(&0u16.to_be_bytes());
        udp_hdr.extend_from_slice(&payload);

        let mut raw_v6 = Vec::new();
        raw_v6.extend_from_slice(&[0x60, 0, 0, 0]);
        raw_v6.extend_from_slice(&((24 + udp_hdr.len()) as u16).to_be_bytes());
        raw_v6.push(135); // Mobility
        raw_v6.push(64);
        raw_v6.extend_from_slice(&src6.octets());
        raw_v6.extend_from_slice(&dst6.octets());
        raw_v6.extend_from_slice(&[139, 0, 0, 0, 0, 0, 0, 0]); // Mobility (8B) -> HIP
        raw_v6.extend_from_slice(&[140, 0, 0, 0, 0, 0, 0, 0]); // HIP (8B) -> SHIM6
        raw_v6.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]); // SHIM6 (8B) -> UDP
        raw_v6.extend_from_slice(&udp_hdr);

        let parsed = parse_udp_packet(&raw_v6)
            .expect("unfragmented IPv6 UDP with Mobility/HIP/SHIM6 extension headers must parse");
        assert!(parsed.is_ipv6);
        assert_eq!(parsed.src_ip, IpAddr::V6(src6));
        assert_eq!(parsed.dst_ip, IpAddr::V6(dst6));
        assert_eq!(parsed.src_port, 51234);
        assert_eq!(parsed.dst_port, 53);
        assert_eq!(parsed.payload, payload.as_slice());

        // 2. P3-5: Windows Offload UDP length == 0（以及 IPv4 total_len == 0）必须正确解析
        let mut offload_v4 = Vec::new();
        PacketBuilder::ipv4([10, 0, 0, 2], [8, 8, 8, 8], 64)
            .udp(55555, 53)
            .write(&mut offload_v4, &payload)
            .unwrap();
        offload_v4[2] = 0;
        offload_v4[3] = 0; // IPv4 total_len = 0 offload
        offload_v4[24] = 0;
        offload_v4[25] = 0; // UDP length = 0 offload
        let parsed_offload =
            parse_udp_packet(&offload_v4).expect("Windows offload UDP length==0 must parse");
        assert_eq!(parsed_offload.dst_port, 53);
        assert_eq!(parsed_offload.payload, payload.as_slice());

        // 3. 真正的截断畸形 UDP（1 <= udp_len < 8 或 udp_len > slice）仍须返回 None
        let mut malformed_v4 = offload_v4.clone();
        malformed_v4[24] = 0;
        malformed_v4[25] = 4; // invalid udp_len < 8
        assert!(parse_udp_packet(&malformed_v4).is_none());
    }

    #[test]
    fn test_p1_3_pending_inspect_dns_table_passive_observation_including_fe80_and_spoof_rejection()
    {
        let pool = FakeIpPool::new_default();
        let table = PendingInspectDnsTable::new();
        let client_ip: IpAddr = "fe80::2".parse().unwrap();
        let server_ip: IpAddr = "fe80::1".parse().unwrap();
        let query = build_sample_dns_query(0x7123, "passive-v6.example", 1);

        assert!(table.record_outbound_query(client_ip, server_ip, 52000, 53, &query));

        let mut resp = Vec::new();
        resp.extend_from_slice(&0x7123u16.to_be_bytes());
        resp.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        resp.extend_from_slice(&query[12..]);
        resp.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 45, 0, 4, 93, 184, 216, 77,
        ]);

        // 错误源服务器伪造包不得命中或消耗待观测项
        let spoof_ip: IpAddr = "fe80::99".parse().unwrap();
        assert!(!table.observe_inbound_response(spoof_ip, client_ip, 53, 52000, &resp, &pool));
        assert_eq!(
            pool.lookup_real_ip_domain(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 77))),
            None
        );

        // 合法 fe80::1 入站响应应被动学习 real_ip -> domain，且无任何 Fake-IP 分配
        assert!(table.observe_inbound_response(server_ip, client_ip, 53, 52000, &resp, &pool));
        assert!(pool.is_empty());
        assert_eq!(
            pool.lookup_real_ip_domain(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 77)))
                .as_deref(),
            Some("passive-v6.example")
        );
    }

    #[test]
    fn test_inline_inbound_dns_observation_handles_standard_and_large_reassembled_edns0_v4_v6() {
        let pool = FakeIpPool::new_default();
        let table = PendingInspectDnsTable::new();

        // 1. 标准入站 UDP/53 应答：调用 observe_inbound_dns_packet_for_inspect 后立即完成落盘（早于重注入 OS）
        let client_v4 = Ipv4Addr::new(10, 0, 0, 2);
        let server_v4 = Ipv4Addr::new(8, 8, 8, 8);
        let q1 = build_sample_dns_query(0x5101, "ssh.corp.example", 1);
        assert!(table.record_outbound_query(
            IpAddr::V4(client_v4),
            IpAddr::V4(server_v4),
            51001,
            53,
            &q1,
        ));
        let mut dns_resp1 = Vec::new();
        dns_resp1.extend_from_slice(&0x5101u16.to_be_bytes());
        dns_resp1.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        dns_resp1.extend_from_slice(&q1[12..]);
        dns_resp1.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4, 10, 20, 30, 40,
        ]);
        let mut raw_unfrag = Vec::new();
        PacketBuilder::ipv4(server_v4.octets(), client_v4.octets(), 64)
            .udp(53, 51001)
            .write(&mut raw_unfrag, &dns_resp1)
            .unwrap();
        assert!(observe_inbound_dns_packet_for_inspect(
            &raw_unfrag,
            &table,
            &pool,
        ));
        assert_eq!(
            pool.lookup_real_ip_domain(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)))
                .as_deref(),
            Some("ssh.corp.example")
        );

        // 2. IPv4 大包 EDNS0/DNSSEC (>1500B，WinDivert flags=0 原生重组后交付完整 UDP/53 报文)
        let q2 = build_sample_dns_query(0x5102, "dnssec-v4.example", 1);
        assert!(table.record_outbound_query(
            IpAddr::V4(client_v4),
            IpAddr::V4(server_v4),
            51002,
            53,
            &q2,
        ));
        let mut dns_resp2 = Vec::new();
        dns_resp2.extend_from_slice(&0x5102u16.to_be_bytes());
        dns_resp2.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01]);
        dns_resp2.extend_from_slice(&q2[12..]);
        dns_resp2.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4, 93, 184, 216, 81,
        ]);
        dns_resp2.push(0x00);
        dns_resp2.extend_from_slice(&[0x00, 41, 0x10, 0x00, 0, 0, 0, 0]);
        dns_resp2.extend_from_slice(&1500u16.to_be_bytes());
        dns_resp2.extend(std::iter::repeat_n(0x41u8, 1500));

        let mut raw_edns_v4 = Vec::new();
        PacketBuilder::ipv4(server_v4.octets(), client_v4.octets(), 64)
            .udp(53, 51002)
            .write(&mut raw_edns_v4, &dns_resp2)
            .unwrap();
        assert!(raw_edns_v4.len() > 1500);
        assert!(observe_inbound_dns_packet_for_inspect(
            &raw_edns_v4,
            &table,
            &pool,
        ));
        assert_eq!(
            pool.lookup_real_ip_domain(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 81)))
                .as_deref(),
            Some("dnssec-v4.example")
        );

        // 3. IPv6 完整入站 UDP/53 应答同样同步学习 real_ip -> domain
        let client_v6: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let server_v6: Ipv6Addr = "2001:db8::53".parse().unwrap();
        let q3 = build_sample_dns_query(0x5103, "dnssec-v6.example", 1);
        assert!(table.record_outbound_query(
            IpAddr::V6(client_v6),
            IpAddr::V6(server_v6),
            51003,
            53,
            &q3,
        ));
        let mut dns_resp3 = Vec::new();
        dns_resp3.extend_from_slice(&0x5103u16.to_be_bytes());
        dns_resp3.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        dns_resp3.extend_from_slice(&q3[12..]);
        dns_resp3.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4, 93, 184, 216, 82,
        ]);
        let mut raw_v6 = Vec::new();
        PacketBuilder::ipv6(server_v6.octets(), client_v6.octets(), 64)
            .udp(53, 51003)
            .write(&mut raw_v6, &dns_resp3)
            .unwrap();
        assert!(observe_inbound_dns_packet_for_inspect(
            &raw_v6, &table, &pool,
        ));
        assert_eq!(
            pool.lookup_real_ip_domain(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 82)))
                .as_deref(),
            Some("dnssec-v6.example")
        );

        // 4. 非 DNS 入站 UDP 报文安全返回 false，不影响状态机
        let mut non_dns_udp = Vec::new();
        PacketBuilder::ipv4(server_v4.octets(), client_v4.octets(), 64)
            .udp(443, 51004)
            .write(&mut non_dns_udp, &[1, 2, 3, 4])
            .unwrap();
        assert!(!observe_inbound_dns_packet_for_inspect(
            &non_dns_udp,
            &table,
            &pool,
        ));
    }
}
