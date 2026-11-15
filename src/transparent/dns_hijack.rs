use std::io;
use std::net::IpAddr;

use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};

use crate::dns::server::DnsPacketParser;
use crate::dns::FakeIpPool;
use crate::interceptor::process::ProcessTracker;
use crate::outbound::bypass::is_udp_port_bypassed;
use crate::router::{Action, DnsHijackDecision, DomainNeedDecision, RuleEngine};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpDecision {
    Passthrough,
    DropQuic,
    DropFakeIp,
    HandleDns,
}

/// 识别代表系统共享 DNS 解析器（如 Windows `svchost.exe` DNS Client）发起 UDP/53 查询的进程
pub fn is_shared_system_dns_process(
    process_path: Option<&str>,
    process_name: Option<&str>,
) -> bool {
    let base = process_name
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            process_path.and_then(|p| {
                p.rsplit(['\\', '/'])
                    .next()
                    .filter(|s| !s.is_empty())
            })
        });
    let Some(name) = base.map(str::trim) else {
        return false;
    };
    name.eq_ignore_ascii_case("svchost.exe")
        || name.eq_ignore_ascii_case("svchost")
        || name.eq_ignore_ascii_case("dnscache")
        || name.eq_ignore_ascii_case("systemd-resolved")
        || name.eq_ignore_ascii_case("mdnsresponder")
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

/// 解析原始 IPv4/IPv6 UDP 报文；分片包或非 UDP 报文返回 `None`
pub fn parse_udp_packet(raw_ip: &[u8]) -> Option<ParsedUdpPacket<'_>> {
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

    let TransportSlice::Udp(udp) = sliced.transport? else {
        return None;
    };

    Some(ParsedUdpPacket {
        src_ip: src_ip.to_canonical(),
        dst_ip: dst_ip.to_canonical(),
        src_port: udp.source_port(),
        dst_port: udp.destination_port(),
        payload: udp.payload(),
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

/// 判定出站 UDP 报文动作：自环/放行端口直通、UDP/53 选择性劫持至内置 DNS、UDP/443 QUIC 选择性丢弃降级 TCP
pub fn decide_udp_packet(
    pkt: &ParsedUdpPacket<'_>,
    pid: Option<u32>,
    hijack_dns: bool,
    block_quic_for_proxied: bool,
    rule_engine: Option<&RuleEngine>,
    tracker: Option<&ProcessTracker>,
    fake_ip_pool: Option<&FakeIpPool>,
) -> UdpDecision {
    // 第一优先防回环：本进程注册的绕过 UDP 端口或当前进程发出的流量绝对放行
    if is_udp_port_bypassed(pkt.src_port) || pid.is_some_and(|p| p != 0 && p == std::process::id())
    {
        return UdpDecision::Passthrough;
    }

    // 广播、多播与未指定地址不做透明劫持
    let is_broadcast = matches!(pkt.dst_ip, IpAddr::V4(v4) if v4.is_broadcast());
    if pkt.dst_ip.is_multicast() || pkt.dst_ip.is_unspecified() || is_broadcast {
        return UdpDecision::Passthrough;
    }

    // 发往 Fake-IP 地址段的任意非 53 端口 UDP（443 QUIC、8443、游戏/STUN 等）均无法直接穿透公网，必须全部拦截丢弃
    if pkt.dst_port != 53
        && fake_ip_pool.is_some_and(|pool| pool.is_fake_ip_addr(pkt.dst_ip))
    {
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
            let proc_path = proc_info.as_ref().map(|i| i.path.as_str());
            let proc_name = proc_info.as_ref().map(|i| i.name.as_str());
            let is_shared = pid.is_none() || is_shared_system_dns_process(proc_path, proc_name);

            match re.classify_dns_query(proc_path, proc_name, &question.name, is_shared) {
                DnsHijackDecision::Hijack => UdpDecision::HandleDns,
                DnsHijackDecision::Passthrough => UdpDecision::Passthrough,
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
            let proc_path = proc_info.as_ref().map(|i| i.path.as_str());
            let proc_name = proc_info.as_ref().map(|i| i.name.as_str());

            match re.needs_domain_for_routing(proc_path, proc_name, Some(pkt.dst_ip), pkt.dst_port)
            {
                DomainNeedDecision::Immediate(Action::Direct) => {
                    if pid.is_none()
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
    use crate::outbound::bypass::{register_bypass_port, BypassProtocol};
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
        assert_eq!(parsed_reply_v4.src_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
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
    }
}
