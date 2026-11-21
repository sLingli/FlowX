use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use anyhow::{anyhow, bail, Context, Result};

use crate::dns::server::{resolve_via_upstream_dns, DnsNxDomainError};
use crate::dns::{
    canonicalize_socket_addr_preserving_scope, sanitize_upstream_dns_addr, FakeIpPool,
};
use super::bypass::{connect_tcp_guarded, OutboundTcpStream};
use super::{is_local_or_loopback_ip, is_loopback_domain, local_interface_ips, TargetAddr};

/// Maximum timeout for direct TCP connection (including upstream DNS resolution)
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DIRECT_DNS_TIMEOUT: Duration = Duration::from_secs(3);

/// 默认上游 DNS 地址（仅在测试或无独立运行时配置注入的场景下使用）
pub(crate) const DEFAULT_OUTBOUND_UPSTREAM_DNS: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)), 53);

pub struct DirectOutbound;

#[derive(Debug)]
pub(crate) enum CandidateConnectError {
    TimedOut { budget: Duration, addr: SocketAddr },
    Io(std::io::Error),
    NoCandidates,
}

/// 按剩余候选地址数分段分配单次连接预算，避免首个黑洞地址耗尽全部超时窗口。
pub(crate) async fn connect_candidates_with<T, F, Fut>(
    ips: &[IpAddr],
    port: u16,
    deadline: tokio::time::Instant,
    min_attempt: Duration,
    max_attempt: Duration,
    mut connector: F,
) -> std::result::Result<T, CandidateConnectError>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    let total_candidates = ips.len();
    if total_candidates == 0 {
        return Err(CandidateConnectError::NoCandidates);
    }
    let mut last_err: Option<CandidateConnectError> = None;
    for (idx, ip) in ips.iter().copied().enumerate() {
        let sock_addr = SocketAddr::new(ip, port);
        let remaining_total = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining_total.is_zero() {
            return Err(last_err.unwrap_or(CandidateConnectError::TimedOut {
                budget: Duration::ZERO,
                addr: sock_addr,
            }));
        }
        let remaining_candidates = (total_candidates - idx) as u32;
        let attempt_budget = if remaining_candidates <= 1 {
            remaining_total
        } else {
            (remaining_total / remaining_candidates)
                .max(min_attempt)
                .min(max_attempt)
                .min(remaining_total)
        };
        match tokio::time::timeout(attempt_budget, connector(sock_addr)).await {
            Ok(Ok(conn)) => return Ok(conn),
            Ok(Err(e)) => last_err = Some(CandidateConnectError::Io(e)),
            Err(_) => {
                last_err = Some(CandidateConnectError::TimedOut {
                    budget: attempt_budget,
                    addr: sock_addr,
                });
            }
        }
    }
    Err(last_err.unwrap_or(CandidateConnectError::NoCandidates))
}

pub(crate) async fn connect_candidates_guarded_with_budget(
    ips: &[IpAddr],
    port: u16,
    deadline: tokio::time::Instant,
    min_attempt: Duration,
    max_attempt: Duration,
) -> std::result::Result<OutboundTcpStream, CandidateConnectError> {
    connect_candidates_with(ips, port, deadline, min_attempt, max_attempt, |addr| {
        connect_tcp_guarded(addr)
    })
    .await
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectIpViolation {
    FakeIp(IpAddr),
    SelfLoop(IpAddr),
}

pub(crate) fn check_direct_ips_violation(
    ips: &[IpAddr],
    port: u16,
    self_ports: &[u16],
    fake_ip_pool: Option<&FakeIpPool>,
) -> Option<DirectIpViolation> {
    if let Some(fake_ip) = ips.iter().copied().find(|ip| {
        fake_ip_pool.is_some_and(|pool| pool.is_fake_ip_addr(*ip))
            || FakeIpPool::is_default_fake_ip_addr(*ip)
    }) {
        return Some(DirectIpViolation::FakeIp(fake_ip));
    }
    if self_ports.contains(&port) {
        let local_ips = local_interface_ips();
        if let Some(bad_ip) = ips
            .iter()
            .copied()
            .find(|ip| is_local_or_loopback_ip(*ip, &local_ips))
        {
            return Some(DirectIpViolation::SelfLoop(bad_ip));
        }
    }
    None
}

pub(crate) fn validate_direct_ips(
    ips: &[IpAddr],
    port: u16,
    self_ports: &[u16],
    fake_ip_pool: Option<&FakeIpPool>,
    host_label: &str,
) -> Result<()> {
    match check_direct_ips_violation(ips, port, self_ports, fake_ip_pool) {
        Some(DirectIpViolation::FakeIp(fake_ip)) => {
            bail!(
                "Outbound connection blocked: resolved Fake-IP {} for {}:{}",
                fake_ip,
                host_label,
                port
            );
        }
        Some(DirectIpViolation::SelfLoop(bad_ip)) => {
            bail!(
                "Direct outbound blocked due to self/loopback IP resolution ({} -> {}:{})",
                host_label,
                bad_ip,
                port
            );
        }
        None => Ok(()),
    }
}

/// 通过显式上游 DNS + Fake-IP 防死锁与回环自检连接上级代理节点，避免阻塞 `getaddrinfo` 命中系统 Fake-IP
pub(crate) async fn connect_proxy_tcp_guarded(
    proxy_addr: &str,
    upstream_dns: SocketAddr,
    fake_ip_pool: Option<&FakeIpPool>,
    self_ports: &[u16],
    role: &str,
) -> Result<OutboundTcpStream> {
    let proxy_target = TargetAddr::parse_authority(proxy_addr, None, false)
        .with_context(|| format!("Invalid {} server address: {}", role, proxy_addr))?;
    DirectOutbound::connect_guarded(&proxy_target, upstream_dns, fake_ip_pool, self_ports)
        .await
        .with_context(|| format!("Failed to connect to {}: {}", role, proxy_addr))
}

#[allow(dead_code)]
pub(crate) async fn connect_proxy_tcp(
    proxy_addr: &str,
    upstream_dns: SocketAddr,
    fake_ip_pool: Option<&FakeIpPool>,
    self_ports: &[u16],
    role: &str,
) -> Result<OutboundTcpStream> {
    connect_proxy_tcp_guarded(proxy_addr, upstream_dns, fake_ip_pool, self_ports, role).await
}

impl DirectOutbound {
    pub async fn connect(
        target: &TargetAddr,
        upstream_dns: SocketAddr,
        fake_ip_pool: Option<&FakeIpPool>,
        self_ports: &[u16],
    ) -> Result<OutboundTcpStream> {
        Self::connect_guarded(target, upstream_dns, fake_ip_pool, self_ports).await
    }

    pub async fn connect_guarded(
        target: &TargetAddr,
        upstream_dns: SocketAddr,
        fake_ip_pool: Option<&FakeIpPool>,
        self_ports: &[u16],
    ) -> Result<OutboundTcpStream> {
        Self::connect_guarded_with_dns_candidates(target, upstream_dns, &[], fake_ip_pool, self_ports)
            .await
    }

    /// 显式直连：若存在 `preferred_dns`（例如透明 Fake-IP 分配阶段记录的原路由器/企业分域 DNS），
    /// 优先向清洗后的 `preferred_dns` 解析；若网络不可达/超时则回退至 `upstream_dns`，
    /// 若权威 `orig_dns` 返回 `NXDOMAIN` 则绝不向公网 `upstream_dns` 泄露内网不存在域名。
    pub async fn connect_guarded_with_dns_fallback(
        target: &TargetAddr,
        upstream_dns: SocketAddr,
        preferred_dns: Option<SocketAddr>,
        fake_ip_pool: Option<&FakeIpPool>,
        self_ports: &[u16],
    ) -> Result<OutboundTcpStream> {
        let slice = preferred_dns.as_slice();
        Self::connect_guarded_with_dns_candidates(target, upstream_dns, slice, fake_ip_pool, self_ports)
            .await
    }

    /// 支持多 `orig_dns` 候选列表的显式直连回源解析（企业 VPN DNS + 备选网卡 DNS 共存时依次尝试，
    /// 发起查询前过滤 `169.254/16` / `255.255.255.255` / Fake-IP / 未带 `scope_id` 的 `fe80::` / `self_ports`）。
    pub async fn connect_guarded_with_dns_candidates(
        target: &TargetAddr,
        upstream_dns: SocketAddr,
        preferred_dns_list: &[SocketAddr],
        fake_ip_pool: Option<&FakeIpPool>,
        self_ports: &[u16],
    ) -> Result<OutboundTcpStream> {
        let deadline = tokio::time::Instant::now() + DIRECT_CONNECT_TIMEOUT;
        let fut = async {
            match target {
                TargetAddr::Ip(addr) => {
                    validate_direct_ips(
                        &[addr.ip()],
                        addr.port(),
                        self_ports,
                        fake_ip_pool,
                        &addr.ip().to_string(),
                    )?;
                    connect_tcp_guarded(*addr)
                        .await
                        .with_context(|| format!("Direct connection to target IP failed: {}", addr))
                }
                TargetAddr::Domain(domain, port) => {
                    let resolved_ips = if is_loopback_domain(domain) {
                        if self_ports.contains(port) {
                            bail!(
                                "Direct outbound blocked loopback domain targeting internal port {}:{}",
                                domain,
                                port
                            );
                        }
                        vec![
                            IpAddr::V4(Ipv4Addr::LOCALHOST),
                            IpAddr::V6(Ipv6Addr::LOCALHOST),
                        ]
                    } else {
                        let dns_deadline = tokio::time::Instant::now()
                            + DIRECT_DNS_TIMEOUT
                                .min(deadline.saturating_duration_since(tokio::time::Instant::now()));
                        let canonical_upstream =
                            canonicalize_socket_addr_preserving_scope(upstream_dns);
                        let mut orig_candidates: Vec<SocketAddr> = Vec::new();
                        for &cand in preferred_dns_list {
                            if let Some(clean) =
                                sanitize_upstream_dns_addr(cand, fake_ip_pool, self_ports)
                                && !orig_candidates.contains(&clean)
                            {
                                orig_candidates.push(clean);
                            }
                        }
                        let has_fallback_upstream = !orig_candidates.contains(&canonical_upstream);
                        let total_servers =
                            orig_candidates.len() + usize::from(has_fallback_upstream);

                        let mut resolved: Option<Vec<IpAddr>> = None;
                        let mut last_err: Option<(SocketAddr, anyhow::Error)> = None;
                        let mut saw_authoritative_nxdomain = false;

                        for (idx, &dns_server) in orig_candidates.iter().enumerate() {
                            let rem = dns_deadline
                                .saturating_duration_since(tokio::time::Instant::now());
                            if rem.is_zero() {
                                break;
                            }
                            let remaining_servers = (total_servers - idx) as u32;
                            let budget = if remaining_servers <= 1 {
                                rem
                            } else {
                                (rem / remaining_servers)
                                    .max(Duration::from_millis(300))
                                    .min(DIRECT_DNS_TIMEOUT / 2)
                                    .min(rem)
                            };
                            match resolve_via_upstream_dns(domain, dns_server, fake_ip_pool, budget)
                                .await
                            {
                                Ok(ips) => {
                                    resolved = Some(ips);
                                    break;
                                }
                                Err(err) => {
                                    if err.downcast_ref::<DnsNxDomainError>().is_some() {
                                        saw_authoritative_nxdomain = true;
                                    }
                                    last_err = Some((dns_server, err));
                                }
                            }
                        }

                        if let Some(ips) = resolved {
                            ips
                        } else if saw_authoritative_nxdomain && !orig_candidates.is_empty() {
                            // 权威 orig_dns 已明确返回 NXDOMAIN：禁止将内网不存在主机名回退泄露至公网 upstream_dns
                            let (srv, err) = last_err.expect("nxdomain must record error");
                            return Err(err).with_context(|| {
                                format!(
                                    "Authoritative original DNS {} returned NXDOMAIN for direct target {} (skipped public DNS fallback)",
                                    srv, domain
                                )
                            });
                        } else if has_fallback_upstream {
                            let fb_budget = dns_deadline
                                .saturating_duration_since(tokio::time::Instant::now());
                            if !fb_budget.is_zero() {
                                resolve_via_upstream_dns(
                                    domain,
                                    canonical_upstream,
                                    fake_ip_pool,
                                    fb_budget,
                                )
                                .await
                                .with_context(|| match &last_err {
                                    Some((primary_dns, primary_err)) => format!(
                                        "Upstream DNS resolution failed for direct target {} (primary {}: {:#})",
                                        domain, primary_dns, primary_err
                                    ),
                                    None => format!(
                                        "Upstream DNS resolution failed for direct target {}",
                                        domain
                                    ),
                                })?
                            } else if let Some((_, err)) = last_err {
                                return Err(err).with_context(|| {
                                    format!(
                                        "Upstream DNS resolution failed for direct target {}",
                                        domain
                                    )
                                });
                            } else {
                                bail!("Upstream DNS resolution timed out for direct target {}", domain);
                            }
                        } else if let Some((_, err)) = last_err {
                            return Err(err).with_context(|| {
                                format!(
                                    "Upstream DNS resolution failed for direct target {}",
                                    domain
                                )
                            });
                        } else {
                            bail!("Upstream DNS resolution failed for direct target {}", domain);
                        }
                    };

                    validate_direct_ips(&resolved_ips, *port, self_ports, fake_ip_pool, domain)?;

                    match connect_candidates_guarded_with_budget(
                        &resolved_ips,
                        *port,
                        deadline,
                        Duration::from_millis(1500),
                        Duration::from_secs(4),
                    )
                    .await
                    {
                        Ok(stream) => Ok(stream),
                        Err(CandidateConnectError::Io(e)) => Err(anyhow::Error::new(e)).with_context(|| {
                            format!("Direct connection to target domain failed: {}:{}", domain, port)
                        }),
                        Err(CandidateConnectError::TimedOut { budget, addr }) => Err(anyhow!(
                            "Direct connection attempt timed out ({:?}) for {}",
                            budget,
                            addr
                        ))
                        .with_context(|| {
                            format!("Direct connection to target domain failed: {}:{}", domain, port)
                        }),
                        Err(CandidateConnectError::NoCandidates) => {
                            bail!("No resolved IP candidates available for {}:{}", domain, port)
                        }
                    }
                }
            }
        };
        tokio::time::timeout(DIRECT_CONNECT_TIMEOUT, fut).await.map_err(|_| {
            anyhow!(
                "Direct connection timed out ({:?}): {}:{}",
                DIRECT_CONNECT_TIMEOUT,
                target.host_string(),
                target.port()
            )
        })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;
    use crate::dns::server::DnsPacketParser;

    #[tokio::test]
    async fn test_direct_outbound_blocks_dns_rebinding_to_self_port() {
        let mock_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = mock_upstream.local_addr().unwrap();

        tokio::spawn(async move {
            for _ in 0..2 {
                let mut buf = [0u8; 512];
                let (n, src) = mock_upstream.recv_from(&mut buf).await.unwrap();
                let (tx, q) = DnsPacketParser::parse_question(&buf[..n]).unwrap();
                let resp = if q.qtype == 1 {
                    // 同时返回 93.184.216.34 和 127.0.0.1 混合记录，校验任何一条命中本机都整体拦截
                    let mut r = Vec::new();
                    r.extend_from_slice(&tx.to_be_bytes());
                    r.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]);
                    r.extend_from_slice(&buf[12..q.raw_len]);
                    r.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 5, 0, 4, 93, 184, 216, 34]);
                    r.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 5, 0, 4, 127, 0, 0, 1]);
                    r
                } else {
                    DnsPacketParser::build_empty_response(tx, &buf, q.raw_len)
                };
                mock_upstream.send_to(&resp, src).await.unwrap();
            }
        });

        let target = TargetAddr::Domain("localtest.me".into(), 40080);
        let err = DirectOutbound::connect(&target, upstream_addr, None, &[40001, 40080, 1053])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("self/loopback IP resolution"));
    }

    #[tokio::test]
    async fn test_direct_outbound_blocks_fake_ip_and_multi_ip_failover() {
        // 1. Default Fake-IP literal (both plain IPv4 and IPv4-mapped IPv6) blocked even when fake_ip_pool is None
        let fake_target = TargetAddr::Ip("198.18.0.42:443".parse().unwrap());
        let err = DirectOutbound::connect(&fake_target, DEFAULT_OUTBOUND_UPSTREAM_DNS, None, &[])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Fake-IP"));

        let fake_mapped_target = TargetAddr::Ip("[::ffff:198.18.0.10]:1080".parse().unwrap());
        let err_mapped =
            DirectOutbound::connect(&fake_mapped_target, DEFAULT_OUTBOUND_UPSTREAM_DNS, None, &[])
                .await
                .unwrap_err();
        assert!(err_mapped.to_string().contains("Fake-IP"));
        let pool = FakeIpPool::new_default();
        assert!(matches!(
            check_direct_ips_violation(
                &["::ffff:198.18.0.10".parse().unwrap()],
                1080,
                &[],
                Some(&pool),
            ),
            Some(DirectIpViolation::FakeIp(_))
        ));

        // 2. Multi-IP DNS result falls through closed candidate to listening candidate
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ok_port = listener.local_addr().unwrap().port();
        let closed_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_ip_port = closed_probe.local_addr().unwrap();
        drop(closed_probe);
        assert_ne!(closed_ip_port.port(), ok_port);

        let mock_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = mock_upstream.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..2 {
                let mut buf = [0u8; 512];
                let (n, src) = mock_upstream.recv_from(&mut buf).await.unwrap();
                let (tx, q) = DnsPacketParser::parse_question(&buf[..n]).unwrap();
                let resp = if q.qtype == 1 {
                    // Return unreachable/reserved TEST-NET-1 first, then localhost 127.0.0.1
                    let mut r = Vec::new();
                    r.extend_from_slice(&tx.to_be_bytes());
                    r.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]);
                    r.extend_from_slice(&buf[12..q.raw_len]);
                    // 127.0.0.2 (connection refused fast) or 192.0.2.1 (blackhole capped at <=4s);
                    // pick non-listening loopback/local test IP if fast, or verify failover to 127.0.0.1
                    r.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 5, 0, 4, 127, 0, 0, 99]);
                    r.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 5, 0, 4, 127, 0, 0, 1]);
                    r
                } else {
                    DnsPacketParser::build_empty_response(tx, &buf, q.raw_len)
                };
                mock_upstream.send_to(&resp, src).await.unwrap();
            }
        });

        let accept_task = tokio::spawn(async move { listener.accept().await.unwrap() });
        let target = TargetAddr::Domain("failover.example".into(), ok_port);
        let stream = DirectOutbound::connect(&target, upstream_addr, None, &[40080])
            .await
            .unwrap();
        drop(stream);
        accept_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_connect_candidates_with_blackhole_failover() {
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ];
        let mut attempted = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(600);
        let winner = connect_candidates_with(
            &ips,
            443,
            deadline,
            Duration::from_millis(50),
            Duration::from_millis(600),
            |addr| {
                attempted.push(addr);
                let is_blackhole = addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST);
                async move {
                    if is_blackhole {
                        std::future::pending::<std::io::Result<SocketAddr>>().await
                    } else {
                        Ok(addr)
                    }
                }
            },
        )
        .await
        .expect("third reachable candidate should succeed within shared deadline");

        assert_eq!(winner, "127.0.0.1:443".parse::<SocketAddr>().unwrap());
        assert_eq!(
            attempted,
            vec![
                "198.51.100.1:443".parse::<SocketAddr>().unwrap(),
                "198.51.100.2:443".parse::<SocketAddr>().unwrap(),
                "127.0.0.1:443".parse::<SocketAddr>().unwrap(),
            ]
        );

        let timeout_deadline = tokio::time::Instant::now() + Duration::from_millis(120);
        let err = connect_candidates_with(
            &ips[..2],
            443,
            timeout_deadline,
            Duration::from_millis(30),
            Duration::from_millis(120),
            |_| std::future::pending::<std::io::Result<SocketAddr>>(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CandidateConnectError::TimedOut { .. }));

        let empty_err = connect_candidates_with::<SocketAddr, _, _>(
            &[],
            443,
            tokio::time::Instant::now() + Duration::from_millis(100),
            Duration::from_millis(50),
            Duration::from_millis(100),
            |_| async { unreachable!() },
        )
        .await
        .unwrap_err();
        assert!(matches!(empty_err, CandidateConnectError::NoCandidates));
    }

    #[tokio::test]
    async fn test_direct_outbound_skips_unusable_preferred_dns_and_does_not_leak_nxdomain() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        // 1. P3-1: 权威 orig_dns 返回 NXDOMAIN 时绝不得回退查询公网 fallback upstream_dns
        let corp_dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let corp_addr = corp_dns.local_addr().unwrap();
        let public_dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let public_addr = public_dns.local_addr().unwrap();
        let public_hits = Arc::new(AtomicUsize::new(0));
        let public_hits_c = Arc::clone(&public_hits);

        let (stop_tx, mut stop_rx1) = tokio::sync::watch::channel(false);
        let mut stop_rx2 = stop_tx.subscribe();
        let corp_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                tokio::select! {
                    r = corp_dns.recv_from(&mut buf) => {
                        let Ok((n, peer)) = r else { break };
                        let (txid, q) = DnsPacketParser::parse_question(&buf[..n]).unwrap();
                        let mut resp = Vec::new();
                        resp.extend_from_slice(&txid.to_be_bytes());
                        resp.extend_from_slice(&[0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                        resp.extend_from_slice(&buf[12..q.raw_len]);
                        let _ = corp_dns.send_to(&resp, peer).await;
                    }
                    _ = stop_rx1.changed() => break,
                }
            }
        });
        let pub_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                tokio::select! {
                    r = public_dns.recv_from(&mut buf) => {
                        let Ok((n, peer)) = r else { break };
                        public_hits_c.fetch_add(1, Ordering::Relaxed);
                        let (txid, q) = DnsPacketParser::parse_question(&buf[..n]).unwrap();
                        let resp = if q.qtype == 1 {
                            let mut r = Vec::new();
                            r.extend_from_slice(&txid.to_be_bytes());
                            r.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
                            r.extend_from_slice(&buf[12..q.raw_len]);
                            r.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
                            r
                        } else {
                            DnsPacketParser::build_empty_response(txid, &buf, q.raw_len)
                        };
                        let _ = public_dns.send_to(&resp, peer).await;
                    }
                    _ = stop_rx2.changed() => break,
                }
            }
        });

        let err = DirectOutbound::connect_guarded_with_dns_fallback(
            &TargetAddr::Domain("missing-secret.corp.example".into(), 443),
            public_addr,
            Some(corp_addr),
            None,
            &[1053, 40001, 40080],
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("NXDOMAIN"),
            "expected NXDOMAIN error, got: {err:#}"
        );
        assert_eq!(
            public_hits.load(Ordering::Relaxed),
            0,
            "authoritative NXDOMAIN from orig_dns must never fall back to public upstream_dns"
        );

        // 2. P2-2: 不可用的 preferred_dns（如 self_port / 169.254/16 / Fake-IP / 255.255.255.255）在发起查询前直接过滤，
        //    立即使用 fallback upstream_dns 建连成功，不浪费 1.5s 预算
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ok_port = listener.local_addr().unwrap().port();
        let accept_task = tokio::spawn(async move { listener.accept().await.unwrap() });
        let start = std::time::Instant::now();
        let stream = DirectOutbound::connect_guarded_with_dns_candidates(
            &TargetAddr::Domain("filtered-pref.example".into(), ok_port),
            public_addr,
            &[
                "127.0.0.1:1053".parse().unwrap(),
                "169.254.1.1:53".parse().unwrap(),
                "255.255.255.255:53".parse().unwrap(),
                "198.18.0.10:53".parse().unwrap(),
                "[fe80::1]:53".parse().unwrap(),
            ],
            None,
            &[1053, 40001, 40080],
        )
        .await
        .unwrap();
        assert!(
            start.elapsed() < Duration::from_millis(800),
            "unusable preferred_dns entries must be filtered before querying"
        );
        drop(stream);
        accept_task.await.unwrap();
        assert!(public_hits.load(Ordering::Relaxed) >= 1);

        let _ = stop_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), corp_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), pub_task).await;
    }
}
