use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use anyhow::{anyhow, bail, Context, Result};
use tokio::net::TcpStream;

use crate::dns::server::resolve_via_upstream_dns;
use crate::dns::FakeIpPool;
use super::{is_local_or_loopback_ip, is_loopback_domain, local_interface_ips, TargetAddr};

/// Maximum timeout for direct TCP connection (including upstream DNS resolution)
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DIRECT_DNS_TIMEOUT: Duration = Duration::from_secs(3);

/// 默认上游 DNS 地址（仅在测试或无独立运行时配置注入的场景下使用）
pub(crate) const DEFAULT_OUTBOUND_UPSTREAM_DNS: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)), 53);

pub struct DirectOutbound;

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
    if let Some(fake_ip) = ips.iter().copied().find(|ip| match ip {
        IpAddr::V4(v4) => {
            fake_ip_pool.is_some_and(|pool| pool.is_fake_ip(v4))
                || FakeIpPool::is_default_fake_ip(v4)
        }
        IpAddr::V6(_) => false,
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
pub(crate) async fn connect_proxy_tcp(
    proxy_addr: &str,
    upstream_dns: SocketAddr,
    fake_ip_pool: Option<&FakeIpPool>,
    self_ports: &[u16],
    role: &str,
) -> Result<TcpStream> {
    let proxy_target = TargetAddr::parse_authority(proxy_addr, None, false)
        .with_context(|| format!("Invalid {} server address: {}", role, proxy_addr))?;
    DirectOutbound::connect(&proxy_target, upstream_dns, fake_ip_pool, self_ports)
        .await
        .with_context(|| format!("Failed to connect to {}: {}", role, proxy_addr))
}

impl DirectOutbound {
    pub async fn connect(
        target: &TargetAddr,
        upstream_dns: SocketAddr,
        fake_ip_pool: Option<&FakeIpPool>,
        self_ports: &[u16],
    ) -> Result<TcpStream> {
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
                    TcpStream::connect(addr)
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
                        let dns_budget = DIRECT_DNS_TIMEOUT
                            .min(deadline.saturating_duration_since(tokio::time::Instant::now()));
                        resolve_via_upstream_dns(domain, upstream_dns, fake_ip_pool, dns_budget)
                            .await
                            .with_context(|| format!("Upstream DNS resolution failed for direct target {}", domain))?
                    };

                    validate_direct_ips(&resolved_ips, *port, self_ports, fake_ip_pool, domain)?;

                    let total_candidates = resolved_ips.len();
                    let mut last_err: Option<anyhow::Error> = None;
                    for (idx, ip) in resolved_ips.into_iter().enumerate() {
                        let remaining_total =
                            deadline.saturating_duration_since(tokio::time::Instant::now());
                        if remaining_total.is_zero() {
                            break;
                        }
                        let remaining_candidates = (total_candidates - idx) as u32;
                        let attempt_budget = if remaining_candidates <= 1 {
                            remaining_total
                        } else {
                            (remaining_total / remaining_candidates)
                                .max(Duration::from_millis(1500))
                                .min(Duration::from_secs(4))
                                .min(remaining_total)
                        };
                        let sock_addr = SocketAddr::new(ip, *port);
                        match tokio::time::timeout(attempt_budget, TcpStream::connect(sock_addr)).await {
                            Ok(Ok(stream)) => return Ok(stream),
                            Ok(Err(e)) => last_err = Some(anyhow::Error::new(e)),
                            Err(_) => {
                                last_err = Some(anyhow!(
                                    "Direct connection attempt timed out ({:?}) for {}",
                                    attempt_budget,
                                    sock_addr
                                ))
                            }
                        }
                    }

                    match last_err {
                        Some(e) => Err(e).with_context(|| {
                            format!("Direct connection to target domain failed: {}:{}", domain, port)
                        }),
                        None => bail!("No resolved IP candidates available for {}:{}", domain, port),
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
        // 1. Default Fake-IP CIDR literal blocked even when fake_ip_pool is None
        let fake_target = TargetAddr::Ip("198.18.0.42:443".parse().unwrap());
        let err = DirectOutbound::connect(&fake_target, DEFAULT_OUTBOUND_UPSTREAM_DNS, None, &[])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Fake-IP"));

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
}
