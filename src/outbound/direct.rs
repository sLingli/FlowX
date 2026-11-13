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

pub struct DirectOutbound;

fn validate_direct_ips(ips: &[IpAddr], port: u16, self_ports: &[u16], host_label: &str) -> Result<()> {
    if self_ports.contains(&port) {
        let local_ips = local_interface_ips();
        if let Some(bad_ip) = ips.iter().copied().find(|ip| is_local_or_loopback_ip(*ip, &local_ips)) {
            bail!(
                "Direct outbound blocked due to self/loopback IP resolution ({} -> {}:{})",
                host_label,
                bad_ip,
                port
            );
        }
    }
    Ok(())
}

impl DirectOutbound {
    pub async fn connect(
        target: &TargetAddr,
        upstream_dns: SocketAddr,
        fake_ip_pool: Option<&FakeIpPool>,
        self_ports: &[u16],
    ) -> Result<TcpStream> {
        let fut = async {
            match target {
                TargetAddr::Ip(addr) => {
                    validate_direct_ips(&[addr.ip()], addr.port(), self_ports, &addr.ip().to_string())?;
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
                        resolve_via_upstream_dns(domain, upstream_dns, fake_ip_pool, DIRECT_DNS_TIMEOUT)
                            .await
                            .with_context(|| format!("Upstream DNS resolution failed for direct target {}", domain))?
                    };

                    validate_direct_ips(&resolved_ips, *port, self_ports, domain)?;

                    let mut last_err = None;
                    for ip in resolved_ips {
                        let sock_addr = SocketAddr::new(ip, *port);
                        match TcpStream::connect(sock_addr).await {
                            Ok(stream) => return Ok(stream),
                            Err(e) => last_err = Some(e),
                        }
                    }

                    match last_err {
                        Some(e) => Err(anyhow::Error::new(e)).with_context(|| {
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
}
