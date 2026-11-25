use super::TargetAddr;
use super::bypass::OutboundTcpStream;
use super::direct::{DEFAULT_OUTBOUND_UPSTREAM_DNS, connect_proxy_tcp_guarded};
use crate::dns::FakeIpPool;
use anyhow::{Result, bail};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct Socks5Client {
    pub proxy_addr: String,
    pub auth: Option<(String, String)>,
}

impl Socks5Client {
    pub fn new(proxy_addr: impl Into<String>) -> Self {
        Self {
            proxy_addr: proxy_addr.into(),
            auth: None,
        }
    }

    pub fn with_auth(mut self, user: String, pass: String) -> Self {
        self.auth = Some((user, pass));
        self
    }

    /// Establish initial TCP connection through proxy address and handshake (with 10s timeout protection)
    pub async fn connect(&self, target: &TargetAddr) -> Result<OutboundTcpStream> {
        self.connect_with_policy(target, DEFAULT_OUTBOUND_UPSTREAM_DNS, None, &[])
            .await
    }

    pub async fn connect_with_policy(
        &self,
        target: &TargetAddr,
        upstream_dns: SocketAddr,
        fake_ip_pool: Option<&FakeIpPool>,
        self_ports: &[u16],
    ) -> Result<OutboundTcpStream> {
        self.connect_with_policy_guarded(target, upstream_dns, fake_ip_pool, self_ports)
            .await
    }

    pub async fn connect_with_policy_guarded(
        &self,
        target: &TargetAddr,
        upstream_dns: SocketAddr,
        fake_ip_pool: Option<&FakeIpPool>,
        self_ports: &[u16],
    ) -> Result<OutboundTcpStream> {
        tokio::time::timeout(DEFAULT_TIMEOUT, async {
            let mut stream = connect_proxy_tcp_guarded(
                &self.proxy_addr,
                upstream_dns,
                fake_ip_pool,
                self_ports,
                "SOCKS5 proxy",
            )
            .await?;

            self.handshake_internal(&mut stream, target).await?;
            Ok(stream)
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "SOCKS5 connection timed out ({:?}): {}",
                DEFAULT_TIMEOUT,
                self.proxy_addr
            )
        })?
    }

    /// Perform SOCKS5 handshake over an already established stream (e.g. for proxy chaining)
    pub async fn handshake(&self, stream: TcpStream, target: &TargetAddr) -> Result<TcpStream> {
        self.handshake_stream(stream, target).await
    }

    pub async fn handshake_stream<S>(&self, mut stream: S, target: &TargetAddr) -> Result<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        tokio::time::timeout(
            DEFAULT_TIMEOUT,
            self.handshake_internal(&mut stream, target),
        )
        .await
        .map_err(|_| anyhow::anyhow!("SOCKS5 handshake timed out ({:?})", DEFAULT_TIMEOUT))??;
        Ok(stream)
    }

    async fn handshake_internal<S>(&self, stream: &mut S, target: &TargetAddr) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // 1. Send auth negotiation
        if self.auth.is_some() {
            stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
        } else {
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
        }

        let mut method_reply = [0u8; 2];
        stream.read_exact(&mut method_reply).await?;
        if method_reply[0] != 0x05 {
            bail!("Invalid SOCKS version response: 0x{:02x}", method_reply[0]);
        }

        match method_reply[1] {
            0x00 => {} // No authentication required, proceed to connect
            0x02 => {
                // Username/password authentication subprotocol (RFC 1929)
                if let Some((user, pass)) = &self.auth {
                    if user.len() > 255 || pass.len() > 255 {
                        bail!("SOCKS5 username or password exceeds RFC 1929 limit (max 255 bytes)");
                    }
                    let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
                    auth_req.push(0x01); // Auth version (RFC 1929 specifies 0x01)
                    auth_req.push(user.len() as u8);
                    auth_req.extend_from_slice(user.as_bytes());
                    auth_req.push(pass.len() as u8);
                    auth_req.extend_from_slice(pass.as_bytes());
                    stream.write_all(&auth_req).await?;

                    let mut auth_resp = [0u8; 2];
                    stream.read_exact(&mut auth_resp).await?;
                    if auth_resp[0] != 0x01 {
                        bail!(
                            "SOCKS5 auth sub-negotiation response version error: 0x{:02x}",
                            auth_resp[0]
                        );
                    }
                    if auth_resp[1] != 0x00 {
                        bail!(
                            "SOCKS5 authentication failed (status: 0x{:02x})",
                            auth_resp[1]
                        );
                    }
                } else {
                    bail!("Proxy requires authentication, but no credentials provided");
                }
            }
            0xFF => bail!("SOCKS5 proxy rejected authentication methods offered by client (0xFF)"),
            other => bail!(
                "SOCKS5 unsupported authentication response code: 0x{:02x}",
                other
            ),
        }

        // 2. Initiate CONNECT request (CMD = 0x01)
        let mut connect_req = Vec::new();
        connect_req.extend_from_slice(&[0x05, 0x01, 0x00]);

        match target {
            TargetAddr::Ip(addr) => match addr {
                SocketAddr::V4(v4) => {
                    connect_req.push(0x01); // ATYP: IPv4
                    connect_req.extend_from_slice(&v4.ip().octets());
                    connect_req.extend_from_slice(&v4.port().to_be_bytes());
                }
                SocketAddr::V6(v6) => {
                    connect_req.push(0x04); // ATYP: IPv6
                    connect_req.extend_from_slice(&v6.ip().octets());
                    connect_req.extend_from_slice(&v6.port().to_be_bytes());
                }
            },
            TargetAddr::Domain(domain, port) => {
                if domain.len() > 255 {
                    bail!(
                        "SOCKS5 target domain length exceeds RFC 1928 limit (max 255 bytes): {}",
                        domain
                    );
                }
                connect_req.push(0x03); // ATYP: Domain
                connect_req.push(domain.len() as u8);
                connect_req.extend_from_slice(domain.as_bytes());
                connect_req.extend_from_slice(&port.to_be_bytes());
            }
        }

        stream.write_all(&connect_req).await?;

        // 3. Read reply and parse status
        let mut reply_header = [0u8; 4];
        stream.read_exact(&mut reply_header).await?;
        if reply_header[0] != 0x05 {
            bail!("Invalid SOCKS5 reply version: 0x{:02x}", reply_header[0]);
        }

        if reply_header[1] != 0x00 {
            let reason = match reply_header[1] {
                0x01 => "General SOCKS server failure",
                0x02 => "Connection not allowed by ruleset",
                0x03 => "Network unreachable",
                0x04 => "Host unreachable",
                0x05 => "Connection refused",
                0x06 => "TTL expired",
                0x07 => "Command not supported",
                0x08 => "Address type not supported",
                _code => "Unknown error code",
            };
            bail!(
                "SOCKS5 target connection failed: {} (code 0x{:02x})",
                reason,
                reply_header[1]
            );
        }

        // Read bound address field to clear buffer
        match reply_header[3] {
            0x01 => {
                let mut buf = [0u8; 6]; // 4 bytes IP + 2 bytes Port
                stream.read_exact(&mut buf).await?;
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut buf = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut buf).await?;
            }
            0x04 => {
                let mut buf = [0u8; 18]; // 16 bytes IPv6 + 2 bytes Port
                stream.read_exact(&mut buf).await?;
            }
            other => bail!(
                "SOCKS5 returned unknown bound address type: 0x{:02x}",
                other
            ),
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_client_creation() {
        let client = Socks5Client::new("127.0.0.1:1080").with_auth("user".into(), "pass".into());
        assert_eq!(client.proxy_addr, "127.0.0.1:1080");
        assert_eq!(client.auth, Some(("user".into(), "pass".into())));
    }

    #[tokio::test]
    async fn test_socks5_uses_upstream_dns_and_blocks_loopback_rebinding_and_fake_ip() {
        let mock_dns = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_addr = mock_dns.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..2 {
                let mut buf = [0u8; 512];
                let (n, src) = mock_dns.recv_from(&mut buf).await.unwrap();
                let (tx, q) =
                    crate::dns::server::DnsPacketParser::parse_question(&buf[..n]).unwrap();
                let resp = if q.qtype == 1 {
                    let mut r = Vec::new();
                    r.extend_from_slice(&tx.to_be_bytes());
                    r.extend_from_slice(&[
                        0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                    ]);
                    r.extend_from_slice(&buf[12..q.raw_len]);
                    r.extend_from_slice(&[
                        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 5, 0, 4, 127, 0, 0, 1,
                    ]);
                    r
                } else {
                    crate::dns::server::DnsPacketParser::build_empty_response(tx, &buf, q.raw_len)
                };
                mock_dns.send_to(&resp, src).await.unwrap();
            }
        });

        let pool = FakeIpPool::new_default();
        let client = Socks5Client::new("proxy-domain.example:40001");
        let err = client
            .connect_with_policy(
                &TargetAddr::Domain("example.com".into(), 443),
                dns_addr,
                Some(&pool),
                &[40001, 40080, 1053],
            )
            .await
            .unwrap_err();
        assert!(format!("{:#}", err).contains("self/loopback IP resolution"));

        let fake_ip = pool.allocate("socks5.example");
        let fake_client = Socks5Client::new(format!("{}:1080", fake_ip));
        let err2 = fake_client
            .connect_with_policy(
                &TargetAddr::Domain("example.com".into(), 443),
                dns_addr,
                Some(&pool),
                &[40001],
            )
            .await
            .unwrap_err();
        assert!(format!("{:#}", err2).contains("Fake-IP"));
    }
}
