use std::net::SocketAddr;
use std::time::Duration;
use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use super::TargetAddr;

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
    pub async fn connect(&self, target: &TargetAddr) -> Result<TcpStream> {
        tokio::time::timeout(DEFAULT_TIMEOUT, async {
            let stream = TcpStream::connect(&self.proxy_addr)
                .await
                .with_context(|| format!("Failed to connect to SOCKS5 proxy: {}", self.proxy_addr))?;

            self.handshake(stream, target).await
        })
        .await
        .map_err(|_| anyhow::anyhow!("SOCKS5 connection timed out ({:?}): {}", DEFAULT_TIMEOUT, self.proxy_addr))?
    }

    /// Perform SOCKS5 handshake over an already established stream (e.g. for proxy chaining)
    pub async fn handshake(&self, mut stream: TcpStream, target: &TargetAddr) -> Result<TcpStream> {
        tokio::time::timeout(DEFAULT_TIMEOUT, self.handshake_internal(&mut stream, target))
            .await
            .map_err(|_| anyhow::anyhow!("SOCKS5 handshake timed out ({:?})", DEFAULT_TIMEOUT))??;
        Ok(stream)
    }

    async fn handshake_internal(&self, stream: &mut TcpStream, target: &TargetAddr) -> Result<()> {
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
                        bail!("SOCKS5 auth sub-negotiation response version error: 0x{:02x}", auth_resp[0]);
                    }
                    if auth_resp[1] != 0x00 {
                        bail!("SOCKS5 authentication failed (status: 0x{:02x})", auth_resp[1]);
                    }
                } else {
                    bail!("Proxy requires authentication, but no credentials provided");
                }
            }
            0xFF => bail!("SOCKS5 proxy rejected authentication methods offered by client (0xFF)"),
            other => bail!("SOCKS5 unsupported authentication response code: 0x{:02x}", other),
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
                    bail!("SOCKS5 target domain length exceeds RFC 1928 limit (max 255 bytes): {}", domain);
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
            bail!("SOCKS5 target connection failed: {} (code 0x{:02x})", reason, reply_header[1]);
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
            other => bail!("SOCKS5 returned unknown bound address type: 0x{:02x}", other),
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_client_creation() {
        let client = Socks5Client::new("127.0.0.1:1080")
            .with_auth("user".into(), "pass".into());
        assert_eq!(client.proxy_addr, "127.0.0.1:1080");
        assert_eq!(client.auth, Some(("user".into(), "pass".into())));
    }
}
