use std::net::SocketAddr;
use std::time::Duration;
use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use super::TargetAddr;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct Socks4Client {
    pub proxy_addr: String,
    pub user_id: String,
}

impl Socks4Client {
    pub fn new(proxy_addr: impl Into<String>) -> Self {
        Self {
            proxy_addr: proxy_addr.into(),
            user_id: "flowx".into(),
        }
    }

    pub fn with_user_id(mut self, user_id: String) -> Self {
        self.user_id = user_id;
        self
    }

    pub async fn connect(&self, target: &TargetAddr) -> Result<TcpStream> {
        tokio::time::timeout(DEFAULT_TIMEOUT, async {
            let stream = TcpStream::connect(&self.proxy_addr)
                .await
                .with_context(|| format!("Failed to connect to SOCKS4 proxy: {}", self.proxy_addr))?;

            self.handshake(stream, target).await
        })
        .await
        .map_err(|_| anyhow::anyhow!("SOCKS4 connection timed out ({:?}): {}", DEFAULT_TIMEOUT, self.proxy_addr))?
    }

    pub async fn handshake(&self, mut stream: TcpStream, target: &TargetAddr) -> Result<TcpStream> {
        tokio::time::timeout(DEFAULT_TIMEOUT, self.handshake_internal(&mut stream, target))
            .await
            .map_err(|_| anyhow::anyhow!("SOCKS4 handshake timed out ({:?})", DEFAULT_TIMEOUT))??;
        Ok(stream)
    }

    async fn handshake_internal(&self, stream: &mut TcpStream, target: &TargetAddr) -> Result<()> {
        if self.user_id.contains('\0') {
            bail!("SOCKS4 user_id contains invalid null byte (\\0)");
        }
        if self.user_id.len() > 255 {
            bail!("SOCKS4 user_id length exceeds 255 bytes limit: {}", self.user_id.len());
        }

        let mut req = Vec::new();
        req.push(0x04); // VN: 4
        req.push(0x01); // CD: 1 (CONNECT)

        let port_bytes = target.port().to_be_bytes();
        req.extend_from_slice(&port_bytes);

        match target {
            TargetAddr::Ip(SocketAddr::V4(v4)) => {
                // Standard SOCKS4
                req.extend_from_slice(&v4.ip().octets());
                req.extend_from_slice(self.user_id.as_bytes());
                req.push(0x00);
            }
            TargetAddr::Ip(SocketAddr::V6(_)) => {
                bail!("SOCKS4 protocol does not support IPv6 target addresses");
            }
            TargetAddr::Domain(domain, _) => {
                if domain.contains('\0') {
                    bail!("SOCKS4 target domain contains invalid null byte (\\0): {}", domain);
                }
                if domain.len() > 255 {
                    bail!("SOCKS4a target domain length exceeds 255 bytes limit: {}", domain.len());
                }
                // SOCKS4a domain extension: IP set to 0.0.0.1
                req.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
                req.extend_from_slice(self.user_id.as_bytes());
                req.push(0x00);
                req.extend_from_slice(domain.as_bytes());
                req.push(0x00);
            }
        }

        stream.write_all(&req).await?;

        // Read response: 8 bytes (VN, CD, DSTPORT, DSTIP)
        let mut reply = [0u8; 8];
        stream.read_exact(&mut reply).await?;

        // reply[0] should be 0x00 (RFC standard) or 0x04
        if reply[0] != 0x00 && reply[0] != 0x04 {
            bail!("Invalid SOCKS4 reply version: 0x{:02x}", reply[0]);
        }

        if reply[1] != 0x5A {
            let reason = match reply[1] {
                0x5B => "Request rejected or failed (91)",
                0x5C => "Cannot connect to identd on client (92)",
                0x5D => "Identd reported user mismatch (93)",
                _code => "Unknown error code",
            };
            bail!("SOCKS4 proxy connection failed: {} (code: 0x{:02x})", reason, reply[1]);
        }

        Ok(())
    }
}
