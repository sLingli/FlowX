use std::time::Duration;
use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use super::TargetAddr;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct HttpConnectClient {
    pub proxy_addr: String,
    pub auth: Option<(String, String)>,
}

impl HttpConnectClient {
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

    pub async fn connect(&self, target: &TargetAddr) -> Result<TcpStream> {
        tokio::time::timeout(DEFAULT_TIMEOUT, async {
            let stream = TcpStream::connect(&self.proxy_addr)
                .await
                .with_context(|| format!("Failed to connect to HTTP proxy: {}", self.proxy_addr))?;

            self.handshake(stream, target).await
        })
        .await
        .map_err(|_| anyhow::anyhow!("HTTP proxy connection timed out ({:?}): {}", DEFAULT_TIMEOUT, self.proxy_addr))?
    }

    /// Perform HTTP CONNECT tunnel handshake on an existing TCP stream
    pub async fn handshake(&self, mut stream: TcpStream, target: &TargetAddr) -> Result<TcpStream> {
        tokio::time::timeout(DEFAULT_TIMEOUT, self.handshake_internal(&mut stream, target))
            .await
            .map_err(|_| anyhow::anyhow!("HTTP CONNECT handshake timed out ({:?})", DEFAULT_TIMEOUT))??;
        Ok(stream)
    }

    async fn handshake_internal(&self, stream: &mut TcpStream, target: &TargetAddr) -> Result<()> {
        let target_authority = match target {
            TargetAddr::Ip(addr) => addr.to_string(),
            TargetAddr::Domain(host, port) => {
                if host.contains('\r') || host.contains('\n') || host.contains(' ') {
                    bail!("HTTP target domain contains invalid control characters: {:?}", host);
                }
                format!("{}:{}", host, port)
            }
        };

        let mut req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: Keep-Alive\r\n",
            target_authority, target_authority
        );

        if let Some((user, pass)) = &self.auth {
            if user.contains('\r') || user.contains('\n') || pass.contains('\r') || pass.contains('\n') {
                bail!("HTTP proxy credentials contain invalid control characters");
            }
            let encoded = base64_encode(format!("{}:{}", user, pass).as_bytes());
            req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }

        req.push_str("\r\n");

        stream.write_all(req.as_bytes()).await?;

        // Read response until header end (\r\n\r\n)
        let mut response_buf = Vec::new();
        let mut single_byte = [0u8; 1];
        loop {
            stream.read_exact(&mut single_byte).await?;
            response_buf.push(single_byte[0]);

            if response_buf.ends_with(b"\r\n\r\n") {
                break;
            }
            if response_buf.len() > 8192 {
                bail!("HTTP proxy response headers too large (exceeds 8KB)");
            }
        }

        let resp_str = String::from_utf8_lossy(&response_buf);
        let first_line = resp_str.lines().next().unwrap_or_default();

        // Expect first line like: "HTTP/1.1 200 Connection established"
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            bail!("HTTP proxy returned invalid status line: {}", first_line);
        }

        let status_code: u16 = parts[1].parse().with_context(|| {
            format!("Failed to parse HTTP proxy response status code: {}", parts[1])
        })?;

        // Follow RFC 7231: allow all 2xx status codes
        if !(200..=299).contains(&status_code) {
            let reason = match status_code {
                407 => "Proxy Authentication Required",
                403 => "Forbidden",
                502 => "Bad Gateway",
                503 => "Service Unavailable",
                504 => "Gateway Timeout",
                _ => "Non-2xx response",
            };
            bail!("HTTP CONNECT tunnel establishment failed [{}]: {}", status_code, reason);
        }

        Ok(())
    }
}

/// Minimal zero-dependency Base64 encoder
#[allow(clippy::chunks_exact_to_as_chunks)]
fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut chunks = input.chunks_exact(3);

    for chunk in chunks.by_ref() {
        let b0 = chunk[0] as usize;
        let b1 = chunk[1] as usize;
        let b2 = chunk[2] as usize;
        out.push(TABLE[b0 >> 2] as char);
        out.push(TABLE[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        out.push(TABLE[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        out.push(TABLE[b2 & 0x3f] as char);
    }

    let rem = chunks.remainder();
    if rem.len() == 1 {
        let b0 = rem[0] as usize;
        out.push(TABLE[b0 >> 2] as char);
        out.push(TABLE[(b0 & 0x03) << 4] as char);
        out.push('=');
        out.push('=');
    } else if rem.len() == 2 {
        let b0 = rem[0] as usize;
        let b1 = rem[1] as usize;
        out.push(TABLE[b0 >> 2] as char);
        out.push(TABLE[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        out.push(TABLE[(b1 & 0x0f) << 2] as char);
        out.push('=');
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b"admin:123456"), "YWRtaW46MTIzNDU2");
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
    }
}
