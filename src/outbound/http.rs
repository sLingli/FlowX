use std::net::SocketAddr;
use std::time::Duration;
use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::dns::FakeIpPool;
use super::direct::{connect_proxy_tcp, DEFAULT_OUTBOUND_UPSTREAM_DNS};
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
        self.connect_with_policy(target, DEFAULT_OUTBOUND_UPSTREAM_DNS, None, &[])
            .await
    }

    pub async fn connect_with_policy(
        &self,
        target: &TargetAddr,
        upstream_dns: SocketAddr,
        fake_ip_pool: Option<&FakeIpPool>,
        self_ports: &[u16],
    ) -> Result<TcpStream> {
        tokio::time::timeout(DEFAULT_TIMEOUT, async {
            let stream = connect_proxy_tcp(
                &self.proxy_addr,
                upstream_dns,
                fake_ip_pool,
                self_ports,
                "HTTP proxy",
            )
            .await?;

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
                if host.is_empty()
                    || host.bytes().any(|b| {
                        b < 0x20
                            || b == 0x7f
                            || matches!(b, b' ' | b'/' | b'?' | b'#' | b'@' | b'\\')
                    })
                {
                    bail!("HTTP target domain contains invalid characters: {:?}", host);
                }
                format!("{}:{}", host, port)
            }
        };

        let mut req = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: Keep-Alive\r\n",
            target_authority, target_authority
        );

        if let Some((user, pass)) = &self.auth {
            if user.chars().any(char::is_control) || pass.chars().any(char::is_control) {
                bail!("HTTP proxy credentials contain invalid control characters");
            }
            if user.contains(':') {
                bail!("HTTP proxy Basic authentication username cannot contain ':' (RFC 7617)");
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

        let status_code = parse_connect_response_head(&response_buf)?;

        // Follow RFC 9110: allow 2xx status codes for CONNECT tunnel establishment
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

/// 严格校验上游 CONNECT 响应头（仅接受 \r\n\r\n 结尾、无 NUL/孤立换行，严格 HTTP/1.0 或 HTTP/1.1 与三位状态码）
fn parse_connect_status_line(first_line: &str) -> Result<u16> {
    let rest = first_line
        .strip_prefix("HTTP/1.1 ")
        .or_else(|| first_line.strip_prefix("HTTP/1.0 "))
        .ok_or_else(|| anyhow::anyhow!("HTTP proxy returned invalid status line version: {:?}", first_line))?;

    let bytes = rest.as_bytes();
    if bytes.len() < 3 || !bytes[..3].iter().all(|b| b.is_ascii_digit()) {
        bail!("HTTP proxy returned malformed status code: {:?}", first_line);
    }
    if bytes.len() > 3 && bytes[3] != b' ' {
        bail!("HTTP proxy status code must be 3 digits: {:?}", first_line);
    }
    // Reject leading zero like 0200 (handled above via len>3 != ' '), or 020 (< 100)
    if bytes[0] == b'0' {
        bail!("HTTP proxy returned invalid status code leading zero: {:?}", first_line);
    }
    let code: u16 = rest[..3]
        .parse()
        .with_context(|| format!("Failed to parse HTTP proxy status code: {:?}", first_line))?;
    Ok(code)
}

fn parse_connect_response_head(response_buf: &[u8]) -> Result<u16> {
    let Some(head) = response_buf.strip_suffix(b"\r\n\r\n") else {
        bail!("HTTP proxy response did not end with CRLFCRLF");
    };
    if head.contains(&0) {
        bail!("HTTP proxy response contains NUL byte");
    }

    let mut lines = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < head.len() {
        if head[i] == b'\n' {
            bail!("HTTP proxy response contains bare LF");
        }
        if head[i] == b'\r' {
            if i + 1 >= head.len() || head[i + 1] != b'\n' {
                bail!("HTTP proxy response contains bare CR");
            }
            lines.push(&head[start..i]);
            i += 2;
            start = i;
            continue;
        }
        i += 1;
    }
    lines.push(&head[start..]);

    let first_line = std::str::from_utf8(lines.first().copied().unwrap_or_default())
        .context("HTTP proxy status line is not valid UTF-8")?;
    let status_code = parse_connect_status_line(first_line)?;

    // Ensure 2xx CONNECT responses do not carry Content-Length / Transfer-Encoding framing headers
    let is_2xx = (200..=299).contains(&status_code);
    for line in &lines[1..] {
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            bail!("HTTP proxy response header missing colon");
        };
        let name = &line[..colon];
        if name.is_empty() || name.iter().any(|&b| b == b' ' || b == b'\t') {
            bail!("HTTP proxy response contains malformed header name");
        }
        if is_2xx
            && (name.eq_ignore_ascii_case(b"content-length")
                || name.eq_ignore_ascii_case(b"transfer-encoding"))
        {
            bail!("HTTP proxy 2xx CONNECT response must not contain body framing headers");
        }
    }

    Ok(status_code)
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

    #[test]
    fn test_parse_connect_status_line_strict() {
        assert_eq!(parse_connect_status_line("HTTP/1.1 200 Connection established").unwrap(), 200);
        assert_eq!(parse_connect_status_line("HTTP/1.0 200").unwrap(), 200);
        assert_eq!(parse_connect_status_line("HTTP/1.1 407 Proxy Authentication Required").unwrap(), 407);

        for bad in [
            "HTTP/1.1 +200 OK",
            "HTTP/1.1 0200 OK",
            "HTTP/1.1 2000 OK",
            "HTTP/1.1 020 OK",
            "HTTP/1.1  200 OK",
            "HTTP/2 200 OK",
            "HTTP/1.1 200OK",
            "NOTHTTP 200 OK",
        ] {
            assert!(parse_connect_status_line(bad).is_err(), "expected err for {:?}", bad);
        }

        assert!(parse_connect_response_head(b"HTTP/1.1 200 OK\r\nProxy-Agent: x\r\n\r\n").is_ok());
        assert!(parse_connect_response_head(b"HTTP/1.1 200 OK\n\r\n\r\n").is_err());
        assert!(parse_connect_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n").is_err());
    }

    #[tokio::test]
    async fn test_http_connect_rejects_bad_target_chars_basic_colon_and_fake_ip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                drop(s);
            }
        });

        let client = HttpConnectClient::new(proxy_addr.to_string());
        for bad_host in ["evil.com/path", "evil.com?x=1", "evil.com#frag", "user@evil.com", "evil.com\tHTTP/1.1", "evil\0.com"] {
            let s = TcpStream::connect(proxy_addr).await.unwrap();
            let err = client
                .handshake(s, &TargetAddr::Domain(bad_host.into(), 443))
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("invalid characters"),
                "expected invalid char err for {:?}: {}",
                bad_host,
                err
            );
        }

        let bad_user_client = HttpConnectClient::new(proxy_addr.to_string())
            .with_auth("ali:ce".into(), "secret".into());
        let s = TcpStream::connect(proxy_addr).await.unwrap();
        let err = bad_user_client
            .handshake(s, &TargetAddr::Domain("example.com".into(), 443))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("':'"));

        // Fake-IP server_addr must be blocked rather than connecting back into Fake-IP range
        let pool = FakeIpPool::new_default();
        let fake_ip = pool.allocate("upstream-proxy.example");
        let fake_client = HttpConnectClient::new(format!("{}:8080", fake_ip));
        let err = fake_client
            .connect_with_policy(
                &TargetAddr::Domain("example.com".into(), 443),
                "127.0.0.1:53".parse().unwrap(),
                Some(&pool),
                &[40001],
            )
            .await
            .unwrap_err();
        assert!(format!("{:#}", err).contains("Fake-IP"));
    }
}
