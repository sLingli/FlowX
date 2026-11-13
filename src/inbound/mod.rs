//! 混合协议入站 (Mixed Inbound)
//!
//! 在同一个监听端口上自动识别 SOCKS5 / SOCKS4(a) / HTTP CONNECT / HTTP 明文转发四种代理协议，
//! 并从协议握手中解析出客户端真正想要访问的目标地址。
//!
//! 这取代了早期从 `accept()` 后的 `local_addr()` 推断目标的做法 —— 在未接入驱动级流量重定向
//! (Wintun / WinDivert) 的情况下，`local_addr()` 永远是 FlowX 自身的监听地址，
//! 会导致每条连接都被识别为发往 `127.0.0.1:<入站端口>` 并直连回自身，形成无限自连循环。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::outbound::TargetAddr;

/// HTTP 请求头部允许的最大字节数（防止慢速/超大头部 DoS）
const MAX_HTTP_HEADER: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundKind {
    Socks5,
    Socks4,
    HttpConnect,
    HttpForward,
}

impl InboundKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            InboundKind::Socks5 => "SOCKS5",
            InboundKind::Socks4 => "SOCKS4",
            InboundKind::HttpConnect => "HTTP-CONNECT",
            InboundKind::HttpForward => "HTTP",
        }
    }
}

/// 明文 HTTP 转发请求体帧边界（用于限制上游写入长度，阻断流水线走私）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpBodyFraming {
    ContentLength(u64),
    Chunked,
}

/// 一次入站握手解析的结果
#[derive(Debug)]
pub struct InboundRequest {
    pub kind: InboundKind,
    pub target: TargetAddr,
    /// 隧道建立后需要首先写往远端的数据
    /// （HTTP 明文转发时仅为改写后的请求头；CONNECT 时为客户端提前发送的数据）
    pub pending: Vec<u8>,
    /// 明文 HTTP 转发时的请求体帧边界；其余协议为 None
    pub http_body_framing: Option<HttpBodyFraming>,
    /// 解析 HTTP 请求头时已多读入的请求体前缀字节（仅用于受限帧转发，绝不无界透传）
    pub body_prefix: Vec<u8>,
}

/// 读取并解析入站握手，返回目标地址（此时尚未向客户端回复成功）
pub async fn read_request<S>(stream: &mut S) -> Result<InboundRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await.context("Failed to read first inbound byte")?;
    match first[0] {
        0x05 => read_socks5(stream).await,
        0x04 => read_socks4(stream).await,
        b'A'..=b'Z' => read_http(stream, first[0]).await,
        other => bail!("Unrecognized inbound protocol (first byte 0x{:02x})", other),
    }
}

/// 目标连接成功后，按协议向客户端回复成功
pub async fn send_success<S>(stream: &mut S, kind: InboundKind) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    match kind {
        // BND.ADDR 填 0.0.0.0:0，客户端普遍不使用该字段
        InboundKind::Socks5 => stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await,
        InboundKind::Socks4 => stream.write_all(&[0x00, 0x5A, 0, 0, 0, 0, 0, 0]).await,
        InboundKind::HttpConnect => {
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: FlowX\r\n\r\n")
                .await
        }
        InboundKind::HttpForward => Ok(()),
    }
}

/// 规则阻断或出站失败时，按协议向客户端回复失败
pub async fn send_failure<S>(stream: &mut S, kind: InboundKind, blocked: bool) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    match kind {
        InboundKind::Socks5 => {
            // 0x02: 规则集拒绝; 0x05: 连接被拒绝
            let rep = if blocked { 0x02 } else { 0x05 };
            stream.write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await
        }
        InboundKind::Socks4 => stream.write_all(&[0x00, 0x5B, 0, 0, 0, 0, 0, 0]).await,
        InboundKind::HttpConnect | InboundKind::HttpForward => {
            let resp: &[u8] = if blocked {
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            } else {
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            };
            stream.write_all(resp).await
        }
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 (RFC 1928)，仅支持 NO AUTH + CONNECT
// ---------------------------------------------------------------------------

async fn read_socks5<S>(stream: &mut S) -> Result<InboundRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut nmethods = [0u8; 1];
    stream.read_exact(&mut nmethods).await?;
    let mut methods = vec![0u8; nmethods[0] as usize];
    stream.read_exact(&mut methods).await?;

    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xFF]).await.ok();
        bail!("SOCKS5 client did not offer NO AUTH authentication method");
    }
    stream.write_all(&[0x05, 0x00]).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        bail!("SOCKS5 invalid version: 0x{:02x}", header[0]);
    }
    if header[1] != 0x01 {
        // 0x07: Command not supported (BIND / UDP ASSOCIATE 暂不支持)
        stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.ok();
        bail!("SOCKS5 unsupported command: 0x{:02x}", header[1]);
    }

    let target = match header[3] {
        0x01 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x04 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[..16]);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            TargetAddr::Ip(SocketAddr::new(IpAddr::from(octets), port))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let host = String::from_utf8(domain).context("SOCKS5 target domain is not valid UTF-8")?;
            make_target(&host, u16::from_be_bytes(port))?
        }
        other => {
            stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.ok();
            bail!("SOCKS5 unsupported address type: 0x{:02x}", other);
        }
    };

    Ok(InboundRequest {
        kind: InboundKind::Socks5,
        target,
        pending: Vec::new(),
        http_body_framing: None,
        body_prefix: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// SOCKS4 / SOCKS4a，仅支持 CONNECT
// ---------------------------------------------------------------------------

async fn read_socks4<S>(stream: &mut S) -> Result<InboundRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 7];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x01 {
        stream.write_all(&[0x00, 0x5B, 0, 0, 0, 0, 0, 0]).await.ok();
        bail!("SOCKS4 unsupported command: 0x{:02x}", header[0]);
    }
    let port = u16::from_be_bytes([header[1], header[2]]);
    let ip = Ipv4Addr::new(header[3], header[4], header[5], header[6]);

    // USERID（以 NUL 结尾，忽略内容）
    read_nul_terminated(stream, 255).await.context("Failed to read SOCKS4 USERID")?;

    // SOCKS4a：DSTIP 为 0.0.0.x (x != 0) 时，USERID 之后紧跟以 NUL 结尾的域名
    let o = ip.octets();
    let target = if o[0] == 0 && o[1] == 0 && o[2] == 0 && o[3] != 0 {
        let domain = read_nul_terminated(stream, 255).await.context("Failed to read SOCKS4a domain")?;
        let host = String::from_utf8(domain).context("SOCKS4a target domain is not valid UTF-8")?;
        make_target(&host, port)?
    } else {
        TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port))
    };

    Ok(InboundRequest {
        kind: InboundKind::Socks4,
        target,
        pending: Vec::new(),
        http_body_framing: None,
        body_prefix: Vec::new(),
    })
}

async fn read_nul_terminated<S>(stream: &mut S, max: usize) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    loop {
        stream.read_exact(&mut b).await?;
        if b[0] == 0 {
            return Ok(out);
        }
        if out.len() >= max {
            bail!("Field length exceeds {} bytes limit", max);
        }
        out.push(b[0]);
    }
}

// ---------------------------------------------------------------------------
// HTTP CONNECT / HTTP 明文转发
// ---------------------------------------------------------------------------

async fn read_http<S>(stream: &mut S, first: u8) -> Result<InboundRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(2048);
    buf.push(first);
    let mut tmp = [0u8; 4096];

    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > MAX_HTTP_HEADER {
            reply_http_error(stream, "431 Request Header Fields Too Large").await;
            bail!("HTTP headers exceed {} bytes limit", MAX_HTTP_HEADER);
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            bail!("Connection closed before HTTP headers ended");
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let head = &buf[..header_end - 4]; // 不含末尾空行
    let leftover = buf[header_end..].to_vec();

    let Some(lines) = split_crlf_lines(head) else {
        reply_http_error(stream, "400 Bad Request").await;
        bail!("HTTP request contains invalid line endings or NUL byte");
    };
    let mut lines_iter = lines.into_iter();
    let request_line = lines_iter.next().unwrap_or_default();
    let Ok(request_line) = std::str::from_utf8(request_line) else {
        reply_http_error(stream, "400 Bad Request").await;
        bail!("HTTP request line is not valid UTF-8");
    };
    let mut parts = request_line.split(' ');
    let (Some(method), Some(uri), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        reply_http_error(stream, "400 Bad Request").await;
        bail!("Malformed HTTP request line: {:?}", request_line);
    };
    if method.is_empty() || !method.bytes().all(is_http_token_byte) {
        reply_http_error(stream, "400 Bad Request").await;
        bail!("Invalid HTTP method token: {:?}", method);
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        if version.starts_with("HTTP/") {
            reply_http_error(stream, "505 HTTP Version Not Supported").await;
        } else {
            reply_http_error(stream, "400 Bad Request").await;
        }
        bail!("Unsupported HTTP version: {}", version);
    }

    let is_connect = method.eq_ignore_ascii_case("CONNECT");
    let (target, origin_path) = if is_connect {
        let target = match parse_authority(uri, None) {
            Ok(t) => t,
            Err(e) => {
                reply_http_error(stream, "400 Bad Request").await;
                return Err(e);
            }
        };
        (target, None)
    } else {
        // 明文代理请求必须使用绝对 URI：http://host[:port]/path，且禁止 fragment 或 authority 含 ?/#
        if uri.contains('#') {
            reply_http_error(stream, "400 Bad Request").await;
            bail!("HTTP proxy request URI must not contain fragment: {}", uri);
        }
        let Some(rest) = strip_prefix_ignore_case(uri, "http://") else {
            reply_http_error(stream, "400 Bad Request").await;
            bail!("HTTP proxy request must use http:// absolute URI: {}", uri);
        };
        let (authority, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        if authority.contains(['?', '#', '@', '\\']) {
            reply_http_error(stream, "400 Bad Request").await;
            bail!("HTTP proxy authority contains forbidden delimiter: {}", authority);
        }
        let target = match parse_authority(authority, Some(80)) {
            Ok(t) => t,
            Err(e) => {
                reply_http_error(stream, "400 Bad Request").await;
                return Err(e);
            }
        };
        (target, Some(path))
    };

    // 严格校验请求头，阻断请求走私（obs-fold、畸形字段名、CL/TE 冲突、Host 不一致等）
    let mut header_lines: Vec<(&[u8], &[u8])> = Vec::new();
    let mut host_header: Option<&str> = None;
    let mut content_length: Option<u64> = None;
    let mut transfer_encoding_seen = false;
    let mut upgrade_seen = false;
    let mut nominated_hop_headers: Vec<Vec<u8>> = Vec::new();

    for line in lines_iter {
        if line.is_empty() || line[0] == b' ' || line[0] == b'\t' {
            reply_http_error(stream, "400 Bad Request").await;
            bail!("Malformed or obs-fold HTTP header line");
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            reply_http_error(stream, "400 Bad Request").await;
            bail!("HTTP header line missing colon");
        };
        let name = &line[..colon];
        let val = &line[colon + 1..];
        if name.is_empty() || !name.iter().all(|&b| is_http_token_byte(b)) {
            reply_http_error(stream, "400 Bad Request").await;
            bail!("Invalid HTTP header name");
        }
        if val.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            reply_http_error(stream, "400 Bad Request").await;
            bail!("HTTP header value contains control characters");
        }

        if name.eq_ignore_ascii_case(b"host") {
            if host_header.is_some() {
                reply_http_error(stream, "400 Bad Request").await;
                bail!("Duplicate Host header");
            }
            let Ok(v) = std::str::from_utf8(val) else {
                reply_http_error(stream, "400 Bad Request").await;
                bail!("Non-UTF-8 Host header");
            };
            host_header = Some(v.trim_matches(|c| c == ' ' || c == '\t'));
        } else if name.eq_ignore_ascii_case(b"content-length") {
            if is_connect || content_length.is_some() {
                reply_http_error(stream, "400 Bad Request").await;
                bail!("Forbidden or duplicate Content-Length header");
            }
            let Ok(v) = std::str::from_utf8(val) else {
                reply_http_error(stream, "400 Bad Request").await;
                bail!("Invalid Content-Length header");
            };
            let trimmed = v.trim_matches(|c| c == ' ' || c == '\t');
            let parsed_cl = trimmed.parse::<u64>().ok();
            if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) || parsed_cl.is_none() {
                reply_http_error(stream, "400 Bad Request").await;
                bail!("Malformed Content-Length header: {:?}", trimmed);
            }
            content_length = parsed_cl;
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            if is_connect || transfer_encoding_seen {
                reply_http_error(stream, "400 Bad Request").await;
                bail!("Forbidden or duplicate Transfer-Encoding header");
            }
            let Ok(v) = std::str::from_utf8(val) else {
                reply_http_error(stream, "400 Bad Request").await;
                bail!("Invalid Transfer-Encoding header");
            };
            let trimmed = v.trim_matches(|c| c == ' ' || c == '\t');
            if !trimmed.eq_ignore_ascii_case("chunked") {
                reply_http_error(stream, "400 Bad Request").await;
                bail!("Unsupported Transfer-Encoding: {:?}", trimmed);
            }
            transfer_encoding_seen = true;
        } else if name.eq_ignore_ascii_case(b"upgrade") {
            if !is_connect {
                reply_http_error(stream, "400 Bad Request").await;
                bail!("Upgrade header is not supported on plain HTTP proxy requests");
            }
            upgrade_seen = true;
        } else if name.eq_ignore_ascii_case(b"connection") || name.eq_ignore_ascii_case(b"proxy-connection") {
            let Ok(v) = std::str::from_utf8(val) else {
                reply_http_error(stream, "400 Bad Request").await;
                bail!("Invalid Connection header");
            };
            for item in v.split(',') {
                let token = item.trim_matches(|c| c == ' ' || c == '\t');
                if token.is_empty() {
                    continue;
                }
                if !token.bytes().all(is_http_token_byte) {
                    reply_http_error(stream, "400 Bad Request").await;
                    bail!("Malformed token in Connection header: {:?}", token);
                }
                let lower = token.to_ascii_lowercase();
                if matches!(lower.as_str(), "host" | "content-length" | "transfer-encoding")
                    || (!is_connect && lower == "upgrade")
                {
                    reply_http_error(stream, "400 Bad Request").await;
                    bail!("Connection header must not nominate framing header: {}", lower);
                }
                nominated_hop_headers.push(lower.into_bytes());
            }
        }

        header_lines.push((line, name));
    }

    if content_length.is_some() && transfer_encoding_seen {
        reply_http_error(stream, "400 Bad Request").await;
        bail!("HTTP request contains both Content-Length and Transfer-Encoding");
    }
    if is_connect && upgrade_seen {
        reply_http_error(stream, "400 Bad Request").await;
        bail!("Upgrade header is not allowed on CONNECT");
    }

    if version == "HTTP/1.1" && host_header.is_none() {
        reply_http_error(stream, "400 Bad Request").await;
        bail!("HTTP/1.1 request missing Host header");
    }
    if let Some(host_str) = host_header {
        let Ok(host_target) = TargetAddr::parse_authority(host_str, Some(target.port()), false) else {
            reply_http_error(stream, "400 Bad Request").await;
            bail!("Invalid Host header: {:?}", host_str);
        };
        if host_target != target {
            reply_http_error(stream, "400 Bad Request").await;
            bail!("Host header {:?} does not match request target {:?}", host_str, target);
        }
    }

    if is_connect {
        return Ok(InboundRequest {
            kind: InboundKind::HttpConnect,
            target,
            pending: leftover,
            http_body_framing: None,
            body_prefix: Vec::new(),
        });
    }

    let http_body_framing = if transfer_encoding_seen {
        Some(HttpBodyFraming::Chunked)
    } else {
        Some(HttpBodyFraming::ContentLength(content_length.unwrap_or(0)))
    };

    let path = origin_path.unwrap_or("/");

    // 改写为源站形式 (origin-form)，移除 RFC 9110 §7.6.1 与 Connection 指定的逐跳头，并强制 Connection: close，
    // 防止同一条 keep-alive 连接上的后续请求被误发往首个请求的目标主机
    let mut rewritten = Vec::with_capacity(head.len() + 32);
    rewritten.extend_from_slice(format!("{} {} {}\r\n", method, path, version).as_bytes());
    for (line, name) in header_lines {
        let is_fixed_hop = [
            &b"proxy-connection"[..],
            b"proxy-authorization",
            b"proxy-authenticate",
            b"connection",
            b"keep-alive",
            b"te",
            b"trailer",
            b"upgrade",
        ]
        .iter()
        .any(|h| name.eq_ignore_ascii_case(h));
        let is_nominated_hop = nominated_hop_headers.iter().any(|h| name.eq_ignore_ascii_case(h));
        if !is_fixed_hop && !is_nominated_hop {
            rewritten.extend_from_slice(line);
            rewritten.extend_from_slice(b"\r\n");
        }
    }
    rewritten.extend_from_slice(b"Connection: close\r\n\r\n");

    Ok(InboundRequest {
        kind: InboundKind::HttpForward,
        target,
        pending: rewritten,
        http_body_framing,
        body_prefix: leftover,
    })
}

pub(crate) fn is_http_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

fn split_crlf_lines(head: &[u8]) -> Option<Vec<&[u8]>> {
    if head.contains(&0) {
        return None;
    }
    let mut lines = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < head.len() {
        if head[i] == b'\n' {
            return None;
        }
        if head[i] == b'\r' {
            if i + 1 >= head.len() || head[i + 1] != b'\n' {
                return None;
            }
            lines.push(&head[start..i]);
            i += 2;
            start = i;
            continue;
        }
        i += 1;
    }
    lines.push(&head[start..]);
    Some(lines)
}

async fn reply_http_error<S>(stream: &mut S, status: &str)
where
    S: AsyncWrite + Unpin,
{
    let resp = format!("HTTP/1.1 {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status);
    let _ = stream.write_all(resp.as_bytes()).await;
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// 解析 `host:port` / `[v6]:port` 形式的 authority；`default_port` 为 None 时端口必填
pub fn parse_authority(authority: &str, default_port: Option<u16>) -> Result<TargetAddr> {
    TargetAddr::parse_authority(authority, default_port, false)
}

/// 由主机字符串构造目标地址：IP 字面量转为 Ip，否则校验为合法域名
fn make_target(host: &str, port: u16) -> Result<TargetAddr> {
    TargetAddr::from_host_port(host, port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_socks5_domain_request() {
        let (mut client, mut server) = duplex(1024);
        let task = tokio::spawn(async move { read_request(&mut server).await.map(|r| (r, server)) });

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0x00]);

        let mut req = vec![0x05, 0x01, 0x00, 0x03, 10];
        req.extend_from_slice(b"github.com");
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).await.unwrap();

        let (r, mut server) = task.await.unwrap().unwrap();
        assert_eq!(r.kind, InboundKind::Socks5);
        assert_eq!(r.target, TargetAddr::Domain("github.com".into(), 443));

        send_success(&mut server, r.kind).await.unwrap();
        let mut ok = [0u8; 10];
        client.read_exact(&mut ok).await.unwrap();
        assert_eq!(ok[1], 0x00);
    }

    #[tokio::test]
    async fn test_socks4a_request() {
        let (mut client, mut server) = duplex(1024);
        let mut req = vec![0x04, 0x01];
        req.extend_from_slice(&80u16.to_be_bytes());
        req.extend_from_slice(&[0, 0, 0, 1]);
        req.extend_from_slice(b"user\0example.org\0");
        client.write_all(&req).await.unwrap();

        let r = read_request(&mut server).await.unwrap();
        assert_eq!(r.kind, InboundKind::Socks4);
        assert_eq!(r.target, TargetAddr::Domain("example.org".into(), 80));
    }

    #[tokio::test]
    async fn test_http_connect_request() {
        let (mut client, mut server) = duplex(4096);
        client
            .write_all(b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\n\r\nEARLY")
            .await
            .unwrap();
        let r = read_request(&mut server).await.unwrap();
        assert_eq!(r.kind, InboundKind::HttpConnect);
        assert_eq!(r.target, TargetAddr::Ip("[2001:db8::1]:8443".parse().unwrap()));
        assert_eq!(r.pending, b"EARLY");
    }

    #[tokio::test]
    async fn test_http_forward_rewrite() {
        let (mut client, mut server) = duplex(4096);
        client
            .write_all(
                b"GET http://Example.com/a?b=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive, X-Hop-Secret\r\nX-Hop-Secret: s\r\nUser-Agent: t\r\n\r\nGET http://evil.example/smuggled HTTP/1.1\r\nHost: evil.example\r\n\r\n",
            )
            .await
            .unwrap();
        let r = read_request(&mut server).await.unwrap();
        assert_eq!(r.kind, InboundKind::HttpForward);
        assert_eq!(r.target, TargetAddr::Domain("example.com".into(), 80));
        assert_eq!(r.http_body_framing, Some(HttpBodyFraming::ContentLength(0)));
        let text = String::from_utf8(r.pending).unwrap();
        assert!(text.starts_with("GET /a?b=1 HTTP/1.1\r\n"));
        assert!(text.contains("Host: example.com\r\n"));
        assert!(text.contains("User-Agent: t\r\n"));
        assert!(!text.contains("X-Hop-Secret"));
        assert!(!text.contains("smuggled"));
        assert!(!text.to_lowercase().contains("keep-alive"));
        assert!(text.ends_with("Connection: close\r\n\r\n"));
        assert!(r.body_prefix.starts_with(b"GET http://evil.example/smuggled"));
    }

    #[tokio::test]
    async fn test_http_forward_captures_content_length_and_chunked_framing() {
        let (mut c1, mut s1) = duplex(4096);
        c1.write_all(
            b"POST http://example.com/submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhelloEXTRA",
        )
        .await
        .unwrap();
        let r1 = read_request(&mut s1).await.unwrap();
        assert_eq!(r1.http_body_framing, Some(HttpBodyFraming::ContentLength(5)));
        assert!(!r1.pending.ends_with(b"helloEXTRA"));
        assert_eq!(r1.body_prefix, b"helloEXTRA");

        let (mut c2, mut s2) = duplex(4096);
        c2.write_all(
            b"POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        )
        .await
        .unwrap();
        let r2 = read_request(&mut s2).await.unwrap();
        assert_eq!(r2.http_body_framing, Some(HttpBodyFraming::Chunked));
        assert_eq!(r2.body_prefix, b"3\r\nabc\r\n0\r\n\r\n");
    }

    #[tokio::test]
    async fn test_http_origin_form_rejected() {
        let (mut client, mut server) = duplex(4096);
        client.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").await.unwrap();
        assert!(read_request(&mut server).await.is_err());
        let mut resp = vec![0u8; 64];
        let n = client.read(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp[..n]).starts_with("HTTP/1.1 400"));
    }

    #[tokio::test]
    async fn test_http_smuggling_and_host_mismatch_rejected() {
        let bad_cases: &[&[u8]] = &[
            b"GET http://example.com/ HTTP/1.1\nHost: example.com\r\n\r\n",
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n folded: 1\r\n\r\n",
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length : 0\r\n\r\n",
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            b"GET http://user:pass@example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"GET http://good.com?@evil.com/ HTTP/1.1\r\nHost: good.com\r\n\r\n",
            b"GET http://good.com#evil.com/ HTTP/1.1\r\nHost: good.com\r\n\r\n",
            b"GET http://example.com/ HTTP/1.1\r\nHost: other.com\r\n\r\n",
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: other.com:443\r\n\r\n",
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nContent-Length: 0\r\n\r\n",
            b"GET http://example.com/ HTTP/1.9\r\nHost: example.com\r\n\r\n",
        ];

        for raw in bad_cases {
            let (mut client, mut server) = duplex(4096);
            client.write_all(raw).await.unwrap();
            assert!(read_request(&mut server).await.is_err(), "expected err for {:?}", String::from_utf8_lossy(raw));
            let mut resp = vec![0u8; 64];
            let n = client.read(&mut resp).await.unwrap();
            let text = String::from_utf8_lossy(&resp[..n]);
            assert!(
                text.starts_with("HTTP/1.1 400") || text.starts_with("HTTP/1.1 505"),
                "unexpected status for {:?}: {}",
                String::from_utf8_lossy(raw),
                text
            );
        }
    }

    #[test]
    fn test_parse_authority() {
        assert_eq!(parse_authority("a.com:443", None).unwrap(), TargetAddr::Domain("a.com".into(), 443));
        assert_eq!(parse_authority("a.com", Some(80)).unwrap(), TargetAddr::Domain("a.com".into(), 80));
        assert!(parse_authority("a.com", None).is_err());
        assert!(parse_authority("user:pass@a.com:443", None).is_err());
        assert!(parse_authority("bad host:80", None).is_err());
        assert!(parse_authority("a.com:0", None).is_err());
        assert_eq!(
            parse_authority("1.2.3.4:5", None).unwrap(),
            TargetAddr::Ip("1.2.3.4:5".parse().unwrap())
        );
    }
}
