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

/// 一次入站握手解析的结果
#[derive(Debug)]
pub struct InboundRequest {
    pub kind: InboundKind,
    pub target: TargetAddr,
    /// 隧道建立后需要首先写往远端的数据
    /// （HTTP 明文转发时为改写后的请求头 + 已读取的请求体；CONNECT 时为客户端提前发送的数据）
    pub pending: Vec<u8>,
}

/// 读取并解析入站握手，返回目标地址（此时尚未向客户端回复成功）
pub async fn read_request<S>(stream: &mut S) -> Result<InboundRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await.context("读取入站协议首字节失败")?;
    match first[0] {
        0x05 => read_socks5(stream).await,
        0x04 => read_socks4(stream).await,
        b'A'..=b'Z' => read_http(stream, first[0]).await,
        other => bail!("无法识别的入站协议 (首字节 0x{:02x})", other),
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
        bail!("SOCKS5 客户端未提供 NO AUTH 认证方式");
    }
    stream.write_all(&[0x05, 0x00]).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        bail!("SOCKS5 请求版本错误: 0x{:02x}", header[0]);
    }
    if header[1] != 0x01 {
        // 0x07: Command not supported (BIND / UDP ASSOCIATE 暂不支持)
        stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.ok();
        bail!("SOCKS5 不支持的命令: 0x{:02x}", header[1]);
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
            let host = String::from_utf8(domain).context("SOCKS5 目标域名不是合法 UTF-8")?;
            make_target(&host, u16::from_be_bytes(port))?
        }
        other => {
            stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.ok();
            bail!("SOCKS5 不支持的地址类型: 0x{:02x}", other);
        }
    };

    Ok(InboundRequest { kind: InboundKind::Socks5, target, pending: Vec::new() })
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
        bail!("SOCKS4 不支持的命令: 0x{:02x}", header[0]);
    }
    let port = u16::from_be_bytes([header[1], header[2]]);
    let ip = Ipv4Addr::new(header[3], header[4], header[5], header[6]);

    // USERID（以 NUL 结尾，忽略内容）
    read_nul_terminated(stream, 255).await.context("读取 SOCKS4 USERID 失败")?;

    // SOCKS4a：DSTIP 为 0.0.0.x (x != 0) 时，USERID 之后紧跟以 NUL 结尾的域名
    let o = ip.octets();
    let target = if o[0] == 0 && o[1] == 0 && o[2] == 0 && o[3] != 0 {
        let domain = read_nul_terminated(stream, 255).await.context("读取 SOCKS4a 域名失败")?;
        let host = String::from_utf8(domain).context("SOCKS4a 目标域名不是合法 UTF-8")?;
        make_target(&host, port)?
    } else {
        TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port))
    };

    Ok(InboundRequest { kind: InboundKind::Socks4, target, pending: Vec::new() })
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
            bail!("字段长度超出上限 {} 字节", max);
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
            bail!("HTTP 请求头超出 {} 字节上限", MAX_HTTP_HEADER);
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            bail!("HTTP 请求头尚未结束连接即关闭");
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let head = &buf[..header_end - 4]; // 不含末尾空行
    let leftover = buf[header_end..].to_vec();

    let mut lines = head.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let request_line = lines.next().unwrap_or_default();
    let request_line = std::str::from_utf8(request_line).context("HTTP 请求行不是合法 UTF-8")?;
    let mut parts = request_line.split(' ');
    let (Some(method), Some(uri), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        reply_http_error(stream, "400 Bad Request").await;
        bail!("HTTP 请求行格式错误: {:?}", request_line);
    };
    if !version.starts_with("HTTP/1.") {
        reply_http_error(stream, "505 HTTP Version Not Supported").await;
        bail!("不支持的 HTTP 版本: {}", version);
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let target = match parse_authority(uri, None) {
            Ok(t) => t,
            Err(e) => {
                reply_http_error(stream, "400 Bad Request").await;
                return Err(e);
            }
        };
        return Ok(InboundRequest { kind: InboundKind::HttpConnect, target, pending: leftover });
    }

    // 明文代理请求必须使用绝对 URI：http://host[:port]/path
    let Some(rest) = strip_prefix_ignore_case(uri, "http://") else {
        reply_http_error(stream, "400 Bad Request").await;
        bail!("HTTP 代理请求未使用 http:// 绝对 URI: {}", uri);
    };
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let target = match parse_authority(authority, Some(80)) {
        Ok(t) => t,
        Err(e) => {
            reply_http_error(stream, "400 Bad Request").await;
            return Err(e);
        }
    };

    // 改写为源站形式 (origin-form)，移除逐跳代理头，并强制 Connection: close，
    // 防止同一条 keep-alive 连接上的后续请求被误发往首个请求的目标主机
    let mut rewritten = Vec::with_capacity(head.len() + 32);
    rewritten.extend_from_slice(format!("{} {} {}\r\n", method, path, version).as_bytes());
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let name = line.split(|&b| b == b':').next().unwrap_or_default();
        let skip = [&b"proxy-connection"[..], b"proxy-authorization", b"connection", b"keep-alive"]
            .iter()
            .any(|h| name.trim_ascii().eq_ignore_ascii_case(h));
        if !skip {
            rewritten.extend_from_slice(line);
            rewritten.extend_from_slice(b"\r\n");
        }
    }
    rewritten.extend_from_slice(b"Connection: close\r\n\r\n");
    rewritten.extend_from_slice(&leftover);

    Ok(InboundRequest { kind: InboundKind::HttpForward, target, pending: rewritten })
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
    TargetAddr::parse_authority(authority, default_port, true)
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
            .write_all(b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\nHost: x\r\n\r\nEARLY")
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
                b"GET http://Example.com/a?b=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\nUser-Agent: t\r\n\r\n",
            )
            .await
            .unwrap();
        let r = read_request(&mut server).await.unwrap();
        assert_eq!(r.kind, InboundKind::HttpForward);
        assert_eq!(r.target, TargetAddr::Domain("example.com".into(), 80));
        let text = String::from_utf8(r.pending).unwrap();
        assert!(text.starts_with("GET /a?b=1 HTTP/1.1\r\n"));
        assert!(text.contains("Host: example.com\r\n"));
        assert!(text.contains("User-Agent: t\r\n"));
        assert!(!text.to_lowercase().contains("keep-alive"));
        assert!(text.ends_with("Connection: close\r\n\r\n"));
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

    #[test]
    fn test_parse_authority() {
        assert_eq!(parse_authority("a.com:443", None).unwrap(), TargetAddr::Domain("a.com".into(), 443));
        assert_eq!(parse_authority("a.com", Some(80)).unwrap(), TargetAddr::Domain("a.com".into(), 80));
        assert!(parse_authority("a.com", None).is_err());
        assert!(parse_authority("bad host:80", None).is_err());
        assert!(parse_authority("a.com:0", None).is_err());
        assert_eq!(
            parse_authority("1.2.3.4:5", None).unwrap(),
            TargetAddr::Ip("1.2.3.4:5".parse().unwrap())
        );
    }
}
