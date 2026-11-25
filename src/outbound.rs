use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

pub mod bypass;
pub mod chain;
pub mod direct;
pub mod http;
mod http_relay;
mod relay;
pub mod socks4;
pub mod socks5;

pub use bypass::OutboundTcpStream;
pub use http_relay::{relay_http_forward_monitored, relay_http_forward_monitored_with_timeout};
pub(crate) use http_relay::{find_http_header_end, trim_http_ows};
pub use relay::{relay_stream, relay_stream_monitored, relay_stream_monitored_with_timeout};

/// 可拆分全双工中继流抽象（统一支持原生 `TcpStream`、带端口绕过守卫的 `OutboundTcpStream` 及未来 `smoltcp` 透明流）
pub trait RelayStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    type ReadHalf: AsyncRead + Unpin + Send + 'static;
    type WriteHalf: AsyncWrite + Unpin + Send + 'static;

    fn split_stream(self) -> (Self::ReadHalf, Self::WriteHalf);
}

impl RelayStream for TcpStream {
    type ReadHalf = tokio::net::tcp::OwnedReadHalf;
    type WriteHalf = tokio::net::tcp::OwnedWriteHalf;

    fn split_stream(self) -> (Self::ReadHalf, Self::WriteHalf) {
        self.into_split()
    }
}

impl RelayStream for OutboundTcpStream {
    type ReadHalf = bypass::GuardedReadHalf;
    type WriteHalf = bypass::GuardedWriteHalf;

    fn split_stream(self) -> (Self::ReadHalf, Self::WriteHalf) {
        self.into_split()
    }
}

impl RelayStream for tokio::io::DuplexStream {
    type ReadHalf = tokio::io::ReadHalf<tokio::io::DuplexStream>;
    type WriteHalf = tokio::io::WriteHalf<tokio::io::DuplexStream>;

    fn split_stream(self) -> (Self::ReadHalf, Self::WriteHalf) {
        tokio::io::split(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

pub(crate) fn is_loopback_or_unspecified_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
        }
    }
}

/// 解析非规范 / 缩写 IPv4 主机形式（如 `127.1`、`0177.0.0.1`、`0x7f000001`、`2130706433`），
/// 防止绕过字面量 `IpAddr` 检查与自连环路防护。
pub(crate) fn parse_noncanonical_ipv4(host: &str) -> Option<Ipv4Addr> {
    let trimmed = host.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.contains(':') {
        return None;
    }

    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.is_empty() || parts.len() > 4 || parts.iter().any(|p| p.is_empty()) {
        return None;
    }

    let parse_part = |part: &str| -> Option<u64> {
        let b = part.as_bytes();
        if b.starts_with(b"0x") || b.starts_with(b"0X") {
            let hex = &part[2..];
            if hex.is_empty() || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            u64::from_str_radix(hex, 16).ok()
        } else if b.len() > 1 && b[0] == b'0' {
            let oct = &part[1..];
            if !oct.bytes().all(|c| matches!(c, b'0'..=b'7')) {
                return None;
            }
            u64::from_str_radix(oct, 8).ok()
        } else {
            if !part.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            part.parse::<u64>().ok()
        }
    };

    let mut nums = Vec::with_capacity(parts.len());
    for part in &parts {
        nums.push(parse_part(part)?);
    }

    let addr_u32 = match nums.as_slice() {
        [a] => {
            if *a > u32::MAX as u64 {
                return None;
            }
            *a as u32
        }
        [a, b] => {
            if *a > 0xFF || *b > 0x00FF_FFFF {
                return None;
            }
            ((*a as u32) << 24) | (*b as u32)
        }
        [a, b, c] => {
            if *a > 0xFF || *b > 0xFF || *c > 0xFFFF {
                return None;
            }
            ((*a as u32) << 24) | ((*b as u32) << 16) | (*c as u32)
        }
        [a, b, c, d] => {
            if nums.iter().any(|n| *n > 0xFF) {
                return None;
            }
            ((*a as u32) << 24) | ((*b as u32) << 16) | ((*c as u32) << 8) | (*d as u32)
        }
        _ => return None,
    };

    Some(Ipv4Addr::from(addr_u32))
}

pub(crate) fn is_loopback_domain(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.');
    let unbracketed = h
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(h);

    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return is_loopback_or_unspecified_ip(ip);
    }
    if let Some(v4) = parse_noncanonical_ipv4(unbracketed) {
        return is_loopback_or_unspecified_ip(IpAddr::V4(v4));
    }

    let bytes = h.as_bytes();
    bytes.eq_ignore_ascii_case(b"localhost")
        || (bytes.len() > 10 && bytes[bytes.len() - 10..].eq_ignore_ascii_case(b".localhost"))
}

/// 枚举本机在线网络接口上处于 Preferred 状态的单播 IP 地址（用于防 DNS 重绑定直连本机开放端口）
pub fn local_interface_ips() -> Vec<IpAddr> {
    use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{
        IpDadStatePreferred, AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };

    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut ips = Vec::new();
    let mut buf_len: u32 = 16 * 1024;
    let mut buf: Vec<u64> = Vec::new();

    for _ in 0..4 {
        buf.resize((buf_len as usize).div_ceil(std::mem::size_of::<u64>()), 0);
        let ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut buf_len,
            )
        };
        if ret == 0 {
            let mut adapter_ptr = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
            while !adapter_ptr.is_null() {
                if unsafe { (*adapter_ptr).OperStatus } != IfOperStatusUp {
                    adapter_ptr = unsafe { (*adapter_ptr).Next };
                    continue;
                }
                let mut unicast_ptr = unsafe { (*adapter_ptr).FirstUnicastAddress };
                while !unicast_ptr.is_null() {
                    if unsafe { (*unicast_ptr).DadState } != IpDadStatePreferred {
                        unicast_ptr = unsafe { (*unicast_ptr).Next };
                        continue;
                    }
                    let sock_addr = unsafe { (*unicast_ptr).Address };
                    if !sock_addr.lpSockaddr.is_null() && sock_addr.iSockaddrLength > 0 {
                        let family = unsafe { (*sock_addr.lpSockaddr).sa_family };
                        if family == AF_INET
                            && sock_addr.iSockaddrLength as usize
                                >= std::mem::size_of::<SOCKADDR_IN>()
                        {
                            let sin = unsafe {
                                (sock_addr.lpSockaddr as *const SOCKADDR_IN).read_unaligned()
                            };
                            let addr = u32::from_be(unsafe { sin.sin_addr.S_un.S_addr });
                            ips.push(IpAddr::V4(Ipv4Addr::from(addr)));
                        } else if family == AF_INET6
                            && sock_addr.iSockaddrLength as usize
                                >= std::mem::size_of::<SOCKADDR_IN6>()
                        {
                            let sin6 = unsafe {
                                (sock_addr.lpSockaddr as *const SOCKADDR_IN6).read_unaligned()
                            };
                            let bytes = unsafe { sin6.sin6_addr.u.Byte };
                            ips.push(IpAddr::V6(std::net::Ipv6Addr::from(bytes)));
                        }
                    }
                    unicast_ptr = unsafe { (*unicast_ptr).Next };
                }
                adapter_ptr = unsafe { (*adapter_ptr).Next };
            }
            return ips;
        } else if ret == ERROR_BUFFER_OVERFLOW && buf_len > 0 {
            continue;
        } else {
            break;
        }
    }
    ips
}

pub(crate) fn is_local_or_loopback_ip(ip: IpAddr, local_ips: &[IpAddr]) -> bool {
    if is_loopback_or_unspecified_ip(ip) {
        return true;
    }
    let canonical = match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    };
    local_ips.iter().any(|local| {
        let local_canon = match local {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(*v6),
            },
            other => *other,
        };
        local_canon == canonical
    })
}

impl TargetAddr {
    /// Construct validated `TargetAddr::Ip` from IP address and non-zero port
    pub fn from_ip_port(ip: IpAddr, port: u16) -> Result<Self> {
        if port == 0 {
            anyhow::bail!("Target port cannot be 0");
        }
        Ok(TargetAddr::Ip(SocketAddr::new(ip, port)))
    }

    /// Construct validated `TargetAddr` from hostname/IP literal and non-zero port
    pub fn from_host_port(host: &str, port: u16) -> Result<Self> {
        if port == 0 {
            anyhow::bail!("Target port cannot be 0");
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Self::from_ip_port(ip, port);
        }
        if let Some(v4) = parse_noncanonical_ipv4(host) {
            return Self::from_ip_port(IpAddr::V4(v4), port);
        }
        let valid = !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_');
        if !valid {
            anyhow::bail!("Invalid target hostname: {:?}", host);
        }
        Ok(TargetAddr::Domain(host.to_ascii_lowercase(), port))
    }

    /// Parse authority in `host:port` or `[ipv6]:port` format;
    /// `default_port` is required if port is missing; `allow_userinfo` controls stripping of `user@`
    pub fn parse_authority(
        authority: &str,
        default_port: Option<u16>,
        allow_userinfo: bool,
    ) -> Result<Self> {
        let authority = if allow_userinfo {
            authority.rsplit('@').next().unwrap_or(authority)
        } else if authority.contains('@') {
            anyhow::bail!("Target address must not contain userinfo (@): {}", authority);
        } else {
            authority
        };

        let (host, port_str) = if let Some(rest) = authority.strip_prefix('[') {
            let Some(end) = rest.find(']') else {
                anyhow::bail!("IPv6 address missing closing bracket: {}", authority);
            };
            let host = &rest[..end];
            let after = &rest[end + 1..];
            let port = match after.strip_prefix(':') {
                Some(p) => Some(p),
                None if after.is_empty() => None,
                None => anyhow::bail!("Invalid authority: {}", authority),
            };
            (host, port)
        } else {
            let (host, port_opt) = match authority.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            };
            if host.contains(':') {
                anyhow::bail!("For IPv6 addresses, please use [addr]:port format: {}", authority);
            }
            (host, port_opt)
        };

        let port = match port_str {
            Some(p) => p
                .parse::<u16>()
                .map_err(|_| anyhow::anyhow!("Invalid port number: {}", p))?,
            None => default_port.ok_or_else(|| anyhow::anyhow!("Missing port number: {}", authority))?,
        };
        Self::from_host_port(host, port)
    }

    /// 判断目标是否指向本地回环或未指定地址（如 `127.0.0.1`、`::1`、`0.0.0.0`、`::`、`localhost`、`*.localhost`）
    pub fn is_loopback_or_unspecified(&self) -> bool {
        match self {
            TargetAddr::Ip(addr) => is_loopback_or_unspecified_ip(addr.ip()),
            TargetAddr::Domain(host, _) => is_loopback_domain(host),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ip(addr) => addr.port(),
            TargetAddr::Domain(_, port) => *port,
        }
    }

    pub fn host_string(&self) -> String {
        match self {
            TargetAddr::Ip(addr) => addr.ip().to_string(),
            TargetAddr::Domain(host, _) => host.clone(),
        }
    }

    /// 构造标准 `host:port`（对 IPv6 字面量自动包裹方括号 `[...]:port`）
    pub fn to_authority_string(&self) -> String {
        match self {
            TargetAddr::Ip(addr) => addr.to_string(),
            TargetAddr::Domain(host, port) => {
                if host.contains(':') && !host.starts_with('[') {
                    format!("[{host}]:{port}")
                } else {
                    format!("{host}:{port}")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use http_relay::{
        parse_and_rewrite_http_response_head, HttpResponseFraming, ParsedHttpResponseHead,
    };
    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (a, b) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (a.unwrap(), b.unwrap().0)
    }

    /// P0-1 回归测试 1：单向大流量/长时间下载期间，上行完全静默且不发送 EOF 时，不得触发读超时误杀
    #[tokio::test]
    async fn test_relay_allows_long_unidirectional_transfer_without_false_timeout() {
        let (client_app, local_relay) = tcp_pair().await;
        let (remote_relay, server_app) = tcp_pair().await;

        let relay_handle = tokio::spawn(async move {
            relay_stream_monitored_with_timeout(
                local_relay,
                remote_relay,
                None,
                Duration::from_millis(120),
            )
            .await
        });

        let (mut client_r, mut client_w) = client_app.into_split();
        let (mut server_r, mut server_w) = server_app.into_split();

        // 客户端发送一次请求后保持写端打开但静默（模拟 HTTP 长下载上行无后续数据）
        client_w.write_all(b"GET /large HTTP/1.1\r\n\r\n").await.unwrap();
        let mut req_buf = vec![0u8; 64];
        let req_len = server_r.read(&mut req_buf).await.unwrap();
        assert_eq!(&req_buf[..req_len], b"GET /large HTTP/1.1\r\n\r\n");

        // 服务端持续以每 50ms 发送一次持续共 300ms（远超 120ms 单向空闲阈值）
        let server_task = tokio::spawn(async move {
            for _ in 0..6 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                server_w.write_all(b"chunk-data").await.unwrap();
            }
            server_w.shutdown().await.unwrap();
        });

        let mut downloaded = Vec::new();
        let mut tmp = [0u8; 64];
        loop {
            let n = client_r.read(&mut tmp).await.unwrap();
            if n == 0 {
                break;
            }
            downloaded.extend_from_slice(&tmp[..n]);
        }
        assert_eq!(downloaded.len(), 6 * b"chunk-data".len());

        // Client shuts down write side after receiving EOF from server to complete graceful termination
        client_w.shutdown().await.unwrap();
        server_task.await.unwrap();

        let (up, down) = relay_handle.await.unwrap().expect("Unidirectional active transfer should not time out while other side is silent");
        assert_eq!(up, 23);
        assert_eq!(down, 60);
    }

    /// P0-1 Regression Test 2: Client half-closes (EOF), server continues sending across multiple idle intervals to completion
    #[tokio::test]
    async fn test_relay_supports_half_close_continuation() {
        let (client_app, local_relay) = tcp_pair().await;
        let (remote_relay, server_app) = tcp_pair().await;

        let relay_handle = tokio::spawn(async move {
            relay_stream_monitored_with_timeout(
                local_relay,
                remote_relay,
                None,
                Duration::from_millis(120),
            )
            .await
        });

        let (mut client_r, mut client_w) = client_app.into_split();
        let (mut server_r, mut server_w) = server_app.into_split();

        client_w.write_all(b"ping").await.unwrap();
        client_w.shutdown().await.unwrap();

        let mut received = Vec::new();
        server_r.read_to_end(&mut received).await.unwrap();
        assert_eq!(&received, b"ping");

        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(55)).await;
            server_w.write_all(b"pong").await.unwrap();
        }
        server_w.shutdown().await.unwrap();

        let mut reply = Vec::new();
        client_r.read_to_end(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pongpongpongpong");

        let (up, down) = relay_handle.await.unwrap().expect("Opposite direction data stream after half-close should complete successfully");
        assert_eq!(up, 4);
        assert_eq!(down, 16);
    }

    /// P0-1 Regression Test 3: Idle timeout triggered if and only if both directions are silent beyond threshold
    #[tokio::test]
    async fn test_relay_times_out_when_both_sides_idle() {
        let (_client_app, local_relay) = tcp_pair().await;
        let (_remote_relay, _server_app) = tcp_pair().await;

        let res = relay_stream_monitored_with_timeout(
            local_relay,
            _remote_relay,
            None,
            Duration::from_millis(100),
        )
        .await;

        assert!(res.is_err(), "Prolonged mutual silence should trigger idle timeout cleanup");
    }

    #[test]
    fn test_loopback_domain_utf8_safe_and_noncanonical_ipv4() {
        // P0-3: multi-byte UTF-8 host must never slice-panic
        assert!(!is_loopback_domain("élocalhost"));
        assert!(!is_loopback_domain("中文.example"));
        assert!(is_loopback_domain("localhost."));
        assert!(is_loopback_domain("sub.LOCALHOST."));
        assert!(is_loopback_domain("[::ffff:127.0.0.1]"));
        assert!(is_loopback_domain("0.0.0.0"));
        assert!(is_loopback_domain("::"));
        assert!(is_loopback_domain("127.1"));
        assert!(is_loopback_domain("0x7f000001"));
        assert!(is_loopback_domain("0177.0.0.1"));
        assert!(is_loopback_domain("2130706433"));
        assert!(!is_loopback_domain("example.com"));

        // Non-canonical IPv4 normalized into Ip variant in TargetAddr::from_host_port
        assert_eq!(
            TargetAddr::from_host_port("127.1", 40080).unwrap(),
            TargetAddr::Ip("127.0.0.1:40080".parse().unwrap())
        );
        assert_eq!(
            TargetAddr::from_host_port("0x7f000001", 80).unwrap(),
            TargetAddr::Ip("127.0.0.1:80".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn test_http_forward_content_length_zero_blocks_pipelined_second_request() {
        let (client_app, local_relay) = tcp_pair().await;
        let (remote_relay, server_app) = tcp_pair().await;

        let relay = tokio::spawn(async move {
            relay_http_forward_monitored_with_timeout(
                local_relay,
                remote_relay,
                None,
                crate::inbound::HttpBodyFraming::ContentLength(0),
                b"GET /smuggled HTTP/1.1\r\nHost: evil\r\n\r\n".to_vec(),
                false,
                Duration::from_secs(2),
            )
            .await
        });

        let (mut client_r, mut client_w) = client_app.into_split();
        let (mut server_r, mut server_w) = server_app.into_split();

        // Client keeps socket open briefly attempting to send more data
        client_w.write_all(b"MORE_SMUGGLED").await.unwrap();

        // Remote must receive NEITHER premature EOF (P1-1) NOR smuggled pipelined bytes
        let mut probe = [0u8; 64];
        let early = tokio::time::timeout(Duration::from_millis(80), server_r.read(&mut probe)).await;
        assert!(
            early.is_err(),
            "Expected neither premature EOF nor smuggled bytes, got: {:?}",
            early
        );

        server_w
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
        server_w.shutdown().await.unwrap();

        let mut resp = Vec::new();
        client_r.read_to_end(&mut resp).await.unwrap();
        assert_eq!(
            &resp,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        );

        let (up, down) = relay.await.unwrap().unwrap();
        assert_eq!(up, 0);
        assert_eq!(down, resp.len() as u64);
    }

    #[tokio::test]
    async fn test_http_forward_content_length_exact_and_chunked_stop_before_smuggling() {
        // 1. Exact Content-Length: 5
        let (client_app, local_relay) = tcp_pair().await;
        let (remote_relay, server_app) = tcp_pair().await;
        let relay = tokio::spawn(async move {
            relay_http_forward_monitored_with_timeout(
                local_relay,
                remote_relay,
                None,
                crate::inbound::HttpBodyFraming::ContentLength(5),
                b"he".to_vec(),
                false,
                Duration::from_secs(2),
            )
            .await
        });
        let (mut client_r, mut client_w) = client_app.into_split();
        let (mut server_r, mut server_w) = server_app.into_split();
        client_w.write_all(b"lloGET /evil HTTP/1.1\r\n\r\n").await.unwrap();

        let mut remote_body = [0u8; 5];
        server_r.read_exact(&mut remote_body).await.unwrap();
        assert_eq!(&remote_body, b"hello");
        let mut probe = [0u8; 64];
        let after_exact = tokio::time::timeout(Duration::from_millis(80), server_r.read(&mut probe)).await;
        assert!(after_exact.is_err(), "Expected open write half and zero smuggling, got: {:?}", after_exact);

        server_w
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nresp1")
            .await
            .unwrap();
        server_w.shutdown().await.unwrap();
        let mut client_resp = Vec::new();
        client_r.read_to_end(&mut client_resp).await.unwrap();
        let expected_resp1 = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nresp1";
        assert_eq!(&client_resp[..], expected_resp1);
        assert_eq!(relay.await.unwrap().unwrap(), (5, expected_resp1.len() as u64));

        // 2. Chunked encoding with trailer + trailing pipelined request
        let (client_app, local_relay) = tcp_pair().await;
        let (remote_relay, server_app) = tcp_pair().await;
        let relay2 = tokio::spawn(async move {
            relay_http_forward_monitored_with_timeout(
                local_relay,
                remote_relay,
                None,
                crate::inbound::HttpBodyFraming::Chunked,
                b"3;ext=1\r\nabc\r\n".to_vec(),
                false,
                Duration::from_secs(2),
            )
            .await
        });
        let (mut client_r2, mut client_w2) = client_app.into_split();
        let (mut server_r2, mut server_w2) = server_app.into_split();
        client_w2
            .write_all(b"2\r\nde\r\n0\r\nX-Check: yes\r\n\r\nGET /smuggled HTTP/1.1\r\n\r\n")
            .await
            .unwrap();

        let expected_chunked = b"3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\nX-Check: yes\r\n\r\n";
        let mut remote_chunked = vec![0u8; expected_chunked.len()];
        server_r2.read_exact(&mut remote_chunked).await.unwrap();
        assert_eq!(&remote_chunked[..], expected_chunked);
        let after_chunked = tokio::time::timeout(Duration::from_millis(80), server_r2.read(&mut probe)).await;
        assert!(after_chunked.is_err(), "Expected open write half and zero chunked smuggling, got: {:?}", after_chunked);

        server_w2
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nresp2")
            .await
            .unwrap();
        server_w2.shutdown().await.unwrap();
        let mut client_resp2 = Vec::new();
        client_r2.read_to_end(&mut client_resp2).await.unwrap();
        let expected_resp2 = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nresp2";
        assert_eq!(&client_resp2[..], expected_resp2);
        assert_eq!(
            relay2.await.unwrap().unwrap(),
            (remote_chunked.len() as u64, expected_resp2.len() as u64)
        );
    }

    #[tokio::test]
    async fn test_http_forward_early_4xx_response_does_not_hang() {
        let (client_app, local_relay) = tcp_pair().await;
        let (remote_relay, server_app) = tcp_pair().await;

        let relay = tokio::spawn(async move {
            relay_http_forward_monitored_with_timeout(
                local_relay,
                remote_relay,
                None,
                crate::inbound::HttpBodyFraming::ContentLength(10_000_000),
                b"part".to_vec(),
                false,
                Duration::from_secs(10),
            )
            .await
        });

        let (mut client_r, _client_w_keepopen) = client_app.into_split();
        let (mut server_r, mut server_w) = server_app.into_split();

        let mut head_body = [0u8; 4];
        server_r.read_exact(&mut head_body).await.unwrap();
        assert_eq!(&head_body, b"part");

        // Origin rejects upload early with 401 and closes without waiting for remaining 10MB body
        let reject = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno";
        server_w.write_all(reject).await.unwrap();
        server_w.shutdown().await.unwrap();

        let (up, down) = tokio::time::timeout(Duration::from_secs(1), relay)
            .await
            .expect("Early 4xx response must finish promptly instead of hanging for idle timeout")
            .unwrap()
            .unwrap();
        assert_eq!(up, 4);
        assert_eq!(down, reject.len() as u64);

        let mut got_resp = Vec::new();
        client_r.read_to_end(&mut got_resp).await.unwrap();
        assert_eq!(&got_resp, reject);
    }

    #[tokio::test]
    async fn test_http_forward_persistent_keepalive_origin_completes_without_timeout() {
        // 1. Origin ignores Connection: close and sends Content-Length + Connection: keep-alive without FIN
        let (client_app, local_relay) = tcp_pair().await;
        let (remote_relay, server_app) = tcp_pair().await;
        let relay = tokio::spawn(async move {
            relay_http_forward_monitored_with_timeout(
                local_relay,
                remote_relay,
                None,
                crate::inbound::HttpBodyFraming::ContentLength(0),
                Vec::new(),
                false,
                Duration::from_secs(120),
            )
            .await
        });
        let (mut client_r, _client_w_open) = client_app.into_split();
        let (_server_r_open, mut server_w_keepalive) = server_app.into_split();

        server_w_keepalive
            .write_all(
                b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nKeep-Alive: timeout=60\r\nProxy-Connection: keep-alive\r\nContent-Length: 5\r\n\r\nhello",
            )
            .await
            .unwrap();

        let (up, down) = tokio::time::timeout(Duration::from_millis(500), relay)
            .await
            .expect("Keep-alive Content-Length response must not hang waiting for server FIN")
            .unwrap()
            .unwrap();
        let mut got = Vec::new();
        client_r.read_to_end(&mut got).await.unwrap();
        assert_eq!(
            &got,
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
        );
        assert_eq!((up, down), (0, got.len() as u64));

        // 2. Origin sends chunked response with keep-alive without FIN
        let (client_app, local_relay) = tcp_pair().await;
        let (remote_relay, server_app) = tcp_pair().await;
        let relay2 = tokio::spawn(async move {
            relay_http_forward_monitored_with_timeout(
                local_relay,
                remote_relay,
                None,
                crate::inbound::HttpBodyFraming::ContentLength(0),
                Vec::new(),
                false,
                Duration::from_secs(120),
            )
            .await
        });
        let (mut client_r2, _client_w2) = client_app.into_split();
        let (_server_r2, mut server_w2_keepalive) = server_app.into_split();
        server_w2_keepalive
            .write_all(
                b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nworld\r\n0\r\nX-Done: 1\r\n\r\n",
            )
            .await
            .unwrap();

        let (_up2, down2) = tokio::time::timeout(Duration::from_millis(500), relay2)
            .await
            .expect("Keep-alive chunked response must finish cleanly at 0-chunk terminator")
            .unwrap()
            .unwrap();
        let mut got2 = Vec::new();
        client_r2.read_to_end(&mut got2).await.unwrap();
        assert_eq!(
            &got2,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nworld\r\n0\r\nX-Done: 1\r\n\r\n"
        );
        assert_eq!(down2, got2.len() as u64);

        // 3. HEAD request with Content-Length: 1024 + keep-alive finishes immediately with 0 body bytes
        let (client_app, local_relay) = tcp_pair().await;
        let (remote_relay, server_app) = tcp_pair().await;
        let relay3 = tokio::spawn(async move {
            relay_http_forward_monitored_with_timeout(
                local_relay,
                remote_relay,
                None,
                crate::inbound::HttpBodyFraming::ContentLength(0),
                Vec::new(),
                true,
                Duration::from_secs(120),
            )
            .await
        });
        let (mut client_r3, _client_w3) = client_app.into_split();
        let (_server_r3, mut server_w3_keepalive) = server_app.into_split();
        server_w3_keepalive
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nConnection: keep-alive\r\n\r\n")
            .await
            .unwrap();
        let (_, down3) = tokio::time::timeout(Duration::from_millis(500), relay3)
            .await
            .expect("HEAD response with Content-Length must terminate with 0 body bytes")
            .unwrap()
            .unwrap();
        let mut got3 = Vec::new();
        client_r3.read_to_end(&mut got3).await.unwrap();
        assert_eq!(
            &got3,
            b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(down3, got3.len() as u64);

        // 4. 100 Continue followed by 204 No Content completes immediately without waiting for FIN
        let (client_app, local_relay) = tcp_pair().await;
        let (remote_relay, server_app) = tcp_pair().await;
        let relay4 = tokio::spawn(async move {
            relay_http_forward_monitored_with_timeout(
                local_relay,
                remote_relay,
                None,
                crate::inbound::HttpBodyFraming::ContentLength(0),
                Vec::new(),
                false,
                Duration::from_secs(120),
            )
            .await
        });
        let (mut client_r4, _client_w4) = client_app.into_split();
        let (_server_r4, mut server_w4_keepalive) = server_app.into_split();
        server_w4_keepalive
            .write_all(
                b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n",
            )
            .await
            .unwrap();
        let (_, down4) = tokio::time::timeout(Duration::from_millis(500), relay4)
            .await
            .expect("100 Continue + 204 No Content must complete immediately")
            .unwrap()
            .unwrap();
        let mut got4 = Vec::new();
        client_r4.read_to_end(&mut got4).await.unwrap();
        assert_eq!(
            &got4,
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(down4, got4.len() as u64);
    }

    #[test]
    fn test_target_addr_to_authority_string_brackets_ipv6() {
        let v4 = TargetAddr::Ip("1.2.3.4:80".parse().unwrap());
        assert_eq!(v4.to_authority_string(), "1.2.3.4:80");

        let v6 = TargetAddr::Ip("[2001:db8::1]:443".parse().unwrap());
        assert_eq!(v6.to_authority_string(), "[2001:db8::1]:443");

        let domain = TargetAddr::Domain("api.github.com".to_string(), 443);
        assert_eq!(domain.to_authority_string(), "api.github.com:443");

        let raw_v6_domain = TargetAddr::Domain("2001:db8::2".to_string(), 8443);
        assert_eq!(raw_v6_domain.to_authority_string(), "[2001:db8::2]:8443");
    }

    #[test]
    fn test_find_http_header_end_incremental_boundary_splits() {
        let req = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\nbody";
        // Simulate byte-by-byte reads advancing scanned_len after each append
        let mut buf = Vec::new();
        let mut scanned = 0usize;
        let mut found = None;
        for &b in req {
            buf.push(b);
            if let Some(end) = find_http_header_end(&buf, scanned) {
                found = Some(end);
                break;
            }
            scanned = buf.len();
        }
        assert_eq!(found, Some(b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n".len()));

        // Split right before each byte of `\r\n\r\n`
        let sample = b"GET / HTTP/1.1\r\n\r\n";
        let head_len = sample.len();
        for split in (head_len - 4)..head_len {
            assert_eq!(find_http_header_end(&sample[..split], 0), None);
            assert_eq!(find_http_header_end(sample, split), Some(head_len));
        }

        // Clamping out-of-range scanned_len does not panic and preserves the 3-byte overlap invariant
        assert_eq!(find_http_header_end(b"\r\n\r\n", 3), Some(4));
        assert_eq!(find_http_header_end(b"Host: x\r\n\r\n", 999), None);
        assert_eq!(find_http_header_end(b"abc", 999), None);
    }

    #[test]
    fn test_parse_http_response_head_strict_ows_rejects_unicode_whitespace() {
        // ASCII OWS (SP / HTAB) around Content-Length and Transfer-Encoding is valid per RFC 9110
        let ok_cl = b"HTTP/1.1 200 OK\r\nContent-Length:\t 12 \t";
        assert!(matches!(
            parse_and_rewrite_http_response_head(ok_cl, false).unwrap(),
            ParsedHttpResponseHead::Final {
                framing: HttpResponseFraming::ContentLength(12),
                ..
            }
        ));
        let ok_te = b"HTTP/1.1 200 OK\r\nTransfer-Encoding:\t chunked \t";
        assert!(matches!(
            parse_and_rewrite_http_response_head(ok_te, false).unwrap(),
            ParsedHttpResponseHead::Final {
                framing: HttpResponseFraming::Chunked,
                ..
            }
        ));

        // Non-OWS Unicode whitespace (NBSP U+00A0, EM SPACE U+2003) must be rejected
        for bad in [
            "HTTP/1.1 200 OK\r\nContent-Length:\u{00a0}5",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\u{2003}",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding:\u{00a0}chunked",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\u{2003}",
        ] {
            assert!(
                parse_and_rewrite_http_response_head(bad.as_bytes(), false).is_err(),
                "expected error for non-OWS whitespace in {:?}",
                bad
            );
        }
    }
}
