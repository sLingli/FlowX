use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::monitor::ActiveConnection;

pub mod chain;
pub mod direct;
pub mod http;
pub mod socks4;
pub mod socks5;

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

/// 枚举本机网络接口上的所有 IP 地址（用于防 DNS 重绑定直连本机开放端口）
pub(crate) fn local_interface_ips() -> Vec<IpAddr> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
        };
        use windows_sys::Win32::Networking::WinSock::{
            AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
        };

        let mut ips = Vec::new();
        let mut buf_len: u32 = 16 * 1024;
        let mut buf: Vec<u8> = Vec::new();

        for _ in 0..4 {
            buf.resize(buf_len as usize, 0);
            let ret = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    0,
                    std::ptr::null(),
                    buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                    &mut buf_len,
                )
            };
            if ret == 0 {
                let mut adapter_ptr = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
                while !adapter_ptr.is_null() {
                    let mut unicast_ptr = unsafe { (*adapter_ptr).FirstUnicastAddress };
                    while !unicast_ptr.is_null() {
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

    #[cfg(unix)]
    {
        let mut ips = Vec::new();
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut ifap) } != 0 || ifap.is_null() {
            return ips;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let addr_ptr = unsafe { (*cur).ifa_addr };
            if !addr_ptr.is_null() {
                let family = unsafe { (*addr_ptr).sa_family } as i32;
                if family == libc::AF_INET {
                    let sin = unsafe { (addr_ptr as *const libc::sockaddr_in).read_unaligned() };
                    let addr = u32::from_be(sin.sin_addr.s_addr);
                    ips.push(IpAddr::V4(Ipv4Addr::from(addr)));
                } else if family == libc::AF_INET6 {
                    let sin6 = unsafe { (addr_ptr as *const libc::sockaddr_in6).read_unaligned() };
                    ips.push(IpAddr::V6(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
                }
            }
            cur = unsafe { (*cur).ifa_next };
        }
        unsafe { libc::freeifaddrs(ifap) };
        ips
    }

    #[cfg(not(any(windows, unix)))]
    {
        Vec::new()
    }
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
    /// Construct validated `TargetAddr` from hostname/IP literal and non-zero port
    pub fn from_host_port(host: &str, port: u16) -> Result<Self> {
        if port == 0 {
            anyhow::bail!("Target port cannot be 0");
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(TargetAddr::Ip(SocketAddr::new(ip, port)));
        }
        if let Some(v4) = parse_noncanonical_ipv4(host) {
            return Ok(TargetAddr::Ip(SocketAddr::new(IpAddr::V4(v4), port)));
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
}

/// 全双工透明流中继对拷（带实时流量监视与主动熔断切断支持）
pub async fn relay_stream_monitored(
    local: TcpStream,
    remote: TcpStream,
    conn: Option<&Arc<ActiveConnection>>,
) -> Result<(u64, u64)> {
    const RELAY_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
    relay_stream_monitored_with_timeout(local, remote, conn, RELAY_IDLE_TIMEOUT).await
}

/// 可配置双向静默空闲超时的全双工对拷实现：
/// 仅当上行与下行在 `idle_timeout` 内均无任何数据流动时才判定超时；
/// 任一方向收到 EOF (n == 0) 半关闭后，仅关闭对端写方向并允许另一方向继续传输。
pub async fn relay_stream_monitored_with_timeout(
    local: TcpStream,
    remote: TcpStream,
    conn: Option<&Arc<ActiveConnection>>,
    idle_timeout: std::time::Duration,
) -> Result<(u64, u64)> {
    use std::sync::atomic::{AtomicU64, Ordering};

    if conn.is_some_and(|c| c.is_cancelled()) {
        anyhow::bail!("Connection aborted by administrator");
    }

    let (mut lr, mut lw) = local.into_split();
    let (mut rr, mut rw) = remote.into_split();

    let conn_up = conn.cloned();
    let conn_down = conn.cloned();

    let start = tokio::time::Instant::now();
    // Track microsecond timestamp of the most recent payload activity in either direction
    let last_activity_us = Arc::new(AtomicU64::new(0));
    let last_up = Arc::clone(&last_activity_us);
    let last_down = Arc::clone(&last_activity_us);

    let touch_activity = |tracker: &AtomicU64| {
        let elapsed_us = start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        tracker.store(elapsed_us, Ordering::Relaxed);
    };

    let up_task = async move {
        let mut buf = [0u8; 16384];
        let mut total_up = 0u64;
        loop {
            let n = lr.read(&mut buf).await?;
            if n == 0 {
                rw.shutdown().await.ok();
                break;
            }
            touch_activity(&last_up);
            rw.write_all(&buf[..n]).await?;
            touch_activity(&last_up);
            total_up += n as u64;
            if let Some(c) = &conn_up {
                c.add_upload(n as u64);
            }
        }
        Ok::<u64, std::io::Error>(total_up)
    };

    let down_task = async move {
        let mut buf = [0u8; 16384];
        let mut total_down = 0u64;
        loop {
            let n = rr.read(&mut buf).await?;
            if n == 0 {
                lw.shutdown().await.ok();
                break;
            }
            touch_activity(&last_down);
            lw.write_all(&buf[..n]).await?;
            touch_activity(&last_down);
            total_down += n as u64;
            if let Some(c) = &conn_down {
                c.add_download(n as u64);
            }
        }
        Ok::<u64, std::io::Error>(total_down)
    };

    let idle_watchdog = async {
        let timeout_us = idle_timeout.as_micros().min(u128::from(u64::MAX)) as u64;
        loop {
            let last_us = last_activity_us.load(Ordering::Relaxed);
            let now_us = start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
            let elapsed_since_activity = now_us.saturating_sub(last_us);
            if elapsed_since_activity >= timeout_us {
                return;
            }
            let remaining = std::time::Duration::from_micros(
                (timeout_us - elapsed_since_activity).max(1),
            );
            tokio::time::sleep(remaining).await;
        }
    };

    tokio::select! {
        res = async {
            tokio::try_join!(up_task, down_task)
        } => {
            let (up, down) = res?;
            Ok((up, down))
        }
        _ = idle_watchdog => {
            anyhow::bail!(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("Both directions idle for {:?}, connection timed out", idle_timeout),
            ));
        }
        _ = async {
            if let Some(c) = conn {
                let notified = c.cancel_notify.notified();
                if c.is_cancelled() {
                    return;
                }
                notified.await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {
            anyhow::bail!("Connection aborted by administrator");
        }
    }
}

pub async fn relay_stream(local: TcpStream, remote: TcpStream) -> Result<(u64, u64)> {
    relay_stream_monitored(local, remote, None).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;

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
}
