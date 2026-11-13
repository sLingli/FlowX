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
        let mut buf: Vec<u64> = Vec::new();

        for _ in 0..4 {
            buf.resize((buf_len as usize).div_ceil(std::mem::size_of::<u64>()), 0);
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

fn record_activity_us(start: &tokio::time::Instant, tracker: &std::sync::atomic::AtomicU64) {
    let elapsed_us = start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    tracker.store(elapsed_us, std::sync::atomic::Ordering::Relaxed);
}

async fn relay_downlink(
    mut rr: tokio::net::tcp::OwnedReadHalf,
    mut lw: tokio::net::tcp::OwnedWriteHalf,
    conn: Option<Arc<ActiveConnection>>,
    start: tokio::time::Instant,
    last_activity_us: Arc<std::sync::atomic::AtomicU64>,
) -> std::io::Result<u64> {
    let mut buf = vec![0u8; 16384];
    let mut total_down = 0u64;
    loop {
        let n = rr.read(&mut buf).await?;
        if n == 0 {
            lw.shutdown().await.ok();
            break;
        }
        record_activity_us(&start, &last_activity_us);
        lw.write_all(&buf[..n]).await?;
        record_activity_us(&start, &last_activity_us);
        total_down += n as u64;
        if let Some(c) = &conn {
            c.add_download(n as u64);
        }
    }
    Ok(total_down)
}

async fn await_relay_with_watchdog<FR>(
    relay_fut: FR,
    start: tokio::time::Instant,
    last_activity_us: Arc<std::sync::atomic::AtomicU64>,
    conn: Option<&Arc<ActiveConnection>>,
    idle_timeout: std::time::Duration,
) -> Result<(u64, u64)>
where
    FR: std::future::Future<Output = std::io::Result<(u64, u64)>>,
{
    use std::sync::atomic::Ordering;

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
        res = relay_fut => {
            Ok(res?)
        }
        _ = idle_watchdog => {
            anyhow::bail!(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("Both directions idle for {:?}, connection timed out", idle_timeout),
            ));
        }
        _ = async {
            if let Some(c) = conn {
                c.cancelled().await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {
            anyhow::bail!("Connection aborted by administrator");
        }
    }
}

async fn run_relay_with_watchdog<FUp, FDown>(
    up_task: FUp,
    down_task: FDown,
    start: tokio::time::Instant,
    last_activity_us: Arc<std::sync::atomic::AtomicU64>,
    conn: Option<&Arc<ActiveConnection>>,
    idle_timeout: std::time::Duration,
) -> Result<(u64, u64)>
where
    FUp: std::future::Future<Output = std::io::Result<u64>>,
    FDown: std::future::Future<Output = std::io::Result<u64>>,
{
    await_relay_with_watchdog(
        async { tokio::try_join!(up_task, down_task) },
        start,
        last_activity_us,
        conn,
        idle_timeout,
    )
    .await
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
    use std::sync::atomic::AtomicU64;

    if conn.is_some_and(|c| c.is_cancelled()) {
        anyhow::bail!("Connection aborted by administrator");
    }

    let (mut lr, lw) = local.into_split();
    let (rr, mut rw) = remote.into_split();

    let conn_up = conn.cloned();
    let conn_down = conn.cloned();

    let start = tokio::time::Instant::now();
    let last_activity_us = Arc::new(AtomicU64::new(0));
    let last_up = Arc::clone(&last_activity_us);
    let last_down = Arc::clone(&last_activity_us);

    let up_task = async move {
        let mut buf = vec![0u8; 16384];
        let mut total_up = 0u64;
        loop {
            let n = lr.read(&mut buf).await?;
            if n == 0 {
                rw.shutdown().await.ok();
                break;
            }
            record_activity_us(&start, &last_up);
            rw.write_all(&buf[..n]).await?;
            record_activity_us(&start, &last_up);
            total_up += n as u64;
            if let Some(c) = &conn_up {
                c.add_upload(n as u64);
            }
        }
        Ok::<u64, std::io::Error>(total_up)
    };

    let down_task = relay_downlink(rr, lw, conn_down, start, last_down);
    run_relay_with_watchdog(up_task, down_task, start, last_activity_us, conn, idle_timeout).await
}

/// 预读前缀 + 底层的顺序流读取器，用于精确消费 HTTP 请求/响应体边界而绝不溢出到后续流水线报文
struct PrefixedTcpReader {
    buf: Vec<u8>,
    pos: usize,
    inner: tokio::net::tcp::OwnedReadHalf,
}

impl PrefixedTcpReader {
    fn new(prefix: Vec<u8>, inner: tokio::net::tcp::OwnedReadHalf) -> Self {
        Self {
            buf: prefix,
            pos: 0,
            inner,
        }
    }

    async fn fill(&mut self) -> std::io::Result<usize> {
        if self.pos < self.buf.len() {
            return Ok(self.buf.len() - self.pos);
        }
        self.buf.clear();
        self.pos = 0;
        if self.buf.capacity() < 16384 {
            self.buf.reserve(16384 - self.buf.capacity());
        }
        self.inner.read_buf(&mut self.buf).await
    }

    async fn read_byte(&mut self) -> std::io::Result<Option<u8>> {
        if self.fill().await? == 0 {
            return Ok(None);
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(Some(b))
    }

    async fn read_exact_bytes(&mut self, dst: &mut [u8]) -> std::io::Result<()> {
        let mut written = 0usize;
        while written < dst.len() {
            let n = self.fill().await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF while reading framed HTTP body",
                ));
            }
            let take = n.min(dst.len() - written);
            dst[written..written + take].copy_from_slice(&self.buf[self.pos..self.pos + take]);
            self.pos += take;
            written += take;
        }
        Ok(())
    }

    /// 读取一行 CRLF 结尾内容（返回不含 `\r\n` 的内容），拒绝裸 `\n` 与 NUL 字节
    async fn read_crlf_line(&mut self, max_len: usize) -> std::io::Result<Vec<u8>> {
        let mut line = Vec::new();
        loop {
            let Some(b) = self.read_byte().await? else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF while reading HTTP chunk line",
                ));
            };
            if b == b'\0' {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "NUL byte not allowed in HTTP chunked framing",
                ));
            }
            if b == b'\n' {
                if !line.ends_with(b"\r") {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Bare LF line ending not allowed in HTTP chunked framing",
                    ));
                }
                line.pop();
                return Ok(line);
            }
            if line.len() >= max_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP chunked line exceeds maximum allowed length",
                ));
            }
            line.push(b);
        }
    }

    /// 读取以 `\r\n\r\n` 结束的 HTTP 头部块（不包含末尾 `\r\n\r\n`），严格受限于 `max_bytes`
    /// 若在首字节前即遇到 clean EOF，则返回 `Ok(None)`
    async fn read_http_header_block(&mut self, max_bytes: usize) -> std::io::Result<Option<Vec<u8>>> {
        let mut tmp = [0u8; 4096];
        loop {
            let unconsumed = &self.buf[self.pos..];
            if let Some(rel) = unconsumed.windows(4).position(|w| w == b"\r\n\r\n") {
                if rel + 4 > max_bytes {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "HTTP response headers exceed maximum allowed size",
                    ));
                }
                let head = unconsumed[..rel].to_vec();
                self.pos += rel + 4;
                return Ok(Some(head));
            }
            if self.pos > 0 {
                self.buf.drain(..self.pos);
                self.pos = 0;
            }
            if self.buf.len() >= max_bytes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP response headers exceed maximum allowed size",
                ));
            }
            let cap = (max_bytes - self.buf.len()).min(tmp.len());
            let n = self.inner.read(&mut tmp[..cap]).await?;
            if n == 0 {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF before HTTP response headers terminated",
                ));
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayDirection {
    Upload,
    Download,
}

enum BodyRelayError {
    PeerWriteClosed(std::io::Error),
    Fatal(std::io::Error),
}

impl BodyRelayError {
    fn into_io_error(self) -> std::io::Error {
        match self {
            BodyRelayError::PeerWriteClosed(e) | BodyRelayError::Fatal(e) => e,
        }
    }
}

impl From<std::io::Error> for BodyRelayError {
    fn from(e: std::io::Error) -> Self {
        Self::Fatal(e)
    }
}

/// 统一带活跃计时与全局/单连接字节计数的有界 HTTP 体写入端，同时复用在上行请求体与下行响应体路径
struct TrackedBodySink<'a> {
    writer: tokio::net::tcp::OwnedWriteHalf,
    total_bytes: &'a std::sync::atomic::AtomicU64,
    conn: &'a Option<Arc<ActiveConnection>>,
    start: &'a tokio::time::Instant,
    last_activity_us: &'a Arc<std::sync::atomic::AtomicU64>,
    direction: RelayDirection,
}

impl<'a> TrackedBodySink<'a> {
    async fn write_all(&mut self, bytes: &[u8]) -> std::result::Result<(), BodyRelayError> {
        if bytes.is_empty() {
            return Ok(());
        }
        record_activity_us(self.start, self.last_activity_us);
        self.writer.write_all(bytes).await.map_err(|e| {
            if matches!(
                e.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            ) {
                BodyRelayError::PeerWriteClosed(e)
            } else {
                BodyRelayError::Fatal(e)
            }
        })?;
        record_activity_us(self.start, self.last_activity_us);
        self.total_bytes
            .fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
        if let Some(c) = self.conn {
            match self.direction {
                RelayDirection::Upload => c.add_upload(bytes.len() as u64),
                RelayDirection::Download => c.add_download(bytes.len() as u64),
            }
        }
        Ok(())
    }
}

async fn copy_exact_body(
    reader: &mut PrefixedTcpReader,
    sink: &mut TrackedBodySink<'_>,
    mut remaining: u64,
) -> std::result::Result<(), BodyRelayError> {
    while remaining > 0 {
        let avail = reader.fill().await?;
        if avail == 0 {
            return Err(BodyRelayError::Fatal(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Truncated HTTP body before reaching declared length",
            )));
        }
        let take = (avail as u64).min(remaining) as usize;
        sink.write_all(&reader.buf[reader.pos..reader.pos + take])
            .await?;
        reader.pos += take;
        remaining -= take as u64;
    }
    Ok(())
}

async fn copy_until_eof(
    reader: &mut PrefixedTcpReader,
    sink: &mut TrackedBodySink<'_>,
) -> std::result::Result<(), BodyRelayError> {
    loop {
        let avail = reader.fill().await?;
        if avail == 0 {
            return Ok(());
        }
        sink.write_all(&reader.buf[reader.pos..reader.pos + avail])
            .await?;
        reader.pos += avail;
    }
}

fn parse_chunk_size_line(line: &[u8]) -> std::io::Result<u64> {
    let size_part = match line.iter().position(|&b| b == b';') {
        Some(idx) => {
            let ext = &line[idx + 1..];
            if ext.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Control character in HTTP chunk extension",
                ));
            }
            &line[..idx]
        }
        None => line,
    };
    let trimmed = {
        let mut end = size_part.len();
        while end > 0 && matches!(size_part[end - 1], b' ' | b'\t') {
            end -= 1;
        }
        &size_part[..end]
    };
    if trimmed.is_empty() || !trimmed.iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid HTTP chunk size hex digits",
        ));
    }
    let hex_str = std::str::from_utf8(trimmed).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "Non-ASCII HTTP chunk size")
    })?;
    u64::from_str_radix(hex_str, 16).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP chunk size overflows u64",
        )
    })
}

fn validate_chunk_trailer_line(line: &[u8]) -> std::io::Result<()> {
    if line.is_empty() || matches!(line[0], b' ' | b'\t') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Malformed or folded HTTP chunk trailer header",
        ));
    }
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP chunk trailer missing colon",
        ));
    };
    let name = &line[..colon];
    let val = &line[colon + 1..];
    if name.is_empty() || !name.iter().all(|&b| crate::inbound::is_http_token_byte(b)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid HTTP chunk trailer header name",
        ));
    }
    if val.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid control character in HTTP chunk trailer value",
        ));
    }
    if name.eq_ignore_ascii_case(b"host")
        || name.eq_ignore_ascii_case(b"content-length")
        || name.eq_ignore_ascii_case(b"transfer-encoding")
        || name.eq_ignore_ascii_case(b"trailer")
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Forbidden framing header in HTTP chunk trailer",
        ));
    }
    Ok(())
}

async fn forward_chunked_body(
    reader: &mut PrefixedTcpReader,
    sink: &mut TrackedBodySink<'_>,
) -> std::result::Result<(), BodyRelayError> {
    const MAX_CHUNK_LINE_BYTES: usize = 8 * 1024;
    const MAX_TRAILER_BYTES: usize = 16 * 1024;

    loop {
        let size_line = reader.read_crlf_line(MAX_CHUNK_LINE_BYTES).await?;
        let chunk_size = parse_chunk_size_line(&size_line)?;
        sink.write_all(&size_line).await?;
        sink.write_all(b"\r\n").await?;

        if chunk_size == 0 {
            let mut trailer_bytes = 0usize;
            loop {
                let trailer = reader.read_crlf_line(MAX_CHUNK_LINE_BYTES).await?;
                if trailer.is_empty() {
                    sink.write_all(b"\r\n").await?;
                    return Ok(());
                }
                trailer_bytes = trailer_bytes.saturating_add(trailer.len() + 2);
                if trailer_bytes > MAX_TRAILER_BYTES {
                    return Err(BodyRelayError::Fatal(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "HTTP chunk trailers exceed size limit",
                    )));
                }
                validate_chunk_trailer_line(&trailer)?;
                sink.write_all(&trailer).await?;
                sink.write_all(b"\r\n").await?;
            }
        }

        copy_exact_body(reader, sink, chunk_size).await?;
        let mut crlf = [0u8; 2];
        reader.read_exact_bytes(&mut crlf).await?;
        if &crlf != b"\r\n" {
            return Err(BodyRelayError::Fatal(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Missing CRLF terminator after HTTP chunk payload",
            )));
        }
        sink.write_all(b"\r\n").await?;
    }
}

enum HttpResponseFraming {
    Empty,
    ContentLength(u64),
    Chunked,
    UntilEof,
}

enum ParsedHttpResponseHead {
    Interim(Vec<u8>),
    Final {
        rewritten_head: Vec<u8>,
        framing: HttpResponseFraming,
    },
}

fn parse_and_rewrite_http_response_head(
    head: &[u8],
    is_head_request: bool,
) -> std::io::Result<ParsedHttpResponseHead> {
    let invalid = |msg: &'static str| std::io::Error::new(std::io::ErrorKind::InvalidData, msg);
    let lines = crate::inbound::split_crlf_lines(head)
        .ok_or_else(|| invalid("HTTP response contains invalid line endings or NUL byte"))?;
    let mut lines_iter = lines.into_iter();
    let status_line_bytes = lines_iter
        .next()
        .ok_or_else(|| invalid("Empty HTTP response status line"))?;
    let status_line = std::str::from_utf8(status_line_bytes)
        .map_err(|_| invalid("HTTP response status line is not valid UTF-8"))?;
    let after_ver = status_line
        .strip_prefix("HTTP/1.1 ")
        .or_else(|| status_line.strip_prefix("HTTP/1.0 "))
        .ok_or_else(|| invalid("Invalid HTTP response status line version"))?;
    if after_ver.len() < 3
        || !after_ver.as_bytes()[..3].iter().all(|b| b.is_ascii_digit())
        || after_ver.as_bytes().get(3).is_some_and(|&b| b != b' ')
    {
        return Err(invalid("Malformed HTTP response status code"));
    }
    let status_code: u16 = after_ver[..3]
        .parse()
        .map_err(|_| invalid("Unparseable HTTP response status code"))?;
    if !(100..=599).contains(&status_code) {
        return Err(invalid("HTTP response status code out of range"));
    }
    if status_code == 101 {
        return Err(invalid("Unexpected 101 Switching Protocols on non-upgrade HTTP forward"));
    }

    let mut header_lines: Vec<(&[u8], &[u8])> = Vec::new();
    let mut content_length: Option<u64> = None;
    let mut te_codings: Vec<String> = Vec::new();
    let mut te_seen = false;

    for line in lines_iter {
        if line.is_empty() || matches!(line[0], b' ' | b'\t') {
            return Err(invalid("Malformed or obs-fold HTTP response header line"));
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return Err(invalid("HTTP response header missing colon"));
        };
        let name = &line[..colon];
        let val = &line[colon + 1..];
        if name.is_empty() || !name.iter().all(|&b| crate::inbound::is_http_token_byte(b)) {
            return Err(invalid("Invalid HTTP response header name"));
        }
        if val.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err(invalid("HTTP response header value contains control characters"));
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            let v = std::str::from_utf8(val)
                .map_err(|_| invalid("Non-UTF-8 response Content-Length header"))?
                .trim();
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid("Invalid response Content-Length header"));
            }
            let parsed = v
                .parse::<u64>()
                .map_err(|_| invalid("Overflow in response Content-Length header"))?;
            if let Some(prev) = content_length
                && prev != parsed
            {
                return Err(invalid("Conflicting Content-Length headers in HTTP response"));
            }
            content_length = Some(parsed);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            te_seen = true;
            let v = std::str::from_utf8(val)
                .map_err(|_| invalid("Non-UTF-8 response Transfer-Encoding header"))?;
            for part in v.split(',') {
                let coding = part.trim().to_ascii_lowercase();
                if coding.is_empty() {
                    return Err(invalid("Empty Transfer-Encoding coding in HTTP response"));
                }
                te_codings.push(coding);
            }
        }
        header_lines.push((line, name));
    }

    if (100..200).contains(&status_code) {
        if content_length.is_some() || te_seen {
            return Err(invalid("1xx interim HTTP response must not contain body framing headers"));
        }
        let mut raw = Vec::with_capacity(head.len() + 4);
        raw.extend_from_slice(head);
        raw.extend_from_slice(b"\r\n\r\n");
        return Ok(ParsedHttpResponseHead::Interim(raw));
    }

    if content_length.is_some() && te_seen {
        return Err(invalid(
            "HTTP response contains both Content-Length and Transfer-Encoding",
        ));
    }
    let chunked_count = te_codings.iter().filter(|c| c.as_str() == "chunked").count();
    let is_chunked = if chunked_count > 1 {
        return Err(invalid("Duplicate chunked coding in response Transfer-Encoding"));
    } else if chunked_count == 1 {
        if te_codings.last().map(|s| s.as_str()) != Some("chunked") {
            return Err(invalid("chunked must be the final Transfer-Encoding coding"));
        }
        true
    } else {
        false
    };

    // 剥离源站 keep-alive/逐跳声明并强制注入 Connection: close，告知客户端响应结束后即可断连
    let mut rewritten = Vec::with_capacity(head.len() + 32);
    rewritten.extend_from_slice(status_line_bytes);
    rewritten.extend_from_slice(b"\r\n");
    for (line, name) in header_lines {
        let is_conn_hop = name.eq_ignore_ascii_case(b"connection")
            || name.eq_ignore_ascii_case(b"keep-alive")
            || name.eq_ignore_ascii_case(b"proxy-connection");
        if !is_conn_hop {
            rewritten.extend_from_slice(line);
            rewritten.extend_from_slice(b"\r\n");
        }
    }
    rewritten.extend_from_slice(b"Connection: close\r\n\r\n");

    let framing = if is_head_request || status_code == 204 || status_code == 304 {
        HttpResponseFraming::Empty
    } else if is_chunked {
        HttpResponseFraming::Chunked
    } else if let Some(len) = content_length {
        HttpResponseFraming::ContentLength(len)
    } else {
        HttpResponseFraming::UntilEof
    };

    Ok(ParsedHttpResponseHead::Final {
        rewritten_head: rewritten,
        framing,
    })
}

async fn relay_http_response_downlink(
    rr: tokio::net::tcp::OwnedReadHalf,
    sink: &mut TrackedBodySink<'_>,
    is_head_request: bool,
) -> std::io::Result<u64> {
    const MAX_HTTP_RESPONSE_HEADER: usize = 64 * 1024;
    const MAX_INTERIM_RESPONSES: usize = 16;

    let mut reader = PrefixedTcpReader::new(Vec::new(), rr);
    let mut interim_count = 0usize;

    let framing = loop {
        let Some(head) = reader
            .read_http_header_block(MAX_HTTP_RESPONSE_HEADER)
            .await?
        else {
            sink.writer.shutdown().await.ok();
            return Ok(sink.total_bytes.load(std::sync::atomic::Ordering::Relaxed));
        };
        match parse_and_rewrite_http_response_head(&head, is_head_request)? {
            ParsedHttpResponseHead::Interim(raw) => {
                interim_count += 1;
                if interim_count > MAX_INTERIM_RESPONSES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Too many 1xx interim HTTP responses",
                    ));
                }
                sink.write_all(&raw)
                    .await
                    .map_err(BodyRelayError::into_io_error)?;
                sink.writer.flush().await?;
            }
            ParsedHttpResponseHead::Final {
                rewritten_head,
                framing,
            } => {
                sink.write_all(&rewritten_head)
                    .await
                    .map_err(BodyRelayError::into_io_error)?;
                break framing;
            }
        }
    };

    match framing {
        HttpResponseFraming::Empty => {}
        HttpResponseFraming::ContentLength(len) => {
            copy_exact_body(&mut reader, sink, len)
                .await
                .map_err(BodyRelayError::into_io_error)?;
        }
        HttpResponseFraming::Chunked => {
            forward_chunked_body(&mut reader, sink)
                .await
                .map_err(BodyRelayError::into_io_error)?;
        }
        HttpResponseFraming::UntilEof => {
            copy_until_eof(&mut reader, sink)
                .await
                .map_err(BodyRelayError::into_io_error)?;
        }
    }

    sink.writer.flush().await.ok();
    sink.writer.shutdown().await.ok();
    Ok(sink.total_bytes.load(std::sync::atomic::Ordering::Relaxed))
}

/// 明文 HTTP 代理有界双向报文转发：请求侧严格按 `Content-Length` / `chunked` 截断并隔离流水线走私；
/// 响应侧解析 HTTP/1.x 响应头与有界响应体（重写 `Connection: close`），响应体完毕即主动优雅关闭双方连接，
/// 防止忽略 `Connection: close` 的 HTTP/1.1 Keep-Alive 源站拖挂至 120s 空闲超时，同时兼容延迟响应与早期 4xx 拒绝。
pub async fn relay_http_forward_monitored(
    local: TcpStream,
    remote: TcpStream,
    conn: Option<&Arc<ActiveConnection>>,
    framing: crate::inbound::HttpBodyFraming,
    body_prefix: Vec<u8>,
    is_head_request: bool,
) -> Result<(u64, u64)> {
    const RELAY_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
    relay_http_forward_monitored_with_timeout(
        local,
        remote,
        conn,
        framing,
        body_prefix,
        is_head_request,
        RELAY_IDLE_TIMEOUT,
    )
    .await
}

pub async fn relay_http_forward_monitored_with_timeout(
    local: TcpStream,
    remote: TcpStream,
    conn: Option<&Arc<ActiveConnection>>,
    framing: crate::inbound::HttpBodyFraming,
    body_prefix: Vec<u8>,
    is_head_request: bool,
    idle_timeout: std::time::Duration,
) -> Result<(u64, u64)> {
    use std::sync::atomic::{AtomicU64, Ordering};

    if conn.is_some_and(|c| c.is_cancelled()) {
        anyhow::bail!("Connection aborted by administrator");
    }

    let (lr, lw) = local.into_split();
    let (rr, rw) = remote.into_split();

    let conn_up = conn.cloned();
    let conn_down = conn.cloned();

    let start = tokio::time::Instant::now();
    let last_activity_us = Arc::new(AtomicU64::new(0));
    let last_up = Arc::clone(&last_activity_us);
    let last_down = Arc::clone(&last_activity_us);
    let up_bytes = Arc::new(AtomicU64::new(0));
    let up_bytes_ref = Arc::clone(&up_bytes);
    let down_bytes = Arc::new(AtomicU64::new(0));
    let down_bytes_ref = Arc::clone(&down_bytes);

    let up_task = async move {
        let mut reader = PrefixedTcpReader::new(body_prefix, lr);
        let mut up_sink = TrackedBodySink {
            writer: rw,
            total_bytes: &up_bytes_ref,
            conn: &conn_up,
            start: &start,
            last_activity_us: &last_up,
            direction: RelayDirection::Upload,
        };
        match framing {
            crate::inbound::HttpBodyFraming::ContentLength(len) => {
                copy_exact_body(&mut reader, &mut up_sink, len).await?;
            }
            crate::inbound::HttpBodyFraming::Chunked => {
                forward_chunked_body(&mut reader, &mut up_sink).await?;
            }
        }
        // 丢弃 client 读端（阻断后续流水线请求字节），同时保留写端至响应完成，不发送提前 FIN
        drop(reader);
        Ok::<tokio::net::tcp::OwnedWriteHalf, BodyRelayError>(up_sink.writer)
    };

    let down_task = async move {
        let mut down_sink = TrackedBodySink {
            writer: lw,
            total_bytes: &down_bytes_ref,
            conn: &conn_down,
            start: &start,
            last_activity_us: &last_down,
            direction: RelayDirection::Download,
        };
        relay_http_response_downlink(rr, &mut down_sink, is_head_request).await
    };

    let relay_fut = async {
        tokio::pin!(up_task);
        tokio::pin!(down_task);
        let mut up_done = false;
        let mut rw_keepalive: Option<tokio::net::tcp::OwnedWriteHalf> = None;
        let mut pending_up_write_err: Option<std::io::Error> = None;

        loop {
            tokio::select! {
                up_res = &mut up_task, if !up_done => {
                    match up_res {
                        Ok(rw_done) => {
                            rw_keepalive = Some(rw_done);
                            up_done = true;
                        }
                        Err(BodyRelayError::PeerWriteClosed(e)) => {
                            // 源站可能已发送 4xx/413 响应并关闭接收端；继续完成下行读取以免吞掉响应体
                            pending_up_write_err = Some(e);
                            up_done = true;
                        }
                        Err(BodyRelayError::Fatal(e)) => return Err(e),
                    }
                }
                down_res = &mut down_task => {
                    let down_bytes = down_res?;
                    if let Some(mut rw_open) = rw_keepalive.take() {
                        rw_open.shutdown().await.ok();
                    }
                    if down_bytes == 0
                        && let Some(e) = pending_up_write_err
                    {
                        return Err(e);
                    }
                    return Ok((up_bytes.load(Ordering::Relaxed), down_bytes));
                }
            }
        }
    };

    await_relay_with_watchdog(relay_fut, start, last_activity_us, conn, idle_timeout).await
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
}
