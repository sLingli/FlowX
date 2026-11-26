use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

const PORT_SPACE: usize = 65536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassProtocol {
    Tcp,
    Udp,
}

/// 进程全局无锁出站端口绕过注册表（按协议与 IPv4/IPv6 地址族隔离），
/// 用于 WinDivert 透明拦截模式下防止 FlowX 自身出站流与上游 DNS 查询发生自环，
/// 同时避免同端口跨地址族误绕过其它应用流量。
struct BypassPortRegistry {
    tcp_v4: Box<[AtomicU32]>,
    tcp_v6: Box<[AtomicU32]>,
    udp_v4: Box<[AtomicU32]>,
    udp_v6: Box<[AtomicU32]>,
}

impl BypassPortRegistry {
    fn new() -> Self {
        let make_table = || {
            (0..PORT_SPACE)
                .map(|_| AtomicU32::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice()
        };
        Self {
            tcp_v4: make_table(),
            tcp_v6: make_table(),
            udp_v4: make_table(),
            udp_v6: make_table(),
        }
    }

    #[inline]
    fn table(&self, proto: BypassProtocol, is_ipv6: bool) -> &[AtomicU32] {
        match (proto, is_ipv6) {
            (BypassProtocol::Tcp, false) => &self.tcp_v4,
            (BypassProtocol::Tcp, true) => &self.tcp_v6,
            (BypassProtocol::Udp, false) => &self.udp_v4,
            (BypassProtocol::Udp, true) => &self.udp_v6,
        }
    }
}

static BYPASS_REGISTRY: OnceLock<BypassPortRegistry> = OnceLock::new();
static TRANSPARENT_ACTIVE: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
thread_local! {
    /// 单元测试专用的线程局部透明代理激活覆盖值，避免 `bypass::tests` 修改进程全局
    /// `TRANSPARENT_ACTIVE` 时污染并发运行的其它模块单测。
    static TEST_TRANSPARENT_ACTIVE_OVERRIDE: std::cell::Cell<Option<bool>> =
        const { std::cell::Cell::new(None) };
}

fn registry() -> &'static BypassPortRegistry {
    BYPASS_REGISTRY.get_or_init(BypassPortRegistry::new)
}

/// 切换透明代理激活状态：仅在 WinDivert 拦截激活期间预绑定并登记绕过端口；显式代理模式下保持 OS 原始 `TcpStream::connect` 选源行为
pub fn set_transparent_active(active: bool) {
    TRANSPARENT_ACTIVE.store(active, Ordering::Release);
}

#[inline]
pub fn is_transparent_active() -> bool {
    #[cfg(test)]
    if let Some(override_active) = TEST_TRANSPARENT_ACTIVE_OVERRIDE.with(std::cell::Cell::get) {
        return override_active;
    }
    TRANSPARENT_ACTIVE.load(Ordering::Acquire)
}

/// RAII 端口绕过守卫：创建时以 SeqCst 屏障登记源端口，析构时自动递减引用计数。
#[derive(Debug)]
pub struct BypassPortGuard {
    proto: BypassProtocol,
    is_ipv6: bool,
    port: u16,
}

impl BypassPortGuard {
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn is_ipv6(&self) -> bool {
        self.is_ipv6
    }
}

impl Drop for BypassPortGuard {
    fn drop(&mut self) {
        if self.port == 0 {
            return;
        }
        registry().table(self.proto, self.is_ipv6)[self.port as usize]
            .fetch_sub(1, Ordering::Release);
    }
}

/// 按协议与地址族登记本地源端口，确保内核 emit 首包前已可见。
pub fn register_bypass_port_for_family(
    proto: BypassProtocol,
    is_ipv6: bool,
    port: u16,
) -> BypassPortGuard {
    if port != 0 {
        registry().table(proto, is_ipv6)[port as usize].fetch_add(1, Ordering::SeqCst);
    }
    BypassPortGuard {
        proto,
        is_ipv6,
        port,
    }
}

/// 登记 IPv4 本地源端口（兼容快捷入口）。
pub fn register_bypass_port(proto: BypassProtocol, port: u16) -> BypassPortGuard {
    register_bypass_port_for_family(proto, false, port)
}

#[inline]
pub fn is_tcp_port_bypassed_for_family(port: u16, is_ipv6: bool) -> bool {
    port != 0
        && registry().table(BypassProtocol::Tcp, is_ipv6)[port as usize].load(Ordering::Acquire) > 0
}

#[inline]
pub fn is_udp_port_bypassed_for_family(port: u16, is_ipv6: bool) -> bool {
    port != 0
        && registry().table(BypassProtocol::Udp, is_ipv6)[port as usize].load(Ordering::Acquire) > 0
}

#[inline]
pub fn is_tcp_port_bypassed(port: u16) -> bool {
    is_tcp_port_bypassed_for_family(port, false)
}

#[inline]
pub fn is_udp_port_bypassed(port: u16) -> bool {
    is_udp_port_bypassed_for_family(port, false)
}

fn normalize_connect_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => {
            if let Some(v4) = crate::dns::FakeIpPool::unwrap_ipv4(IpAddr::V6(*v6.ip())) {
                SocketAddr::new(IpAddr::V4(v4), v6.port())
            } else {
                SocketAddr::V6(v6)
            }
        }
        v4 => v4,
    }
}

/// 持有源端口绕过守卫的出站 TCP 流；注意字段声明顺序保证 `inner` 先于 `_bypass_guard` 释放。
#[derive(Debug)]
pub struct OutboundTcpStream {
    inner: TcpStream,
    _bypass_guard: Option<Arc<BypassPortGuard>>,
}

impl OutboundTcpStream {
    pub fn from_raw(stream: TcpStream) -> Self {
        Self {
            inner: stream,
            _bypass_guard: None,
        }
    }

    /// 显式拆解底层 `TcpStream` 与绕过守卫；调用方需确保 `TcpStream` 先于守卫析构。
    pub fn into_parts(self) -> (TcpStream, Option<Arc<BypassPortGuard>>) {
        (self.inner, self._bypass_guard)
    }

    /// 仅当未持有绕过守卫（显式模式）时解包为裸 `TcpStream`，杜绝透明模式下提前释放端口守卫。
    pub fn try_into_inner(self) -> std::result::Result<TcpStream, Self> {
        if self._bypass_guard.is_some() {
            Err(self)
        } else {
            Ok(self.inner)
        }
    }

    pub fn into_split(self) -> (GuardedReadHalf, GuardedWriteHalf) {
        let Self {
            inner,
            _bypass_guard,
        } = self;
        let (r, w) = inner.into_split();
        (
            GuardedReadHalf {
                inner: r,
                _bypass_guard: _bypass_guard.clone(),
            },
            GuardedWriteHalf {
                inner: w,
                _bypass_guard,
            },
        )
    }
}

impl From<TcpStream> for OutboundTcpStream {
    fn from(stream: TcpStream) -> Self {
        Self::from_raw(stream)
    }
}

impl Deref for OutboundTcpStream {
    type Target = TcpStream;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for OutboundTcpStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl AsyncRead for OutboundTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for OutboundTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[derive(Debug)]
pub struct GuardedReadHalf {
    inner: OwnedReadHalf,
    _bypass_guard: Option<Arc<BypassPortGuard>>,
}

impl AsyncRead for GuardedReadHalf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[derive(Debug)]
pub struct GuardedWriteHalf {
    inner: OwnedWriteHalf,
    _bypass_guard: Option<Arc<BypassPortGuard>>,
}

impl AsyncWrite for GuardedWriteHalf {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// 仅在透明代理激活期间先绑定未指定端口并登记到 `BypassPortRegistry` 再发起连接；显式模式下直接走 `TcpStream::connect` 保留 OS 原生行为
pub async fn connect_tcp_guarded(addr: SocketAddr) -> std::io::Result<OutboundTcpStream> {
    let target = normalize_connect_addr(addr);
    if !is_transparent_active() {
        let stream = TcpStream::connect(target).await?;
        return Ok(OutboundTcpStream {
            inner: stream,
            _bypass_guard: None,
        });
    }
    // 守卫必须声明于 socket 及 connect future 之前，确保连接失败、panic 或取消时 LIFO 析构顺序先关闭 socket 再释放端口守卫
    let guard: Option<Arc<BypassPortGuard>>;
    let sock = match target {
        SocketAddr::V4(_) => {
            let s = TcpSocket::new_v4()?;
            s.bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
            s
        }
        SocketAddr::V6(_) => {
            let s = TcpSocket::new_v6()?;
            s.bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))?;
            s
        }
    };
    let local_addr = sock.local_addr()?;
    guard = Some(Arc::new(register_bypass_port_for_family(
        BypassProtocol::Tcp,
        local_addr.is_ipv6(),
        local_addr.port(),
    )));
    let stream = sock.connect(target).await?;
    Ok(OutboundTcpStream {
        inner: stream,
        _bypass_guard: guard,
    })
}

/// 持有源端口绕过守卫的出站 UDP 套接字；`socket` 先于 `_bypass_guard` 析构以保护关闭时序。
pub struct GuardedUdpSocket {
    socket: UdpSocket,
    _bypass_guard: Option<BypassPortGuard>,
}

impl Deref for GuardedUdpSocket {
    type Target = UdpSocket;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

/// 绑定临时 UDP 套接字；透明代理激活时自动登记本地源端口至 UDP 绕过表（供上游 DNS 查询使用）。
pub async fn bind_udp_guarded(local_bind: &str) -> std::io::Result<GuardedUdpSocket> {
    // 守卫先于 socket 声明，防止中途错误路径下守卫早于 socket 释放
    let mut guard: Option<BypassPortGuard> = None;
    let socket = UdpSocket::bind(local_bind).await?;
    if is_transparent_active() {
        let local_addr = socket.local_addr()?;
        guard = Some(register_bypass_port_for_family(
            BypassProtocol::Udp,
            local_addr.is_ipv6(),
            local_addr.port(),
        ));
    }
    Ok(GuardedUdpSocket {
        socket,
        _bypass_guard: guard,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// 线程局部 RAII 透明激活态守卫：仅影响当前单测线程，绝不向其它并发单测外溢全局状态。
    struct ScopedTransparentActive {
        prev: Option<bool>,
    }

    impl ScopedTransparentActive {
        fn new(active: bool) -> Self {
            let prev = TEST_TRANSPARENT_ACTIVE_OVERRIDE.with(|cell| {
                let old = cell.get();
                cell.set(Some(active));
                old
            });
            Self { prev }
        }
    }

    impl Drop for ScopedTransparentActive {
        fn drop(&mut self) {
            TEST_TRANSPARENT_ACTIVE_OVERRIDE.with(|cell| cell.set(self.prev));
        }
    }

    #[tokio::test]
    async fn test_bypass_port_refcount_overlapping_guards() {
        let _active = ScopedTransparentActive::new(false);

        let port_holder = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = port_holder.local_addr().unwrap().port();
        assert!(!is_tcp_port_bypassed(port));
        assert!(!is_udp_port_bypassed(port));

        let g1 = register_bypass_port(BypassProtocol::Tcp, port);
        assert!(is_tcp_port_bypassed(port));
        assert!(!is_udp_port_bypassed(port));

        let g2 = register_bypass_port(BypassProtocol::Tcp, port);
        assert!(is_tcp_port_bypassed(port));

        drop(g1);
        assert!(
            is_tcp_port_bypassed(port),
            "Overlapping guard must preserve bypass registration"
        );

        drop(g2);
        assert!(
            !is_tcp_port_bypassed(port),
            "Port must clear once final guard drops"
        );
        drop(port_holder);
    }

    #[tokio::test]
    async fn test_connect_tcp_guarded_and_split_lifetime() {
        let _active = ScopedTransparentActive::new(true);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (client_res, accept_res) = tokio::join!(connect_tcp_guarded(addr), listener.accept());
        let client = client_res.unwrap();
        let _server = accept_res.unwrap().0;

        let local_port = client.local_addr().unwrap().port();
        assert!(is_tcp_port_bypassed(local_port));

        let (r, w) = client.into_split();
        assert!(is_tcp_port_bypassed(local_port));
        drop(r);
        assert!(
            is_tcp_port_bypassed(local_port),
            "Write half must still retain bypass guard after read half drops"
        );
        drop(w);
        assert!(
            !is_tcp_port_bypassed(local_port),
            "Bypass guard must release after both halves drop"
        );
    }

    #[tokio::test]
    async fn test_connect_tcp_and_bind_udp_skip_bypass_when_transparent_inactive() {
        let _active = ScopedTransparentActive::new(false);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client_res, accept_res) = tokio::join!(connect_tcp_guarded(addr), listener.accept());
        let client = client_res.unwrap();
        let _server = accept_res.unwrap().0;

        let local_port = client.local_addr().unwrap().port();
        assert!(
            !is_tcp_port_bypassed(local_port),
            "Explicit mode must not register TCP ports in BypassPortRegistry"
        );

        let udp = bind_udp_guarded("127.0.0.1:0").await.unwrap();
        let udp_port = udp.local_addr().unwrap().port();
        assert!(
            !is_udp_port_bypassed(udp_port),
            "Explicit mode must not register UDP ports in BypassPortRegistry"
        );
    }

    #[tokio::test]
    async fn test_bind_udp_guarded_registers_and_releases() {
        let _active = ScopedTransparentActive::new(true);

        let guarded = bind_udp_guarded("127.0.0.1:0").await.unwrap();
        let port = guarded.local_addr().unwrap().port();
        assert!(is_udp_port_bypassed(port));
        assert!(
            !is_udp_port_bypassed_for_family(port, true),
            "IPv4 UDP guard must not bypass same IPv6 port"
        );
        drop(guarded);
        assert!(!is_udp_port_bypassed(port));
    }

    #[tokio::test]
    async fn test_bypass_port_ipv4_ipv6_isolation_and_try_into_inner() {
        let _active = ScopedTransparentActive::new(true);

        let port_holder = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = port_holder.local_addr().unwrap().port();
        let g_v4 = register_bypass_port_for_family(BypassProtocol::Tcp, false, port);
        assert!(is_tcp_port_bypassed_for_family(port, false));
        assert!(!is_tcp_port_bypassed_for_family(port, true));

        let g_v6 = register_bypass_port_for_family(BypassProtocol::Tcp, true, port);
        assert!(is_tcp_port_bypassed_for_family(port, false));
        assert!(is_tcp_port_bypassed_for_family(port, true));

        drop(g_v4);
        assert!(!is_tcp_port_bypassed_for_family(port, false));
        assert!(is_tcp_port_bypassed_for_family(port, true));
        drop(g_v6);
        assert!(!is_tcp_port_bypassed_for_family(port, true));
        drop(port_holder);

        // Guarded OutboundTcpStream must refuse try_into_inner so bypass guard cannot drop prematurely
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client_res, accept_res) = tokio::join!(connect_tcp_guarded(addr), listener.accept());
        let client = client_res.unwrap();
        let _server = accept_res.unwrap().0;
        let local_port = client.local_addr().unwrap().port();
        assert!(is_tcp_port_bypassed_for_family(local_port, false));

        let guarded_again = client
            .try_into_inner()
            .expect_err("try_into_inner must reject stream with active bypass guard");
        assert!(is_tcp_port_bypassed_for_family(local_port, false));

        let (raw_stream, guard_opt) = guarded_again.into_parts();
        assert!(guard_opt.is_some());
        assert!(is_tcp_port_bypassed_for_family(local_port, false));
        drop(raw_stream);
        assert!(is_tcp_port_bypassed_for_family(local_port, false));
        drop(guard_opt);
        assert!(!is_tcp_port_bypassed_for_family(local_port, false));
    }

    #[test]
    fn test_scoped_transparent_active_does_not_leak_to_other_threads() {
        let _active = ScopedTransparentActive::new(true);
        assert!(is_transparent_active());
        let other_thread_val = std::thread::spawn(is_transparent_active).join().unwrap();
        assert!(
            !other_thread_val,
            "thread-local test override must never leak TRANSPARENT_ACTIVE to concurrent tests"
        );
    }
}
