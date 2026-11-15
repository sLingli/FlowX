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

/// 进程全局无锁出站端口绕过注册表，用于 WinDivert 透明拦截模式下防止 FlowX 自身出站流与上游 DNS 查询发生自环。
struct BypassPortRegistry {
    tcp: Box<[AtomicU32]>,
    udp: Box<[AtomicU32]>,
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
            tcp: make_table(),
            udp: make_table(),
        }
    }

    #[inline]
    fn table(&self, proto: BypassProtocol) -> &[AtomicU32] {
        match proto {
            BypassProtocol::Tcp => &self.tcp,
            BypassProtocol::Udp => &self.udp,
        }
    }
}

static BYPASS_REGISTRY: OnceLock<BypassPortRegistry> = OnceLock::new();
static TRANSPARENT_ACTIVE: AtomicBool = AtomicBool::new(false);

fn registry() -> &'static BypassPortRegistry {
    BYPASS_REGISTRY.get_or_init(BypassPortRegistry::new)
}

/// 切换透明代理激活状态：仅在 WinDivert 拦截激活期间预绑定并登记绕过端口；显式代理模式下保持 OS 原始 `TcpStream::connect` 选源行为
pub fn set_transparent_active(active: bool) {
    TRANSPARENT_ACTIVE.store(active, Ordering::Release);
}

#[inline]
pub fn is_transparent_active() -> bool {
    TRANSPARENT_ACTIVE.load(Ordering::Acquire)
}

/// RAII 端口绕过守卫：创建时以 SeqCst 屏障登记源端口，析构时自动递减引用计数。
#[derive(Debug)]
pub struct BypassPortGuard {
    proto: BypassProtocol,
    port: u16,
}

impl BypassPortGuard {
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for BypassPortGuard {
    fn drop(&mut self) {
        if self.port == 0 {
            return;
        }
        registry().table(self.proto)[self.port as usize].fetch_sub(1, Ordering::Release);
    }
}

/// 在发起真实出站连线或发包前注册本地源端口，确保内核 emit 首包前已可见。
pub fn register_bypass_port(proto: BypassProtocol, port: u16) -> BypassPortGuard {
    if port != 0 {
        registry().table(proto)[port as usize].fetch_add(1, Ordering::SeqCst);
    }
    BypassPortGuard { proto, port }
}

#[inline]
pub fn is_tcp_port_bypassed(port: u16) -> bool {
    port != 0 && registry().table(BypassProtocol::Tcp)[port as usize].load(Ordering::Acquire) > 0
}

#[inline]
pub fn is_udp_port_bypassed(port: u16) -> bool {
    port != 0 && registry().table(BypassProtocol::Udp)[port as usize].load(Ordering::Acquire) > 0
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

    pub fn into_inner(self) -> TcpStream {
        self.inner
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
    let local_port = sock.local_addr()?.port();
    let guard = Arc::new(register_bypass_port(BypassProtocol::Tcp, local_port));
    let stream = sock.connect(target).await?;
    Ok(OutboundTcpStream {
        inner: stream,
        _bypass_guard: Some(guard),
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
    let socket = UdpSocket::bind(local_bind).await?;
    let guard = if is_transparent_active() {
        let local_port = socket.local_addr()?.port();
        Some(register_bypass_port(BypassProtocol::Udp, local_port))
    } else {
        None
    };
    Ok(GuardedUdpSocket {
        socket,
        _bypass_guard: guard,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    static TEST_ACTIVE_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct TransparentActiveReset;
    impl Drop for TransparentActiveReset {
        fn drop(&mut self) {
            set_transparent_active(false);
        }
    }

    #[test]
    fn test_bypass_port_refcount_overlapping_guards() {
        let port = 59123u16;
        assert!(!is_tcp_port_bypassed(port));
        assert!(!is_udp_port_bypassed(port));

        let g1 = register_bypass_port(BypassProtocol::Tcp, port);
        assert!(is_tcp_port_bypassed(port));
        assert!(!is_udp_port_bypassed(port));

        let g2 = register_bypass_port(BypassProtocol::Tcp, port);
        assert!(is_tcp_port_bypassed(port));

        drop(g1);
        assert!(is_tcp_port_bypassed(port), "Overlapping guard must preserve bypass registration");

        drop(g2);
        assert!(!is_tcp_port_bypassed(port), "Port must clear once final guard drops");
    }

    #[tokio::test]
    async fn test_connect_tcp_guarded_and_split_lifetime() {
        let _lock = TEST_ACTIVE_MUTEX.lock().await;
        let _reset = TransparentActiveReset;
        set_transparent_active(true);

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
        let _lock = TEST_ACTIVE_MUTEX.lock().await;
        let _reset = TransparentActiveReset;
        set_transparent_active(false);

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
        let _lock = TEST_ACTIVE_MUTEX.lock().await;
        let _reset = TransparentActiveReset;
        set_transparent_active(true);

        let guarded = bind_udp_guarded("127.0.0.1:0").await.unwrap();
        let port = guarded.local_addr().unwrap().port();
        assert!(is_udp_port_bypassed(port));
        drop(guarded);
        assert!(!is_udp_port_bypassed(port));
    }
}
