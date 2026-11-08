use std::net::SocketAddr;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
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

    let (mut lr, mut lw) = local.into_split();
    let (mut rr, mut rw) = remote.into_split();

    let conn_up = conn.cloned();
    let conn_down = conn.cloned();
    let cancel_notify = conn.map(|c| c.cancel_notify.clone());

    let start = tokio::time::Instant::now();
    // 使用微秒精度记录最近一次任一方向产生有效载荷的时间点
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
                format!("双向通道均空闲超过 {:?}，连接已超时关闭", idle_timeout),
            ));
        }
        _ = async {
            if let Some(ref cancel) = cancel_notify {
                cancel.notified().await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {
            anyhow::bail!("连接已被管理员手动切断");
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

        // 客户端收到服务端 EOF 后再关闭写端完成双向收尾
        client_w.shutdown().await.unwrap();
        server_task.await.unwrap();

        let (up, down) = relay_handle.await.unwrap().expect("单向持续传输期间不应因另一侧静默而超时");
        assert_eq!(up, 23);
        assert_eq!(down, 60);
    }

    /// P0-1 回归测试 2：客户端先半关闭 (EOF)，服务端继续跨多个空闲周期正常发送至完成
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

        let (up, down) = relay_handle.await.unwrap().expect("半关闭后对向持续数据流应完整成功");
        assert_eq!(up, 4);
        assert_eq!(down, 16);
    }

    /// P0-1 回归测试 3：当且仅当双向同时静默超过超时阈值时才触发空闲超时
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

        assert!(res.is_err(), "双向长期完全静默应触发超时清理");
    }
}
