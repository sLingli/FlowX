use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::monitor::ActiveConnection;

use super::RelayStream;

pub(super) fn record_activity_us(
    start: &tokio::time::Instant,
    tracker: &std::sync::atomic::AtomicU64,
) {
    let elapsed_us = start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    tracker.store(elapsed_us, std::sync::atomic::Ordering::Relaxed);
}

async fn relay_downlink<R, W>(
    mut rr: R,
    mut lw: W,
    conn: Option<Arc<ActiveConnection>>,
    start: tokio::time::Instant,
    last_activity_us: Arc<std::sync::atomic::AtomicU64>,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
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

pub(super) async fn await_relay_with_watchdog<FR>(
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
            let remaining =
                std::time::Duration::from_micros((timeout_us - elapsed_since_activity).max(1));
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
pub async fn relay_stream_monitored<L, R>(
    local: L,
    remote: R,
    conn: Option<&Arc<ActiveConnection>>,
) -> Result<(u64, u64)>
where
    L: RelayStream,
    R: RelayStream,
{
    const RELAY_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
    relay_stream_monitored_with_timeout(local, remote, conn, RELAY_IDLE_TIMEOUT).await
}

/// 可配置双向静默空闲超时的全双工对拷实现：
/// 仅当上行与下行在 `idle_timeout` 内均无任何数据流动时才判定超时；
/// 任一方向收到 EOF (n == 0) 半关闭后，仅关闭对端写方向并允许另一方向继续传输。
pub async fn relay_stream_monitored_with_timeout<L, R>(
    local: L,
    remote: R,
    conn: Option<&Arc<ActiveConnection>>,
    idle_timeout: std::time::Duration,
) -> Result<(u64, u64)>
where
    L: RelayStream,
    R: RelayStream,
{
    use std::sync::atomic::AtomicU64;

    if conn.is_some_and(|c| c.is_cancelled()) {
        anyhow::bail!("Connection aborted by administrator");
    }

    let (mut lr, lw) = local.split_stream();
    let (rr, mut rw) = remote.split_stream();

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
    run_relay_with_watchdog(
        up_task,
        down_task,
        start,
        last_activity_us,
        conn,
        idle_timeout,
    )
    .await
}

pub async fn relay_stream<L: RelayStream, R: RelayStream>(
    local: L,
    remote: R,
) -> Result<(u64, u64)> {
    relay_stream_monitored(local, remote, None).await
}
