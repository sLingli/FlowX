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
    let (mut lr, mut lw) = local.into_split();
    let (mut rr, mut rw) = remote.into_split();

    let conn_up = conn.cloned();
    let conn_down = conn.cloned();
    let cancel_notify = conn.map(|c| c.cancel_notify.clone());

    const RELAY_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

    let up_task = async move {
        let mut buf = [0u8; 16384];
        let mut total_up = 0u64;
        loop {
            let res = tokio::time::timeout(RELAY_IDLE_TIMEOUT, lr.read(&mut buf)).await;
            let n = match res {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "上传通道空闲超时")),
            };
            if n == 0 {
                rw.shutdown().await.ok();
                break;
            }
            rw.write_all(&buf[..n]).await?;
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
            let res = tokio::time::timeout(RELAY_IDLE_TIMEOUT, rr.read(&mut buf)).await;
            let n = match res {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "下载通道空闲超时")),
            };
            if n == 0 {
                lw.shutdown().await.ok();
                break;
            }
            lw.write_all(&buf[..n]).await?;
            total_down += n as u64;
            if let Some(c) = &conn_down {
                c.add_download(n as u64);
            }
        }
        Ok::<u64, std::io::Error>(total_down)
    };

    tokio::select! {
        res = async {
            tokio::try_join!(up_task, down_task)
        } => {
            let (up, down) = res?;
            Ok((up, down))
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
