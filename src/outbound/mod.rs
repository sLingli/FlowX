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

/// 全双工透明流中继对拷（带实时流量监视）
pub async fn relay_stream_monitored(
    local: TcpStream,
    remote: TcpStream,
    conn: Option<&Arc<ActiveConnection>>,
) -> Result<(u64, u64)> {
    let (mut lr, mut lw) = local.into_split();
    let (mut rr, mut rw) = remote.into_split();

    let conn_up = conn.cloned();
    let up_task = async move {
        let mut buf = [0u8; 16384];
        let mut total_up = 0u64;
        loop {
            let n = lr.read(&mut buf).await?;
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

    let conn_down = conn.cloned();
    let down_task = async move {
        let mut buf = [0u8; 16384];
        let mut total_down = 0u64;
        loop {
            let n = rr.read(&mut buf).await?;
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

    let (up_res, down_res) = tokio::join!(up_task, down_task);
    let up = up_res?;
    let down = down_res?;
    Ok((up, down))
}

pub async fn relay_stream(local: TcpStream, remote: TcpStream) -> Result<(u64, u64)> {
    relay_stream_monitored(local, remote, None).await
}
