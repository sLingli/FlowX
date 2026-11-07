use std::net::SocketAddr;
use anyhow::Result;
use tokio::net::TcpStream;

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

/// 全双工透明流中继对拷
pub async fn relay_stream(mut local: TcpStream, mut remote: TcpStream) -> Result<(u64, u64)> {
    let (uploaded, downloaded) = tokio::io::copy_bidirectional(&mut local, &mut remote).await?;
    Ok((uploaded, downloaded))
}
