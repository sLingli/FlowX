use anyhow::{Context, Result};
use tokio::net::TcpStream;
use super::TargetAddr;

pub struct DirectOutbound;

impl DirectOutbound {
    pub async fn connect(target: &TargetAddr) -> Result<TcpStream> {
        let stream = match target {
            TargetAddr::Ip(addr) => {
                TcpStream::connect(addr)
                    .await
                    .with_context(|| format!("直连目标 IP 失败: {}", addr))?
            }
            TargetAddr::Domain(domain, port) => {
                let target_str = format!("{}:{}", domain, port);
                TcpStream::connect(&target_str)
                    .await
                    .with_context(|| format!("直连目标域名失败: {}", target_str))?
            }
        };
        Ok(stream)
    }
}
