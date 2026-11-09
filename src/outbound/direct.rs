use std::time::Duration;
use anyhow::{anyhow, Context, Result};
use tokio::net::TcpStream;
use super::TargetAddr;

/// Maximum timeout for direct TCP connection (including DNS resolution)
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct DirectOutbound;

impl DirectOutbound {
    pub async fn connect(target: &TargetAddr) -> Result<TcpStream> {
        let fut = async {
            match target {
                TargetAddr::Ip(addr) => TcpStream::connect(addr)
                    .await
                    .with_context(|| format!("Direct connection to target IP failed: {}", addr)),
                TargetAddr::Domain(domain, port) => {
                    let target_str = format!("{}:{}", domain, port);
                    TcpStream::connect(&target_str)
                        .await
                        .with_context(|| format!("Direct connection to target domain failed: {}", target_str))
                }
            }
        };
        tokio::time::timeout(DIRECT_CONNECT_TIMEOUT, fut).await.map_err(|_| {
            anyhow!(
                "Direct connection timed out ({:?}): {}:{}",
                DIRECT_CONNECT_TIMEOUT,
                target.host_string(),
                target.port()
            )
        })?
    }
}
