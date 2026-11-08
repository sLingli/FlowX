use std::time::Duration;
use anyhow::{anyhow, Context, Result};
use tokio::net::TcpStream;
use super::TargetAddr;

/// 直连建立 TCP 连接（含域名解析）的最长等待时间，防止黑洞目标长期占用并发名额
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct DirectOutbound;

impl DirectOutbound {
    pub async fn connect(target: &TargetAddr) -> Result<TcpStream> {
        let fut = async {
            match target {
                TargetAddr::Ip(addr) => TcpStream::connect(addr)
                    .await
                    .with_context(|| format!("直连目标 IP 失败: {}", addr)),
                TargetAddr::Domain(domain, port) => {
                    let target_str = format!("{}:{}", domain, port);
                    TcpStream::connect(&target_str)
                        .await
                        .with_context(|| format!("直连目标域名失败: {}", target_str))
                }
            }
        };
        tokio::time::timeout(DIRECT_CONNECT_TIMEOUT, fut).await.map_err(|_| {
            anyhow!(
                "直连目标超时 ({:?}): {}:{}",
                DIRECT_CONNECT_TIMEOUT,
                target.host_string(),
                target.port()
            )
        })?
    }
}
