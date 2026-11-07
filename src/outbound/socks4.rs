use std::net::SocketAddr;
use std::time::Duration;
use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use super::TargetAddr;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct Socks4Client {
    pub proxy_addr: String,
    pub user_id: String,
}

impl Socks4Client {
    pub fn new(proxy_addr: impl Into<String>) -> Self {
        Self {
            proxy_addr: proxy_addr.into(),
            user_id: "flowx".into(),
        }
    }

    pub fn with_user_id(mut self, user_id: String) -> Self {
        self.user_id = user_id;
        self
    }

    pub async fn connect(&self, target: &TargetAddr) -> Result<TcpStream> {
        tokio::time::timeout(DEFAULT_TIMEOUT, async {
            let stream = TcpStream::connect(&self.proxy_addr)
                .await
                .with_context(|| format!("连接 SOCKS4 代理节点失败: {}", self.proxy_addr))?;

            self.handshake(stream, target).await
        })
        .await
        .map_err(|_| anyhow::anyhow!("连接 SOCKS4 代理超时 ({:?}): {}", DEFAULT_TIMEOUT, self.proxy_addr))?
    }

    pub async fn handshake(&self, mut stream: TcpStream, target: &TargetAddr) -> Result<TcpStream> {
        tokio::time::timeout(DEFAULT_TIMEOUT, self.handshake_internal(&mut stream, target))
            .await
            .map_err(|_| anyhow::anyhow!("SOCKS4 握手超时 ({:?})", DEFAULT_TIMEOUT))??;
        Ok(stream)
    }

    async fn handshake_internal(&self, stream: &mut TcpStream, target: &TargetAddr) -> Result<()> {
        if self.user_id.contains('\0') {
            bail!("SOCKS4 user_id 包含非法的空字符 (\\0)");
        }

        let mut req = Vec::new();
        req.push(0x04); // VN: 4
        req.push(0x01); // CD: 1 (CONNECT)

        let port_bytes = target.port().to_be_bytes();
        req.extend_from_slice(&port_bytes);

        match target {
            TargetAddr::Ip(SocketAddr::V4(v4)) => {
                // 标准 SOCKS4
                req.extend_from_slice(&v4.ip().octets());
                req.extend_from_slice(self.user_id.as_bytes());
                req.push(0x00);
            }
            TargetAddr::Ip(SocketAddr::V6(_)) => {
                bail!("SOCKS4 协议不支持 IPv6 目标地址");
            }
            TargetAddr::Domain(domain, _) => {
                if domain.contains('\0') {
                    bail!("SOCKS4 目标域名包含非法的空字符 (\\0): {}", domain);
                }
                // SOCKS4a 域名远程解析扩展: IP 设为 0.0.0.1
                req.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
                req.extend_from_slice(self.user_id.as_bytes());
                req.push(0x00);
                req.extend_from_slice(domain.as_bytes());
                req.push(0x00);
            }
        }

        stream.write_all(&req).await?;

        // 读取响应: 8 字节 (VN, CD, DSTPORT, DSTIP)
        let mut reply = [0u8; 8];
        stream.read_exact(&mut reply).await?;

        // reply[0] 应为 0x00 (RFC/标准协议实现) 或 0x04
        if reply[0] != 0x00 && reply[0] != 0x04 {
            bail!("无效的 SOCKS4 应答版本: 0x{:02x}", reply[0]);
        }

        if reply[1] != 0x5A {
            let reason = match reply[1] {
                0x5B => "请求被拒绝或失败 (91: Request rejected or failed)",
                0x5C => "无法连接客户端的 identd (92: Rejected: identd unreachable)",
                0x5D => "identd 返回的用户不匹配 (93: Rejected: user mismatch)",
                _code => "未知错误码",
            };
            bail!("SOCKS4 代理连接失败: {} (code: 0x{:02x})", reason, reply[1]);
        }

        Ok(())
    }
}
