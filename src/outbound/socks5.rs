use std::net::SocketAddr;
use std::time::Duration;
use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use super::TargetAddr;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct Socks5Client {
    pub proxy_addr: String,
    pub auth: Option<(String, String)>,
}

impl Socks5Client {
    pub fn new(proxy_addr: impl Into<String>) -> Self {
        Self {
            proxy_addr: proxy_addr.into(),
            auth: None,
        }
    }

    pub fn with_auth(mut self, user: String, pass: String) -> Self {
        self.auth = Some((user, pass));
        self
    }

    /// 通过代理地址建立初始 TCP 连接并握手（带 10s 超时保护）
    pub async fn connect(&self, target: &TargetAddr) -> Result<TcpStream> {
        tokio::time::timeout(DEFAULT_TIMEOUT, async {
            let stream = TcpStream::connect(&self.proxy_addr)
                .await
                .with_context(|| format!("连接 SOCKS5 代理节点失败: {}", self.proxy_addr))?;

            self.handshake(stream, target).await
        })
        .await
        .map_err(|_| anyhow::anyhow!("连接 SOCKS5 代理超时 ({:?}): {}", DEFAULT_TIMEOUT, self.proxy_addr))?
    }

    /// 在一个已建立的流（如前驱代理连接）上执行 SOCKS5 握手（用于代理链 Chaining）
    pub async fn handshake(&self, mut stream: TcpStream, target: &TargetAddr) -> Result<TcpStream> {
        tokio::time::timeout(DEFAULT_TIMEOUT, self.handshake_internal(&mut stream, target))
            .await
            .map_err(|_| anyhow::anyhow!("SOCKS5 握手超时 ({:?})", DEFAULT_TIMEOUT))??;
        Ok(stream)
    }

    async fn handshake_internal(&self, stream: &mut TcpStream, target: &TargetAddr) -> Result<()> {
        // 1. 发送认证协商
        if self.auth.is_some() {
            stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
        } else {
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
        }

        let mut method_reply = [0u8; 2];
        stream.read_exact(&mut method_reply).await?;
        if method_reply[0] != 0x05 {
            bail!("无效的 SOCKS 版本响应: 0x{:02x}", method_reply[0]);
        }

        match method_reply[1] {
            0x00 => {} // 无认证，直接进入请求阶段
            0x02 => {
                // 用户名密码认证子协议 (RFC 1929)
                if let Some((user, pass)) = &self.auth {
                    if user.len() > 255 || pass.len() > 255 {
                        bail!("SOCKS5 用户名或密码长度超出 RFC 1929 限制 (最大 255 字节)");
                    }
                    let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
                    auth_req.push(0x01); // 认证版本 (RFC 1929 指定为 0x01)
                    auth_req.push(user.len() as u8);
                    auth_req.extend_from_slice(user.as_bytes());
                    auth_req.push(pass.len() as u8);
                    auth_req.extend_from_slice(pass.as_bytes());
                    stream.write_all(&auth_req).await?;

                    let mut auth_resp = [0u8; 2];
                    stream.read_exact(&mut auth_resp).await?;
                    if auth_resp[0] != 0x01 {
                        bail!("SOCKS5 认证子协商响应版本错误: 0x{:02x}", auth_resp[0]);
                    }
                    if auth_resp[1] != 0x00 {
                        bail!("SOCKS5 用户名或密码认证失败 (status: 0x{:02x})", auth_resp[1]);
                    }
                } else {
                    bail!("代理节点要求认证，但未配置账号密码");
                }
            }
            0xFF => bail!("SOCKS5 代理服务器拒绝了客户端提供的认证方式 (0xFF)"),
            other => bail!("SOCKS5 不受支持的认证响应码: 0x{:02x}", other),
        }

        // 2. 发起 CONNECT 请求 (CMD = 0x01)
        let mut connect_req = Vec::new();
        connect_req.extend_from_slice(&[0x05, 0x01, 0x00]);

        match target {
            TargetAddr::Ip(addr) => match addr {
                SocketAddr::V4(v4) => {
                    connect_req.push(0x01); // ATYP: IPv4
                    connect_req.extend_from_slice(&v4.ip().octets());
                    connect_req.extend_from_slice(&v4.port().to_be_bytes());
                }
                SocketAddr::V6(v6) => {
                    connect_req.push(0x04); // ATYP: IPv6
                    connect_req.extend_from_slice(&v6.ip().octets());
                    connect_req.extend_from_slice(&v6.port().to_be_bytes());
                }
            },
            TargetAddr::Domain(domain, port) => {
                if domain.len() > 255 {
                    bail!("SOCKS5 目标域名长度超出 RFC 1928 限制 (最大 255 字节): {}", domain);
                }
                connect_req.push(0x03); // ATYP: 域名
                connect_req.push(domain.len() as u8);
                connect_req.extend_from_slice(domain.as_bytes());
                connect_req.extend_from_slice(&port.to_be_bytes());
            }
        }

        stream.write_all(&connect_req).await?;

        // 3. 读取应答并解析状态
        let mut reply_header = [0u8; 4];
        stream.read_exact(&mut reply_header).await?;
        if reply_header[0] != 0x05 {
            bail!("无效的 SOCKS5 应答版本: 0x{:02x}", reply_header[0]);
        }

        if reply_header[1] != 0x00 {
            let reason = match reply_header[1] {
                0x01 => "常规 SOCKS 服务器故障 (General failure)",
                0x02 => "连接被规则集拒绝 (Connection not allowed by ruleset)",
                0x03 => "网络不可达 (Network unreachable)",
                0x04 => "主机不可达 (Host unreachable)",
                0x05 => "目标连接被拒绝 (Connection refused)",
                0x06 => "TTL 超时 (TTL expired)",
                0x07 => "命令不受支持 (Command not supported)",
                0x08 => "地址类型不受支持 (Address type not supported)",
                _code => "未知错误响应码",
            };
            bail!("SOCKS5 连接目标失败: {} (code 0x{:02x})", reason, reply_header[1]);
        }

        // 读取绑定的服务器地址字段以清空缓冲区
        match reply_header[3] {
            0x01 => {
                let mut buf = [0u8; 6]; // 4 bytes IP + 2 bytes Port
                stream.read_exact(&mut buf).await?;
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut buf = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut buf).await?;
            }
            0x04 => {
                let mut buf = [0u8; 18]; // 16 bytes IPv6 + 2 bytes Port
                stream.read_exact(&mut buf).await?;
            }
            other => bail!("SOCKS5 返回了未知的绑定地址类型: 0x{:02x}", other),
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_client_creation() {
        let client = Socks5Client::new("127.0.0.1:1080")
            .with_auth("user".into(), "pass".into());
        assert_eq!(client.proxy_addr, "127.0.0.1:1080");
        assert_eq!(client.auth, Some(("user".into(), "pass".into())));
    }
}
