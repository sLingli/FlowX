use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use anyhow::{bail, Context, Result};

pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

/// SOCKS5 客户端实现
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

    /// 与 SOCKS5 代理服务器建立 TCP 连接并完成握手请求
    pub async fn connect(&self, target: TargetAddr) -> Result<TcpStream> {
        let mut stream = TcpStream::connect(&self.proxy_addr)
            .await
            .with_context(|| format!("连接代理服务器失败: {}", self.proxy_addr))?;

        // 1. 发送认证协商 (Version 5, 支持 1 种或 2 种认证方法)
        if self.auth.is_some() {
            // 支持 NO AUTH (0x00) 与 USER/PASS (0x02)
            stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
        } else {
            // 仅 NO AUTH (0x00)
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
        }

        let mut method_reply = [0u8; 2];
        stream.read_exact(&mut method_reply).await?;
        if method_reply[0] != 0x05 {
            bail!("无效的 SOCKS 版本响应: 0x{:02x}", method_reply[0]);
        }

        match method_reply[1] {
            0x00 => {
                // 无需密码，协商完成
            }
            0x02 => {
                // 需要用户名/密码认证
                if let Some((user, pass)) = &self.auth {
                    let mut auth_req = Vec::new();
                    auth_req.push(0x01); // 认证子协议版本
                    auth_req.push(user.len() as u8);
                    auth_req.extend_from_slice(user.as_bytes());
                    auth_req.push(pass.len() as u8);
                    auth_req.extend_from_slice(pass.as_bytes());
                    stream.write_all(&auth_req).await?;

                    let mut auth_resp = [0u8; 2];
                    stream.read_exact(&mut auth_resp).await?;
                    if auth_resp[1] != 0x00 {
                        bail!("SOCKS5 用户名密码认证失败");
                    }
                } else {
                    bail!("代理服务器要求认证，但未配置用户名和密码");
                }
            }
            0xFF => bail!("代理服务器不接受我们支持的任何认证方式"),
            other => bail!("不支持的 SOCKS5 认证方法: 0x{:02x}", other),
        }

        // 2. 发起 CONNECT 请求 (CMD = 0x01)
        let mut connect_req = Vec::new();
        connect_req.extend_from_slice(&[0x05, 0x01, 0x00]); // VER, CMD=CONNECT, RSV

        match target {
            TargetAddr::Ip(addr) => match addr {
                SocketAddr::V4(v4) => {
                    connect_req.push(0x01); // ATYP = IPv4
                    connect_req.extend_from_slice(&v4.ip().octets());
                    connect_req.extend_from_slice(&v4.port().to_be_bytes());
                }
                SocketAddr::V6(v6) => {
                    connect_req.push(0x04); // ATYP = IPv6
                    connect_req.extend_from_slice(&v6.ip().octets());
                    connect_req.extend_from_slice(&v6.port().to_be_bytes());
                }
            },
            TargetAddr::Domain(domain, port) => {
                connect_req.push(0x03); // ATYP = Domain
                connect_req.push(domain.len() as u8);
                connect_req.extend_from_slice(domain.as_bytes());
                connect_req.extend_from_slice(&port.to_be_bytes());
            }
        }

        stream.write_all(&connect_req).await?;

        // 3. 读取代理服务器的应答
        let mut reply_header = [0u8; 4];
        stream.read_exact(&mut reply_header).await?;
        if reply_header[0] != 0x05 {
            bail!("无效的 SOCKS5 应答版本: 0x{:02x}", reply_header[0]);
        }
        if reply_header[1] != 0x00 {
            bail!("SOCKS5 连接目标失败，错误码: 0x{:02x}", reply_header[1]);
        }

        // 读取绑定的地址并丢弃
        match reply_header[3] {
            0x01 => {
                // IPv4: 4 bytes IP + 2 bytes Port
                let mut buf = [0u8; 6];
                stream.read_exact(&mut buf).await?;
            }
            0x03 => {
                // Domain: 1 byte len + N bytes domain + 2 bytes Port
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut buf = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut buf).await?;
            }
            0x04 => {
                // IPv6: 16 bytes IP + 2 bytes Port
                let mut buf = [0u8; 18];
                stream.read_exact(&mut buf).await?;
            }
            other => bail!("SOCKS5 未知应答地址类型: 0x{:02x}", other),
        }

        Ok(stream)
    }

    /// 在本地连接和远端代理连接之间实现全双工字节对拷
    pub async fn relay(mut local: TcpStream, mut remote: TcpStream) -> Result<(u64, u64)> {
        let (uploaded, downloaded) = tokio::io::copy_bidirectional(&mut local, &mut remote).await?;
        Ok((uploaded, downloaded))
    }
}
