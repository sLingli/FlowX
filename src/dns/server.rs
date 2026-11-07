use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use anyhow::{bail, Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};
use super::FakeIpPool;

/// 极简、零外部依赖的 RFC 1035 DNS 报文解析与构造器
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,  // 1 = A, 28 = AAAA
    pub qclass: u16, // 1 = IN
    pub raw_len: usize,
}

pub struct DnsPacketParser;

impl DnsPacketParser {
    pub fn parse_question(buf: &[u8]) -> Result<(u16, DnsQuestion)> {
        if buf.len() < 12 {
            bail!("DNS 报文过短 (小于头部 12 字节)");
        }

        // 检查 QR 标志位: 第 2 字节最高位 (bit 7) 必须为 0 (Query)
        if (buf[2] & 0x80) != 0 {
            bail!("DNS 报文不是标准查询 (QR != 0)");
        }

        // 检查 Opcode: 第 2 字节 bits 3-6 必须为 0 (Standard Query)
        let opcode = (buf[2] >> 3) & 0x0F;
        if opcode != 0 {
            bail!("不受支持的 DNS 操作码 (Opcode != 0): {}", opcode);
        }

        let tx_id = u16::from_be_bytes([buf[0], buf[1]]);
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
        if qdcount == 0 {
            bail!("DNS 查询未包含任何 Question 条目");
        }

        let mut offset = 12;
        let mut domain_parts = Vec::new();
        let mut total_domain_len = 0;
        let mut terminated = false;

        while offset < buf.len() {
            let len = buf[offset] as usize;
            offset += 1;
            if len == 0 {
                terminated = true;
                break;
            }
            if (len & 0xC0) != 0 {
                bail!("DNS 查询域名中包含不受支持的指针压缩标签");
            }
            if len > 63 {
                bail!("DNS 报文域名标签长度超出 RFC 1035 上限 63 字节: {}", len);
            }
            if offset + len > buf.len() {
                bail!("DNS 报文域名标签长度超出数据包边界");
            }
            total_domain_len += len + 1;
            if total_domain_len > 255 {
                bail!("DNS 域名总长度超出 RFC 1035 上限 253 字节");
            }
            let label = std::str::from_utf8(&buf[offset..offset + len])
                .context("DNS 域名包含非 UTF-8 字符")?;
            domain_parts.push(label.to_string());
            offset += len;
        }

        if !terminated {
            bail!("DNS 域名解析未遇到根空标签 (0x00) 即结束");
        }

        if offset + 4 > buf.len() {
            bail!("DNS Question 缺少 QTYPE 或 QCLASS 字段");
        }

        let qtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let qclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        let raw_len = offset + 4;

        Ok((
            tx_id,
            DnsQuestion {
                name: domain_parts.join("."),
                qtype,
                qclass,
                raw_len,
            },
        ))
    }

    /// 构造 Fake-IP A 记录应答报文
    pub fn build_a_response(tx_id: u16, original_query: &[u8], question_len: usize, ip: Ipv4Addr) -> Vec<u8> {
        let mut resp = Vec::with_capacity(question_len + 16);

        // 1. 事务 ID
        resp.extend_from_slice(&tx_id.to_be_bytes());

        // 2. 标志位: 0x8180 (标准响应, 递归可用, No error)
        resp.extend_from_slice(&[0x81, 0x80]);

        // 3. 计数: QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);

        // 4. 拷贝原始 Question 部分 (从 offset 12 到 question_len)
        if question_len > 12 && question_len <= original_query.len() {
            resp.extend_from_slice(&original_query[12..question_len]);
        }

        // 5. Answer 资源记录
        // 名称指针: 0xc00c 指向原始 Question 的域名起始位置 (第 12 字节)
        resp.extend_from_slice(&[0xc0, 0x0c]);
        // TYPE: 0x0001 (A), CLASS: 0x0001 (IN)
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // TTL: 10 秒 (防止操作系统长久缓存导致规则切换不及时)
        resp.extend_from_slice(&10u32.to_be_bytes());
        // RDLENGTH: 4 bytes
        resp.extend_from_slice(&4u16.to_be_bytes());
        // RDATA: IPv4 4 字节
        resp.extend_from_slice(&ip.octets());

        resp
    }

    /// 构造空的 NOERROR 应答 (用于阻断 IPv6 AAAA 查询，防止 IPv6 泄露)
    pub fn build_empty_response(tx_id: u16, original_query: &[u8], question_len: usize) -> Vec<u8> {
        let mut resp = Vec::with_capacity(question_len);
        resp.extend_from_slice(&tx_id.to_be_bytes());
        resp.extend_from_slice(&[0x81, 0x80]);
        // ANCOUNT=0
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        if question_len > 12 && question_len <= original_query.len() {
            resp.extend_from_slice(&original_query[12..question_len]);
        }
        resp
    }
}

/// 本地 DNS 拦截处理服务
pub struct DnsServer {
    pub bind_addr: SocketAddr,
    pub pool: Arc<FakeIpPool>,
    pub upstream_dns: SocketAddr,
    pub block_ipv6: bool,
}

impl DnsServer {
    pub fn new(
        bind_addr: SocketAddr,
        pool: Arc<FakeIpPool>,
        upstream_dns: SocketAddr,
        block_ipv6: bool,
    ) -> Self {
        Self {
            bind_addr,
            pool,
            upstream_dns,
            block_ipv6,
        }
    }

    /// 同步绑定套接字（Fail-Fast 检查端口占用）
    pub async fn bind(&self) -> Result<Arc<UdpSocket>> {
        let socket = UdpSocket::bind(self.bind_addr)
            .await
            .with_context(|| format!("绑定 DNS 服务套接字失败 ({})", self.bind_addr))?;
        info!("[DNS 引擎] 本地 DNS 劫持与防泄漏服务已在 {} 绑定", self.bind_addr);
        Ok(Arc::new(socket))
    }

    /// 启动异步 UDP DNS 监听循环（支持优雅停机与多任务并发）
    pub async fn run(&self, socket: Arc<UdpSocket>, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        let mut buf = [0u8; 1500];
        loop {
            let (len, peer) = tokio::select! {
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok(r) => r,
                        Err(e) => {
                            error!("[DNS 引擎] 接收 UDP DNS 数据包失败: {}", e);
                            continue;
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    info!("[DNS 引擎] 接收到退出信号，安全停止 DNS 监听");
                    break;
                }
            };

            let query_bytes = buf[..len].to_vec();
            let socket_clone = socket.clone();
            let pool_clone = self.pool.clone();
            let upstream_dns = self.upstream_dns;
            let block_ipv6 = self.block_ipv6;

            tokio::spawn(async move {
                match DnsPacketParser::parse_question(&query_bytes) {
                    Ok((tx_id, question)) => {
                        debug!(
                            "[DNS 查询] 来源: {}, 域名: {}, QType: {}",
                            peer, question.name, question.qtype
                        );

                        // 1. 若为 AAAA (IPv6) 且开启了防泄露，直接返回空应答
                        if question.qtype == 28 && block_ipv6 {
                            let empty_resp = DnsPacketParser::build_empty_response(
                                tx_id,
                                &query_bytes,
                                question.raw_len,
                            );
                            let _ = socket_clone.send_to(&empty_resp, peer).await;
                            return;
                        }

                        // 2. 若为 A (IPv4) 查询，分配 Fake-IP 并应答
                        if question.qtype == 1 {
                            let fake_ip = pool_clone.allocate(&question.name);
                            let resp = DnsPacketParser::build_a_response(
                                tx_id,
                                &query_bytes,
                                question.raw_len,
                                fake_ip,
                            );
                            let _ = socket_clone.send_to(&resp, peer).await;
                            return;
                        }

                        // 3. 其它类型查询转向上游 DNS 进行代理解析（异步并发，不阻塞主循环）
                        if let Ok(upstream_socket) = UdpSocket::bind("0.0.0.0:0").await {
                            let _ = upstream_socket.send_to(&query_bytes, upstream_dns).await;
                            let mut upstream_buf = [0u8; 1500];
                            if let Ok(Ok(n)) = tokio::time::timeout(
                                std::time::Duration::from_secs(2),
                                upstream_socket.recv(&mut upstream_buf),
                            )
                            .await
                            {
                                let _ = socket_clone.send_to(&upstream_buf[..n], peer).await;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[DNS 引擎] 解析 DNS 请求报文失败: {}", e);
                    }
                }
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_and_build_dns_response() {
        let mut sample_query = Vec::new();
        sample_query.extend_from_slice(&[0x12, 0x34]); // TX ID: 0x1234
        sample_query.extend_from_slice(&[0x01, 0x00]); // Standard query (RD=1, QR=0, Opcode=0)
        sample_query.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // QD=1
        sample_query.extend_from_slice(&[7]);
        sample_query.extend_from_slice(b"example");
        sample_query.extend_from_slice(&[3]);
        sample_query.extend_from_slice(b"com");
        sample_query.push(0);
        sample_query.extend_from_slice(&[0x00, 0x01]); // QTYPE: A (1)
        sample_query.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN (1)

        let (tx_id, question) = DnsPacketParser::parse_question(&sample_query).unwrap();
        assert_eq!(tx_id, 0x1234);
        assert_eq!(question.name, "example.com");
        assert_eq!(question.qtype, 1);

        let fake_ip = Ipv4Addr::new(198, 18, 0, 10);
        let resp = DnsPacketParser::build_a_response(tx_id, &sample_query, question.raw_len, fake_ip);

        // 校验响应头
        assert_eq!(resp[0..2], [0x12, 0x34]);
        assert_eq!(resp[2..4], [0x81, 0x80]);
        assert_eq!(resp[6..8], [0x00, 0x01]);
        assert_eq!(&resp[resp.len() - 4..], &[198, 18, 0, 10]);
    }

    #[test]
    fn test_parse_dns_rejection() {
        let mut query = vec![0x12, 0x34, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        query.extend_from_slice(&[3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        assert!(DnsPacketParser::parse_question(&query).is_err());

        let mut query_long = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        query_long.push(64);
        query_long.extend_from_slice(&[b'a'; 64]);
        query_long.push(0);
        query_long.extend_from_slice(&[0, 1, 0, 1]);
        assert!(DnsPacketParser::parse_question(&query_long).is_err());
    }
}
