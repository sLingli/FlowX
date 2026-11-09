use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use anyhow::{bail, Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, watch, Semaphore};
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
            bail!("DNS packet too short (less than 12 bytes header)");
        }

        // Check QR flag: byte 2 bit 7 must be 0 (Query)
        if (buf[2] & 0x80) != 0 {
            bail!("DNS packet is not a standard query (QR != 0)");
        }

        // Check Opcode: byte 2 bits 3-6 must be 0 (Standard Query)
        let opcode = (buf[2] >> 3) & 0x0F;
        if opcode != 0 {
            bail!("Unsupported DNS opcode (Opcode != 0): {}", opcode);
        }

        let tx_id = u16::from_be_bytes([buf[0], buf[1]]);
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
        if qdcount == 0 {
            bail!("DNS query does not contain any Question entries");
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
                bail!("DNS query domain contains unsupported compressed pointer label");
            }
            if len > 63 {
                bail!("DNS domain label length exceeds RFC 1035 limit of 63 bytes: {}", len);
            }
            if offset + len > buf.len() {
                bail!("DNS domain label length exceeds packet boundary");
            }
            total_domain_len += len + 1;
            if total_domain_len > 255 {
                bail!("DNS total domain length exceeds RFC 1035 limit of 253 bytes");
            }
            let label = std::str::from_utf8(&buf[offset..offset + len])
                .context("DNS domain contains non-UTF-8 characters")?;
            domain_parts.push(label.to_string());
            offset += len;
        }

        if !terminated {
            bail!("DNS domain parsing did not terminate with root null label (0x00)");
        }

        if offset + 4 > buf.len() {
            bail!("DNS Question missing QTYPE or QCLASS fields");
        }

        let qtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let qclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        let raw_len = offset + 4;

        let name = domain_parts.join(".");
        if name.is_empty() {
            bail!("DNS query domain is empty (Root Query)");
        }

        Ok((
            tx_id,
            DnsQuestion {
                name,
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

    /// 构造空的 NOERROR 应答 (用于阻断 IPv6 AAAA 及现代浏览器 HTTPS/SVCB 记录，防止 DNS 泄露与 Fake-IP 绕过)
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
    concurrency_limit: Arc<Semaphore>,
}

/// 规范化套接字地址，避免双栈环境下的 IPv4-mapped IPv6 形式影响源地址核验
fn normalize_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::new(std::net::IpAddr::V4(v4), v6.port())
            } else {
                SocketAddr::V6(v6)
            }
        }
        v4 => v4,
    }
}

/// 从 OS CSPRNG 种子随机挑选未占用的 16 位内部事务 ID，避免不同客户端 TxID 冲突串包
fn allocate_internal_tx_id(
    pending: &Mutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>,
    sender: oneshot::Sender<Vec<u8>>,
) -> Option<u16> {
    use std::collections::hash_map::{Entry, RandomState};
    use std::hash::{BuildHasher, Hasher};

    let seed = RandomState::new().build_hasher().finish();
    let start = ((seed ^ (seed >> 16) ^ (seed >> 32)) & 0xFFFF) as u16;
    let mut guard = pending.lock().unwrap_or_else(|e| e.into_inner());
    for offset in 0..=u16::MAX {
        let candidate = start.wrapping_add(offset);
        if let Entry::Vacant(entry) = guard.entry(candidate) {
            entry.insert(sender);
            return Some(candidate);
        }
    }
    None
}

/// RAII 守卫：在超时、发送失败或任务取消时自动回收挂起的内部事务 ID
struct PendingQueryGuard {
    tx_id: u16,
    pending: Arc<Mutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>>,
    active: bool,
}

impl PendingQueryGuard {
    fn new(tx_id: u16, pending: Arc<Mutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>>) -> Self {
        Self {
            tx_id,
            pending,
            active: true,
        }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for PendingQueryGuard {
    fn drop(&mut self) {
        if self.active {
            self.pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&self.tx_id);
        }
    }
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
            concurrency_limit: Arc::new(Semaphore::new(5000)),
        }
    }

    /// Synchronously bind socket (Fail-Fast port check)
    pub async fn bind(&self) -> Result<Arc<UdpSocket>> {
        let socket = UdpSocket::bind(self.bind_addr)
            .await
            .with_context(|| format!("Failed to bind DNS server socket ({})", self.bind_addr))?;
        info!("[DNS Engine] Local DNS hijack and leak-prevention service bound on {}", self.bind_addr);
        Ok(Arc::new(socket))
    }

    /// Run asynchronous UDP DNS listener loop (supports graceful shutdown, concurrency limit, and upstream multiplexing)
    pub async fn run(&self, socket: Arc<UdpSocket>, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        let mut buf = [0u8; 1500];

        // Bind single multiplexed upstream DNS client socket matching address family
        let upstream_bind = if self.upstream_dns.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let upstream_client = Arc::new(
            UdpSocket::bind(upstream_bind)
                .await
                .context("Failed to bind upstream DNS client socket")?,
        );
        let pending_queries: Arc<Mutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Start background upstream DNS response multiplexing receiver loop
        let uc = Arc::clone(&upstream_client);
        let pq = Arc::clone(&pending_queries);
        let expected_upstream = normalize_socket_addr(self.upstream_dns);
        let mut shutdown_rx_upstream = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut up_buf = [0u8; 1500];
            loop {
                tokio::select! {
                    res = uc.recv_from(&mut up_buf) => {
                        match res {
                            Ok((n, src_addr)) if n >= 2 => {
                                if normalize_socket_addr(src_addr) != expected_upstream {
                                    warn!(
                                        "[DNS Engine] Dropped response packet from unexpected upstream source address {} (expected {})",
                                        src_addr, expected_upstream
                                    );
                                    continue;
                                }
                                let internal_id = u16::from_be_bytes([up_buf[0], up_buf[1]]);
                                let sender = pq
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .remove(&internal_id);
                                if let Some(sender) = sender {
                                    let _ = sender.send(up_buf[..n].to_vec());
                                }
                            }
                            Ok(_) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                                debug!("[DNS Engine] Upstream UDP endpoint temporarily unreachable: {}", e);
                            }
                            Err(e) => {
                                error!("[DNS Engine] Upstream response receive error: {}", e);
                                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                            }
                        }
                    }
                    _ = shutdown_rx_upstream.changed() => break,
                }
            }
        });

        loop {
            let (len, peer) = tokio::select! {
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok(r) => r,
                        Err(e) => {
                            error!("[DNS Engine] Failed to receive UDP DNS packet: {}", e);
                            continue;
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    info!("[DNS Engine] Shutdown signal received, stopping DNS listener");
                    break;
                }
            };

            let permit = match self.concurrency_limit.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!("[DNS Engine] Dropped DNS query exceeding concurrency limit (5000)");
                    continue;
                }
            };

            let query_bytes = buf[..len].to_vec();
            let socket_clone = socket.clone();
            let pool_clone = self.pool.clone();
            let upstream_dns = self.upstream_dns;
            let block_ipv6 = self.block_ipv6;
            let uc_clone = Arc::clone(&upstream_client);
            let pq_clone = Arc::clone(&pending_queries);

            tokio::spawn(async move {
                let _permit = permit;
                match DnsPacketParser::parse_question(&query_bytes) {
                    Ok((client_tx_id, question)) => {
                        debug!(
                            "[DNS Query] Client: {}, Domain: {}, QType: {}",
                            peer, question.name, question.qtype
                        );

                        // 1. In anti-leak mode, block AAAA (28), SVCB (64), and HTTPS (65) queries
                        if block_ipv6 && matches!(question.qtype, 28 | 64 | 65) {
                            let empty_resp = DnsPacketParser::build_empty_response(
                                client_tx_id,
                                &query_bytes,
                                question.raw_len,
                            );
                            let _ = socket_clone.send_to(&empty_resp, peer).await;
                            return;
                        }

                        // 2. For A (IPv4) queries, allocate Fake-IP and respond
                        if question.qtype == 1 && question.qclass == 1 {
                            let fake_ip = pool_clone.allocate(&question.name);
                            let resp = DnsPacketParser::build_a_response(
                                client_tx_id,
                                &query_bytes,
                                question.raw_len,
                                fake_ip,
                            );
                            let _ = socket_clone.send_to(&resp, peer).await;
                            return;
                        }

                        // 3. Forward other queries to upstream DNS with isolated internal TxID
                        let (tx, rx) = oneshot::channel();
                        let Some(internal_tx_id) = allocate_internal_tx_id(&pq_clone, tx) else {
                            warn!("[DNS Engine] Upstream transaction ID mapping table full, dropping query: {}", question.name);
                            return;
                        };
                        let mut pending_guard = PendingQueryGuard::new(internal_tx_id, Arc::clone(&pq_clone));
                        let mut forward_bytes = query_bytes;
                        forward_bytes[0..2].copy_from_slice(&internal_tx_id.to_be_bytes());

                        if uc_clone.send_to(&forward_bytes, upstream_dns).await.is_ok()
                            && let Ok(Ok(mut resp_bytes)) =
                                tokio::time::timeout(std::time::Duration::from_secs(2), rx).await
                        {
                            pending_guard.disarm();
                            if resp_bytes.len() >= 2 {
                                resp_bytes[0..2].copy_from_slice(&client_tx_id.to_be_bytes());
                                let _ = socket_clone.send_to(&resp_bytes, peer).await;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("[DNS Engine] Failed to parse DNS query packet: {}", e);
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

    fn build_sample_query(tx_id: u16, domain: &str, qtype: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&tx_id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00]); // Standard query, RD=1
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // QD=1
        for label in domain.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0x00, 0x01]); // IN
        q
    }

    #[test]
    fn test_parse_and_build_dns_response() {
        let sample_query = build_sample_query(0x1234, "example.com", 1);

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

        // 测试空域名 (Root Query) 被拒绝
        let query_empty = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0, 0, 1, 0, 1];
        assert!(DnsPacketParser::parse_question(&query_empty).is_err());
    }

    /// P0-3 回归测试：开启防泄露模式下，AAAA (28)、SVCB (64) 与 HTTPS (65) 均返回空应答且不泄露给上游 DNS
    #[tokio::test]
    async fn test_dns_blocks_https_svcb_and_aaaa_queries() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mock_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = mock_upstream.local_addr().unwrap();
        let upstream_hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = Arc::clone(&upstream_hits);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while mock_upstream.recv_from(&mut buf).await.is_ok() {
                hits_clone.fetch_add(1, Ordering::Relaxed);
            }
        });

        let pool = Arc::new(FakeIpPool::new_default());
        let server = DnsServer::new("127.0.0.1:0".parse().unwrap(), pool, upstream_addr, true);
        let sock = server.bind().await.unwrap();
        let dns_addr = sock.local_addr().unwrap();
        let (_tx, rx) = watch::channel(false);
        tokio::spawn(async move { server.run(sock, rx).await });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for (idx, qtype) in [28u16, 64u16, 65u16].into_iter().enumerate() {
            let tx_id = 0x2000 + idx as u16;
            let q = build_sample_query(tx_id, "browser-hint.example", qtype);
            client.send_to(&q, dns_addr).await.unwrap();

            let mut resp = [0u8; 512];
            let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(1), client.recv_from(&mut resp))
                .await
                .unwrap()
                .unwrap();
            assert!(n >= 12);
            assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), tx_id);
            assert_eq!([resp[2], resp[3]], [0x81, 0x80]); // NOERROR
            assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0); // ANCOUNT=0
        }

        assert_eq!(upstream_hits.load(Ordering::Relaxed), 0, "SVCB/HTTPS/AAAA queries must not leak to public DNS");
    }

    /// P0-2 Regression Test: Concurrent upstream queries with same client TxID isolated by internal TxID, rejecting spoofed responses
    #[tokio::test]
    async fn test_dns_upstream_txid_isolation_and_source_verification() {
        let mock_upstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let upstream_addr = mock_upstream.local_addr().unwrap();
        let spoof_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mock_up_task = {
            let mock_upstream = Arc::clone(&mock_upstream);
            tokio::spawn(async move {
                let mut buf1 = [0u8; 512];
                let (n1, src1) = mock_upstream.recv_from(&mut buf1).await.unwrap();
                let mut buf2 = [0u8; 512];
                let (n2, src2) = mock_upstream.recv_from(&mut buf2).await.unwrap();

                let id1 = u16::from_be_bytes([buf1[0], buf1[1]]);
                let id2 = u16::from_be_bytes([buf2[0], buf2[1]]);
                assert_ne!(id1, id2, "Internal transaction IDs forwarded to upstream must be distinct even with identical client TxID");

                // 构造一个来自错误源地址的伪造响应（复刻 id1），应被接收器直接丢弃
                let mut spoof_resp = vec![0u8; n1];
                spoof_resp[..n1].copy_from_slice(&buf1[..n1]);
                spoof_resp[2] = 0x81;
                spoof_resp[3] = 0x80;
                spoof_resp.extend_from_slice(b"SPOOFED");
                let _ = spoof_socket.send_to(&spoof_resp, src1).await;

                let (_, q1) = DnsPacketParser::parse_question(&buf1[..n1]).unwrap();
                let (_, q2) = DnsPacketParser::parse_question(&buf2[..n2]).unwrap();
                assert_ne!(q1.name, q2.name);

                let tag_for = |name: &str| -> &'static [u8] {
                    if name == "alpha.example" {
                        b"ANS-ALPHA"
                    } else {
                        b"ANS-BETA!"
                    }
                };

                // 先乱序回复第二个查询，再回复第一个查询，验证各自精准对应到原域名与原客户端
                let build_marked_resp = |req: &[u8], tag: &[u8]| {
                    let mut r = req.to_vec();
                    r[2] = 0x81;
                    r[3] = 0x80;
                    r.extend_from_slice(tag);
                    r
                };
                let resp2 = build_marked_resp(&buf2[..n2], tag_for(&q2.name));
                let resp1 = build_marked_resp(&buf1[..n1], tag_for(&q1.name));
                mock_upstream.send_to(&resp2, src2).await.unwrap();
                mock_upstream.send_to(&resp1, src1).await.unwrap();
            })
        };

        let pool = Arc::new(FakeIpPool::new_default());
        let server = DnsServer::new("127.0.0.1:0".parse().unwrap(), pool, upstream_addr, true);
        let sock = server.bind().await.unwrap();
        let dns_addr = sock.local_addr().unwrap();
        let (_tx, rx) = watch::channel(false);
        tokio::spawn(async move { server.run(sock, rx).await });

        let client1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // 两个独立客户端故意发送完全相同的客户端 TxID (0x1234)
        let q1 = build_sample_query(0x1234, "alpha.example", 16);
        let q2 = build_sample_query(0x1234, "beta.example", 16);
        client1.send_to(&q1, dns_addr).await.unwrap();
        client2.send_to(&q2, dns_addr).await.unwrap();

        let mut r1 = [0u8; 512];
        let mut r2 = [0u8; 512];
        let (res1, res2) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            async { tokio::join!(client1.recv_from(&mut r1), client2.recv_from(&mut r2)) },
        )
        .await
        .unwrap();
        let (len1, len2) = (res1.unwrap().0, res2.unwrap().0);

        mock_up_task.await.unwrap();

        assert_eq!(&r1[0..2], &[0x12, 0x34]);
        assert_eq!(&r2[0..2], &[0x12, 0x34]);
        let p1 = &r1[..len1];
        let p2 = &r2[..len2];
        assert!(!p1.windows(7).any(|w| w == b"SPOOFED"));
        assert!(!p2.windows(7).any(|w| w == b"SPOOFED"));
        assert!(p1.windows(9).any(|w| w == b"ANS-ALPHA"), "Client 1 must receive alpha response");
        assert!(!p1.windows(9).any(|w| w == b"ANS-BETA!"), "Client 1 must not receive beta response");
        assert!(p2.windows(9).any(|w| w == b"ANS-BETA!"), "Client 2 must receive beta response");
        assert!(!p2.windows(9).any(|w| w == b"ANS-ALPHA"), "Client 2 must not receive alpha response");
    }
}
