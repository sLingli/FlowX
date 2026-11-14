use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use anyhow::{bail, Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{watch, Semaphore};
use tracing::{debug, error, info, warn};
use super::FakeIpPool;
use crate::monitor::InFlightTracker;

const MAX_DNS_UPSTREAM_CONCURRENCY: usize = 1024;
const UPSTREAM_DNS_TIMEOUT: Duration = Duration::from_secs(2);
static UPSTREAM_RESOLVE_SEMAPHORE: OnceLock<Semaphore> = OnceLock::new();

fn upstream_resolve_semaphore() -> &'static Semaphore {
    UPSTREAM_RESOLVE_SEMAPHORE.get_or_init(|| Semaphore::new(MAX_DNS_UPSTREAM_CONCURRENCY))
}

/// 极简、零外部依赖的 RFC 1035 DNS 报文解析与构造器
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,  // 1 = A, 28 = AAAA
    pub qclass: u16, // 1 = IN
    pub raw_len: usize,
}

pub struct DnsPacketParser;

fn is_valid_dns_label_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// 安全解码 DNS 报文中的域名（支持指针压缩，防越界与指针循环）
fn decode_dns_name(packet: &[u8], start: usize) -> Result<(String, usize)> {
    if start >= packet.len() {
        bail!("DNS domain offset exceeds packet length");
    }

    let mut offset = start;
    let mut next_offset: Option<usize> = None;
    let mut total_len = 0usize;
    let mut labels = Vec::new();
    let mut jumps = 0usize;

    loop {
        if offset >= packet.len() {
            bail!("DNS domain truncated before root label");
        }
        let len_byte = packet[offset];
        if len_byte == 0 {
            let end_pos = next_offset.unwrap_or(offset + 1);
            return Ok((labels.join("."), end_pos));
        }

        if (len_byte & 0xC0) == 0xC0 {
            if offset + 1 >= packet.len() {
                bail!("DNS compression pointer truncated");
            }
            let ptr = (((len_byte & 0x3F) as usize) << 8) | (packet[offset + 1] as usize);
            if ptr < 12 || ptr >= packet.len() {
                bail!("DNS compression pointer out of range: {}", ptr);
            }
            jumps += 1;
            if jumps > 32 {
                bail!("DNS compression pointer loop detected");
            }
            if next_offset.is_none() {
                next_offset = Some(offset + 2);
            }
            offset = ptr;
            continue;
        }

        if (len_byte & 0xC0) != 0 {
            bail!("Unsupported DNS label type flags: 0x{:02x}", len_byte);
        }

        let len = len_byte as usize;
        offset += 1;
        if len > 63 {
            bail!("DNS domain label exceeds 63 bytes: {}", len);
        }
        if offset + len > packet.len() {
            bail!("DNS domain label exceeds packet boundary");
        }
        total_len += len + 1;
        if total_len + 1 > 255 {
            bail!("DNS total domain length exceeds RFC 1035 limit");
        }

        let raw_label = &packet[offset..offset + len];
        if !raw_label.iter().all(|b| is_valid_dns_label_byte(*b)) {
            bail!("DNS domain label contains invalid or non-ASCII bytes");
        }
        let label = std::str::from_utf8(raw_label)?;
        labels.push(label.to_string());
        offset += len;
    }
}

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
        if qdcount != 1 {
            bail!("DNS query must contain exactly 1 Question entry (got {})", qdcount);
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
            if total_domain_len + 1 > 255 {
                bail!("DNS total domain length exceeds RFC 1035 limit of 253 bytes");
            }
            let raw_label = &buf[offset..offset + len];
            if !raw_label.iter().all(|b| is_valid_dns_label_byte(*b)) {
                bail!("DNS domain label contains invalid or non-ASCII characters");
            }
            let label = std::str::from_utf8(raw_label)
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
    upstream_limit: Arc<Semaphore>,
    in_flight: Option<Arc<InFlightTracker>>,
}

/// 规范化套接字地址，避免双栈环境下的 IPv4-mapped IPv6 形式影响源地址核验
fn normalize_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::new(IpAddr::V4(v4), v6.port())
            } else {
                SocketAddr::V6(v6)
            }
        }
        v4 => v4,
    }
}

/// 使用系统级 CSPRNG 生成强随机 16 位事务 ID（用于上游 DNS 查询防欺骗）
pub(crate) fn csprng_u16() -> u16 {
    let mut bytes = [0u8; 2];

    #[cfg(windows)]
    {
        use windows_sys::Win32::Security::Cryptography::{
            BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        };
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status == 0 {
            return u16::from_be_bytes(bytes);
        }
    }

    #[cfg(unix)]
    {
        use std::io::Read;
        use std::sync::OnceLock;
        static URANDOM: OnceLock<Option<std::fs::File>> = OnceLock::new();
        if let Some(mut f) = URANDOM
            .get_or_init(|| std::fs::File::open("/dev/urandom").ok())
            .as_ref()
            && f.read_exact(&mut bytes).is_ok()
        {
            return u16::from_be_bytes(bytes);
        }
    }

    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let h = RandomState::new().build_hasher().finish();
    ((h ^ (h >> 16) ^ (h >> 32)) & 0xFFFF) as u16
}

/// 严格校验上游 DNS 响应头部、QR=1、TxID 以及 Question 元组一致性
fn validate_upstream_dns_response(
    expected_tx_id: u16,
    expected_question: &DnsQuestion,
    resp: &[u8],
) -> Result<usize> {
    if resp.len() < 12 {
        bail!("Upstream DNS response shorter than 12 bytes header");
    }
    let resp_tx_id = u16::from_be_bytes([resp[0], resp[1]]);
    if resp_tx_id != expected_tx_id {
        bail!("Upstream DNS TxID mismatch");
    }
    if (resp[2] & 0x80) == 0 {
        bail!("Upstream DNS packet missing QR=1 response bit");
    }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]);
    if qdcount < 1 {
        bail!("Upstream DNS response missing Question section");
    }

    let (qname, next_off) = decode_dns_name(resp, 12)?;
    if next_off + 4 > resp.len() {
        bail!("Upstream DNS response Question missing QTYPE/QCLASS");
    }
    let qtype = u16::from_be_bytes([resp[next_off], resp[next_off + 1]]);
    let qclass = u16::from_be_bytes([resp[next_off + 2], resp[next_off + 3]]);

    if !qname.eq_ignore_ascii_case(&expected_question.name)
        || qtype != expected_question.qtype
        || qclass != expected_question.qclass
    {
        bail!(
            "Upstream DNS response Question mismatch: got ({}, {}, {}), expected ({}, {}, {})",
            qname,
            qtype,
            qclass,
            expected_question.name,
            expected_question.qtype,
            expected_question.qclass
        );
    }

    Ok(next_off + 4)
}

/// 构造标准 DNS 查询报文
fn build_dns_query_packet(tx_id: u16, domain: &str, qtype: u16) -> Result<(Vec<u8>, DnsQuestion)> {
    let clean = domain.trim().trim_end_matches('.');
    if clean.is_empty() || clean.len() > 253 {
        bail!("Invalid domain length for DNS query: {:?}", domain);
    }
    let mut pkt = Vec::with_capacity(clean.len() + 18);
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00]); // Standard query, RD=1
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // QDCOUNT=1

    for label in clean.split('.') {
        if label.is_empty() || label.len() > 63 || !label.bytes().all(is_valid_dns_label_byte) {
            bail!("Invalid DNS query label: {:?}", label);
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS IN

    let q = DnsQuestion {
        name: clean.to_string(),
        qtype,
        qclass: 1,
        raw_len: pkt.len(),
    };
    Ok((pkt, q))
}

/// 解析 DNS 应答中的 A / AAAA（跟踪 CNAME 链），并过滤任何 Fake-IP 防止自环路
fn parse_answer_ips(
    resp: &[u8],
    question: &DnsQuestion,
    first_answer_offset: usize,
    fake_ip_pool: Option<&FakeIpPool>,
) -> Result<Vec<IpAddr>> {
    let rcode = resp[3] & 0x0F;
    if rcode != 0 && rcode != 3 {
        bail!("Upstream DNS returned error RCODE={}", rcode);
    }

    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;

    // first_answer_offset 已经跳过第一个 Question；若还有额外 Question 继续跳过
    let mut offset = first_answer_offset;
    for _ in 1..qdcount {
        let (_, next) = decode_dns_name(resp, offset)?;
        if next + 4 > resp.len() {
            bail!("Upstream DNS extra Question truncated");
        }
        offset = next + 4;
    }

    let mut allowed_names: HashSet<String> = HashSet::new();
    allowed_names.insert(question.name.to_ascii_lowercase());
    let mut ips = Vec::new();

    for _ in 0..ancount {
        if offset >= resp.len() {
            break;
        }
        let (owner, next) = decode_dns_name(resp, offset)?;
        if next + 10 > resp.len() {
            bail!("Upstream DNS Answer RR header truncated");
        }
        let rtype = u16::from_be_bytes([resp[next], resp[next + 1]]);
        let rclass = u16::from_be_bytes([resp[next + 2], resp[next + 3]]);
        let rdlength = u16::from_be_bytes([resp[next + 8], resp[next + 9]]) as usize;
        let rdata_start = next + 10;
        let rdata_end = rdata_start + rdlength;
        if rdata_end > resp.len() {
            bail!("Upstream DNS Answer RDATA exceeds packet length");
        }

        let owner_lower = owner.to_ascii_lowercase();
        if rclass == 1 && allowed_names.contains(&owner_lower) {
            match rtype {
                5 => {
                    // CNAME
                    if let Ok((cname, _)) = decode_dns_name(resp, rdata_start) {
                        allowed_names.insert(cname.to_ascii_lowercase());
                    }
                }
                1 if rdlength == 4 => {
                    let v4 = Ipv4Addr::new(
                        resp[rdata_start],
                        resp[rdata_start + 1],
                        resp[rdata_start + 2],
                        resp[rdata_start + 3],
                    );
                    if fake_ip_pool.is_none_or(|p| !p.is_fake_ip_addr(IpAddr::V4(v4))) {
                        ips.push(IpAddr::V4(v4));
                    }
                }
                28 if rdlength == 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&resp[rdata_start..rdata_end]);
                    let v6 = Ipv6Addr::from(octets);
                    if fake_ip_pool.is_none_or(|p| !p.is_fake_ip_addr(IpAddr::V6(v6))) {
                        ips.push(IpAddr::V6(v6));
                    }
                }
                _ => {}
            }
        }
        offset = rdata_end;
    }

    Ok(ips)
}

async fn forward_upstream_udp(
    upstream_dns: SocketAddr,
    query_bytes: &[u8],
    tx_id: u16,
    question: &DnsQuestion,
    timeout: Duration,
) -> Result<Option<(Vec<u8>, usize)>> {
    let local_bind = if upstream_dns.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = crate::outbound::bypass::bind_udp_guarded(local_bind)
        .await
        .context("Failed to bind ephemeral upstream DNS socket")?;
    sock.send_to(query_bytes, upstream_dns)
        .await
        .context("Failed to send upstream DNS query")?;

    let expected_upstream = normalize_socket_addr(upstream_dns);
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        let rem = deadline - now;
        match tokio::time::timeout(rem, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, src_addr))) => {
                if normalize_socket_addr(src_addr) != expected_upstream {
                    warn!(
                        "[DNS Engine] Dropped response packet from unexpected upstream source {} (expected {})",
                        src_addr, expected_upstream
                    );
                    continue;
                }
                match validate_upstream_dns_response(tx_id, question, &buf[..n]) {
                    Ok(answer_off) => return Ok(Some((buf[..n].to_vec(), answer_off))),
                    Err(e) => {
                        debug!("[DNS Engine] Ignored invalid upstream packet from {}: {}", src_addr, e);
                        continue;
                    }
                }
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                debug!("[DNS Engine] Upstream UDP endpoint unreachable: {}", e);
                return Ok(None);
            }
            Ok(Err(e)) => {
                debug!("[DNS Engine] Upstream UDP receive error: {}", e);
                return Ok(None);
            }
            Err(_) => return Ok(None),
        }
    }
}

/// 显式经由上游 DNS 解析域名的 A + AAAA 记录（完全绕过 OS getaddrinfo 与 Fake-IP 冲突）
pub(crate) async fn resolve_via_upstream_dns(
    domain: &str,
    upstream_dns: SocketAddr,
    fake_ip_pool: Option<&FakeIpPool>,
    timeout: Duration,
) -> Result<Vec<IpAddr>> {
    resolve_via_upstream_dns_with_options(domain, upstream_dns, fake_ip_pool, timeout, true).await
}

pub(crate) async fn resolve_via_upstream_dns_with_options(
    domain: &str,
    upstream_dns: SocketAddr,
    fake_ip_pool: Option<&FakeIpPool>,
    timeout: Duration,
    include_ipv6: bool,
) -> Result<Vec<IpAddr>> {
    let deadline = tokio::time::Instant::now() + timeout;
    let _permit = tokio::time::timeout(timeout, upstream_resolve_semaphore().acquire())
        .await
        .map_err(|_| anyhow::anyhow!("Upstream DNS concurrency wait timed out for {}", domain))?
        .context("Upstream DNS semaphore closed")?;

    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        bail!("Upstream DNS resolution timed out for {}", domain);
    }

    let tx_a = csprng_u16();
    let (pkt_a, q_a) = build_dns_query_packet(tx_a, domain, 1)?;

    let mut responses = Vec::with_capacity(if include_ipv6 { 2 } else { 1 });
    if include_ipv6 {
        let tx_aaaa = csprng_u16();
        let (pkt_aaaa, q_aaaa) = build_dns_query_packet(tx_aaaa, domain, 28)?;
        let (res_a, res_aaaa) = tokio::join!(
            forward_upstream_udp(upstream_dns, &pkt_a, tx_a, &q_a, remaining),
            forward_upstream_udp(upstream_dns, &pkt_aaaa, tx_aaaa, &q_aaaa, remaining),
        );
        responses.push((res_a, q_a));
        responses.push((res_aaaa, q_aaaa));
    } else {
        let res_a = forward_upstream_udp(upstream_dns, &pkt_a, tx_a, &q_a, remaining).await;
        responses.push((res_a, q_a));
    }

    let mut ips = Vec::new();
    let mut got_response = false;
    let mut last_err: Option<anyhow::Error> = None;

    for (res, q) in &responses {
        match res {
            Ok(Some((resp, ans_off))) => {
                got_response = true;
                match parse_answer_ips(resp, q, *ans_off, fake_ip_pool) {
                    Ok(parsed) => {
                        for ip in parsed {
                            if !ips.contains(&ip) {
                                ips.push(ip);
                            }
                        }
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            Ok(None) => {}
            Err(e) => last_err = Some(anyhow::anyhow!("{:#}", e)),
        }
    }

    if !ips.is_empty() {
        return Ok(ips);
    }
    if let Some(err) = last_err {
        return Err(err);
    }
    if !got_response {
        bail!("Upstream DNS resolution timed out for {}", domain);
    }
    bail!("No usable IP records returned by upstream DNS for {}", domain)
}

fn is_transient_udp_recv_error(err: &std::io::Error) -> bool {
    if matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::Interrupted
    ) {
        return true;
    }
    #[cfg(windows)]
    if err.raw_os_error() == Some(10040) {
        // WSAEMSGSIZE: UDP datagram truncated by socket receive buffer
        return true;
    }
    #[cfg(unix)]
    if err.raw_os_error() == Some(libc::EMSGSIZE) {
        return true;
    }
    false
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
            upstream_limit: Arc::new(Semaphore::new(MAX_DNS_UPSTREAM_CONCURRENCY)),
            in_flight: None,
        }
    }

    pub fn with_in_flight(mut self, tracker: Arc<InFlightTracker>) -> Self {
        self.in_flight = Some(tracker);
        self
    }

    /// Synchronously bind socket (Fail-Fast port check)
    pub async fn bind(&self) -> Result<Arc<UdpSocket>> {
        let socket = UdpSocket::bind(self.bind_addr)
            .await
            .with_context(|| format!("Failed to bind DNS server socket ({})", self.bind_addr))?;
        info!("[DNS Engine] Local DNS hijack and leak-prevention service bound on {}", self.bind_addr);
        Ok(Arc::new(socket))
    }

    /// Run asynchronous UDP DNS listener loop (supports graceful shutdown, concurrency limit, and ephemeral upstream isolation)
    pub async fn run(&self, socket: Arc<UdpSocket>, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        let mut buf = vec![0u8; 4096];
        let mut transient_err_streak: u32 = 0;

        loop {
            if *shutdown_rx.borrow() {
                info!("[DNS Engine] Shutdown signal already set, stopping DNS listener");
                break;
            }
            let (len, peer) = tokio::select! {
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok(r) => {
                            transient_err_streak = 0;
                            r
                        }
                        Err(e) if is_transient_udp_recv_error(&e) => {
                            // Windows returns WSAECONNRESET when a local UDP peer closes early after querying;
                            // exempt transient socket errors from backoff so throughput is not capped at ~20 qps,
                            // while yielding periodically during burst transient errors to prevent executor spin.
                            transient_err_streak = transient_err_streak.saturating_add(1);
                            debug!("[DNS Engine] Transient UDP receive error ignored: {}", e);
                            if transient_err_streak.is_multiple_of(16) {
                                tokio::task::yield_now().await;
                            }
                            continue;
                        }
                        Err(e) => {
                            transient_err_streak = 0;
                            error!("[DNS Engine] Failed to receive UDP DNS packet: {}", e);
                            tokio::select! {
                                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                                _ = shutdown_rx.changed() => break,
                            }
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
            let upstream_limit = Arc::clone(&self.upstream_limit);
            let _in_flight = self.in_flight.as_ref().map(|t| t.enter());

            tokio::spawn(async move {
                let _permit = permit;
                let _in_flight = _in_flight;
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

                        // 3. Forward other queries to upstream DNS via per-query ephemeral UDP socket & CSPRNG TxID
                        let Ok(_up_permit) = upstream_limit.try_acquire_owned() else {
                            warn!("[DNS Engine] Upstream forwarding limit reached, dropping query: {}", question.name);
                            return;
                        };
                        let upstream_tx_id = csprng_u16();
                        let mut forward_bytes = query_bytes;
                        forward_bytes[0..2].copy_from_slice(&upstream_tx_id.to_be_bytes());

                        if let Ok(Some((mut resp_bytes, _))) = forward_upstream_udp(
                            upstream_dns,
                            &forward_bytes,
                            upstream_tx_id,
                            &question,
                            UPSTREAM_DNS_TIMEOUT,
                        )
                        .await
                        {
                            resp_bytes[0..2].copy_from_slice(&client_tx_id.to_be_bytes());
                            let _ = socket_clone.send_to(&resp_bytes, peer).await;
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

        // P0-3 回归测试：包含非 ASCII UTF-8（如 "élocalhost"）的 DNS 查询必须在入口被拒绝
        let mut query_utf8 = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let utf8_label = "élocalhost".as_bytes();
        query_utf8.push(utf8_label.len() as u8);
        query_utf8.extend_from_slice(utf8_label);
        query_utf8.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert!(DnsPacketParser::parse_question(&query_utf8).is_err());

        // P2-3: RFC 1035 total wire limit includes terminating 0x00 root byte (253 chars == 254 pre-root wire bytes == 255 total)
        let max_valid = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(max_valid.len(), 253);
        let (pkt_valid, q_valid) = build_dns_query_packet(0x4242, &max_valid, 1).unwrap();
        assert_eq!(q_valid.name, max_valid);
        assert!(DnsPacketParser::parse_question(&pkt_valid).is_ok());
        assert_eq!(decode_dns_name(&pkt_valid, 12).unwrap().0, max_valid);

        let over_domain = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
        assert_eq!(over_domain.len(), 254);
        assert!(build_dns_query_packet(0x4243, &over_domain, 1).is_err());
        let mut wire_over = vec![0x42, 0x43, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        for label in over_domain.split('.') {
            wire_over.push(label.len() as u8);
            wire_over.extend_from_slice(label.as_bytes());
        }
        wire_over.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert!(DnsPacketParser::parse_question(&wire_over).is_err());
        assert!(decode_dns_name(&wire_over, 12).is_err());
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

    /// P0-2 / P1-5 Regression Test: Concurrent upstream queries use isolated ephemeral sockets & strict QR/Question/TxID/source validation
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

                assert_ne!(src1.port(), src2.port(), "Each forwarded query should bind an isolated ephemeral source port");

                // 1. 错误源地址伪造包应被丢弃
                let mut spoof_resp = buf1[..n1].to_vec();
                spoof_resp[2] = 0x81;
                spoof_resp[3] = 0x80;
                spoof_resp.extend_from_slice(b"SPOOFED");
                let _ = spoof_socket.send_to(&spoof_resp, src1).await;

                // 2. 来自真实上游 IP 但缺少 QR=1 位（反射查询）与 Question 不一致的假包也应被忽略
                let mut qr0_resp = buf1[..n1].to_vec();
                qr0_resp[2] = 0x01; // QR=0
                qr0_resp.extend_from_slice(b"SPOOFED");
                let _ = mock_upstream.send_to(&qr0_resp, src1).await;

                let mut wrong_q_resp = build_sample_query(
                    u16::from_be_bytes([buf1[0], buf1[1]]),
                    "wrong.example",
                    16,
                );
                wrong_q_resp[2] = 0x81;
                wrong_q_resp.extend_from_slice(b"SPOOFED");
                let _ = mock_upstream.send_to(&wrong_q_resp, src1).await;

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

    #[tokio::test]
    async fn test_resolve_via_upstream_dns_follows_cname_and_filters_fake_ip() {
        let mock_upstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let upstream_addr = mock_upstream.local_addr().unwrap();

        let up_task = {
            let mock_upstream = Arc::clone(&mock_upstream);
            tokio::spawn(async move {
                for _ in 0..2 {
                    let mut buf = [0u8; 512];
                    let (n, src) = mock_upstream.recv_from(&mut buf).await.unwrap();
                    let (tx, q) = DnsPacketParser::parse_question(&buf[..n]).unwrap();
                    let mut resp = Vec::new();
                    resp.extend_from_slice(&tx.to_be_bytes());
                    resp.extend_from_slice(&[0x81, 0x80]);
                    if q.qtype == 1 {
                        // QD=1, AN=3: CNAME -> Fake-IP (filtered) + Real IP 93.184.216.34
                        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00]);
                        resp.extend_from_slice(&buf[12..q.raw_len]);
                        // Answer 1: CNAME alias.example
                        resp.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0, 0, 0, 60]);
                        let alias = [5u8, b'a', b'l', b'i', b'a', b's', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0];
                        resp.extend_from_slice(&(alias.len() as u16).to_be_bytes());
                        let alias_offset = resp.len() as u16;
                        resp.extend_from_slice(&alias);
                        let ptr_alias = (0xC000u16 | alias_offset).to_be_bytes();
                        // Answer 2: Fake-IP 198.18.0.55 (should be dropped)
                        resp.extend_from_slice(&ptr_alias);
                        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0, 0, 0, 10, 0, 4, 198, 18, 0, 55]);
                        // Answer 3: Real IP 93.184.216.34
                        resp.extend_from_slice(&ptr_alias);
                        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
                    } else {
                        // AAAA empty NOERROR
                        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                        resp.extend_from_slice(&buf[12..q.raw_len]);
                    }
                    mock_upstream.send_to(&resp, src).await.unwrap();
                }
            })
        };

        let pool = FakeIpPool::new_default();
        let ips = resolve_via_upstream_dns(
            "cdn.example",
            upstream_addr,
            Some(&pool),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        up_task.await.unwrap();

        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
    }

    #[test]
    fn test_transient_udp_recv_error_classification() {
        use std::io::{Error, ErrorKind};
        assert!(is_transient_udp_recv_error(&Error::from(ErrorKind::ConnectionReset)));
        assert!(is_transient_udp_recv_error(&Error::from(ErrorKind::WouldBlock)));
        assert!(is_transient_udp_recv_error(&Error::from(ErrorKind::Interrupted)));
        #[cfg(windows)]
        assert!(is_transient_udp_recv_error(&Error::from_raw_os_error(10040)));
        #[cfg(unix)]
        assert!(is_transient_udp_recv_error(&Error::from_raw_os_error(libc::EMSGSIZE)));
        assert!(!is_transient_udp_recv_error(&Error::from(ErrorKind::PermissionDenied)));
        assert!(!is_transient_udp_recv_error(&Error::from(ErrorKind::InvalidInput)));
    }

    #[tokio::test]
    async fn test_dns_server_fast_burst_with_dropped_peers() {
        let pool = Arc::new(FakeIpPool::new_default());
        let server = DnsServer::new(
            "127.0.0.1:0".parse().unwrap(),
            Arc::clone(&pool),
            "127.0.0.1:53".parse().unwrap(),
            true,
        );
        let socket = server.bind().await.unwrap();
        let dns_addr = socket.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        let srv_handle = tokio::spawn(async move {
            let _ = server.run(socket, rx).await;
        });

        // Fire 20 queries from ephemeral sockets that immediately close before receiving reply,
        // which triggers WSAECONNRESET on Windows when send_to lands after socket closure.
        for i in 0..20u16 {
            let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let q = build_sample_query(0x3000 + i, &format!("drop{}.example.com", i), 1);
            c.send_to(&q, dns_addr).await.unwrap();
            drop(c);
        }

        // Subsequent queries must still complete well under 250ms total (no 50ms-per-reset stall).
        let started = std::time::Instant::now();
        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for i in 0..5u16 {
            let q = build_sample_query(0x4000 + i, &format!("ok{}.example.com", i), 1);
            c.send_to(&q, dns_addr).await.unwrap();
            let mut resp = [0u8; 512];
            let (n, _) = tokio::time::timeout(Duration::from_millis(200), c.recv_from(&mut resp))
                .await
                .expect("DNS response timed out after peer resets")
                .unwrap();
            assert_eq!(&resp[0..2], &(0x4000 + i).to_be_bytes());
            assert!(n > 12);
        }
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "Queries took too long ({:?}), transient error backoff leaked",
            started.elapsed()
        );

        let _ = tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), srv_handle).await;
    }

    #[tokio::test]
    async fn test_resolve_via_upstream_dns_skips_aaaa_when_ipv6_blocked() {
        let mock_upstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let upstream_addr = mock_upstream.local_addr().unwrap();

        let up_task = {
            let mock_upstream = Arc::clone(&mock_upstream);
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let (n, src) = mock_upstream.recv_from(&mut buf).await.unwrap();
                let (tx, q) = DnsPacketParser::parse_question(&buf[..n]).unwrap();
                assert_eq!(q.qtype, 1, "Only A query expected when include_ipv6=false");
                let mut resp = Vec::new();
                resp.extend_from_slice(&tx.to_be_bytes());
                resp.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
                resp.extend_from_slice(&buf[12..q.raw_len]);
                resp.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 30, 0, 4, 93, 184, 216, 34]);
                mock_upstream.send_to(&resp, src).await.unwrap();

                // Verify no second AAAA query arrives
                let extra = tokio::time::timeout(
                    Duration::from_millis(80),
                    mock_upstream.recv_from(&mut buf),
                )
                .await;
                assert!(extra.is_err(), "Unexpected extra DNS query when include_ipv6=false");
            })
        };

        let ips = resolve_via_upstream_dns_with_options(
            "v4only.example",
            upstream_addr,
            None,
            Duration::from_secs(2),
            false,
        )
        .await
        .unwrap();
        up_task.await.unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
    }
}
