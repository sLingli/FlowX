use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use anyhow::{bail, Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{watch, Semaphore};
use tracing::{debug, error, info, warn};
use super::{canonicalize_socket_addr_preserving_scope, FakeIpPool};
use crate::monitor::InFlightTracker;

const MAX_DNS_UPSTREAM_CONCURRENCY: usize = 1024;
const UPSTREAM_DNS_TIMEOUT: Duration = Duration::from_secs(2);
/// 双栈并行查询（A + AAAA）中，当一族地址已返回可用 IP 或权威 NXDOMAIN 后，等待另一族的宽限窗口，
/// 避免丢弃 AAAA 的企业/路由器 DNS 将每次 Direct 建连拖满 1.5s~3s 超时。
const DUAL_STACK_SECOND_FAMILY_GRACE: Duration = Duration::from_millis(150);
const MAX_UDP_DNS_PACKET_LEN: usize = 65_535;
static UPSTREAM_RESOLVE_SEMAPHORE: OnceLock<Semaphore> = OnceLock::new();

/// 上游 DNS 明确返回权威 `NXDOMAIN` (`RCODE=3`) 时的类型化错误，
/// 供 `DirectOutbound` 识别并禁止将内网不存在主机名回退泄露至公网 `upstream_dns`。
#[derive(Debug, Clone)]
pub(crate) struct DnsNxDomainError {
    pub domain: String,
    pub server: SocketAddr,
}

impl std::fmt::Display for DnsNxDomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Upstream DNS {} returned NXDOMAIN for {}",
            self.server, self.domain
        )
    }
}

impl std::error::Error for DnsNxDomainError {}

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

/// 线协议级 DNS 名称解码器（支持指针压缩，防越界与指针循环）：
/// - `strict_hostname = true`：校验每个标签字符符合主机名子集（用于 Question 严格校验）；
/// - `strict_hostname = false`：兼容 Answer 段中可能出现的 `*`、`/`（如 RFC 2317 反向域或通配/DNS-SD 属主）等线协议标签，
///   避免单条无关 RR 属主字符触发错误而中断整包有效 IP 提取。
fn decode_dns_name_inner(packet: &[u8], start: usize, strict_hostname: bool) -> Result<(String, usize)> {
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
        if strict_hostname {
            if !raw_label.iter().all(|b| is_valid_dns_label_byte(*b)) {
                bail!("DNS domain label contains invalid or non-ASCII bytes");
            }
            let label = std::str::from_utf8(raw_label)?;
            labels.push(label.to_string());
        } else {
            labels.push(String::from_utf8_lossy(raw_label).into_owned());
        }
        offset += len;
    }
}

/// 安全解码 DNS 报文中的严格主机名（支持指针压缩，防越界与指针循环）
fn decode_dns_name(packet: &[u8], start: usize) -> Result<(String, usize)> {
    decode_dns_name_inner(packet, start, true)
}

/// 线协议级 DNS 名称解码（用于 Answer RR 属主与 CNAME 解码，容忍 `*`/`/` 等合法 DNS 标签字符）
fn decode_dns_name_wire(packet: &[u8], start: usize) -> Result<(String, usize)> {
    decode_dns_name_inner(packet, start, false)
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

/// 规范化套接字地址，避免双栈环境下的 IPv4-mapped IPv6 形式影响源地址核验，同时保留 IPv6 `scope_id`
fn normalize_socket_addr(addr: SocketAddr) -> SocketAddr {
    canonicalize_socket_addr_preserving_scope(addr)
}

/// 使用系统级 CSPRNG 生成强随机 16 位事务 ID（用于上游 DNS 查询防欺骗）
pub(crate) fn csprng_u16() -> u16 {
    let mut bytes = [0u8; 2];

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

/// 从 DNS 响应报文中快速窥探 `(tx_id, qname_lower, qtype, qclass)`（供被动入站响应观测器按五元组+TxID+QType 精确匹配）
pub(crate) fn peek_dns_response_key(resp: &[u8]) -> Option<(u16, String, u16, u16)> {
    if resp.len() < 12 || (resp[2] & 0x80) == 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]);
    if qdcount < 1 {
        return None;
    }
    let tx_id = u16::from_be_bytes([resp[0], resp[1]]);
    let (qname, next_off) = decode_dns_name(resp, 12).ok()?;
    if next_off + 4 > resp.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([resp[next_off], resp[next_off + 1]]);
    let qclass = u16::from_be_bytes([resp[next_off + 2], resp[next_off + 3]]);
    Some((tx_id, qname.to_ascii_lowercase(), qtype, qclass))
}

/// 严格校验并被动学习一条入站 DNS 响应中的 `real_ip -> domain` 映射（绝不修改或阻塞报文）
pub(crate) fn observe_passive_dns_response(
    pool: &FakeIpPool,
    expected_tx_id: u16,
    question: &DnsQuestion,
    resp_bytes: &[u8],
) -> bool {
    if !matches!(question.qtype, 1 | 28) || question.qclass != 1 {
        return false;
    }
    let Ok(ans_off) = validate_upstream_dns_response(expected_tx_id, question, resp_bytes) else {
        return false;
    };
    if (resp_bytes[3] & 0x0F) != 0 {
        return false;
    }
    if let Ok((ips, min_ttl)) =
        parse_answer_ips_with_ttl(resp_bytes, question, ans_off, Some(pool))
        && !ips.is_empty()
    {
        let ttl_hint = min_ttl.map(|s| Duration::from_secs(u64::from(s)));
        pool.record_real_ip_mappings_with_ttl(&question.name, &ips, ttl_hint);
        return true;
    }
    false
}

/// 解析 DNS 应答中的 A / AAAA（支持乱序与多跳 CNAME 链，计入链上 CNAME 最小 TTL，限定 RDATA 边界，并过滤任何 Fake-IP 防止自环路）
fn parse_answer_ips_with_ttl(
    resp: &[u8],
    question: &DnsQuestion,
    first_answer_offset: usize,
    fake_ip_pool: Option<&FakeIpPool>,
) -> Result<(Vec<IpAddr>, Option<u32>)> {
    let rcode = resp[3] & 0x0F;
    if rcode != 0 && rcode != 3 {
        bail!("Upstream DNS returned error RCODE={}", rcode);
    }

    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;

    // first_answer_offset 已经跳过第一个 Question；若还有额外 Question 继续跳过
    let mut offset = first_answer_offset;
    for _ in 1..qdcount {
        let (_, next) = decode_dns_name_wire(resp, offset)?;
        if next + 4 > resp.len() {
            bail!("Upstream DNS extra Question truncated");
        }
        offset = next + 4;
    }

    let mut cnames: Vec<(String, String, u32)> = Vec::new();
    let mut addr_records: Vec<(String, IpAddr, u32)> = Vec::new();

    for _ in 0..ancount {
        if offset >= resp.len() {
            break;
        }
        let (owner, next) = decode_dns_name_wire(resp, offset)?;
        if next + 10 > resp.len() {
            bail!("Upstream DNS Answer RR header truncated");
        }
        let rtype = u16::from_be_bytes([resp[next], resp[next + 1]]);
        let rclass = u16::from_be_bytes([resp[next + 2], resp[next + 3]]);
        let ttl_secs = u32::from_be_bytes([
            resp[next + 4],
            resp[next + 5],
            resp[next + 6],
            resp[next + 7],
        ]);
        let rdlength = u16::from_be_bytes([resp[next + 8], resp[next + 9]]) as usize;
        let rdata_start = next + 10;
        let rdata_end = rdata_start + rdlength;
        if rdata_end > resp.len() {
            bail!("Upstream DNS Answer RDATA exceeds packet length");
        }

        if rclass == 1 {
            let owner_lower = owner.to_ascii_lowercase();
            match rtype {
                5 => {
                    // CNAME：截断至 &resp[..rdata_end]，既允许合法前向压缩指针，又防止读取越过本 RR 的 RDATA 边界
                    if let Ok((cname, end_pos)) =
                        decode_dns_name_wire(&resp[..rdata_end], rdata_start)
                        && end_pos <= rdata_end
                        && !cname.is_empty()
                    {
                        cnames.push((owner_lower, cname.to_ascii_lowercase(), ttl_secs));
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
                        addr_records.push((owner_lower, IpAddr::V4(v4), ttl_secs));
                    }
                }
                28 if rdlength == 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&resp[rdata_start..rdata_end]);
                    let v6 = Ipv6Addr::from(octets);
                    if fake_ip_pool.is_none_or(|p| !p.is_fake_ip_addr(IpAddr::V6(v6))) {
                        addr_records.push((owner_lower, IpAddr::V6(v6), ttl_secs));
                    }
                }
                _ => {}
            }
        }
        offset = rdata_end;
    }

    // 两阶段解析：按不动点追踪任意顺序的 CNAME 链（免疫乱序 Answer 与 CNAME 环路），并准确计入链上 CNAME 最小 TTL
    let mut reachable: HashMap<String, Option<u32>> = HashMap::new();
    reachable.insert(question.name.to_ascii_lowercase(), None);
    for _ in 0..cnames.len() {
        let mut progressed = false;
        for (owner, target, cname_ttl) in &cnames {
            if let Some(&owner_cname_ttl) = reachable.get(owner) {
                let candidate_ttl = Some(owner_cname_ttl.map_or(*cname_ttl, |t| t.min(*cname_ttl)));
                match reachable.get(target) {
                    None => {
                        reachable.insert(target.clone(), candidate_ttl);
                        progressed = true;
                    }
                    Some(prev_ttl) => {
                        // 若另一路径给出了更保守的 CNAME TTL 则保留较小者（同时防止环路无限更新）
                        let merged = match (*prev_ttl, candidate_ttl) {
                            (Some(a), Some(b)) if b < a => Some(b),
                            _ => *prev_ttl,
                        };
                        if merged != *prev_ttl {
                            reachable.insert(target.clone(), merged);
                            progressed = true;
                        }
                    }
                }
            }
        }
        if !progressed {
            break;
        }
    }

    let mut ips = Vec::new();
    let mut min_ttl: Option<u32> = None;
    for (owner, ip, rr_ttl) in addr_records {
        if let Some(&chain_cname_ttl) = reachable.get(&owner) {
            ips.push(ip);
            let effective_ttl = chain_cname_ttl.map_or(rr_ttl, |c| c.min(rr_ttl));
            min_ttl = Some(min_ttl.map_or(effective_ttl, |cur| cur.min(effective_ttl)));
        }
    }

    Ok((ips, min_ttl))
}

/// 解析 DNS 应答中的 A / AAAA（跟踪 CNAME 链），并过滤任何 Fake-IP 防止自环路
fn parse_answer_ips(
    resp: &[u8],
    question: &DnsQuestion,
    first_answer_offset: usize,
    fake_ip_pool: Option<&FakeIpPool>,
) -> Result<Vec<IpAddr>> {
    parse_answer_ips_with_ttl(resp, question, first_answer_offset, fake_ip_pool)
        .map(|(ips, _)| ips)
}

async fn forward_upstream_udp(
    upstream_dns: SocketAddr,
    query_bytes: &[u8],
    tx_id: u16,
    question: &DnsQuestion,
    timeout: Duration,
) -> Result<Option<(Vec<u8>, usize)>> {
    // 先将 [::ffff:a.b.c.d]:53 规范化为原生 IPv4，保留纯 IPv6 的 scope_id，避免 Windows V6ONLY 套接字发包失败
    let upstream_dns = normalize_socket_addr(upstream_dns);
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

    let expected_upstream = upstream_dns;
    let mut buf = vec![0u8; MAX_UDP_DNS_PACKET_LEN];
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
                bail!(
                    "Upstream DNS endpoint {} unreachable (connection reset): {}",
                    upstream_dns,
                    e
                );
            }
            Ok(Err(e)) if is_transient_udp_recv_error(&e) => {
                debug!(
                    "[DNS Engine] Transient upstream UDP receive error from {} ignored: {}",
                    upstream_dns, e
                );
                tokio::task::yield_now().await;
                continue;
            }
            Ok(Err(e)) => {
                debug!("[DNS Engine] Upstream UDP receive error: {}", e);
                bail!("Upstream DNS {} UDP receive error: {}", upstream_dns, e);
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

struct ParsedFamilyOutcome {
    ips: Vec<IpAddr>,
    got_response: bool,
    saw_nxdomain: bool,
    saw_noerror: bool,
    err: Option<anyhow::Error>,
}

fn evaluate_family_response(
    res: Result<Option<(Vec<u8>, usize)>>,
    q: &DnsQuestion,
    fake_ip_pool: Option<&FakeIpPool>,
) -> ParsedFamilyOutcome {
    match res {
        Ok(Some((resp, ans_off))) => {
            let rcode = resp[3] & 0x0F;
            let saw_nxdomain = rcode == 3;
            let saw_noerror = rcode == 0;
            match parse_answer_ips(&resp, q, ans_off, fake_ip_pool) {
                Ok(parsed) => ParsedFamilyOutcome {
                    ips: parsed,
                    got_response: true,
                    saw_nxdomain,
                    saw_noerror,
                    err: None,
                },
                Err(e) => ParsedFamilyOutcome {
                    ips: Vec::new(),
                    got_response: true,
                    saw_nxdomain,
                    saw_noerror,
                    err: Some(e),
                },
            }
        }
        Ok(None) => ParsedFamilyOutcome {
            ips: Vec::new(),
            got_response: false,
            saw_nxdomain: false,
            saw_noerror: false,
            err: None,
        },
        Err(e) => ParsedFamilyOutcome {
            ips: Vec::new(),
            got_response: false,
            saw_nxdomain: false,
            saw_noerror: false,
            err: Some(e),
        },
    }
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
        bail!(
            "Upstream DNS resolution timed out for {} (server: {})",
            domain,
            upstream_dns
        );
    }

    let tx_a = csprng_u16();
    let (pkt_a, q_a) = build_dns_query_packet(tx_a, domain, 1)?;

    let (out_a, out_aaaa) = if include_ipv6 {
        let tx_aaaa = csprng_u16();
        let (pkt_aaaa, q_aaaa) = build_dns_query_packet(tx_aaaa, domain, 28)?;
        let fut_a = forward_upstream_udp(upstream_dns, &pkt_a, tx_a, &q_a, remaining);
        let fut_aaaa = forward_upstream_udp(upstream_dns, &pkt_aaaa, tx_aaaa, &q_aaaa, remaining);
        tokio::pin!(fut_a);
        tokio::pin!(fut_aaaa);

        // 先等任意一族返回；若已获有效 IP 或权威 NXDOMAIN，仅再给另一族短暂宽限窗口 (150ms)，
        // 避免企业/路由器 DNS 静默丢弃 AAAA 时把每次 Direct 建连拉满 1.5s~3s。
        tokio::select! {
            res_a = &mut fut_a => {
                let first = evaluate_family_response(res_a, &q_a, fake_ip_pool);
                let rem_now = deadline.saturating_duration_since(tokio::time::Instant::now());
                let wait_second = if !first.ips.is_empty() || first.saw_nxdomain {
                    DUAL_STACK_SECOND_FAMILY_GRACE.min(rem_now)
                } else {
                    rem_now
                };
                let second = if wait_second.is_zero() {
                    evaluate_family_response(Ok(None), &q_aaaa, fake_ip_pool)
                } else {
                    match tokio::time::timeout(wait_second, fut_aaaa).await {
                        Ok(res_aaaa) => evaluate_family_response(res_aaaa, &q_aaaa, fake_ip_pool),
                        Err(_) => evaluate_family_response(Ok(None), &q_aaaa, fake_ip_pool),
                    }
                };
                (first, Some(second))
            }
            res_aaaa = &mut fut_aaaa => {
                let first = evaluate_family_response(res_aaaa, &q_aaaa, fake_ip_pool);
                let rem_now = deadline.saturating_duration_since(tokio::time::Instant::now());
                let wait_second = if !first.ips.is_empty() || first.saw_nxdomain {
                    DUAL_STACK_SECOND_FAMILY_GRACE.min(rem_now)
                } else {
                    rem_now
                };
                let second = if wait_second.is_zero() {
                    evaluate_family_response(Ok(None), &q_a, fake_ip_pool)
                } else {
                    match tokio::time::timeout(wait_second, fut_a).await {
                        Ok(res_a) => evaluate_family_response(res_a, &q_a, fake_ip_pool),
                        Err(_) => evaluate_family_response(Ok(None), &q_a, fake_ip_pool),
                    }
                };
                (second, Some(first))
            }
        }
    } else {
        let res_a = forward_upstream_udp(upstream_dns, &pkt_a, tx_a, &q_a, remaining).await;
        (evaluate_family_response(res_a, &q_a, fake_ip_pool), None)
    };

    let mut ips = Vec::new();
    let mut got_response = false;
    let mut saw_nxdomain = false;
    let mut saw_noerror = false;
    let mut last_err: Option<anyhow::Error> = None;

    for outcome in [Some(out_a), out_aaaa].into_iter().flatten() {
        got_response |= outcome.got_response;
        saw_nxdomain |= outcome.saw_nxdomain;
        saw_noerror |= outcome.saw_noerror;
        for ip in outcome.ips {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
        if let Some(e) = outcome.err {
            last_err = Some(e);
        }
    }

    if !ips.is_empty() {
        return Ok(ips);
    }
    if saw_nxdomain && !saw_noerror {
        return Err(anyhow::Error::new(DnsNxDomainError {
            domain: domain.to_string(),
            server: upstream_dns,
        }));
    }
    if let Some(err) = last_err {
        return Err(err);
    }
    if !got_response {
        bail!(
            "Upstream DNS resolution timed out for {} (server: {})",
            domain,
            upstream_dns
        );
    }
    bail!(
        "No usable IP records returned by upstream DNS {} for {}",
        upstream_dns,
        domain
    )
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
    if err.raw_os_error() == Some(10040) {
        // WSAEMSGSIZE: UDP datagram truncated by socket receive buffer
        return true;
    }
    false
}

enum ForwardQueryOutcome {
    RateLimited,
    NoResponse,
    Response { bytes: Vec<u8>, ans_off: usize },
}

async fn forward_raw_query_with_limit(
    upstream_limit: &Arc<Semaphore>,
    upstream_dns: SocketAddr,
    query_bytes: &[u8],
    client_tx_id: u16,
    question: &DnsQuestion,
    log_ctx: &str,
) -> ForwardQueryOutcome {
    let Ok(_up_permit) = Arc::clone(upstream_limit).try_acquire_owned() else {
        warn!(
            "[DNS Engine] Upstream forwarding limit reached ({}), dropping query: {}",
            log_ctx, question.name
        );
        return ForwardQueryOutcome::RateLimited;
    };
    let upstream_tx_id = csprng_u16();
    let mut forward_bytes = query_bytes.to_vec();
    forward_bytes[0..2].copy_from_slice(&upstream_tx_id.to_be_bytes());

    if let Ok(Some((mut resp_bytes, ans_off))) = forward_upstream_udp(
        upstream_dns,
        &forward_bytes,
        upstream_tx_id,
        question,
        UPSTREAM_DNS_TIMEOUT,
    )
    .await
    {
        resp_bytes[0..2].copy_from_slice(&client_tx_id.to_be_bytes());
        return ForwardQueryOutcome::Response {
            bytes: resp_bytes,
            ans_off,
        };
    }
    ForwardQueryOutcome::NoResponse
}

/// 处理单条原始 DNS 查询报文并生成响应（未就绪或限流丢弃时返回 `None`）
pub async fn handle_dns_query_bytes(
    pool: &FakeIpPool,
    upstream_dns: SocketAddr,
    block_ipv6: bool,
    upstream_limit: &Arc<Semaphore>,
    query_bytes: &[u8],
    peer_label: Option<SocketAddr>,
) -> Option<Vec<u8>> {
    handle_dns_query_bytes_with_orig_dns(
        pool,
        upstream_dns,
        None,
        block_ipv6,
        upstream_limit,
        query_bytes,
        peer_label,
    )
    .await
}

async fn handle_dns_query_bytes_with_orig_dns(
    pool: &FakeIpPool,
    upstream_dns: SocketAddr,
    orig_dns_hint: Option<SocketAddr>,
    block_ipv6: bool,
    upstream_limit: &Arc<Semaphore>,
    query_bytes: &[u8],
    peer_label: Option<SocketAddr>,
) -> Option<Vec<u8>> {
    match DnsPacketParser::parse_question(query_bytes) {
        Ok((client_tx_id, question)) => {
            debug!(
                "[DNS Query] Client: {}, Domain: {}, QType: {}",
                peer_label
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "transparent-udp53".to_string()),
                question.name,
                question.qtype
            );

            // 1. In anti-leak mode, block AAAA (28), SVCB (64), and HTTPS (65) queries
            if block_ipv6 && matches!(question.qtype, 28 | 64 | 65) {
                return Some(DnsPacketParser::build_empty_response(
                    client_tx_id,
                    query_bytes,
                    question.raw_len,
                ));
            }

            // 2. For A (IPv4) queries, allocate Fake-IP and respond (recording orig_dns for split-horizon Direct fallback)
            if question.qtype == 1 && question.qclass == 1 {
                let fake_ip = pool.allocate_with_dns(&question.name, orig_dns_hint);
                return Some(DnsPacketParser::build_a_response(
                    client_tx_id,
                    query_bytes,
                    question.raw_len,
                    fake_ip,
                ));
            }

            // 3. Forward other queries to upstream DNS via per-query ephemeral UDP socket & CSPRNG TxID
            match forward_raw_query_with_limit(
                upstream_limit,
                upstream_dns,
                query_bytes,
                client_tx_id,
                &question,
                "hijack",
            )
            .await
            {
                ForwardQueryOutcome::Response { bytes, .. } => Some(bytes),
                ForwardQueryOutcome::RateLimited | ForwardQueryOutcome::NoResponse => None,
            }
        }
        Err(e) => {
            warn!("[DNS Engine] Failed to parse DNS query packet: {}", e);
            None
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

    async fn process_query_with_upstream(
        &self,
        query_bytes: &[u8],
        upstream_dns: SocketAddr,
        orig_dns_hint: Option<SocketAddr>,
    ) -> Option<Vec<u8>> {
        let Ok(_permit) = self.concurrency_limit.clone().try_acquire_owned() else {
            warn!("[DNS Engine] Dropped transparent DNS query exceeding concurrency limit (5000)");
            return None;
        };
        let _in_flight = self.in_flight.as_ref().map(|t| t.enter());
        handle_dns_query_bytes_with_orig_dns(
            &self.pool,
            upstream_dns,
            orig_dns_hint,
            self.block_ipv6,
            &self.upstream_limit,
            query_bytes,
            None,
        )
        .await
    }

    /// 直接处理原始 DNS 查询报文（与 UDP 监听端共用 Fake-IP 分配、IPv6/HTTPS 防泄漏屏蔽及上游受控转发逻辑）
    pub async fn process_query_bytes(&self, query_bytes: &[u8]) -> Option<Vec<u8>> {
        self.process_query_with_upstream(query_bytes, self.upstream_dns, None)
            .await
    }

    fn resolve_transparent_upstream(&self, orig_dst: SocketAddr) -> (SocketAddr, bool) {
        let canon = canonicalize_socket_addr_preserving_scope(orig_dst);
        let dst_ip = canon.ip();
        let bind_ip = self.bind_addr.ip().to_canonical();
        let points_to_self_bind = canon.port() == self.bind_addr.port()
            && self.bind_addr.port() != 0
            && (dst_ip == bind_ip
                || (bind_ip.is_unspecified()
                    && crate::outbound::is_local_or_loopback_ip(
                        dst_ip,
                        &crate::outbound::local_interface_ips(),
                    )));
        if points_to_self_bind {
            return (self.upstream_dns, false);
        }
        match super::sanitize_upstream_dns_addr(canon, Some(&self.pool), self.pool.self_ports()) {
            Some(clean) => (clean, true),
            None => (self.upstream_dns, false),
        }
    }

    /// 透明代理专用 DNS 查询处理：保留原始报文目的 DNS 服务器 `orig_dst`（含 IPv6 `scope_id`）供非 `A/AAAA/HTTPS` 记录直达企业/VPN 原配 DNS，
    /// 同时在分配 Fake-IP 时记录原始 DNS 地址以便命中 `Direct` 时优先回源查询。
    pub async fn process_transparent_query_bytes(
        &self,
        query_bytes: &[u8],
        orig_dst: SocketAddr,
    ) -> Option<Vec<u8>> {
        let (effective_upstream, preserved_orig) = self.resolve_transparent_upstream(orig_dst);
        let orig_dns_hint = preserved_orig.then_some(effective_upstream);
        self.process_query_with_upstream(query_bytes, effective_upstream, orig_dns_hint)
            .await
    }

    /// 共享系统 DNS（如 `svchost.exe`）严格被动观测处理：
    /// 仅在 `orig_dst` 有效保留（`preserved_orig == true`）时原样透传至原始上游 DNS 并原样返回全部应答
    /// （绝不改道 `self.upstream_dns`、绝不伪造 Fake-IP、绝不篡改内网/回环/`0.0.0.0`/`NXDOMAIN`/`SERVFAIL`/`NODATA`/`AAAA`/`HTTPS`、
    /// 超时失败直接返回 `None` 让 OS 正常主备切换），仅在收到健康 `RCODE=0` 的 `A`/`AAAA` 应答时被动记录带 TTL 的 `real_ip -> domain` 辅助映射。
    pub async fn process_transparent_inspect_query_bytes(
        &self,
        query_bytes: &[u8],
        orig_dst: SocketAddr,
    ) -> Option<Vec<u8>> {
        let Ok(_permit) = self.concurrency_limit.clone().try_acquire_owned() else {
            warn!("[DNS Engine] Dropped transparent inspect DNS query exceeding concurrency limit (5000)");
            return None;
        };
        let _in_flight = self.in_flight.as_ref().map(|t| t.enter());

        let (client_tx_id, question) = match DnsPacketParser::parse_question(query_bytes) {
            Ok(parsed) => parsed,
            Err(e) => {
                warn!("[DNS Engine] Failed to parse transparent inspect DNS query: {}", e);
                return None;
            }
        };

        // 严禁在 preserved_orig == false（端口 0、未指定、自指、无 scope_id 的 fe80:: 等）时暗中改道至 self.upstream_dns
        let (effective_upstream, preserved_orig) = self.resolve_transparent_upstream(orig_dst);
        if !preserved_orig {
            return None;
        }
        match forward_raw_query_with_limit(
            &self.upstream_limit,
            effective_upstream,
            query_bytes,
            client_tx_id,
            &question,
            "inspect",
        )
        .await
        {
            ForwardQueryOutcome::Response {
                bytes: resp_bytes,
                ans_off,
            } => {
                if matches!(question.qtype, 1 | 28)
                    && question.qclass == 1
                    && (resp_bytes[3] & 0x0F) == 0
                    && let Ok((ips, min_ttl)) = parse_answer_ips_with_ttl(
                        &resp_bytes,
                        &question,
                        ans_off,
                        Some(&self.pool),
                    )
                    && !ips.is_empty()
                {
                    let ttl_hint = min_ttl.map(|s| Duration::from_secs(u64::from(s)));
                    self.pool
                        .record_real_ip_mappings_with_ttl(&question.name, &ips, ttl_hint);
                }
                Some(resp_bytes)
            }
            ForwardQueryOutcome::NoResponse | ForwardQueryOutcome::RateLimited => None,
        }
    }

    /// Run asynchronous UDP DNS listener loop (supports graceful shutdown, concurrency limit, and ephemeral upstream isolation)
    pub async fn run(&self, socket: Arc<UdpSocket>, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        let mut buf = vec![0u8; MAX_UDP_DNS_PACKET_LEN];
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
                if let Some(resp_bytes) = handle_dns_query_bytes(
                    &pool_clone,
                    upstream_dns,
                    block_ipv6,
                    &upstream_limit,
                    &query_bytes,
                    Some(peer),
                )
                .await
                {
                    let _ = socket_clone.send_to(&resp_bytes, peer).await;
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
        assert!(is_transient_udp_recv_error(&Error::from_raw_os_error(10040)));
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

    #[tokio::test]
    async fn test_process_query_bytes_allocates_fake_ip_and_blocks_aaaa() {
        let pool = Arc::new(FakeIpPool::new_default());
        let server = DnsServer::new(
            "127.0.0.1:0".parse().unwrap(),
            Arc::clone(&pool),
            "223.5.5.5:53".parse().unwrap(),
            true,
        );

        let a_query = build_sample_query(0x55AA, "transparent.example", 1);
        let a_resp = server
            .process_query_bytes(&a_query)
            .await
            .expect("A query should yield Fake-IP response");
        assert_eq!(&a_resp[0..2], &[0x55, 0xAA]);
        assert_eq!(&a_resp[6..8], &[0x00, 0x01]);
        let assigned_ip = Ipv4Addr::new(
            a_resp[a_resp.len() - 4],
            a_resp[a_resp.len() - 3],
            a_resp[a_resp.len() - 2],
            a_resp[a_resp.len() - 1],
        );
        assert_eq!(
            pool.restore_ip(IpAddr::V4(assigned_ip)).as_deref(),
            Some("transparent.example")
        );

        let aaaa_query = build_sample_query(0x66BB, "transparent.example", 28);
        let aaaa_resp = server
            .process_query_bytes(&aaaa_query)
            .await
            .expect("AAAA query with block_ipv6=true should yield empty answer response");
        assert_eq!(&aaaa_resp[0..2], &[0x66, 0xBB]);
        assert_eq!(&aaaa_resp[6..8], &[0x00, 0x00]);
    }

    #[tokio::test]
    async fn test_process_transparent_query_bytes_preserves_orig_dst_upstream() {
        let mock_up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_up.local_addr().unwrap();
        let up_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = mock_up.recv_from(&mut buf).await.unwrap();
            let (_txid, q) = DnsPacketParser::parse_question(&buf[..n]).unwrap();
            assert_eq!(q.qtype, 16);
            // 回送标准 RCODE=0 响应，保持相同 TxID 与 Question 段
            let mut resp = Vec::with_capacity(n);
            resp.extend_from_slice(&buf[0..2]);
            resp.extend_from_slice(&[0x81, 0x80]); // QR=1, RD=1, RA=1
            resp.extend_from_slice(&buf[4..n]);
            mock_up.send_to(&resp, peer).await.unwrap();
        });

        let pool = Arc::new(FakeIpPool::new_default());
        // 默认 upstream 指向不可达 TEST-NET，若未保留 orig_dst 则 TXT 请求必然超时失败
        let server = DnsServer::new(
            "127.0.0.1:0".parse().unwrap(),
            pool,
            "192.0.2.1:53".parse().unwrap(),
            true,
        );
        let txt_query = build_sample_query(0x77CC, "corp.internal.example", 16);
        let resp = server
            .process_transparent_query_bytes(&txt_query, mock_addr)
            .await
            .expect("TXT query must forward to original packet dst_ip:dst_port");
        up_task.await.unwrap();
        assert_eq!(&resp[0..2], &[0x77, 0xCC]);
    }

    #[tokio::test]
    async fn test_process_transparent_inspect_query_is_strictly_passive_and_preserves_all_upstream_semantics(
    ) {
        let mock_up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_up.local_addr().unwrap();
        let (stop_tx, mut stop_rx) = watch::channel(false);

        let up_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                tokio::select! {
                    recv = mock_up.recv_from(&mut buf) => {
                        let Ok((n, peer)) = recv else { break };
                        let (txid, q) = DnsPacketParser::parse_question(&buf[..n]).unwrap();
                        let name = q.name.to_ascii_lowercase();
                        let mut resp = Vec::new();
                        resp.extend_from_slice(&txid.to_be_bytes());
                        if name == "nxdomain.example" && q.qtype == 1 {
                            // RCODE=3 (NXDOMAIN)
                            resp.extend_from_slice(&[0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                            resp.extend_from_slice(&buf[12..q.raw_len]);
                        } else if name == "servfail.example" && q.qtype == 1 {
                            // RCODE=2 (SERVFAIL)
                            resp.extend_from_slice(&[0x81, 0x82, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                            resp.extend_from_slice(&buf[12..q.raw_len]);
                        } else if name == "healthy.example" && q.qtype == 1 {
                            resp.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
                            resp.extend_from_slice(&buf[12..q.raw_len]);
                            resp.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
                        } else if name == "dual-process.example" && q.qtype == 1 {
                            resp.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
                            resp.extend_from_slice(&buf[12..q.raw_len]);
                            resp.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4, 93, 184, 216, 35]);
                        } else if name == "nas.home" && q.qtype == 1 {
                            resp.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
                            resp.extend_from_slice(&buf[12..q.raw_len]);
                            resp.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4, 192, 168, 1, 10]);
                        } else if name == "localtest.me" && q.qtype == 1 {
                            resp.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
                            resp.extend_from_slice(&buf[12..q.raw_len]);
                            resp.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
                        } else if name == "ads.tracker.example" && q.qtype == 1 {
                            resp.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
                            resp.extend_from_slice(&buf[12..q.raw_len]);
                            resp.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4, 0, 0, 0, 0]);
                        } else if name == "v6only.example" && q.qtype == 1 {
                            // Pure IPv6 domain: A query legally returns NOERROR ANCOUNT=0 (NODATA)
                            resp.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                            resp.extend_from_slice(&buf[12..q.raw_len]);
                        } else if name == "v6only.example" && q.qtype == 28 {
                            resp.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
                            resp.extend_from_slice(&buf[12..q.raw_len]);
                            resp.extend_from_slice(&[
                                0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0, 0, 0, 60, 0, 16,
                                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                            ]);
                        } else {
                            resp.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                            resp.extend_from_slice(&buf[12..q.raw_len]);
                        }
                        let _ = mock_up.send_to(&resp, peer).await;
                    }
                    _ = stop_rx.changed() => break,
                }
            }
        });

        let pool = Arc::new(FakeIpPool::new_default());
        let server = DnsServer::new(
            "127.0.0.1:0".parse().unwrap(),
            Arc::clone(&pool),
            mock_addr,
            true,
        );

        // 1. 健康外部域名：原样返回真实 IP 且被动写入 real_ip_to_domain
        let q_healthy = build_sample_query(0x1001, "healthy.example", 1);
        let r_healthy = server
            .process_transparent_inspect_query_bytes(&q_healthy, mock_addr)
            .await
            .unwrap();
        assert_eq!(&r_healthy[0..2], &[0x10, 0x01]);
        assert_eq!(r_healthy[3] & 0x0F, 0);
        assert_eq!(&r_healthy[r_healthy.len() - 4..], &[93, 184, 216, 34]);
        assert_eq!(
            pool.lookup_real_ip_domain(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))
                .as_deref(),
            Some("healthy.example")
        );

        // 2. P0-1：内网 192.168.1.10 / 回环 127.0.0.1 / 广告屏蔽 0.0.0.0 全部原样透传，绝不伪造 Fake-IP
        for (tx, domain, expected) in [
            (0x2001, "nas.home", [192, 168, 1, 10]),
            (0x2002, "localtest.me", [127, 0, 0, 1]),
            (0x2003, "ads.tracker.example", [0, 0, 0, 0]),
        ] {
            let q = build_sample_query(tx, domain, 1);
            let r = server
                .process_transparent_inspect_query_bytes(&q, mock_addr)
                .await
                .unwrap();
            assert_eq!(r[3] & 0x0F, 0);
            assert_eq!(
                &r[r.len() - 4..],
                &expected,
                "InspectDns must preserve real IP {:?} verbatim for {}",
                expected,
                domain
            );
        }
        assert!(pool.is_empty(), "InspectDns must never allocate Fake-IP");
        assert_eq!(
            pool.lookup_real_ip_domain(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            None
        );
        assert_eq!(
            pool.lookup_real_ip_domain(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            None
        );

        // 3. P0-2：真实 NXDOMAIN、SERVFAIL、纯 IPv6 域名的 A NODATA + AAAA 均原样保留，绝不伪造 Fake-IP
        let r_nx = server
            .process_transparent_inspect_query_bytes(
                &build_sample_query(0x3001, "nxdomain.example", 1),
                mock_addr,
            )
            .await
            .unwrap();
        assert_eq!(r_nx[3] & 0x0F, 3, "NXDOMAIN must be preserved verbatim");
        assert_eq!(&r_nx[6..8], &[0x00, 0x00]);

        let r_sf = server
            .process_transparent_inspect_query_bytes(
                &build_sample_query(0x3002, "servfail.example", 1),
                mock_addr,
            )
            .await
            .unwrap();
        assert_eq!(r_sf[3] & 0x0F, 2, "SERVFAIL must be preserved verbatim");

        let r_v6_a = server
            .process_transparent_inspect_query_bytes(
                &build_sample_query(0x3003, "v6only.example", 1),
                mock_addr,
            )
            .await
            .unwrap();
        assert_eq!(r_v6_a[3] & 0x0F, 0);
        assert_eq!(
            &r_v6_a[6..8],
            &[0x00, 0x00],
            "IPv6-only A NODATA must not be rewritten into Fake-IP"
        );
        let r_v6_aaaa = server
            .process_transparent_inspect_query_bytes(
                &build_sample_query(0x3004, "v6only.example", 28),
                mock_addr,
            )
            .await
            .unwrap();
        assert_eq!(r_v6_aaaa[3] & 0x0F, 0);
        assert_eq!(&r_v6_aaaa[6..8], &[0x00, 0x01]);
        assert_eq!(
            pool.lookup_real_ip_domain("2001:db8::1".parse().unwrap())
                .as_deref(),
            Some("v6only.example")
        );

        // 4. P0-2：上游不可达 / link-local IPv6 返回 None 交由 OS 主备 DNS 切换，不注入伪造应答
        let closed_up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = closed_up.local_addr().unwrap();
        drop(closed_up);
        assert!(
            server
                .process_transparent_inspect_query_bytes(
                    &build_sample_query(0x3005, "unreachable.example", 1),
                    closed_addr,
                )
                .await
                .is_none(),
            "unreachable upstream must return None for OS DNS failover"
        );
        assert!(
            server
                .process_transparent_inspect_query_bytes(
                    &build_sample_query(0x3006, "linklocal.example", 1),
                    "[fe80::1]:53".parse().unwrap(),
                )
                .await
                .is_none()
        );

        // 5. P1-3 + P0-1：即便其它进程（HandleDns）已为 dual-process.example 分配 Fake-IP（且记录了 orig_dst），
        // 共享系统 DNS 的 InspectDns 仍必须原样返回真实上游 IP，绝不跨进程扩散 Fake-IP；
        // 同时 resolve_via_upstream_dns 不得反向污染 real_ip_to_domain
        let handle_resp = server
            .process_transparent_query_bytes(
                &build_sample_query(0x4001, "dual-process.example", 1),
                mock_addr,
            )
            .await
            .unwrap();
        let allocated_fake = Ipv4Addr::new(
            handle_resp[handle_resp.len() - 4],
            handle_resp[handle_resp.len() - 3],
            handle_resp[handle_resp.len() - 2],
            handle_resp[handle_resp.len() - 1],
        );
        assert_eq!(
            pool.restore_ip_with_dns(IpAddr::V4(allocated_fake)),
            Some(("dual-process.example".to_string(), Some(mock_addr)))
        );

        let inspect_dual = server
            .process_transparent_inspect_query_bytes(
                &build_sample_query(0x4002, "dual-process.example", 1),
                mock_addr,
            )
            .await
            .unwrap();
        assert_eq!(
            &inspect_dual[inspect_dual.len() - 4..],
            &[93, 184, 216, 35],
            "active Fake-IP from HandleDns must never leak into InspectDns"
        );

        // resolve_via_upstream_dns（直连解析/节点测速）不得写入 real_ip_to_domain
        let direct_pool = FakeIpPool::new_default();
        let resolved = resolve_via_upstream_dns_with_options(
            "healthy.example",
            mock_addr,
            Some(&direct_pool),
            Duration::from_secs(2),
            false,
        )
        .await
        .unwrap();
        assert_eq!(resolved, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        assert_eq!(
            direct_pool.lookup_real_ip_domain(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            None,
            "resolve_via_upstream_dns must not pollute real_ip_to_domain"
        );

        let _ = stop_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), up_task).await;
    }

    #[test]
    fn test_parse_answer_ips_with_ttl_cname_ttl_out_of_order_wildcard_owner_and_rdata_bound() {
        let q = DnsQuestion {
            name: "app.example.com".to_string(),
            qtype: 1,
            qclass: 1,
            raw_len: 0,
        };
        let encode_name = |name: &str, out: &mut Vec<u8>| {
            for label in name.split('.') {
                out.push(label.len() as u8);
                out.extend_from_slice(label.as_bytes());
            }
            out.push(0);
        };

        // 构造包含 3 条 Answer 的响应：
        // 1) A 记录排在 CNAME 之前（乱序）：edge.cdn.example -> 93.184.216.34 (TTL=300)
        // 2) 无关 RR 属主含 '*' 与 '/'：*.0/25.other.example (TXT, TTL=1) -> 不得中止整包提取，也不得拉低有效 TTL
        // 3) CNAME 排在 A 之后：app.example.com -> edge.cdn.example (TTL=5) -> 必须拉低 min_ttl 至 5
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x12, 0x34, 0x81, 0x80]); // QR=1, NOERROR
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00]); // QD=1, AN=3
        encode_name("app.example.com", &mut resp);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
        let ans_off = resp.len();

        // RR1: A edge.cdn.example TTL=300 -> 93.184.216.34
        encode_name("edge.cdn.example", &mut resp);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        resp.extend_from_slice(&300u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&[93, 184, 216, 34]);

        // RR2: TXT *.0/25.other.example TTL=1
        resp.push(1);
        resp.push(b'*');
        resp.push(4);
        resp.extend_from_slice(b"0/25");
        encode_name("other.example", &mut resp);
        resp.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]);
        resp.extend_from_slice(&1u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(b"note");

        // RR3: CNAME app.example.com TTL=5 -> edge.cdn.example
        encode_name("app.example.com", &mut resp);
        resp.extend_from_slice(&[0x00, 0x05, 0x00, 0x01]);
        resp.extend_from_slice(&5u32.to_be_bytes());
        let mut cname_rdata = Vec::new();
        encode_name("edge.cdn.example", &mut cname_rdata);
        resp.extend_from_slice(&(cname_rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(&cname_rdata);

        let (ips, min_ttl) = parse_answer_ips_with_ttl(&resp, &q, ans_off, None).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        assert_eq!(
            min_ttl,
            Some(5),
            "min_ttl must include short CNAME TTL (5s) and ignore unrelated wildcard RR (1s)"
        );

        // 验证 CNAME RDATA 截断边界：RDLENGTH 故意短于完整域名时必须忽略该畸形 CNAME，不得越界读入后续 RR
        let mut bad_cname = Vec::new();
        bad_cname.extend_from_slice(&[0x12, 0x35, 0x81, 0x80]);
        bad_cname.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]);
        encode_name("app.example.com", &mut bad_cname);
        bad_cname.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        let bad_off = bad_cname.len();
        // RR1: CNAME with truncated RDLENGTH=3 (missing null terminator)
        encode_name("app.example.com", &mut bad_cname);
        bad_cname.extend_from_slice(&[0x00, 0x05, 0x00, 0x01, 0, 0, 0, 10, 0, 3, 4, b'e', b'v']);
        // RR2: trailing bytes forming another RR
        encode_name("evil.example", &mut bad_cname);
        bad_cname.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0, 0, 0, 10, 0, 4, 1, 2, 3, 4]);
        let (bad_ips, _) = parse_answer_ips_with_ttl(&bad_cname, &q, bad_off, None).unwrap();
        assert!(bad_ips.is_empty(), "truncated CNAME RDATA must not read past rdata_end");
    }

    #[tokio::test]
    async fn test_dual_stack_dropped_aaaa_grace_window_nxdomain_conn_reset_and_inspect_no_redirect() {
        use std::net::SocketAddrV6;

        // 1. P2-2: A 返回后静默丢弃 AAAA 不得拖满 2s 超时（应在 ~150ms 宽限窗口内快速返回）
        let blackhole_aaaa_dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let blackhole_addr = blackhole_aaaa_dns.local_addr().unwrap();
        let (stop_tx, mut stop_rx) = watch::channel(false);
        let bh_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                tokio::select! {
                    recv = blackhole_aaaa_dns.recv_from(&mut buf) => {
                        let Ok((n, peer)) = recv else { break };
                        let (txid, q) = DnsPacketParser::parse_question(&buf[..n]).unwrap();
                        if q.name == "nx.corp.example" {
                            let mut r = Vec::new();
                            r.extend_from_slice(&txid.to_be_bytes());
                            r.extend_from_slice(&[0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                            r.extend_from_slice(&buf[12..q.raw_len]);
                            let _ = blackhole_aaaa_dns.send_to(&r, peer).await;
                        } else if q.qtype == 1 {
                            let mut r = Vec::new();
                            r.extend_from_slice(&txid.to_be_bytes());
                            r.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
                            r.extend_from_slice(&buf[12..q.raw_len]);
                            r.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4, 93, 184, 216, 40]);
                            let _ = blackhole_aaaa_dns.send_to(&r, peer).await;
                        }
                        // AAAA 查询故意静默丢弃不回复
                    }
                    _ = stop_rx.changed() => break,
                }
            }
        });

        let start = std::time::Instant::now();
        // 同时测试 [::ffff:127.0.0.1]:port 规范化发包
        let mapped_addr = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
            blackhole_addr.port(),
            0,
            0,
        ));
        let ips = resolve_via_upstream_dns(
            "v4-drop-aaaa.example",
            mapped_addr,
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        let elapsed = start.elapsed();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 40))]);
        assert!(
            elapsed < Duration::from_millis(800),
            "dropped AAAA must finish after short grace window instead of full 2s timeout, took {:?}",
            elapsed
        );

        // 2. P3-1: 权威 NXDOMAIN 必须返回 DnsNxDomainError
        let nx_err = resolve_via_upstream_dns(
            "nx.corp.example",
            blackhole_addr,
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert!(
            nx_err.downcast_ref::<DnsNxDomainError>().is_some(),
            "authoritative NXDOMAIN must surface DnsNxDomainError, got: {nx_err:#}"
        );

        // 3. P3-3: 本地关闭端口触发 WSAECONNRESET 时不得误报为超时
        let closed_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = closed_sock.local_addr().unwrap();
        drop(closed_sock);
        let reset_err = resolve_via_upstream_dns_with_options(
            "closed-dns.example",
            closed_addr,
            None,
            Duration::from_millis(600),
            false,
        )
        .await
        .unwrap_err();
        let msg = format!("{reset_err:#}");
        assert!(!msg.is_empty());
        // Windows 立即触发 ConnectionReset，不得误报为 timed out
        assert!(
            msg.contains("connection reset") || msg.contains("unreachable"),
            "Windows WSAECONNRESET must not be misreported as timeout, got: {msg}"
        );

        // 4. P1-3 & P3-3c: InspectDns 在 preserved_orig == false（端口 0 / 未指定 / 自指 DNS 端口或任意 FlowX 自服务端口）时必须返回 None，
        //    绝不暗中改道至 self.upstream_dns；同时 resolve_transparent_upstream 保留带 scope_id 的 fe80::1
        let pool = Arc::new(FakeIpPool::new_default().with_self_ports(vec![1053, 40001, 40080]));
        let srv = DnsServer::new(
            "0.0.0.0:1053".parse().unwrap(),
            Arc::clone(&pool),
            blackhole_addr,
            true,
        );
        let q_test = build_sample_query(0x5001, "v4-drop-aaaa.example", 1);
        for bad_orig in [
            "0.0.0.0:53".parse::<SocketAddr>().unwrap(),
            "8.8.8.8:0".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:1053".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:40001".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:40080".parse::<SocketAddr>().unwrap(),
            "[::1]:40001".parse::<SocketAddr>().unwrap(),
            "[::ffff:127.0.0.1]:40080".parse::<SocketAddr>().unwrap(),
        ] {
            let (fallback, preserved) = srv.resolve_transparent_upstream(bad_orig);
            assert!(
                !preserved && fallback == blackhole_addr,
                "resolve_transparent_upstream must reject {bad_orig}"
            );
            assert!(
                srv.process_transparent_inspect_query_bytes(&q_test, bad_orig)
                    .await
                    .is_none(),
                "InspectDns must return None instead of redirecting {bad_orig} to self.upstream_dns"
            );
        }
        let scoped_ll = SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 53, 0, 9));
        let (resolved_ll, preserved) = srv.resolve_transparent_upstream(scoped_ll);
        assert!(preserved);
        assert_eq!(resolved_ll, scoped_ll);

        let _ = stop_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), bh_task).await;
    }
}
