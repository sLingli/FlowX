use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use anyhow::{Context, Result, bail};

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

fn is_valid_dns_label_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// 线协议级 DNS 名称解码器（支持指针压缩，防越界与指针循环）：
/// - `strict_hostname = true`：校验每个标签字符符合主机名子集（用于 Question 严格校验）；
/// - `strict_hostname = false`：兼容 Answer 段中可能出现的 `*`、`/`（如 RFC 2317 反向域或通配/DNS-SD 属主）等线协议标签，
///   避免单条无关 RR 属主字符触发错误而中断整包有效 IP 提取。
fn decode_dns_name_inner(
    packet: &[u8],
    start: usize,
    strict_hostname: bool,
) -> Result<(String, usize)> {
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
pub(super) fn decode_dns_name(packet: &[u8], start: usize) -> Result<(String, usize)> {
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
            bail!(
                "DNS query must contain exactly 1 Question entry (got {})",
                qdcount
            );
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
                bail!(
                    "DNS domain label length exceeds RFC 1035 limit of 63 bytes: {}",
                    len
                );
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
    pub fn build_a_response(
        tx_id: u16,
        original_query: &[u8],
        question_len: usize,
        ip: Ipv4Addr,
    ) -> Vec<u8> {
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

/// 使用系统级 CSPRNG 生成强随机 16 位事务 ID（用于上游 DNS 查询防欺骗）
pub(crate) fn csprng_u16() -> u16 {
    let mut bytes = [0u8; 2];

    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
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
pub(super) fn validate_upstream_dns_response(
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
pub(super) fn build_dns_query_packet(
    tx_id: u16,
    domain: &str,
    qtype: u16,
) -> Result<(Vec<u8>, DnsQuestion)> {
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
    if let Ok((ips, min_ttl)) = parse_answer_ips_with_ttl(resp_bytes, question, ans_off, Some(pool))
        && !ips.is_empty()
    {
        let ttl_hint = min_ttl.map(|s| Duration::from_secs(u64::from(s)));
        pool.record_real_ip_mappings_with_ttl(&question.name, &ips, ttl_hint);
        return true;
    }
    false
}

/// 解析 DNS 应答中的 A / AAAA（支持乱序与多跳 CNAME 链，计入链上 CNAME 最小 TTL，限定 RDATA 边界，并过滤任何 Fake-IP 防止自环路）
pub(super) fn parse_answer_ips_with_ttl(
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
pub(super) fn parse_answer_ips(
    resp: &[u8],
    question: &DnsQuestion,
    first_answer_offset: usize,
    fake_ip_pool: Option<&FakeIpPool>,
) -> Result<Vec<IpAddr>> {
    parse_answer_ips_with_ttl(resp, question, first_answer_offset, fake_ip_pool).map(|(ips, _)| ips)
}
