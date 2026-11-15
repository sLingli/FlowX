use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use crate::dns::FakeIpPool;
use crate::transparent::netstack::{EmittedIpPacket, PacketInterfaceMeta};

const MAX_FRAGMENT_GROUPS: usize = 1024;
const MAX_CHUNKS_PER_GROUP: usize = 64;
const MAX_TOTAL_FRAGMENT_BYTES: usize = 4 * 1024 * 1024;
const FRAGMENT_TTL: Duration = Duration::from_secs(10);

const IP_PROTO_HOPOPT: u8 = 0;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;
const IP_PROTO_ROUTING: u8 = 43;
const IP_PROTO_FRAGMENT: u8 = 44;
const IP_PROTO_DESTOPT: u8 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragmentKey {
    is_ipv6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    proto: u8,
    ident: u32,
}

#[derive(Debug)]
pub enum FragmentOutcome {
    /// 非 TCP/UDP 的合法报文（如大包 ICMP 分片）：直接单包放行
    PassthroughSingle,
    /// 非法分片、重叠分片攻击或发往 Fake-IP 的未认证流量：直接丢弃
    Drop,
    /// 尚缺其余分片，已进入有界缓存等待完整重组（严禁提前放行）
    Pending,
    /// 所有分片均已收齐并还原为完整的未分片 IP 报文，同时附带按偏移有序的原分片供必要时逐片直连放行
    Reassembled {
        full_packet: Vec<u8>,
        orig_fragments: Vec<EmittedIpPacket>,
    },
}

#[derive(Debug)]
enum FragmentParse {
    NotFragmented {
        dst_ip: IpAddr,
        proto: u8,
    },
    Fragment {
        key: FragmentKey,
        proto: u8,
        frag_offset: usize,
        more_fragments: bool,
        payload_start: usize,
        payload_end: usize,
        v4_ihl: usize,
        v6_frag_hdr_offset: usize,
        v6_next_hdr_ptr_offset: usize,
        is_ipv6: bool,
    },
    Malformed,
}

struct StoredChunk {
    payload: Vec<u8>,
    raw_packet: EmittedIpPacket,
}

impl StoredChunk {
    #[inline]
    fn byte_cost(&self) -> usize {
        self.payload.len() + self.raw_packet.data.len()
    }
}

enum ReassemblyPrefix {
    Ipv4 {
        header: Vec<u8>,
    },
    Ipv6 {
        prefix_headers: Vec<u8>,
        next_hdr_ptr_offset: usize,
        upper_proto: u8,
    },
}

struct FragmentGroup {
    created_at: Instant,
    chunks: BTreeMap<usize, StoredChunk>,
    first_prefix: Option<ReassemblyPrefix>,
    expected_total_len: Option<usize>,
    bytes_used: usize,
}

impl FragmentGroup {
    fn new(now: Instant) -> Self {
        Self {
            created_at: now,
            chunks: BTreeMap::new(),
            first_prefix: None,
            expected_total_len: None,
            bytes_used: 0,
        }
    }
}

/// 面向 WinDivert NETWORK 层的有界 IPv4/IPv6 分片重组器与安全分类器，
/// 消除 `parse_tcp_packet` / `parse_udp_packet` 遇分片返回 `None` 后被裸 `net_h.send` 盲目放行的规则穿透漏洞。
pub struct FragmentTracker {
    groups: HashMap<FragmentKey, FragmentGroup>,
    total_bytes: usize,
    last_prune: Instant,
}

impl Default for FragmentTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl FragmentTracker {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
            total_bytes: 0,
            last_prune: Instant::now(),
        }
    }

    pub fn active_group_count(&self) -> usize {
        self.groups.len()
    }

    pub fn buffered_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn ingest(
        &mut self,
        raw: &[u8],
        meta: PacketInterfaceMeta,
        fake_ip_pool: Option<&FakeIpPool>,
    ) -> FragmentOutcome {
        self.ingest_at(Instant::now(), raw, meta, fake_ip_pool)
    }

    pub(crate) fn ingest_at(
        &mut self,
        now: Instant,
        raw: &[u8],
        meta: PacketInterfaceMeta,
        fake_ip_pool: Option<&FakeIpPool>,
    ) -> FragmentOutcome {
        self.maybe_prune_expired(now);

        match parse_ip_fragment(raw) {
            FragmentParse::Malformed => FragmentOutcome::Drop,
            FragmentParse::NotFragmented { dst_ip, proto } => {
                if fake_ip_pool.is_some_and(|pool| pool.is_fake_ip_addr(dst_ip)) {
                    return FragmentOutcome::Drop;
                }
                if proto == IP_PROTO_TCP || proto == IP_PROTO_UDP {
                    // 未分片且已明确为 TCP/UDP 却未能通过传输层完整头解析：属于截断异常包，禁止旁路放行
                    return FragmentOutcome::Drop;
                }
                FragmentOutcome::PassthroughSingle
            }
            FragmentParse::Fragment {
                key,
                proto,
                frag_offset,
                more_fragments,
                payload_start,
                payload_end,
                v4_ihl,
                v6_frag_hdr_offset,
                v6_next_hdr_ptr_offset,
                is_ipv6,
            } => {
                let is_fake_ip = fake_ip_pool.is_some_and(|pool| pool.is_fake_ip_addr(key.dst_ip));

                // 非 TCP/UDP（例如 ping -l 2000 等大 ICMP 报文）且非发往 Fake-IP：立即平滑放行，不浪费重组预算
                if proto != IP_PROTO_TCP && proto != IP_PROTO_UDP {
                    return if is_fake_ip {
                        FragmentOutcome::Drop
                    } else {
                        FragmentOutcome::PassthroughSingle
                    };
                }

                let frag_payload = &raw[payload_start..payload_end];

                // RFC 791 / RFC 8200 合法性检查：非末尾分片载荷长度必须为 8 字节正整数倍
                if more_fragments && (frag_payload.is_empty() || !frag_payload.len().is_multiple_of(8)) {
                    self.remove_group(&key);
                    return FragmentOutcome::Drop;
                }

                let max_payload = if is_ipv6 {
                    let ext_before_frag = v6_frag_hdr_offset.saturating_sub(40);
                    u16::MAX as usize - ext_before_frag
                } else {
                    u16::MAX as usize - v4_ihl
                };
                let Some(chunk_end) = frag_offset.checked_add(frag_payload.len()) else {
                    self.remove_group(&key);
                    return FragmentOutcome::Drop;
                };
                if chunk_end > max_payload {
                    self.remove_group(&key);
                    return FragmentOutcome::Drop;
                }

                // Fake-IP 快速拦截：如果首片 UDP 目标端口并非 DNS 53，直接拒绝整组重组并丢弃
                if is_fake_ip && proto == IP_PROTO_UDP && frag_offset == 0 && frag_payload.len() >= 4 {
                    let dst_port = u16::from_be_bytes([frag_payload[2], frag_payload[3]]);
                    if dst_port != 53 {
                        self.remove_group(&key);
                        return FragmentOutcome::Drop;
                    }
                }

                let incoming_cost = frag_payload.len() + raw.len();
                if incoming_cost > MAX_TOTAL_FRAGMENT_BYTES {
                    self.remove_group(&key);
                    return FragmentOutcome::Drop;
                }

                self.ensure_capacity_for(&key, incoming_cost);

                let group = self
                    .groups
                    .entry(key)
                    .or_insert_with(|| FragmentGroup::new(now));

                if let Some(prev_total) = group.expected_total_len {
                    if !more_fragments && prev_total != chunk_end {
                        self.remove_group(&key);
                        return FragmentOutcome::Drop;
                    }
                    if chunk_end > prev_total {
                        self.remove_group(&key);
                        return FragmentOutcome::Drop;
                    }
                } else if !more_fragments {
                    // 确保此前已到达的任何分片都没有越过尾片宣告的总长度
                    if let Some((&last_off, last_chunk)) = group.chunks.iter().next_back()
                        && last_off + last_chunk.payload.len() > chunk_end
                    {
                        self.remove_group(&key);
                        return FragmentOutcome::Drop;
                    }
                    group.expected_total_len = Some(chunk_end);
                }

                // 重叠分片检查（拦截 TearDrop / 首片传输头覆盖逃逸攻击）
                if let Some(existing) = group.chunks.get(&frag_offset) {
                    if existing.payload.as_slice() == frag_payload {
                        return FragmentOutcome::Pending;
                    }
                    self.remove_group(&key);
                    return FragmentOutcome::Drop;
                }
                if let Some((&prev_off, prev_chunk)) = group.chunks.range(..frag_offset).next_back()
                    && prev_off + prev_chunk.payload.len() > frag_offset
                {
                    self.remove_group(&key);
                    return FragmentOutcome::Drop;
                }
                if let Some((&next_off, _)) = group.chunks.range((frag_offset + 1)..).next()
                    && chunk_end > next_off
                {
                    self.remove_group(&key);
                    return FragmentOutcome::Drop;
                }

                if group.chunks.len() >= MAX_CHUNKS_PER_GROUP {
                    self.remove_group(&key);
                    return FragmentOutcome::Drop;
                }

                if frag_offset == 0 && group.first_prefix.is_none() {
                    group.first_prefix = Some(if is_ipv6 {
                        ReassemblyPrefix::Ipv6 {
                            prefix_headers: raw[..v6_frag_hdr_offset].to_vec(),
                            next_hdr_ptr_offset: v6_next_hdr_ptr_offset,
                            upper_proto: proto,
                        }
                    } else {
                        ReassemblyPrefix::Ipv4 {
                            header: raw[..v4_ihl].to_vec(),
                        }
                    });
                }

                let stored = StoredChunk {
                    payload: frag_payload.to_vec(),
                    raw_packet: EmittedIpPacket {
                        data: raw.to_vec(),
                        meta,
                    },
                };
                group.bytes_used += stored.byte_cost();
                self.total_bytes += stored.byte_cost();
                group.chunks.insert(frag_offset, stored);

                if !is_group_complete(group) {
                    return FragmentOutcome::Pending;
                }

                let completed = self.remove_group(&key).expect("group just inserted");
                match build_reassembled_ip_packet(completed) {
                    Some((full_packet, orig_fragments)) => FragmentOutcome::Reassembled {
                        full_packet,
                        orig_fragments,
                    },
                    None => FragmentOutcome::Drop,
                }
            }
        }
    }

    fn remove_group(&mut self, key: &FragmentKey) -> Option<FragmentGroup> {
        let removed = self.groups.remove(key)?;
        self.total_bytes = self.total_bytes.saturating_sub(removed.bytes_used);
        Some(removed)
    }

    fn maybe_prune_expired(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_prune) < Duration::from_secs(2)
            && self.groups.len() < 128
        {
            return;
        }
        self.last_prune = now;
        let expired: Vec<FragmentKey> = self
            .groups
            .iter()
            .filter(|(_, g)| now.saturating_duration_since(g.created_at) > FRAGMENT_TTL)
            .map(|(k, _)| *k)
            .collect();
        for k in expired {
            self.remove_group(&k);
        }
    }

    fn ensure_capacity_for(&mut self, incoming_key: &FragmentKey, incoming_cost: usize) {
        let needs_new_slot = !self.groups.contains_key(incoming_key);
        while (needs_new_slot && self.groups.len() >= MAX_FRAGMENT_GROUPS)
            || self.total_bytes.saturating_add(incoming_cost) > MAX_TOTAL_FRAGMENT_BYTES
        {
            let Some(oldest_key) = self
                .groups
                .iter()
                .filter(|(k, _)| *k != incoming_key)
                .min_by_key(|(_, g)| g.created_at)
                .map(|(k, _)| *k)
            else {
                break;
            };
            self.remove_group(&oldest_key);
        }
    }
}

fn is_group_complete(group: &FragmentGroup) -> bool {
    let Some(total_len) = group.expected_total_len else {
        return false;
    };
    if group.first_prefix.is_none() || total_len == 0 {
        return false;
    }
    let mut cursor = 0usize;
    for (&off, chunk) in &group.chunks {
        if off != cursor {
            return false;
        }
        cursor += chunk.payload.len();
    }
    cursor == total_len
}

fn build_reassembled_ip_packet(group: FragmentGroup) -> Option<(Vec<u8>, Vec<EmittedIpPacket>)> {
    let total_payload_len = group.expected_total_len?;
    let prefix = group.first_prefix?;

    let mut orig_fragments = Vec::with_capacity(group.chunks.len());
    let mut assembled_payload = Vec::with_capacity(total_payload_len);
    for (_, chunk) in group.chunks {
        assembled_payload.extend_from_slice(&chunk.payload);
        orig_fragments.push(chunk.raw_packet);
    }
    if assembled_payload.len() != total_payload_len {
        return None;
    }

    match prefix {
        ReassemblyPrefix::Ipv4 { mut header } => {
            let full_len = header.len().checked_add(assembled_payload.len())?;
            let total_len_u16 = u16::try_from(full_len).ok()?;
            header[2..4].copy_from_slice(&total_len_u16.to_be_bytes());
            header[6..8].copy_from_slice(&[0, 0]);
            recompute_ipv4_checksum(&mut header);

            let mut out = Vec::with_capacity(full_len);
            out.extend_from_slice(&header);
            out.extend_from_slice(&assembled_payload);
            Some((out, orig_fragments))
        }
        ReassemblyPrefix::Ipv6 {
            mut prefix_headers,
            next_hdr_ptr_offset,
            upper_proto,
        } => {
            if prefix_headers.len() < 40 || next_hdr_ptr_offset >= prefix_headers.len() {
                return None;
            }
            let ext_len = prefix_headers.len() - 40;
            let ipv6_payload_len = ext_len.checked_add(assembled_payload.len())?;
            let payload_len_u16 = u16::try_from(ipv6_payload_len).ok()?;
            prefix_headers[next_hdr_ptr_offset] = upper_proto;
            prefix_headers[4..6].copy_from_slice(&payload_len_u16.to_be_bytes());

            let mut out = Vec::with_capacity(prefix_headers.len() + assembled_payload.len());
            out.extend_from_slice(&prefix_headers);
            out.extend_from_slice(&assembled_payload);
            Some((out, orig_fragments))
        }
    }
}

#[inline]
fn recompute_ipv4_checksum(hdr: &mut [u8]) {
    if hdr.len() < 20 {
        return;
    }
    hdr[10] = 0;
    hdr[11] = 0;
    let mut sum: u32 = 0;
    for pair in hdr.as_chunks::<2>().0 {
        sum += u16::from_be_bytes(*pair) as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    hdr[10..12].copy_from_slice(&checksum.to_be_bytes());
}

fn parse_ip_fragment(raw: &[u8]) -> FragmentParse {
    if raw.is_empty() {
        return FragmentParse::Malformed;
    }
    match raw[0] >> 4 {
        4 => parse_ipv4_fragment(raw),
        6 => parse_ipv6_fragment(raw),
        _ => FragmentParse::Malformed,
    }
}

fn parse_ipv4_fragment(raw: &[u8]) -> FragmentParse {
    if raw.len() < 20 {
        return FragmentParse::Malformed;
    }
    let ihl = ((raw[0] & 0x0F) as usize) * 4;
    if ihl < 20 || raw.len() < ihl {
        return FragmentParse::Malformed;
    }
    let total_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    if total_len < ihl || raw.len() < total_len {
        return FragmentParse::Malformed;
    }

    let proto = raw[9];
    let src_ip = IpAddr::V4(Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15])).to_canonical();
    let dst_ip = IpAddr::V4(Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19])).to_canonical();

    let flags_frag = u16::from_be_bytes([raw[6], raw[7]]);
    let more_fragments = (flags_frag & 0x2000) != 0;
    let frag_offset = ((flags_frag & 0x1FFF) as usize) * 8;

    if !more_fragments && frag_offset == 0 {
        return FragmentParse::NotFragmented { dst_ip, proto };
    }

    let ident = u16::from_be_bytes([raw[4], raw[5]]) as u32;
    FragmentParse::Fragment {
        key: FragmentKey {
            is_ipv6: false,
            src_ip,
            dst_ip,
            proto,
            ident,
        },
        proto,
        frag_offset,
        more_fragments,
        payload_start: ihl,
        payload_end: total_len,
        v4_ihl: ihl,
        v6_frag_hdr_offset: 0,
        v6_next_hdr_ptr_offset: 0,
        is_ipv6: false,
    }
}

fn parse_ipv6_fragment(raw: &[u8]) -> FragmentParse {
    if raw.len() < 40 {
        return FragmentParse::Malformed;
    }
    let payload_len = u16::from_be_bytes([raw[4], raw[5]]) as usize;
    let Some(end) = 40usize.checked_add(payload_len) else {
        return FragmentParse::Malformed;
    };
    if end > raw.len() || payload_len == 0 {
        return FragmentParse::Malformed;
    }

    let Ok(src_octets) = <[u8; 16]>::try_from(&raw[8..24]) else {
        return FragmentParse::Malformed;
    };
    let Ok(dst_octets) = <[u8; 16]>::try_from(&raw[24..40]) else {
        return FragmentParse::Malformed;
    };
    let src_ip = IpAddr::V6(Ipv6Addr::from(src_octets)).to_canonical();
    let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_octets)).to_canonical();

    let mut next_hdr = raw[6];
    let mut next_hdr_ptr_offset = 6usize;
    let mut pos = 40usize;

    for _ in 0..8 {
        match next_hdr {
            IP_PROTO_FRAGMENT => {
                if pos + 8 > end {
                    return FragmentParse::Malformed;
                }
                let upper_proto = raw[pos];
                let off_m = u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]);
                let frag_offset = (off_m & 0xFFF8) as usize;
                let more_fragments = (off_m & 0x0001) != 0;
                let Ok(ident_bytes) = <[u8; 4]>::try_from(&raw[pos + 4..pos + 8]) else {
                    return FragmentParse::Malformed;
                };
                let ident = u32::from_be_bytes(ident_bytes);

                return FragmentParse::Fragment {
                    key: FragmentKey {
                        is_ipv6: true,
                        src_ip,
                        dst_ip,
                        proto: upper_proto,
                        ident,
                    },
                    proto: upper_proto,
                    frag_offset,
                    more_fragments,
                    payload_start: pos + 8,
                    payload_end: end,
                    v4_ihl: 0,
                    v6_frag_hdr_offset: pos,
                    v6_next_hdr_ptr_offset: next_hdr_ptr_offset,
                    is_ipv6: true,
                };
            }
            IP_PROTO_HOPOPT | IP_PROTO_ROUTING | IP_PROTO_DESTOPT => {
                if pos + 2 > end {
                    return FragmentParse::Malformed;
                }
                let ext_len = ((raw[pos + 1] as usize) + 1) * 8;
                if pos + ext_len > end {
                    return FragmentParse::Malformed;
                }
                next_hdr_ptr_offset = pos;
                next_hdr = raw[pos];
                pos += ext_len;
            }
            other => {
                return FragmentParse::NotFragmented {
                    dst_ip,
                    proto: other,
                };
            }
        }
    }

    FragmentParse::Malformed
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};

    use crate::transparent::dns_hijack::parse_udp_packet;
    use crate::transparent::netstack::parse_tcp_packet;

    fn make_ipv4_packet(src: [u8; 4], dst: [u8; 4], proto: u8, id: u16, offset_bytes: usize, mf: bool, payload: &[u8]) -> Vec<u8> {
        let total_len = (20 + payload.len()) as u16;
        let flags_frag = ((offset_bytes / 8) as u16) | if mf { 0x2000 } else { 0 };
        let mut out = vec![0u8; total_len as usize];
        out[0] = 0x45;
        out[2..4].copy_from_slice(&total_len.to_be_bytes());
        out[4..6].copy_from_slice(&id.to_be_bytes());
        out[6..8].copy_from_slice(&flags_frag.to_be_bytes());
        out[8] = 64;
        out[9] = proto;
        out[12..16].copy_from_slice(&src);
        out[16..20].copy_from_slice(&dst);
        out[20..].copy_from_slice(payload);
        recompute_ipv4_checksum(&mut out[..20]);
        out
    }

    fn make_ipv6_frag_packet(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        upper_proto: u8,
        id: u32,
        offset_bytes: usize,
        mf: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let ipv6_payload_len = (8 + payload.len()) as u16;
        let mut out = vec![0u8; 48 + payload.len()];
        out[0] = 0x60;
        out[4..6].copy_from_slice(&ipv6_payload_len.to_be_bytes());
        out[6] = IP_PROTO_FRAGMENT;
        out[7] = 64;
        out[8..24].copy_from_slice(&src.octets());
        out[24..40].copy_from_slice(&dst.octets());
        // Fragment header
        out[40] = upper_proto;
        let off_m = ((offset_bytes as u16) & 0xFFF8) | if mf { 1 } else { 0 };
        out[42..44].copy_from_slice(&off_m.to_be_bytes());
        out[44..48].copy_from_slice(&id.to_be_bytes());
        out[48..].copy_from_slice(payload);
        out
    }

    #[test]
    fn test_ipv4_fragmented_udp_dns_reassembles_out_of_order() {
        let mut tracker = FragmentTracker::new();
        let meta = PacketInterfaceMeta {
            if_idx: 3,
            ..Default::default()
        };

        // 构造一条完整 UDP/53 报文，拆为两个 IPv4 分片且故意乱序到达（片 1 先于片 0）
        let dns_payload = [0xAAu8; 40];
        let builder = PacketBuilder::ipv4([10, 0, 0, 2], [8, 8, 8, 8], 64).udp(51000, 53);
        let mut unfrag = Vec::with_capacity(builder.size(dns_payload.len()));
        builder.write(&mut unfrag, &dns_payload).unwrap();
        let udp_segment = &unfrag[20..]; // 8 + 40 = 48 字节

        let frag1 = make_ipv4_packet([10, 0, 0, 2], [8, 8, 8, 8], IP_PROTO_UDP, 0x1234, 24, false, &udp_segment[24..]);
        let frag0 = make_ipv4_packet([10, 0, 0, 2], [8, 8, 8, 8], IP_PROTO_UDP, 0x1234, 0, true, &udp_segment[..24]);

        assert!(matches!(tracker.ingest(&frag1, meta, None), FragmentOutcome::Pending));
        assert_eq!(tracker.active_group_count(), 1);

        let FragmentOutcome::Reassembled {
            full_packet,
            orig_fragments,
        } = tracker.ingest(&frag0, meta, None)
        else {
            panic!("expected completed IPv4 reassembly");
        };
        assert_eq!(tracker.active_group_count(), 0);
        assert_eq!(tracker.buffered_bytes(), 0);
        assert_eq!(orig_fragments.len(), 2);

        let parsed = parse_udp_packet(&full_packet).expect("reassembled DNS UDP should parse");
        assert_eq!(parsed.dst_port, 53);
        assert_eq!(parsed.payload, &dns_payload);
    }

    #[test]
    fn test_ipv6_fragmented_tcp_syn_reassembles_cleanly() {
        let mut tracker = FragmentTracker::new();
        let src6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let dst6 = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let mut hdr = etherparse::TcpHeader::new(55000, 443, 12345, 65535);
        hdr.syn = true;
        let payload = b"0123456789ABCDEF";
        let builder = PacketBuilder::ipv6(src6.octets(), dst6.octets(), 64).tcp_header(hdr);
        let mut full_v6 = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut full_v6, payload).unwrap();
        let tcp_seg = &full_v6[40..];

        let meta = PacketInterfaceMeta {
            if_idx: 5,
            is_ipv6: true,
            ..Default::default()
        };
        let frag0 = make_ipv6_frag_packet(src6, dst6, IP_PROTO_TCP, 0xCAFEBABE, 0, true, &tcp_seg[..16]);
        let frag1 = make_ipv6_frag_packet(src6, dst6, IP_PROTO_TCP, 0xCAFEBABE, 16, false, &tcp_seg[16..]);

        assert!(matches!(tracker.ingest(&frag0, meta, None), FragmentOutcome::Pending));
        let FragmentOutcome::Reassembled { full_packet, .. } = tracker.ingest(&frag1, meta, None)
        else {
            panic!("expected completed IPv6 TCP reassembly");
        };

        let parsed = parse_tcp_packet(&full_packet).expect("reassembled IPv6 TCP should parse");
        assert!(parsed.is_ipv6 && parsed.syn && parsed.dst_port == 443);
        let sliced = SlicedPacket::from_ip(&full_packet).unwrap();
        assert!(matches!(sliced.net, Some(NetSlice::Ipv6(_))));
        let Some(TransportSlice::Tcp(t)) = sliced.transport else {
            panic!("expected tcp transport slice");
        };
        assert_eq!(t.payload(), payload);
    }

    #[test]
    fn test_fragmented_fake_ip_and_overlapping_and_orphan_fragments_never_passthrough() {
        let mut tracker = FragmentTracker::new();
        let fake_pool = FakeIpPool::new_default();
        let fake_v4 = fake_pool.allocate("quic.example.com");
        let meta = PacketInterfaceMeta::default();

        // 1. 发往 Fake-IP 的非 53 端口 UDP 首片必须立即 Drop，禁止放行
        let builder = PacketBuilder::ipv4([10, 0, 0, 2], fake_v4.octets(), 64).udp(52000, 443);
        let mut fake_udp = Vec::with_capacity(builder.size(16));
        builder.write(&mut fake_udp, &[0u8; 16]).unwrap();
        let fake_frag0 = make_ipv4_packet(
            [10, 0, 0, 2],
            fake_v4.octets(),
            IP_PROTO_UDP,
            0x2222,
            0,
            true,
            &fake_udp[20..20 + 16],
        );
        assert!(matches!(
            tracker.ingest(&fake_frag0, meta, Some(&fake_pool)),
            FragmentOutcome::Drop
        ));

        // 2. 重叠分片 TearDrop/逃逸攻击必须立即整组丢弃
        let f_ok = make_ipv4_packet([10, 0, 0, 2], [1, 1, 1, 1], IP_PROTO_TCP, 0x3333, 0, true, &[1u8; 16]);
        let f_overlap = make_ipv4_packet([10, 0, 0, 2], [1, 1, 1, 1], IP_PROTO_TCP, 0x3333, 8, false, &[2u8; 16]);
        assert!(matches!(tracker.ingest(&f_ok, meta, Some(&fake_pool)), FragmentOutcome::Pending));
        assert!(matches!(tracker.ingest(&f_overlap, meta, Some(&fake_pool)), FragmentOutcome::Drop));
        assert_eq!(tracker.active_group_count(), 0);
        assert_eq!(tracker.buffered_bytes(), 0);

        // 3. 孤立非首片 UDP 分片进入 Pending 后超时清理，绝不泄露给网卡
        let orphan = make_ipv4_packet([10, 0, 0, 2], [1, 1, 1, 1], IP_PROTO_UDP, 0x4444, 24, false, &[3u8; 16]);
        let t0 = Instant::now();
        assert!(matches!(tracker.ingest_at(t0, &orphan, meta, Some(&fake_pool)), FragmentOutcome::Pending));
        assert_eq!(tracker.active_group_count(), 1);
        let t_later = t0 + FRAGMENT_TTL + Duration::from_secs(1);
        let other_icmp = make_ipv4_packet([10, 0, 0, 2], [8, 8, 8, 8], 1, 0x5555, 0, true, &[0u8; 24]);
        // 合法 ICMP 分片允许放行，且已超时的孤立 UDP 分片顺带被回收
        assert!(matches!(
            tracker.ingest_at(t_later, &other_icmp, meta, Some(&fake_pool)),
            FragmentOutcome::PassthroughSingle
        ));
        assert_eq!(tracker.active_group_count(), 0);
    }
}
