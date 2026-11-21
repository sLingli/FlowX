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
const IP_PROTO_ICMPV4: u8 = 1;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;
const IP_PROTO_ROUTING: u8 = 43;
const IP_PROTO_FRAGMENT: u8 = 44;
const IP_PROTO_AH: u8 = 51;
const IP_PROTO_ICMPV6: u8 = 58;
const IP_PROTO_DESTOPT: u8 = 60;
const IP_PROTO_MOBILITY: u8 = 135;
const IP_PROTO_HIP: u8 = 139;
const IP_PROTO_SHIM6: u8 = 140;

#[inline]
fn is_ipv6_extension_header(nh: u8) -> bool {
    matches!(
        nh,
        IP_PROTO_HOPOPT
            | IP_PROTO_ROUTING
            | IP_PROTO_AH
            | IP_PROTO_DESTOPT
            | IP_PROTO_MOBILITY
            | IP_PROTO_HIP
            | IP_PROTO_SHIM6
    )
}

#[inline]
fn ipv6_ext_header_len(nh: u8, slice: &[u8]) -> Option<usize> {
    if slice.len() < 2 {
        return None;
    }
    match nh {
        IP_PROTO_HOPOPT
        | IP_PROTO_ROUTING
        | IP_PROTO_DESTOPT
        | IP_PROTO_MOBILITY
        | IP_PROTO_HIP
        | IP_PROTO_SHIM6 => Some(((slice[1] as usize) + 1) * 8),
        IP_PROTO_AH => Some(((slice[1] as usize) + 2) * 4),
        _ => None,
    }
}

enum ExtWalk {
    Transport { proto: u8, offset: usize },
    Incomplete { next_nh: u8 },
    NestedFragOrMalformed,
}

fn walk_ipv6_ext_headers(mut nh: u8, data: &[u8]) -> ExtWalk {
    let mut pos = 0usize;
    for _ in 0..8 {
        if nh == IP_PROTO_FRAGMENT {
            return ExtWalk::NestedFragOrMalformed;
        }
        if !is_ipv6_extension_header(nh) {
            return ExtWalk::Transport { proto: nh, offset: pos };
        }
        let Some(ext_len) = ipv6_ext_header_len(nh, &data[pos..]) else {
            return ExtWalk::Incomplete { next_nh: nh };
        };
        if pos + ext_len > data.len() {
            return ExtWalk::Incomplete { next_nh: nh };
        }
        nh = data[pos];
        pos += ext_len;
    }
    if nh == IP_PROTO_FRAGMENT || is_ipv6_extension_header(nh) {
        ExtWalk::NestedFragOrMalformed
    } else {
        ExtWalk::Transport { proto: nh, offset: pos }
    }
}

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
    /// 重组校验后确认为非 TCP/UDP（如携带后置扩展头的 IPv6 ICMPv6/ESP/NoNext）的合法分片组：逐片放行原始分片
    PassthroughGroup(Vec<EmittedIpPacket>),
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
        v6_frag_next_hdr: u8,
        frag_offset: usize,
        more_fragments: bool,
        payload_start: usize,
        payload_end: usize,
        v4_ihl: usize,
        v6_frag_hdr_offset: usize,
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
        base_header: [u8; 40],
        frag_next_hdr: u8,
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
                v6_frag_next_hdr,
                frag_offset,
                more_fragments,
                payload_start,
                payload_end,
                v4_ihl,
                v6_frag_hdr_offset,
                is_ipv6,
            } => {
                let is_fake_ip = fake_ip_pool.is_some_and(|pool| pool.is_fake_ip_addr(key.dst_ip));
                let frag_payload = &raw[payload_start..payload_end];

                // RFC 6946: IPv6 原子分片（offset == 0 && !M）必须完全隔离处理，绝不与 self.groups 中任何同 ID 组交互或互相破坏
                if is_ipv6 && frag_offset == 0 && !more_fragments {
                    let ext_before_frag = v6_frag_hdr_offset.saturating_sub(40);
                    let max_payload = u16::MAX as usize - ext_before_frag;
                    if frag_payload.is_empty() || frag_payload.len() > max_payload {
                        return FragmentOutcome::Drop;
                    }
                    let ExtWalk::Transport {
                        proto: final_proto,
                        offset: ext_offset,
                    } = walk_ipv6_ext_headers(v6_frag_next_hdr, frag_payload)
                    else {
                        return FragmentOutcome::Drop;
                    };
                    if !matches!(final_proto, IP_PROTO_TCP | IP_PROTO_UDP) {
                        return if is_fake_ip {
                            FragmentOutcome::Drop
                        } else {
                            FragmentOutcome::PassthroughSingle
                        };
                    }
                    let transport_slice = &frag_payload[ext_offset..];
                    if is_fake_ip && final_proto == IP_PROTO_UDP && transport_slice.len() >= 4 {
                        let dst_port = u16::from_be_bytes([transport_slice[2], transport_slice[3]]);
                        if dst_port != 53 {
                            return FragmentOutcome::Drop;
                        }
                    }
                    let Ok(mut base_header) = <[u8; 40]>::try_from(&raw[..40]) else {
                        return FragmentOutcome::Drop;
                    };
                    let Ok(payload_len_u16) = u16::try_from(transport_slice.len()) else {
                        return FragmentOutcome::Drop;
                    };
                    base_header[6] = final_proto;
                    base_header[4..6].copy_from_slice(&payload_len_u16.to_be_bytes());
                    let mut full_packet = Vec::with_capacity(40 + transport_slice.len());
                    full_packet.extend_from_slice(&base_header);
                    full_packet.extend_from_slice(transport_slice);
                    return FragmentOutcome::Reassembled {
                        full_packet,
                        orig_fragments: vec![EmittedIpPacket {
                            data: raw.to_vec(),
                            meta,
                        }],
                    };
                }

                // 携带 post-Fragment 扩展头的 IPv6 分片（如 DestOpt/AH/Mobility -> ICMPv6/ESP/NoNext/TCP/UDP）
                // 无论首片还是后续片先到达，统一走同一重组组，待完整解析最终传输协议后再决定 Reassembled 或 PassthroughGroup；
                // 无 post-Fragment 扩展头的非 TCP/UDP 报文（如纯 ICMPv4/ICMPv6/ESP）在不冲突已有组时直接单包放行。
                let has_v6_post_frag_ext = is_ipv6 && is_ipv6_extension_header(v6_frag_next_hdr);
                if !is_fake_ip
                    && !has_v6_post_frag_ext
                    && matches!(proto, IP_PROTO_ICMPV4 | IP_PROTO_ICMPV6)
                    && !self.groups.contains_key(&key)
                {
                    return FragmentOutcome::PassthroughSingle;
                }
                let needs_reassembly = proto == IP_PROTO_TCP
                    || proto == IP_PROTO_UDP
                    || has_v6_post_frag_ext
                    || (is_ipv6 && is_ipv6_extension_header(proto));
                if !needs_reassembly {
                    self.remove_group(&key);
                    return if is_fake_ip {
                        FragmentOutcome::Drop
                    } else {
                        FragmentOutcome::PassthroughSingle
                    };
                }

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

                // Fake-IP 快速拦截：如果无前置扩展头的 UDP 首片目标端口并非 DNS 53，直接拒绝整组重组并丢弃
                if is_fake_ip
                    && proto == IP_PROTO_UDP
                    && (!is_ipv6 || v6_frag_next_hdr == IP_PROTO_UDP)
                    && frag_offset == 0
                    && frag_payload.len() >= 4
                {
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

                if is_ipv6 && frag_offset == 0 && raw.len() < 40 {
                    self.remove_group(&key);
                    return FragmentOutcome::Drop;
                }

                // 先在已有组上执行全部一致性、重复与重叠分片校验，全部通过后再调用 ensure_capacity_for，
                // 防止畸形/重叠/重复分片攻击提前驱逐其它正常重组组！
                if let Some(existing_group) = self.groups.get(&key) {
                    if let Some(prev_total) = existing_group.expected_total_len {
                        if (!more_fragments && prev_total != chunk_end) || chunk_end > prev_total {
                            self.remove_group(&key);
                            return FragmentOutcome::Drop;
                        }
                    } else if !more_fragments
                        && let Some((&last_off, last_chunk)) = existing_group.chunks.iter().next_back()
                        && last_off + last_chunk.payload.len() > chunk_end
                    {
                        self.remove_group(&key);
                        return FragmentOutcome::Drop;
                    }

                    if let Some(existing) = existing_group.chunks.get(&frag_offset) {
                        if existing.payload.as_slice() == frag_payload {
                            return FragmentOutcome::Pending;
                        }
                        self.remove_group(&key);
                        return FragmentOutcome::Drop;
                    }
                    if let Some((&prev_off, prev_chunk)) =
                        existing_group.chunks.range(..frag_offset).next_back()
                        && prev_off + prev_chunk.payload.len() > frag_offset
                    {
                        self.remove_group(&key);
                        return FragmentOutcome::Drop;
                    }
                    if let Some((&next_off, _)) =
                        existing_group.chunks.range((frag_offset + 1)..).next()
                        && chunk_end > next_off
                    {
                        self.remove_group(&key);
                        return FragmentOutcome::Drop;
                    }
                    if existing_group.chunks.len() >= MAX_CHUNKS_PER_GROUP {
                        self.remove_group(&key);
                        return FragmentOutcome::Drop;
                    }
                }

                self.ensure_capacity_for(&key, incoming_cost);

                let group = self
                    .groups
                    .entry(key)
                    .or_insert_with(|| FragmentGroup::new(now));

                if !more_fragments && group.expected_total_len.is_none() {
                    group.expected_total_len = Some(chunk_end);
                }

                if frag_offset == 0 && group.first_prefix.is_none() {
                    if is_ipv6 {
                        let Ok(base_header) = <[u8; 40]>::try_from(&raw[..40]) else {
                            self.remove_group(&key);
                            return FragmentOutcome::Drop;
                        };
                        group.first_prefix = Some(ReassemblyPrefix::Ipv6 {
                            base_header,
                            frag_next_hdr: v6_frag_next_hdr,
                        });
                    } else {
                        group.first_prefix = Some(ReassemblyPrefix::Ipv4 {
                            header: raw[..v4_ihl].to_vec(),
                        });
                    }
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
                    ReassemblyBuild::Transport {
                        full_packet,
                        orig_fragments,
                    } => FragmentOutcome::Reassembled {
                        full_packet,
                        orig_fragments,
                    },
                    ReassemblyBuild::NonTransport(orig_fragments) => {
                        if is_fake_ip {
                            FragmentOutcome::Drop
                        } else {
                            FragmentOutcome::PassthroughGroup(orig_fragments)
                        }
                    }
                    ReassemblyBuild::Malformed => FragmentOutcome::Drop,
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

enum ReassemblyBuild {
    Transport {
        full_packet: Vec<u8>,
        orig_fragments: Vec<EmittedIpPacket>,
    },
    NonTransport(Vec<EmittedIpPacket>),
    Malformed,
}

fn build_reassembled_ip_packet(group: FragmentGroup) -> ReassemblyBuild {
    let Some(total_payload_len) = group.expected_total_len else {
        return ReassemblyBuild::Malformed;
    };
    let Some(prefix) = group.first_prefix else {
        return ReassemblyBuild::Malformed;
    };

    let mut orig_fragments = Vec::with_capacity(group.chunks.len());
    let mut assembled_payload = Vec::with_capacity(total_payload_len);
    for (_, chunk) in group.chunks {
        assembled_payload.extend_from_slice(&chunk.payload);
        orig_fragments.push(chunk.raw_packet);
    }
    if assembled_payload.len() != total_payload_len {
        return ReassemblyBuild::Malformed;
    }

    match prefix {
        ReassemblyPrefix::Ipv4 { mut header } => {
            let Some(full_len) = header.len().checked_add(assembled_payload.len()) else {
                return ReassemblyBuild::Malformed;
            };
            let Ok(total_len_u16) = u16::try_from(full_len) else {
                return ReassemblyBuild::Malformed;
            };
            header[2..4].copy_from_slice(&total_len_u16.to_be_bytes());
            header[6..8].copy_from_slice(&[0, 0]);
            recompute_ipv4_checksum(&mut header);

            let mut out = Vec::with_capacity(full_len);
            out.extend_from_slice(&header);
            out.extend_from_slice(&assembled_payload);
            ReassemblyBuild::Transport {
                full_packet: out,
                orig_fragments,
            }
        }
        ReassemblyPrefix::Ipv6 {
            mut base_header,
            frag_next_hdr,
        } => {
            let ExtWalk::Transport {
                proto: final_proto,
                offset: ext_offset,
            } = walk_ipv6_ext_headers(frag_next_hdr, &assembled_payload)
            else {
                return ReassemblyBuild::Malformed;
            };
            if !matches!(final_proto, IP_PROTO_TCP | IP_PROTO_UDP) {
                return ReassemblyBuild::NonTransport(orig_fragments);
            }
            let transport_slice = &assembled_payload[ext_offset..];
            let Ok(payload_len_u16) = u16::try_from(transport_slice.len()) else {
                return ReassemblyBuild::Malformed;
            };
            base_header[6] = final_proto;
            base_header[4..6].copy_from_slice(&payload_len_u16.to_be_bytes());

            let mut out = Vec::with_capacity(40 + transport_slice.len());
            out.extend_from_slice(&base_header);
            out.extend_from_slice(transport_slice);
            ReassemblyBuild::Transport {
                full_packet: out,
                orig_fragments,
            }
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
    let proto = raw[9];
    let src_ip = IpAddr::V4(Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15])).to_canonical();
    let dst_ip = IpAddr::V4(Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19])).to_canonical();

    let flags_frag = u16::from_be_bytes([raw[6], raw[7]]);
    let more_fragments = (flags_frag & 0x2000) != 0;
    let frag_offset = ((flags_frag & 0x1FFF) as usize) * 8;

    if !more_fragments && frag_offset == 0 {
        return FragmentParse::NotFragmented { dst_ip, proto };
    }

    if total_len < ihl || raw.len() < total_len {
        return FragmentParse::Malformed;
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
        v6_frag_next_hdr: proto,
        frag_offset,
        more_fragments,
        payload_start: ihl,
        payload_end: total_len,
        v4_ihl: ihl,
        v6_frag_hdr_offset: 0,
        is_ipv6: false,
    }
}

fn parse_ipv6_fragment(raw: &[u8]) -> FragmentParse {
    if raw.len() < 40 {
        return FragmentParse::Malformed;
    }
    let payload_len = u16::from_be_bytes([raw[4], raw[5]]) as usize;
    let lso_or_oversized =
        (payload_len == 0 && raw.len() > 40) || raw.len() > 40 + u16::MAX as usize;
    let end = if lso_or_oversized {
        raw.len()
    } else {
        let Some(end) = 40usize.checked_add(payload_len) else {
            return FragmentParse::Malformed;
        };
        if end > raw.len() || payload_len == 0 {
            return FragmentParse::Malformed;
        }
        end
    };

    let Ok(src_octets) = <[u8; 16]>::try_from(&raw[8..24]) else {
        return FragmentParse::Malformed;
    };
    let Ok(dst_octets) = <[u8; 16]>::try_from(&raw[24..40]) else {
        return FragmentParse::Malformed;
    };
    let src_ip = IpAddr::V6(Ipv6Addr::from(src_octets)).to_canonical();
    let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_octets)).to_canonical();

    let mut next_hdr = raw[6];
    let mut pos = 40usize;

    for step in 0..=8 {
        match next_hdr {
            IP_PROTO_FRAGMENT => {
                if lso_or_oversized || pos + 8 > end {
                    return FragmentParse::Malformed;
                }
                let frag_next_hdr = raw[pos];
                if frag_next_hdr == IP_PROTO_FRAGMENT {
                    return FragmentParse::Malformed;
                }
                let off_m = u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]);
                let frag_offset = (off_m & 0xFFF8) as usize;
                let more_fragments = (off_m & 0x0001) != 0;
                let Ok(ident_bytes) = <[u8; 4]>::try_from(&raw[pos + 4..pos + 8]) else {
                    return FragmentParse::Malformed;
                };
                let ident = u32::from_be_bytes(ident_bytes);

                let effective_proto = if frag_offset == 0 {
                    match walk_ipv6_ext_headers(frag_next_hdr, &raw[pos + 8..end]) {
                        ExtWalk::Transport { proto, .. } => proto,
                        ExtWalk::Incomplete { next_nh } => next_nh,
                        ExtWalk::NestedFragOrMalformed => return FragmentParse::Malformed,
                    }
                } else {
                    frag_next_hdr
                };

                return FragmentParse::Fragment {
                    key: FragmentKey {
                        is_ipv6: true,
                        src_ip,
                        dst_ip,
                        proto: 0,
                        ident,
                    },
                    proto: effective_proto,
                    v6_frag_next_hdr: frag_next_hdr,
                    frag_offset,
                    more_fragments,
                    payload_start: pos + 8,
                    payload_end: end,
                    v4_ihl: 0,
                    v6_frag_hdr_offset: pos,
                    is_ipv6: true,
                };
            }
            other if is_ipv6_extension_header(other) => {
                if step == 8 {
                    return FragmentParse::Malformed;
                }
                let Some(ext_len) = ipv6_ext_header_len(other, &raw[pos..end]) else {
                    return FragmentParse::Malformed;
                };
                if pos + ext_len > end {
                    return FragmentParse::Malformed;
                }
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

    #[test]
    fn test_ipv6_fragment_with_post_fragment_dest_opt_and_ah_reassembles_and_nested_frag_drops() {
        let mut tracker = FragmentTracker::new();
        let src6 = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 10);
        let dst6 = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let meta = PacketInterfaceMeta {
            if_idx: 4,
            is_ipv6: true,
            ..Default::default()
        };

        let mut hdr = etherparse::TcpHeader::new(57000, 443, 424242, 65535);
        hdr.syn = true;
        let payload = b"HELLO_POST_FRAG!";
        let builder = PacketBuilder::ipv6(src6.octets(), dst6.octets(), 64).tcp_header(hdr);
        let mut full_v6 = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut full_v6, payload).unwrap();
        let tcp_seg = &full_v6[40..];

        // 1. 构建 [IPv6(nh=44)][Frag(nh=60)][DestOpt(8B, nh=6)][TCP SYN] 并按两片递交
        let mut fragmentable = Vec::with_capacity(8 + tcp_seg.len());
        fragmentable.extend_from_slice(&[IP_PROTO_TCP, 0, 0, 0, 0, 0, 0, 0]);
        fragmentable.extend_from_slice(tcp_seg);

        let f0 = make_ipv6_frag_packet(
            src6,
            dst6,
            IP_PROTO_DESTOPT,
            0x0BAD_F00D,
            0,
            true,
            &fragmentable[..24],
        );
        let f1 = make_ipv6_frag_packet(
            src6,
            dst6,
            IP_PROTO_DESTOPT,
            0x0BAD_F00D,
            24,
            false,
            &fragmentable[24..],
        );

        // 先收到 Fragment 1 (next_hdr = DestOpt 60)：绝不可误当作非 TCP/UDP 放行，必须 Pending
        assert!(matches!(tracker.ingest(&f1, meta, None), FragmentOutcome::Pending));
        let FragmentOutcome::Reassembled { full_packet, .. } = tracker.ingest(&f0, meta, None)
        else {
            panic!("expected IPv6 packet with post-Fragment DestOpt to reassemble cleanly");
        };
        let parsed = parse_tcp_packet(&full_packet).expect("stripped IPv6 TCP packet must parse");
        assert!(parsed.is_ipv6 && parsed.syn && parsed.dst_port == 443);
        let sliced = SlicedPacket::from_ip(&full_packet).unwrap();
        let Some(TransportSlice::Tcp(t)) = sliced.transport else {
            panic!("expected TCP slice after stripping DestOpt");
        };
        assert_eq!(t.payload(), payload);

        // 2. 嵌套分片攻击：[IPv6(nh=44)][Frag(nh=60)][DestOpt(nh=44)][Frag(nh=6)] 必须 Drop
        let mut nested_payload = Vec::new();
        nested_payload.extend_from_slice(&[IP_PROTO_FRAGMENT, 0, 0, 0, 0, 0, 0, 0]);
        nested_payload.extend_from_slice(&[IP_PROTO_TCP, 0, 0, 0, 0x11, 0x22, 0x33, 0x44]);
        nested_payload.extend_from_slice(&tcp_seg[..8]);
        let nested_pkt = make_ipv6_frag_packet(
            src6,
            dst6,
            IP_PROTO_DESTOPT,
            0xDEAD_BEEF,
            0,
            false,
            &nested_payload,
        );
        assert!(matches!(tracker.ingest(&nested_pkt, meta, None), FragmentOutcome::Drop));
        assert_eq!(tracker.active_group_count(), 0);
    }

    #[test]
    fn test_ipv6_fragment_with_mobility_hip_shim6_ext_headers() {
        let mut tracker = FragmentTracker::new();
        let src6 = Ipv6Addr::new(0x2001, 0xdb8, 2, 3, 0, 0, 0, 10);
        let dst6 = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x2222);
        let meta = PacketInterfaceMeta {
            if_idx: 6,
            is_ipv6: true,
            ..Default::default()
        };

        let mut hdr = etherparse::TcpHeader::new(58000, 443, 98765, 65535);
        hdr.syn = true;
        let payload = b"EXT135_139_140!";
        let builder = PacketBuilder::ipv6(src6.octets(), dst6.octets(), 64).tcp_header(hdr);
        let mut full_v6 = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut full_v6, payload).unwrap();
        let tcp_seg = &full_v6[40..];

        // 1. Mobility (135) -> HIP (139) -> Shim6 (140) 位于 Fragment (44) 之后：
        //    不可误判为非 TCP/UDP 扩展头而直接 PassthroughSingle，必须完整重组并交付内层 TCP
        let mut post_frag = Vec::with_capacity(24 + tcp_seg.len());
        // Mobility (nh=139, len=0 => 8B)
        post_frag.extend_from_slice(&[IP_PROTO_HIP, 0, 0, 0, 0, 0, 0, 0]);
        // HIP (nh=140, len=0 => 8B)
        post_frag.extend_from_slice(&[IP_PROTO_SHIM6, 0, 0, 0, 0, 0, 0, 0]);
        // Shim6 (nh=6 TCP, len=0 => 8B)
        post_frag.extend_from_slice(&[IP_PROTO_TCP, 0, 0, 0, 0, 0, 0, 0]);
        post_frag.extend_from_slice(tcp_seg);

        let f0 = make_ipv6_frag_packet(
            src6,
            dst6,
            IP_PROTO_MOBILITY,
            0x1351_3914,
            0,
            true,
            &post_frag[..32],
        );
        let f1 = make_ipv6_frag_packet(
            src6,
            dst6,
            IP_PROTO_MOBILITY,
            0x1351_3914,
            32,
            false,
            &post_frag[32..],
        );

        assert!(matches!(tracker.ingest(&f1, meta, None), FragmentOutcome::Pending));
        let FragmentOutcome::Reassembled {
            full_packet,
            orig_fragments,
        } = tracker.ingest(&f0, meta, None)
        else {
            panic!("expected Mobility/HIP/Shim6 post-Fragment IPv6 TCP packet to reassemble");
        };
        assert_eq!(orig_fragments.len(), 2);
        let parsed = parse_tcp_packet(&full_packet).expect("reassembled TCP must parse");
        assert!(parsed.is_ipv6 && parsed.syn && parsed.dst_port == 443);

        // 2. Mobility (135) 位于 Fragment (44) 之前，HIP (139) 位于 Fragment 之后：
        //    构建 [IPv6(nh=135)][Mobility(8B, nh=44)][Frag(nh=139)][HIP(8B, nh=6)][TCP SYN]
        let mut pre_post_payload = Vec::with_capacity(8 + tcp_seg.len());
        pre_post_payload.extend_from_slice(&[IP_PROTO_TCP, 0, 0, 0, 0, 0, 0, 0]);
        pre_post_payload.extend_from_slice(tcp_seg);
        let build_pre_frag = |offset: usize, mf: bool, chunk: &[u8]| -> Vec<u8> {
            let mut out = Vec::with_capacity(40 + 8 + 8 + chunk.len());
            out.extend_from_slice(&[0x60, 0, 0, 0]);
            out.extend_from_slice(&((8 + 8 + chunk.len()) as u16).to_be_bytes());
            out.push(IP_PROTO_MOBILITY);
            out.push(64);
            out.extend_from_slice(&src6.octets());
            out.extend_from_slice(&dst6.octets());
            // Mobility ext hdr -> nh=44, hdrlen=0 (8B)
            out.extend_from_slice(&[IP_PROTO_FRAGMENT, 0, 0, 0, 0, 0, 0, 0]);
            // Fragment hdr -> nh=139
            out.push(IP_PROTO_HIP);
            out.push(0);
            let off_m = ((offset as u16) & 0xFFF8) | if mf { 1 } else { 0 };
            out.extend_from_slice(&off_m.to_be_bytes());
            out.extend_from_slice(&0x9988_7766u32.to_be_bytes());
            out.extend_from_slice(chunk);
            out
        };
        let pf0 = build_pre_frag(0, true, &pre_post_payload[..16]);
        let pf1 = build_pre_frag(16, false, &pre_post_payload[16..]);
        assert!(matches!(tracker.ingest(&pf0, meta, None), FragmentOutcome::Pending));
        let FragmentOutcome::Reassembled { full_packet: full2, .. } =
            tracker.ingest(&pf1, meta, None)
        else {
            panic!("expected pre-Fragment Mobility + post-Fragment HIP packet to reassemble");
        };
        let parsed2 = parse_tcp_packet(&full2).expect("reassembled pre/post ext TCP must parse");
        assert!(parsed2.is_ipv6 && parsed2.syn && parsed2.dst_port == 443);

        // 3. 验证单包未分片且含 SHIM6 (140) 前置扩展头的 IPv6-mapped Fake-IP UDP 包被拦截而非 passthrough
        let fake_pool = FakeIpPool::new_default();
        let fake_v4 = fake_pool.allocate("hip-shim6.example");
        let fake_v6 = fake_v4.to_ipv6_mapped();
        let mut fake_shim6_udp = Vec::with_capacity(40 + 8 + 12);
        fake_shim6_udp.extend_from_slice(&[0x60, 0, 0, 0]);
        fake_shim6_udp.extend_from_slice(&(20u16).to_be_bytes());
        fake_shim6_udp.push(IP_PROTO_SHIM6);
        fake_shim6_udp.push(64);
        fake_shim6_udp.extend_from_slice(&src6.octets());
        fake_shim6_udp.extend_from_slice(&fake_v6.octets());
        // SHIM6 ext hdr (8B) -> nh = UDP (17)
        fake_shim6_udp.extend_from_slice(&[IP_PROTO_UDP, 0, 0, 0, 0, 0, 0, 0]);
        // 截断/普通 UDP payload
        fake_shim6_udp.extend_from_slice(&[0x30, 0x39, 0x01, 0xBB, 0x00, 0x0C, 0, 0, 1, 2, 3, 4]);
        assert!(matches!(
            tracker.ingest(&fake_shim6_udp, meta, Some(&fake_pool)),
            FragmentOutcome::Drop
        ));
    }

    #[test]
    fn test_fragment_rfc6946_atomic_isolation_post_frag_non_tcp_8th_ext_header_and_eviction_order() {
        let mut tracker = FragmentTracker::new();
        let meta = PacketInterfaceMeta {
            is_ipv6: true,
            ..Default::default()
        };
        let src6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
        let dst6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 20);

        // 1. RFC 6946: 同 ID 的普通分片正在等待时，到达的原子分片 (offset=0, !M) 必须独立完成且绝不破坏原有重组组
        let mut full_tcp = Vec::new();
        PacketBuilder::ipv6(src6.octets(), dst6.octets(), 64)
            .tcp(50000, 443, 1, 65535)
            .syn()
            .write(&mut full_tcp, &[])
            .unwrap();
        let tcp_seg = &full_tcp[40..];
        let shared_id = 0xCAFE_0001u32;
        let normal_f0 = make_ipv6_frag_packet(src6, dst6, IP_PROTO_TCP, shared_id, 0, true, &tcp_seg[..16]);
        let normal_f1 = make_ipv6_frag_packet(src6, dst6, IP_PROTO_TCP, shared_id, 16, false, &tcp_seg[16..]);
        let atomic = make_ipv6_frag_packet(src6, dst6, IP_PROTO_TCP, shared_id, 0, false, tcp_seg);

        assert!(matches!(tracker.ingest(&normal_f0, meta, None), FragmentOutcome::Pending));
        assert_eq!(tracker.active_group_count(), 1);
        assert!(matches!(
            tracker.ingest(&atomic, meta, None),
            FragmentOutcome::Reassembled { .. }
        ));
        assert_eq!(
            tracker.active_group_count(),
            1,
            "RFC 6946 atomic fragment must not disturb existing pending group with same ident"
        );
        assert!(matches!(
            tracker.ingest(&normal_f1, meta, None),
            FragmentOutcome::Reassembled { .. }
        ));
        assert_eq!(tracker.active_group_count(), 0);

        // 2. Post-Fragment 扩展头后接非 TCP/UDP (ICMPv6 58 / ESP 50 / NoNext 59)：无论分片乱序与否均平滑 PassthroughGroup
        for non_transport_proto in [IP_PROTO_ICMPV6, 50u8, 59u8] {
            let mut post_payload = Vec::new();
            post_payload.extend_from_slice(&[non_transport_proto, 0, 0, 0, 0, 0, 0, 0]); // DestOpt 8B -> proto
            post_payload.extend_from_slice(&[0xAA; 16]);
            let f0 = make_ipv6_frag_packet(
                src6,
                dst6,
                IP_PROTO_DESTOPT,
                0xABCD_0000 + non_transport_proto as u32,
                0,
                true,
                &post_payload[..16],
            );
            let f1 = make_ipv6_frag_packet(
                src6,
                dst6,
                IP_PROTO_DESTOPT,
                0xABCD_0000 + non_transport_proto as u32,
                16,
                false,
                &post_payload[16..],
            );
            // 先收 f1 再收 f0，确认不丢弃也不卡死
            assert!(matches!(tracker.ingest(&f1, meta, None), FragmentOutcome::Pending));
            match tracker.ingest(&f0, meta, None) {
                FragmentOutcome::PassthroughGroup(frags) => assert_eq!(frags.len(), 2),
                other => panic!(
                    "expected PassthroughGroup for post-frag proto {non_transport_proto}, got {other:?}"
                ),
            }
        }

        // 3. 第 8 层扩展头边界：8 个有效扩展头 + TCP 必须通过；9 个扩展头必须返回 Malformed/Drop
        let mut ext8_data = Vec::new();
        for _ in 0..7 {
            ext8_data.extend_from_slice(&[IP_PROTO_DESTOPT, 0, 0, 0, 0, 0, 0, 0]);
        }
        ext8_data.extend_from_slice(&[IP_PROTO_TCP, 0, 0, 0, 0, 0, 0, 0]);
        assert!(matches!(
            walk_ipv6_ext_headers(IP_PROTO_DESTOPT, &ext8_data),
            ExtWalk::Transport { proto: IP_PROTO_TCP, offset: 64 }
        ));
        let mut ext9_data = Vec::new();
        for _ in 0..8 {
            ext9_data.extend_from_slice(&[IP_PROTO_DESTOPT, 0, 0, 0, 0, 0, 0, 0]);
        }
        ext9_data.extend_from_slice(&[IP_PROTO_TCP, 0, 0, 0, 0, 0, 0, 0]);
        assert!(matches!(
            walk_ipv6_ext_headers(IP_PROTO_DESTOPT, &ext9_data),
            ExtWalk::NestedFragOrMalformed
        ));

        // 4. ensure_capacity_for 滞后于重叠/重复校验：满容时收到某已有组的非法重叠片仅丢弃该组，不驱逐其他健康组
        let mut cap_tracker = FragmentTracker::new();
        let meta4 = PacketInterfaceMeta::default();
        let t0 = Instant::now();
        for i in 0..MAX_FRAGMENT_GROUPS {
            let pkt = make_ipv4_packet(
                [10, 0, (i >> 8) as u8, (i & 0xFF) as u8],
                [93, 184, 216, 34],
                IP_PROTO_UDP,
                (i as u16).wrapping_add(1),
                0,
                true,
                &[0u8; 16],
            );
            assert!(matches!(
                cap_tracker.ingest_at(t0 + Duration::from_micros(i as u64), &pkt, meta4, None),
                FragmentOutcome::Pending
            ));
        }
        assert_eq!(cap_tracker.active_group_count(), MAX_FRAGMENT_GROUPS);
        // 给最后一组发送重叠分片（offset=8 与已有 0..16 重叠）：应仅删除该组（变成 MAX-1），绝不误删最早的健康组 (i=0)
        let last = MAX_FRAGMENT_GROUPS - 1;
        let overlap = make_ipv4_packet(
            [10, 0, (last >> 8) as u8, (last & 0xFF) as u8],
            [93, 184, 216, 34],
            IP_PROTO_UDP,
            (last as u16).wrapping_add(1),
            8,
            false,
            &[1u8; 16],
        );
        assert!(matches!(
            cap_tracker.ingest_at(t0 + Duration::from_secs(1), &overlap, meta4, None),
            FragmentOutcome::Drop
        ));
        assert_eq!(cap_tracker.active_group_count(), MAX_FRAGMENT_GROUPS - 1);
        // 验证最早的健康组 (i=0) 仍然存活并可正常完成重组
        let finish_first = make_ipv4_packet(
            [10, 0, 0, 0],
            [93, 184, 216, 34],
            IP_PROTO_UDP,
            1,
            16,
            false,
            &[2u8; 8],
        );
        assert!(matches!(
            cap_tracker.ingest_at(t0 + Duration::from_secs(1), &finish_first, meta4, None),
            FragmentOutcome::Reassembled { .. }
        ));
    }
}
