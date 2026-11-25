use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6};
use std::sync::RwLock;
use std::time::{Duration, Instant};

mod codec;
pub mod server;
mod upstream;

const MAX_REAL_IP_MAPPINGS: usize = 16_384;
const MAX_REAL_IP_MAPPING_TTL: Duration = Duration::from_secs(120);
const MIN_REAL_IP_MAPPING_TTL: Duration = Duration::from_secs(5);
const MAX_ORIG_DNS_PER_DOMAIN: usize = 4;

/// 规范化套接字地址：将 IPv4-mapped IPv6 (`[::ffff:a.b.c.d]:port`) 还原为原生 IPv4，
/// 同时完整保留纯 IPv6 的 `flowinfo` 与 `scope_id`（供 `fe80::` 链路本地接口路由使用）。
pub(crate) fn canonicalize_socket_addr_preserving_scope(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddr::V4(v4),
        SocketAddr::V6(v6) => {
            if let Some(mapped) = v6.ip().to_ipv4_mapped() {
                SocketAddr::new(IpAddr::V4(mapped), v6.port())
            } else {
                SocketAddr::V6(SocketAddrV6::new(
                    *v6.ip(),
                    v6.port(),
                    v6.flowinfo(),
                    v6.scope_id(),
                ))
            }
        }
    }
}

/// 校验并规范化可用于回源解析的上游 DNS 服务器地址：
/// - 剔除端口 0、未指定地址 (`0.0.0.0`/`::`)、广播 (`255.255.255.255`)、多播、IPv4 链路本地 (`169.254/16`)、
///   缺少 `scope_id` 的 IPv6 链路本地 (`fe80::/10` 且 `scope_id == 0`)、Fake-IP 及指向 FlowX 自身服务端口的地址；
/// - 保留有效 `scope_id != 0` 的 IPv6 链路本地 DNS 与非自端口本地/企业 DNS。
pub(crate) fn sanitize_upstream_dns_addr(
    addr: SocketAddr,
    fake_ip_pool: Option<&FakeIpPool>,
    self_ports: &[u16],
) -> Option<SocketAddr> {
    let canon = canonicalize_socket_addr_preserving_scope(addr);
    if canon.port() == 0 {
        return None;
    }
    let ip = canon.ip();
    let unusable = match canon {
        SocketAddr::V4(v4) => {
            let ip4 = v4.ip();
            ip4.is_unspecified() || ip4.is_broadcast() || ip4.is_multicast() || ip4.is_link_local()
        }
        SocketAddr::V6(v6) => {
            let ip6 = v6.ip();
            ip6.is_unspecified()
                || ip6.is_multicast()
                || (ip6.is_unicast_link_local() && v6.scope_id() == 0)
        }
    };
    if unusable {
        return None;
    }
    if fake_ip_pool.is_some_and(|p| p.is_fake_ip_addr(ip))
        || FakeIpPool::is_default_fake_ip_addr(ip)
    {
        return None;
    }
    if !self_ports.is_empty() && self_ports.contains(&canon.port()) {
        let local_ips = crate::outbound::local_interface_ips();
        if crate::outbound::is_local_or_loopback_ip(ip, &local_ips) {
            return None;
        }
    }
    Some(canon)
}

#[inline]
fn is_private_or_local_dns_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private() || v4.is_loopback() || (a == 100 && (64..=127).contains(&b)) // RFC 6598 CGNAT (Tailscale/VPN)
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            v6.is_loopback() || v6.is_unicast_link_local() || (seg0 & 0xfe00) == 0xfc00 // RFC 4193 ULA
        }
    }
}

fn push_orig_dns(list: &mut Vec<SocketAddr>, dns: SocketAddr) -> bool {
    if list.contains(&dns) {
        return false;
    }
    if list.len() < MAX_ORIG_DNS_PER_DOMAIN {
        // 企业/内网/VPN DNS 优先排在公网 DNS 之前，但不覆盖先到同级别条目
        if is_private_or_local_dns_ip(dns.ip())
            && let Some(first_public_idx) = list
                .iter()
                .position(|a| !is_private_or_local_dns_ip(a.ip()))
        {
            list.insert(first_public_idx, dns);
        } else {
            list.push(dns);
        }
        return true;
    }
    // 满容时：仅允许内网/VPN DNS 替换末尾的公网 DNS，避免抖动
    if is_private_or_local_dns_ip(dns.ip())
        && let Some(last_public_idx) = list
            .iter()
            .rposition(|a| !is_private_or_local_dns_ip(a.ip()))
    {
        list.remove(last_public_idx);
        let insert_idx = list
            .iter()
            .position(|a| !is_private_or_local_dns_ip(a.ip()))
            .unwrap_or(list.len());
        list.insert(insert_idx, dns);
        return true;
    }
    false
}

/// Fake-IP 线程安全分配池与双向映射表（Fake-IP 池与被动真实 IP 反查缓存采用独立读写锁隔离争用）
#[derive(Debug)]
pub struct FakeIpPool {
    min: u32,
    max: u32,
    inner: RwLock<PoolState>,
    real_ip_cache: RwLock<RealIpState>,
    ttl: Duration,
    self_ports: Vec<u16>,
}

#[derive(Debug, Clone)]
struct FakeIpEntry {
    domain: String,
    expire: Instant,
    seq: u64,
    /// 记录该域名在当前有效 TTL 内观测到的原始上游 DNS 列表（最多 4 个，内网/VPN DNS 优先且互不覆盖）
    orig_dns: Vec<SocketAddr>,
}

#[derive(Debug, Clone)]
enum RealIpMapping {
    /// 有效 TTL 内仅观测到单一域名解析至该真实 IP（可用于规则域名辅助匹配）
    Unique { domain: String, expire: Instant },
    /// 有效 TTL 内观测到多个不同域名共享该 IP（CDN/反代/Anycast）：
    /// 在 `conflict_until` 到期前一律返回 `None`，但不因单一活跃域名持续刷新而无限顺延冲突窗口。
    Ambiguous {
        latest_domain: String,
        latest_expire: Instant,
        conflict_until: Instant,
    },
}

impl RealIpMapping {
    fn expire(&self) -> Instant {
        match self {
            Self::Unique { expire, .. } => *expire,
            Self::Ambiguous {
                latest_expire,
                conflict_until,
                ..
            } => (*latest_expire).max(*conflict_until),
        }
    }
}

#[derive(Debug, Clone)]
struct RealIpEntry {
    mapping: RealIpMapping,
    seq: u64,
}

#[derive(Debug, Default)]
struct RealIpState {
    seq: u64,
    map: HashMap<IpAddr, RealIpEntry>,
    expiry_heap: BinaryHeap<Reverse<(Instant, u64, IpAddr)>>,
}

impl RealIpState {
    fn rebuild_heap(&mut self) {
        self.expiry_heap.clear();
        for (&ip, entry) in &self.map {
            self.expiry_heap
                .push(Reverse((entry.mapping.expire(), entry.seq, ip)));
        }
    }

    fn prune_expired(&mut self, now: Instant) {
        while let Some(&Reverse((exp, seq, ip))) = self.expiry_heap.peek() {
            if exp > now {
                break;
            }
            self.expiry_heap.pop();
            if self
                .map
                .get(&ip)
                .is_some_and(|e| e.seq == seq && e.mapping.expire() <= now)
            {
                self.map.remove(&ip);
            }
        }
        if self.expiry_heap.len() > self.map.len().saturating_mul(4).max(256) {
            self.rebuild_heap();
        }
    }

    fn pop_oldest_live(&mut self) -> Option<IpAddr> {
        while let Some(Reverse((exp, seq, ip))) = self.expiry_heap.pop() {
            if self
                .map
                .get(&ip)
                .is_some_and(|e| e.seq == seq && e.mapping.expire() == exp)
            {
                self.map.remove(&ip);
                return Some(ip);
            }
        }
        None
    }

    fn push_entry(&mut self, ip: IpAddr, mapping: RealIpMapping) {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let exp = mapping.expire();
        self.map.insert(ip, RealIpEntry { mapping, seq });
        self.expiry_heap.push(Reverse((exp, seq, ip)));
        if self.expiry_heap.len() > self.map.len().saturating_mul(4).max(256) {
            self.rebuild_heap();
        }
    }
}

#[derive(Debug)]
struct PoolState {
    current: u32,
    alloc_seq: u64,
    ip_to_domain: HashMap<Ipv4Addr, FakeIpEntry>,
    domain_to_ip: HashMap<String, (Ipv4Addr, Instant)>,
    expiry_heap: BinaryHeap<Reverse<(Instant, u64, u32)>>,
}

impl PoolState {
    fn new(start: u32) -> Self {
        Self {
            current: start,
            alloc_seq: 0,
            ip_to_domain: HashMap::new(),
            domain_to_ip: HashMap::new(),
            expiry_heap: BinaryHeap::new(),
        }
    }

    fn record_mapping(
        &mut self,
        ip: Ipv4Addr,
        domain: String,
        expire: Instant,
        orig_dns: Vec<SocketAddr>,
    ) {
        self.alloc_seq = self.alloc_seq.wrapping_add(1);
        let seq = self.alloc_seq;
        self.domain_to_ip.insert(domain.clone(), (ip, expire));
        self.ip_to_domain.insert(
            ip,
            FakeIpEntry {
                domain,
                expire,
                seq,
                orig_dns,
            },
        );
        self.expiry_heap.push(Reverse((expire, seq, u32::from(ip))));
        if self.expiry_heap.len() > self.ip_to_domain.len().saturating_mul(4).max(256) {
            self.rebuild_expiry_heap();
        }
    }

    fn rebuild_expiry_heap(&mut self) {
        self.expiry_heap.clear();
        for (&ip, entry) in &self.ip_to_domain {
            self.expiry_heap
                .push(Reverse((entry.expire, entry.seq, u32::from(ip))));
        }
    }

    fn pop_oldest_ip(&mut self) -> Option<Ipv4Addr> {
        while let Some(Reverse((exp, seq, ip_raw))) = self.expiry_heap.pop() {
            let ip = Ipv4Addr::from(ip_raw);
            if self
                .ip_to_domain
                .get(&ip)
                .is_some_and(|entry| entry.expire == exp && entry.seq == seq)
            {
                return Some(ip);
            }
        }
        None
    }
}

impl FakeIpPool {
    /// 默认采用 IETF 规范定义的保留基准测试网段 198.18.0.0/15 (共包含 131,070 个可用 IP)
    pub fn new_default() -> Self {
        // 范围: 198.18.0.1 ~ 198.19.255.254
        let min = u32::from(Ipv4Addr::new(198, 18, 0, 1));
        let max = u32::from(Ipv4Addr::new(198, 19, 255, 254));

        Self {
            min,
            max,
            inner: RwLock::new(PoolState::new(min)),
            real_ip_cache: RwLock::new(RealIpState::default()),
            ttl: Duration::from_secs(600), // 默认映射保留 10 分钟
            self_ports: Vec::new(),
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn with_self_ports(mut self, self_ports: Vec<u16>) -> Self {
        self.self_ports = self_ports;
        self
    }

    pub(crate) fn self_ports(&self) -> &[u16] {
        &self.self_ports
    }

    /// 为指定域名分配或复用一个 Fake-IP（采用 Double-Checked Locking 消除 TOCTOU 竞态）
    ///
    /// 命中已有映射时会滑动续期 TTL，保证仍在被查询的活跃域名不会因固定 TTL 到期而被回收重分配。
    pub fn allocate(&self, domain: &str) -> Ipv4Addr {
        self.allocate_with_dns(domain, None)
    }

    /// 为指定域名分配或复用 Fake-IP，同时可选记录该查询原本发往的上游 DNS（供 `Direct` 流量回源解析企业/内网分域 DNS）
    pub fn allocate_with_dns(&self, domain: &str, orig_dns: Option<SocketAddr>) -> Ipv4Addr {
        let domain_lower = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let orig_dns = orig_dns
            .and_then(|addr| sanitize_upstream_dns_addr(addr, Some(self), &self.self_ports));
        let now = Instant::now();
        let refresh_threshold = now + self.ttl / 2;

        // 1. 读锁快速路径：若已存在且剩余寿命充足且无需补充新 orig_dns 则直接复用（双 DNS 交替命中零写锁抖动）
        {
            let state = self.inner.read().unwrap_or_else(|e| e.into_inner());
            if let Some((ip, expire)) = state.domain_to_ip.get(&domain_lower)
                && *expire > refresh_threshold
            {
                let dns_satisfied = match orig_dns {
                    None => true,
                    Some(dns) => state.ip_to_domain.get(ip).is_some_and(|entry| {
                        entry.orig_dns.contains(&dns)
                            || (entry.orig_dns.len() >= MAX_ORIG_DNS_PER_DOMAIN
                                && (!is_private_or_local_dns_ip(dns.ip())
                                    || entry
                                        .orig_dns
                                        .iter()
                                        .all(|a| is_private_or_local_dns_ip(a.ip()))))
                    }),
                };
                if dns_satisfied {
                    return *ip;
                }
            }
        }

        // 2. 写锁路径：续期已有映射或分配新 IP，Double-Check 确保锁升级间隙未被并发线程抢占
        let mut state = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let expire = now + self.ttl;

        // 已有映射（即使已过期）只要其 IP 尚未被转让给其它域名，就原地续期复用，
        // 避免客户端仍缓存旧 IP 时出现域名无法还原的问题；
        // 但仅当 `existing.expire > now` 时才保留历史 orig_dns，绝不复活已过期条目上遗留的失效 VPN DNS。
        if let Some((ip, _)) = state.domain_to_ip.get(&domain_lower).copied()
            && let Some(existing) = state.ip_to_domain.get(&ip)
            && existing.domain == domain_lower
        {
            let merged_dns = if existing.expire > now {
                let mut list = existing.orig_dns.clone();
                if let Some(dns) = orig_dns {
                    push_orig_dns(&mut list, dns);
                }
                list
            } else {
                orig_dns.into_iter().collect()
            };
            state.record_mapping(ip, domain_lower, expire, merged_dns);
            return ip;
        }

        // 从环形游标起探测首个空闲或已过期槽位；池已满时直接使用 O(log N) 过期优先堆淘汰
        let cap = (self.max - self.min) as usize + 1;
        let chosen_ip = if state.ip_to_domain.len() < cap {
            let mut cursor = state.current;
            let mut found = None;
            for _ in 0..cap {
                let candidate = Ipv4Addr::from(cursor);
                cursor = if cursor >= self.max {
                    self.min
                } else {
                    cursor + 1
                };
                match state.ip_to_domain.get(&candidate) {
                    None => {
                        found = Some(candidate);
                        break;
                    }
                    Some(entry) if entry.expire <= now => {
                        found = Some(candidate);
                        break;
                    }
                    Some(_) => {}
                }
            }
            state.current = cursor;
            found
        } else {
            None
        };

        let ip = match chosen_ip {
            Some(ip) => ip,
            None => state
                .pop_oldest_ip()
                .unwrap_or_else(|| Ipv4Addr::from(self.min)),
        };

        // 若当前选中的 IP 之前绑定过其它域名，清理其旧的逆向映射
        let old_domain_opt = state.ip_to_domain.get(&ip).map(|e| e.domain.clone());
        if let Some(old_domain) = old_domain_opt {
            state.domain_to_ip.remove(&old_domain);
        }

        state.record_mapping(ip, domain_lower, expire, orig_dns.into_iter().collect());

        ip
    }

    /// 从 Fake-IP 还原原始域名与记录的全部原始上游 DNS 列表 (O(1) 复杂度)，并对仍在使用中的映射滑动续期；
    /// 若条目在 GC 前已过期，则清空陈旧 `orig_dns` 防止复活已断开 VPN 的失效 DNS。
    pub fn restore_with_dns_list(&self, ip: &Ipv4Addr) -> Option<(String, Vec<SocketAddr>)> {
        let now = Instant::now();
        let refresh_threshold = now + self.ttl / 2;
        {
            let state = self.inner.read().unwrap_or_else(|e| e.into_inner());
            match state.ip_to_domain.get(ip) {
                None => return None,
                Some(entry) if entry.expire > refresh_threshold => {
                    return Some((entry.domain.clone(), entry.orig_dns.clone()));
                }
                Some(_) => {}
            }
        }

        let mut state = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let (domain, orig_dns) = state.ip_to_domain.get(ip).map(|e| {
            let dns = if e.expire > now {
                e.orig_dns.clone()
            } else {
                Vec::new()
            };
            (e.domain.clone(), dns)
        })?;
        let expire = now + self.ttl;
        state.record_mapping(*ip, domain.clone(), expire, orig_dns.clone());
        Some((domain, orig_dns))
    }

    /// 从 Fake-IP 还原原始域名与首选原始上游 DNS (O(1) 复杂度)，并对仍在使用中的映射滑动续期
    pub fn restore_with_dns(&self, ip: &Ipv4Addr) -> Option<(String, Option<SocketAddr>)> {
        self.restore_with_dns_list(ip)
            .map(|(domain, dns_list)| (domain, dns_list.into_iter().next()))
    }

    /// 从 Fake-IP 还原原始域名 (O(1) 复杂度)，并对仍在使用中的映射滑动续期
    pub fn restore(&self, ip: &Ipv4Addr) -> Option<String> {
        self.restore_with_dns_list(ip).map(|(d, _)| d)
    }

    /// 将 `IpAddr` 中的原生 IPv4 或 IPv4-mapped IPv6 (`::ffff:a.b.c.d`) 统一解包为 IPv4
    pub fn unwrap_ipv4(ip: IpAddr) -> Option<Ipv4Addr> {
        match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(v6) => v6.to_ipv4_mapped(),
        }
    }

    /// 判断指定 IP 是否落在 Fake-IP 保留网段内
    pub fn is_fake_ip(&self, ip: &Ipv4Addr) -> bool {
        let raw = u32::from(*ip);
        raw >= self.min && raw <= self.max
    }

    /// 判断任意 IPv4 / IPv4-mapped IPv6 地址是否落在当前 Fake-IP 池内
    pub fn is_fake_ip_addr(&self, ip: IpAddr) -> bool {
        Self::unwrap_ipv4(ip).is_some_and(|v4| self.is_fake_ip(&v4))
    }

    /// 从任意 IPv4 / IPv4-mapped IPv6 中还原 Fake-IP 对应的原始域名及全部原始上游 DNS 候选
    pub fn restore_ip_with_dns_list(&self, ip: IpAddr) -> Option<(String, Vec<SocketAddr>)> {
        Self::unwrap_ipv4(ip).and_then(|v4| self.restore_with_dns_list(&v4))
    }

    /// 从任意 IPv4 / IPv4-mapped IPv6 中还原 Fake-IP 对应的原始域名及首选原始上游 DNS
    pub fn restore_ip_with_dns(&self, ip: IpAddr) -> Option<(String, Option<SocketAddr>)> {
        Self::unwrap_ipv4(ip).and_then(|v4| self.restore_with_dns(&v4))
    }

    /// 从任意 IPv4 / IPv4-mapped IPv6 中还原 Fake-IP 对应的原始域名
    pub fn restore_ip(&self, ip: IpAddr) -> Option<String> {
        self.restore_ip_with_dns_list(ip).map(|(d, _)| d)
    }

    /// 判断 IPv4 地址是否落在默认 Fake-IP 保留网段 (`198.18.0.0/15`)
    pub fn is_default_fake_ip(ip: &Ipv4Addr) -> bool {
        (u32::from(*ip) & 0xFFFE_0000) == 0xC612_0000
    }

    /// 判断任意 IPv4 / IPv4-mapped IPv6 地址是否落在默认 Fake-IP 保留网段
    pub fn is_default_fake_ip_addr(ip: IpAddr) -> bool {
        Self::unwrap_ipv4(ip).is_some_and(|v4| Self::is_default_fake_ip(&v4))
    }

    /// 返回当前池中映射条目数
    pub fn len(&self) -> usize {
        let state = self.inner.read().unwrap_or_else(|e| e.into_inner());
        state.ip_to_domain.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 清理池中全部已过期的映射条目（先持读锁窥探堆顶，无过期项时零写锁开销）
    pub fn cleanup_expired(&self) -> usize {
        let now = Instant::now();
        let fake_has_expired = {
            let state = self.inner.read().unwrap_or_else(|e| e.into_inner());
            state
                .expiry_heap
                .peek()
                .is_some_and(|Reverse((exp, _, _))| *exp <= now)
        };
        let cleaned_fake = if fake_has_expired {
            let mut state = self.inner.write().unwrap_or_else(|e| e.into_inner());
            let before_count = state.ip_to_domain.len();
            state.ip_to_domain.retain(|_, entry| entry.expire > now);
            state.domain_to_ip.retain(|_, (_, expire)| *expire > now);
            while state
                .expiry_heap
                .peek()
                .is_some_and(|Reverse((exp, _, _))| *exp <= now)
            {
                state.expiry_heap.pop();
            }
            if state.expiry_heap.len() > state.ip_to_domain.len().saturating_mul(4).max(256) {
                state.rebuild_expiry_heap();
            }
            before_count.saturating_sub(state.ip_to_domain.len())
        } else {
            0
        };

        let real_has_expired = {
            let state = self.real_ip_cache.read().unwrap_or_else(|e| e.into_inner());
            state
                .expiry_heap
                .peek()
                .is_some_and(|Reverse((exp, _, _))| *exp <= now)
        };
        if real_has_expired {
            let mut state = self
                .real_ip_cache
                .write()
                .unwrap_or_else(|e| e.into_inner());
            state.prune_expired(now);
        }

        cleaned_fake
    }

    /// 记录通过被动 DNS 探测观测到的 真实单播 IP -> 域名 反向映射（使用默认上限 TTL）
    pub fn record_real_ip_mappings(&self, domain: &str, ips: &[IpAddr]) {
        self.record_real_ip_mappings_with_ttl(domain, ips, None);
    }

    /// 记录通过被动 DNS 探测观测到的 真实单播 IP -> 域名 反向映射：
    /// - 独立读写锁 + $O(\log N)$ 最小堆淘汰，绝不阻塞 Fake-IP 热路径；
    /// - 自动按 DNS 应答 TTL 裁剪并封顶至 `MAX_REAL_IP_MAPPING_TTL` (120s)；
    /// - 同一 IP 在 TTL 内被两个不同域名命中时自动标记为 `Ambiguous`，防止共享 CDN/反代互相覆盖。
    pub fn record_real_ip_mappings_with_ttl(
        &self,
        domain: &str,
        ips: &[IpAddr],
        ttl_hint: Option<Duration>,
    ) {
        let domain_lower = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain_lower.is_empty() || ips.is_empty() {
            return;
        }
        let mut valid_ips: Vec<IpAddr> = Vec::with_capacity(ips.len());
        for &ip in ips {
            let canon = ip.to_canonical();
            let usable = match canon {
                IpAddr::V4(v4) => {
                    !v4.is_loopback()
                        && !v4.is_unspecified()
                        && !v4.is_broadcast()
                        && !v4.is_multicast()
                        && !v4.is_link_local()
                        && !self.is_fake_ip(&v4)
                }
                IpAddr::V6(v6) => {
                    !v6.is_loopback()
                        && !v6.is_unspecified()
                        && !v6.is_multicast()
                        && !v6.is_unicast_link_local()
                }
            };
            if usable && !valid_ips.contains(&canon) {
                valid_ips.push(canon);
            }
        }
        if valid_ips.is_empty() {
            return;
        }

        let base_cap = self.ttl.min(MAX_REAL_IP_MAPPING_TTL);
        let min_cap = MIN_REAL_IP_MAPPING_TTL.min(base_cap);
        let effective_ttl = ttl_hint
            .map(|d| d.clamp(min_cap, base_cap))
            .unwrap_or(base_cap);

        let now = Instant::now();
        let expire = now + effective_ttl;
        let mut state = self
            .real_ip_cache
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let new_keys_needed = valid_ips
            .iter()
            .filter(|ip| !state.map.contains_key(ip))
            .count();
        if state.map.len() + new_keys_needed > MAX_REAL_IP_MAPPINGS {
            state.prune_expired(now);
            let recalc_needed = valid_ips
                .iter()
                .filter(|ip| !state.map.contains_key(ip))
                .count();
            while state.map.len() + recalc_needed > MAX_REAL_IP_MAPPINGS {
                if state.pop_oldest_live().is_none() {
                    break;
                }
            }
        }
        for ip in valid_ips {
            let next_mapping = match state.map.get(&ip).map(|e| &e.mapping) {
                Some(RealIpMapping::Unique {
                    domain: existing,
                    expire: old_exp,
                }) if *old_exp > now => {
                    let merged_exp = (*old_exp).max(expire);
                    if *existing == domain_lower {
                        RealIpMapping::Unique {
                            domain: domain_lower.clone(),
                            expire: merged_exp,
                        }
                    } else {
                        RealIpMapping::Ambiguous {
                            latest_domain: domain_lower.clone(),
                            latest_expire: expire,
                            conflict_until: merged_exp,
                        }
                    }
                }
                Some(RealIpMapping::Ambiguous {
                    latest_domain,
                    latest_expire,
                    conflict_until,
                }) if (*latest_expire).max(*conflict_until) > now => {
                    if *latest_domain == domain_lower {
                        if now >= *conflict_until {
                            RealIpMapping::Unique {
                                domain: domain_lower.clone(),
                                expire: (*latest_expire).max(expire),
                            }
                        } else {
                            RealIpMapping::Ambiguous {
                                latest_domain: domain_lower.clone(),
                                latest_expire: (*latest_expire).max(expire),
                                conflict_until: *conflict_until,
                            }
                        }
                    } else if now >= *conflict_until && now >= *latest_expire {
                        RealIpMapping::Unique {
                            domain: domain_lower.clone(),
                            expire,
                        }
                    } else {
                        RealIpMapping::Ambiguous {
                            latest_domain: domain_lower.clone(),
                            latest_expire: expire,
                            conflict_until: (*conflict_until).max(*latest_expire).max(expire),
                        }
                    }
                }
                _ => RealIpMapping::Unique {
                    domain: domain_lower.clone(),
                    expire,
                },
            };
            state.push_entry(ip, next_mapping);
        }
    }

    /// 仅当该真实 IP 在有效 TTL 内唯一归属单一域名时返回对应域名；若多个域名共享该 IP (`Ambiguous` 冲突期内) 或已过期则返回 `None`
    pub fn lookup_real_ip_domain(&self, ip: IpAddr) -> Option<String> {
        let canon = ip.to_canonical();
        let now = Instant::now();
        let state = self.real_ip_cache.read().unwrap_or_else(|e| e.into_inner());
        match state.map.get(&canon).map(|e| &e.mapping) {
            Some(RealIpMapping::Unique { domain, expire }) if *expire > now => Some(domain.clone()),
            Some(RealIpMapping::Ambiguous {
                latest_domain,
                latest_expire,
                conflict_until,
            }) if now >= *conflict_until && *latest_expire > now => Some(latest_domain.clone()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fake_ip_allocation_and_restore() {
        let pool = FakeIpPool::new_default();
        let domain = "api.github.com";
        let ip = pool.allocate(domain);

        assert!(pool.is_fake_ip(&ip));
        assert_eq!(pool.restore(&ip), Some(domain.to_string()));

        // 再次获取同一域名应获得相同 IP (在 TTL 内)
        let ip_repeat = pool.allocate(domain);
        assert_eq!(ip, ip_repeat);
    }

    #[test]
    fn test_fake_ip_expiration() {
        let pool = FakeIpPool::new_default().with_ttl(Duration::from_millis(50));
        let ip = pool.allocate("short-lived.com");
        assert!(pool.restore(&ip).is_some());

        std::thread::sleep(Duration::from_millis(60));
        let cleaned = pool.cleanup_expired();
        assert_eq!(cleaned, 1);
        assert!(pool.restore(&ip).is_none());
    }

    #[test]
    fn test_fake_ip_sliding_refresh() {
        let pool = FakeIpPool::new_default().with_ttl(Duration::from_millis(100));
        let ip = pool.allocate("busy.com");

        // 在 TTL 过半后访问，映射应被续期而不是到期回收
        std::thread::sleep(Duration::from_millis(70));
        assert_eq!(pool.restore(&ip).as_deref(), Some("busy.com"));
        std::thread::sleep(Duration::from_millis(70));
        assert_eq!(pool.cleanup_expired(), 0);
        assert_eq!(pool.allocate("busy.com"), ip);

        // 过期但 IP 未被转让时重新查询应复用原 IP
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(pool.allocate("busy.com"), ip);
    }

    #[test]
    fn test_fake_ip_wraparound_skips_active_and_uses_lru_when_full() {
        let small_pool = FakeIpPool {
            min: u32::from(Ipv4Addr::new(198, 18, 0, 1)),
            max: u32::from(Ipv4Addr::new(198, 18, 0, 3)),
            inner: RwLock::new(PoolState::new(u32::from(Ipv4Addr::new(198, 18, 0, 1)))),
            real_ip_cache: RwLock::new(RealIpState::default()),
            ttl: Duration::from_millis(120),
            self_ports: Vec::new(),
        };

        let ip_a = small_pool.allocate("a.example");
        let ip_b = small_pool.allocate("b.example");
        let ip_c = small_pool.allocate("c.example");
        assert_eq!(ip_a, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(ip_b, Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!(ip_c, Ipv4Addr::new(198, 18, 0, 3));

        // 等过半 TTL 仅续期 a 和 c，让 b 先到期
        std::thread::sleep(Duration::from_millis(75));
        assert_eq!(small_pool.restore(&ip_a).as_deref(), Some("a.example"));
        assert_eq!(small_pool.restore(&ip_c).as_deref(), Some("c.example"));
        std::thread::sleep(Duration::from_millis(60));

        // 此时游标位于 .1 (a.example 仍活跃)，应跳过 .1/.3 命中已过期的 .2
        let ip_d = small_pool.allocate("d.example");
        assert_eq!(ip_d, ip_b);
        assert_eq!(small_pool.restore(&ip_a).as_deref(), Some("a.example"));
        assert_eq!(small_pool.restore(&ip_c).as_deref(), Some("c.example"));

        // 全满未过期场景：刷新 p1 后，p2 成为最旧未过期项 (LRU) 淘汰目标
        let lru_pool = FakeIpPool {
            min: u32::from(Ipv4Addr::new(198, 18, 2, 1)),
            max: u32::from(Ipv4Addr::new(198, 18, 2, 3)),
            inner: RwLock::new(PoolState::new(u32::from(Ipv4Addr::new(198, 18, 2, 1)))),
            real_ip_cache: RwLock::new(RealIpState::default()),
            ttl: Duration::from_millis(100),
            self_ports: Vec::new(),
        };
        let p1 = lru_pool.allocate("old.example");
        std::thread::sleep(Duration::from_millis(15));
        let p2 = lru_pool.allocate("mid.example");
        std::thread::sleep(Duration::from_millis(15));
        let p3 = lru_pool.allocate("new.example");
        std::thread::sleep(Duration::from_millis(45));
        assert_eq!(lru_pool.restore(&p1).as_deref(), Some("old.example"));
        let p4 = lru_pool.allocate("newest.example");
        assert_eq!(p4, p2);
        assert_eq!(lru_pool.restore(&p1).as_deref(), Some("old.example"));
        assert_eq!(lru_pool.restore(&p3).as_deref(), Some("new.example"));
    }

    #[test]
    fn test_fake_ip_heap_eviction_and_large_pool_lru() {
        let base = u32::from(Ipv4Addr::new(198, 18, 10, 0));
        let pool = FakeIpPool {
            min: base,
            max: base + 999,
            inner: RwLock::new(PoolState::new(base)),
            real_ip_cache: RwLock::new(RealIpState::default()),
            ttl: Duration::from_secs(30),
            self_ports: Vec::new(),
        };

        // Fill all 1000 slots with deterministic seq order
        let mut allocated = Vec::with_capacity(1000);
        for i in 0..1000 {
            allocated.push(pool.allocate(&format!("d{i}.example")));
        }
        assert_eq!(pool.len(), 1000);

        // Overwrite oldest 10 slots via heap eviction
        for (j, expected_ip) in allocated.iter().enumerate().take(10) {
            let evicted_reused = pool.allocate(&format!("overflow{j}.example"));
            assert_eq!(evicted_reused, *expected_ip);
        }
        assert_eq!(pool.len(), 1000);
        assert!(pool.restore(&allocated[10]).is_some());
    }

    #[test]
    fn test_real_ip_mapping_uniqueness_ambiguity_and_orig_dns_restore() {
        let pool = FakeIpPool::new_default().with_ttl(Duration::from_millis(80));
        let real_v4: IpAddr = "93.184.216.34".parse().unwrap();
        let cdn_v4: IpAddr = "104.16.1.1".parse().unwrap();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let unspecified: IpAddr = "0.0.0.0".parse().unwrap();
        let link_local: IpAddr = "169.254.1.10".parse().unwrap();
        let corp_dns: SocketAddr = "10.0.0.53:53".parse().unwrap();
        let fake_v4: IpAddr =
            IpAddr::V4(pool.allocate_with_dns("fake-only.example", Some(corp_dns)));

        // Fake-IP 应保留原始上游 DNS 线索供 Direct 回源
        assert_eq!(
            pool.restore_ip_with_dns(fake_v4),
            Some(("fake-only.example".to_string(), Some(corp_dns)))
        );

        // Loopback / Unspecified / Link-Local / Fake-IP 不会被记录进 real_ip_to_domain
        pool.record_real_ip_mappings(
            "Real.Example.",
            &[real_v4, loopback, unspecified, link_local, fake_v4],
        );
        assert_eq!(
            pool.lookup_real_ip_domain(real_v4).as_deref(),
            Some("real.example")
        );
        assert_eq!(pool.lookup_real_ip_domain(loopback), None);
        assert_eq!(pool.lookup_real_ip_domain(unspecified), None);
        assert_eq!(pool.lookup_real_ip_domain(link_local), None);
        assert_eq!(pool.lookup_real_ip_domain(fake_v4), None);

        // 共享 CDN IP 一旦在有效 TTL 内命中第二个不同域名，应退化为 Ambiguous 并返回 None（防止后写覆盖）
        pool.record_real_ip_mappings("site-a.example", &[cdn_v4]);
        assert_eq!(
            pool.lookup_real_ip_domain(cdn_v4).as_deref(),
            Some("site-a.example")
        );
        pool.record_real_ip_mappings("site-b.example", &[cdn_v4]);
        assert_eq!(pool.lookup_real_ip_domain(cdn_v4), None);
        // 冲突期内再次记录仍维持 Ambiguous
        pool.record_real_ip_mappings("site-b.example", &[cdn_v4]);
        assert_eq!(pool.lookup_real_ip_domain(cdn_v4), None);

        // TTL 到期后不再无限滑动续期，清理失效且允许后续重新建立唯一映射
        std::thread::sleep(Duration::from_millis(95));
        pool.cleanup_expired();
        assert_eq!(pool.lookup_real_ip_domain(real_v4), None);
        assert_eq!(pool.lookup_real_ip_domain(cdn_v4), None);
        pool.record_real_ip_mappings("fresh.example", &[cdn_v4]);
        assert_eq!(
            pool.lookup_real_ip_domain(cdn_v4).as_deref(),
            Some("fresh.example")
        );
    }

    #[test]
    fn test_fake_ip_multi_dns_preserves_corp_dns_and_never_resurrects_expired_dns() {
        let pool = FakeIpPool::new_default()
            .with_ttl(Duration::from_millis(100))
            .with_self_ports(vec![1053, 40001, 40080]);
        let corp_dns: SocketAddr = "10.0.0.53:53".parse().unwrap();
        let pub_dns: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let scoped_ll_v6 = SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 53, 0, 7));
        let unscoped_ll_v6: SocketAddr = "[fe80::1]:53".parse().unwrap();

        // 1. 双 DNS 交替查询：企业 VPN DNS 不被 8.8.8.8 覆盖，且两者均保留，不触发写锁/堆抖动
        let ip = pool.allocate_with_dns("git.corp.example", Some(corp_dns));
        let ip2 = pool.allocate_with_dns("git.corp.example", Some(pub_dns));
        assert_eq!(ip, ip2);
        let (_, list) = pool.restore_with_dns_list(&ip).unwrap();
        assert_eq!(list, vec![corp_dns, pub_dns]);
        assert_eq!(
            pool.restore_with_dns(&ip),
            Some(("git.corp.example".to_string(), Some(corp_dns)))
        );

        let seq_before = pool.inner.read().unwrap().alloc_seq;
        // 再次交替命中已记录的两种 DNS 必须走读锁快速路径（alloc_seq 不增长）
        assert_eq!(
            pool.allocate_with_dns("git.corp.example", Some(corp_dns)),
            ip
        );
        assert_eq!(
            pool.allocate_with_dns("git.corp.example", Some(pub_dns)),
            ip
        );
        assert_eq!(pool.inner.read().unwrap().alloc_seq, seq_before);

        // 2. 即使先收到公网 DNS 后收到企业 DNS，企业 DNS 仍应排在公网 DNS 之前
        let ip_rev = pool.allocate_with_dns("erp.corp.example", Some(pub_dns));
        assert_eq!(
            pool.allocate_with_dns("erp.corp.example", Some(corp_dns)),
            ip_rev
        );
        let (_, rev_list) = pool.restore_with_dns_list(&ip_rev).unwrap();
        assert_eq!(rev_list, vec![corp_dns, pub_dns]);

        // 3. 过滤不可用 DNS：self_port、169.254/16、255.255.255.255、无 scope_id 的 fe80::，但保留带 scope_id 的 fe80::
        let ip_san = pool.allocate_with_dns("san.example", Some("127.0.0.1:1053".parse().unwrap()));
        assert_eq!(
            pool.restore_with_dns_list(&ip_san).unwrap().1,
            Vec::<SocketAddr>::new()
        );
        assert_eq!(
            pool.allocate_with_dns("san.example", Some("169.254.1.1:53".parse().unwrap())),
            ip_san
        );
        assert_eq!(
            pool.allocate_with_dns("san.example", Some("255.255.255.255:53".parse().unwrap())),
            ip_san
        );
        assert_eq!(
            pool.allocate_with_dns("san.example", Some(unscoped_ll_v6)),
            ip_san
        );
        assert_eq!(
            pool.restore_with_dns_list(&ip_san).unwrap().1,
            Vec::<SocketAddr>::new()
        );
        assert_eq!(
            pool.allocate_with_dns("san.example", Some(scoped_ll_v6)),
            ip_san
        );
        assert_eq!(
            pool.restore_with_dns_list(&ip_san).unwrap().1,
            vec![scoped_ll_v6]
        );

        // 4. 过期但尚未被 GC 回收时，以 orig_dns=None 重新 allocate 绝不得复活旧 VPN DNS
        std::thread::sleep(Duration::from_millis(120));
        let ip_reused = pool.allocate_with_dns("git.corp.example", None);
        assert_eq!(ip_reused, ip);
        assert_eq!(
            pool.restore_with_dns_list(&ip_reused).unwrap().1,
            Vec::<SocketAddr>::new(),
            "expired Fake-IP entry must not resurrect stale orig_dns before GC"
        );
    }

    #[test]
    fn test_ambiguous_real_ip_recovers_after_conflict_window_without_infinite_extension() {
        let pool = FakeIpPool::new_default().with_ttl(Duration::from_millis(80));
        let shared_ip: IpAddr = "104.16.2.2".parse().unwrap();

        pool.record_real_ip_mappings("site-a.example", &[shared_ip]);
        pool.record_real_ip_mappings("site-b.example", &[shared_ip]);
        assert_eq!(pool.lookup_real_ip_domain(shared_ip), None);

        // 冲突期内 site-b 持续活跃续期，不得无限顺延 conflict_until
        std::thread::sleep(Duration::from_millis(45));
        pool.record_real_ip_mappings("site-b.example", &[shared_ip]);
        assert_eq!(pool.lookup_real_ip_domain(shared_ip), None);

        // 原冲突窗口（80ms）结束后，仅 site-b 仍处于有效 TTL，应自然恢复为唯一域名 site-b.example
        std::thread::sleep(Duration::from_millis(45));
        assert_eq!(
            pool.lookup_real_ip_domain(shared_ip).as_deref(),
            Some("site-b.example")
        );
    }
}
