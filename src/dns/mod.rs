use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::RwLock;
use std::time::{Duration, Instant};

pub mod server;

const MAX_REAL_IP_MAPPINGS: usize = 16_384;
const MAX_REAL_IP_MAPPING_TTL: Duration = Duration::from_secs(120);
const MIN_REAL_IP_MAPPING_TTL: Duration = Duration::from_secs(5);

/// Fake-IP 线程安全分配池与双向映射表
#[derive(Debug)]
pub struct FakeIpPool {
    min: u32,
    max: u32,
    inner: RwLock<PoolState>,
    ttl: Duration,
}

#[derive(Debug, Clone)]
struct FakeIpEntry {
    domain: String,
    expire: Instant,
    seq: u64,
    orig_dns: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
enum RealIpMapping {
    /// 有效 TTL 内仅观测到单一域名解析至该真实 IP（可用于规则域名辅助匹配）
    Unique { domain: String, expire: Instant },
    /// 有效 TTL 内观测到多个不同域名共享该 IP（CDN/反代/Anycast），禁止按单一域名归属
    Ambiguous { expire: Instant },
}

impl RealIpMapping {
    fn expire(&self) -> Instant {
        match self {
            Self::Unique { expire, .. } | Self::Ambiguous { expire } => *expire,
        }
    }
}

#[derive(Debug)]
struct PoolState {
    current: u32,
    alloc_seq: u64,
    ip_to_domain: HashMap<Ipv4Addr, FakeIpEntry>,
    domain_to_ip: HashMap<String, (Ipv4Addr, Instant)>,
    expiry_heap: std::collections::BinaryHeap<std::cmp::Reverse<(Instant, u64, u32)>>,
    /// 共享 DNS 被动探测阶段记录的 真实 IP -> 域名 反向映射（支持多域名共享 IP 冲突退化为 Ambiguous）
    real_ip_to_domain: HashMap<IpAddr, RealIpMapping>,
}

impl PoolState {
    fn new(start: u32) -> Self {
        Self {
            current: start,
            alloc_seq: 0,
            ip_to_domain: HashMap::new(),
            domain_to_ip: HashMap::new(),
            expiry_heap: std::collections::BinaryHeap::new(),
            real_ip_to_domain: HashMap::new(),
        }
    }

    fn record_mapping(
        &mut self,
        ip: Ipv4Addr,
        domain: String,
        expire: Instant,
        orig_dns: Option<SocketAddr>,
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
        self.expiry_heap
            .push(std::cmp::Reverse((expire, seq, u32::from(ip))));
        if self.expiry_heap.len() > self.ip_to_domain.len().saturating_mul(4).max(256) {
            self.rebuild_expiry_heap();
        }
    }

    fn rebuild_expiry_heap(&mut self) {
        self.expiry_heap.clear();
        for (&ip, entry) in &self.ip_to_domain {
            self.expiry_heap
                .push(std::cmp::Reverse((entry.expire, entry.seq, u32::from(ip))));
        }
    }

    fn pop_oldest_ip(&mut self) -> Option<Ipv4Addr> {
        while let Some(std::cmp::Reverse((exp, seq, ip_raw))) = self.expiry_heap.pop() {
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
            ttl: Duration::from_secs(600), // 默认映射保留 10 分钟
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
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
        let orig_dns = orig_dns.and_then(|addr| {
            let ip = addr.ip().to_canonical();
            let unusable = addr.port() == 0
                || ip.is_unspecified()
                || ip.is_multicast()
                || self.is_fake_ip_addr(ip)
                || matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local());
            (!unusable).then_some(SocketAddr::new(ip, addr.port()))
        });
        let now = Instant::now();
        let refresh_threshold = now + self.ttl / 2;

        // 1. 读锁快速路径：若已存在且剩余寿命充足且无需补充 orig_dns 则直接复用
        {
            let state = self.inner.read().unwrap_or_else(|e| e.into_inner());
            if let Some((ip, expire)) = state.domain_to_ip.get(&domain_lower)
                && *expire > refresh_threshold
                && (orig_dns.is_none()
                    || state
                        .ip_to_domain
                        .get(ip)
                        .is_some_and(|entry| entry.orig_dns == orig_dns))
            {
                return *ip;
            }
        }

        // 2. 写锁路径：续期已有映射或分配新 IP，Double-Check 确保锁升级间隙未被并发线程抢占
        let mut state = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let expire = now + self.ttl;

        // 已有映射（即使已过期）只要其 IP 尚未被转让给其它域名，就原地续期复用，
        // 避免客户端仍缓存旧 IP 时出现域名无法还原的问题
        if let Some((ip, _)) = state.domain_to_ip.get(&domain_lower).copied()
            && let Some(existing) = state.ip_to_domain.get(&ip)
            && existing.domain == domain_lower
        {
            let merged_dns = orig_dns.or(existing.orig_dns);
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
                cursor = if cursor >= self.max { self.min } else { cursor + 1 };
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

        state.record_mapping(ip, domain_lower, expire, orig_dns);

        ip
    }

    /// 从 Fake-IP 还原原始域名与记录的原始上游 DNS (O(1) 复杂度)，并对仍在使用中的映射滑动续期
    pub fn restore_with_dns(&self, ip: &Ipv4Addr) -> Option<(String, Option<SocketAddr>)> {
        let now = Instant::now();
        let refresh_threshold = now + self.ttl / 2;
        {
            let state = self.inner.read().unwrap_or_else(|e| e.into_inner());
            match state.ip_to_domain.get(ip) {
                None => return None,
                Some(entry) if entry.expire > refresh_threshold => {
                    return Some((entry.domain.clone(), entry.orig_dns));
                }
                Some(_) => {}
            }
        }

        let mut state = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let (domain, orig_dns) = state
            .ip_to_domain
            .get(ip)
            .map(|e| (e.domain.clone(), e.orig_dns))?;
        let expire = now + self.ttl;
        state.record_mapping(*ip, domain.clone(), expire, orig_dns);
        Some((domain, orig_dns))
    }

    /// 从 Fake-IP 还原原始域名 (O(1) 复杂度)，并对仍在使用中的映射滑动续期
    pub fn restore(&self, ip: &Ipv4Addr) -> Option<String> {
        self.restore_with_dns(ip).map(|(d, _)| d)
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

    /// 从任意 IPv4 / IPv4-mapped IPv6 中还原 Fake-IP 对应的原始域名及记录的原始上游 DNS
    pub fn restore_ip_with_dns(&self, ip: IpAddr) -> Option<(String, Option<SocketAddr>)> {
        Self::unwrap_ipv4(ip).and_then(|v4| self.restore_with_dns(&v4))
    }

    /// 从任意 IPv4 / IPv4-mapped IPv6 中还原 Fake-IP 对应的原始域名
    pub fn restore_ip(&self, ip: IpAddr) -> Option<String> {
        self.restore_ip_with_dns(ip).map(|(d, _)| d)
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

    /// 清理池中全部已过期的映射条目
    pub fn cleanup_expired(&self) -> usize {
        let now = Instant::now();
        let mut state = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let before_count = state.ip_to_domain.len();

        state.ip_to_domain.retain(|_, entry| entry.expire > now);
        state.domain_to_ip.retain(|_, (_, expire)| *expire > now);
        state
            .real_ip_to_domain
            .retain(|_, entry| entry.expire() > now);
        if state.expiry_heap.len() > state.ip_to_domain.len().saturating_mul(4).max(256) {
            state.rebuild_expiry_heap();
        }

        before_count - state.ip_to_domain.len()
    }

    /// 记录通过被动 DNS 探测观测到的 真实单播 IP -> 域名 反向映射（使用默认上限 TTL）
    pub fn record_real_ip_mappings(&self, domain: &str, ips: &[IpAddr]) {
        self.record_real_ip_mappings_with_ttl(domain, ips, None);
    }

    /// 记录通过被动 DNS 探测观测到的 真实单播 IP -> 域名 反向映射：
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
        let valid_ips: Vec<IpAddr> = ips
            .iter()
            .copied()
            .filter_map(|ip| {
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
                usable.then_some(canon)
            })
            .collect();
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
        let mut state = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if state.real_ip_to_domain.len() + valid_ips.len() > MAX_REAL_IP_MAPPINGS {
            state
                .real_ip_to_domain
                .retain(|_, entry| entry.expire() > now);
            while state.real_ip_to_domain.len() + valid_ips.len() > MAX_REAL_IP_MAPPINGS {
                let Some(oldest_ip) = state
                    .real_ip_to_domain
                    .iter()
                    .min_by_key(|(_, entry)| entry.expire())
                    .map(|(k, _)| *k)
                else {
                    break;
                };
                state.real_ip_to_domain.remove(&oldest_ip);
            }
        }
        for ip in valid_ips {
            state
                .real_ip_to_domain
                .entry(ip)
                .and_modify(|entry| match entry {
                    RealIpMapping::Unique {
                        domain: existing,
                        expire: old_exp,
                    } if *old_exp > now => {
                        let merged_exp = (*old_exp).max(expire);
                        if *existing == domain_lower {
                            *old_exp = merged_exp;
                        } else {
                            *entry = RealIpMapping::Ambiguous { expire: merged_exp };
                        }
                    }
                    RealIpMapping::Ambiguous { expire: old_exp } if *old_exp > now => {
                        *old_exp = (*old_exp).max(expire);
                    }
                    _ => {
                        *entry = RealIpMapping::Unique {
                            domain: domain_lower.clone(),
                            expire,
                        };
                    }
                })
                .or_insert_with(|| RealIpMapping::Unique {
                    domain: domain_lower.clone(),
                    expire,
                });
        }
    }

    /// 仅当该真实 IP 在有效 TTL 内唯一归属单一域名时返回对应域名；若多个域名共享该 IP (`Ambiguous`) 或已过期则返回 `None`
    pub fn lookup_real_ip_domain(&self, ip: IpAddr) -> Option<String> {
        let canon = ip.to_canonical();
        let now = Instant::now();
        let state = self.inner.read().unwrap_or_else(|e| e.into_inner());
        match state.real_ip_to_domain.get(&canon) {
            Some(RealIpMapping::Unique { domain, expire }) if *expire > now => Some(domain.clone()),
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
            ttl: Duration::from_millis(120),
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
            ttl: Duration::from_millis(100),
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
            ttl: Duration::from_secs(30),
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
        let fake_v4: IpAddr = IpAddr::V4(pool.allocate_with_dns("fake-only.example", Some(corp_dns)));

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
}
