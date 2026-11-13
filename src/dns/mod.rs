use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::RwLock;
use std::time::{Duration, Instant};

pub mod server;

/// Fake-IP 线程安全分配池与双向映射表
#[derive(Debug)]
pub struct FakeIpPool {
    min: u32,
    max: u32,
    inner: RwLock<PoolState>,
    ttl: Duration,
}

#[derive(Debug)]
struct PoolState {
    current: u32,
    alloc_seq: u64,
    ip_to_domain: HashMap<Ipv4Addr, (String, Instant, u64)>,
    domain_to_ip: HashMap<String, (Ipv4Addr, Instant)>,
    expiry_heap: std::collections::BinaryHeap<std::cmp::Reverse<(Instant, u64, u32)>>,
}

impl PoolState {
    fn new(start: u32) -> Self {
        Self {
            current: start,
            alloc_seq: 0,
            ip_to_domain: HashMap::new(),
            domain_to_ip: HashMap::new(),
            expiry_heap: std::collections::BinaryHeap::new(),
        }
    }

    fn record_mapping(&mut self, ip: Ipv4Addr, domain: String, expire: Instant) {
        self.alloc_seq = self.alloc_seq.wrapping_add(1);
        let seq = self.alloc_seq;
        self.domain_to_ip.insert(domain.clone(), (ip, expire));
        self.ip_to_domain.insert(ip, (domain, expire, seq));
        self.expiry_heap
            .push(std::cmp::Reverse((expire, seq, u32::from(ip))));
        if self.expiry_heap.len() > self.ip_to_domain.len().saturating_mul(4).max(256) {
            self.rebuild_expiry_heap();
        }
    }

    fn rebuild_expiry_heap(&mut self) {
        self.expiry_heap.clear();
        for (&ip, (_, expire, seq)) in &self.ip_to_domain {
            self.expiry_heap
                .push(std::cmp::Reverse((*expire, *seq, u32::from(ip))));
        }
    }

    fn pop_oldest_ip(&mut self) -> Option<Ipv4Addr> {
        while let Some(std::cmp::Reverse((exp, seq, ip_raw))) = self.expiry_heap.pop() {
            let ip = Ipv4Addr::from(ip_raw);
            if self
                .ip_to_domain
                .get(&ip)
                .is_some_and(|(_, cur_exp, cur_seq)| *cur_exp == exp && *cur_seq == seq)
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
        let domain_lower = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let now = Instant::now();
        let refresh_threshold = now + self.ttl / 2;

        // 1. 读锁快速路径：若已存在且剩余寿命充足直接复用
        {
            let state = self.inner.read().unwrap_or_else(|e| e.into_inner());
            if let Some((ip, expire)) = state.domain_to_ip.get(&domain_lower)
                && *expire > refresh_threshold {
                    return *ip;
                }
        }

        // 2. 写锁路径：续期已有映射或分配新 IP，Double-Check 确保锁升级间隙未被并发线程抢占
        let mut state = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let expire = now + self.ttl;

        // 已有映射（即使已过期）只要其 IP 尚未被转让给其它域名，就原地续期复用，
        // 避免客户端仍缓存旧 IP 时出现域名无法还原的问题
        if let Some((ip, _)) = state.domain_to_ip.get(&domain_lower).copied()
            && state.ip_to_domain.get(&ip).is_some_and(|(d, _, _)| *d == domain_lower)
        {
            state.record_mapping(ip, domain_lower, expire);
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
                    Some((_, old_expire, _)) if *old_expire <= now => {
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
        let old_domain_opt = state.ip_to_domain.get(&ip).map(|(d, _, _)| d.clone());
        if let Some(old_domain) = old_domain_opt {
            state.domain_to_ip.remove(&old_domain);
        }

        state.record_mapping(ip, domain_lower, expire);

        ip
    }

    /// 从 Fake-IP 还原原始域名 (O(1) 复杂度)，并对仍在使用中的映射滑动续期
    pub fn restore(&self, ip: &Ipv4Addr) -> Option<String> {
        let now = Instant::now();
        let refresh_threshold = now + self.ttl / 2;
        {
            let state = self.inner.read().unwrap_or_else(|e| e.into_inner());
            match state.ip_to_domain.get(ip) {
                None => return None,
                Some((d, expire, _)) if *expire > refresh_threshold => return Some(d.clone()),
                Some(_) => {}
            }
        }

        let mut state = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let domain = state.ip_to_domain.get(ip).map(|(d, _, _)| d.clone())?;
        let expire = now + self.ttl;
        state.record_mapping(*ip, domain.clone(), expire);
        Some(domain)
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

    /// 从任意 IPv4 / IPv4-mapped IPv6 中还原 Fake-IP 对应的原始域名
    pub fn restore_ip(&self, ip: IpAddr) -> Option<String> {
        Self::unwrap_ipv4(ip).and_then(|v4| self.restore(&v4))
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

        state.ip_to_domain.retain(|_, (_, expire, _)| *expire > now);
        state.domain_to_ip.retain(|_, (_, expire)| *expire > now);
        if state.expiry_heap.len() > state.ip_to_domain.len().saturating_mul(4).max(256) {
            state.rebuild_expiry_heap();
        }

        before_count - state.ip_to_domain.len()
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
}
