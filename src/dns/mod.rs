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
    ip_to_domain: HashMap<Ipv4Addr, (String, Instant)>,
    domain_to_ip: HashMap<String, (Ipv4Addr, Instant)>,
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
            inner: RwLock::new(PoolState {
                current: min,
                ip_to_domain: HashMap::new(),
                domain_to_ip: HashMap::new(),
            }),
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
            && state.ip_to_domain.get(&ip).is_some_and(|(d, _)| *d == domain_lower) {
                state.domain_to_ip.insert(domain_lower.clone(), (ip, expire));
                state.ip_to_domain.insert(ip, (domain_lower, expire));
                return ip;
            }

        // 从环形游标起探测首个空闲或已过期槽位，避免在池未满时直接覆写仍活跃的旧映射
        let cap = (self.max - self.min) as usize + 1;
        let mut cursor = state.current;
        let mut chosen_ip = None;
        for _ in 0..cap {
            let candidate = Ipv4Addr::from(cursor);
            cursor = if cursor >= self.max { self.min } else { cursor + 1 };
            match state.ip_to_domain.get(&candidate) {
                None => {
                    chosen_ip = Some(candidate);
                    break;
                }
                Some((_, old_expire)) if *old_expire <= now => {
                    chosen_ip = Some(candidate);
                    break;
                }
                Some(_) => {}
            }
        }
        state.current = cursor;

        let ip = match chosen_ip {
            Some(ip) => ip,
            None => {
                // 所有槽位均被未过期映射占满：按最早到期（等效 LRU）淘汰
                state
                    .ip_to_domain
                    .iter()
                    .min_by_key(|(_, (_, exp))| *exp)
                    .map(|(candidate, _)| *candidate)
                    .unwrap_or_else(|| Ipv4Addr::from(self.min))
            }
        };

        // 若当前选中的 IP 之前绑定过其它域名，清理其旧的逆向映射
        let old_domain_opt = state.ip_to_domain.get(&ip).map(|(d, _)| d.clone());
        if let Some(old_domain) = old_domain_opt {
            state.domain_to_ip.remove(&old_domain);
        }

        state.domain_to_ip.insert(domain_lower.clone(), (ip, expire));
        state.ip_to_domain.insert(ip, (domain_lower, expire));

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
                Some((d, expire)) if *expire > refresh_threshold => return Some(d.clone()),
                Some(_) => {}
            }
        }

        let mut state = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let domain = state.ip_to_domain.get(ip).map(|(d, _)| d.clone())?;
        let expire = now + self.ttl;
        state.ip_to_domain.insert(*ip, (domain.clone(), expire));
        state.domain_to_ip.insert(domain.clone(), (*ip, expire));
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

        state.ip_to_domain.retain(|_, (_, expire)| *expire > now);
        state.domain_to_ip.retain(|_, (_, expire)| *expire > now);

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
            inner: RwLock::new(PoolState {
                current: u32::from(Ipv4Addr::new(198, 18, 0, 1)),
                ip_to_domain: HashMap::new(),
                domain_to_ip: HashMap::new(),
            }),
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
            inner: RwLock::new(PoolState {
                current: u32::from(Ipv4Addr::new(198, 18, 2, 1)),
                ip_to_domain: HashMap::new(),
                domain_to_ip: HashMap::new(),
            }),
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
}
