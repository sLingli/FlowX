use std::collections::HashMap;
use std::net::Ipv4Addr;
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
        let domain_lower = domain.to_lowercase();
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

        let raw_ip = state.current;
        if state.current >= self.max {
            state.current = self.min; // 环形复用
        } else {
            state.current += 1;
        }

        let ip = Ipv4Addr::from(raw_ip);

        // 若当前轮转到的 IP 之前绑定过其它域名，清理其旧的逆向映射
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

    /// 判断指定 IP 是否落在 Fake-IP 保留网段内
    pub fn is_fake_ip(&self, ip: &Ipv4Addr) -> bool {
        let raw = u32::from(*ip);
        raw >= self.min && raw <= self.max
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
}
