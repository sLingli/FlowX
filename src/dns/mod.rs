use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Fake-IP 分配池与双向映射表
pub struct FakeIpPool {
    current: RwLock<u32>,
    min: u32,
    max: u32,
    inner: RwLock<PoolState>,
    ttl: Duration,
}

struct PoolState {
    ip_to_domain: HashMap<Ipv4Addr, (String, Instant)>,
    domain_to_ip: HashMap<String, (Ipv4Addr, Instant)>,
}

impl FakeIpPool {
    /// 默认使用保留测试网段 198.18.0.0/15
    pub fn new_default() -> Self {
        // 198.18.0.1 到 198.19.255.254
        let min = u32::from(Ipv4Addr::new(198, 18, 0, 1));
        let max = u32::from(Ipv4Addr::new(198, 19, 255, 254));

        Self {
            current: RwLock::new(min),
            min,
            max,
            inner: RwLock::new(PoolState {
                ip_to_domain: HashMap::new(),
                domain_to_ip: HashMap::new(),
            }),
            ttl: Duration::from_secs(600), // 10分钟有效期
        }
    }

    /// 为指定域名分配一个 Fake-IP (若已分配且未过期则复用)
    pub fn allocate(&self, domain: &str) -> Ipv4Addr {
        let domain_lower = domain.to_lowercase();
        let now = Instant::now();

        // 读锁检查是否已存在有效映射
        {
            let state = self.inner.read().unwrap();
            if let Some((ip, expire)) = state.domain_to_ip.get(&domain_lower) {
                if *expire > now {
                    return *ip;
                }
            }
        }

        // 分配新 IP
        let mut curr_guard = self.current.write().unwrap();
        let raw_ip = *curr_guard;
        if *curr_guard >= self.max {
            *curr_guard = self.min;
        } else {
            *curr_guard += 1;
        }

        let ip = Ipv4Addr::from(raw_ip);
        let expire = now + self.ttl;

        let mut state = self.inner.write().unwrap();
        state.domain_to_ip.insert(domain_lower.clone(), (ip, expire));
        state.ip_to_domain.insert(ip, (domain_lower, expire));

        ip
    }

    /// 从 Fake-IP 还原原始域名
    pub fn restore(&self, ip: &Ipv4Addr) -> Option<String> {
        let state = self.inner.read().unwrap();
        state.ip_to_domain.get(ip).map(|(d, _)| d.clone())
    }

    /// 判断某个 IP 是否属于 Fake-IP 网段
    pub fn is_fake_ip(&self, ip: &Ipv4Addr) -> bool {
        let raw = u32::from(*ip);
        raw >= self.min && raw <= self.max
    }
}
