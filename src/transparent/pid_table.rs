use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::transparent::windivert_ffi::WinDivertEvent;

const SHARD_COUNT: usize = 16;
const MAX_ENTRIES_PER_SHARD: usize = 4096;
const ENTRY_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy)]
struct PidEntry {
    pid: u32,
    updated_at: Instant,
}

#[derive(Default)]
struct PidShard {
    exact: HashMap<(u8, IpAddr, u16), PidEntry>,
    wild: HashMap<(u8, u16), PidEntry>,
}

impl PidShard {
    fn maybe_evict(&mut self, now: Instant) {
        if self.exact.len() <= MAX_ENTRIES_PER_SHARD && self.wild.len() <= MAX_ENTRIES_PER_SHARD {
            return;
        }
        self.exact
            .retain(|_, v| now.saturating_duration_since(v.updated_at) <= ENTRY_TTL);
        self.wild
            .retain(|_, v| now.saturating_duration_since(v.updated_at) <= ENTRY_TTL);

        // 若未过期项仍超限（高并发短连接冲击），按最近更新时间淘汰最老的四分之一
        if self.exact.len() > MAX_ENTRIES_PER_SHARD {
            let mut items: Vec<_> = self
                .exact
                .iter()
                .map(|(k, v)| (*k, v.updated_at))
                .collect();
            items.sort_unstable_by_key(|(_, ts)| *ts);
            let remove_cnt = self.exact.len().saturating_sub(MAX_ENTRIES_PER_SHARD * 3 / 4);
            for (k, _) in items.into_iter().take(remove_cnt) {
                self.exact.remove(&k);
            }
        }
        if self.wild.len() > MAX_ENTRIES_PER_SHARD {
            let mut items: Vec<_> = self
                .wild
                .iter()
                .map(|(k, v)| (*k, v.updated_at))
                .collect();
            items.sort_unstable_by_key(|(_, ts)| *ts);
            let remove_cnt = self.wild.len().saturating_sub(MAX_ENTRIES_PER_SHARD * 3 / 4);
            for (k, _) in items.into_iter().take(remove_cnt) {
                self.wild.remove(&k);
            }
        }
    }
}

/// 由 `WINDIVERT_LAYER_SOCKET` 实时喂入的分片 `(proto, local_ip, local_port) -> PID` 映射表。
///
/// 通过按源端口分成 16 个独立分片降低锁竞争，无需每次收到 TCP SYN / UDP DNS 包都扫描全局表。
pub struct SocketPidTable {
    shards: [Mutex<PidShard>; SHARD_COUNT],
}

impl Default for SocketPidTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketPidTable {
    pub fn new() -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(PidShard::default())),
        }
    }

    #[inline]
    fn shard_index(local_port: u16) -> usize {
        (local_port as usize) & (SHARD_COUNT - 1)
    }

    /// 处理一条来自 `WINDIVERT_LAYER_SOCKET` 的套接字生命周期事件
    pub fn record_event(
        &self,
        event: WinDivertEvent,
        protocol: u8,
        local_ip: IpAddr,
        local_port: u16,
        pid: u32,
    ) {
        if local_port == 0 || !matches!(protocol, 6 | 17) {
            return;
        }
        let norm_ip = local_ip.to_canonical();
        let now = Instant::now();
        let mut shard = self.shards[Self::shard_index(local_port)]
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        match event {
            WinDivertEvent::SocketBind
            | WinDivertEvent::SocketConnect
            | WinDivertEvent::SocketAccept
            | WinDivertEvent::SocketListen => {
                if pid == 0 {
                    return;
                }
                let entry = PidEntry {
                    pid,
                    updated_at: now,
                };
                if !norm_ip.is_unspecified() {
                    shard.exact.insert((protocol, norm_ip, local_port), entry);
                }
                // 同时写入按 `(proto, local_port)` 索引的后备项，以便应对先 bind(0.0.0.0) 后发送首包的情形
                shard.wild.insert((protocol, local_port), entry);
                shard.maybe_evict(now);
            }
            WinDivertEvent::SocketClose => {
                if !norm_ip.is_unspecified() {
                    if let Some(existing) = shard.exact.get(&(protocol, norm_ip, local_port))
                        && (pid == 0 || existing.pid == pid)
                    {
                        shard.exact.remove(&(protocol, norm_ip, local_port));
                    }
                }
                if let Some(existing) = shard.wild.get(&(protocol, local_port))
                    && (pid == 0 || existing.pid == pid)
                {
                    shard.wild.remove(&(protocol, local_port));
                }
            }
            _ => {}
        }
    }

    /// 根据五元组中的源协议、源 IP 与源端口高速查询归属 PID；优先精确匹配，未命中则查同端口通配绑定
    pub fn lookup(&self, protocol: u8, local_ip: IpAddr, local_port: u16) -> Option<u32> {
        if local_port == 0 {
            return None;
        }
        let norm_ip = local_ip.to_canonical();
        let now = Instant::now();
        let shard = self.shards[Self::shard_index(local_port)]
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(entry) = shard.exact.get(&(protocol, norm_ip, local_port))
            && now.saturating_duration_since(entry.updated_at) <= ENTRY_TTL
        {
            return Some(entry.pid);
        }
        if let Some(entry) = shard.wild.get(&(protocol, local_port))
            && now.saturating_duration_since(entry.updated_at) <= ENTRY_TTL
        {
            return Some(entry.pid);
        }
        None
    }

    #[inline]
    pub fn is_self_pid(pid: u32) -> bool {
        pid != 0 && pid == std::process::id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_socket_pid_table_bind_connect_canonical_and_close() {
        let table = SocketPidTable::new();
        let unspec = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let nic_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 88));
        let mapped_nic = IpAddr::V6(Ipv4Addr::new(192, 168, 1, 88).to_ipv6_mapped());

        // 1. 仅 BIND 0.0.0.0:54321 也能通过通配回退命中
        table.record_event(WinDivertEvent::SocketBind, 17, unspec, 54321, 1001);
        assert_eq!(table.lookup(17, nic_ip, 54321), Some(1001));
        assert_eq!(table.lookup(17, mapped_nic, 54321), Some(1001));
        assert_eq!(table.lookup(6, nic_ip, 54321), None);

        // 2. CONNECT 提供具体源 IP 与新 PID 时优先命中 exact
        table.record_event(WinDivertEvent::SocketConnect, 6, mapped_nic, 55000, 2002);
        assert_eq!(table.lookup(6, nic_ip, 55000), Some(2002));

        // 3. CLOSE 事件校验 PID 后精确清理
        table.record_event(WinDivertEvent::SocketClose, 6, nic_ip, 55000, 9999);
        assert_eq!(table.lookup(6, nic_ip, 55000), Some(2002));
        table.record_event(WinDivertEvent::SocketClose, 6, nic_ip, 55000, 2002);
        assert_eq!(table.lookup(6, nic_ip, 55000), None);
        assert!(SocketPidTable::is_self_pid(std::process::id()));
    }

    #[test]
    fn test_socket_pid_table_shard_capacity_eviction() {
        let table = SocketPidTable::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        // 向同一分片插入超出 MAX_ENTRIES_PER_SHARD 的端口，应自动淘汰且不 Panic
        for k in 0..(MAX_ENTRIES_PER_SHARD + 128) {
            let port = ((k * SHARD_COUNT + 1) % 65535).max(1) as u16;
            table.record_event(WinDivertEvent::SocketConnect, 6, ip, port, 3000 + k as u32);
        }
        let shard = table.shards[1].lock().unwrap();
        assert!(shard.exact.len() <= MAX_ENTRIES_PER_SHARD);
    }
}
