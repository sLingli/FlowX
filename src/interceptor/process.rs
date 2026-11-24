use std::collections::HashMap;
use std::hash::Hash;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// PID 正向缓存最大条目数（防无界增长与 O(N^2) 全表扫描）
const MAX_PID_CACHE: usize = 1024;
/// 周期性插入时清理过期条目的最小间隔
const CACHE_SWEEP_INTERVAL: Duration = Duration::from_secs(2);
/// 并发执行阻塞式进程反查的最大任务数
const LOOKUP_SEMAPHORE_PERMITS: usize = 8;
/// 获取进程反查信号量的等待上限（高突发下优雅降级为未归属，避免打满阻塞线程池）
const LOOKUP_SEMAPHORE_TIMEOUT: Duration = Duration::from_millis(200);
/// PID 正向缓存默认有效期
const DEFAULT_PID_TTL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub path: String,
    pub name: String,
}

#[derive(Debug, Clone)]
struct PidCacheEntry {
    info: ProcessInfo,
    start_time: Option<u128>,
}

#[derive(Debug, Clone)]
struct CacheSlot<V> {
    value: V,
    expires_at: Instant,
    last_access: Instant,
}

struct CacheState<K, V> {
    entries: HashMap<K, CacheSlot<V>>,
    last_sweep: Instant,
}

struct BoundedCache<K, V> {
    state: RwLock<CacheState<K, V>>,
    ttl: Duration,
    max_entries: usize,
    sweep_interval: Duration,
}

impl<K: Eq + Hash + Copy, V: Clone> BoundedCache<K, V> {
    fn new(ttl: Duration, max_entries: usize) -> Self {
        let cap = max_entries.max(1);
        let sweep_interval = CACHE_SWEEP_INTERVAL.min(ttl.max(Duration::from_millis(1)));
        Self {
            state: RwLock::new(CacheState {
                entries: HashMap::new(),
                last_sweep: Instant::now(),
            }),
            ttl,
            max_entries: cap,
            sweep_interval,
        }
    }

    fn get_cloned(&self, key: &K, now: Instant) -> Option<V> {
        let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
        guard
            .entries
            .get(key)
            .filter(|slot| slot.expires_at > now)
            .map(|slot| slot.value.clone())
    }

    fn remove(&self, key: &K) {
        let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
        guard.entries.remove(key);
    }

    fn insert(&self, key: K, value: V, now: Instant) {
        let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
        let elapsed_since_sweep = now.saturating_duration_since(guard.last_sweep);
        if elapsed_since_sweep >= self.sweep_interval
            || (guard.entries.len() >= self.max_entries
                && elapsed_since_sweep >= Duration::from_millis(50))
        {
            guard.entries.retain(|_, slot| slot.expires_at > now);
            guard.last_sweep = now;
        }
        if !guard.entries.contains_key(&key) {
            while guard.entries.len() >= self.max_entries {
                let Some(oldest_key) = guard
                    .entries
                    .iter()
                    .min_by_key(|(_, slot)| slot.last_access)
                    .map(|(k, _)| *k)
                else {
                    break;
                };
                guard.entries.remove(&oldest_key);
            }
        }
        guard.entries.insert(
            key,
            CacheSlot {
                value,
                expires_at: now + self.ttl,
                last_access: now,
            },
        );
    }

    fn cleanup_expired(&self, now: Instant) -> usize {
        let has_expired = {
            let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
            guard.entries.values().any(|slot| slot.expires_at <= now)
        };
        if !has_expired {
            return 0;
        }
        let mut guard = self.state.write().unwrap_or_else(|e| e.into_inner());
        let before = guard.entries.len();
        guard.entries.retain(|_, slot| slot.expires_at > now);
        guard.last_sweep = now;
        before.saturating_sub(guard.entries.len())
    }
}

pub struct ProcessTracker {
    pid_cache: BoundedCache<u32, PidCacheEntry>,
    lookup_semaphore: Arc<Semaphore>,
}

impl ProcessTracker {
    pub fn new() -> Self {
        Self::with_config(DEFAULT_PID_TTL, MAX_PID_CACHE)
    }

    fn with_config(pid_ttl: Duration, max_pid_entries: usize) -> Self {
        Self {
            pid_cache: BoundedCache::new(pid_ttl, max_pid_entries),
            lookup_semaphore: Arc::new(Semaphore::new(LOOKUP_SEMAPHORE_PERMITS)),
        }
    }

    fn resolve_pid_with<FStart, FFull>(
        &self,
        pid: u32,
        now: Instant,
        mut get_start_time: FStart,
        mut get_identity: FFull,
    ) -> Option<ProcessInfo>
    where
        FStart: FnMut(u32) -> Option<u128>,
        FFull: FnMut(u32) -> Option<(String, Option<u128>)>,
    {
        if let Some(entry) = self.pid_cache.get_cloned(&pid, now) {
            let still_same_process = is_system_pid(pid)
                || match (entry.start_time, get_start_time(pid)) {
                    (Some(expected), Some(actual)) => expected == actual,
                    _ => false,
                };
            if still_same_process {
                return Some(entry.info);
            }
            self.pid_cache.remove(&pid);
        }

        let (path, start_time) = get_identity(pid)?;
        if path.trim().is_empty() {
            return None;
        }
        let name = extract_process_name(&path);
        let info = ProcessInfo { pid, path, name };
        self.pid_cache.insert(
            pid,
            PidCacheEntry {
                info: info.clone(),
                start_time,
            },
            now,
        );
        Some(info)
    }

    /// 根据 TCP 连接四元组查询发起连接的进程信息 (PID, 绝对路径, 进程名)
    ///
    /// `client` 为入站连接的对端地址（即发起方本地套接字），`server` 为 FlowX 入站监听端的本地地址。
    /// 仅当系统 TCP 表中存在 `local == client && remote == server` 的行时才认定归属，
    /// 若进程在反查窗口内已退出或不可访问则返回 `None`（绝不缓存未知占位）。
    pub fn find_by_connection(&self, client: SocketAddr, server: SocketAddr) -> Option<ProcessInfo> {
        let now = Instant::now();
        let pid = get_pid_by_connection(client, server)?;
        self.resolve_pid_with(
            pid,
            now,
            get_process_start_time,
            get_process_identity,
        )
    }

    /// 直接按已知 PID 解析进程信息（复用进程启动时间防 PID 复用校验与 TTL 缓存）
    pub fn resolve_pid(&self, pid: u32) -> Option<ProcessInfo> {
        self.resolve_pid_with(
            pid,
            Instant::now(),
            get_process_start_time,
            get_process_identity,
        )
    }

    /// 异步非阻塞按已知 PID 查询进程信息：通过信号量限流 `spawn_blocking` 并发度
    pub async fn resolve_pid_async(self: &Arc<Self>, pid: u32) -> Option<ProcessInfo> {
        let permit = tokio::time::timeout(
            LOOKUP_SEMAPHORE_TIMEOUT,
            Arc::clone(&self.lookup_semaphore).acquire_owned(),
        )
        .await
        .ok()?
        .ok()?;

        let tracker = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            tracker.resolve_pid(pid)
        })
        .await
        .ok()
        .flatten()
    }

    /// 异步非阻塞查询进程信息：通过信号量限流 `spawn_blocking` 并发度，超时则优雅返回 `None`
    pub async fn find_by_connection_async(
        self: &Arc<Self>,
        client: SocketAddr,
        server: SocketAddr,
    ) -> Option<ProcessInfo> {
        let permit = tokio::time::timeout(
            LOOKUP_SEMAPHORE_TIMEOUT,
            Arc::clone(&self.lookup_semaphore).acquire_owned(),
        )
        .await
        .ok()?
        .ok()?;

        let tracker = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            tracker.find_by_connection(client, server)
        })
        .await
        .ok()
        .flatten()
    }

    /// 清理过期的 PID 缓存项，返回清理数量
    pub fn cleanup_expired(&self) -> usize {
        self.pid_cache.cleanup_expired(Instant::now())
    }
}

impl Default for ProcessTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn is_system_pid(pid: u32) -> bool {
    pid == 4
}

fn extract_process_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| path.trim())
        .to_string()
}

fn normalize_ipv4_pair(client: SocketAddr, server: SocketAddr) -> Option<(SocketAddrV4, SocketAddrV4)> {
    let to_v4 = |addr: SocketAddr| -> Option<SocketAddrV4> {
        match addr {
            SocketAddr::V4(v4) => Some(v4),
            SocketAddr::V6(v6) => Some(SocketAddrV4::new(v6.ip().to_ipv4_mapped()?, v6.port())),
        }
    };
    Some((to_v4(client)?, to_v4(server)?))
}

fn normalize_ipv6_pair(client: SocketAddr, server: SocketAddr) -> Option<(SocketAddrV6, SocketAddrV6)> {
    let to_v6 = |addr: SocketAddr| -> SocketAddrV6 {
        match addr {
            SocketAddr::V6(v6) => v6,
            SocketAddr::V4(v4) => SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0),
        }
    };
    Some((to_v6(client), to_v6(server)))
}

fn find_in_tcp_table_bytes<Row: Copy, F>(
    raw_bytes: &[u8],
    actual_size: usize,
    table_offset: usize,
    mut matcher: F,
) -> Option<u32>
where
    F: FnMut(&Row) -> Option<u32>,
{
    let valid_bytes = actual_size.min(raw_bytes.len());
    if valid_bytes < size_of::<u32>() || valid_bytes < table_offset {
        return None;
    }
    let raw_ptr = raw_bytes.as_ptr();
    // SAFETY: `valid_bytes >= size_of::<u32>()` guarantees at least 4 readable bytes for `dwNumEntries`.
    let raw_count = unsafe { (raw_ptr as *const u32).read_unaligned() } as usize;
    let row_size = size_of::<Row>();
    if row_size == 0 {
        return None;
    }
    let max_rows = (valid_bytes - table_offset) / row_size;
    let safe_count = raw_count.min(max_rows);
    for i in 0..safe_count {
        let offset = table_offset + i * row_size;
        // SAFETY: `offset + row_size <= valid_bytes <= raw_bytes.len()`, reading an independent copy via raw pointer.
        let row = unsafe { (raw_ptr.add(offset) as *const Row).read_unaligned() };
        if let Some(pid) = matcher(&row) {
            return Some(pid);
        }
    }
    None
}

fn query_ip_helper_owner_pid_table<Row: Copy, Fetch, Match>(
    table_offset: usize,
    mut fetch_fn: Fetch,
    mut matcher: Match,
) -> Option<u32>
where
    Fetch: FnMut(*mut std::ffi::c_void, *mut u32) -> u32,
    Match: FnMut(&Row) -> Option<u32>,
{
    use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;

    unsafe {
        for _ in 0..4 {
            let mut size = 0u32;
            let _ = fetch_fn(std::ptr::null_mut(), &mut size);
            if size == 0 {
                return None;
            }

            let alloc_bytes = (size as usize).saturating_add(512);
            let u32_elements = alloc_bytes.div_ceil(4);
            let buf_byte_len = u32_elements.checked_mul(4)?;
            let Ok(mut actual_size) = u32::try_from(buf_byte_len) else {
                return None;
            };
            let mut buffer: Vec<u32> = vec![0u32; u32_elements];

            let ret = fetch_fn(buffer.as_mut_ptr().cast(), &mut actual_size);
            if ret == ERROR_INSUFFICIENT_BUFFER {
                continue;
            }
            if ret != 0 {
                return None;
            }

            let raw_bytes = std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), buf_byte_len);
            return find_in_tcp_table_bytes::<Row, _>(
                raw_bytes,
                actual_size as usize,
                table_offset,
                &mut matcher,
            );
        }
    }

    None
}

fn query_extended_tcp_table<Row: Copy, F>(
    af: u32,
    table_offset: usize,
    matcher: F,
) -> Option<u32>
where
    F: FnMut(&Row) -> Option<u32>,
{
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL,
    };

    query_ip_helper_owner_pid_table::<Row, _, _>(
        table_offset,
        |ptr, size_ptr| unsafe {
            GetExtendedTcpTable(ptr, size_ptr, 0, af, TCP_TABLE_OWNER_PID_ALL, 0)
        },
        matcher,
    )
}

fn query_extended_udp_table<Row: Copy, F>(
    af: u32,
    table_offset: usize,
    matcher: F,
) -> Option<u32>
where
    F: FnMut(&Row) -> Option<u32>,
{
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedUdpTable, UDP_TABLE_OWNER_PID,
    };

    query_ip_helper_owner_pid_table::<Row, _, _>(
        table_offset,
        |ptr, size_ptr| unsafe {
            GetExtendedUdpTable(ptr, size_ptr, 0, af, UDP_TABLE_OWNER_PID, 0)
        },
        matcher,
    )
}

fn query_windows_tcp_v4(client_v4: SocketAddrV4, server_v4: SocketAddrV4) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let table_offset = std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
    query_extended_tcp_table::<MIB_TCPROW_OWNER_PID, _>(AF_INET as u32, table_offset, |row| {
        if row.dwOwningPid == 0 {
            return None;
        }
        let local_port = u16::from_be((row.dwLocalPort & 0xffff) as u16);
        let remote_port = u16::from_be((row.dwRemotePort & 0xffff) as u16);
        if local_port != client_v4.port() || remote_port != server_v4.port() {
            return None;
        }
        let local_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
        let remote_ip = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());
        if local_ip == *client_v4.ip() && remote_ip == *server_v4.ip() {
            Some(row.dwOwningPid)
        } else {
            None
        }
    })
}

fn query_windows_tcp_v6(client_v6: SocketAddrV6, server_v6: SocketAddrV6) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET6;

    let table_offset = std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table);
    query_extended_tcp_table::<MIB_TCP6ROW_OWNER_PID, _>(AF_INET6 as u32, table_offset, |row| {
        if row.dwOwningPid == 0 {
            return None;
        }
        let local_port = u16::from_be((row.dwLocalPort & 0xffff) as u16);
        let remote_port = u16::from_be((row.dwRemotePort & 0xffff) as u16);
        if local_port != client_v6.port() || remote_port != server_v6.port() {
            return None;
        }
        let local_ip = Ipv6Addr::from(row.ucLocalAddr);
        let remote_ip = Ipv6Addr::from(row.ucRemoteAddr);
        if local_ip == *client_v6.ip() && remote_ip == *server_v6.ip() {
            Some(row.dwOwningPid)
        } else {
            None
        }
    })
}

fn get_pid_by_connection(client: SocketAddr, server: SocketAddr) -> Option<u32> {
    match (client, server) {
        (SocketAddr::V4(client_v4), SocketAddr::V4(server_v4)) => {
            if let Some(pid) = query_windows_tcp_v4(client_v4, server_v4) {
                return Some(pid);
            }
            if let Some((c_v6, s_v6)) = normalize_ipv6_pair(client, server) {
                return query_windows_tcp_v6(c_v6, s_v6);
            }
            None
        }
        (SocketAddr::V6(client_v6), SocketAddr::V6(server_v6)) => {
            if let Some(pid) = query_windows_tcp_v6(client_v6, server_v6) {
                return Some(pid);
            }
            if let Some((c_v4, s_v4)) = normalize_ipv4_pair(client, server) {
                return query_windows_tcp_v4(c_v4, s_v4);
            }
            None
        }
        _ => {
            if let Some((c_v4, s_v4)) = normalize_ipv4_pair(client, server)
                && let Some(pid) = query_windows_tcp_v4(c_v4, s_v4)
            {
                return Some(pid);
            }
            if let Some((c_v6, s_v6)) = normalize_ipv6_pair(client, server) {
                return query_windows_tcp_v6(c_v6, s_v6);
            }
            None
        }
    }
}

fn query_windows_udp_v4(target_ip: Option<Ipv4Addr>, target_port: u16) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let table_offset = std::mem::offset_of!(MIB_UDPTABLE_OWNER_PID, table);
    let mut wild_pid: Option<u32> = None;
    let exact = query_extended_udp_table::<MIB_UDPROW_OWNER_PID, _>(AF_INET as u32, table_offset, |row| {
        let local_port = u16::from_be((row.dwLocalPort & 0xffff) as u16);
        if local_port != target_port || row.dwOwningPid == 0 {
            return None;
        }
        let local_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
        if target_ip.is_some_and(|req_ip| local_ip == req_ip) {
            return Some(row.dwOwningPid);
        }
        if local_ip.is_unspecified() && wild_pid.is_none() {
            wild_pid = Some(row.dwOwningPid);
        }
        None
    });
    exact.or(wild_pid)
}

fn query_windows_udp_v6(target_ip: Option<Ipv6Addr>, target_port: u16) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET6;

    let table_offset = std::mem::offset_of!(MIB_UDP6TABLE_OWNER_PID, table);
    let mut wild_pid: Option<u32> = None;
    let exact = query_extended_udp_table::<MIB_UDP6ROW_OWNER_PID, _>(AF_INET6 as u32, table_offset, |row| {
        let local_port = u16::from_be((row.dwLocalPort & 0xffff) as u16);
        if local_port != target_port || row.dwOwningPid == 0 {
            return None;
        }
        let local_ip = Ipv6Addr::from(row.ucLocalAddr);
        if target_ip.is_some_and(|req_ip| local_ip == req_ip) {
            return Some(row.dwOwningPid);
        }
        if local_ip.is_unspecified() && wild_pid.is_none() {
            wild_pid = Some(row.dwOwningPid);
        }
        None
    });
    exact.or(wild_pid)
}

fn get_pid_by_udp_endpoint(local: SocketAddr) -> Option<u32> {
    match local.ip().to_canonical() {
        std::net::IpAddr::V4(v4) => query_windows_udp_v4(Some(v4), local.port())
            .or_else(|| query_windows_udp_v6(Some(v4.to_ipv6_mapped()), local.port())),
        std::net::IpAddr::V6(v6) => query_windows_udp_v6(Some(v6), local.port()),
    }
}

/// 透明代理在 `SocketPidTable` 未命中时的 OS 套接字表同步回退查询（Windows `GetExtendedTcpTable` / `GetExtendedUdpTable`）
pub fn lookup_outbound_socket_pid(
    protocol: u8,
    local: SocketAddr,
    remote: SocketAddr,
) -> Option<u32> {
    match protocol {
        6 => get_pid_by_connection(local, remote).filter(|&p| p != 0),
        17 => get_pid_by_udp_endpoint(local).filter(|&p| p != 0),
        _ => None,
    }
}

struct HandleGuard(windows_sys::Win32::Foundation::HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

fn query_windows_process_creation_time(handle: windows_sys::Win32::Foundation::HANDLE) -> Option<u128> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::GetProcessTimes;

    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    let ok = unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
    if ok == 0 {
        return None;
    }
    Some(((creation.dwHighDateTime as u128) << 32) | (creation.dwLowDateTime as u128))
}

fn get_process_start_time(pid: u32) -> Option<u128> {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    if pid == 0 {
        return None;
    }
    if pid == 4 {
        return Some(0);
    }
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let _guard = HandleGuard(handle);
    query_windows_process_creation_time(handle)
}

fn get_process_identity(pid: u32) -> Option<(String, Option<u128>)> {
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    if pid == 0 {
        return None;
    }
    if pid == 4 {
        return Some(("System".to_string(), Some(0)));
    }

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let _guard = HandleGuard(handle);

    let start_time = query_windows_process_creation_time(handle);
    let mut cap = 1024usize;
    while cap <= 32768 {
        let mut buf = vec![0u16; cap];
        let mut size = buf.len() as u32;
        let ret = unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size) };
        if ret != 0 {
            if size == 0 || (size as usize) > buf.len() {
                return None;
            }
            let path = String::from_utf16_lossy(&buf[..size as usize]);
            return Some((path, start_time));
        }
        let last_err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        if last_err == windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER {
            cap = cap.saturating_mul(2);
            continue;
        }
        return None;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn test_process_tracker_nonexistent_connection_returns_none() {
        let tracker = ProcessTracker::new();
        let client: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let server: SocketAddr = "127.0.0.1:2".parse().unwrap();
        assert!(tracker.find_by_connection(client, server).is_none());
        assert_eq!(tracker.cleanup_expired(), 0);
    }

    #[test]
    fn test_find_own_process_by_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let server = listener.local_addr().unwrap();
        let client_stream = std::net::TcpStream::connect(server).unwrap();
        let (_accepted, peer) = listener.accept().unwrap();
        assert_eq!(peer, client_stream.local_addr().unwrap());

        let tracker = ProcessTracker::new();
        let info = tracker
            .find_by_connection(peer, server)
            .expect("Should locate current IPv4 process");
        assert_eq!(info.pid, std::process::id());
    }

    #[test]
    fn test_find_own_process_by_ipv6_connection() {
        let Ok(listener) = std::net::TcpListener::bind("[::1]:0") else {
            return; // 跳过未启用 IPv6 回环的环境
        };
        let server = listener.local_addr().unwrap();
        let Ok(client_stream) = std::net::TcpStream::connect(server) else {
            return;
        };
        let (_accepted, peer) = listener.accept().unwrap();
        assert_eq!(peer, client_stream.local_addr().unwrap());

        let tracker = ProcessTracker::new();
        let info = tracker
            .find_by_connection(peer, server)
            .expect("Should locate current IPv6 process");
        assert_eq!(info.pid, std::process::id());
    }

    #[tokio::test]
    async fn test_find_by_connection_async_nonexistent() {
        let tracker = Arc::new(ProcessTracker::new());
        let client: SocketAddr = "127.0.0.1:3".parse().unwrap();
        let server: SocketAddr = "127.0.0.1:4".parse().unwrap();
        assert!(tracker.find_by_connection_async(client, server).await.is_none());
    }

    #[test]
    fn test_find_in_tcp_table_bytes_safety_and_clamping() {
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct SyntheticRow {
            local_port: u16,
            remote_port: u16,
            pid: u32,
        }

        let header_offset = 4usize;
        let row_size = size_of::<SyntheticRow>();
        assert_eq!(row_size, 8);

        // 构造含 3 行的缓冲区（第 3 行 index=2），同时测试超过 1 行迭代无 Stacked-Borrows UB
        let mut buf = vec![0u8; header_offset + 3 * row_size];
        buf[0..4].copy_from_slice(&3u32.to_ne_bytes());

        let write_row = |dst: &mut [u8], idx: usize, row: SyntheticRow| {
            let start = header_offset + idx * row_size;
            dst[start..start + 2].copy_from_slice(&row.local_port.to_ne_bytes());
            dst[start + 2..start + 4].copy_from_slice(&row.remote_port.to_ne_bytes());
            dst[start + 4..start + 8].copy_from_slice(&row.pid.to_ne_bytes());
        };

        write_row(&mut buf, 0, SyntheticRow { local_port: 1000, remote_port: 80, pid: 111 });
        write_row(&mut buf, 1, SyntheticRow { local_port: 2000, remote_port: 443, pid: 222 });
        write_row(&mut buf, 2, SyntheticRow { local_port: 3000, remote_port: 8080, pid: 333 });

        let found = find_in_tcp_table_bytes::<SyntheticRow, _>(&buf, buf.len(), header_offset, |r| {
            (r.local_port == 3000 && r.remote_port == 8080).then_some(r.pid)
        });
        assert_eq!(found, Some(333));

        // 畸形 dwNumEntries = u32::MAX 且 actual_size > buf.len()，必须被安全钳制而不越界读
        buf[0..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        let clamped = find_in_tcp_table_bytes::<SyntheticRow, _>(&buf, usize::MAX, header_offset, |r| {
            (r.local_port == 2000).then_some(r.pid)
        });
        assert_eq!(clamped, Some(222));

        // actual_size 小于 2 行时，第 2 行 (index=1) 不可越过 actual_size 读取
        let truncated = find_in_tcp_table_bytes::<SyntheticRow, _>(
            &buf,
            header_offset + row_size + 3,
            header_offset,
            |r| (r.local_port == 2000).then_some(r.pid),
        );
        assert_eq!(truncated, None);

        // actual_size < table_offset 返回 None
        assert_eq!(
            find_in_tcp_table_bytes::<SyntheticRow, _>(&buf, 2, header_offset, |r| Some(r.pid)),
            None
        );
    }

    #[test]
    fn test_pid_cache_start_time_invalidation_and_no_unknown_cache() {
        let tracker = ProcessTracker::new();
        let t0 = Instant::now();
        let identity_calls = Cell::new(0);

        // 1. 首次查询成功，写入 pid_cache 并记录启动时间戳 100
        let first = tracker
            .resolve_pid_with(
                4242,
                t0,
                |_| Some(100),
                |_| {
                    identity_calls.set(identity_calls.get() + 1);
                    Some(("C:\\Apps\\curl.exe".to_string(), Some(100)))
                },
            )
            .unwrap();
        assert_eq!(first.name, "curl.exe");
        assert_eq!(identity_calls.get(), 1);

        // 2. 启动时间戳一致 -> 命中缓存，不触发完整路径反查
        let hit = tracker
            .resolve_pid_with(
                4242,
                t0,
                |_| Some(100),
                |_| {
                    identity_calls.set(identity_calls.get() + 1);
                    Some(("C:\\Apps\\unexpected.exe".to_string(), Some(100)))
                },
            )
            .unwrap();
        assert_eq!(hit.name, "curl.exe");
        assert_eq!(identity_calls.get(), 1);

        // 3. PID 被新进程复用（启动时间戳变为 200）-> 旧缓存失效并刷新
        let reused = tracker
            .resolve_pid_with(
                4242,
                t0,
                |_| Some(200),
                |_| {
                    identity_calls.set(identity_calls.get() + 1);
                    Some(("C:\\Apps\\git.exe".to_string(), Some(200)))
                },
            )
            .unwrap();
        assert_eq!(reused.name, "git.exe");
        assert_eq!(identity_calls.get(), 2);

        // 4. 短命进程退出导致完整路径查询返回 None -> 必须返回 None 且绝不将 Unknown 写入 pid_cache
        let missing = tracker.resolve_pid_with(9999, t0, |_| None, |_| None);
        assert!(missing.is_none());
        assert!(tracker.pid_cache.get_cloned(&9999, t0).is_none());
    }

    #[test]
    fn test_bounded_cache_capacity_and_expiry() {
        let tracker = ProcessTracker::with_config(Duration::from_millis(40), 3);
        let t0 = Instant::now();

        for i in 1..=5u32 {
            let entry = PidCacheEntry {
                info: ProcessInfo {
                    pid: i,
                    path: format!("C:\\Apps\\p{}.exe", i),
                    name: format!("p{}.exe", i),
                },
                start_time: Some(i as u128),
            };
            tracker.pid_cache.insert(i, entry, t0 + Duration::from_millis(i as u64));
        }

        // 受 MAX 容量=3 约束，最老的条目 (1, 2) 应已被逐出，保留最新 (3, 4, 5)
        assert_eq!(tracker.pid_cache.state.read().unwrap().entries.len(), 3);
        assert!(tracker.pid_cache.get_cloned(&1, t0).is_none());
        assert!(tracker.pid_cache.get_cloned(&5, t0).is_some());

        std::thread::sleep(Duration::from_millis(60));
        let cleaned_pids = tracker.cleanup_expired();
        assert_eq!(cleaned_pids, 3);
        assert_eq!(tracker.cleanup_expired(), 0);
    }

    #[tokio::test]
    async fn test_resolve_pid_and_async_caches_current_process() {
        let tracker = Arc::new(ProcessTracker::new());
        let pid = std::process::id();
        let sync_info = tracker.resolve_pid(pid).expect("current pid should resolve synchronously");
        assert_eq!(sync_info.pid, pid);
        assert!(!sync_info.path.is_empty());
        assert!(!sync_info.name.is_empty());

        let async_info = tracker
            .resolve_pid_async(pid)
            .await
            .expect("current pid should resolve asynchronously");
        assert_eq!(async_info.pid, pid);
        assert_eq!(async_info.path, sync_info.path);
    }

    #[test]
    fn test_lookup_outbound_socket_pid_udp_and_tcp_fallback() {
        let udp_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_local = udp_sock.local_addr().unwrap();
        let udp_pid = lookup_outbound_socket_pid(17, udp_local, "1.1.1.1:53".parse().unwrap());
        assert_eq!(udp_pid, Some(std::process::id()));

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(server_addr).unwrap();
        let _accepted = listener.accept().unwrap();
        let client_local = client.local_addr().unwrap();
        let tcp_pid = lookup_outbound_socket_pid(6, client_local, server_addr);
        assert_eq!(tcp_pid, Some(std::process::id()));

        // PID 0 (Idle/TIME_WAIT 无归属槽位) 绝不可被误判为 Windows System 内核进程（仅 PID 4 为 System）
        let tracker = ProcessTracker::new();
        assert!(tracker.resolve_pid(0).is_none());
        let sys_info = tracker.resolve_pid(4).expect("PID 4 should resolve to System");
        assert_eq!(sys_info.name, "System");

        // 双栈 IPv6 UDP 套接字（显式绑定 ::ffff:127.0.0.1 或 [::]）按 IPv4 地址查询也应命中本进程 PID
        if let Ok(v6_sock) = std::net::UdpSocket::bind("[::]:0") {
            let v6_port = v6_sock.local_addr().unwrap().port();
            let v4_lookup = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), v6_port);
            assert_eq!(
                lookup_outbound_socket_pid(17, v4_lookup, "1.1.1.1:53".parse().unwrap()),
                Some(std::process::id())
            );
        }
    }
}
