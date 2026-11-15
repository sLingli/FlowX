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
/// 跨用户/权限受限 PID 负缓存最大条目数
const MAX_NEG_PID_CACHE: usize = 1024;
/// 周期性插入时清理过期条目的最小间隔
const CACHE_SWEEP_INTERVAL: Duration = Duration::from_secs(2);
/// 并发执行阻塞式进程反查的最大任务数
const LOOKUP_SEMAPHORE_PERMITS: usize = 8;
/// 获取进程反查信号量的等待上限（高突发下优雅降级为未归属，避免打满阻塞线程池）
const LOOKUP_SEMAPHORE_TIMEOUT: Duration = Duration::from_millis(200);
/// PID 正向缓存默认有效期
const DEFAULT_PID_TTL: Duration = Duration::from_secs(10);
/// 不可访问 PID (`EACCES`/`EPERM`) 负缓存默认有效期
const DEFAULT_NEG_PID_TTL: Duration = Duration::from_secs(6);

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

    #[cfg(any(target_os = "linux", target_os = "macos", test))]
    fn contains_active(&self, key: &K, now: Instant) -> bool {
        let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
        guard
            .entries
            .get(key)
            .is_some_and(|slot| slot.expires_at > now)
    }

    fn get_cloned(&self, key: &K, now: Instant) -> Option<V> {
        let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
        guard
            .entries
            .get(key)
            .filter(|slot| slot.expires_at > now)
            .map(|slot| slot.value.clone())
    }

    #[cfg(any(target_os = "linux", target_os = "macos", test))]
    fn active_keys(&self, now: Instant) -> Vec<K> {
        let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
        guard
            .entries
            .iter()
            .filter(|(_, slot)| slot.expires_at > now)
            .map(|(k, _)| *k)
            .collect()
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
    neg_pid_cache: BoundedCache<u32, ()>,
    lookup_semaphore: Arc<Semaphore>,
}

impl ProcessTracker {
    pub fn new() -> Self {
        Self::with_config(
            DEFAULT_PID_TTL,
            DEFAULT_NEG_PID_TTL,
            MAX_PID_CACHE,
            MAX_NEG_PID_CACHE,
        )
    }

    fn with_config(
        pid_ttl: Duration,
        neg_ttl: Duration,
        max_pid_entries: usize,
        max_neg_entries: usize,
    ) -> Self {
        Self {
            pid_cache: BoundedCache::new(pid_ttl, max_pid_entries),
            neg_pid_cache: BoundedCache::new(neg_ttl, max_neg_entries),
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

        #[cfg(target_os = "linux")]
        let pid = {
            let hint_pids = self.pid_cache.active_keys(now);
            get_pid_by_connection_with_hints(client, server, &hint_pids, &self.neg_pid_cache, now)?
        };

        #[cfg(target_os = "macos")]
        let pid = {
            let hint_pids = self.pid_cache.active_keys(now);
            get_pid_by_connection_with_hints(client, server, &hint_pids, &self.neg_pid_cache, now)?
        };

        #[cfg(windows)]
        let pid = get_pid_by_connection(client, server)?;

        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
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

    /// 清理过期的 PID 正/负缓存项，返回 `(pid_cleaned, neg_cleaned)`
    pub fn cleanup_expired(&self) -> (usize, usize) {
        let now = Instant::now();
        let cleaned_pids = self.pid_cache.cleanup_expired(now);
        let cleaned_neg = self.neg_pid_cache.cleanup_expired(now);
        (cleaned_pids, cleaned_neg)
    }
}

impl Default for ProcessTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn is_system_pid(pid: u32) -> bool {
    #[cfg(windows)]
    {
        pid == 0 || pid == 4
    }
    #[cfg(not(windows))]
    {
        pid == 0
    }
}

fn extract_process_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| path.trim())
        .to_string()
}

#[cfg(any(windows, target_os = "linux", test))]
fn normalize_ipv4_pair(client: SocketAddr, server: SocketAddr) -> Option<(SocketAddrV4, SocketAddrV4)> {
    let to_v4 = |addr: SocketAddr| -> Option<SocketAddrV4> {
        match addr {
            SocketAddr::V4(v4) => Some(v4),
            SocketAddr::V6(v6) => Some(SocketAddrV4::new(v6.ip().to_ipv4_mapped()?, v6.port())),
        }
    };
    Some((to_v4(client)?, to_v4(server)?))
}

#[cfg(any(windows, target_os = "linux", test))]
fn normalize_ipv6_pair(client: SocketAddr, server: SocketAddr) -> Option<(SocketAddrV6, SocketAddrV6)> {
    let to_v6 = |addr: SocketAddr| -> SocketAddrV6 {
        match addr {
            SocketAddr::V6(v6) => v6,
            SocketAddr::V4(v4) => SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0),
        }
    };
    Some((to_v6(client), to_v6(server)))
}

#[cfg(any(windows, test))]
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

#[cfg(windows)]
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

#[cfg(windows)]
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

#[cfg(windows)]
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

#[cfg(windows)]
fn query_windows_tcp_v4(client_v4: SocketAddrV4, server_v4: SocketAddrV4) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let table_offset = std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
    query_extended_tcp_table::<MIB_TCPROW_OWNER_PID, _>(AF_INET as u32, table_offset, |row| {
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

#[cfg(windows)]
fn query_windows_tcp_v6(client_v6: SocketAddrV6, server_v6: SocketAddrV6) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET6;

    let table_offset = std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table);
    query_extended_tcp_table::<MIB_TCP6ROW_OWNER_PID, _>(AF_INET6 as u32, table_offset, |row| {
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

#[cfg(windows)]
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

#[cfg(windows)]
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

#[cfg(windows)]
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

#[cfg(windows)]
fn get_pid_by_udp_endpoint(local: SocketAddr) -> Option<u32> {
    match local.ip().to_canonical() {
        std::net::IpAddr::V4(v4) => query_windows_udp_v4(Some(v4), local.port())
            .or_else(|| query_windows_udp_v6(None, local.port())),
        std::net::IpAddr::V6(v6) => query_windows_udp_v6(Some(v6), local.port()),
    }
}

/// 透明代理在 `SocketPidTable` 未命中时的 OS 套接字表同步回退查询（Windows `GetExtendedTcpTable` / `GetExtendedUdpTable`）
pub fn lookup_outbound_socket_pid(
    protocol: u8,
    local: SocketAddr,
    remote: SocketAddr,
) -> Option<u32> {
    #[cfg(windows)]
    {
        match protocol {
            6 => get_pid_by_connection(local, remote).filter(|&p| p != 0),
            17 => get_pid_by_udp_endpoint(local).filter(|&p| p != 0),
            _ => None,
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (protocol, local, remote);
        None
    }
}

#[cfg(windows)]
struct HandleGuard(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

#[cfg(windows)]
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

#[cfg(windows)]
fn get_process_start_time(pid: u32) -> Option<u128> {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    if pid == 0 || pid == 4 {
        return Some(0);
    }
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let _guard = HandleGuard(handle);
    query_windows_process_creation_time(handle)
}

#[cfg(windows)]
fn get_process_identity(pid: u32) -> Option<(String, Option<u128>)> {
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    if pid == 0 || pid == 4 {
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

#[cfg(target_os = "linux")]
fn get_pid_by_connection_with_hints(
    client: SocketAddr,
    server: SocketAddr,
    hint_pids: &[u32],
    neg_cache: &BoundedCache<u32, ()>,
    now: Instant,
) -> Option<u32> {
    let (inode, sock_uid) = find_socket_inode_linux(client, server)?;
    find_pid_by_socket_inode_linux(inode, sock_uid, hint_pids, neg_cache, now)
}

#[cfg(target_os = "linux")]
fn find_socket_inode_linux(client: SocketAddr, server: SocketAddr) -> Option<(u64, Option<u32>)> {
    use std::fs::File;
    use std::io::BufReader;

    let try_tcp4 = |c_v4: SocketAddrV4, s_v4: SocketAddrV4| -> Option<(u64, Option<u32>)> {
        let file = File::open("/proc/net/tcp").ok()?;
        find_socket_meta_in_proc_tcp_reader(BufReader::new(file), c_v4, s_v4)
    };
    let try_tcp6 = |c_v6: SocketAddrV6, s_v6: SocketAddrV6| -> Option<(u64, Option<u32>)> {
        let file = File::open("/proc/net/tcp6").ok()?;
        find_socket_meta_in_proc_tcp6_reader(BufReader::new(file), c_v6, s_v6)
    };

    match (client, server) {
        (SocketAddr::V4(c_v4), SocketAddr::V4(s_v4)) => {
            if let Some(meta) = try_tcp4(c_v4, s_v4) {
                return Some(meta);
            }
            if let Some((c_v6, s_v6)) = normalize_ipv6_pair(client, server) {
                return try_tcp6(c_v6, s_v6);
            }
            None
        }
        (SocketAddr::V6(c_v6), SocketAddr::V6(s_v6)) => {
            if let Some(meta) = try_tcp6(c_v6, s_v6) {
                return Some(meta);
            }
            if let Some((c_v4, s_v4)) = normalize_ipv4_pair(client, server) {
                return try_tcp4(c_v4, s_v4);
            }
            None
        }
        _ => {
            if let Some((c_v4, s_v4)) = normalize_ipv4_pair(client, server)
                && let Some(meta) = try_tcp4(c_v4, s_v4)
            {
                return Some(meta);
            }
            if let Some((c_v6, s_v6)) = normalize_ipv6_pair(client, server) {
                return try_tcp6(c_v6, s_v6);
            }
            None
        }
    }
}

#[cfg(target_os = "linux")]
enum PidFdProbe {
    Matched,
    NoMatch,
    PermissionDenied,
}

#[cfg(target_os = "linux")]
fn proc_pid_owns_socket_inode(pid: u32, inode: u64) -> PidFdProbe {
    let fd_dir = format!("/proc/{}/fd", pid);
    let entries = match std::fs::read_dir(fd_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            return PidFdProbe::PermissionDenied;
        }
        Err(_) => return PidFdProbe::NoMatch,
    };
    for entry in entries.flatten() {
        if let Ok(target) = std::fs::read_link(entry.path())
            && let Some(target_str) = target.to_str()
            && matches_socket_inode(target_str, inode)
        {
            return PidFdProbe::Matched;
        }
    }
    PidFdProbe::NoMatch
}

#[cfg(target_os = "linux")]
fn find_pid_by_socket_inode_linux(
    inode: u64,
    sock_uid: Option<u32>,
    hint_pids: &[u32],
    neg_cache: &BoundedCache<u32, ()>,
    now: Instant,
) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;

    let probe_pid = |pid: u32| -> bool {
        if neg_cache.contains_active(&pid, now) {
            return false;
        }
        match proc_pid_owns_socket_inode(pid, inode) {
            PidFdProbe::Matched => true,
            PidFdProbe::PermissionDenied => {
                neg_cache.insert(pid, (), now);
                false
            }
            PidFdProbe::NoMatch => false,
        }
    };

    // 1. 快路径：优先探测最近活跃进程
    for &pid in hint_pids {
        if probe_pid(pid) {
            return Some(pid);
        }
    }

    // 2. 慢路径：遍历 /proc 下纯数字 PID 目录，若已解析出套接字 UID 则先探测同 UID 进程
    let entries = std::fs::read_dir("/proc").ok()?;
    let mut deferred_pids: Vec<u32> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if name_str.is_empty() || !name_str.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(pid) = name_str.parse::<u32>() else {
            continue;
        };
        if hint_pids.contains(&pid) || neg_cache.contains_active(&pid, now) {
            continue;
        }
        if let Some(target_uid) = sock_uid {
            let dir_uid = entry.metadata().ok().map(|m| m.uid());
            if dir_uid != Some(target_uid) {
                deferred_pids.push(pid);
                continue;
            }
        }
        if probe_pid(pid) {
            return Some(pid);
        }
    }

    // 3. 回退：兼容跨 UID fd 继承/传递或 setuid 服务场景
    for pid in deferred_pids {
        if probe_pid(pid) {
            return Some(pid);
        }
    }
    None
}

#[cfg(any(target_os = "linux", test))]
fn parse_proc_u64(raw: &str) -> Option<u64> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse::<u64>().ok()
}

/// 解析 `/proc/net/tcp` 单列十六进制 `HHHHHHHH:PPPP` 地址（IP 按主机字节序编码，端口按大端编码）
#[cfg(any(target_os = "linux", test))]
fn parse_proc_net_ipv4_addr(raw: &str) -> Option<(Ipv4Addr, u16)> {
    let (ip_hex, port_hex) = raw.split_once(':')?;
    if ip_hex.len() != 8
        || port_hex.len() != 4
        || !ip_hex.bytes().all(|b| b.is_ascii_hexdigit())
        || !port_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    let ip_host = u32::from_str_radix(ip_hex, 16).ok()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((Ipv4Addr::from(ip_host.to_ne_bytes()), port))
}

/// 解析 `/proc/net/tcp6` 单列十六进制 `32位Hex:PPPP` 地址（4 个 32-bit 字均按主机字节序编码）
#[cfg(any(target_os = "linux", test))]
fn parse_proc_net_ipv6_addr(raw: &str) -> Option<(Ipv6Addr, u16)> {
    let (ip_hex, port_hex) = raw.split_once(':')?;
    if ip_hex.len() != 32
        || port_hex.len() != 4
        || !ip_hex.bytes().all(|b| b.is_ascii_hexdigit())
        || !port_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let mut octets = [0u8; 16];
    for i in 0..4 {
        let word_hex = &ip_hex[i * 8..(i + 1) * 8];
        let word = u32::from_str_radix(word_hex, 16).ok()?;
        octets[i * 4..(i + 1) * 4].copy_from_slice(&word.to_ne_bytes());
    }
    Some((Ipv6Addr::from(octets), port))
}

#[cfg(any(target_os = "linux", test))]
fn parse_proc_u32(s: &str) -> Option<u32> {
    parse_proc_u64(s).and_then(|v| u32::try_from(v).ok())
}

#[cfg(any(target_os = "linux", test))]
fn find_socket_meta_in_proc_reader<R, A, P>(
    mut reader: R,
    target_local: (A, u16),
    target_rem: (A, u16),
    parse_addr: P,
) -> Option<(u64, Option<u32>)>
where
    R: std::io::BufRead,
    A: PartialEq,
    P: Fn(&str) -> Option<(A, u16)>,
{
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.read_line(&mut line).ok()?;
        if read == 0 {
            break;
        }
        let mut cols = line.split_ascii_whitespace();
        let Some(_sl) = cols.next() else {
            continue;
        };
        let Some(local_raw) = cols.next() else {
            continue;
        };
        let Some(rem_raw) = cols.next() else {
            continue;
        };
        if parse_addr(local_raw).as_ref() != Some(&target_local)
            || parse_addr(rem_raw).as_ref() != Some(&target_rem)
        {
            continue;
        }
        // 列布局: sl(0) local(1) rem(2) st(3) queue(4) tr(5) retrnsmt(6) uid(7) timeout(8) inode(9)
        let uid = cols.nth(4).and_then(parse_proc_u32);
        if let Some(inode_str) = cols.nth(1)
            && let Some(inode) = parse_proc_u64(inode_str)
            && inode > 0
        {
            return Some((inode, uid));
        }
    }
    None
}

#[cfg(any(target_os = "linux", test))]
fn find_socket_meta_in_proc_tcp_reader<R: std::io::BufRead>(
    reader: R,
    client: SocketAddrV4,
    server: SocketAddrV4,
) -> Option<(u64, Option<u32>)> {
    find_socket_meta_in_proc_reader(
        reader,
        (*client.ip(), client.port()),
        (*server.ip(), server.port()),
        parse_proc_net_ipv4_addr,
    )
}

#[cfg(any(target_os = "linux", test))]
fn find_socket_meta_in_proc_tcp6_reader<R: std::io::BufRead>(
    reader: R,
    client: SocketAddrV6,
    server: SocketAddrV6,
) -> Option<(u64, Option<u32>)> {
    find_socket_meta_in_proc_reader(
        reader,
        (*client.ip(), client.port()),
        (*server.ip(), server.port()),
        parse_proc_net_ipv6_addr,
    )
}

#[cfg(test)]
fn find_socket_inode_in_proc_tcp_reader<R: std::io::BufRead>(
    reader: R,
    client: SocketAddrV4,
    server: SocketAddrV4,
) -> Option<u64> {
    find_socket_meta_in_proc_tcp_reader(reader, client, server).map(|(inode, _)| inode)
}

#[cfg(test)]
fn find_socket_inode_in_proc_tcp6_reader<R: std::io::BufRead>(
    reader: R,
    client: SocketAddrV6,
    server: SocketAddrV6,
) -> Option<u64> {
    find_socket_meta_in_proc_tcp6_reader(reader, client, server).map(|(inode, _)| inode)
}

/// 在 `/proc/net/tcp` 文本中按完整四元组 (`local == client && remote == server`) 查找套接字 inode
#[cfg(test)]
fn find_socket_inode_in_proc_tcp(
    content: &str,
    client: SocketAddrV4,
    server: SocketAddrV4,
) -> Option<u64> {
    find_socket_inode_in_proc_tcp_reader(std::io::Cursor::new(content), client, server)
}

/// 在 `/proc/net/tcp6` 文本中按完整四元组 (`local == client && remote == server`) 查找套接字 inode
#[cfg(test)]
fn find_socket_inode_in_proc_tcp6(
    content: &str,
    client: SocketAddrV6,
    server: SocketAddrV6,
) -> Option<u64> {
    find_socket_inode_in_proc_tcp6_reader(std::io::Cursor::new(content), client, server)
}

/// 判断 `/proc/<pid>/fd/*` 符号链接目标是否指向指定套接字 inode（兼容 `socket:[inode]` 与 `[0000]:inode`）
#[cfg(any(target_os = "linux", test))]
fn matches_socket_inode(link_target: &str, inode: u64) -> bool {
    if let Some(rest) = link_target.strip_prefix("socket:[")
        && let Some(num_str) = rest.strip_suffix(']')
    {
        return parse_proc_u64(num_str) == Some(inode);
    }
    if let Some(rest) = link_target.strip_prefix("[0000]:") {
        return parse_proc_u64(rest) == Some(inode);
    }
    false
}

/// 解析 `/proc/<pid>/stat` 的第 22 字段 (`starttime`)，在最后一个 `')'` 之后切分以免疫含空格/括号的进程名
#[cfg(any(target_os = "linux", test))]
fn parse_proc_stat_starttime(stat_content: &str) -> Option<u128> {
    let close_paren = stat_content.rfind(')')?;
    let after_comm = stat_content.get(close_paren + 1..)?;
    // `after_comm` 首个空白分隔列为第 3 字段 (`state`)，索引 19 即为第 22 字段 (`starttime`)
    let starttime_str = after_comm.split_ascii_whitespace().nth(19)?;
    parse_proc_u64(starttime_str).map(u128::from)
}

#[cfg(target_os = "linux")]
fn get_process_start_time(pid: u32) -> Option<u128> {
    if pid == 0 {
        return Some(0);
    }
    let stat_path = format!("/proc/{}/stat", pid);
    let content = std::fs::read_to_string(stat_path).ok()?;
    parse_proc_stat_starttime(&content)
}

/// 清理 `/proc/<pid>/exe` 软链读取结果（剥离 Linux 内核对已覆盖二进制附加的 `" (deleted)"` 后缀）
#[cfg(any(target_os = "linux", test))]
fn clean_proc_exe_path(raw: &str) -> String {
    let trimmed = raw.trim_end_matches(['\r', '\n']);
    trimmed
        .strip_suffix(" (deleted)")
        .unwrap_or(trimmed)
        .to_string()
}

/// 规范化 `/proc/<pid>/cmdline` 的首个参数，剥离 ASCII 控制字符并截断前导空白
#[cfg(any(target_os = "linux", test))]
fn parse_proc_cmdline_argv0(bytes: &[u8]) -> Option<String> {
    let first_arg = bytes.split(|&b| b == 0).next().unwrap_or(bytes);
    let sanitized: String = String::from_utf8_lossy(first_arg)
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let trimmed = sanitized.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// 清理 `/proc/<pid>/comm` 进程短名中的目录分隔符与控制字符，避免破坏进程名提取与日志安全
#[cfg(any(target_os = "linux", test))]
fn sanitize_proc_comm_fallback(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| if c == '/' || c == '\\' { '_' } else { c })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(target_os = "linux")]
fn get_process_identity(pid: u32) -> Option<(String, Option<u128>)> {
    if pid == 0 {
        return Some(("kernel".to_string(), Some(0)));
    }

    let start_time = get_process_start_time(pid);

    // 1. 优先读取 /proc/<pid>/exe 符号链接以获得真实可执行文件绝对路径
    let exe_link = format!("/proc/{}/exe", pid);
    if let Ok(path_buf) = std::fs::read_link(&exe_link) {
        let cleaned = clean_proc_exe_path(&path_buf.to_string_lossy());
        if !cleaned.is_empty() {
            return Some((cleaned, start_time));
        }
    }

    // 2. 回退：受限读取 /proc/<pid>/cmdline 的前 4096 字节并取 argv[0]
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(file) = std::fs::File::open(&cmdline_path) {
        use std::io::Read;
        let mut bytes = Vec::with_capacity(256);
        if file.take(4096).read_to_end(&mut bytes).is_ok()
            && let Some(arg0) = parse_proc_cmdline_argv0(&bytes)
        {
            return Some((arg0, start_time));
        }
    }

    // 3. 回退：读取并清洗 /proc/<pid>/comm 进程短名
    let comm_path = format!("/proc/{}/comm", pid);
    if let Ok(comm) = std::fs::read_to_string(&comm_path)
        && let Some(cleaned) = sanitize_proc_comm_fallback(&comm)
    {
        return Some((cleaned, start_time));
    }

    None
}

// =========================================================================
// macOS XNU libproc (`<sys/proc_info.h>`) 结构布局与套接字/进程反查
// =========================================================================

#[cfg(any(target_os = "macos", test))]
mod macos_proc_info {
    use super::*;
    use std::net::IpAddr;

    pub const SOCKINFO_IN: i32 = 1;
    pub const SOCKINFO_TCP: i32 = 2;
    pub const INI_IPV4: u8 = 0x1;
    pub const INI_IPV6: u8 = 0x2;
    #[cfg(target_os = "macos")]
    pub const PROC_ALL_PIDS: u32 = 1;
    #[cfg(target_os = "macos")]
    pub const PROC_PIDFDSOCKETINFO: i32 = 3;
    const SOCK_MAXADDRLEN: usize = 255;
    const IF_NAMESIZE: usize = 16;
    const MAX_KCTL_NAME: usize = 96;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ProcFileInfo {
        pub fi_openflags: u32,
        pub fi_status: u32,
        pub fi_offset: i64,
        pub fi_type: i32,
        pub fi_guardflags: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct VinfoStat {
        pub vst_dev: u32,
        pub vst_mode: u16,
        pub vst_nlink: u16,
        pub vst_ino: u64,
        pub vst_uid: u32,
        pub vst_gid: u32,
        pub vst_atime: i64,
        pub vst_atimensec: i64,
        pub vst_mtime: i64,
        pub vst_mtimensec: i64,
        pub vst_ctime: i64,
        pub vst_ctimensec: i64,
        pub vst_birthtime: i64,
        pub vst_birthtimensec: i64,
        pub vst_size: i64,
        pub vst_blocks: i64,
        pub vst_blksize: i32,
        pub vst_flags: u32,
        pub vst_gen: u32,
        pub vst_rdev: u32,
        pub vst_qspare: [i64; 2],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct SockBufInfo {
        pub sbi_cc: u32,
        pub sbi_hiwat: u32,
        pub sbi_mbcnt: u32,
        pub sbi_mbmax: u32,
        pub sbi_lowat: u32,
        pub sbi_flags: i16,
        pub sbi_timeo: i16,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct In4In6Addr {
        pub i46a_pad32: [u32; 3],
        pub i46a_addr4: [u8; 4],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub union InAddrUnion {
        pub ina_46: In4In6Addr,
        pub ina_6: [u8; 16],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct InSockV4 {
        pub in4_tos: u8,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct InSockV6 {
        pub in6_hlim: u8,
        pub in6_cksum: i32,
        pub in6_ifindex: u16,
        pub in6_hops: i16,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct InSockInfo {
        pub insi_fport: i32,
        pub insi_lport: i32,
        pub insi_gencnt: u64,
        pub insi_flags: u32,
        pub insi_flow: u32,
        pub insi_vflag: u8,
        pub insi_ip_ttl: u8,
        pub rfu_1: u32,
        pub insi_faddr: InAddrUnion,
        pub insi_laddr: InAddrUnion,
        pub insi_v4: InSockV4,
        pub insi_v6: InSockV6,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct TcpSockInfo {
        pub tcpsi_ini: InSockInfo,
        pub tcpsi_state: i32,
        pub tcpsi_timer: [i32; 4],
        pub tcpsi_mss: i32,
        pub tcpsi_flags: u32,
        pub rfu_1: u32,
        pub tcpsi_tp: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct UnSockInfo {
        pub unsi_conn_so: u64,
        pub unsi_conn_pcb: u64,
        pub unsi_addr: [u8; SOCK_MAXADDRLEN],
        pub unsi_caddr: [u8; SOCK_MAXADDRLEN],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct NdrvInfo {
        pub ndrvsi_if_family: u32,
        pub ndrvsi_if_unit: u32,
        pub ndrvsi_if_name: [u8; IF_NAMESIZE],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct KernEventInfo {
        pub kesi_vendor_code_filter: u32,
        pub kesi_class_filter: u32,
        pub kesi_subclass_filter: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct KernCtlInfo {
        pub kcsi_id: u32,
        pub kcsi_reg_unit: u32,
        pub kcsi_flags: u32,
        pub kcsi_recvbufsize: u32,
        pub kcsi_sendbufsize: u32,
        pub kcsi_unit: u32,
        pub kcsi_name: [u8; MAX_KCTL_NAME],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct VsockSockInfo {
        pub local_cid: u32,
        pub local_port: u32,
        pub remote_cid: u32,
        pub remote_port: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub union SocketProtoUnion {
        pub pri_in: InSockInfo,
        pub pri_tcp: TcpSockInfo,
        pub pri_un: UnSockInfo,
        pub pri_ndrv: NdrvInfo,
        pub pri_kern_event: KernEventInfo,
        pub pri_kern_ctl: KernCtlInfo,
        pub pri_vsock: VsockSockInfo,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct SocketInfo {
        pub soi_stat: VinfoStat,
        pub soi_so: u64,
        pub soi_pcb: u64,
        pub soi_type: i32,
        pub soi_protocol: i32,
        pub soi_family: i32,
        pub soi_options: i16,
        pub soi_linger: i16,
        pub soi_state: i16,
        pub soi_qlen: i16,
        pub soi_incqlen: i16,
        pub soi_qlimit: i16,
        pub soi_timeo: i16,
        pub soi_error: u16,
        pub soi_oobmark: u32,
        pub soi_rcv: SockBufInfo,
        pub soi_snd: SockBufInfo,
        pub soi_kind: i32,
        pub rfu_1: u32,
        pub soi_proto: SocketProtoUnion,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct SocketFdInfo {
        pub pfi: ProcFileInfo,
        pub psi: SocketInfo,
    }

    fn canonical_ip(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        }
    }

    pub fn matches_macos_socket_info(
        info: &SocketFdInfo,
        client: SocketAddr,
        server: SocketAddr,
        tcp_proto: i32,
    ) -> bool {
        let psi = &info.psi;
        if psi.soi_kind != SOCKINFO_TCP && !(psi.soi_kind == SOCKINFO_IN && psi.soi_protocol == tcp_proto) {
            return false;
        }
        // SAFETY: `soi_kind` 已验证为 TCP/IN，对应联合体首字段均等价为 `InSockInfo`。
        let ini = unsafe { &psi.soi_proto.pri_tcp.tcpsi_ini };
        let local_port = u16::from_be((ini.insi_lport & 0xffff) as u16);
        let remote_port = u16::from_be((ini.insi_fport & 0xffff) as u16);
        if local_port != client.port() || remote_port != server.port() {
            return false;
        }

        let target_local = canonical_ip(client.ip());
        let target_remote = canonical_ip(server.ip());

        if ini.insi_vflag & INI_IPV4 != 0 {
            let local_ip = IpAddr::V4(Ipv4Addr::from(unsafe { ini.insi_laddr.ina_46.i46a_addr4 }));
            let remote_ip = IpAddr::V4(Ipv4Addr::from(unsafe { ini.insi_faddr.ina_46.i46a_addr4 }));
            if local_ip == target_local && remote_ip == target_remote {
                return true;
            }
        }

        if ini.insi_vflag & INI_IPV6 != 0 {
            let local_ip = canonical_ip(IpAddr::V6(Ipv6Addr::from(unsafe { ini.insi_laddr.ina_6 })));
            let remote_ip = canonical_ip(IpAddr::V6(Ipv6Addr::from(unsafe { ini.insi_faddr.ina_6 })));
            if local_ip == target_local && remote_ip == target_remote {
                return true;
            }
        }

        false
    }
}

#[cfg(target_os = "macos")]
fn macos_pid_owns_socket(
    pid: u32,
    client: SocketAddr,
    server: SocketAddr,
    neg_cache: &BoundedCache<u32, ()>,
    now: Instant,
) -> bool {
    use macos_proc_info::{matches_macos_socket_info, SocketFdInfo, PROC_PIDFDSOCKETINFO};

    if pid == 0 || neg_cache.contains_active(&pid, now) {
        return false;
    }

    let check_pidinfo = |ret: libc::c_int| -> bool {
        if ret < 0 {
            if let Some(errno) = std::io::Error::last_os_error().raw_os_error()
                && (errno == libc::EPERM || errno == libc::EACCES)
            {
                neg_cache.insert(pid, (), now);
            }
            return false;
        }
        ret > 0
    };

    let c_pid = pid as libc::c_int;
    let buf_bytes = unsafe { libc::proc_pidinfo(c_pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if !check_pidinfo(buf_bytes) {
        return false;
    }

    let elem_size = size_of::<libc::proc_fdinfo>();
    let capacity = (buf_bytes as usize / elem_size).saturating_add(16);
    let mut fds: Vec<libc::proc_fdinfo> = vec![unsafe { std::mem::zeroed() }; capacity];
    let actual_bytes = unsafe {
        libc::proc_pidinfo(
            c_pid,
            libc::PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr().cast(),
            (fds.len() * elem_size) as libc::c_int,
        )
    };
    if !check_pidinfo(actual_bytes) {
        return false;
    }

    let fd_count = (actual_bytes as usize / elem_size).min(fds.len());
    let sock_fd_size = size_of::<SocketFdInfo>() as libc::c_int;

    for fd in &fds[..fd_count] {
        if fd.proc_fdtype != libc::PROX_FDTYPE_SOCKET as u32 {
            continue;
        }
        let mut sock_info: SocketFdInfo = unsafe { std::mem::zeroed() };
        let got = unsafe {
            libc::proc_pidfdinfo(
                c_pid,
                fd.proc_fd,
                PROC_PIDFDSOCKETINFO,
                (&mut sock_info as *mut SocketFdInfo).cast(),
                sock_fd_size,
            )
        };
        if got == sock_fd_size
            && matches_macos_socket_info(&sock_info, client, server, libc::IPPROTO_TCP)
        {
            return true;
        }
    }
    false
}

#[cfg(target_os = "macos")]
fn get_pid_by_connection_with_hints(
    client: SocketAddr,
    server: SocketAddr,
    hint_pids: &[u32],
    neg_cache: &BoundedCache<u32, ()>,
    now: Instant,
) -> Option<u32> {
    for &pid in hint_pids {
        if macos_pid_owns_socket(pid, client, server, neg_cache, now) {
            return Some(pid);
        }
    }

    let need_bytes = unsafe {
        libc::proc_listpids(macos_proc_info::PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0)
    };
    if need_bytes <= 0 {
        return None;
    }

    let count = (need_bytes as usize / size_of::<libc::c_int>()).saturating_add(64);
    let mut pids: Vec<libc::c_int> = vec![0; count];
    let got_bytes = unsafe {
        libc::proc_listpids(
            macos_proc_info::PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr().cast(),
            (pids.len() * size_of::<libc::c_int>()) as libc::c_int,
        )
    };
    if got_bytes <= 0 {
        return None;
    }

    let actual_count = (got_bytes as usize / size_of::<libc::c_int>()).min(pids.len());
    for &raw_pid in &pids[..actual_count] {
        if raw_pid <= 0 {
            continue;
        }
        let pid = raw_pid as u32;
        if hint_pids.contains(&pid) {
            continue;
        }
        if macos_pid_owns_socket(pid, client, server, neg_cache, now) {
            return Some(pid);
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn macos_read_bsdinfo(pid: u32) -> Option<libc::proc_bsdinfo> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let expected = size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let ret = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            expected,
        )
    };
    if ret == expected {
        Some(info)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn macos_cstr_array_to_string(bytes: &[libc::c_char]) -> Option<String> {
    let u8_bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<u8>(), bytes.len()) };
    let nul_pos = u8_bytes.iter().position(|&b| b == 0).unwrap_or(u8_bytes.len());
    let s = String::from_utf8_lossy(&u8_bytes[..nul_pos]).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(target_os = "macos")]
fn get_process_start_time(pid: u32) -> Option<u128> {
    if pid == 0 {
        return Some(0);
    }
    let info = macos_read_bsdinfo(pid)?;
    Some((info.pbi_start_tvsec as u128) * 1_000_000 + (info.pbi_start_tvusec as u128))
}

#[cfg(target_os = "macos")]
fn get_process_identity(pid: u32) -> Option<(String, Option<u128>)> {
    if pid == 0 {
        return Some(("kernel".to_string(), Some(0)));
    }

    let bsd = macos_read_bsdinfo(pid);
    let start_time = bsd
        .as_ref()
        .map(|b| (b.pbi_start_tvsec as u128) * 1_000_000 + (b.pbi_start_tvusec as u128));

    let mut path_buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let ret = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            path_buf.as_mut_ptr().cast(),
            path_buf.len() as u32,
        )
    };
    if ret > 0 && (ret as usize) <= path_buf.len() {
        let path = String::from_utf8_lossy(&path_buf[..ret as usize])
            .trim()
            .to_string();
        if !path.is_empty() {
            return Some((path, start_time));
        }
    }

    if let Some(info) = bsd {
        if let Some(name) = macos_cstr_array_to_string(&info.pbi_name) {
            return Some((name, start_time));
        }
        if let Some(comm) = macos_cstr_array_to_string(&info.pbi_comm) {
            return Some((comm, start_time));
        }
    }

    None
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn get_pid_by_connection(_client: SocketAddr, _server: SocketAddr) -> Option<u32> {
    None
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn get_process_start_time(_pid: u32) -> Option<u128> {
    None
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn get_process_identity(_pid: u32) -> Option<(String, Option<u128>)> {
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
        assert_eq!(tracker.cleanup_expired(), (0, 0));
    }

    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
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

    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
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
    fn test_linux_proc_net_tcp_and_tcp6_parsers_hardened() {
        let c_ip = Ipv4Addr::new(127, 0, 0, 1);
        let s_ip = Ipv4Addr::new(127, 0, 0, 1);
        let c_port = 54321u16;
        let s_port = 40001u16;

        let c_hex = format!("{:08X}:{:04X}", u32::from_ne_bytes(c_ip.octets()), c_port);
        let s_hex = format!("{:08X}:{:04X}", u32::from_ne_bytes(s_ip.octets()), s_port);

        let sample_tcp = format!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
               0: {s_hex} 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 41001 1 0000000000000000 100 0 0 10 0\n\
               1: {c_hex} {s_hex} 01 00000000:00000000 00:00000000 00000000  1000        0 +987654 1 0000000000000000 20 4 30 10 -1\n\
               2: {c_hex} {s_hex} 01 00000000:00000000 00:00000000 00000000  1000        0 987654 1 0000000000000000 20 4 30 10 -1\n"
        );

        let client_v4 = SocketAddrV4::new(c_ip, c_port);
        let server_v4 = SocketAddrV4::new(s_ip, s_port);
        assert_eq!(
            find_socket_inode_in_proc_tcp(&sample_tcp, client_v4, server_v4),
            Some(987654)
        );
        assert_eq!(
            find_socket_inode_in_proc_tcp(&sample_tcp, SocketAddrV4::new(c_ip, 12345), server_v4),
            None
        );

        let v6_ip: Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
        let oct = v6_ip.octets();
        let w0 = u32::from_ne_bytes([oct[0], oct[1], oct[2], oct[3]]);
        let w1 = u32::from_ne_bytes([oct[4], oct[5], oct[6], oct[7]]);
        let w2 = u32::from_ne_bytes([oct[8], oct[9], oct[10], oct[11]]);
        let w3 = u32::from_ne_bytes([oct[12], oct[13], oct[14], oct[15]]);
        let c6_hex = format!("{:08X}{:08X}{:08X}{:08X}:{:04X}", w0, w1, w2, w3, c_port);
        let s6_hex = format!("{:08X}{:08X}{:08X}{:08X}:{:04X}", w0, w1, w2, w3, s_port);

        let sample_tcp6 = format!(
            "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
               0: {c6_hex} {s6_hex} 01 00000000:00000000 00:00000000 00000000  1000        0 556677 1 0000000000000000 20 4 30 10 -1\n"
        );
        let client_v6 = SocketAddrV6::new(v6_ip, c_port, 0, 0);
        let server_v6 = SocketAddrV6::new(v6_ip, s_port, 0, 0);
        assert_eq!(
            find_socket_inode_in_proc_tcp6(&sample_tcp6, client_v6, server_v6),
            Some(556677)
        );

        // P0-2: 32 字节非 ASCII 多字节 UTF-8 与前导 `+` 必须被拒绝且不触发切片 Panic
        let utf8_32bytes = "0000000é00000000000000000000000:0050";
        assert_eq!(utf8_32bytes.split_once(':').unwrap().0.len(), 32);
        assert!(parse_proc_net_ipv6_addr(utf8_32bytes).is_none());
        assert!(parse_proc_net_ipv6_addr("+0000000000000000000000000000001:0050").is_none());
        assert!(parse_proc_net_ipv4_addr("+7F00001:0050").is_none());
        assert!(parse_proc_net_ipv4_addr("0100007F:+050").is_none());
        assert!(!matches_socket_inode("socket:[+987654]", 987654));
        assert!(!matches_socket_inode("[0000]:+987654", 987654));

        assert!(matches_socket_inode("socket:[987654]", 987654));
        assert!(matches_socket_inode("[0000]:987654", 987654));
        assert!(!matches_socket_inode("socket:[987655]", 987654));
        assert!(!matches_socket_inode("pipe:[987654]", 987654));
        assert_eq!(
            clean_proc_exe_path("/usr/bin/curl (deleted)\n"),
            "/usr/bin/curl"
        );
        assert_eq!(clean_proc_exe_path("/usr/bin/git"), "/usr/bin/git");
        assert_eq!(
            find_socket_meta_in_proc_tcp_reader(std::io::Cursor::new(&sample_tcp), client_v4, server_v4),
            Some((987654, Some(1000)))
        );
        assert_eq!(
            parse_proc_cmdline_argv0(b"/usr/bin/curl\n--silent\0https://example.com\0"),
            Some("/usr/bin/curl--silent".to_string())
        );
        assert_eq!(parse_proc_cmdline_argv0(b"\0--flag"), None);
        assert_eq!(
            sanitize_proc_comm_fallback("../../ev\x1bil/app\n"),
            Some(".._.._evil_app".to_string())
        );
        assert_eq!(
            sanitize_proc_comm_fallback("..\\..\\ev\x1bil\\app\r\n"),
            Some(".._.._evil_app".to_string())
        );
        assert_eq!(sanitize_proc_comm_fallback("\x00\n\t "), None);
    }

    #[test]
    fn test_parse_proc_stat_starttime() {
        let stat = "1234 (my )Weird( app ) S 1 1234 1234 0 -1 4194304 100 0 0 0 5 1 0 0 20 0 1 0 987654321 1024 10 0 0";
        assert_eq!(parse_proc_stat_starttime(stat), Some(987654321));
        assert_eq!(parse_proc_stat_starttime("1234 (bad) S 1 2"), None);
        assert_eq!(
            parse_proc_stat_starttime(
                "1234 (plus) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 +999"
            ),
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
        let tracker = ProcessTracker::with_config(
            Duration::from_millis(40),
            Duration::from_millis(40),
            3,
            3,
        );
        let t0 = Instant::now();

        for i in 1..=5u32 {
            let entry = PidCacheEntry {
                info: ProcessInfo {
                    pid: i,
                    path: format!("/usr/bin/p{}", i),
                    name: format!("p{}", i),
                },
                start_time: Some(i as u128),
            };
            tracker.pid_cache.insert(i, entry, t0 + Duration::from_millis(i as u64));
            tracker.neg_pid_cache.insert(i, (), t0 + Duration::from_millis(i as u64));
        }

        // 受 MAX 容量=3 约束，最老的条目 (1, 2) 应已被逐出，保留最新 (3, 4, 5)
        assert_eq!(tracker.pid_cache.state.read().unwrap().entries.len(), 3);
        assert_eq!(tracker.neg_pid_cache.state.read().unwrap().entries.len(), 3);
        assert!(tracker.pid_cache.get_cloned(&1, t0).is_none());
        assert!(tracker.pid_cache.get_cloned(&5, t0).is_some());
        assert!(tracker.neg_pid_cache.contains_active(&5, t0));
        assert_eq!(tracker.pid_cache.active_keys(t0).len(), 3);

        std::thread::sleep(Duration::from_millis(60));
        let (cleaned_pids, cleaned_neg) = tracker.cleanup_expired();
        assert_eq!(cleaned_pids, 3);
        assert_eq!(cleaned_neg, 3);
        assert_eq!(tracker.cleanup_expired(), (0, 0));
    }

    #[test]
    fn test_macos_socket_fdinfo_layout_and_matching() {
        use macos_proc_info::{matches_macos_socket_info, SocketFdInfo, INI_IPV4, INI_IPV6, SOCKINFO_TCP};

        assert_eq!(size_of::<SocketFdInfo>(), 792);
        assert_eq!(std::mem::align_of::<SocketFdInfo>(), 8);

        let mut info: SocketFdInfo = unsafe { std::mem::zeroed() };
        info.psi.soi_kind = SOCKINFO_TCP;
        info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_vflag = INI_IPV4;
        info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport = u16::to_be(51234) as i32;
        info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport = u16::to_be(40081) as i32;
        info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_46.i46a_addr4 = [127, 0, 0, 1];
        info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_46.i46a_addr4 = [127, 0, 0, 1];
        assert!(matches_macos_socket_info(
            &info,
            "127.0.0.1:51234".parse().unwrap(),
            "127.0.0.1:40081".parse().unwrap(),
            6
        ));
        assert!(matches_macos_socket_info(
            &info,
            "[::ffff:127.0.0.1]:51234".parse().unwrap(),
            "[::ffff:127.0.0.1]:40081".parse().unwrap(),
            6
        ));

        info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_vflag = INI_IPV6;
        info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_6 = Ipv6Addr::LOCALHOST.octets();
        info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_6 = Ipv6Addr::LOCALHOST.octets();
        assert!(matches_macos_socket_info(
            &info,
            "[::1]:51234".parse().unwrap(),
            "[::1]:40081".parse().unwrap(),
            6
        ));

        // Dual-stack INI_IPV4 | INI_IPV6 socket with IPv6 addresses must NOT early-return false on INI_IPV4 mismatch
        info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_vflag = INI_IPV4 | INI_IPV6;
        assert!(matches_macos_socket_info(
            &info,
            "[::1]:51234".parse().unwrap(),
            "[::1]:40081".parse().unwrap(),
            6
        ));
        assert!(!matches_macos_socket_info(
            &info,
            "[::1]:51235".parse().unwrap(),
            "[::1]:40081".parse().unwrap(),
            6
        ));
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

    #[cfg(windows)]
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
    }
}
