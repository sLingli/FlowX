use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// 缓存写入时触发惰性过期清理的默认条目阈值
const LAZY_EVICT_THRESHOLD: usize = 512;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub path: String,
    pub name: String,
}

pub struct ProcessTracker {
    /// 以客户端套接字地址 (IP:Port) 为键的短期缓存，避免仅按端口匹配导致的跨网卡误判
    conn_cache: RwLock<HashMap<SocketAddr, (ProcessInfo, Instant)>>,
    pid_cache: RwLock<HashMap<u32, (ProcessInfo, Instant)>>,
    conn_ttl: Duration,
    pid_ttl: Duration,
    lazy_evict_threshold: usize,
}

impl ProcessTracker {
    pub fn new() -> Self {
        Self::with_ttls(Duration::from_millis(1000), Duration::from_secs(10))
    }

    pub fn with_ttls(conn_ttl: Duration, pid_ttl: Duration) -> Self {
        Self {
            conn_cache: RwLock::new(HashMap::new()),
            pid_cache: RwLock::new(HashMap::new()),
            conn_ttl,
            pid_ttl,
            lazy_evict_threshold: LAZY_EVICT_THRESHOLD,
        }
    }

    #[cfg(test)]
    fn with_evict_threshold(mut self, threshold: usize) -> Self {
        self.lazy_evict_threshold = threshold;
        self
    }

    fn cache_pid_entry(&self, pid: u32, info: &ProcessInfo, now: Instant) {
        let mut pid_guard = self.pid_cache.write().unwrap_or_else(|e| e.into_inner());
        if pid_guard.len() >= self.lazy_evict_threshold {
            pid_guard.retain(|_, (_, expire)| *expire > now);
        }
        pid_guard.insert(pid, (info.clone(), now + self.pid_ttl));
    }

    fn cache_conn_entry(&self, client: SocketAddr, info: ProcessInfo, now: Instant) {
        let mut conn_guard = self.conn_cache.write().unwrap_or_else(|e| e.into_inner());
        if conn_guard.len() >= self.lazy_evict_threshold {
            conn_guard.retain(|_, (_, expire)| *expire > now);
        }
        conn_guard.insert(client, (info, now + self.conn_ttl));
    }

    /// 根据 TCP 连接四元组查询发起连接的进程信息 (PID, 绝对路径, 进程名)
    ///
    /// `client` 为入站连接的对端地址（即发起方本地套接字），`server` 为 FlowX 入站监听端的本地地址。
    /// 仅当系统 TCP 表中存在 `local == client && remote == server` 的行时才认定归属，
    /// 杜绝仅凭端口号匹配到其它网卡/其它连接上同端口套接字的误判。
    pub fn find_by_connection(&self, client: SocketAddr, server: SocketAddr) -> Option<ProcessInfo> {
        let now = Instant::now();

        // 1. 读锁查询连接短期缓存
        {
            let cache = self.conn_cache.read().unwrap_or_else(|e| e.into_inner());
            if let Some((info, expire)) = cache.get(&client)
                && *expire > now {
                    return Some(info.clone());
                }
        }

        // 2. 缓存未命中，调用平台原生接口精确查找连接归属的 PID
        #[cfg(target_os = "linux")]
        let pid = {
            let hint_pids: Vec<u32> = {
                let p_cache = self.pid_cache.read().unwrap_or_else(|e| e.into_inner());
                p_cache
                    .iter()
                    .filter(|(_, (_, expire))| *expire > now)
                    .map(|(pid, _)| *pid)
                    .collect()
            };
            get_pid_by_connection_with_hints(client, server, &hint_pids)?
        };
        #[cfg(not(target_os = "linux"))]
        let pid = get_pid_by_connection(client, server)?;

        // 3. 查询 PID 级缓存以避免重复调用昂贵的系统级进程路径查询
        let cached = {
            let p_cache = self.pid_cache.read().unwrap_or_else(|e| e.into_inner());
            p_cache
                .get(&pid)
                .filter(|(_, expire)| *expire > now)
                .map(|(info, _)| info.clone())
        };

        let info = match cached {
            Some(info) => info,
            None => {
                // 4. PID 缓存未命中，查询可执行文件完整路径与进程名
                let path = get_process_image_path(pid)
                    .unwrap_or_else(|| crate::i18n::UNKNOWN_PROCESS.to_string());
                let name = Path::new(&path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(crate::i18n::UNKNOWN_PROCESS)
                    .to_string();
                let info = ProcessInfo { pid, path, name };
                self.cache_pid_entry(pid, &info, now);
                info
            }
        };

        // 5. 写入连接级缓存（超阈值时触发惰性剔除）
        self.cache_conn_entry(client, info.clone(), now);

        Some(info)
    }

    /// 异步非阻塞查询进程信息：快路径读锁命中直接返回，未命中则交付 spawn_blocking 避免阻塞 Tokio 调度线程
    pub async fn find_by_connection_async(
        self: &std::sync::Arc<Self>,
        client: SocketAddr,
        server: SocketAddr,
    ) -> Option<ProcessInfo> {
        let now = Instant::now();

        // 1. 读锁查询连接短期缓存 (非阻塞快路径)
        {
            let cache = self.conn_cache.read().unwrap_or_else(|e| e.into_inner());
            if let Some((info, expire)) = cache.get(&client)
                && *expire > now {
                    return Some(info.clone());
                }
        }

        // 2. 慢路径：交由 spawn_blocking 执行 Win32 阻塞调用
        let tracker = std::sync::Arc::clone(self);
        tokio::task::spawn_blocking(move || tracker.find_by_connection(client, server))
            .await
            .ok()
            .flatten()
    }

    /// 清理过期的连接与 PID 缓存项；若读锁探测无过期条目则直接跳过写锁，返回 `(conn清理数, pid清理数)`
    pub fn cleanup_expired(&self) -> (usize, usize) {
        let now = Instant::now();

        let cleaned_conns = {
            let has_expired = {
                let guard = self.conn_cache.read().unwrap_or_else(|e| e.into_inner());
                guard.values().any(|(_, expire)| *expire <= now)
            };
            if has_expired {
                let mut conn_guard = self.conn_cache.write().unwrap_or_else(|e| e.into_inner());
                let before = conn_guard.len();
                conn_guard.retain(|_, (_, expire)| *expire > now);
                before.saturating_sub(conn_guard.len())
            } else {
                0
            }
        };

        let cleaned_pids = {
            let has_expired = {
                let guard = self.pid_cache.read().unwrap_or_else(|e| e.into_inner());
                guard.values().any(|(_, expire)| *expire <= now)
            };
            if has_expired {
                let mut pid_guard = self.pid_cache.write().unwrap_or_else(|e| e.into_inner());
                let before = pid_guard.len();
                pid_guard.retain(|_, (_, expire)| *expire > now);
                before.saturating_sub(pid_guard.len())
            } else {
                0
            }
        };

        (cleaned_conns, cleaned_pids)
    }
}

impl Default for ProcessTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
fn get_pid_by_connection(client: SocketAddr, server: SocketAddr) -> Option<u32> {
    use std::net::Ipv4Addr;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    // 当前仅支持 IPv4 TCP 表（FlowX 入站默认监听 IPv4 回环地址）
    let (SocketAddr::V4(client_v4), SocketAddr::V4(server_v4)) = (client, server) else {
        return None;
    };

    unsafe {
        // 重试最多 3 次，处理高并发下表大小动态增长的问题 (ERROR_INSUFFICIENT_BUFFER)
        for _ in 0..3 {
            let mut size = 0u32;
            let _ = GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if size == 0 {
                return None;
            }

            // 使用 u32 数组分配缓冲区以严格保证 4 字节指针对齐，避免 UB
            let u32_elements = (size as usize + 512).div_ceil(4);
            let mut buffer: Vec<u32> = vec![0u32; u32_elements];
            let mut actual_size = (u32_elements * 4) as u32;

            let ret = GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut actual_size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if ret != 0 {
                continue; // 缓冲区变化，重试
            }

            let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let entries_count = table.dwNumEntries as usize;
            let rows_ptr = table.table.as_ptr();

            for i in 0..entries_count {
                let row = &*rows_ptr.add(i);
                // 地址与端口均以网络字节序保存（端口仅低 16 位有效）
                let local_port = u16::from_be((row.dwLocalPort & 0xffff) as u16);
                let remote_port = u16::from_be((row.dwRemotePort & 0xffff) as u16);
                if local_port != client_v4.port() || remote_port != server_v4.port() {
                    continue;
                }
                let local_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
                let remote_ip = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());
                if local_ip == *client_v4.ip() && remote_ip == *server_v4.ip() {
                    return Some(row.dwOwningPid);
                }
            }
            return None;
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn get_pid_by_connection_with_hints(
    client: SocketAddr,
    server: SocketAddr,
    hint_pids: &[u32],
) -> Option<u32> {
    let inode = find_socket_inode_linux(client, server)?;
    find_pid_by_socket_inode_linux(inode, hint_pids)
}

#[cfg(target_os = "linux")]
fn find_socket_inode_linux(client: SocketAddr, server: SocketAddr) -> Option<u64> {
    use std::net::SocketAddrV6;

    match (client, server) {
        (SocketAddr::V4(client_v4), SocketAddr::V4(server_v4)) => {
            if let Ok(content) = std::fs::read_to_string("/proc/net/tcp")
                && let Some(inode) = find_socket_inode_in_proc_tcp(&content, client_v4, server_v4)
            {
                return Some(inode);
            }
            // 兼容双栈套接字在 /proc/net/tcp6 中以 ::ffff:a.b.c.d 记录 IPv4 连接的情况
            if let Ok(content6) = std::fs::read_to_string("/proc/net/tcp6") {
                let c_v6 = SocketAddrV6::new(client_v4.ip().to_ipv6_mapped(), client_v4.port(), 0, 0);
                let s_v6 = SocketAddrV6::new(server_v4.ip().to_ipv6_mapped(), server_v4.port(), 0, 0);
                if let Some(inode) = find_socket_inode_in_proc_tcp6(&content6, c_v6, s_v6) {
                    return Some(inode);
                }
            }
            None
        }
        (SocketAddr::V6(client_v6), SocketAddr::V6(server_v6)) => {
            let content = std::fs::read_to_string("/proc/net/tcp6").ok()?;
            find_socket_inode_in_proc_tcp6(&content, client_v6, server_v6)
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn proc_pid_owns_socket_inode(pid: u32, inode: u64) -> bool {
    let fd_dir = format!("/proc/{}/fd", pid);
    let Ok(entries) = std::fs::read_dir(fd_dir) else {
        return false;
    };
    for entry in entries.flatten() {
        if let Ok(target) = std::fs::read_link(entry.path())
            && let Some(target_str) = target.to_str()
            && matches_socket_inode(target_str, inode)
        {
            return true;
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn find_pid_by_socket_inode_linux(inode: u64, hint_pids: &[u32]) -> Option<u32> {
    // 1. 快路径：优先探测已在 PID 缓存中的活跃进程与当前自身进程，避免每次全量遍历 /proc
    for &pid in hint_pids {
        if proc_pid_owns_socket_inode(pid, inode) {
            return Some(pid);
        }
    }
    let self_pid = std::process::id();
    if !hint_pids.contains(&self_pid) && proc_pid_owns_socket_inode(self_pid, inode) {
        return Some(self_pid);
    }

    // 2. 慢路径：遍历 /proc 下所有纯数字 PID 目录
    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !name_str.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(pid) = name_str.parse::<u32>() else {
            continue;
        };
        if pid == self_pid || hint_pids.contains(&pid) {
            continue;
        }
        if proc_pid_owns_socket_inode(pid, inode) {
            return Some(pid);
        }
    }
    None
}

/// 解析 `/proc/net/tcp` 单列十六进制 `HHHHHHHH:PPPP` 地址（IP 按主机字节序编码，端口按大端编码）
#[cfg(any(target_os = "linux", test))]
fn parse_proc_net_ipv4_addr(raw: &str) -> Option<(std::net::Ipv4Addr, u16)> {
    let (ip_hex, port_hex) = raw.split_once(':')?;
    if ip_hex.len() != 8 || port_hex.len() != 4 {
        return None;
    }
    let ip_host = u32::from_str_radix(ip_hex, 16).ok()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((std::net::Ipv4Addr::from(ip_host.to_ne_bytes()), port))
}

/// 解析 `/proc/net/tcp6` 单列十六进制 `32位Hex:PPPP` 地址（4 个 32-bit 字均按主机字节序编码）
#[cfg(any(target_os = "linux", test))]
fn parse_proc_net_ipv6_addr(raw: &str) -> Option<(std::net::Ipv6Addr, u16)> {
    let (ip_hex, port_hex) = raw.split_once(':')?;
    if ip_hex.len() != 32 || port_hex.len() != 4 {
        return None;
    }
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let mut octets = [0u8; 16];
    for i in 0..4 {
        let word_hex = &ip_hex[i * 8..(i + 1) * 8];
        let word = u32::from_str_radix(word_hex, 16).ok()?;
        octets[i * 4..(i + 1) * 4].copy_from_slice(&word.to_ne_bytes());
    }
    Some((std::net::Ipv6Addr::from(octets), port))
}

/// 在 `/proc/net/tcp` 文本中按完整四元组 (`local == client && remote == server`) 查找套接字 inode
#[cfg(any(target_os = "linux", test))]
fn find_socket_inode_in_proc_tcp(
    content: &str,
    client: std::net::SocketAddrV4,
    server: std::net::SocketAddrV4,
) -> Option<u64> {
    let target_local = (*client.ip(), client.port());
    let target_rem = (*server.ip(), server.port());

    for line in content.lines() {
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
        if parse_proc_net_ipv4_addr(local_raw) != Some(target_local)
            || parse_proc_net_ipv4_addr(rem_raw) != Some(target_rem)
        {
            continue;
        }
        // 列布局: sl(0) local(1) rem(2) st(3) queue(4) tr(5) retrnsmt(6) uid(7) timeout(8) inode(9)
        if let Some(inode_str) = cols.nth(6)
            && let Ok(inode) = inode_str.parse::<u64>()
            && inode > 0
        {
            return Some(inode);
        }
    }
    None
}

/// 在 `/proc/net/tcp6` 文本中按完整四元组 (`local == client && remote == server`) 查找套接字 inode
#[cfg(any(target_os = "linux", test))]
fn find_socket_inode_in_proc_tcp6(
    content: &str,
    client: std::net::SocketAddrV6,
    server: std::net::SocketAddrV6,
) -> Option<u64> {
    let target_local = (*client.ip(), client.port());
    let target_rem = (*server.ip(), server.port());

    for line in content.lines() {
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
        if parse_proc_net_ipv6_addr(local_raw) != Some(target_local)
            || parse_proc_net_ipv6_addr(rem_raw) != Some(target_rem)
        {
            continue;
        }
        if let Some(inode_str) = cols.nth(6)
            && let Ok(inode) = inode_str.parse::<u64>()
            && inode > 0
        {
            return Some(inode);
        }
    }
    None
}

/// 判断 `/proc/<pid>/fd/*` 符号链接目标是否指向指定套接字 inode（兼容 `socket:[inode]` 与 `[0000]:inode`）
#[cfg(any(target_os = "linux", test))]
fn matches_socket_inode(link_target: &str, inode: u64) -> bool {
    if let Some(rest) = link_target.strip_prefix("socket:[")
        && let Some(num_str) = rest.strip_suffix(']')
    {
        return num_str.parse::<u64>().ok() == Some(inode);
    }
    if let Some(rest) = link_target.strip_prefix("[0000]:") {
        return rest.parse::<u64>().ok() == Some(inode);
    }
    false
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

#[cfg(not(any(windows, target_os = "linux")))]
fn get_pid_by_connection(_client: SocketAddr, _server: SocketAddr) -> Option<u32> {
    None
}

#[cfg(windows)]
fn get_process_image_path(pid: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    if pid == 0 || pid == 4 {
        return Some("System".to_string());
    }

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }

        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;

        let ret = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size);
        CloseHandle(handle);

        if ret != 0 {
            let path = String::from_utf16_lossy(&buf[..size as usize]);
            Some(path)
        } else {
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn get_process_image_path(pid: u32) -> Option<String> {
    if pid == 0 {
        return Some("kernel".to_string());
    }

    // 1. 优先读取 /proc/<pid>/exe 符号链接以获得真实可执行文件绝对路径
    let exe_link = format!("/proc/{}/exe", pid);
    if let Ok(path_buf) = std::fs::read_link(&exe_link) {
        let cleaned = clean_proc_exe_path(&path_buf.to_string_lossy());
        if !cleaned.is_empty() {
            return Some(cleaned);
        }
    }

    // 2. 回退：读取 /proc/<pid>/cmdline 的首个 NUL 分隔参数 (argv[0])
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(bytes) = std::fs::read(&cmdline_path)
        && !bytes.is_empty()
    {
        let first_arg = bytes.split(|&b| b == 0).next().unwrap_or(&bytes[..]);
        let arg0 = String::from_utf8_lossy(first_arg).trim().to_string();
        if !arg0.is_empty() {
            return Some(arg0);
        }
    }

    // 3. 回退：读取 /proc/<pid>/comm 进程短名
    let comm_path = format!("/proc/{}/comm", pid);
    if let Ok(comm) = std::fs::read_to_string(&comm_path) {
        let trimmed = comm.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    None
}

#[cfg(not(any(windows, target_os = "linux")))]
fn get_process_image_path(_pid: u32) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_tracker_cache() {
        let tracker = ProcessTracker::new();
        // 不存在的连接不应误判出任何进程
        let client: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let server: SocketAddr = "127.0.0.1:2".parse().unwrap();
        assert!(tracker.find_by_connection(client, server).is_none());
        tracker.cleanup_expired();
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn test_find_own_process_by_connection() {
        // Establish a loopback connection and verify finding current process via 4-tuple
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let server = listener.local_addr().unwrap();
        let client_stream = std::net::TcpStream::connect(server).unwrap();
        let (_accepted, peer) = listener.accept().unwrap();
        assert_eq!(peer, client_stream.local_addr().unwrap());

        let tracker = ProcessTracker::new();
        let info = tracker.find_by_connection(peer, server).expect("Should locate current process");
        assert_eq!(info.pid, std::process::id());
    }

    #[test]
    fn test_linux_proc_net_tcp_and_tcp6_parsers() {
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

        let c_ip = Ipv4Addr::new(127, 0, 0, 1);
        let s_ip = Ipv4Addr::new(127, 0, 0, 1);
        let c_port = 54321u16;
        let s_port = 40001u16;

        let c_hex = format!("{:08X}:{:04X}", u32::from_ne_bytes(c_ip.octets()), c_port);
        let s_hex = format!("{:08X}:{:04X}", u32::from_ne_bytes(s_ip.octets()), s_port);

        let sample_tcp = format!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
               0: {s_hex} 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 41001 1 0000000000000000 100 0 0 10 0\n\
               1: {c_hex} {s_hex} 01 00000000:00000000 00:00000000 00000000  1000        0 987654 1 0000000000000000 20 4 30 10 -1\n"
        );

        let client_v4 = SocketAddrV4::new(c_ip, c_port);
        let server_v4 = SocketAddrV4::new(s_ip, s_port);
        assert_eq!(
            find_socket_inode_in_proc_tcp(&sample_tcp, client_v4, server_v4),
            Some(987654)
        );
        // 端口不匹配时应返回 None
        assert_eq!(
            find_socket_inode_in_proc_tcp(&sample_tcp, SocketAddrV4::new(c_ip, 12345), server_v4),
            None
        );

        // 验证 /proc/net/tcp6 解析（含 IPv4-mapped IPv6 地址 ::ffff:127.0.0.1）
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

        // 验证 socket:[inode] 软链匹配与 (deleted) 路径清洗
        assert!(matches_socket_inode("socket:[987654]", 987654));
        assert!(matches_socket_inode("[0000]:987654", 987654));
        assert!(!matches_socket_inode("socket:[987655]", 987654));
        assert!(!matches_socket_inode("pipe:[987654]", 987654));
        assert_eq!(
            clean_proc_exe_path("/usr/bin/curl (deleted)\n"),
            "/usr/bin/curl"
        );
        assert_eq!(clean_proc_exe_path("/usr/bin/git"), "/usr/bin/git");
    }

    #[test]
    fn test_lazy_eviction_and_cleanup_expired() {
        let tracker = ProcessTracker::with_ttls(Duration::from_millis(40), Duration::from_millis(40))
            .with_evict_threshold(3);

        let dummy = ProcessInfo {
            pid: 10,
            path: "a.exe".into(),
            name: "a.exe".into(),
        };
        let t0 = Instant::now();
        tracker.cache_conn_entry("127.0.0.1:1001".parse().unwrap(), dummy.clone(), t0);
        tracker.cache_conn_entry("127.0.0.1:1002".parse().unwrap(), dummy.clone(), t0);
        tracker.cache_conn_entry("127.0.0.1:1003".parse().unwrap(), dummy.clone(), t0);

        // 等待 TTL 过期后再写入第 4 条（达到阈值 3），应自动惰性清除前 3 条过期记录
        std::thread::sleep(Duration::from_millis(55));
        let t1 = Instant::now();
        tracker.cache_conn_entry("127.0.0.1:1004".parse().unwrap(), dummy.clone(), t1);
        assert_eq!(tracker.conn_cache.read().unwrap().len(), 1);

        // 等待剩余记录过期并通过 cleanup_expired 清理
        tracker.cache_pid_entry(10, &dummy, t1);
        std::thread::sleep(Duration::from_millis(55));
        let (cleaned_conns, cleaned_pids) = tracker.cleanup_expired();
        assert_eq!(cleaned_conns, 1);
        assert_eq!(cleaned_pids, 1);
        assert_eq!(tracker.cleanup_expired(), (0, 0));
    }
}
