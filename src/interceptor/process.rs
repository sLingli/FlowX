use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::RwLock;
use std::time::{Duration, Instant};

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
}

impl ProcessTracker {
    pub fn new() -> Self {
        Self {
            conn_cache: RwLock::new(HashMap::new()),
            pid_cache: RwLock::new(HashMap::new()),
            conn_ttl: Duration::from_millis(1000), // 连接映射缓存 1 秒
            pid_ttl: Duration::from_secs(10),      // 进程路径缓存 10 秒
        }
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

        // 2. 缓存未命中，调用 Windows API 精确查找连接归属的 PID
        let pid = get_pid_by_connection(client, server)?;

        // 3. 查询 PID 级缓存以避免重复调用昂贵的 OpenProcess + QueryFullProcessImageNameW
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
                // 4. PID 缓存未命中，调用 Windows API 查询可执行文件完整路径
                let path = get_process_image_path(pid).unwrap_or_else(|| "Unknown".to_string());
                let name = Path::new(&path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("Unknown")
                    .to_string();
                let info = ProcessInfo { pid, path, name };
                let mut pid_guard = self.pid_cache.write().unwrap_or_else(|e| e.into_inner());
                pid_guard.insert(pid, (info.clone(), now + self.pid_ttl));
                info
            }
        };

        // 5. 写入连接级缓存
        {
            let mut conn_guard = self.conn_cache.write().unwrap_or_else(|e| e.into_inner());
            conn_guard.insert(client, (info.clone(), now + self.conn_ttl));
        }

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

    /// 清理过期的连接与 PID 缓存项
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        {
            let mut conn_guard = self.conn_cache.write().unwrap_or_else(|e| e.into_inner());
            conn_guard.retain(|_, (_, expire)| *expire > now);
        }
        {
            let mut pid_guard = self.pid_cache.write().unwrap_or_else(|e| e.into_inner());
            pid_guard.retain(|_, (_, expire)| *expire > now);
        }
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

#[cfg(not(windows))]
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

#[cfg(not(windows))]
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

    #[cfg(windows)]
    #[test]
    fn test_find_own_process_by_connection() {
        // 建立一条真实回环连接，验证可以通过四元组精确定位到当前测试进程
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let server = listener.local_addr().unwrap();
        let client_stream = std::net::TcpStream::connect(server).unwrap();
        let (_accepted, peer) = listener.accept().unwrap();
        assert_eq!(peer, client_stream.local_addr().unwrap());

        let tracker = ProcessTracker::new();
        let info = tracker.find_by_connection(peer, server).expect("应能定位到当前进程");
        assert_eq!(info.pid, std::process::id());
    }
}
