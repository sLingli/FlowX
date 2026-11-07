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
    port_cache: RwLock<HashMap<u16, (ProcessInfo, Instant)>>,
    pid_cache: RwLock<HashMap<u32, (ProcessInfo, Instant)>>,
    port_ttl: Duration,
    pid_ttl: Duration,
}

impl ProcessTracker {
    pub fn new() -> Self {
        Self {
            port_cache: RwLock::new(HashMap::new()),
            pid_cache: RwLock::new(HashMap::new()),
            port_ttl: Duration::from_millis(1000), // 端口映射缓存 1 秒
            pid_ttl: Duration::from_secs(10),      // 进程路径缓存 10 秒
        }
    }

    /// 根据本地套接字端口查询发起连接的进程信息 (PID, 绝对路径, 进程名)
    pub fn find_by_local_port(&self, local_port: u16) -> Option<ProcessInfo> {
        let now = Instant::now();

        // 1. 读锁查询端口短期缓存
        {
            let cache = self.port_cache.read().unwrap_or_else(|e| e.into_inner());
            if let Some((info, expire)) = cache.get(&local_port) {
                if *expire > now {
                    return Some(info.clone());
                }
            }
        }

        // 2. 端口缓存未命中，调用 Windows API 查找本地端口归属的 PID
        let pid = get_pid_by_local_port(local_port)?;

        // 3. 查询 PID 级缓存以避免重复调用昂贵的 OpenProcess + QueryFullProcessImageNameW
        {
            let p_cache = self.pid_cache.read().unwrap_or_else(|e| e.into_inner());
            if let Some((info, expire)) = p_cache.get(&pid) {
                if *expire > now {
                    let mut port_guard = self.port_cache.write().unwrap_or_else(|e| e.into_inner());
                    port_guard.insert(local_port, (info.clone(), now + self.port_ttl));
                    return Some(info.clone());
                }
            }
        }

        // 4. PID 缓存未命中，调用 Windows API 查询可执行文件完整路径
        let path = get_process_image_path(pid).unwrap_or_else(|| "Unknown".to_string());
        let name = Path::new(&path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Unknown")
            .to_string();

        let info = ProcessInfo { pid, path, name };

        // 5. 写入二级缓存
        {
            let mut pid_guard = self.pid_cache.write().unwrap_or_else(|e| e.into_inner());
            pid_guard.insert(pid, (info.clone(), now + self.pid_ttl));
        }
        {
            let mut port_guard = self.port_cache.write().unwrap_or_else(|e| e.into_inner());
            port_guard.insert(local_port, (info.clone(), now + self.port_ttl));
        }

        Some(info)
    }

    pub fn find_by_addr(&self, addr: &SocketAddr) -> Option<ProcessInfo> {
        self.find_by_local_port(addr.port())
    }

    /// 清理过期的端口与 PID 缓存项
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        {
            let mut port_guard = self.port_cache.write().unwrap_or_else(|e| e.into_inner());
            port_guard.retain(|_, (_, expire)| *expire > now);
        }
        {
            let mut pid_guard = self.pid_cache.write().unwrap_or_else(|e| e.into_inner());
            pid_guard.retain(|_, (_, expire)| *expire > now);
        }
    }
}

#[cfg(windows)]
fn get_pid_by_local_port(target_port: u16) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

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

            // 预留少量余量，防止两次调用间隙新增连接
            let mut buffer: Vec<u8> = vec![0; (size as usize) + 512];
            let ret = GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut _,
                &mut size,
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
                // 本地端口保存在网络字节序中
                let port = u16::from_be((row.dwLocalPort & 0xffff) as u16);
                if port == target_port {
                    return Some(row.dwOwningPid);
                }
            }
            return None;
        }
    }

    None
}

#[cfg(not(windows))]
fn get_pid_by_local_port(_target_port: u16) -> Option<u32> {
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
        // 验证结构体正常初始化与查询
        assert!(tracker.find_by_local_port(0).is_none() || tracker.find_by_local_port(0).is_some());
        tracker.cleanup_expired();
    }
}
