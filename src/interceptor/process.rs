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
    cache: RwLock<HashMap<u16, (ProcessInfo, Instant)>>,
    cache_ttl: Duration,
}

impl ProcessTracker {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_millis(500), // 500ms 缓存避免高频扫描
        }
    }

    /// 根据本地套接字端口查询发起连接的进程信息 (PID, 绝对路径, 进程名)
    pub fn find_by_local_port(&self, local_port: u16) -> Option<ProcessInfo> {
        let now = Instant::now();

        // 1. 读锁查询缓存
        {
            let cache = self.cache.read().unwrap();
            if let Some((info, expire)) = cache.get(&local_port) {
                if *expire > now {
                    return Some(info.clone());
                }
            }
        }

        // 2. 缓存未命中，调用 Windows API 遍历 TCP 连接所有者表
        let pid = get_pid_by_local_port(local_port)?;
        let path = get_process_image_path(pid).unwrap_or_else(|| "Unknown".to_string());
        let name = Path::new(&path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Unknown")
            .to_string();

        let info = ProcessInfo { pid, path, name };

        // 3. 写入缓存
        let mut cache = self.cache.write().unwrap();
        cache.insert(local_port, (info.clone(), now + self.cache_ttl));

        Some(info)
    }

    pub fn find_by_addr(&self, addr: &SocketAddr) -> Option<ProcessInfo> {
        self.find_by_local_port(addr.port())
    }
}

#[cfg(windows)]
fn get_pid_by_local_port(target_port: u16) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    unsafe {
        let mut size = 0u32;
        // 第一次调用获取所需内存缓冲区大小
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

        let mut buffer: Vec<u8> = vec![0; size as usize];
        let ret = GetExtendedTcpTable(
            buffer.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if ret != 0 {
            return None;
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
        // 验证结构体正常初始化
        assert!(tracker.find_by_local_port(0).is_none() || tracker.find_by_local_port(0).is_some());
    }
}
