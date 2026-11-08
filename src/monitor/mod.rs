use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionSnapshot {
    pub id: u64,
    pub process_name: String,
    pub process_path: String,
    pub pid: u32,
    pub target: String,
    pub rule_name: String,
    pub action: String,
    pub duration_secs: u64,
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub upload_speed_bps: u64,
    pub download_speed_bps: u64,
}

pub struct ActiveConnection {
    pub id: u64,
    pub process_name: String,
    pub process_path: String,
    pub pid: u32,
    pub target: String,
    pub rule_name: String,
    pub action: String,
    pub start_time: Instant,
    pub uploaded_bytes: AtomicU64,
    pub downloaded_bytes: AtomicU64,
    pub cancel_notify: Arc<tokio::sync::Notify>,
    last_up: AtomicU64,
    last_down: AtomicU64,
    current_up_speed: AtomicU64,
    current_down_speed: AtomicU64,
    last_tick: RwLock<Instant>,
}

impl ActiveConnection {
    pub fn add_upload(&self, bytes: u64) {
        self.uploaded_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_download(&self, bytes: u64) {
        self.downloaded_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> ConnectionSnapshot {
        let now = Instant::now();
        let up = self.uploaded_bytes.load(Ordering::Relaxed);
        let down = self.downloaded_bytes.load(Ordering::Relaxed);

        let mut tick_guard = self.last_tick.write().unwrap_or_else(|e| e.into_inner());
        let elapsed = now.duration_since(*tick_guard).as_secs_f64();

        // 仅当时间步长达到 0.5s 时更新速率缓存，避免高频并发轮询将速率重置为 0
        if elapsed >= 0.5 {
            let last_up = self.last_up.swap(up, Ordering::Relaxed);
            let last_down = self.last_down.swap(down, Ordering::Relaxed);
            let up_speed = ((up.saturating_sub(last_up) as f64) / elapsed) as u64;
            let down_speed = ((down.saturating_sub(last_down) as f64) / elapsed) as u64;

            self.current_up_speed.store(up_speed, Ordering::Relaxed);
            self.current_down_speed.store(down_speed, Ordering::Relaxed);
            *tick_guard = now;
        }

        ConnectionSnapshot {
            id: self.id,
            process_name: self.process_name.clone(),
            process_path: self.process_path.clone(),
            pid: self.pid,
            target: self.target.clone(),
            rule_name: self.rule_name.clone(),
            action: self.action.clone(),
            duration_secs: now.duration_since(self.start_time).as_secs(),
            uploaded_bytes: up,
            downloaded_bytes: down,
            upload_speed_bps: self.current_up_speed.load(Ordering::Relaxed),
            download_speed_bps: self.current_down_speed.load(Ordering::Relaxed),
        }
    }
}

/// 全局连接监视器与速率统计器
pub struct ConnectionManager {
    next_id: AtomicU64,
    connections: RwLock<std::collections::HashMap<u64, Arc<ActiveConnection>>>,
    closed_uploaded: AtomicU64,
    closed_downloaded: AtomicU64,
    last_total_up: AtomicU64,
    last_total_down: AtomicU64,
    current_up_speed: AtomicU64,
    current_down_speed: AtomicU64,
    last_tick: RwLock<Instant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalTrafficStats {
    pub total_uploaded_bytes: u64,
    pub total_downloaded_bytes: u64,
    pub current_upload_bps: u64,
    pub current_download_bps: u64,
    pub active_connections_count: usize,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            connections: RwLock::new(std::collections::HashMap::new()),
            closed_uploaded: AtomicU64::new(0),
            closed_downloaded: AtomicU64::new(0),
            last_total_up: AtomicU64::new(0),
            last_total_down: AtomicU64::new(0),
            current_up_speed: AtomicU64::new(0),
            current_down_speed: AtomicU64::new(0),
            last_tick: RwLock::new(Instant::now()),
        }
    }

    pub fn register(
        &self,
        process_name: String,
        process_path: String,
        pid: u32,
        target: String,
        rule_name: String,
        action: String,
    ) -> Arc<ActiveConnection> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();

        let conn = Arc::new(ActiveConnection {
            id,
            process_name,
            process_path,
            pid,
            target,
            rule_name,
            action,
            start_time: now,
            uploaded_bytes: AtomicU64::new(0),
            downloaded_bytes: AtomicU64::new(0),
            cancel_notify: Arc::new(tokio::sync::Notify::new()),
            last_up: AtomicU64::new(0),
            last_down: AtomicU64::new(0),
            current_up_speed: AtomicU64::new(0),
            current_down_speed: AtomicU64::new(0),
            last_tick: RwLock::new(now),
        });

        self.connections
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, Arc::clone(&conn));
        conn
    }

    pub fn unregister(&self, id: u64) {
        if let Some(conn) = self
            .connections
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id)
        {
            let up = conn.uploaded_bytes.load(Ordering::Relaxed);
            let down = conn.downloaded_bytes.load(Ordering::Relaxed);
            self.closed_uploaded.fetch_add(up, Ordering::Relaxed);
            self.closed_downloaded.fetch_add(down, Ordering::Relaxed);
        }
    }

    /// 向指定的活跃连接发送终止通知
    pub fn kill_connection(&self, id: u64) -> bool {
        let conns = self.connections.read().unwrap_or_else(|e| e.into_inner());
        if let Some(conn) = conns.get(&id) {
            conn.cancel_notify.notify_waiters();
            true
        } else {
            false
        }
    }

    pub fn list_snapshots(&self) -> Vec<ConnectionSnapshot> {
        let conns = self.connections.read().unwrap_or_else(|e| e.into_inner());
        conns.values().map(|c| c.snapshot()).collect()
    }

    pub fn global_stats(&self) -> GlobalTrafficStats {
        let now = Instant::now();

        // 实时汇总：已关闭连接流量 + 当前活跃连接传输量（在读锁内读取避免与 unregister 产生时序空隙）
        let (total_up, total_down, active_count) = {
            let conns = self.connections.read().unwrap_or_else(|e| e.into_inner());
            let mut up = self.closed_uploaded.load(Ordering::Relaxed);
            let mut down = self.closed_downloaded.load(Ordering::Relaxed);
            for c in conns.values() {
                up += c.uploaded_bytes.load(Ordering::Relaxed);
                down += c.downloaded_bytes.load(Ordering::Relaxed);
            }
            (up, down, conns.len())
        };

        let mut tick_guard = self.last_tick.write().unwrap_or_else(|e| e.into_inner());
        let elapsed = now.duration_since(*tick_guard).as_secs_f64();

        if elapsed >= 0.5 {
            let last_up = self.last_total_up.swap(total_up, Ordering::Relaxed);
            let last_down = self.last_total_down.swap(total_down, Ordering::Relaxed);
            let up_bps = ((total_up.saturating_sub(last_up) as f64) / elapsed) as u64;
            let down_bps = ((total_down.saturating_sub(last_down) as f64) / elapsed) as u64;

            self.current_up_speed.store(up_bps, Ordering::Relaxed);
            self.current_down_speed.store(down_bps, Ordering::Relaxed);
            *tick_guard = now;
        }

        GlobalTrafficStats {
            total_uploaded_bytes: total_up,
            total_downloaded_bytes: total_down,
            current_upload_bps: self.current_up_speed.load(Ordering::Relaxed),
            current_download_bps: self.current_down_speed.load(Ordering::Relaxed),
            active_connections_count: active_count,
        }
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_manager_lifecycle() {
        let mgr = ConnectionManager::new();
        let conn = mgr.register(
            "node.exe".into(),
            "C:/node.exe".into(),
            1234,
            "api.github.com:443".into(),
            "DevRule".into(),
            "Proxy(101)".into(),
        );

        assert_eq!(conn.id, 1);
        conn.add_upload(1024);
        conn.add_download(2048);

        // 验证实时统计（无需等到 unregister 即可统计活跃流量）
        let stats_live = mgr.global_stats();
        assert_eq!(stats_live.total_uploaded_bytes, 1024);
        assert_eq!(stats_live.total_downloaded_bytes, 2048);

        let list = mgr.list_snapshots();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].process_name, "node.exe");
        assert_eq!(list[0].uploaded_bytes, 1024);
        assert_eq!(list[0].downloaded_bytes, 2048);

        mgr.unregister(conn.id);
        assert_eq!(mgr.list_snapshots().len(), 0);

        let stats = mgr.global_stats();
        assert_eq!(stats.total_uploaded_bytes, 1024);
        assert_eq!(stats.total_downloaded_bytes, 2048);
    }

    #[tokio::test]
    async fn test_connection_kill_notification() {
        let mgr = ConnectionManager::new();
        let conn = mgr.register(
            "curl.exe".into(),
            "C:/curl.exe".into(),
            5678,
            "1.1.1.1:80".into(),
            "Direct".into(),
            "Direct".into(),
        );

        let notify = conn.cancel_notify.clone();
        let handle = tokio::spawn(async move {
            notify.notified().await;
            true
        });

        // 让出时间片确保等待任务已挂载至 Notify 队列
        tokio::task::yield_now().await;

        let killed = mgr.kill_connection(conn.id);
        assert!(killed);

        let res = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
        assert!(res.is_ok());
        assert!(res.unwrap().unwrap());

        assert!(!mgr.kill_connection(9999));
    }
}
