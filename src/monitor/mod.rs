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
    last_up: AtomicU64,
    last_down: AtomicU64,
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

        let mut tick_guard = self.last_tick.write().unwrap();
        let elapsed = now.duration_since(*tick_guard).as_secs_f64();

        let mut up_speed = 0;
        let mut down_speed = 0;

        if elapsed >= 0.5 {
            let last_up = self.last_up.swap(up, Ordering::Relaxed);
            let last_down = self.last_down.swap(down, Ordering::Relaxed);
            up_speed = ((up.saturating_sub(last_up) as f64) / elapsed) as u64;
            down_speed = ((down.saturating_sub(last_down) as f64) / elapsed) as u64;
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
            upload_speed_bps: up_speed,
            download_speed_bps: down_speed,
        }
    }
}

/// 全局连接监视器与速率统计器
pub struct ConnectionManager {
    next_id: AtomicU64,
    connections: RwLock<std::collections::HashMap<u64, Arc<ActiveConnection>>>,
    total_uploaded: AtomicU64,
    total_downloaded: AtomicU64,
    last_total_up: AtomicU64,
    last_total_down: AtomicU64,
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
            total_uploaded: AtomicU64::new(0),
            total_downloaded: AtomicU64::new(0),
            last_total_up: AtomicU64::new(0),
            last_total_down: AtomicU64::new(0),
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
            last_up: AtomicU64::new(0),
            last_down: AtomicU64::new(0),
            last_tick: RwLock::new(now),
        });

        self.connections.write().unwrap().insert(id, Arc::clone(&conn));
        conn
    }

    pub fn unregister(&self, id: u64) {
        if let Some(conn) = self.connections.write().unwrap().remove(&id) {
            let up = conn.uploaded_bytes.load(Ordering::Relaxed);
            let down = conn.downloaded_bytes.load(Ordering::Relaxed);
            self.total_uploaded.fetch_add(up, Ordering::Relaxed);
            self.total_downloaded.fetch_add(down, Ordering::Relaxed);
        }
    }

    pub fn list_snapshots(&self) -> Vec<ConnectionSnapshot> {
        let conns = self.connections.read().unwrap();
        conns.values().map(|c| c.snapshot()).collect()
    }

    pub fn global_stats(&self) -> GlobalTrafficStats {
        let now = Instant::now();
        let total_up = self.total_uploaded.load(Ordering::Relaxed);
        let total_down = self.total_downloaded.load(Ordering::Relaxed);

        let mut tick_guard = self.last_tick.write().unwrap();
        let elapsed = now.duration_since(*tick_guard).as_secs_f64();

        let mut up_bps = 0;
        let mut down_bps = 0;

        if elapsed >= 0.5 {
            let last_up = self.last_total_up.swap(total_up, Ordering::Relaxed);
            let last_down = self.last_total_down.swap(total_down, Ordering::Relaxed);
            up_bps = ((total_up.saturating_sub(last_up) as f64) / elapsed) as u64;
            down_bps = ((total_down.saturating_sub(last_down) as f64) / elapsed) as u64;
            *tick_guard = now;
        }

        GlobalTrafficStats {
            total_uploaded_bytes: total_up,
            total_downloaded_bytes: total_down,
            current_upload_bps: up_bps,
            current_download_bps: down_bps,
            active_connections_count: self.connections.read().unwrap().len(),
        }
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
}
