use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use flowx::api::ApiServer;
use flowx::interceptor::dispatcher::ProxyNodeEntry;
use flowx::monitor::ConnectionManager;
use flowx::router::{Action, RuleEngine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;

#[allow(dead_code)]
pub const DEFAULT_SELF_PORTS: [u16; 3] = [40001, 40080, 1053];

#[allow(dead_code)]
pub async fn spawn_test_api() -> (
    SocketAddr,
    Arc<RwLock<HashMap<u32, ProxyNodeEntry>>>,
    Arc<RuleEngine>,
    watch::Sender<bool>,
) {
    let mgr = Arc::new(ConnectionManager::new());
    let re = Arc::new(RuleEngine::new(Vec::new(), Action::Direct));
    let nodes = Arc::new(RwLock::new(HashMap::new()));
    let srv = ApiServer::new(
        "127.0.0.1:0".parse().unwrap(),
        mgr,
        Arc::clone(&re),
        Arc::clone(&nodes),
    )
    .with_self_ports(DEFAULT_SELF_PORTS.to_vec());
    let listener = srv.bind().await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move { srv.run(listener, rx).await });
    (addr, nodes, re, tx)
}

#[allow(dead_code)]
pub async fn raw_http(addr: SocketAddr, req: &str) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    String::from_utf8(buf).unwrap()
}

/// RAII temp file/config guard that removes the file, its `.filename.lock` sidecar,
/// and any leftover `.filename.tmp.*` staging files on creation and on drop (even on panic).
#[allow(dead_code)]
pub struct TempConfigGuard {
    path: std::path::PathBuf,
}

#[allow(dead_code)]
impl TempConfigGuard {
    pub fn new(prefix: &str) -> Self {
        Self::with_ext(prefix, "xml")
    }

    pub fn with_ext(prefix: &str, ext: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT_TEMP_SEQ: AtomicU64 = AtomicU64::new(1);
        let seq = NEXT_TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "{prefix}_{}_{}_{}.{}",
                std::process::id(),
                ts,
                seq,
                ext
            ));
        let guard = Self { path };
        guard.cleanup();
        guard
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn as_str(&self) -> String {
        self.path.to_string_lossy().to_string()
    }

    pub fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.path);
        if let (Some(parent), Some(name)) = (self.path.parent(), self.path.file_name()) {
            let file_name = name.to_string_lossy();
            let lock_path = parent.join(format!(".{file_name}.lock"));
            let _ = std::fs::remove_file(lock_path);
            let tmp_prefix = format!(".{file_name}.tmp.");
            if let Ok(entries) = std::fs::read_dir(parent) {
                for entry in entries.flatten() {
                    if entry.file_name().to_string_lossy().starts_with(&tmp_prefix) {
                        let _ = std::fs::remove_file(entry.path());
                    }
                }
            }
        }
    }
}

impl Drop for TempConfigGuard {
    fn drop(&mut self) {
        self.cleanup();
    }
}
