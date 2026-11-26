mod http;
mod nodes;
mod routes;
mod rules;
mod system;
mod transparent;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore, watch};
use tracing::{error, info};

use crate::api::http::send_http_response;
use crate::api::routes::handle_api_request;
use crate::config::ConfigStore;
use crate::control::ControlError;
use crate::i18n::Locale;
use crate::interceptor::dispatcher::ProxyNodeEntry;
use crate::monitor::{ConnectionManager, InFlightTracker};
use crate::router::RuleEngine;
use crate::transparent::TransparentManager;

pub use crate::control::{
    AddNodeRequest, AddRuleRequest, DefaultActionResponse, MoveRuleRequest, PatchNodeRequest,
    PatchRuleRequest, PingNodeRequest, PingResponse, ProxyNodeView, SetDefaultActionRequest,
    SimulateRouteRequest, SimulateRouteResponse, SystemInfoResponse, SystemRuntimeContext,
    ToggleRuleRequest, TransparentConfigRequest, TransparentToggleRequest, UpdateNodeRequest,
    UpdateRuleRequest,
};

const CONFIG_PERSIST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_API_CONCURRENCY: usize = 128;
const MAX_MUTATION_CONCURRENCY: usize = 16;
const MAX_PING_CONCURRENCY: usize = 16;
pub(crate) const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";

#[cfg(test)]
pub(crate) type ElevateRunner = Arc<dyn Fn() -> std::io::Result<()> + Send + Sync>;
#[cfg(not(test))]
pub(super) type ElevateRunner = ();

pub(crate) fn control_error_to_http(
    err: ControlError,
    locale: Locale,
) -> (&'static str, &'static str, String) {
    (
        err.kind.http_status_line(),
        JSON_CONTENT_TYPE,
        err.to_localized_json(locale),
    )
}

pub(crate) fn serde_json_to_string<T: serde::Serialize>(val: &T) -> String {
    serde_json::to_string(val).unwrap_or_else(|_| "{}".to_string())
}

pub struct ApiServer {
    pub bind_addr: SocketAddr,
    pub monitor: Arc<ConnectionManager>,
    pub rule_engine: Arc<RuleEngine>,
    pub proxy_nodes: Arc<RwLock<HashMap<u32, ProxyNodeEntry>>>,
    pub self_ports: Vec<u16>,
    pub config_store: Option<Arc<ConfigStore>>,
    pub runtime_context: Option<Arc<SystemRuntimeContext>>,
    pub in_flight: Option<Arc<InFlightTracker>>,
    pub transparent_manager: Option<Arc<TransparentManager>>,
    pub shutdown_tx: Option<watch::Sender<bool>>,
    conn_limit: Arc<Semaphore>,
    ping_semaphore: Arc<Semaphore>,
    mutation_semaphore: Arc<Semaphore>,
    mutation_lock: Arc<Mutex<()>>,
    elevating: Arc<AtomicBool>,
    #[cfg(test)]
    elevate_runner: Option<ElevateRunner>,
    persist_timeout: Duration,
    started_at: Instant,
}

impl ApiServer {
    pub fn new(
        bind_addr: SocketAddr,
        monitor: Arc<ConnectionManager>,
        rule_engine: Arc<RuleEngine>,
        proxy_nodes: Arc<RwLock<HashMap<u32, ProxyNodeEntry>>>,
    ) -> Self {
        Self {
            bind_addr,
            monitor,
            rule_engine,
            proxy_nodes,
            self_ports: vec![bind_addr.port()],
            config_store: None,
            runtime_context: None,
            in_flight: None,
            transparent_manager: None,
            shutdown_tx: None,
            conn_limit: Arc::new(Semaphore::new(MAX_API_CONCURRENCY)),
            ping_semaphore: Arc::new(Semaphore::new(MAX_PING_CONCURRENCY)),
            mutation_semaphore: Arc::new(Semaphore::new(MAX_MUTATION_CONCURRENCY)),
            mutation_lock: Arc::new(Mutex::new(())),
            elevating: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            elevate_runner: None,
            persist_timeout: CONFIG_PERSIST_TIMEOUT,
            started_at: Instant::now(),
        }
    }

    pub fn with_persist_timeout(mut self, timeout: Duration) -> Self {
        self.persist_timeout = timeout;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_elevate_runner(mut self, runner: ElevateRunner) -> Self {
        self.elevate_runner = Some(runner);
        self
    }

    pub fn with_self_ports(mut self, self_ports: Vec<u16>) -> Self {
        self.self_ports = self_ports;
        self
    }

    pub fn with_config_store(mut self, store: Arc<ConfigStore>) -> Self {
        self.config_store = Some(store);
        self
    }

    pub fn with_runtime_context(mut self, ctx: Arc<SystemRuntimeContext>) -> Self {
        self.runtime_context = Some(ctx);
        self
    }

    pub fn with_in_flight(mut self, tracker: Arc<InFlightTracker>) -> Self {
        self.in_flight = Some(tracker);
        self
    }

    pub fn with_transparent_manager(mut self, mgr: Arc<TransparentManager>) -> Self {
        self.transparent_manager = Some(mgr);
        self
    }

    pub fn with_shutdown_sender(mut self, tx: watch::Sender<bool>) -> Self {
        self.shutdown_tx = Some(tx);
        self
    }

    /// 同步绑定 TCP 监听器（Fail-Fast 检查端口占用与回环地址限制）
    pub async fn bind(&self) -> Result<TcpListener> {
        if !self.bind_addr.ip().is_loopback() {
            anyhow::bail!(
                "Refusing to bind HTTP API server on non-loopback address {}: local loopback only",
                self.bind_addr
            );
        }
        let listener = TcpListener::bind(self.bind_addr)
            .await
            .with_context(|| format!("Failed to bind HTTP API server port ({})", self.bind_addr))?;
        info!(
            "[API] FlowX control and status HTTP API server bound on http://{}",
            listener.local_addr().unwrap_or(self.bind_addr)
        );
        Ok(listener)
    }

    /// 启动异步 HTTP API 监听服务（支持并发连接限流、内部在途排空与优雅停机）
    pub async fn run(
        &self,
        listener: TcpListener,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<()> {
        let actual_port = listener.local_addr().unwrap_or(self.bind_addr).port();
        let mut self_ports = self.self_ports.clone();
        if !self_ports.contains(&actual_port) {
            self_ports.push(actual_port);
        }
        let self_ports = Arc::new(self_ports);
        // 无论外部是否注入 `with_in_flight(...)`，均在 `run()` 内部追踪已派生的请求协程，
        // 停机前优雅排空在途响应写回（防止独立调用 `ApiServer::run` 时 `elevate` 提前触发 `shutdown_tx` 导致丢失 200 OK）
        let local_in_flight = Arc::new(InFlightTracker::new());

        loop {
            if *shutdown_rx.borrow() {
                info!("[API] Shutdown signal already set, stopping API server");
                break;
            }
            let (mut stream, _) = tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok(r) => r,
                        Err(e) => {
                            error!("[API] Failed to accept HTTP API request: {}", e);
                            tokio::select! {
                                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                                _ = shutdown_rx.changed() => break,
                            }
                            continue;
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    info!("[API] Received shutdown signal, stopping API server");
                    break;
                }
            };

            let permit = match self.conn_limit.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    let _in_flight = self.in_flight.as_ref().map(|t| t.enter());
                    let _local_guard = local_in_flight.enter();
                    tokio::spawn(async move {
                        let _in_flight = _in_flight;
                        let _local_guard = _local_guard;
                        let _ = tokio::time::timeout(
                            Duration::from_secs(2),
                            send_http_response(
                                &mut stream,
                                "503 Service Unavailable",
                                "application/json; charset=utf-8",
                                r#"{"error":"Too many concurrent API requests","code":"ERR_OVERLOADED"}"#,
                            ),
                        )
                        .await;
                    });
                    continue;
                }
            };

            let monitor = Arc::clone(&self.monitor);
            let rule_engine = Arc::clone(&self.rule_engine);
            let proxy_nodes = Arc::clone(&self.proxy_nodes);
            let self_ports_clone = Arc::clone(&self_ports);
            let config_store = self.config_store.clone();
            let runtime_context = self.runtime_context.clone();
            let transparent_manager = self.transparent_manager.clone();
            let shutdown_tx = self.shutdown_tx.clone();
            let ping_semaphore = Arc::clone(&self.ping_semaphore);
            let mutation_semaphore = Arc::clone(&self.mutation_semaphore);
            let mutation_lock = Arc::clone(&self.mutation_lock);
            let elevating = Arc::clone(&self.elevating);
            #[cfg(test)]
            let elevate_runner = self.elevate_runner.clone();
            #[cfg(not(test))]
            let elevate_runner: Option<ElevateRunner> = None;
            let persist_timeout = self.persist_timeout;
            let started_at = self.started_at;
            let _in_flight = self.in_flight.as_ref().map(|t| t.enter());
            let _local_guard = local_in_flight.enter();

            tokio::spawn(async move {
                let _permit = permit;
                let _in_flight = _in_flight;
                let _local_guard = _local_guard;
                if let Err(e) = handle_api_request(
                    stream,
                    actual_port,
                    self_ports_clone,
                    monitor,
                    rule_engine,
                    proxy_nodes,
                    config_store,
                    runtime_context,
                    transparent_manager,
                    shutdown_tx,
                    ping_semaphore,
                    mutation_semaphore,
                    mutation_lock,
                    elevating,
                    elevate_runner,
                    persist_timeout,
                    started_at,
                )
                .await
                {
                    error!("[API] Request processing failed: {}", e);
                }
            });
        }
        drop(listener);
        let _ = tokio::time::timeout(Duration::from_secs(5), local_in_flight.wait_zero()).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::http::{
        is_allowed_host, is_allowed_origin, read_full_http_request_with_timeout,
    };
    use crate::api::routes::{
        finish_api_response_and_maybe_shutdown, is_mutation_endpoint,
        release_mutation_locks_before_response,
    };
    use crate::api::transparent::handle_transparent_elevate_after_gate;
    use crate::router::{Action, Rule};
    use crate::transparent::TransparentSettings;
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[test]
    fn test_host_and_origin_validation() {
        assert!(is_allowed_host("127.0.0.1:40080", 40080, false));
        assert!(is_allowed_host("localhost:40080", 40080, false));
        assert!(is_allowed_host("[::1]:40080", 40080, false));
        assert!(is_allowed_host("127.0.0.1", 40080, false));
        assert!(!is_allowed_host("evil.com:40080", 40080, false));
        assert!(!is_allowed_host("127.0.0.1.evil.com:40080", 40080, false));
        assert!(!is_allowed_host("127.0.0.1:9999", 40080, false));

        assert!(is_allowed_origin("http://127.0.0.1:40080", 40080));
        assert!(is_allowed_origin("http://localhost:40080", 40080));
        assert!(!is_allowed_origin("http://localhost:3000", 40080));
        assert!(!is_allowed_origin("http://evil.com:40080", 40080));
        assert!(!is_allowed_origin("https://127.0.0.1:40080", 40080));
        assert!(!is_allowed_origin("null", 40080));
    }

    async fn spawn_test_api() -> (
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
        .with_self_ports(vec![40001, 40080, 1053]);
        let listener = srv.bind().await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move { srv.run(listener, rx).await });
        (addr, nodes, re, tx)
    }

    async fn raw_http(addr: SocketAddr, req: &str) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[tokio::test]
    async fn test_api_staged_persist_failure_read_timeout_and_chain_to_proxy_patch() {
        // 1. Chain -> Proxy PATCH without node_id must NOT reuse Chain ID even if Proxy node shares that ID
        let (api_addr, api_nodes, api_re, _tx) = spawn_test_api().await;
        let api_port = api_addr.port();

        let add_node = r#"{"name":"n101","protocol":"SOCKS5","server_addr":"10.0.0.2:1080"}"#;
        let r_node = raw_http(
            api_addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                api_port,
                add_node.len(),
                add_node
            ),
        )
        .await;
        assert!(r_node.starts_with("HTTP/1.1 200 OK"));
        let node_id =
            serde_json::from_str::<serde_json::Value>(r_node.split("\r\n\r\n").nth(1).unwrap())
                .unwrap()["id"]
                .as_u64()
                .unwrap() as u32;
        assert!(api_nodes.read().unwrap().contains_key(&node_id));

        let chain_rule = Rule::from_raw(
            "ChainRule".to_string(),
            true,
            None,
            Some("example.com"),
            None,
            Action::Chain(node_id),
        );
        let chain_rule_id = chain_rule.id;
        api_re.add_rule(chain_rule);

        let switch_missing_node = format!(r#"{{"id":{},"action":"Proxy"}}"#, chain_rule_id);
        let r_bad_switch = raw_http(
            api_addr,
            &format!(
                "PATCH /api/rules HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                api_port,
                switch_missing_node.len(),
                switch_missing_node
            ),
        )
        .await;
        assert!(r_bad_switch.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(r_bad_switch.contains("ERR_MISSING_NODE_FOR_PROXY"));
        assert_eq!(
            api_re
                .current_rules()
                .iter()
                .find(|r| r.id == chain_rule_id)
                .unwrap()
                .action,
            Action::Chain(node_id)
        );

        let switch_with_node = format!(
            r#"{{"id":{},"action":"Proxy","node_id":{}}}"#,
            chain_rule_id, node_id
        );
        let r_ok_switch = raw_http(
            api_addr,
            &format!(
                "PATCH /api/rules HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                api_port,
                switch_with_node.len(),
                switch_with_node
            ),
        )
        .await;
        assert!(r_ok_switch.starts_with("HTTP/1.1 200 OK"));
        assert_eq!(
            api_re
                .current_rules()
                .iter()
                .find(|r| r.id == chain_rule_id)
                .unwrap()
                .action,
            Action::Proxy(node_id)
        );

        // 2. Request read timeout produces 408 / ERR_REQUEST_TIMEOUT cleanly
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let l_addr = l.local_addr().unwrap();
        let srv_task = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = Vec::new();
            read_full_http_request_with_timeout(&mut s, &mut buf, Duration::from_millis(40)).await
        });
        let mut slow_client = TcpStream::connect(l_addr).await.unwrap();
        slow_client
            .write_all(b"POST /api/nodes HTTP/1.1\r\n")
            .await
            .unwrap();
        let read_err = srv_task.await.unwrap().unwrap_err();
        assert_eq!(read_err.http_status(), "408 Request Timeout");
        assert_eq!(read_err.code_and_key().0, "ERR_REQUEST_TIMEOUT");

        // 3. Staged persist-before-commit leaves default action untouched when disk write fails
        let mut blocker = std::env::current_dir().unwrap().join("target");
        blocker.push(format!("flowx_staged_persist_{}.tmp", std::process::id()));
        std::fs::write(&blocker, b"not-a-directory").unwrap();
        let store = Arc::new(ConfigStore::new(blocker.join("flowx.xml")));
        let mgr = Arc::new(ConnectionManager::new());
        let re = Arc::new(RuleEngine::new(Vec::new(), Action::Direct));
        let nodes = Arc::new(RwLock::new(HashMap::new()));
        let srv = ApiServer::new(
            "127.0.0.1:0".parse().unwrap(),
            mgr,
            Arc::clone(&re),
            Arc::clone(&nodes),
        )
        .with_config_store(store);
        let listener = srv.bind().await.unwrap();
        let s_addr = listener.local_addr().unwrap();
        let s_port = s_addr.port();
        let (_tx2, rx2) = watch::channel(false);
        tokio::spawn(async move { srv.run(listener, rx2).await });

        let set_def = r#"{"action":"Block"}"#;
        let r_def = raw_http(
            s_addr,
            &format!(
                "POST /api/rules/default HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                s_port,
                set_def.len(),
                set_def
            ),
        )
        .await;
        assert!(r_def.starts_with("HTTP/1.1 500 Internal Server Error"));
        assert!(r_def.contains("ERR_CONFIG_PERSIST_FAILED"));
        assert_eq!(re.default_action(), Action::Direct);
        let _ = std::fs::remove_file(&blocker);
    }

    #[tokio::test]
    async fn test_api_persist_timeout_and_mutation_isolation_do_not_starve_health_or_kill() {
        let cfg_path = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("test_persist_isolation_{}.xml", std::process::id()));
        let _ = std::fs::remove_file(&cfg_path);
        let store = Arc::new(ConfigStore::new(&cfg_path));
        store
            .save_profile(&crate::config::ProfileConfig::default_profile())
            .unwrap();

        let monitor = Arc::new(ConnectionManager::new());
        let tracked = monitor.register(
            "curl.exe".into(),
            "C:\\curl.exe".into(),
            4321,
            "example.com:443".into(),
            "Default".into(),
            "Direct".into(),
            None,
        );
        let rule_engine = Arc::new(RuleEngine::new(Vec::new(), Action::Direct));
        let nodes = Arc::new(RwLock::new(HashMap::new()));

        let server = ApiServer::new(
            "127.0.0.1:0".parse().unwrap(),
            Arc::clone(&monitor),
            rule_engine,
            Arc::clone(&nodes),
        )
        .with_config_store(Arc::clone(&store))
        .with_persist_timeout(Duration::from_millis(80));
        let listener = server.bind().await.unwrap();
        let api_addr = listener.local_addr().unwrap();
        let api_port = api_addr.port();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(async move { server.run(listener, shutdown_rx).await });

        // Hold save_lock on a background OS thread to simulate stalled disk I/O across awaits
        let (locked_tx, locked_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let store_blocker = Arc::clone(&store);
        let blocker_thread = std::thread::spawn(move || {
            let _guard = store_blocker.lock_save_for_test();
            let _ = locked_tx.send(());
            let _ = release_rx.recv();
        });
        locked_rx.recv().unwrap();

        let mut handles = Vec::new();
        for idx in 0..24 {
            handles.push(tokio::spawn(async move {
                let body = format!(
                    r#"{{"name":"flood-{}","protocol":"SOCKS5","server_addr":"10.0.0.9:1080"}}"#,
                    idx
                );
                let req = format!(
                    "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    api_port,
                    body.len(),
                    body
                );
                raw_http(api_addr, &req).await
            }));
        }

        // Let initial mutation enter stalled disk write while queue fills
        tokio::time::sleep(Duration::from_millis(25)).await;

        // Health & connection kill must remain unstarved and responsive
        let r_health = tokio::time::timeout(
            Duration::from_millis(400),
            raw_http(
                api_addr,
                &format!(
                    "GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                    api_port
                ),
            ),
        )
        .await
        .expect("/api/health starved by stalled mutations");
        assert!(
            r_health.starts_with("HTTP/1.1 200 OK"),
            "health: {}",
            r_health
        );

        let kill_body = format!(r#"{{"id":{}}}"#, tracked.id);
        let r_kill = tokio::time::timeout(
            Duration::from_millis(400),
            raw_http(
                api_addr,
                &format!(
                    "POST /api/connections/kill HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    api_port,
                    kill_body.len(),
                    kill_body
                ),
            ),
        )
        .await
        .expect("/api/connections/kill starved by stalled mutations");
        assert!(r_kill.starts_with("HTTP/1.1 200 OK"), "kill: {}", r_kill);
        assert!(tracked.is_cancelled());

        let mut saw_persist_timeout_500 = 0usize;
        let mut saw_overloaded_503 = 0usize;
        for h in handles {
            let resp = h.await.unwrap();
            assert!(
                !resp.starts_with("HTTP/1.1 200"),
                "unexpected commit: {}",
                resp
            );
            if resp.contains("ERR_CONFIG_PERSIST_FAILED") {
                saw_persist_timeout_500 += 1;
            } else if resp.contains("ERR_OVERLOADED") {
                saw_overloaded_503 += 1;
            } else {
                panic!(
                    "unexpected error response during stalled mutation flood: {}",
                    resp
                );
            }
        }
        assert!(saw_persist_timeout_500 >= 1);
        assert!(saw_overloaded_503 >= 1);
        assert!(
            nodes.read().unwrap().is_empty(),
            "stalled writes must roll back memory"
        );

        let _ = release_tx.send(());
        let _ = blocker_thread.join();
        tokio::time::sleep(Duration::from_millis(60)).await;

        // 确认已超时回滚的暂存快照绝不会在锁释放后延迟覆盖磁盘配置
        let on_disk_after_unlock = std::fs::read_to_string(&cfg_path).unwrap();
        assert!(
            !on_disk_after_unlock.contains("flood-"),
            "timed-out rolled-back snapshots must never be written to disk after lock release: {on_disk_after_unlock}"
        );

        // 锁释放后的新配置变更必须正常落盘且不被先前已取消的任务覆写
        let fresh_body =
            r#"{"name":"post-recovery","protocol":"SOCKS5","server_addr":"10.0.0.10:1080"}"#;
        let r_fresh = raw_http(
            api_addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                api_port,
                fresh_body.len(),
                fresh_body
            ),
        )
        .await;
        assert!(r_fresh.starts_with("HTTP/1.1 200 OK"), "fresh: {r_fresh}");
        let on_disk_after_fresh = std::fs::read_to_string(&cfg_path).unwrap();
        assert!(on_disk_after_fresh.contains("post-recovery"));
        assert!(!on_disk_after_fresh.contains("flood-"));

        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
        let _ = std::fs::remove_file(&cfg_path);
        let _ = std::fs::remove_file(cfg_path.parent().unwrap().join(format!(
            ".{}.lock",
            cfg_path.file_name().unwrap().to_string_lossy()
        )));
    }

    #[tokio::test]
    async fn test_api_transparent_status_config_toggle_and_persist_rollback() {
        use crate::dns::FakeIpPool;
        use crate::dns::server::DnsServer;
        use crate::interceptor::dispatcher::DispatcherConfig;
        use crate::interceptor::process::ProcessTracker;

        let cfg_path = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "flowx_api_transparent_test_{}_{}.xml",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        let lock_path = cfg_path.parent().unwrap().join(format!(
            ".{}.lock",
            cfg_path.file_name().unwrap().to_string_lossy()
        ));
        let _ = std::fs::remove_file(&cfg_path);
        let _ = std::fs::remove_file(&lock_path);

        struct Cleanup(std::path::PathBuf, std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
                let _ = std::fs::remove_file(&self.1);
            }
        }
        let _cleanup = Cleanup(cfg_path.clone(), lock_path);

        let store = Arc::new(ConfigStore::new(&cfg_path));
        let mgr = Arc::new(ConnectionManager::new());
        let re = Arc::new(RuleEngine::new(Vec::new(), Action::Direct));
        let nodes = Arc::new(RwLock::new(HashMap::new()));
        let fake_ip_pool = Arc::new(FakeIpPool::new_default());
        let tracker = Arc::new(ProcessTracker::new());
        let upstream_dns: SocketAddr = "223.5.5.5:53".parse().unwrap();

        let dispatcher_cfg = Arc::new(DispatcherConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            tracker,
            fake_ip_pool: Arc::clone(&fake_ip_pool),
            upstream_dns,
            rule_engine: Arc::clone(&re),
            monitor: Arc::clone(&mgr),
            proxy_nodes: Arc::clone(&nodes),
            proxy_chains: Arc::new(HashMap::new()),
            self_ports: vec![40001, 1053],
            in_flight: None,
        });
        let dns_server = Arc::new(DnsServer::new(
            "127.0.0.1:0".parse().unwrap(),
            fake_ip_pool,
            upstream_dns,
            true,
        ));
        let t_mgr = Arc::new(TransparentManager::new(
            dispatcher_cfg,
            dns_server,
            TransparentSettings::default(),
        ));

        let srv = ApiServer::new(
            "127.0.0.1:0".parse().unwrap(),
            mgr,
            Arc::clone(&re),
            Arc::clone(&nodes),
        )
        .with_self_ports(vec![40001, 40080, 1053])
        .with_config_store(Arc::clone(&store))
        .with_transparent_manager(Arc::clone(&t_mgr))
        .with_persist_timeout(Duration::from_millis(500));
        let listener = srv.bind().await.unwrap();
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        let (shutdown_tx, rx) = watch::channel(false);
        let server_task = tokio::spawn(async move { srv.run(listener, rx).await });

        // 1. /api/system embeds transparent status and /api/transparent/status works
        let sys_resp = raw_http(
            addr,
            &format!(
                "GET /api/system HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                port
            ),
        )
        .await;
        assert!(sys_resp.starts_with("HTTP/1.1 200 OK"), "sys: {sys_resp}");
        assert!(sys_resp.contains(r#""transparent":{"#));

        let status_resp = raw_http(
            addr,
            &format!(
                "GET /api/transparent/status HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                port
            ),
        )
        .await;
        assert!(
            status_resp.starts_with("HTTP/1.1 200 OK"),
            "status: {status_resp}"
        );
        assert!(status_resp.contains(r#""enabled":false"#));
        assert!(status_resp.contains(r#""hijack_dns":true"#));

        // 2. PUT /api/transparent/config rejects control chars, untrusted/relative/UNC/non-WinDivert paths & conflicting clear_dll_path
        for bad_body in [
            r#"{"dll_path":"C:\\bad\npath\\WinDivert.dll"}"#,
            r#"{"dll_path":"C:\\ok\\WinDivert.dll","clear_dll_path":true}"#,
            r#"{"dll_path":"WinDivert.dll"}"#,
            r#"{"dll_path":"..\\evil\\WinDivert.dll"}"#,
            r#"{"dll_path":"\\\\fileserver\\share\\WinDivert.dll"}"#,
            r#"{"dll_path":"C:\\tools\\evil.dll"}"#,
        ] {
            let bad_resp = raw_http(
                addr,
                &format!(
                    "PUT /api/transparent/config HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    port,
                    bad_body.len(),
                    bad_body
                ),
            )
            .await;
            assert!(
                bad_resp.starts_with("HTTP/1.1 400 Bad Request"),
                "bad: {bad_resp}"
            );
            assert!(bad_resp.contains("ERR_TRANSPARENT_INVALID_DLL_PATH"));
        }

        // 3. Valid PUT /api/transparent/config persists <TransparentProxy> to XML
        let cfg_body = r#"{"hijack_dns":false,"block_quic_for_proxied":false,"dll_path":"Z:\\__nonexistent_windivert_test__\\WinDivert.dll"}"#;
        let cfg_resp = raw_http(
            addr,
            &format!(
                "PUT /api/transparent/config HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                port,
                cfg_body.len(),
                cfg_body
            ),
        )
        .await;
        assert!(cfg_resp.starts_with("HTTP/1.1 200 OK"), "cfg: {cfg_resp}");
        assert!(cfg_resp.contains(r#""hijack_dns":false"#));
        assert!(cfg_resp.contains(r#""block_quic_for_proxied":false"#));

        let saved_rt = store.load_existing(&[]).unwrap();
        assert!(!saved_rt.transparent_settings.hijack_dns);
        assert!(!saved_rt.transparent_settings.block_quic_for_proxied);
        assert_eq!(
            saved_rt.transparent_settings.dll_path.as_deref(),
            Some(r"Z:\__nonexistent_windivert_test__\WinDivert.dll")
        );

        // 4. Node mutations preserve <TransparentProxy> on disk
        let node_body = r#"{"name":"n1","protocol":"SOCKS5","server_addr":"10.0.0.1:1080"}"#;
        let node_resp = raw_http(
            addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                port,
                node_body.len(),
                node_body
            ),
        )
        .await;
        assert!(
            node_resp.starts_with("HTTP/1.1 200 OK"),
            "node: {node_resp}"
        );
        let saved_after_node = store.load_existing(&[]).unwrap();
        assert!(!saved_after_node.transparent_settings.hijack_dns);
        assert_eq!(
            saved_after_node.transparent_settings.dll_path.as_deref(),
            Some(r"Z:\__nonexistent_windivert_test__\WinDivert.dll")
        );

        // 5. Enabling transparent proxy with missing driver/non-admin fails closed without mutating XML
        let toggle_body = r#"{"enabled":true}"#;
        let toggle_resp = raw_http(
            addr,
            &format!(
                "POST /api/transparent/toggle HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                port,
                toggle_body.len(),
                toggle_body
            ),
        )
        .await;
        assert!(
            toggle_resp.starts_with("HTTP/1.1 409 Conflict"),
            "toggle fail: {toggle_resp}"
        );
        assert!(!t_mgr.settings().enabled);
        let saved_after_failed_toggle = store.load_existing(&[]).unwrap();
        assert!(!saved_after_failed_toggle.transparent_settings.enabled);

        // 6. Stalled ConfigStore persistence rolls back transparent settings in memory
        let (hold_tx, hold_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let blocker_store = Arc::clone(&store);
        let blocker_nodes = Arc::clone(&nodes);
        let blocker_re = Arc::clone(&re);
        let blocker_thread = std::thread::spawn(move || {
            let _lock = blocker_store.lock_save_for_test();
            let _ = hold_tx.send(());
            let _ = release_rx.recv();
            drop(_lock);
            let _ = blocker_store.save_runtime(&blocker_nodes, &blocker_re);
        });
        hold_rx.recv().unwrap();

        let rollback_body = r#"{"hijack_dns":true,"clear_dll_path":true}"#;
        let rb_resp = raw_http(
            addr,
            &format!(
                "PUT /api/transparent/config HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                port,
                rollback_body.len(),
                rollback_body
            ),
        )
        .await;
        assert!(
            rb_resp.starts_with("HTTP/1.1 500 Internal Server Error"),
            "rb: {rb_resp}"
        );
        assert!(rb_resp.contains("ERR_CONFIG_PERSIST_FAILED"));
        assert!(
            !t_mgr.settings().hijack_dns,
            "hijack_dns should roll back on persist timeout"
        );
        assert_eq!(
            t_mgr.settings().dll_path.as_deref(),
            Some(r"Z:\__nonexistent_windivert_test__\WinDivert.dll")
        );

        let _ = release_tx.send(());
        let _ = blocker_thread.join();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let _ = shutdown_tx.send(true);
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn test_api_elevate_is_mutation_and_always_signals_shutdown() {
        // /api/transparent/elevate 使用前置独立原子闸门，不再落入 mutation_lock 死分支
        assert!(!is_mutation_endpoint("POST", "/api/transparent/elevate"));
        assert!(is_mutation_endpoint("POST", "/api/transparent/toggle"));
        assert!(!is_mutation_endpoint("GET", "/api/transparent/status"));

        // 即使响应写入期间客户端提前断开连接，触发提权重启停机时仍必须广播 shutdown_tx
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (mut server_stream, _) = listener.accept().await.unwrap();
        drop(client);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let large_body = "x".repeat(4 * 1024 * 1024);
        // 先关闭/写探测确保写入最终失败或半关后仍唤醒 shutdown_tx
        let _ = server_stream.shutdown().await;
        let res = finish_api_response_and_maybe_shutdown(
            &mut server_stream,
            "200 OK",
            "application/json; charset=utf-8",
            &large_body,
            true,
            Some(&shutdown_tx),
        )
        .await;
        assert!(
            res.is_err(),
            "writing after shutdown/disconnect should return error"
        );
        assert!(
            *shutdown_rx.borrow(),
            "shutdown_tx must still be triggered when elevated response write fails"
        );
    }

    #[tokio::test]
    async fn test_api_elevate_one_shot_guard_and_shutdown_before_unlock() {
        // 1. 当 elevating 原子闸门已被占用时，并发/重复 POST /api/transparent/elevate 必须立即返回 409 Conflict 且不清空闸门
        let mgr = Arc::new(ConnectionManager::new());
        let re = Arc::new(RuleEngine::new(Vec::new(), Action::Direct));
        let nodes = Arc::new(RwLock::new(HashMap::new()));
        let srv = ApiServer::new("127.0.0.1:0".parse().unwrap(), mgr, re, nodes);
        srv.elevating.store(true, Ordering::Release);

        let listener = srv.bind().await.unwrap();
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        let (shutdown_tx, rx) = watch::channel(false);
        let elevating_ref = Arc::clone(&srv.elevating);
        let server_task = tokio::spawn(async move { srv.run(listener, rx).await });

        let resp = raw_http(
            addr,
            &format!(
                "POST /api/transparent/elevate HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}",
                port
            ),
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 409 Conflict"), "resp: {resp}");
        assert!(resp.contains("ERR_TRANSPARENT_ELEVATE_IN_PROGRESS"));
        assert!(
            elevating_ref.load(Ordering::Acquire),
            "concurrent rejection must not clear active elevating gate"
        );

        let _ = shutdown_tx.send(true);
        let _ = server_task.await;

        // 2. 验证 release_mutation_locks_before_response 先触发 shutdown_tx 再释放 mutation_lock
        let m_lock = Arc::new(Mutex::new(()));
        let m_sem = Arc::new(Semaphore::new(1));
        let (elev_tx, elev_rx) = watch::channel(false);

        let mut g_opt = Some(m_lock.lock().await);
        let mut p_opt = Some(m_sem.try_acquire().unwrap());

        let waiter_lock = Arc::clone(&m_lock);
        let waiter_rx = elev_rx.clone();
        let waiter = tokio::spawn(async move {
            let _g = waiter_lock.lock().await;
            *waiter_rx.borrow()
        });
        tokio::task::yield_now().await;
        assert!(!*elev_rx.borrow());

        release_mutation_locks_before_response(&mut g_opt, &mut p_opt, true, Some(&elev_tx));
        assert!(
            waiter.await.unwrap(),
            "shutdown_tx must be visible before mutation_lock unlocks"
        );
    }

    #[tokio::test]
    async fn test_api_elevate_concurrent_during_blocking_uac_and_cancel_retry() {
        use std::sync::atomic::AtomicUsize;

        let mgr = Arc::new(ConnectionManager::new());
        let re = Arc::new(RuleEngine::new(Vec::new(), Action::Direct));
        let nodes = Arc::new(RwLock::new(HashMap::new()));

        let calls = Arc::new(AtomicUsize::new(0));
        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<std::io::Result<()>>();
        let entered_tx = Arc::new(std::sync::Mutex::new(Some(entered_tx)));
        let release_rx = Arc::new(std::sync::Mutex::new(release_rx));

        let runner: ElevateRunner = {
            let calls = Arc::clone(&calls);
            let entered_tx = Arc::clone(&entered_tx);
            let release_rx = Arc::clone(&release_rx);
            Arc::new(move || {
                let n = calls.fetch_add(1, Ordering::AcqRel) + 1;
                if n == 1 {
                    if let Some(tx) = entered_tx.lock().unwrap().take() {
                        let _ = tx.send(());
                    }
                    release_rx.lock().unwrap().recv().unwrap()
                } else {
                    Ok(())
                }
            })
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let srv = ApiServer::new("127.0.0.1:0".parse().unwrap(), mgr, Arc::clone(&re), nodes)
            .with_shutdown_sender(shutdown_tx.clone())
            .with_persist_timeout(Duration::from_millis(100))
            .with_elevate_runner(runner);

        let listener = srv.bind().await.unwrap();
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        let rx_srv = shutdown_rx.clone();
        let server_task = tokio::spawn(async move { srv.run(listener, rx_srv).await });

        // 1. 请求 1 发起提权并阻塞在模拟 UAC 对话框阶段（远超 mutation_lock 的 100ms persist_timeout）
        let raw_req1 = format!(
            "POST /api/transparent/elevate HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}",
            port
        );
        let req1 = tokio::spawn(async move { raw_http(addr, &raw_req1).await });
        tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
            .await
            .unwrap();

        // 2. UAC 弹窗挂起期间并发发送第二个提权请求：必须立刻返回 409 Conflict（绝不阻塞或返回 503），且不会重入拉起第二个 UAC
        let resp2 = tokio::time::timeout(
            Duration::from_secs(1),
            raw_http(
                addr,
                &format!(
                    "POST /api/transparent/elevate HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}",
                    port
                ),
            ),
        )
        .await
        .expect("concurrent elevate must return 409 immediately without waiting on UAC");
        assert!(resp2.starts_with("HTTP/1.1 409 Conflict"), "resp2: {resp2}");
        assert!(resp2.contains("ERR_TRANSPARENT_ELEVATE_IN_PROGRESS"));
        assert_eq!(calls.load(Ordering::Acquire), 1);

        // 3. UAC 弹窗挂起期间并发发送普通配置修改：不应被阻塞在 UAC 对话框上
        let def_body = r#"{"action":"Direct"}"#;
        let mut_resp = tokio::time::timeout(
            Duration::from_secs(1),
            raw_http(
                addr,
                &format!(
                    "POST /api/rules/default HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    port,
                    def_body.len(),
                    def_body
                ),
            ),
        )
        .await
        .expect("regular mutations must not stall on interactive UAC");
        assert!(
            mut_resp.starts_with("HTTP/1.1 200 OK"),
            "mut_resp: {mut_resp}"
        );

        // 4. 模拟用户在首个 UAC 取消授权：请求 1 返回 409 UAC_CANCELLED，且期间 calls 仍为 1（绝不弹出第二个 UAC）
        release_tx
            .send(Err(std::io::Error::other(
                "ERR_TRANSPARENT_UAC_CANCELLED: User cancelled UAC prompt",
            )))
            .unwrap();
        let resp1 = req1.await.unwrap();
        assert!(resp1.starts_with("HTTP/1.1 409 Conflict"), "resp1: {resp1}");
        assert!(resp1.contains("ERR_TRANSPARENT_UAC_CANCELLED"));
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert!(!*shutdown_rx.borrow());

        // 5. 取消之后允许重新发起提权；一旦成功即触发 shutdown_tx
        let resp3 = raw_http(
            addr,
            &format!(
                "POST /api/transparent/elevate HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}",
                port
            ),
        )
        .await;
        assert!(resp3.starts_with("HTTP/1.1 200 OK"), "resp3: {resp3}");
        assert!(resp3.contains(r#""relaunching":true"#));
        assert_eq!(calls.load(Ordering::Acquire), 2);
        assert!(*shutdown_rx.borrow());

        let _ = server_task.await;

        // 6. 验证 Ctrl+C 正常停机（shutdown_tx=true 且 elevating=false）不会误报 ERR_TRANSPARENT_ELEVATE_IN_PROGRESS，
        //    而是返回 503 ERR_SERVER_SHUTTING_DOWN；同时验证异步 future 取消后 ElevateFlagResetGuard 仍留在 blocking 线程内
        let (ctrl_c_tx, _ctrl_c_rx) = watch::channel(true);
        let mgr2 = Arc::new(ConnectionManager::new());
        let re2 = Arc::new(RuleEngine::new(Vec::new(), Action::Direct));
        let nodes2 = Arc::new(RwLock::new(HashMap::new()));
        let mut_lock = Arc::new(Mutex::new(()));
        let mut_sem = Arc::new(Semaphore::new(4));
        let ping_sem = Arc::new(Semaphore::new(4));
        let elev_flag = Arc::new(AtomicBool::new(false));
        let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a2 = l2.local_addr().unwrap();
        let p2 = a2.port();
        let h2 = tokio::spawn(async move {
            let (stream, _) = l2.accept().await.unwrap();
            handle_api_request(
                stream,
                p2,
                Arc::new(vec![p2]),
                mgr2,
                re2,
                nodes2,
                None,
                None,
                None,
                Some(ctrl_c_tx),
                ping_sem,
                mut_sem,
                mut_lock,
                elev_flag,
                None,
                Duration::from_secs(1),
                Instant::now(),
            )
            .await
            .unwrap();
        });
        let shutdown_resp = raw_http(
            a2,
            &format!(
                "POST /api/rules/default HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: 19\r\n\r\n{{\"action\":\"Direct\"}}",
                p2
            ),
        )
        .await;
        h2.await.unwrap();
        assert!(
            shutdown_resp.starts_with("HTTP/1.1 503 Service Unavailable"),
            "Ctrl+C shutdown should return 503, got: {shutdown_resp}"
        );
        assert!(shutdown_resp.contains("ERR_SERVER_SHUTTING_DOWN"));
        assert!(!shutdown_resp.contains("ERR_TRANSPARENT_ELEVATE_IN_PROGRESS"));

        // 7. 异步 future 被取消时，spawn_blocking 内的 ElevateFlagResetGuard 仍持续锁住 elevating 直到 UAC 返回，
        //    且用户确认后仍立即广播 shutdown_tx
        let (uac_in_tx, uac_in_rx) = std::sync::mpsc::channel::<()>();
        let (uac_out_tx, uac_out_rx) = std::sync::mpsc::channel::<std::io::Result<()>>();
        let uac_in_tx = Arc::new(std::sync::Mutex::new(Some(uac_in_tx)));
        let uac_out_rx = Arc::new(std::sync::Mutex::new(uac_out_rx));
        let blocking_runner: ElevateRunner = Arc::new(move || {
            if let Some(tx) = uac_in_tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
            uac_out_rx.lock().unwrap().recv().unwrap()
        });
        let elev_cancel_flag = Arc::new(AtomicBool::new(true));
        let (cancel_sd_tx, cancel_sd_rx) = watch::channel(false);
        let cancelled_task = tokio::spawn({
            let flag = Arc::clone(&elev_cancel_flag);
            let sd_tx = cancel_sd_tx.clone();
            async move {
                let mut trig = false;
                let _ = handle_transparent_elevate_after_gate(
                    Locale::En,
                    flag,
                    Some(sd_tx),
                    Some(blocking_runner),
                    &mut trig,
                )
                .await;
            }
        });
        tokio::task::spawn_blocking(move || uac_in_rx.recv().unwrap())
            .await
            .unwrap();
        cancelled_task.abort();
        let _ = cancelled_task.await;
        assert!(
            elev_cancel_flag.load(Ordering::Acquire),
            "elevating must remain true while blocking UAC thread is still open after async cancel"
        );
        uac_out_tx.send(Ok(())).unwrap();
        let mut rx_wait = cancel_sd_rx.clone();
        tokio::time::timeout(Duration::from_secs(1), rx_wait.changed())
            .await
            .expect("blocking thread must still signal shutdown_tx when UAC succeeds after async cancel")
            .unwrap();
        assert!(*cancel_sd_rx.borrow());
        assert!(elev_cancel_flag.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn test_p2_6_standalone_api_server_run_drains_elevate_response_before_exiting() {
        let mgr = Arc::new(ConnectionManager::new());
        let re = Arc::new(RuleEngine::new(Vec::new(), Action::Direct));
        let nodes = Arc::new(RwLock::new(HashMap::new()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // 显式不调用 `.with_in_flight(...)`，模拟独立启动 ApiServer::run 的调用方
        let srv = ApiServer::new("127.0.0.1:0".parse().unwrap(), mgr, re, nodes)
            .with_shutdown_sender(shutdown_tx)
            .with_elevate_runner(Arc::new(|| {
                std::thread::sleep(Duration::from_millis(20));
                Ok(())
            }));
        let listener = srv.bind().await.unwrap();
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        let server_task = tokio::spawn(async move { srv.run(listener, shutdown_rx).await });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "POST /api/transparent/elevate HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 0\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();

        // 必须等到 `handle_api_request` 完整写完并刷出 200 OK 后 `run()` 才返回
        tokio::time::timeout(Duration::from_secs(3), server_task)
            .await
            .expect("ApiServer::run must exit cleanly after draining elevate response")
            .unwrap()
            .unwrap();

        let mut resp_bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut resp_bytes))
            .await
            .expect("200 OK response must already be flushed before ApiServer::run returns")
            .unwrap();
        let resp = String::from_utf8_lossy(&resp_bytes);
        assert!(
            resp.starts_with("HTTP/1.1 200 OK") && resp.contains(r#""relaunching":true"#),
            "expected complete 200 OK elevate response after run() drained, got: {resp}"
        );
    }

    #[tokio::test]
    async fn test_elevate_low_integrity_error_maps_to_409_conflict_with_detail() {
        let mgr = Arc::new(ConnectionManager::new());
        let re = Arc::new(RuleEngine::new(Vec::new(), Action::Direct));
        let nodes = Arc::new(RwLock::new(HashMap::new()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let srv = ApiServer::new("127.0.0.1:0".parse().unwrap(), mgr, re, nodes)
            .with_shutdown_sender(shutdown_tx)
            .with_elevate_runner(Arc::new(|| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "ERR_TRANSPARENT_LOW_INTEGRITY: blocked at Low IL",
                ))
            }));
        let listener = srv.bind().await.unwrap();
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        let mut rx_srv = shutdown_rx.clone();
        let server_task = tokio::spawn(async move {
            tokio::select! {
                res = srv.run(listener, rx_srv.clone()) => res,
                _ = rx_srv.changed() => Ok(()),
            }
        });

        let req = format!(
            "POST /api/transparent/elevate HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept-Language: zh-CN\r\nContent-Length: 0\r\n\r\n"
        );
        let resp = raw_http(addr, &req).await;
        assert!(resp.starts_with("HTTP/1.1 409 Conflict"), "resp: {resp}");
        assert!(
            resp.contains("ERR_TRANSPARENT_LOW_INTEGRITY"),
            "resp: {resp}"
        );
        assert!(resp.contains("blocked at Low IL"), "resp: {resp}");
        assert!(!*shutdown_rx.borrow());

        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn test_elevate_rejects_non_utf8_body_without_triggering_uac() {
        let mgr = Arc::new(ConnectionManager::new());
        let re = Arc::new(RuleEngine::new(Vec::new(), Action::Direct));
        let nodes = Arc::new(RwLock::new(HashMap::new()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let invoked_c = Arc::clone(&invoked);

        let srv = ApiServer::new("127.0.0.1:0".parse().unwrap(), mgr, re, nodes)
            .with_shutdown_sender(shutdown_tx)
            .with_elevate_runner(Arc::new(move || {
                invoked_c.store(true, Ordering::SeqCst);
                Ok(())
            }));
        let listener = srv.bind().await.unwrap();
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        let mut rx_srv = shutdown_rx.clone();
        let server_task = tokio::spawn(async move {
            tokio::select! {
                res = srv.run(listener, rx_srv.clone()) => res,
                _ = rx_srv.changed() => Ok(()),
            }
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let header = format!(
            "POST /api/transparent/elevate HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(header.as_bytes()).await.unwrap();
        stream.write_all(&[0xff, 0xfe]).await.unwrap();
        let mut resp_bytes = Vec::new();
        stream.read_to_end(&mut resp_bytes).await.unwrap();
        let resp = String::from_utf8_lossy(&resp_bytes);

        assert!(resp.starts_with("HTTP/1.1 400 Bad Request"), "resp: {resp}");
        assert!(
            resp.contains("ERR_INVALID_TRANSPARENT_BODY"),
            "resp: {resp}"
        );
        assert!(
            !invoked.load(Ordering::SeqCst),
            "invalid non-UTF-8 elevate request must not invoke UAC"
        );
        assert!(!*shutdown_rx.borrow());

        server_task.abort();
        let _ = server_task.await;
    }
}
