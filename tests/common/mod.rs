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
