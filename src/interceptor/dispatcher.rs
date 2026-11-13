use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use anyhow::{anyhow, bail, Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tracing::{error, info, warn};

use crate::dns::FakeIpPool;
use crate::inbound::{self, InboundRequest};
use crate::interceptor::process::ProcessTracker;
use crate::monitor::{ConnectionManager, InFlightTracker};
use crate::outbound::chain::{ProxyChain, ProxyNode};
use crate::outbound::direct::DirectOutbound;
use crate::outbound::{is_local_or_loopback_ip, local_interface_ips, relay_stream_monitored, TargetAddr};
use crate::router::{Action, RouteContext, RuleEngine};

/// 入站协议握手的最长等待时间（防止慢速握手占满并发名额）
const INBOUND_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct ProxyNodeEntry {
    pub id: u32,
    pub name: String,
    pub protocol: String,
    pub server_addr: String,
    pub username: Option<String>,
    pub client: ProxyNode,
}

/// 流量调度核心配置
pub struct DispatcherConfig {
    pub bind_addr: SocketAddr,
    pub tracker: Arc<ProcessTracker>,
    pub fake_ip_pool: Arc<FakeIpPool>,
    pub upstream_dns: SocketAddr,
    pub rule_engine: Arc<RuleEngine>,
    pub monitor: Arc<ConnectionManager>,
    pub proxy_nodes: Arc<RwLock<HashMap<u32, ProxyNodeEntry>>>,
    pub proxy_chains: Arc<HashMap<u32, ProxyChain>>,
    /// FlowX 自身占用的服务端口（入站 / API / DNS），用于拦截指向自身的回环请求
    pub self_ports: Vec<u16>,
}

pub struct StreamDispatcher {
    config: Arc<DispatcherConfig>,
    concurrency_limit: Arc<Semaphore>,
    in_flight: Option<Arc<InFlightTracker>>,
}

impl StreamDispatcher {
    pub fn new(config: DispatcherConfig) -> Self {
        Self {
            config: Arc::new(config),
            concurrency_limit: Arc::new(Semaphore::new(10000)), // 最大并发连接保护
            in_flight: None,
        }
    }

    pub fn with_in_flight(mut self, tracker: Arc<InFlightTracker>) -> Self {
        self.in_flight = Some(tracker);
        self
    }

    /// 同步绑定 TCP 监听器（Fail-Fast 检查端口占用）
    pub async fn bind(&self) -> Result<TcpListener> {
        let listener = TcpListener::bind(self.config.bind_addr)
            .await
            .with_context(|| format!("Failed to bind mixed inbound port ({})", self.config.bind_addr))?;
        info!(
            "[Dispatcher] Mixed proxy inbound (SOCKS5 / SOCKS4a / HTTP) bound on {}",
            self.config.bind_addr
        );
        Ok(listener)
    }

    /// 启动本地入站连接调度监听服务（支持优雅停机）
    pub async fn run(&self, listener: TcpListener, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        loop {
            if *shutdown_rx.borrow() {
                info!("[Dispatcher] Shutdown signal already set, stopping accepting new streams");
                break;
            }
            let (local_stream, peer_addr) = tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok(r) => r,
                        Err(e) => {
                            error!("[Dispatcher] Failed to accept new TCP connection: {}", e);
                            tokio::select! {
                                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                                _ = shutdown_rx.changed() => break,
                            }
                            continue;
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    info!("[Dispatcher] Received shutdown signal, stopping accepting new streams");
                    break;
                }
            };

            let permit = match self.concurrency_limit.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!("[Dispatcher] Active connections exceeded limit (10000), rejecting new connection");
                    drop(local_stream);
                    continue;
                }
            };

            let config = Arc::clone(&self.config);
            let _in_flight = self.in_flight.as_ref().map(|t| t.enter());
            tokio::spawn(async move {
                let _permit = permit;
                let _in_flight = _in_flight;
                if let Err(e) = handle_connection(local_stream, peer_addr, config).await {
                    warn!("[Dispatcher] Relay session closed or error: {:#}", e);
                }
            });
        }
        Ok(())
    }
}

/// RAII 守卫：确保连接注销操作在任何退出分支均能精准执行
struct ConnectionGuard {
    id: u64,
    monitor: Arc<ConnectionManager>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.monitor.unregister(self.id);
    }
}

/// 判断目标是否指向 FlowX 自身的服务端口（防止自连回环）
fn is_self_target(target: &TargetAddr, server_addr: &SocketAddr, self_ports: &[u16]) -> bool {
    if !self_ports.contains(&target.port()) {
        return false;
    }
    if target.is_loopback_or_unspecified() {
        return true;
    }
    if let TargetAddr::Ip(addr) = target {
        if addr.ip() == server_addr.ip() {
            return true;
        }
        let local_ips = local_interface_ips();
        return is_local_or_loopback_ip(addr.ip(), &local_ips);
    }
    false
}

async fn handle_connection(
    mut local_stream: TcpStream,
    peer_addr: SocketAddr,
    config: Arc<DispatcherConfig>,
) -> Result<()> {
    let server_addr = local_stream.local_addr()?;

    // 1. Parse inbound proxy protocol handshake, obtain client target address
    let InboundRequest {
        kind,
        target,
        pending,
        http_body_framing,
        body_prefix,
    } = tokio::time::timeout(INBOUND_HANDSHAKE_TIMEOUT, inbound::read_request(&mut local_stream))
        .await
        .map_err(|_| anyhow!("Inbound handshake timed out ({:?}), peer {}", INBOUND_HANDSHAKE_TIMEOUT, peer_addr))??;

    // 2. Reverse lookup caller process via TCP 4-tuple (async non-blocking)
    let proc_info = config.tracker.find_by_connection_async(peer_addr, server_addr).await;
    let proc_name = proc_info
        .as_ref()
        .map(|p| p.name.clone())
        .unwrap_or_else(|| crate::i18n::UNKNOWN_PROCESS.to_string());
    let proc_path = proc_info
        .as_ref()
        .map(|p| p.path.clone())
        .unwrap_or_else(|| crate::i18n::UNKNOWN_PROCESS.to_string());
    let pid = proc_info.as_ref().map(|p| p.pid).unwrap_or(0);

    // 3. If target is Fake-IP, restore original domain (prevent DNS leak, let upstream proxy resolve)
    let target = match &target {
        TargetAddr::Ip(addr) => match addr.ip() {
            IpAddr::V4(v4) if config.fake_ip_pool.is_fake_ip(&v4) => match config.fake_ip_pool.restore(&v4) {
                Some(domain) => TargetAddr::Domain(domain, addr.port()),
                None => {
                    inbound::send_failure(&mut local_stream, kind, false).await.ok();
                    bail!("Fake-IP {} domain mapping expired or does not exist", v4);
                }
            },
            _ => target,
        },
        TargetAddr::Domain(..) => target,
    };

    // 4. Loop prevention: reject requests targeting FlowX internal service ports
    if is_self_target(&target, &server_addr, &config.self_ports) {
        inbound::send_failure(&mut local_stream, kind, true).await.ok();
        bail!(
            "Loopback request rejected: {} (PID {}) attempted to access internal port {}:{}",
            proc_name,
            pid,
            target.host_string(),
            target.port()
        );
    }

    // 5. Build route context and evaluate rules (`None` when process is unattributed so app rules like `*` or `*.exe` don't match "Unknown")
    let (target_host, target_ip) = match &target {
        TargetAddr::Ip(addr) => (None, Some(addr.ip())),
        TargetAddr::Domain(host, _) => (Some(host.as_str()), None),
    };
    let ctx = RouteContext {
        process_path: proc_info.as_ref().map(|p| p.path.as_str()),
        process_name: proc_info.as_ref().map(|p| p.name.as_str()),
        target_host,
        target_ip,
        target_port: target.port(),
    };

    let (action, rule_name) = config.rule_engine.evaluate(&ctx);

    let action_str = match &action {
        Action::Direct => "Direct".to_string(),
        Action::Block => "Block".to_string(),
        Action::Proxy(id) => format!("Proxy({})", id),
        Action::Chain(id) => format!("Chain({})", id),
    };

    info!(
        "[Route Match] [{}] Process: {} (PID: {}) -> Target: {}:{} => Rule: {} => Action: {}",
        kind.as_str(),
        proc_name,
        pid,
        target.host_string(),
        target.port(),
        rule_name,
        action_str
    );

    // 6. 注册到连接监视器并使用 RAII 守卫
    // 注意：连接快照只保存机器可读的 action_type / action_id，展示文案由 API 层按请求语言本地化
    let active_conn = config.monitor.register(
        proc_name,
        proc_path,
        pid,
        format!("{}:{}", target.host_string(), target.port()),
        rule_name,
        action.type_str().to_string(),
        action.target_id(),
    );

    let _guard = ConnectionGuard {
        id: active_conn.id,
        monitor: Arc::clone(&config.monitor),
    };

    // 7. 按动作建立出站连接
    if action == Action::Block {
        inbound::send_failure(&mut local_stream, kind, true).await.ok();
        return Ok(());
    }

    let cancel_token = Arc::clone(&active_conn);
    let mut remote_stream = tokio::select! {
        res = connect_outbound(&config, &action, &target) => {
            match res {
                Ok(s) => s,
                Err(e) => {
                    inbound::send_failure(&mut local_stream, kind, false).await.ok();
                    return Err(e);
                }
            }
        }
        _ = async {
            let notified = cancel_token.cancel_notify.notified();
            if cancel_token.is_cancelled() {
                return;
            }
            notified.await;
        } => {
            inbound::send_failure(&mut local_stream, kind, true).await.ok();
            bail!("Connection aborted by administrator during establishment");
        }
    };

    // 8. Reply to client that tunnel is ready, and forward buffered payload from handshake
    inbound::send_success(&mut local_stream, kind).await?;
    if !pending.is_empty() {
        remote_stream.write_all(&pending).await?;
        active_conn.add_upload(pending.len() as u64);
    }

    // 9. Traffic relay (HTTP plain forward uses bounded request body framing; tunnel modes use full-duplex relay)
    let (up, down) = match (kind, http_body_framing) {
        (inbound::InboundKind::HttpForward, Some(framing)) => {
            crate::outbound::relay_http_forward_monitored(
                local_stream,
                remote_stream,
                Some(&active_conn),
                framing,
                body_prefix,
            )
            .await?
        }
        _ => relay_stream_monitored(local_stream, remote_stream, Some(&active_conn)).await?,
    };
    info!(
        "[Relay Complete] [{}] {}:{} Upload: {} B, Download: {} B",
        action_str,
        target.host_string(),
        target.port(),
        up + pending.len() as u64,
        down
    );
    Ok(())
}

async fn connect_outbound(config: &DispatcherConfig, action: &Action, target: &TargetAddr) -> Result<TcpStream> {
    match action {
        Action::Block => bail!("Connection blocked by rule"),
        Action::Direct => {
            DirectOutbound::connect(
                target,
                config.upstream_dns,
                Some(config.fake_ip_pool.as_ref()),
                &config.self_ports,
            )
            .await
        }
        Action::Proxy(node_id) => {
            let client = {
                let nodes_guard = config.proxy_nodes.read().unwrap_or_else(|e| e.into_inner());
                match nodes_guard.get(node_id) {
                    Some(e) => e.client.clone(),
                    None => bail!("Rule specifies non-existent proxy node ID: {}", node_id),
                }
            };
            let pool = Some(config.fake_ip_pool.as_ref());
            match &client {
                ProxyNode::Socks5(s) => {
                    s.connect_with_policy(target, config.upstream_dns, pool, &config.self_ports)
                        .await
                }
                ProxyNode::Http(h) => {
                    h.connect_with_policy(target, config.upstream_dns, pool, &config.self_ports)
                        .await
                }
                ProxyNode::Socks4(s) => {
                    s.connect_with_policy(target, config.upstream_dns, pool, &config.self_ports)
                        .await
                }
            }
        }
        Action::Chain(chain_id) => {
            let chain = match config.proxy_chains.get(chain_id) {
                Some(c) => c,
                None => bail!("Rule specifies non-existent proxy chain ID: {}", chain_id),
            };
            chain
                .connect_with_policy(
                    target,
                    config.upstream_dns,
                    Some(config.fake_ip_pool.as_ref()),
                    &config.self_ports,
                )
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn test_config(bind: SocketAddr, rules: Vec<crate::router::Rule>) -> DispatcherConfig {
        DispatcherConfig {
            bind_addr: bind,
            tracker: Arc::new(ProcessTracker::new()),
            fake_ip_pool: Arc::new(FakeIpPool::new_default()),
            upstream_dns: "223.5.5.5:53".parse().unwrap(),
            rule_engine: Arc::new(RuleEngine::new(rules, Action::Direct)),
            monitor: Arc::new(ConnectionManager::new()),
            proxy_nodes: Arc::new(RwLock::new(HashMap::new())),
            proxy_chains: Arc::new(HashMap::new()),
            self_ports: vec![bind.port()],
        }
    }

    #[test]
    fn test_is_self_target() {
        let server: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        let ports = [40001, 40080];
        assert!(is_self_target(&TargetAddr::Ip("127.0.0.1:40001".parse().unwrap()), &server, &ports));
        assert!(is_self_target(&TargetAddr::Ip("0.0.0.0:40080".parse().unwrap()), &server, &ports));
        assert!(is_self_target(&TargetAddr::Domain("LocalHost".into(), 40080), &server, &ports));
        assert!(!is_self_target(&TargetAddr::Ip("127.0.0.1:8080".parse().unwrap()), &server, &ports));
        assert!(!is_self_target(&TargetAddr::Domain("example.com".into(), 40001), &server, &ports));
    }

    /// 端到端：经由 SOCKS5 入站直连到本地回显服务，验证目标解析、隧道建立与数据中继
    #[tokio::test]
    async fn test_socks5_direct_relay_end_to_end() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });

        let dispatcher = StreamDispatcher::new(test_config("127.0.0.1:0".parse().unwrap(), vec![]));
        let listener = dispatcher.bind().await.unwrap();
        let inbound_addr = listener.local_addr().unwrap();
        let (_tx, rx) = watch::channel(false);
        tokio::spawn(async move { dispatcher.run(listener, rx).await });

        let mut c = TcpStream::connect(inbound_addr).await.unwrap();
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut r = [0u8; 2];
        c.read_exact(&mut r).await.unwrap();
        let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        req.extend_from_slice(&echo_addr.port().to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00, "SOCKS5 reply should be success");

        c.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        c.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");
    }

    /// 回环防护：经由入站请求 FlowX 自身入站端口必须被拒绝，而不是无限自连
    #[tokio::test]
    async fn test_self_loop_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_addr = listener.local_addr().unwrap();
        let dispatcher = StreamDispatcher::new(test_config(inbound_addr, vec![]));
        let (_tx, rx) = watch::channel(false);
        tokio::spawn(async move { dispatcher.run(listener, rx).await });

        let mut c = TcpStream::connect(inbound_addr).await.unwrap();
        let req = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            inbound_addr.port(),
            inbound_addr.port()
        );
        c.write_all(req.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 128];
        let n = c.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 403"));
    }

    #[tokio::test]
    async fn test_http_forward_dispatcher_blocks_pipelined_smuggling_on_persistent_origin() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let (req_tx, req_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();

        tokio::spawn(async move {
            let (mut s, _) = origin.accept().await.unwrap();
            let mut got = Vec::new();
            s.read_to_end(&mut got).await.unwrap();
            let _ = req_tx.send(got);
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
                .await
                .unwrap();
            s.shutdown().await.unwrap();
        });

        let dispatcher = StreamDispatcher::new(test_config("127.0.0.1:0".parse().unwrap(), vec![]));
        let listener = dispatcher.bind().await.unwrap();
        let inbound_addr = listener.local_addr().unwrap();
        let (_tx, rx) = watch::channel(false);
        tokio::spawn(async move { dispatcher.run(listener, rx).await });

        let mut c = TcpStream::connect(inbound_addr).await.unwrap();
        let payload = format!(
            "GET http://127.0.0.1:{}/first HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\nGET http://127.0.0.1:{}/smuggled HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            origin_addr.port(),
            origin_addr.port(),
            origin_addr.port(),
            origin_addr.port(),
        );
        c.write_all(payload.as_bytes()).await.unwrap();

        let forwarded = req_rx.await.unwrap();
        let forwarded_str = String::from_utf8(forwarded).unwrap();
        assert!(forwarded_str.starts_with("GET /first HTTP/1.1\r\n"));
        assert!(forwarded_str.contains("Connection: close\r\n\r\n"));
        assert!(!forwarded_str.contains("/smuggled"));

        let mut resp = Vec::new();
        c.read_to_end(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).ends_with("done"));
    }
}
