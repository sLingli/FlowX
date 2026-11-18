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
use crate::interceptor::process::{ProcessInfo, ProcessTracker};
use crate::monitor::{ConnectionManager, InFlightTracker};
use crate::outbound::chain::{ProxyChain, ProxyNode};
use crate::outbound::direct::DirectOutbound;
use crate::outbound::{
    is_local_or_loopback_ip, local_interface_ips, relay_stream_monitored, RelayStream, TargetAddr,
};
use crate::router::{Action, RouteContext, RuleEngine};

/// 入站协议握手的最长等待时间（防止慢速握手占满并发名额）
const INBOUND_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 透明代理首包域名嗅探的最长等待时间（仅在规则需要域名或代理命中 HTTP/TLS 默认端口时启用，避免拖慢服务端先说话协议）
const TRANSPARENT_SNIFF_TIMEOUT: Duration = Duration::from_millis(120);

#[inline]
fn is_sniffable_default_port(port: u16) -> bool {
    matches!(port, 80 | 443 | 8080 | 8443)
}

#[derive(Debug, Clone)]
pub struct ProxyNodeEntry {
    pub id: u32,
    pub name: String,
    pub protocol: String,
    pub server_addr: String,
    pub username: Option<String>,
    pub client: ProxyNode,
}

impl ProxyNodeEntry {
    /// 判断节点认证是否已完整配置：SOCKS4 仅需 UserID，HTTP/SOCKS5 需用户名与密码成对存在
    pub fn is_auth_configured(&self) -> bool {
        if self.protocol == "SOCKS4" {
            self.username.is_some()
        } else {
            self.username.is_some() && self.client.auth_credentials().1.is_some()
        }
    }
}

/// 流量调度核心配置
#[derive(Clone)]
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
    /// 全局在途任务追踪器（供透明代理连接及异步子任务纳入优雅停机排空）
    pub in_flight: Option<Arc<InFlightTracker>>,
}

pub struct StreamDispatcher {
    config: Arc<DispatcherConfig>,
    concurrency_limit: Arc<Semaphore>,
    in_flight: Option<Arc<InFlightTracker>>,
}

impl StreamDispatcher {
    pub fn new(config: DispatcherConfig) -> Self {
        let in_flight = config.in_flight.clone();
        Self {
            config: Arc::new(config),
            concurrency_limit: Arc::new(Semaphore::new(10000)), // 最大并发连接保护
            in_flight,
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

struct DispatchSession {
    inbound_label: &'static str,
    inbound_kind: Option<inbound::InboundKind>,
    proc_info: Option<ProcessInfo>,
    display_target: TargetAddr,
    route_ip: Option<IpAddr>,
    dial_ip_on_direct: Option<SocketAddr>,
    pending: Vec<u8>,
    http_body_framing: Option<inbound::HttpBodyFraming>,
    body_prefix: Vec<u8>,
    http_is_head: bool,
}

async fn evaluate_and_relay_stream<S: RelayStream>(
    config: &DispatcherConfig,
    mut local_stream: S,
    session: DispatchSession,
) -> Result<()> {
    let proc_name = session
        .proc_info
        .as_ref()
        .map(|p| p.name.clone())
        .unwrap_or_else(|| crate::i18n::UNKNOWN_PROCESS.to_string());
    let proc_path = session
        .proc_info
        .as_ref()
        .map(|p| p.path.clone())
        .unwrap_or_else(|| crate::i18n::UNKNOWN_PROCESS.to_string());
    let pid = session.proc_info.as_ref().map(|p| p.pid).unwrap_or(0);

    // 5. Build route context and evaluate rules (`None` when process is unattributed so app rules like `*` or `*.exe` don't match "Unknown")
    let target_host = match &session.display_target {
        TargetAddr::Domain(host, _) => Some(host.as_str()),
        TargetAddr::Ip(_) => None,
    };
    let ctx = RouteContext {
        process_path: session.proc_info.as_ref().map(|p| p.path.as_str()),
        process_name: session.proc_info.as_ref().map(|p| p.name.as_str()),
        target_host,
        target_ip: session.route_ip,
        target_port: session.display_target.port(),
    };

    let (action, rule_name) = config.rule_engine.evaluate(&ctx);

    // 若透明代理面对真实 IP + 嗅探域名且最终命中的是 Direct，直接拨号原始真实 IP，避免多余的上游 DNS 解析开销
    let dial_target = match (&action, session.dial_ip_on_direct) {
        (Action::Direct, Some(real_addr)) => TargetAddr::Ip(real_addr),
        _ => session.display_target.clone(),
    };

    let action_str = match &action {
        Action::Direct => "Direct".to_string(),
        Action::Block => "Block".to_string(),
        Action::Proxy(id) => format!("Proxy({})", id),
        Action::Chain(id) => format!("Chain({})", id),
    };

    info!(
        "[Route Match] [{}] Process: {} (PID: {}) -> Target: {}:{} => Rule: {} => Action: {}",
        session.inbound_label,
        proc_name,
        pid,
        session.display_target.host_string(),
        session.display_target.port(),
        rule_name,
        action_str
    );

    // 6. 注册到连接监视器并使用 RAII 守卫
    // 注意：连接快照只保存机器可读的 action_type / action_id，展示文案由 API 层按请求语言本地化
    let active_conn = config.monitor.register(
        proc_name,
        proc_path,
        pid,
        session.display_target.to_authority_string(),
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
        if let Some(kind) = session.inbound_kind {
            inbound::send_failure(&mut local_stream, kind, true).await.ok();
        }
        return Ok(());
    }

    let cancel_token = Arc::clone(&active_conn);
    let mut remote_stream = tokio::select! {
        res = connect_outbound(config, &action, &dial_target) => {
            match res {
                Ok(s) => s,
                Err(e) => {
                    if let Some(kind) = session.inbound_kind {
                        inbound::send_failure(&mut local_stream, kind, false).await.ok();
                    }
                    return Err(e);
                }
            }
        }
        _ = cancel_token.cancelled() => {
            if let Some(kind) = session.inbound_kind {
                inbound::send_failure(&mut local_stream, kind, true).await.ok();
            }
            bail!("Connection aborted by administrator during establishment");
        }
    };

    // 8. Reply to client that tunnel is ready (explicit proxy protocols only), and forward buffered payload
    if let Some(kind) = session.inbound_kind {
        inbound::send_success(&mut local_stream, kind).await?;
    }
    if !session.pending.is_empty() {
        remote_stream.write_all(&session.pending).await?;
        active_conn.add_upload(session.pending.len() as u64);
    }

    // 9. Traffic relay (HTTP plain forward uses bounded request body framing; tunnel/transparent modes use full-duplex relay)
    let (up, down) = match (session.inbound_kind, session.http_body_framing) {
        (Some(inbound::InboundKind::HttpForward), Some(framing)) => {
            crate::outbound::relay_http_forward_monitored(
                local_stream,
                remote_stream,
                Some(&active_conn),
                framing,
                session.body_prefix,
                session.http_is_head,
            )
            .await?
        }
        _ => relay_stream_monitored(local_stream, remote_stream, Some(&active_conn)).await?,
    };
    info!(
        "[Relay Complete] [{}] {}:{} Upload: {} B, Download: {} B",
        action_str,
        session.display_target.host_string(),
        session.display_target.port(),
        up + session.pending.len() as u64,
        down
    );
    Ok(())
}

/// 透明代理 TCP 流统一调度入口：复用 PID 反查、Fake-IP 还原、按需 TLS SNI / HTTP Host 嗅探、
/// 规则求值、连接监视与全双工中继逻辑
pub async fn dispatch_transparent_stream<S: RelayStream>(
    config: Arc<DispatcherConfig>,
    mut local_stream: S,
    peer_addr: SocketAddr,
    orig_dst: SocketAddr,
    pid_hint: Option<u32>,
    needs_domain_sniff: bool,
) -> Result<()> {
    let _in_flight = config.in_flight.as_ref().map(|t| t.enter());

    // 1. 先检查原始目标是否指向 FlowX 自身监听端口，防止回环自连（无需额外等待嗅探）
    let raw_ip_target = TargetAddr::Ip(orig_dst);
    if is_self_target(&raw_ip_target, &config.bind_addr, &config.self_ports) {
        bail!(
            "Transparent loopback request rejected: peer {} attempted to access internal port {}",
            peer_addr,
            orig_dst
        );
    }

    // 2. 按驱动缓存的 PID 提示解析进程信息；若缺失或未命中则回退到四元组查表
    let proc_info = match pid_hint {
        Some(pid) => match config.tracker.resolve_pid_async(pid).await {
            Some(info) => Some(info),
            None => config.tracker.find_by_connection_async(peer_addr, orig_dst).await,
        },
        None => config.tracker.find_by_connection_async(peer_addr, orig_dst).await,
    };

    // 3. 若命中 Fake-IP 池直接还原域名；否则在规则需要或常见 HTTP/TLS 端口上非破坏性嗅探 SNI / Host
    let (display_target, route_ip, dial_ip_on_direct, pending) =
        if config.fake_ip_pool.is_fake_ip_addr(orig_dst.ip()) {
            let domain = config.fake_ip_pool.restore_ip(orig_dst.ip()).ok_or_else(|| {
                anyhow!("Fake-IP {} domain mapping expired or does not exist", orig_dst.ip())
            })?;
            let target = TargetAddr::Domain(domain, orig_dst.port());
            (target, None, None, Vec::new())
        } else {
            let domain_decision = config.rule_engine.needs_domain_for_routing(
                proc_info.as_ref().map(|p| p.path.as_str()),
                proc_info.as_ref().map(|p| p.name.as_str()),
                Some(orig_dst.ip()),
                orig_dst.port(),
            );
            let need_sniff = needs_domain_sniff
                || match domain_decision {
                    crate::router::DomainNeedDecision::NeedsDomainSniff => true,
                    crate::router::DomainNeedDecision::Immediate(
                        Action::Proxy(_) | Action::Chain(_),
                    ) => is_sniffable_default_port(orig_dst.port()),
                    crate::router::DomainNeedDecision::Immediate(
                        Action::Direct | Action::Block,
                    ) => false,
                };
            let (sniffed_host, buffered) = if need_sniff {
                let outcome = crate::transparent::sniffer::peek_host_prefix(
                    &mut local_stream,
                    TRANSPARENT_SNIFF_TIMEOUT,
                )
                .await?;
                (outcome.host, outcome.buffered)
            } else {
                (None, Vec::new())
            };
            match sniffed_host {
                Some(host) => (
                    TargetAddr::Domain(host, orig_dst.port()),
                    Some(orig_dst.ip()),
                    Some(orig_dst),
                    buffered,
                ),
                None => (
                    TargetAddr::Ip(orig_dst),
                    Some(orig_dst.ip()),
                    Some(orig_dst),
                    buffered,
                ),
            }
        };

    // 4. 域名还原或嗅探后再次校验是否指向自身服务端口（例如 Host: localhost:<api_port>）
    if is_self_target(&display_target, &config.bind_addr, &config.self_ports) {
        bail!(
            "Transparent loopback request rejected after target resolution: {}:{}",
            display_target.host_string(),
            display_target.port()
        );
    }

    evaluate_and_relay_stream(
        &config,
        local_stream,
        DispatchSession {
            inbound_label: "TRANSPARENT",
            inbound_kind: None,
            proc_info,
            display_target,
            route_ip,
            dial_ip_on_direct,
            pending,
            http_body_framing: None,
            body_prefix: Vec::new(),
            http_is_head: false,
        },
    )
    .await
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
        http_is_head,
    } = tokio::time::timeout(INBOUND_HANDSHAKE_TIMEOUT, inbound::read_request(&mut local_stream))
        .await
        .map_err(|_| anyhow!("Inbound handshake timed out ({:?}), peer {}", INBOUND_HANDSHAKE_TIMEOUT, peer_addr))??;

    // 2. Reverse lookup caller process via TCP 4-tuple (async non-blocking)
    let proc_info = config.tracker.find_by_connection_async(peer_addr, server_addr).await;
    let proc_name = proc_info
        .as_ref()
        .map(|p| p.name.clone())
        .unwrap_or_else(|| crate::i18n::UNKNOWN_PROCESS.to_string());
    let pid = proc_info.as_ref().map(|p| p.pid).unwrap_or(0);

    // 3. If target is Fake-IP (IPv4 or IPv4-mapped IPv6), restore original domain (prevent DNS leak, let upstream proxy resolve)
    let target = match &target {
        TargetAddr::Ip(addr) if config.fake_ip_pool.is_fake_ip_addr(addr.ip()) => {
            match config.fake_ip_pool.restore_ip(addr.ip()) {
                Some(domain) => TargetAddr::Domain(domain, addr.port()),
                None => {
                    inbound::send_failure(&mut local_stream, kind, false).await.ok();
                    bail!("Fake-IP {} domain mapping expired or does not exist", addr.ip());
                }
            }
        }
        _ => target,
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

    let route_ip = match &target {
        TargetAddr::Ip(addr) => Some(addr.ip()),
        TargetAddr::Domain(_, _) => None,
    };

    evaluate_and_relay_stream(
        &config,
        local_stream,
        DispatchSession {
            inbound_label: kind.as_str(),
            inbound_kind: Some(kind),
            proc_info,
            display_target: target,
            route_ip,
            dial_ip_on_direct: None,
            pending,
            http_body_framing,
            body_prefix,
            http_is_head,
        },
    )
    .await
}

async fn connect_outbound(
    config: &DispatcherConfig,
    action: &Action,
    target: &TargetAddr,
) -> Result<crate::outbound::OutboundTcpStream> {
    match action {
        Action::Block => bail!("Connection blocked by rule"),
        Action::Direct => {
            DirectOutbound::connect_guarded(
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
                    s.connect_with_policy_guarded(target, config.upstream_dns, pool, &config.self_ports)
                        .await
                }
                ProxyNode::Http(h) => {
                    h.connect_with_policy_guarded(target, config.upstream_dns, pool, &config.self_ports)
                        .await
                }
                ProxyNode::Socks4(s) => {
                    s.connect_with_policy_guarded(target, config.upstream_dns, pool, &config.self_ports)
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
                .connect_with_policy_guarded(
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
            in_flight: None,
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
            let mut buf = [0u8; 1024];
            loop {
                let n = s.read(&mut buf).await.unwrap();
                assert!(n > 0, "Origin received premature FIN before full request");
                got.extend_from_slice(&buf[..n]);
                if got.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            // Wait briefly: must receive NEITHER premature FIN (Ok(0)) NOR smuggled 2nd request bytes
            let probe = tokio::time::timeout(
                std::time::Duration::from_millis(80),
                s.read(&mut buf),
            )
            .await;
            assert!(
                probe.is_err(),
                "Origin expected neither premature EOF nor smuggled bytes, got: {:?}",
                probe
            );
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

    fn build_test_tls_client_hello(sni: &str) -> Vec<u8> {
        let host_bytes = sni.as_bytes();
        let sni_entry_len = 1 + 2 + host_bytes.len();
        let mut ext_sni = Vec::new();
        ext_sni.extend_from_slice(&0x0000u16.to_be_bytes());
        ext_sni.extend_from_slice(&((2 + sni_entry_len) as u16).to_be_bytes());
        ext_sni.extend_from_slice(&(sni_entry_len as u16).to_be_bytes());
        ext_sni.push(0x00);
        ext_sni.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        ext_sni.extend_from_slice(host_bytes);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(ext_sni.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_sni);

        let mut hs = Vec::new();
        hs.push(0x01);
        let hs_len = body.len() as u32;
        hs.extend_from_slice(&hs_len.to_be_bytes()[1..4]);
        hs.extend_from_slice(&body);

        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[tokio::test]
    async fn test_dispatch_transparent_stream_sniffs_sni_evaluates_rule_and_preserves_bytes() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let client_hello = build_test_tls_client_hello("sniffed.example.org");
        let expected_hello = client_hello.clone();

        let srv_task = tokio::spawn(async move {
            let (mut s, _) = origin.accept().await.unwrap();
            let mut got = vec![0u8; expected_hello.len()];
            s.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected_hello, "Original TLS ClientHello bytes must arrive intact");
            s.write_all(b"SERVER_OK").await.unwrap();
        });

        let mut cfg = test_config("127.0.0.1:40001".parse().unwrap(), vec![]);
        cfg.rule_engine = Arc::new(RuleEngine::new(
            vec![
                crate::router::Rule::from_raw(
                    "BlockOther",
                    true,
                    None,
                    Some("blocked.example.org"),
                    None,
                    Action::Block,
                ),
                crate::router::Rule::from_raw(
                    "AllowSniffedSni",
                    true,
                    None,
                    Some("sniffed.example.org"),
                    None,
                    Action::Direct,
                ),
            ],
            Action::Block,
        ));
        let cfg = Arc::new(cfg);

        let (mut app_side, disp_side) = tokio::io::duplex(8192);
        let peer_addr: SocketAddr = "127.0.0.1:55555".parse().unwrap();
        let disp_handle = tokio::spawn(async move {
            dispatch_transparent_stream(
                cfg,
                disp_side,
                peer_addr,
                origin_addr,
                None,
                true,
            )
            .await
        });

        app_side.write_all(&client_hello).await.unwrap();
        let mut ack = [0u8; 9];
        app_side.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"SERVER_OK");
        drop(app_side);

        disp_handle.await.unwrap().unwrap();
        srv_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_dispatch_transparent_stream_blocks_matched_rule() {
        let rules = vec![crate::router::Rule::from_raw(
            "BlockSniffed",
            true,
            None,
            Some("forbidden.example"),
            None,
            Action::Block,
        )];
        let cfg = Arc::new(test_config("127.0.0.1:40001".parse().unwrap(), rules));
        let orig_dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let (mut app_side, disp_side) = tokio::io::duplex(8192);
        let disp_handle = tokio::spawn(async move {
            dispatch_transparent_stream(
                cfg,
                disp_side,
                "127.0.0.1:55556".parse().unwrap(),
                orig_dst,
                None,
                true,
            )
            .await
        });

        let hello = build_test_tls_client_hello("forbidden.example");
        app_side.write_all(&hello).await.unwrap();
        let mut buf = [0u8; 32];
        let n = app_side.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "Blocked transparent flow must close without replying");
        disp_handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_dispatch_transparent_stream_restores_fake_ip_and_rejects_self_port() {
        let cfg = Arc::new(test_config("127.0.0.1:40001".parse().unwrap(), vec![]));
        let (_app_self, disp_self) = tokio::io::duplex(1024);
        let err = dispatch_transparent_stream(
            Arc::clone(&cfg),
            disp_self,
            "127.0.0.1:50000".parse().unwrap(),
            "127.0.0.1:40001".parse().unwrap(),
            None,
            false,
        )
        .await
        .unwrap_err();
        assert!(format!("{:#}", err).contains("loopback"));

        // Fake-IP domain without explicit port or expired should error cleanly; valid Fake-IP resolves & dials localhost test server?
        // Actually localhost rule check + expired Fake-IP error verifies Fake-IP branch without needing an external DNS server:
        let (_app_fake, disp_fake) = tokio::io::duplex(1024);
        let fake_err = dispatch_transparent_stream(
            Arc::clone(&cfg),
            disp_fake,
            "127.0.0.1:50001".parse().unwrap(),
            "198.18.0.55:443".parse().unwrap(),
            None,
            false,
        )
        .await
        .unwrap_err();
        assert!(format!("{:#}", fake_err).contains("Fake-IP"));

        // Mapped Fake-IP restores original domain and matches domain rules directly without sniffing
        let mapped_ip = cfg.fake_ip_pool.allocate("fakeip-blocked.example");
        let mut mapped_cfg = test_config(
            "127.0.0.1:40001".parse().unwrap(),
            vec![crate::router::Rule::from_raw(
                "BlockRestoredFakeIp",
                true,
                None,
                Some("fakeip-blocked.example"),
                None,
                Action::Block,
            )],
        );
        mapped_cfg.fake_ip_pool = Arc::clone(&cfg.fake_ip_pool);
        let (mut app_mapped, disp_mapped) = tokio::io::duplex(1024);
        let mapped_res = dispatch_transparent_stream(
            Arc::new(mapped_cfg),
            disp_mapped,
            "127.0.0.1:50002".parse().unwrap(),
            SocketAddr::new(std::net::IpAddr::V4(mapped_ip), 443),
            None,
            true,
        )
        .await;
        assert!(mapped_res.is_ok(), "Fake-IP domain restore should trigger Action::Block cleanly");
        let mut probe = [0u8; 8];
        assert_eq!(app_mapped.read(&mut probe).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_dispatch_transparent_stream_skips_sniff_when_immediate_on_443() {
        // 服务器等待客户端主动发首字节（不会先发 banner）：若触发 120ms 嗅探则会明显拖延首包或消费超时，
        // 这里使用 Immediate(Proxy/Direct) + 沉默服务端 + 明确发首字节前的 Immediate 直连延迟检测：
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let srv_task = tokio::spawn(async move {
            let (mut s, _) = origin.accept().await.unwrap();
            // 服务端先发送二进制协议 banner：若 dispatcher 在 443 上错误等待客户端先发 SNI，将死锁满 120ms
            s.write_all(b"SRV_BANNER").await.unwrap();
            let mut ack = [0u8; 6];
            s.read_exact(&mut ack).await.unwrap();
            assert_eq!(&ack, b"CLI_OK");
        });

        let mut cfg = test_config(
            "127.0.0.1:40001".parse().unwrap(),
            vec![crate::router::Rule::from_raw(
                "BypassPort443",
                true,
                None,
                None,
                None,
                Action::Direct,
            )],
        );
        cfg.fake_ip_pool = Arc::new(FakeIpPool::new_default());
        let (mut app_side, disp_side) = tokio::io::duplex(4096);
        // 即使源目标端口是 443，只要 needs_domain_sniff=false 且 rule_engine 返回 Immediate，也不得阻塞等待客户端先发 SNI
        let fake_dst_443 = SocketAddr::new(origin_addr.ip(), 443);
        let _ = fake_dst_443;
        let disp_handle = tokio::spawn(async move {
            dispatch_transparent_stream(
                Arc::new(cfg),
                disp_side,
                "127.0.0.1:50099".parse().unwrap(),
                origin_addr,
                None,
                false,
            )
            .await
        });

        let mut banner = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(2), app_side.read_exact(&mut banner))
            .await
            .expect("Immediate route must forward server banner without awaiting client SNI")
            .unwrap();
        assert_eq!(&banner, b"SRV_BANNER");
        app_side.write_all(b"CLI_OK").await.unwrap();
        drop(app_side);
        disp_handle.await.unwrap().unwrap();
        srv_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_dispatch_transparent_stream_sniffs_http_tls_for_immediate_proxy_skips_other_ports() {
        use crate::outbound::socks5::Socks5Client;

        async fn spawn_mock_socks5_server(
            expect_banner: Option<&'static [u8]>,
        ) -> (SocketAddr, tokio::sync::oneshot::Receiver<(u8, String, u16)>, tokio::task::JoinHandle<()>)
        {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (target_tx, target_rx) = tokio::sync::oneshot::channel();
            let handle = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut greeting = [0u8; 3];
                s.read_exact(&mut greeting).await.unwrap();
                s.write_all(&[0x05, 0x00]).await.unwrap();

                let mut hdr = [0u8; 4];
                s.read_exact(&mut hdr).await.unwrap();
                let atyp = hdr[3];
                let host = match atyp {
                    0x01 => {
                        let mut ip = [0u8; 4];
                        s.read_exact(&mut ip).await.unwrap();
                        std::net::Ipv4Addr::from(ip).to_string()
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        s.read_exact(&mut len).await.unwrap();
                        let mut dom = vec![0u8; len[0] as usize];
                        s.read_exact(&mut dom).await.unwrap();
                        String::from_utf8(dom).unwrap()
                    }
                    other => panic!("unexpected SOCKS5 atyp: {other}"),
                };
                let mut port_bytes = [0u8; 2];
                s.read_exact(&mut port_bytes).await.unwrap();
                let port = u16::from_be_bytes(port_bytes);
                let _ = target_tx.send((atyp, host, port));

                s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                    .await
                    .unwrap();
                if let Some(banner) = expect_banner {
                    s.write_all(banner).await.unwrap();
                } else {
                    let mut buf = [0u8; 256];
                    let n = s.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    s.write_all(b"PROXIED_TLS_OK").await.unwrap();
                }
            });
            (addr, target_rx, handle)
        }

        // 1. DevProxy-style Immediate(Proxy) on port 443 -> must sniff TLS SNI and pass ATYP 0x03 Domain to proxy
        let (socks_addr_443, target_rx_443, srv_443) = spawn_mock_socks5_server(None).await;
        let cfg_443 = test_config(
            "127.0.0.1:40001".parse().unwrap(),
            vec![crate::router::Rule::from_raw(
                "DevProxy",
                true,
                None,
                None,
                None,
                Action::Proxy(1),
            )],
        );
        cfg_443.proxy_nodes.write().unwrap().insert(
            1,
            ProxyNodeEntry {
                id: 1,
                name: "MockSocks".into(),
                protocol: "SOCKS5".into(),
                server_addr: socks_addr_443.to_string(),
                username: None,
                client: ProxyNode::Socks5(Socks5Client::new(socks_addr_443.to_string())),
            },
        );
        let (mut app_443, disp_443) = tokio::io::duplex(8192);
        let handle_443 = tokio::spawn(async move {
            dispatch_transparent_stream(
                Arc::new(cfg_443),
                disp_443,
                "127.0.0.1:50100".parse().unwrap(),
                "93.184.216.34:443".parse().unwrap(),
                None,
                false,
            )
            .await
        });
        let hello = build_test_tls_client_hello("api.github.com");
        app_443.write_all(&hello).await.unwrap();
        let (atyp_443, host_443, port_443) = target_rx_443.await.unwrap();
        assert_eq!(atyp_443, 0x03, "port 443 Immediate(Proxy) must sniff SNI as domain");
        assert_eq!(host_443, "api.github.com");
        assert_eq!(port_443, 443);
        let mut ack_443 = [0u8; 14];
        app_443.read_exact(&mut ack_443).await.unwrap();
        assert_eq!(&ack_443, b"PROXIED_TLS_OK");
        drop(app_443);
        handle_443.await.unwrap().unwrap();
        srv_443.await.unwrap();

        // 2. Immediate(Proxy) on port 22 (SSH) -> must NOT wait 120ms for client-first sniff; connects immediately
        let (socks_addr_22, target_rx_22, srv_22) =
            spawn_mock_socks5_server(Some(b"SSH-2.0-OpenSSH")).await;
        let cfg_22 = test_config(
            "127.0.0.1:40001".parse().unwrap(),
            vec![crate::router::Rule::from_raw(
                "DevProxy",
                true,
                None,
                None,
                None,
                Action::Proxy(1),
            )],
        );
        cfg_22.proxy_nodes.write().unwrap().insert(
            1,
            ProxyNodeEntry {
                id: 1,
                name: "MockSocks".into(),
                protocol: "SOCKS5".into(),
                server_addr: socks_addr_22.to_string(),
                username: None,
                client: ProxyNode::Socks5(Socks5Client::new(socks_addr_22.to_string())),
            },
        );
        let (mut app_22, disp_22) = tokio::io::duplex(4096);
        let handle_22 = tokio::spawn(async move {
            dispatch_transparent_stream(
                Arc::new(cfg_22),
                disp_22,
                "127.0.0.1:50101".parse().unwrap(),
                "93.184.216.34:22".parse().unwrap(),
                None,
                false,
            )
            .await
        });
        let mut ssh_banner = [0u8; 15];
        tokio::time::timeout(Duration::from_secs(2), app_22.read_exact(&mut ssh_banner))
            .await
            .expect("Port 22 Immediate(Proxy) must forward SSH server banner without sniffing delay")
            .unwrap();
        assert_eq!(&ssh_banner, b"SSH-2.0-OpenSSH");
        let (atyp_22, host_22, port_22) = target_rx_22.await.unwrap();
        assert_eq!(atyp_22, 0x01);
        assert_eq!(host_22, "93.184.216.34");
        assert_eq!(port_22, 22);
        drop(app_22);
        handle_22.await.unwrap().unwrap();
        srv_22.await.unwrap();
    }

    #[tokio::test]
    async fn test_dispatch_transparent_stream_tracks_in_flight_guard() {
        let tracker = Arc::new(InFlightTracker::new());
        let mut cfg = test_config(
            "127.0.0.1:40001".parse().unwrap(),
            vec![crate::router::Rule::from_raw(
                "NeedSniProxy",
                true,
                None,
                Some("track.example.org"),
                None,
                Action::Block,
            )],
        );
        cfg.in_flight = Some(Arc::clone(&tracker));
        let cfg = Arc::new(cfg);

        assert_eq!(tracker.count(), 0);
        let (mut app_side, disp_side) = tokio::io::duplex(4096);
        let tracker_wait = Arc::clone(&tracker);
        let disp_handle = tokio::spawn(async move {
            dispatch_transparent_stream(
                cfg,
                disp_side,
                "127.0.0.1:50120".parse().unwrap(),
                "93.184.216.34:443".parse().unwrap(),
                None,
                true,
            )
            .await
        });

        // 在透明流进入 SNI 嗅探阻塞阶段时（尚未注册进 ConnectionManager），InFlightTracker 必须已计数 > 0
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            tracker.count() >= 1,
            "transparent dispatch must hold InFlightTracker guard while sniffing"
        );

        let hello = build_test_tls_client_hello("track.example.org");
        app_side.write_all(&hello).await.unwrap();
        let mut eof_buf = [0u8; 8];
        assert_eq!(app_side.read(&mut eof_buf).await.unwrap(), 0);
        drop(app_side);

        disp_handle.await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(2), tracker_wait.wait_zero())
            .await
            .expect("InFlightTracker must drain to zero after transparent stream finishes");
        assert_eq!(tracker.count(), 0);
    }
}
