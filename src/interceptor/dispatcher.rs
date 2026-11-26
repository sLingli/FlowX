use anyhow::{Context, Result, anyhow, bail};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tracing::{error, info, warn};

use crate::dns::FakeIpPool;
use crate::inbound::{self, InboundRequest};
use crate::interceptor::process::{ProcessInfo, ProcessTracker};
use crate::monitor::{ConnectionManager, InFlightTracker};
use crate::outbound::chain::{ProxyChain, ProxyNode};
use crate::outbound::direct::DirectOutbound;
use crate::outbound::{
    RelayStream, TargetAddr, is_local_or_loopback_ip, local_interface_ips, relay_stream_monitored,
};
use crate::router::{Action, RouteContext, RuleEngine};

/// 入站协议握手的最长等待时间（防止慢速握手占满并发名额）
const INBOUND_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 透明代理首包域名嗅探的最长等待时间（用于规则依赖域名或常见 HTTP/TLS 端口）
const TRANSPARENT_SNIFF_TIMEOUT: Duration = Duration::from_millis(120);
/// `Immediate(Proxy | Chain)` 在非常见 HTTP/TLS 端口上的机会式嗅探短超时（本地客户端先发 TLS/HTTP 通常 < 2ms，
/// 同时将未知自定义服务端先发端口的探测成本压低至 25ms，连续超时达阈值后按指数退避学习并支持半开探测恢复）
const TRANSPARENT_OPPORTUNISTIC_SNIFF_TIMEOUT: Duration = Duration::from_millis(25);
const SERVER_FIRST_LEARN_THRESHOLD: u8 = 2;
const SERVER_FIRST_CANDIDATE_TTL: Duration = Duration::from_secs(30);
const SERVER_FIRST_CACHE_TTL: Duration = Duration::from_secs(300);
const SERVER_FIRST_CACHE_MAX_ENTRIES: usize = 1024;

/// 严格标准服务端先发协议端口（FTP/SSH/Telnet/SMTP/POP3/IMAP/Submission/MySQL/VNC）：始终跳过首包嗅探
#[inline]
fn is_strict_server_first_port(port: u16) -> bool {
    matches!(port, 21 | 22 | 23 | 25 | 110 | 143 | 587 | 3306 | 5900)
}

/// 常见非标准服务端先发备选端口（如 SSH 2222 / SMTP 2525 / MySQL 3307 / VNC 5901..5909）：
/// 仅在无需域名的机会式嗅探中跳过，避免阻断 `NeedsDomainSniff` 域名规则（如 2222 上的 HTTPS/管理面板）
#[inline]
fn is_alt_server_first_port(port: u16) -> bool {
    matches!(port, 2222 | 2525 | 3307 | 5901..=5909)
}

#[inline]
fn is_common_http_tls_port(port: u16) -> bool {
    matches!(
        port,
        80 | 443
            | 2052
            | 2053
            | 2082
            | 2083
            | 2086
            | 2087
            | 2095
            | 2096
            | 3000
            | 3001
            | 5000
            | 5173
            | 8000
            | 8008
            | 8080
            | 8443
            | 8444
            | 8888
            | 9000
            | 9090
            | 9443
    )
}

#[derive(Debug, Clone, Copy)]
struct ServerFirstEntry {
    consecutive_timeouts: u8,
    next_probe_at: Instant,
    expires_at: Instant,
}

fn server_first_backoff(consecutive_timeouts: u8) -> (Duration, Duration) {
    match consecutive_timeouts {
        0..=1 => (Duration::ZERO, SERVER_FIRST_CANDIDATE_TTL),
        2 => (Duration::from_secs(15), Duration::from_secs(60)),
        3 => (Duration::from_secs(60), Duration::from_secs(180)),
        _ => (Duration::from_secs(120), SERVER_FIRST_CACHE_TTL),
    }
}

fn server_first_endpoint_cache() -> &'static Mutex<HashMap<(IpAddr, u16), ServerFirstEntry>> {
    static CACHE: OnceLock<Mutex<HashMap<(IpAddr, u16), ServerFirstEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 判断是否应跳过当前端点的机会式嗅探：
/// - 连续超时未达 `SERVER_FIRST_LEARN_THRESHOLD`（2 次）时不跳过，防止单次慢启动/预连接误封；
/// - 超过 `next_probe_at` 时原子放行单次半开探测（并推进下一次探测时间防并发惊群），使 `clear_server_first_endpoint` 真正可达。
fn should_skip_opportunistic_sniff_at(key: (IpAddr, u16), now: Instant) -> bool {
    let mut map = server_first_endpoint_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let Some(entry) = map.get_mut(&key) else {
        return false;
    };
    if entry.expires_at <= now {
        map.remove(&key);
        return false;
    }
    if entry.consecutive_timeouts < SERVER_FIRST_LEARN_THRESHOLD {
        return false;
    }
    if now >= entry.next_probe_at {
        let (probe_wait, _) = server_first_backoff(entry.consecutive_timeouts);
        entry.next_probe_at = now + probe_wait;
        return false;
    }
    true
}

fn should_skip_opportunistic_sniff(key: (IpAddr, u16)) -> bool {
    should_skip_opportunistic_sniff_at(key, Instant::now())
}

fn record_server_first_endpoint_at(key: (IpAddr, u16), now: Instant) {
    let mut map = server_first_endpoint_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let next_count = map
        .get(&key)
        .filter(|e| e.expires_at > now)
        .map_or(1, |e| e.consecutive_timeouts.saturating_add(1));
    let (probe_wait, ttl) = server_first_backoff(next_count);
    let entry = ServerFirstEntry {
        consecutive_timeouts: next_count,
        next_probe_at: now + probe_wait,
        expires_at: now + ttl,
    };
    if map.len() >= SERVER_FIRST_CACHE_MAX_ENTRIES && !map.contains_key(&key) {
        map.retain(|_, e| e.expires_at > now);
        if map.len() >= SERVER_FIRST_CACHE_MAX_ENTRIES
            && let Some(oldest) = map
                .iter()
                .min_by_key(|(_, e)| e.expires_at)
                .map(|(k, _)| *k)
        {
            map.remove(&oldest);
        }
    }
    map.insert(key, entry);
}

fn record_server_first_endpoint(key: (IpAddr, u16)) {
    record_server_first_endpoint_at(key, Instant::now());
}

fn clear_server_first_endpoint(key: (IpAddr, u16)) {
    let mut map = server_first_endpoint_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    map.remove(&key);
}

pub(crate) fn clear_server_first_endpoint_cache() {
    let mut map = server_first_endpoint_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    map.clear();
}

fn is_spoofed_local_hostname(host: &str, orig_dst_ip: IpAddr) -> bool {
    let local_hostname = crate::router::parser::resolve_local_hostname();
    let norm = host.trim().trim_end_matches('.');
    let claims_local = crate::outbound::is_loopback_domain(host)
        || (!local_hostname.is_empty()
            && norm.eq_ignore_ascii_case(local_hostname.trim_end_matches('.')));
    if !claims_local {
        return false;
    }
    let local_ips = local_interface_ips();
    !is_local_or_loopback_ip(orig_dst_ip, &local_ips)
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
            .with_context(|| {
                format!(
                    "Failed to bind mixed inbound port ({})",
                    self.config.bind_addr
                )
            })?;
        info!(
            "[Dispatcher] Mixed proxy inbound (SOCKS5 / SOCKS4a / HTTP) bound on {}",
            self.config.bind_addr
        );
        Ok(listener)
    }

    /// 启动本地入站连接调度监听服务（支持优雅停机）
    pub async fn run(
        &self,
        listener: TcpListener,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<()> {
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
                    warn!(
                        "[Dispatcher] Active connections exceeded limit (10000), rejecting new connection"
                    );
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

#[derive(Debug, Clone, Copy)]
enum DialTargetPolicy {
    /// 始终使用 `display_target` 拨号（显式代理入站 / Fake-IP 还原域名）
    UseDisplayTarget,
    /// 权威嗅探域名（TLS SNI / HTTP Host）：Direct 走真实 IP 免二次解析，Proxy/Chain 传域名由上游代理远程解析
    IpOnDirectDomainOnProxy(SocketAddr),
    /// 被动 DNS 缓存反查的唯一域名（启发式）：用于规则域名匹配与展示，但所有出站拨号一律使用原始真实 IP，
    /// 防止共享 CDN/DoH/裸 IP 场景下把错误域名发给上游代理服务器
    AlwaysUseRealIp(SocketAddr),
}

struct DispatchSession {
    inbound_label: &'static str,
    inbound_kind: Option<inbound::InboundKind>,
    proc_info: Option<ProcessInfo>,
    display_target: TargetAddr,
    route_ip: Option<IpAddr>,
    dial_policy: DialTargetPolicy,
    direct_dns_overrides: Vec<SocketAddr>,
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

    // 依据域名来源策略选择实际拨号目标：
    // - 权威嗅探（SNI/Host）在 Direct 时直连原始真实 IP，Proxy/Chain 时提交域名远程解析；
    // - 被动 DNS 缓存启发式域名一律按原始真实 IP 拨号，避免共享 IP/裸 IP 误发错误域名给远端代理。
    let dial_target = match (&action, session.dial_policy) {
        (Action::Direct, DialTargetPolicy::IpOnDirectDomainOnProxy(real_addr))
        | (_, DialTargetPolicy::AlwaysUseRealIp(real_addr)) => TargetAddr::Ip(real_addr),
        _ => session.display_target.clone(),
    };

    let action_str = match &action {
        Action::Direct => "Direct".to_string(),
        Action::Block => "Block".to_string(),
        Action::Proxy(id) => format!("Proxy({})", id),
        Action::Chain(id) => format!("Chain({})", id),
    };

    if dial_target != session.display_target {
        info!(
            "[Route Match] [{}] Process: {} (PID: {}) -> Target: {}:{} (Dial: {}) => Rule: {} => Action: {}",
            session.inbound_label,
            proc_name,
            pid,
            session.display_target.host_string(),
            session.display_target.port(),
            dial_target.to_authority_string(),
            rule_name,
            action_str
        );
    } else {
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
    }

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
            inbound::send_failure(&mut local_stream, kind, true)
                .await
                .ok();
        }
        return Ok(());
    }

    let cancel_token = Arc::clone(&active_conn);
    let mut remote_stream = tokio::select! {
        res = connect_outbound(config, &action, &dial_target, &session.direct_dns_overrides) => {
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
    if dial_target != session.display_target {
        info!(
            "[Relay Complete] [{}] {}:{} (Dial: {}) Upload: {} B, Download: {} B",
            action_str,
            session.display_target.host_string(),
            session.display_target.port(),
            dial_target.to_authority_string(),
            up + session.pending.len() as u64,
            down
        );
    } else {
        info!(
            "[Relay Complete] [{}] {}:{} Upload: {} B, Download: {} B",
            action_str,
            session.display_target.host_string(),
            session.display_target.port(),
            up + session.pending.len() as u64,
            down
        );
    }
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
    _needs_domain_sniff: bool,
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
            None => {
                config
                    .tracker
                    .find_by_connection_async(peer_addr, orig_dst)
                    .await
            }
        },
        None => {
            config
                .tracker
                .find_by_connection_async(peer_addr, orig_dst)
                .await
        }
    };

    // 3. 若命中 Fake-IP 池直接还原域名与原始上游 DNS；否则优先按需嗅探 TLS SNI / HTTP Host，仅在无嗅探结果时回退至唯一被动 DNS 映射
    let (display_target, route_ip, dial_policy, direct_dns_overrides, pending) =
        if config.fake_ip_pool.is_fake_ip_addr(orig_dst.ip()) {
            let (domain, orig_dns_list) = config
                .fake_ip_pool
                .restore_ip_with_dns_list(orig_dst.ip())
                .ok_or_else(|| {
                    anyhow!(
                        "Fake-IP {} domain mapping expired or does not exist",
                        orig_dst.ip()
                    )
                })?;
            let target = TargetAddr::Domain(domain, orig_dst.port());
            (
                target,
                None,
                DialTargetPolicy::UseDisplayTarget,
                orig_dns_list,
                Vec::new(),
            )
        } else {
            let cached_domain = config.fake_ip_pool.lookup_real_ip_domain(orig_dst.ip());
            // 异步补全进程归属后重新做权威判定，避免 SYN 期因 PID 未就绪残留的过期 needs_domain_sniff
            // 覆盖已确定的 Immediate(Direct | Block)，同时在 Immediate(Proxy | Chain) 下对所有非服务端先发端口
            // （含 8444/9443/2083/3000 等非标准 HTTPS/HTTP 端口）均尝试 TLS SNI / HTTP Host 嗅探。
            let domain_decision = config.rule_engine.needs_domain_for_routing(
                proc_info.as_ref().map(|p| p.path.as_str()),
                proc_info.as_ref().map(|p| p.name.as_str()),
                Some(orig_dst.ip()),
                orig_dst.port(),
            );
            let (want_sniff, opportunistic_sniff) = match domain_decision {
                crate::router::DomainNeedDecision::NeedsDomainSniff => (true, false),
                crate::router::DomainNeedDecision::Immediate(
                    Action::Proxy(_) | Action::Chain(_),
                ) => (true, !is_common_http_tls_port(orig_dst.port())),
                crate::router::DomainNeedDecision::Immediate(Action::Direct | Action::Block) => {
                    (false, false)
                }
            };
            let ep_key = (orig_dst.ip().to_canonical(), orig_dst.port());
            let skip_alt_server_first =
                opportunistic_sniff && is_alt_server_first_port(orig_dst.port());
            let skip_learned_server_first =
                opportunistic_sniff && should_skip_opportunistic_sniff(ep_key);
            // 除已知服务端先发协议端口与已学习的自定义服务端先发端点外，绝不因被动缓存域名或非标准端口跳过权威嗅探
            let need_sniff = want_sniff
                && !is_strict_server_first_port(orig_dst.port())
                && !skip_alt_server_first
                && !skip_learned_server_first;
            let sniff_timeout = if opportunistic_sniff {
                TRANSPARENT_OPPORTUNISTIC_SNIFF_TIMEOUT
            } else {
                TRANSPARENT_SNIFF_TIMEOUT
            };
            let (sniffed_host, buffered) = if need_sniff {
                let outcome =
                    crate::transparent::sniffer::peek_host_prefix(&mut local_stream, sniff_timeout)
                        .await?;
                if opportunistic_sniff {
                    if outcome.timed_out && outcome.buffered.is_empty() {
                        record_server_first_endpoint(ep_key);
                    } else if !outcome.buffered.is_empty() {
                        clear_server_first_endpoint(ep_key);
                    }
                }
                let host = outcome.host.filter(|h| {
                    if is_spoofed_local_hostname(h, orig_dst.ip()) {
                        warn!(
                            orig_dst = %orig_dst,
                            spoofed_host = %h,
                            "Ignored spoofed local hostname on remote destination IP"
                        );
                        false
                    } else {
                        true
                    }
                });
                (host, outcome.buffered)
            } else {
                (None, Vec::new())
            };
            match (sniffed_host, cached_domain) {
                (Some(host), _) => (
                    TargetAddr::Domain(host, orig_dst.port()),
                    Some(orig_dst.ip()),
                    DialTargetPolicy::IpOnDirectDomainOnProxy(orig_dst),
                    Vec::new(),
                    buffered,
                ),
                (None, Some(host)) => (
                    TargetAddr::Domain(host, orig_dst.port()),
                    Some(orig_dst.ip()),
                    DialTargetPolicy::AlwaysUseRealIp(orig_dst),
                    Vec::new(),
                    buffered,
                ),
                (None, None) => (
                    TargetAddr::Ip(orig_dst),
                    Some(orig_dst.ip()),
                    DialTargetPolicy::UseDisplayTarget,
                    Vec::new(),
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
            dial_policy,
            direct_dns_overrides,
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
    } = tokio::time::timeout(
        INBOUND_HANDSHAKE_TIMEOUT,
        inbound::read_request(&mut local_stream),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "Inbound handshake timed out ({:?}), peer {}",
            INBOUND_HANDSHAKE_TIMEOUT,
            peer_addr
        )
    })??;

    // 2. Reverse lookup caller process via TCP 4-tuple (async non-blocking)
    let proc_info = config
        .tracker
        .find_by_connection_async(peer_addr, server_addr)
        .await;
    let proc_name = proc_info
        .as_ref()
        .map(|p| p.name.clone())
        .unwrap_or_else(|| crate::i18n::UNKNOWN_PROCESS.to_string());
    let pid = proc_info.as_ref().map(|p| p.pid).unwrap_or(0);

    // 3. If target is Fake-IP (IPv4 or IPv4-mapped IPv6), restore original domain (prevent DNS leak, let upstream proxy resolve)
    let (target, direct_dns_overrides) = match &target {
        TargetAddr::Ip(addr) if config.fake_ip_pool.is_fake_ip_addr(addr.ip()) => {
            match config.fake_ip_pool.restore_ip_with_dns_list(addr.ip()) {
                Some((domain, orig_dns_list)) => {
                    (TargetAddr::Domain(domain, addr.port()), orig_dns_list)
                }
                None => {
                    inbound::send_failure(&mut local_stream, kind, false)
                        .await
                        .ok();
                    bail!(
                        "Fake-IP {} domain mapping expired or does not exist",
                        addr.ip()
                    );
                }
            }
        }
        _ => (target, Vec::new()),
    };

    // 4. Loop prevention: reject requests targeting FlowX internal service ports
    if is_self_target(&target, &server_addr, &config.self_ports) {
        inbound::send_failure(&mut local_stream, kind, true)
            .await
            .ok();
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
            dial_policy: DialTargetPolicy::UseDisplayTarget,
            direct_dns_overrides,
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
    direct_dns_overrides: &[SocketAddr],
) -> Result<crate::outbound::OutboundTcpStream> {
    match action {
        Action::Block => bail!("Connection blocked by rule"),
        Action::Direct => {
            DirectOutbound::connect_guarded_with_dns_candidates(
                target,
                config.upstream_dns,
                direct_dns_overrides,
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
                    s.connect_with_policy_guarded(
                        target,
                        config.upstream_dns,
                        pool,
                        &config.self_ports,
                    )
                    .await
                }
                ProxyNode::Http(h) => {
                    h.connect_with_policy_guarded(
                        target,
                        config.upstream_dns,
                        pool,
                        &config.self_ports,
                    )
                    .await
                }
                ProxyNode::Socks4(s) => {
                    s.connect_with_policy_guarded(
                        target,
                        config.upstream_dns,
                        pool,
                        &config.self_ports,
                    )
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
        assert!(is_self_target(
            &TargetAddr::Ip("127.0.0.1:40001".parse().unwrap()),
            &server,
            &ports
        ));
        assert!(is_self_target(
            &TargetAddr::Ip("0.0.0.0:40080".parse().unwrap()),
            &server,
            &ports
        ));
        assert!(is_self_target(
            &TargetAddr::Domain("LocalHost".into(), 40080),
            &server,
            &ports
        ));
        assert!(!is_self_target(
            &TargetAddr::Ip("127.0.0.1:8080".parse().unwrap()),
            &server,
            &ports
        ));
        assert!(!is_self_target(
            &TargetAddr::Domain("example.com".into(), 40001),
            &server,
            &ports
        ));
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
    async fn test_p2_3_immediate_proxy_avoids_120ms_stall_on_alt_and_custom_server_first_ports_while_sniffing_custom_https()
     {
        use crate::outbound::socks5::Socks5Client;
        use tokio::io::AsyncReadExt;

        let make_devproxy_cfg = |socks_addr: SocketAddr| {
            let cfg = test_config(
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
            cfg.proxy_nodes.write().unwrap().insert(
                1,
                ProxyNodeEntry {
                    id: 1,
                    name: "MockSocks".into(),
                    protocol: "SOCKS5".into(),
                    server_addr: socks_addr.to_string(),
                    username: None,
                    client: ProxyNode::Socks5(Socks5Client::new(socks_addr.to_string())),
                },
            );
            Arc::new(cfg)
        };

        // 1. 常见非标准服务端先发端口（SSH 2222 / MySQL 3307 / VNC 5901）：首连即零等待直吐 banner
        for port in [2222u16, 3307u16, 5901u16] {
            let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let socks_addr = socks.local_addr().unwrap();
            let srv = tokio::spawn(async move {
                let (mut s, _) = socks.accept().await.unwrap();
                let mut g = [0u8; 3];
                s.read_exact(&mut g).await.unwrap();
                s.write_all(&[0x05, 0x00]).await.unwrap();
                let mut req = [0u8; 10];
                s.read_exact(&mut req).await.unwrap();
                assert_eq!(req[3], 0x01);
                s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                    .await
                    .unwrap();
                s.write_all(b"SRV_BANNER_FAST").await.unwrap();
            });
            let cfg = make_devproxy_cfg(socks_addr);
            let (mut app, disp) = tokio::io::duplex(1024);
            let started = std::time::Instant::now();
            let handle = tokio::spawn(async move {
                dispatch_transparent_stream(
                    cfg,
                    disp,
                    "127.0.0.1:50501".parse().unwrap(),
                    SocketAddr::new("93.184.216.95".parse().unwrap(), port),
                    None,
                    false,
                )
                .await
            });
            let mut banner = [0u8; 15];
            app.read_exact(&mut banner).await.unwrap();
            assert!(is_alt_server_first_port(port));
            assert_eq!(&banner, b"SRV_BANNER_FAST");
            assert!(
                started.elapsed() < Duration::from_millis(500),
                "alt server-first port {} must skip sniff without stalling, took {:?}",
                port,
                started.elapsed()
            );
            drop(app);
            handle.await.unwrap().unwrap();
            srv.await.unwrap();
        }

        // 2. 任意自定义服务端先发端口（如 22022）：需连续 2 次 25ms 静默超时才进入退避跳过（防单次慢启动误封），
        //    第 3 次起零延迟跳过嗅探
        let custom_ep = SocketAddr::new("93.184.216.96".parse().unwrap(), 22022);
        let custom_key = (custom_ep.ip(), custom_ep.port());
        clear_server_first_endpoint(custom_key);
        let socks_c = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_c_addr = socks_c.local_addr().unwrap();
        let srv_c = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut s, _) = socks_c.accept().await.unwrap();
                let mut g = [0u8; 3];
                s.read_exact(&mut g).await.unwrap();
                s.write_all(&[0x05, 0x00]).await.unwrap();
                let mut req = [0u8; 10];
                s.read_exact(&mut req).await.unwrap();
                s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                    .await
                    .unwrap();
                s.write_all(b"SSH-2.0-Custom22022").await.unwrap();
            }
        });
        let cfg_c = make_devproxy_cfg(socks_c_addr);
        for attempt in 0..3 {
            let (mut app, disp) = tokio::io::duplex(1024);
            let cfg_clone = Arc::clone(&cfg_c);
            let started = std::time::Instant::now();
            let handle = tokio::spawn(async move {
                dispatch_transparent_stream(
                    cfg_clone,
                    disp,
                    "127.0.0.1:50502".parse().unwrap(),
                    custom_ep,
                    None,
                    false,
                )
                .await
            });
            let mut banner = [0u8; 19];
            app.read_exact(&mut banner).await.unwrap();
            assert_eq!(&banner, b"SSH-2.0-Custom22022");
            let elapsed = started.elapsed();
            if attempt == 0 {
                assert!(
                    !should_skip_opportunistic_sniff_at(custom_key, Instant::now()),
                    "1st silent timeout must NOT immediately blacklist custom port 22022"
                );
                assert!(
                    elapsed < Duration::from_millis(500),
                    "attempt 0 to unknown server-first port 22022 stalled unexpectedly: {:?}",
                    elapsed
                );
            } else if attempt == 1 {
                assert!(
                    should_skip_opportunistic_sniff_at(custom_key, Instant::now()),
                    "2nd consecutive silent timeout must learn custom port 22022 as server-first"
                );
                assert!(
                    elapsed < Duration::from_millis(500),
                    "attempt 1 to unknown server-first port 22022 stalled unexpectedly: {:?}",
                    elapsed
                );
            } else {
                assert!(
                    should_skip_opportunistic_sniff_at(custom_key, Instant::now()),
                    "3rd connect must still have learned server-first state active"
                );
                assert!(
                    elapsed < Duration::from_millis(250),
                    "3rd connect to learned server-first port 22022 must skip sniff cleanly, took {:?}",
                    elapsed
                );
            }
            drop(app);
            handle.await.unwrap().unwrap();
        }
        srv_c.await.unwrap();

        // 2b. 单次慢启动超时不得拉黑端点；已学习端点在退避探测窗口到期后必须放行单次半开探测并可被清除恢复
        let probe_key: (IpAddr, u16) = ("93.184.216.98".parse().unwrap(), 24443);
        clear_server_first_endpoint(probe_key);
        let t0 = Instant::now();
        record_server_first_endpoint_at(probe_key, t0);
        assert!(
            !should_skip_opportunistic_sniff_at(probe_key, t0 + Duration::from_millis(5)),
            "single 25ms timeout must NOT blacklist endpoint"
        );
        record_server_first_endpoint_at(probe_key, t0 + Duration::from_millis(50));
        assert!(
            should_skip_opportunistic_sniff_at(probe_key, t0 + Duration::from_secs(1)),
            "2 consecutive timeouts should suppress sniff during backoff window"
        );
        // 退避窗口（15s）到期后：仅放行 1 次半开探测，并发后续连接仍跳过，收到字节调用 clear 后彻底恢复
        assert!(
            !should_skip_opportunistic_sniff_at(probe_key, t0 + Duration::from_secs(16)),
            "half-open probe must be allowed after backoff interval so clear_server_first_endpoint is reachable"
        );
        assert!(
            should_skip_opportunistic_sniff_at(probe_key, t0 + Duration::from_secs(16)),
            "concurrent connection during half-open probe must still skip sniff"
        );
        clear_server_first_endpoint(probe_key);
        assert!(!should_skip_opportunistic_sniff_at(
            probe_key,
            t0 + Duration::from_secs(17)
        ));

        // 2c. NeedsDomainSniff 规则下端口 2222 绝不可被当作服务端先发端口无条件跳过（需提取 TLS SNI）
        let domain_2222_socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let domain_2222_socks_addr = domain_2222_socks.local_addr().unwrap();
        let (sni2222_tx, sni2222_rx) = tokio::sync::oneshot::channel();
        let hello_2222 = build_test_tls_client_hello("panel.2222.example");
        let expected_2222 = hello_2222.clone();
        let srv_2222 = tokio::spawn(async move {
            let (mut s, _) = domain_2222_socks.accept().await.unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
            let mut hdr = [0u8; 4];
            s.read_exact(&mut hdr).await.unwrap();
            assert_eq!(
                hdr[3], 0x03,
                "NeedsDomainSniff on port 2222 must sniff TLS SNI"
            );
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.unwrap();
            let mut dom = vec![0u8; l[0] as usize];
            s.read_exact(&mut dom).await.unwrap();
            let mut p = [0u8; 2];
            s.read_exact(&mut p).await.unwrap();
            let _ = sni2222_tx.send((String::from_utf8(dom).unwrap(), u16::from_be_bytes(p)));
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let mut got = vec![0u8; expected_2222.len()];
            s.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected_2222);
            s.write_all(b"OK2222").await.unwrap();
        });
        let cfg_2222 = {
            let cfg = test_config(
                "127.0.0.1:40001".parse().unwrap(),
                vec![crate::router::Rule::from_raw(
                    "PanelProxy",
                    true,
                    None,
                    Some("panel.2222.example"),
                    Some("2222"),
                    Action::Proxy(1),
                )],
            );
            cfg.proxy_nodes.write().unwrap().insert(
                1,
                ProxyNodeEntry {
                    id: 1,
                    name: "MockSocks".into(),
                    protocol: "SOCKS5".into(),
                    server_addr: domain_2222_socks_addr.to_string(),
                    username: None,
                    client: ProxyNode::Socks5(Socks5Client::new(
                        domain_2222_socks_addr.to_string(),
                    )),
                },
            );
            Arc::new(cfg)
        };
        let (mut app_2222, disp_2222) = tokio::io::duplex(4096);
        let h_2222 = tokio::spawn(async move {
            dispatch_transparent_stream(
                cfg_2222,
                disp_2222,
                "127.0.0.1:50504".parse().unwrap(),
                "93.184.216.99:2222".parse().unwrap(),
                None,
                true,
            )
            .await
        });
        app_2222.write_all(&hello_2222).await.unwrap();
        let mut ack_2222 = [0u8; 6];
        app_2222.read_exact(&mut ack_2222).await.unwrap();
        assert_eq!(&ack_2222, b"OK2222");
        assert_eq!(
            sni2222_rx.await.unwrap(),
            ("panel.2222.example".to_string(), 2222)
        );
        drop(app_2222);
        h_2222.await.unwrap().unwrap();
        srv_2222.await.unwrap();

        // 3. 任意非常见 HTTPS 端口（如 18443）在 DevProxy 下仍能在 25ms 机会式窗口内秒提 TLS SNI 并传权威域名给代理
        let custom_tls_ep = SocketAddr::new("93.184.216.97".parse().unwrap(), 18443);
        clear_server_first_endpoint((custom_tls_ep.ip(), custom_tls_ep.port()));
        let socks_t = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_t_addr = socks_t.local_addr().unwrap();
        let (sni_tx, sni_rx) = tokio::sync::oneshot::channel();
        let hello = build_test_tls_client_hello("custom-port.example");
        let expected_hello = hello.clone();
        let srv_t = tokio::spawn(async move {
            let (mut s, _) = socks_t.accept().await.unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
            let mut hdr = [0u8; 4];
            s.read_exact(&mut hdr).await.unwrap();
            assert_eq!(
                hdr[3], 0x03,
                "arbitrary HTTPS port 18443 must still dial authoritative SNI domain"
            );
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.unwrap();
            let mut dom = vec![0u8; l[0] as usize];
            s.read_exact(&mut dom).await.unwrap();
            let mut p = [0u8; 2];
            s.read_exact(&mut p).await.unwrap();
            let _ = sni_tx.send((String::from_utf8(dom).unwrap(), u16::from_be_bytes(p)));
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let mut got = vec![0u8; expected_hello.len()];
            s.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected_hello);
            s.write_all(b"OK18443").await.unwrap();
        });
        let cfg_t = make_devproxy_cfg(socks_t_addr);
        let (mut app_t, disp_t) = tokio::io::duplex(4096);
        let h_t = tokio::spawn(async move {
            dispatch_transparent_stream(
                cfg_t,
                disp_t,
                "127.0.0.1:50503".parse().unwrap(),
                custom_tls_ep,
                None,
                false,
            )
            .await
        });
        app_t.write_all(&hello).await.unwrap();
        let mut ack = [0u8; 7];
        app_t.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"OK18443");
        assert_eq!(
            sni_rx.await.unwrap(),
            ("custom-port.example".to_string(), 18443)
        );
        assert!(!should_skip_opportunistic_sniff((
            custom_tls_ep.ip(),
            custom_tls_ep.port()
        )));
        clear_server_first_endpoint_cache();
        drop(app_t);
        h_t.await.unwrap().unwrap();
        srv_t.await.unwrap();
    }
}
