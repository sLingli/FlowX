use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};
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
            inbound::send_failure(&mut local_stream, kind, true).await.ok();
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
            None => config.tracker.find_by_connection_async(peer_addr, orig_dst).await,
        },
        None => config.tracker.find_by_connection_async(peer_addr, orig_dst).await,
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
                crate::router::DomainNeedDecision::Immediate(
                    Action::Direct | Action::Block,
                ) => (false, false),
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
                let outcome = crate::transparent::sniffer::peek_host_prefix(
                    &mut local_stream,
                    sniff_timeout,
                )
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
    let (target, direct_dns_overrides) = match &target {
        TargetAddr::Ip(addr) if config.fake_ip_pool.is_fake_ip_addr(addr.ip()) => {
            match config.fake_ip_pool.restore_ip_with_dns_list(addr.ip()) {
                Some((domain, orig_dns_list)) => {
                    (TargetAddr::Domain(domain, addr.port()), orig_dns_list)
                }
                None => {
                    inbound::send_failure(&mut local_stream, kind, false).await.ok();
                    bail!("Fake-IP {} domain mapping expired or does not exist", addr.ip());
                }
            }
        }
        _ => (target, Vec::new()),
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

    #[tokio::test]
    async fn test_dispatch_transparent_stream_enforces_domain_port_rules_on_ssh_and_custom_ports_and_blocks_spoofed_localhost()
    {
        use crate::outbound::socks5::Socks5Client;

        // 1. 端口+域名阻断规则 (ports="22", targets="*.foo", Block) 经 real_ip_to_domain 与 Fake-IP 均立即阻断 SSH，不绕过
        let ssh_rules = vec![crate::router::Rule::from_raw(
            "BlockFooSsh",
            true,
            None,
            Some("*.foo"),
            Some("22"),
            Action::Block,
        )];
        let ssh_cfg = test_config("127.0.0.1:40001".parse().unwrap(), ssh_rules);
        let ssh_real_ip: IpAddr = "93.184.216.50".parse().unwrap();
        ssh_cfg
            .fake_ip_pool
            .record_real_ip_mappings("bastion.foo", &[ssh_real_ip]);
        let ssh_cfg = Arc::new(ssh_cfg);

        let (mut app_ssh, disp_ssh) = tokio::io::duplex(1024);
        dispatch_transparent_stream(
            Arc::clone(&ssh_cfg),
            disp_ssh,
            "127.0.0.1:50201".parse().unwrap(),
            SocketAddr::new(ssh_real_ip, 22),
            None,
            true,
        )
        .await
        .unwrap();
        let mut probe = [0u8; 8];
        assert_eq!(app_ssh.read(&mut probe).await.unwrap(), 0);

        // 2. 自定义二进制端口规则 (ports="7777", targets="*.game", Proxy(1)) 经唯一 real_ip_to_domain 命中域名规则，
        // 但走代理时一律以原始真实 IPv4 拨号（AlwaysUseRealIp），避免把启发式缓存域名误发给远端代理
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let (target_tx, target_rx) = tokio::sync::oneshot::channel();
        let socks_srv = tokio::spawn(async move {
            let (mut s, _) = socks_listener.accept().await.unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
            let mut hdr = [0u8; 4];
            s.read_exact(&mut hdr).await.unwrap();
            assert_eq!(
                hdr[3], 0x01,
                "heuristic cached_domain fallback must dial real IPv4 on Proxy instead of unverified domain"
            );
            let mut addr_port = [0u8; 6];
            s.read_exact(&mut addr_port).await.unwrap();
            let ip = std::net::Ipv4Addr::new(addr_port[0], addr_port[1], addr_port[2], addr_port[3]);
            let port = u16::from_be_bytes([addr_port[4], addr_port[5]]);
            let _ = target_tx.send((ip, port));
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let mut client_bin = [0u8; 4];
            s.read_exact(&mut client_bin).await.unwrap();
            assert_eq!(&client_bin, b"\xFE\xED\xFA\xCE");
            s.write_all(b"GAME_SRV_HELLO").await.unwrap();
        });

        let game_cfg = test_config(
            "127.0.0.1:40001".parse().unwrap(),
            vec![crate::router::Rule::from_raw(
                "GameProxy",
                true,
                None,
                Some("*.game"),
                Some("7777"),
                Action::Proxy(1),
            )],
        );
        let game_real_ip: IpAddr = "93.184.216.60".parse().unwrap();
        game_cfg
            .fake_ip_pool
            .record_real_ip_mappings("login.game", &[game_real_ip]);
        game_cfg.proxy_nodes.write().unwrap().insert(
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
        let (mut app_game, disp_game) = tokio::io::duplex(2048);
        let game_handle = tokio::spawn(async move {
            dispatch_transparent_stream(
                Arc::new(game_cfg),
                disp_game,
                "127.0.0.1:50202".parse().unwrap(),
                SocketAddr::new(game_real_ip, 7777),
                None,
                true,
            )
            .await
        });
        // 客户端首包发送非 TLS/非 HTTP 二进制魔数时，peek_host_prefix 立即 NotMatchable 放行并回退至唯一 cached_domain 路由
        app_game.write_all(b"\xFE\xED\xFA\xCE").await.unwrap();
        let mut game_hello = [0u8; 14];
        tokio::time::timeout(Duration::from_secs(2), app_game.read_exact(&mut game_hello))
            .await
            .expect("custom port 7777 with binary client payload must relay without timeout")
            .unwrap();
        assert_eq!(&game_hello, b"GAME_SRV_HELLO");
        assert_eq!(
            target_rx.await.unwrap(),
            (std::net::Ipv4Addr::new(93, 184, 216, 60), 7777)
        );
        drop(app_game);
        game_handle.await.unwrap().unwrap();
        socks_srv.await.unwrap();

        // 3. 未命中缓存的直连 SSH（端口 22）即使传入 needs_domain_sniff=true 也不得在嗅探阶段卡死，立刻放行服务端 banner
        let ssh_socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ssh_socks_addr = ssh_socks.local_addr().unwrap();
        let ssh_srv_task = tokio::spawn(async move {
            let (mut s, _) = ssh_socks.accept().await.unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
            let mut req = [0u8; 10];
            s.read_exact(&mut req).await.unwrap();
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            s.write_all(b"SSH-2.0-Immediate").await.unwrap();
        });
        let uncached_ssh_cfg = test_config(
            "127.0.0.1:40001".parse().unwrap(),
            vec![crate::router::Rule::from_raw(
                "ProxyAll",
                true,
                None,
                None,
                None,
                Action::Proxy(1),
            )],
        );
        uncached_ssh_cfg.proxy_nodes.write().unwrap().insert(
            1,
            ProxyNodeEntry {
                id: 1,
                name: "MockSocks22".into(),
                protocol: "SOCKS5".into(),
                server_addr: ssh_socks_addr.to_string(),
                username: None,
                client: ProxyNode::Socks5(Socks5Client::new(ssh_socks_addr.to_string())),
            },
        );
        let (mut app_u22, disp_u22) = tokio::io::duplex(2048);
        let u22_handle = tokio::spawn(async move {
            dispatch_transparent_stream(
                Arc::new(uncached_ssh_cfg),
                disp_u22,
                "127.0.0.1:50203".parse().unwrap(),
                "93.184.216.70:22".parse().unwrap(),
                None,
                true,
            )
            .await
        });
        let mut ssh_banner = [0u8; 17];
        tokio::time::timeout(Duration::from_secs(2), app_u22.read_exact(&mut ssh_banner))
            .await
            .expect("port 22 SSH must not block waiting for client sniff even with needs_domain_sniff=true")
            .unwrap();
        assert_eq!(&ssh_banner, b"SSH-2.0-Immediate");
        drop(app_u22);
        u22_handle.await.unwrap().unwrap();
        ssh_srv_task.await.unwrap();

        // 4. 远端公网 IP:80 伪造 HTTP Host: localhost 不得命中 LocalBypass 绕过 DevProxy 直连公网 IP
        let spoof_socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let spoof_socks_addr = spoof_socks.local_addr().unwrap();
        let (spoof_tx, spoof_rx) = tokio::sync::oneshot::channel();
        let spoof_srv = tokio::spawn(async move {
            let (mut s, _) = spoof_socks.accept().await.unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
            let mut hdr = [0u8; 4];
            s.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[3], 0x01, "spoofed Host: localhost on remote IP must stay as IP target for Proxy");
            let mut ip = [0u8; 6];
            s.read_exact(&mut ip).await.unwrap();
            let dst = std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
            let port = u16::from_be_bytes([ip[4], ip[5]]);
            let _ = spoof_tx.send((dst, port));
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let mut req_buf = vec![0u8; 35];
            s.read_exact(&mut req_buf).await.unwrap();
            assert_eq!(&req_buf, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
            s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        });
        let spoof_cfg = test_config(
            "127.0.0.1:40001".parse().unwrap(),
            vec![
                crate::router::Rule::from_raw("LocalBypass", true, None, Some("localhost"), None, Action::Direct),
                crate::router::Rule::from_raw("DevProxy", true, None, None, None, Action::Proxy(1)),
            ],
        );
        spoof_cfg.proxy_nodes.write().unwrap().insert(
            1,
            ProxyNodeEntry {
                id: 1,
                name: "SpoofSocks".into(),
                protocol: "SOCKS5".into(),
                server_addr: spoof_socks_addr.to_string(),
                username: None,
                client: ProxyNode::Socks5(Socks5Client::new(spoof_socks_addr.to_string())),
            },
        );
        let (mut app_sp, disp_sp) = tokio::io::duplex(2048);
        let sp_handle = tokio::spawn(async move {
            dispatch_transparent_stream(
                Arc::new(spoof_cfg),
                disp_sp,
                "127.0.0.1:50204".parse().unwrap(),
                "93.184.216.80:80".parse().unwrap(),
                None,
                false,
            )
            .await
        });
        app_sp
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let (got_ip, got_port) = spoof_rx.await.unwrap();
        assert_eq!(got_ip, std::net::Ipv4Addr::new(93, 184, 216, 80));
        assert_eq!(got_port, 80);
        let mut http_ack = [0u8; 19];
        app_sp.read_exact(&mut http_ack).await.unwrap();
        assert_eq!(&http_ack, b"HTTP/1.1 200 OK\r\n\r\n");
        drop(app_sp);
        sp_handle.await.unwrap().unwrap();
        spoof_srv.await.unwrap();
    }

    #[tokio::test]
    async fn test_dispatch_transparent_stream_sniffs_non_default_https_over_cached_ip_handles_cdn_ambiguity_and_uses_fake_ip_orig_dns(
    ) {
        use crate::outbound::socks5::Socks5Client;
        use tokio::io::AsyncReadExt;

        // 1. P1-1：非标准 HTTPS 端口 8444 即使存在过期/不同缓存域名，也不得跳过 TLS SNI 嗅探；
        //    应提取真实 SNI 命中代理规则并向 SOCKS5 传递权威 SNI 域名
        let socks_8444 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_8444_addr = socks_8444.local_addr().unwrap();
        let client_hello = build_test_tls_client_hello("real-sni.example");
        let expected_hello = client_hello.clone();
        let (sni_tx, sni_rx) = tokio::sync::oneshot::channel();
        let srv_8444 = tokio::spawn(async move {
            let (mut s, _) = socks_8444.accept().await.unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
            let mut hdr = [0u8; 4];
            s.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[3], 0x03, "authoritative TLS SNI must dial Domain on Proxy");
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
            let mut got_hello = vec![0u8; expected_hello.len()];
            s.read_exact(&mut got_hello).await.unwrap();
            assert_eq!(got_hello, expected_hello);
            s.write_all(b"TLS_OK").await.unwrap();
        });

        let cfg_8444 = test_config(
            "127.0.0.1:40001".parse().unwrap(),
            vec![crate::router::Rule::from_raw(
                "ProxyRealSni",
                true,
                None,
                Some("real-sni.example"),
                None,
                Action::Proxy(1),
            )],
        );
        cfg_8444.rule_engine.set_default_action(Action::Block);
        let shared_ip: IpAddr = "93.184.216.90".parse().unwrap();
        cfg_8444
            .fake_ip_pool
            .record_real_ip_mappings("stale-site.example", &[shared_ip]);
        cfg_8444.proxy_nodes.write().unwrap().insert(
            1,
            ProxyNodeEntry {
                id: 1,
                name: "SniSocks".into(),
                protocol: "SOCKS5".into(),
                server_addr: socks_8444_addr.to_string(),
                username: None,
                client: ProxyNode::Socks5(Socks5Client::new(socks_8444_addr.to_string())),
            },
        );

        let (mut app_tls, disp_tls) = tokio::io::duplex(4096);
        let tls_handle = tokio::spawn(async move {
            dispatch_transparent_stream(
                Arc::new(cfg_8444),
                disp_tls,
                "127.0.0.1:50301".parse().unwrap(),
                SocketAddr::new(shared_ip, 8444),
                None,
                true,
            )
            .await
        });
        app_tls.write_all(&client_hello).await.unwrap();
        let mut tls_ack = [0u8; 6];
        app_tls.read_exact(&mut tls_ack).await.unwrap();
        assert_eq!(&tls_ack, b"TLS_OK");
        assert_eq!(sni_rx.await.unwrap(), ("real-sni.example".to_string(), 8444));
        drop(app_tls);
        tls_handle.await.unwrap().unwrap();
        srv_8444.await.unwrap();

        // 2. P1-1：共享 CDN IP（两个域名同指 104.16.1.9 -> Ambiguous）在不可嗅探的端口 22 不得误用后写入域名命中错误 Block 规则，
        //    而是直接以真实 IP 走 Proxy
        let socks_cdn = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_cdn_addr = socks_cdn.local_addr().unwrap();
        let srv_cdn = tokio::spawn(async move {
            let (mut s, _) = socks_cdn.accept().await.unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
            let mut hdr = [0u8; 4];
            s.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[3], 0x01, "ambiguous CDN IP must dial raw IPv4");
            let mut ip_port = [0u8; 6];
            s.read_exact(&mut ip_port).await.unwrap();
            assert_eq!(&ip_port[0..4], &[104, 16, 1, 9]);
            assert_eq!(u16::from_be_bytes([ip_port[4], ip_port[5]]), 22);
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            s.write_all(b"SSH-CDN").await.unwrap();
        });
        let cfg_cdn = test_config(
            "127.0.0.1:40001".parse().unwrap(),
            vec![
                crate::router::Rule::from_raw(
                    "BlockSecondDomain",
                    true,
                    None,
                    Some("second.cdn.example"),
                    Some("22"),
                    Action::Block,
                ),
                crate::router::Rule::from_raw("ProxyRest", true, None, None, None, Action::Proxy(1)),
            ],
        );
        let cdn_ip: IpAddr = "104.16.1.9".parse().unwrap();
        cfg_cdn
            .fake_ip_pool
            .record_real_ip_mappings("first.cdn.example", &[cdn_ip]);
        cfg_cdn
            .fake_ip_pool
            .record_real_ip_mappings("second.cdn.example", &[cdn_ip]);
        cfg_cdn.proxy_nodes.write().unwrap().insert(
            1,
            ProxyNodeEntry {
                id: 1,
                name: "CdnSocks".into(),
                protocol: "SOCKS5".into(),
                server_addr: socks_cdn_addr.to_string(),
                username: None,
                client: ProxyNode::Socks5(Socks5Client::new(socks_cdn_addr.to_string())),
            },
        );
        let (mut app_cdn, disp_cdn) = tokio::io::duplex(2048);
        let cdn_handle = tokio::spawn(async move {
            dispatch_transparent_stream(
                Arc::new(cfg_cdn),
                disp_cdn,
                "127.0.0.1:50302".parse().unwrap(),
                SocketAddr::new(cdn_ip, 22),
                None,
                true,
            )
            .await
        });
        let mut ssh_cdn = [0u8; 7];
        app_cdn.read_exact(&mut ssh_cdn).await.unwrap();
        assert_eq!(&ssh_cdn, b"SSH-CDN");
        drop(app_cdn);
        cdn_handle.await.unwrap().unwrap();
        srv_cdn.await.unwrap();

        // 3. P0-1 防御纵深：Fake-IP 命中 Direct 时优先向 allocate_with_dns 记录的原分域 DNS 回源解析，
        //    即使默认 upstream_dns 不可达也可连通内网目标
        let echo_srv = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_srv.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            let (mut s, _) = echo_srv.accept().await.unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"PING");
            s.write_all(b"PONG").await.unwrap();
        });

        let corp_dns = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let corp_dns_addr = corp_dns.local_addr().unwrap();
        let (dns_stop_tx, mut dns_stop_rx) = tokio::sync::watch::channel(false);
        let corp_dns_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                tokio::select! {
                    recv = corp_dns.recv_from(&mut buf) => {
                        let Ok((n, peer)) = recv else { break };
                        let (txid, q) = crate::dns::server::DnsPacketParser::parse_question(&buf[..n]).unwrap();
                        let mut resp = Vec::new();
                        resp.extend_from_slice(&txid.to_be_bytes());
                        if q.qtype == 1 {
                            resp.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
                            resp.extend_from_slice(&buf[12..q.raw_len]);
                            resp.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
                        } else {
                            resp.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                            resp.extend_from_slice(&buf[12..q.raw_len]);
                        }
                        let _ = corp_dns.send_to(&resp, peer).await;
                    }
                    _ = dns_stop_rx.changed() => break,
                }
            }
        });

        let closed_default_dns = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_dns_addr = closed_default_dns.local_addr().unwrap();
        drop(closed_default_dns);

        let mut split_cfg = test_config("127.0.0.1:40001".parse().unwrap(), vec![]);
        split_cfg.upstream_dns = dead_dns_addr;
        let fake_corp = split_cfg
            .fake_ip_pool
            .allocate_with_dns("intranet.corp.example", Some(corp_dns_addr));

        let (mut app_corp, disp_corp) = tokio::io::duplex(2048);
        let corp_handle = tokio::spawn(async move {
            dispatch_transparent_stream(
                Arc::new(split_cfg),
                disp_corp,
                "127.0.0.1:50303".parse().unwrap(),
                SocketAddr::new(IpAddr::V4(fake_corp), echo_port),
                None,
                false,
            )
            .await
        });
        app_corp.write_all(b"PING").await.unwrap();
        let mut pong = [0u8; 4];
        app_corp.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"PONG");
        drop(app_corp);
        corp_handle.await.unwrap().unwrap();
        echo_task.await.unwrap();
        let _ = dns_stop_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(1), corp_dns_task).await;
    }

    #[tokio::test]
    async fn test_p1_1_devproxy_immediate_proxy_sniffs_nonstandard_https_http_and_p2_1_stale_sniff_does_not_delay_direct_or_block(
    ) {
        use crate::outbound::socks5::Socks5Client;

        // 1. P1-1: 默认 DevProxy（无域名条件，Immediate(Proxy(1)), needs_domain_sniff=false）
        //    在非标准 HTTPS 端口 8444 与 HTTP 端口 3000 上仍须嗅探 TLS SNI / HTTP Host 并传域名给远端代理
        for (port, payload, expected_host) in [
            (8444u16, build_test_tls_client_hello("portal.nonstd.example"), "portal.nonstd.example"),
            (3000u16, b"GET /health HTTP/1.1\r\nHost: web.dev.example:3000\r\n\r\n".to_vec(), "web.dev.example"),
        ] {
            let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let socks_addr = socks_listener.local_addr().unwrap();
            let (tx, rx) = tokio::sync::oneshot::channel();
            let expected_payload = payload.clone();
            let srv = tokio::spawn(async move {
                let (mut s, _) = socks_listener.accept().await.unwrap();
                let mut g = [0u8; 3];
                s.read_exact(&mut g).await.unwrap();
                s.write_all(&[0x05, 0x00]).await.unwrap();
                let mut hdr = [0u8; 4];
                s.read_exact(&mut hdr).await.unwrap();
                assert_eq!(hdr[3], 0x03, "DevProxy Immediate(Proxy) on :{port} must sniff and dial Domain");
                let mut l = [0u8; 1];
                s.read_exact(&mut l).await.unwrap();
                let mut dom = vec![0u8; l[0] as usize];
                s.read_exact(&mut dom).await.unwrap();
                let mut p = [0u8; 2];
                s.read_exact(&mut p).await.unwrap();
                let _ = tx.send((String::from_utf8(dom).unwrap(), u16::from_be_bytes(p)));
                s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                    .await
                    .unwrap();
                let mut got = vec![0u8; expected_payload.len()];
                s.read_exact(&mut got).await.unwrap();
                assert_eq!(got, expected_payload);
                s.write_all(b"OK_NONSTD").await.unwrap();
            });

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
            // 即使缓存了过期/不同域名，也不得跳过非标准端口上的权威嗅探
            let orig_ip: IpAddr = "93.184.216.91".parse().unwrap();
            cfg.fake_ip_pool
                .record_real_ip_mappings("stale-cached.example", &[orig_ip]);
            cfg.proxy_nodes.write().unwrap().insert(
                1,
                ProxyNodeEntry {
                    id: 1,
                    name: "NonStdSocks".into(),
                    protocol: "SOCKS5".into(),
                    server_addr: socks_addr.to_string(),
                    username: None,
                    client: ProxyNode::Socks5(Socks5Client::new(socks_addr.to_string())),
                },
            );
            let (mut app, disp) = tokio::io::duplex(4096);
            let h = tokio::spawn(async move {
                dispatch_transparent_stream(
                    Arc::new(cfg),
                    disp,
                    "127.0.0.1:50401".parse().unwrap(),
                    SocketAddr::new(orig_ip, port),
                    None,
                    false, // Immediate(Proxy) from NetstackEngine passes needs_domain_sniff=false
                )
                .await
            });
            app.write_all(&payload).await.unwrap();
            let mut ack = [0u8; 9];
            app.read_exact(&mut ack).await.unwrap();
            assert_eq!(&ack, b"OK_NONSTD");
            assert_eq!(rx.await.unwrap(), (expected_host.to_string(), port));
            drop(app);
            h.await.unwrap().unwrap();
            srv.await.unwrap();
        }

        // 2. P2-1: 即使 SYN 阶段传入了过期的 needs_domain_sniff=true，异步判定为 Immediate(Direct | Block) 后
        //    不得再等待 120ms 嗅探（例如静默 Block 应毫秒级关闭，服务端先发的直连端口应立即转发 banner）
        let block_cfg = Arc::new(test_config(
            "127.0.0.1:40001".parse().unwrap(),
            vec![crate::router::Rule::from_raw(
                "BlockAll",
                true,
                None,
                None,
                None,
                Action::Block,
            )],
        ));
        let (mut app_blk, disp_blk) = tokio::io::duplex(1024);
        let start_blk = std::time::Instant::now();
        let blk_handle = tokio::spawn(async move {
            dispatch_transparent_stream(
                block_cfg,
                disp_blk,
                "127.0.0.1:50402".parse().unwrap(),
                "93.184.216.92:2222".parse().unwrap(),
                None,
                true, // stale SYN-time needs_domain_sniff=true
            )
            .await
        });
        let mut eof = [0u8; 4];
        assert_eq!(app_blk.read(&mut eof).await.unwrap(), 0);
        blk_handle.await.unwrap().unwrap();
        assert!(
            start_blk.elapsed() < Duration::from_millis(80),
            "Immediate(Block) must not wait 120ms for stale SYN needs_domain_sniff, took {:?}",
            start_blk.elapsed()
        );

        let direct_origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let direct_origin_addr = direct_origin.local_addr().unwrap();
        let direct_srv = tokio::spawn(async move {
            let (mut s, _) = direct_origin.accept().await.unwrap();
            s.write_all(b"SSH-2.0-CustomPort").await.unwrap();
        });
        let direct_cfg = Arc::new(test_config(
            "127.0.0.1:40001".parse().unwrap(),
            vec![crate::router::Rule::from_raw(
                "DirectAll",
                true,
                None,
                None,
                None,
                Action::Direct,
            )],
        ));
        let (mut app_dir, disp_dir) = tokio::io::duplex(1024);
        let start_dir = std::time::Instant::now();
        let dir_handle = tokio::spawn(async move {
            dispatch_transparent_stream(
                direct_cfg,
                disp_dir,
                "127.0.0.1:50403".parse().unwrap(),
                direct_origin_addr,
                None,
                true, // stale SYN-time needs_domain_sniff=true
            )
            .await
        });
        let mut banner = [0u8; 18];
        app_dir.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"SSH-2.0-CustomPort");
        assert!(
            start_dir.elapsed() < Duration::from_millis(80),
            "Immediate(Direct) must not wait 120ms for stale SYN needs_domain_sniff, took {:?}",
            start_dir.elapsed()
        );
        drop(app_dir);
        dir_handle.await.unwrap().unwrap();
        direct_srv.await.unwrap();
    }

    #[tokio::test]
    async fn test_p2_3_immediate_proxy_avoids_120ms_stall_on_alt_and_custom_server_first_ports_while_sniffing_custom_https(
    ) {
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
            assert_eq!(&banner, b"SRV_BANNER_FAST");
            assert!(
                started.elapsed() < Duration::from_millis(60),
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
        clear_server_first_endpoint((custom_ep.ip(), custom_ep.port()));
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
            if attempt < 2 {
                assert!(
                    elapsed < Duration::from_millis(90),
                    "attempt {} to unknown server-first port 22022 must use short opportunistic timeout (<90ms), took {:?}",
                    attempt,
                    elapsed
                );
            } else {
                assert!(
                    elapsed < Duration::from_millis(30),
                    "3rd connect to learned server-first port 22022 must skip sniff immediately, took {:?}",
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
            assert_eq!(hdr[3], 0x03, "NeedsDomainSniff on port 2222 must sniff TLS SNI");
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
                    client: ProxyNode::Socks5(Socks5Client::new(domain_2222_socks_addr.to_string())),
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
        assert_eq!(sni2222_rx.await.unwrap(), ("panel.2222.example".to_string(), 2222));
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
            assert_eq!(hdr[3], 0x03, "arbitrary HTTPS port 18443 must still dial authoritative SNI domain");
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
        assert_eq!(sni_rx.await.unwrap(), ("custom-port.example".to_string(), 18443));
        assert!(!should_skip_opportunistic_sniff((custom_tls_ep.ip(), custom_tls_ep.port())));
        clear_server_first_endpoint_cache();
        drop(app_t);
        h_t.await.unwrap().unwrap();
        srv_t.await.unwrap();
    }
}
