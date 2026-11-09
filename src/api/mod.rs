use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{error, info};

use crate::config::ConfigStore;
use crate::dns::FakeIpPool;
use crate::i18n::{json_error, t, Locale};
use crate::interceptor::dispatcher::ProxyNodeEntry;
use crate::monitor::ConnectionManager;
use crate::outbound::chain::{parse_target_addr, ProxyNode};
use crate::outbound::http::HttpConnectClient;
use crate::outbound::socks4::Socks4Client;
use crate::outbound::socks5::Socks5Client;
use crate::router::{Action, Rule, RuleEngine};

const API_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_SIZE: usize = 1024 * 1024; // 1MB 上限防 DoS

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyNodeView {
    pub id: u32,
    pub name: String,
    pub protocol: String,
    pub server_addr: String,
    pub auth_configured: bool,
}

#[derive(Debug, Deserialize)]
pub struct AddNodeRequest {
    pub name: String,
    pub protocol: String,
    pub server_addr: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PingNodeRequest {
    pub id: u32,
}

#[derive(Debug, Serialize)]
pub struct PingResponse {
    pub ok: bool,
    pub latency_ms: u64,
    pub message: String,
    /// 底层错误的原始信息（不本地化，仅供排障，前端不应直接展示）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AddRuleRequest {
    pub name: String,
    pub apps: Option<String>,
    pub targets: Option<String>,
    pub ports: Option<String>,
    pub action: String, // "Direct", "Block", "Proxy"
    pub node_id: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct ToggleRuleRequest {
    pub id: u64,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct MoveRuleRequest {
    pub id: u64,
    pub direction: String, // "up" | "down" | "top" | "bottom"
}

#[derive(Debug, Clone)]
pub struct SystemRuntimeContext {
    pub inbound_addr: SocketAddr,
    pub dns_addr: SocketAddr,
    pub upstream_dns: SocketAddr,
    pub api_addr: SocketAddr,
    pub fake_ip_pool: Arc<FakeIpPool>,
    pub started_at: Instant,
}

#[derive(Debug, Serialize)]
pub struct SystemInfoResponse {
    pub version: &'static str,
    pub inbound_addr: String,
    pub inbound_protocols: Vec<&'static str>,
    pub dns_addr: String,
    pub upstream_dns: String,
    pub api_addr: String,
    pub config_path: String,
    pub fake_ip_cidr: &'static str,
    pub fake_ip_count: usize,
    pub uptime_secs: u64,
    pub default_action: String,
    pub nodes_count: usize,
    pub rules_count: usize,
    pub enabled_rules_count: usize,
}

pub struct ApiServer {
    pub bind_addr: SocketAddr,
    pub monitor: Arc<ConnectionManager>,
    pub rule_engine: Arc<RuleEngine>,
    pub proxy_nodes: Arc<RwLock<HashMap<u32, ProxyNodeEntry>>>,
    pub self_ports: Vec<u16>,
    pub config_store: Option<Arc<ConfigStore>>,
    pub runtime_context: Option<Arc<SystemRuntimeContext>>,
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
            started_at: Instant::now(),
        }
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

    /// 同步绑定 TCP 监听器（Fail-Fast 检查端口占用）
    pub async fn bind(&self) -> Result<TcpListener> {
        let listener = TcpListener::bind(self.bind_addr)
            .await
            .with_context(|| format!("Failed to bind HTTP API server port ({})", self.bind_addr))?;
        info!(
            "[API] FlowX control and status HTTP API server bound on http://{}",
            listener.local_addr().unwrap_or(self.bind_addr)
        );
        Ok(listener)
    }

    /// 启动异步 HTTP API 监听服务（支持优雅停机）
    pub async fn run(&self, listener: TcpListener, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        let actual_port = listener.local_addr().unwrap_or(self.bind_addr).port();
        let mut self_ports = self.self_ports.clone();
        if !self_ports.contains(&actual_port) {
            self_ports.push(actual_port);
        }
        let self_ports = Arc::new(self_ports);

        loop {
            let (stream, _) = tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok(r) => r,
                        Err(e) => {
                            error!("[API] Failed to accept HTTP API request: {}", e);
                            continue;
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    info!("[API] Received shutdown signal, stopping API server");
                    break;
                }
            };

            let monitor = Arc::clone(&self.monitor);
            let rule_engine = Arc::clone(&self.rule_engine);
            let proxy_nodes = Arc::clone(&self.proxy_nodes);
            let self_ports_clone = Arc::clone(&self_ports);
            let config_store = self.config_store.clone();
            let runtime_context = self.runtime_context.clone();
            let started_at = self.started_at;

            tokio::spawn(async move {
                if let Err(e) = tokio::time::timeout(
                    API_TIMEOUT,
                    handle_api_request(
                        stream,
                        actual_port,
                        self_ports_clone,
                        monitor,
                        rule_engine,
                        proxy_nodes,
                        config_store,
                        runtime_context,
                        started_at,
                    ),
                )
                .await
                {
                    error!("[API] Request processing timed out or failed: {}", e);
                }
            });
        }
        Ok(())
    }
}

async fn read_full_http_request(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
) -> std::result::Result<(), RequestReadError> {
    buffer.clear();
    let mut temp = [0u8; 2048];

    loop {
        let n = match stream.read(&mut temp).await {
            Ok(n) => n,
            Err(e) => {
                // 客户端提前断开等读错误较常见，保留原始错误到 debug 日志，对外只返回本地化文案
                tracing::debug!("[API] HTTP request read failed: {}", e);
                return Err(RequestReadError::Io);
            }
        };
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&temp[..n]);
        if buffer.len() > MAX_REQUEST_SIZE {
            return Err(RequestReadError::TooLarge);
        }

        if let Some(header_end) = find_header_end(buffer) {
            let header_str = String::from_utf8_lossy(&buffer[..header_end]);
            let content_length =
                parse_content_length(&header_str).ok_or(RequestReadError::InvalidContentLength)?;
            let total_needed = header_end
                .checked_add(content_length)
                .filter(|&t| t <= MAX_REQUEST_SIZE)
                .ok_or(RequestReadError::TooLarge)?;
            if buffer.len() >= total_needed {
                buffer.truncate(total_needed);
                break;
            }
        }
    }

    Ok(())
}

/// HTTP 请求读取阶段的可分类错误，用于生成本地化且机器可读的错误响应。
#[derive(Debug)]
enum RequestReadError {
    /// 请求体（含头部）超过 1MB 上限
    TooLarge,
    /// `Content-Length` 请求头缺失或非法
    InvalidContentLength,
    /// 底层套接字读取失败（原始错误已记入 debug 日志）
    Io,
}

impl RequestReadError {
    /// 返回（错误码, i18n 键）
    fn code_and_key(&self) -> (&'static str, &'static str) {
        match self {
            RequestReadError::TooLarge => ("ERR_REQUEST_TOO_LARGE", "error.request_too_large"),
            RequestReadError::InvalidContentLength => {
                ("ERR_INVALID_CONTENT_LENGTH", "error.invalid_content_length")
            }
            RequestReadError::Io => ("ERR_REQUEST_READ_FAILED", "error.request_read_failed"),
        }
    }
}

/// 在请求头尚未完整解析（或包含非 UTF-8 字节）时，尽力从已读到的字节中提取语言偏好，
/// 避免 zh 用户在最早期错误上只能拿到英文。
fn best_effort_locale(buffer: &[u8]) -> Locale {
    let text = String::from_utf8_lossy(buffer);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let query = request_line
        .split_whitespace()
        .nth(1)
        .and_then(|target| target.split_once('?'))
        .map(|(_, q)| q)
        .unwrap_or("");
    let mut accept_language = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("accept-language")
        {
            accept_language = Some(value.trim());
        }
    }
    Locale::from_header_or_query(accept_language, parse_query_param(query, "lang"))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// 解析 `Content-Length` 请求头；缺失视为 0，格式非法返回 None。
fn parse_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("content-length")
        {
            return v.trim().parse::<usize>().ok();
        }
    }
    Some(0)
}

fn extract_header<'a>(headers: &[&'a str], target_name: &str) -> Option<&'a str> {
    for line in headers {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case(target_name)
        {
            return Some(v.trim());
        }
    }
    None
}

/// 校验 Host 请求头是否为本地回环地址（防止 DNS Rebinding 攻击）
fn is_allowed_host(host_header: &str, expected_port: u16, require_exact_port: bool) -> bool {
    let trimmed = host_header.trim();
    if trimmed.is_empty() {
        return false;
    }

    let (host, port_opt) = if let Some(rest) = trimmed.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return false;
        };
        let host = &trimmed[..=end + 1]; // 保留 "[::1]"
        let after = &rest[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => match p.parse::<u16>() {
                Ok(n) => Some(n),
                Err(_) => return false,
            },
            None if after.is_empty() => None,
            None => return false,
        };
        (host, port)
    } else if let Some((h, p)) = trimmed.rsplit_once(':') {
        let Ok(n) = p.parse::<u16>() else {
            return false;
        };
        (h, Some(n))
    } else {
        (trimmed, None)
    };

    let is_loopback_name = host.eq_ignore_ascii_case("127.0.0.1")
        || host.eq_ignore_ascii_case("localhost")
        || host == "[::1]";
    if !is_loopback_name {
        return false;
    }

    match port_opt {
        Some(p) => p == expected_port,
        None => !require_exact_port || expected_port == 80,
    }
}

/// 校验 Origin / Referer 是否来自当前控制台同源（防止 CSRF 与跨站脚本调用本地 API）
fn is_allowed_origin(origin: &str, expected_port: u16) -> bool {
    let trimmed = origin.trim().trim_end_matches('/');
    let Some(rest) = strip_prefix_ignore_case(trimmed, "http://") else {
        return false;
    };
    is_allowed_host(rest, expected_port, true)
}

fn is_allowed_referer(referer: &str, expected_port: u16) -> bool {
    let trimmed = referer.trim();
    let Some(rest) = strip_prefix_ignore_case(trimmed, "http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    is_allowed_host(authority, expected_port, true)
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_api_request(
    mut stream: TcpStream,
    actual_port: u16,
    self_ports: Arc<Vec<u16>>,
    monitor: Arc<ConnectionManager>,
    rule_engine: Arc<RuleEngine>,
    proxy_nodes: Arc<RwLock<HashMap<u32, ProxyNodeEntry>>>,
    config_store: Option<Arc<ConfigStore>>,
    runtime_context: Option<Arc<SystemRuntimeContext>>,
    started_at: Instant,
) -> Result<()> {
    let mut req_bytes = Vec::with_capacity(4096);
    if let Err(e) = read_full_http_request(&mut stream, &mut req_bytes).await {
        let (code, key) = e.code_and_key();
        let msg = json_error(best_effort_locale(&req_bytes), code, key);
        send_http_response(&mut stream, "400 Bad Request", "application/json; charset=utf-8", &msg).await?;
        return Ok(());
    }
    if req_bytes.is_empty() {
        return Ok(());
    }

    // 协议早期错误（头部不完整/非 UTF-8）同样按 best-effort 语言偏好本地化
    let locale = best_effort_locale(&req_bytes);

    let Some(header_end) = find_header_end(&req_bytes) else {
        send_http_response(
            &mut stream,
            "400 Bad Request",
            "application/json; charset=utf-8",
            &json_error(locale, "ERR_INCOMPLETE_HEADERS", "error.incomplete_headers"),
        )
        .await?;
        return Ok(());
    };

    let Ok(header_str) = std::str::from_utf8(&req_bytes[..header_end - 4]) else {
        send_http_response(
            &mut stream,
            "400 Bad Request",
            "application/json; charset=utf-8",
            &json_error(locale, "ERR_NON_UTF8_HEADERS", "error.non_utf8_headers"),
        )
        .await?;
        return Ok(());
    };

    let mut header_lines = header_str.split("\r\n");
    let first_line = header_lines.next().unwrap_or_default();
    let headers: Vec<&str> = header_lines.collect();

    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }

    let method = parts[0];
    let path_and_query = parts[1];
    let (path, query) = path_and_query.split_once('?').unwrap_or((path_and_query, ""));

    let accept_lang = extract_header(&headers, "accept-language");
    // 只取 lang 查询参数本身，避免把整段 query 交给子串匹配（如 ?keywords=lang=zh 误命中）
    let locale = Locale::from_header_or_query(accept_lang, parse_query_param(query, "lang"));

    // 安全校验 1: Host 头必须为本地回环地址，防止 DNS Rebinding
    let host_ok = extract_header(&headers, "host")
        .is_some_and(|h| is_allowed_host(h, actual_port, false));
    if !host_ok {
        send_http_response(
            &mut stream,
            "403 Forbidden",
            "application/json; charset=utf-8",
            &json_error(locale, "ERR_FORBIDDEN_HOST", "error.invalid_host"),
        )
        .await?;
        return Ok(());
    }

    // 安全校验 2: Origin / Sec-Fetch-Site / Referer 同源检查，防止跨站 CSRF
    if let Some(origin) = extract_header(&headers, "origin")
        && !is_allowed_origin(origin, actual_port)
    {
        send_http_response(
            &mut stream,
            "403 Forbidden",
            "application/json; charset=utf-8",
            &json_error(locale, "ERR_FORBIDDEN_ORIGIN", "error.invalid_origin"),
        )
        .await?;
        return Ok(());
    }

    if let Some(fetch_site) = extract_header(&headers, "sec-fetch-site")
        && fetch_site.eq_ignore_ascii_case("cross-site")
        && (path.starts_with("/api/") || !matches!(method, "GET" | "HEAD"))
    {
        send_http_response(
            &mut stream,
            "403 Forbidden",
            "application/json; charset=utf-8",
            &json_error(locale, "ERR_FORBIDDEN_FETCH_SITE", "error.invalid_fetch_site"),
        )
        .await?;
        return Ok(());
    }

    if !matches!(method, "GET" | "HEAD" | "OPTIONS")
        && let Some(referer) = extract_header(&headers, "referer")
        && !is_allowed_referer(referer, actual_port)
    {
        send_http_response(
            &mut stream,
            "403 Forbidden",
            "application/json; charset=utf-8",
            &json_error(locale, "ERR_FORBIDDEN_REFERER", "error.invalid_referer"),
        )
        .await?;
        return Ok(());
    }

    let body_bytes = &req_bytes[header_end..];
    let req_body = std::str::from_utf8(body_bytes).unwrap_or("");

    let (status, content_type, body) = match (method, path) {
        ("OPTIONS", _) => ("204 No Content", "text/plain", String::new()),
        ("GET", "/") | ("GET", "/dashboard") => {
            let html = include_str!("../../frontend/index.html");
            ("200 OK", "text/html; charset=utf-8", html.to_string())
        }
        ("GET", "/api/health") => (
            "200 OK",
            "application/json; charset=utf-8",
            r#"{"status":"ok","engine":"FlowX"}"#.to_string(),
        ),
        ("GET", "/api/system") => {
            let info = build_system_info(
                actual_port,
                runtime_context.as_deref(),
                config_store.as_deref(),
                &proxy_nodes,
                &rule_engine,
                started_at,
                locale,
            );
            ("200 OK", "application/json; charset=utf-8", serde_json_to_string(&info))
        }
        ("GET", "/api/stats") => {
            let stats = monitor.global_stats();
            ("200 OK", "application/json; charset=utf-8", serde_json_to_string(&stats))
        }
        ("GET", "/api/connections") => {
            let mut list = monitor.list_snapshots();
            for conn in &mut list {
                localize_connection_view(conn, locale);
            }
            ("200 OK", "application/json; charset=utf-8", serde_json_to_string(&list))
        }
        ("POST", "/api/connections/kill") => {
            let id: Option<u64> = parse_query_param(query, "id")
                .and_then(|v| v.parse().ok())
                .or_else(|| {
                    serde_json::from_str::<serde_json::Value>(req_body)
                        .ok()
                        .and_then(|v| v.get("id").and_then(|i| i.as_u64()))
                });
            if let Some(conn_id) = id {
                // 仅发送终止通知，连接的注销与残余流量核算统一由调度协程的 ConnectionGuard::drop 单点负责
                let killed = monitor.kill_connection(conn_id);
                (
                    "200 OK",
                    "application/json; charset=utf-8",
                    format!(r#"{{"ok":true,"killed":{}}}"#, killed),
                )
            } else {
                (
                    "400 Bad Request",
                    "application/json; charset=utf-8",
                    json_error(locale, "ERR_MISSING_CONN_ID", "error.missing_conn_id"),
                )
            }
        }
        ("GET", "/api/nodes") => {
            let nodes_guard = proxy_nodes.read().unwrap_or_else(|e| e.into_inner());
            let mut list: Vec<ProxyNodeView> = nodes_guard
                .values()
                .map(|n| ProxyNodeView {
                    id: n.id,
                    name: n.name.clone(),
                    protocol: n.protocol.clone(),
                    server_addr: n.server_addr.clone(),
                    auth_configured: n.username.is_some(),
                })
                .collect();
            list.sort_by_key(|n| n.id);
            ("200 OK", "application/json; charset=utf-8", serde_json_to_string(&list))
        }
        ("POST", "/api/nodes") => match serde_json::from_str::<AddNodeRequest>(req_body) {
            Err(_) => (
                "400 Bad Request",
                "application/json; charset=utf-8",
                json_error(locale, "ERR_INVALID_NODE_BODY", "error.invalid_node_body"),
            ),
            Ok(req) => {
                let res = handle_add_node(req, &proxy_nodes, &self_ports, locale);
                if res.0 == "200 OK" {
                    persist_config(config_store.as_deref(), &proxy_nodes, &rule_engine);
                }
                res
            }
        },
        ("DELETE", "/api/nodes") => {
            let id: Option<u32> = parse_query_param(query, "id")
                .and_then(|v| v.parse().ok())
                .or_else(|| {
                    serde_json::from_str::<serde_json::Value>(req_body)
                        .ok()
                        .and_then(|v| v.get("id").and_then(|i| i.as_u64()))
                        .and_then(|n| u32::try_from(n).ok())
                });
            if let Some(node_id) = id {
                // 级联防呆检查：若当前有任何路由规则或默认兜底动作指向该代理节点，禁止删除
                let rules = rule_engine.current_rules();
                let is_referenced = rules.iter().any(|r| match &r.action {
                    Action::Proxy(pid) => *pid == node_id,
                    _ => false,
                }) || matches!(rule_engine.default_action, Action::Proxy(pid) if pid == node_id);
                if is_referenced {
                    (
                        "409 Conflict",
                        "application/json; charset=utf-8",
                        json_error(locale, "ERR_NODE_IN_USE", "error.node_in_use"),
                    )
                } else {
                    let removed = {
                        let mut nodes_guard = proxy_nodes.write().unwrap_or_else(|e| e.into_inner());
                        nodes_guard.remove(&node_id).is_some()
                    };
                    if removed {
                        persist_config(config_store.as_deref(), &proxy_nodes, &rule_engine);
                        ("200 OK", "application/json; charset=utf-8", r#"{"ok":true}"#.to_string())
                    } else {
                        (
                            "404 Not Found",
                            "application/json; charset=utf-8",
                            json_error(locale, "ERR_NODE_NOT_FOUND", "error.node_not_found"),
                        )
                    }
                }
            } else {
                (
                    "400 Bad Request",
                    "application/json; charset=utf-8",
                    json_error(locale, "ERR_MISSING_NODE_ID", "error.missing_node_id"),
                )
            }
        }
        ("POST", "/api/nodes/ping") => {
            let node_id: Option<u32> = parse_query_param(query, "id")
                .and_then(|v| v.parse().ok())
                .or_else(|| {
                    serde_json::from_str::<PingNodeRequest>(req_body).ok().map(|p| p.id)
                });
            if let Some(id) = node_id {
                let target_addr = {
                    let nodes_guard = proxy_nodes.read().unwrap_or_else(|e| e.into_inner());
                    nodes_guard.get(&id).map(|n| n.server_addr.clone())
                };
                if let Some(addr) = target_addr {
                    let (ok, ms, msg, detail) = ping_address(&addr, locale).await;
                    let ping_res = PingResponse {
                        ok,
                        latency_ms: ms,
                        message: msg,
                        detail,
                    };
                    ("200 OK", "application/json; charset=utf-8", serde_json_to_string(&ping_res))
                } else {
                    (
                        "404 Not Found",
                        "application/json; charset=utf-8",
                        json_error(locale, "ERR_NODE_NOT_FOUND", "error.node_not_found"),
                    )
                }
            } else {
                (
                    "400 Bad Request",
                    "application/json; charset=utf-8",
                    json_error(locale, "ERR_MISSING_NODE_ID", "error.missing_node_id"),
                )
            }
        }
        ("GET", "/api/rules") => {
            let list = rule_engine.list_rules_view_with_locale(locale);
            ("200 OK", "application/json; charset=utf-8", serde_json_to_string(&list))
        }
        ("POST", "/api/rules") => match serde_json::from_str::<AddRuleRequest>(req_body) {
            Err(_) => (
                "400 Bad Request",
                "application/json; charset=utf-8",
                json_error(locale, "ERR_INVALID_RULE_BODY", "error.invalid_rule_body"),
            ),
            Ok(req) => {
                let res = handle_add_rule(req, &rule_engine, &proxy_nodes, locale);
                if res.0 == "200 OK" {
                    persist_config(config_store.as_deref(), &proxy_nodes, &rule_engine);
                }
                res
            }
        },
        ("POST", "/api/rules/toggle") => match serde_json::from_str::<ToggleRuleRequest>(req_body) {
            Err(_) => (
                "400 Bad Request",
                "application/json; charset=utf-8",
                json_error(locale, "ERR_INVALID_TOGGLE_BODY", "error.invalid_toggle_body"),
            ),
            Ok(req) => match rule_engine.toggle_rule(req.id, req.enabled) {
                Some(enabled) => {
                    persist_config(config_store.as_deref(), &proxy_nodes, &rule_engine);
                    (
                        "200 OK",
                        "application/json; charset=utf-8",
                        format!(r#"{{"ok":true,"enabled":{}}}"#, enabled),
                    )
                }
                None => (
                    "404 Not Found",
                    "application/json; charset=utf-8",
                    json_error(locale, "ERR_RULE_NOT_FOUND", "error.rule_not_found"),
                ),
            },
        },
        ("POST", "/api/rules/move") => match serde_json::from_str::<MoveRuleRequest>(req_body) {
            Err(_) => (
                "400 Bad Request",
                "application/json; charset=utf-8",
                json_error(locale, "ERR_INVALID_MOVE_BODY", "error.invalid_move_body"),
            ),
            Ok(req) => {
                if !matches!(
                    req.direction.trim().to_ascii_lowercase().as_str(),
                    "up" | "down" | "top" | "bottom"
                ) {
                    (
                        "400 Bad Request",
                        "application/json; charset=utf-8",
                        json_error(locale, "ERR_INVALID_MOVE_DIR", "error.invalid_move_direction"),
                    )
                } else {
                    match rule_engine.move_rule(req.id, &req.direction) {
                        Some(changed) => {
                            if changed {
                                persist_config(config_store.as_deref(), &proxy_nodes, &rule_engine);
                            }
                            (
                                "200 OK",
                                "application/json; charset=utf-8",
                                format!(r#"{{"ok":true,"moved":{}}}"#, changed),
                            )
                        }
                        None => (
                            "404 Not Found",
                            "application/json; charset=utf-8",
                            json_error(locale, "ERR_RULE_NOT_FOUND", "error.rule_not_found"),
                        ),
                    }
                }
            }
        },
        ("DELETE", "/api/rules") => {
            let id: Option<u64> = parse_query_param(query, "id")
                .and_then(|v| v.parse().ok())
                .or_else(|| {
                    serde_json::from_str::<serde_json::Value>(req_body)
                        .ok()
                        .and_then(|v| v.get("id").and_then(|i| i.as_u64()))
                });
            if let Some(rule_id) = id {
                let ok = rule_engine.delete_rule(rule_id);
                if ok {
                    persist_config(config_store.as_deref(), &proxy_nodes, &rule_engine);
                    ("200 OK", "application/json; charset=utf-8", r#"{"ok":true}"#.to_string())
                } else {
                    (
                        "404 Not Found",
                        "application/json; charset=utf-8",
                        json_error(locale, "ERR_RULE_NOT_FOUND", "error.rule_not_found"),
                    )
                }
            } else {
                (
                    "400 Bad Request",
                    "application/json; charset=utf-8",
                    json_error(locale, "ERR_MISSING_RULE_ID", "error.missing_rule_id"),
                )
            }
        }
        _ => (
            "404 Not Found",
            "application/json; charset=utf-8",
            json_error(locale, "ERR_NOT_FOUND", "error.not_found"),
        ),
    };

    send_http_response(&mut stream, status, content_type, &body).await?;
    Ok(())
}

fn handle_add_node(
    req: AddNodeRequest,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    self_ports: &[u16],
    locale: Locale,
) -> (&'static str, &'static str, String) {
    let ct = "application/json; charset=utf-8";
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return (
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_EMPTY_NODE_NAME", "error.empty_node_name"),
        );
    }

    let protocol = req.protocol.trim().to_ascii_uppercase();
    if !matches!(protocol.as_str(), "SOCKS5" | "SOCKS4" | "HTTP") {
        return (
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_UNSUPPORTED_PROTOCOL", "error.unsupported_protocol"),
        );
    }

    let server_addr = req.server_addr.trim().to_string();
    let Ok(target_parsed) = parse_target_addr(&server_addr) else {
        return (
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_INVALID_NODE_ADDR", "error.invalid_node_addr"),
        );
    };
    if target_parsed.port() == 0 || target_parsed.host_string().is_empty() {
        return (
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_INVALID_NODE_PORT", "error.invalid_node_port"),
        );
    }

    if target_parsed.is_loopback_or_unspecified() && self_ports.contains(&target_parsed.port()) {
        return (
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_NODE_SELF_LOOP", "error.node_self_loop"),
        );
    }

    let username = req
        .username
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty());
    let password = req.password.filter(|p| !p.is_empty());

    if let Some(u) = &username
        && (u.contains('\r') || u.contains('\n') || u.contains('\0') || u.len() > 255)
    {
        return (
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_INVALID_USERNAME", "error.invalid_username"),
        );
    }
    if let Some(p) = &password
        && (p.contains('\r') || p.contains('\n') || p.contains('\0') || p.len() > 255)
    {
        return (
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_INVALID_PASSWORD", "error.invalid_password"),
        );
    }

    let client = match protocol.as_str() {
        "HTTP" => {
            let mut c = HttpConnectClient::new(&server_addr);
            if let (Some(u), Some(p)) = (&username, &password) {
                c = c.with_auth(u.clone(), p.clone());
            }
            ProxyNode::Http(c)
        }
        "SOCKS4" => {
            let mut c = Socks4Client::new(&server_addr);
            if let Some(u) = &username {
                c = c.with_user_id(u.clone());
            }
            ProxyNode::Socks4(c)
        }
        _ => {
            let mut c = Socks5Client::new(&server_addr);
            if let (Some(u), Some(p)) = (&username, &password) {
                c = c.with_auth(u.clone(), p.clone());
            }
            ProxyNode::Socks5(c)
        }
    };

    let mut nodes_guard = proxy_nodes.write().unwrap_or_else(|e| e.into_inner());
    let new_id = nodes_guard.keys().max().copied().unwrap_or(100) + 1;
    nodes_guard.insert(
        new_id,
        ProxyNodeEntry {
            id: new_id,
            name,
            protocol,
            server_addr,
            username,
            client,
        },
    );
    ("200 OK", ct, format!(r#"{{"ok":true,"id":{}}}"#, new_id))
}

fn handle_add_rule(
    req: AddRuleRequest,
    rule_engine: &RuleEngine,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    locale: Locale,
) -> (&'static str, &'static str, String) {
    let ct = "application/json; charset=utf-8";
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return (
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_EMPTY_RULE_NAME", "error.empty_rule_name"),
        );
    }

    let action = match req.action.trim().to_ascii_uppercase().as_str() {
        "DIRECT" => Action::Direct,
        "BLOCK" => Action::Block,
        "PROXY" => {
            let Some(nid) = req.node_id else {
                return (
                    "400 Bad Request",
                    ct,
                    json_error(locale, "ERR_MISSING_NODE_FOR_PROXY", "error.missing_node_id_for_proxy"),
                );
            };
            let exists = {
                let nodes_guard = proxy_nodes.read().unwrap_or_else(|e| e.into_inner());
                nodes_guard.contains_key(&nid)
            };
            if !exists {
                return (
                    "400 Bad Request",
                    ct,
                    json_error(locale, "ERR_NODE_NOT_FOUND", "error.node_not_found"),
                );
            }
            Action::Proxy(nid)
        }
        _ => {
            return (
                "400 Bad Request",
                ct,
                json_error(locale, "ERR_INVALID_RULE_ACTION", "error.invalid_rule_action"),
            );
        }
    };

    let apps_clean = req.apps.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let targets_clean = req.targets.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let ports_clean = req.ports.as_deref().map(str::trim).filter(|s| !s.is_empty());

    let rule = Rule::from_raw(name, true, apps_clean, targets_clean, ports_clean, action);

    if apps_clean.is_some()
        && rule.application_patterns.as_ref().is_some_and(Vec::is_empty)
    {
        return (
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_INVALID_APP_PATTERN", "error.invalid_app_pattern"),
        );
    }
    if targets_clean.is_some()
        && rule.target_subnets.is_none()
        && rule.target_domains.as_ref().is_some_and(Vec::is_empty)
    {
        return (
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_INVALID_TARGET_PATTERN", "error.invalid_target_pattern"),
        );
    }
    if ports_clean.is_some() && rule.ports.as_ref().is_some_and(Vec::is_empty) {
        return (
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_INVALID_PORT_FORMAT", "error.invalid_port_format"),
        );
    }

    let id = rule.id;
    rule_engine.add_rule(rule);
    ("200 OK", ct, format!(r#"{{"ok":true,"id":{}}}"#, id))
}

fn build_system_info(
    actual_port: u16,
    runtime_ctx: Option<&SystemRuntimeContext>,
    config_store: Option<&ConfigStore>,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    rule_engine: &RuleEngine,
    started_at: Instant,
    locale: Locale,
) -> SystemInfoResponse {
    let nodes_count = proxy_nodes
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .len();
    let rules = rule_engine.current_rules();
    let rules_count = rules.len();
    let enabled_rules_count = rules.iter().filter(|r| r.enabled).count();
    let default_action = crate::router::format_action_desc(&rule_engine.default_action, locale);

    let (inbound_addr, dns_addr, upstream_dns, api_addr, fake_ip_count, uptime_secs) =
        match runtime_ctx {
            Some(ctx) => (
                ctx.inbound_addr.to_string(),
                ctx.dns_addr.to_string(),
                ctx.upstream_dns.to_string(),
                ctx.api_addr.to_string(),
                ctx.fake_ip_pool.len(),
                ctx.started_at.elapsed().as_secs(),
            ),
            None => (
                "127.0.0.1:40001".to_string(),
                "127.0.0.1:1053".to_string(),
                "223.5.5.5:53".to_string(),
                format!("127.0.0.1:{}", actual_port),
                0,
                started_at.elapsed().as_secs(),
            ),
        };

    SystemInfoResponse {
        version: env!("CARGO_PKG_VERSION"),
        inbound_addr,
        inbound_protocols: vec!["SOCKS5", "SOCKS4a", "HTTP", "HTTP CONNECT"],
        dns_addr,
        upstream_dns,
        api_addr,
        config_path: config_store
            .map(|s| s.path().display().to_string())
            .unwrap_or_else(|| t(locale, "system.memory_mode").to_string()),
        fake_ip_cidr: "198.18.0.0/15",
        fake_ip_count,
        uptime_secs,
        default_action,
        nodes_count,
        rules_count,
        enabled_rules_count,
    }
}

fn persist_config(
    config_store: Option<&ConfigStore>,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    rule_engine: &RuleEngine,
) {
    if let Some(store) = config_store
        && let Err(e) = store.save_runtime(proxy_nodes, rule_engine)
    {
        error!(
            "[Config] Auto-persisting config file ({}) failed: {:#}",
            store.path().display(),
            e
        );
    }
}

async fn send_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {}\r\n\
Content-Type: {}\r\n\
X-Content-Type-Options: nosniff\r\n\
Cache-Control: no-store\r\n\
Content-Length: {}\r\n\
Connection: close\r\n\
\r\n\
{}",
        status,
        content_type,
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await
}

fn parse_query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for part in query.split('&') {
        if let Some((k, v)) = part.split_once('=')
            && k == key
        {
            return Some(v);
        }
    }
    None
}

/// 将连接快照中的机器可读字段按请求语言格式化为展示文案。
///
/// `action_type` / `action_id` 保持英文机器语义，供前端做分支判断与过滤；
/// `action` / `rule_name` / 进程占位名才是给人看的多语言文案。
fn localize_connection_view(conn: &mut crate::monitor::ConnectionSnapshot, locale: Locale) {
    conn.action = crate::router::format_action_desc(
        &Action::from_parts(&conn.action_type, conn.action_id),
        locale,
    );
    if conn.rule_name == crate::router::DEFAULT_RULE_NAME {
        conn.rule_name = t(locale, "action.default_rule").to_string();
    }
    if conn.process_name == crate::i18n::UNKNOWN_PROCESS {
        conn.process_name = t(locale, "label.unknown_process").to_string();
    }
    if conn.process_path == crate::i18n::UNKNOWN_PROCESS {
        conn.process_path = t(locale, "label.unknown_process").to_string();
    }
}

async fn ping_address(addr: &str, locale: Locale) -> (bool, u64, String, Option<String>) {
    let start = std::time::Instant::now();
    let res = tokio::time::timeout(Duration::from_millis(2000), TcpStream::connect(addr)).await;
    match res {
        Ok(Ok(stream)) => {
            drop(stream);
            let ms = start.elapsed().as_millis() as u64;
            (true, ms, format!("{} ms", ms), None)
        }
        // 面向用户的文案本地化；底层 OS 错误串只放进 detail，供排障而不直接展示
        Ok(Err(e)) => (
            false,
            0,
            t(locale, "error.ping_failed").to_string(),
            Some(e.to_string()),
        ),
        Err(_) => (false, 0, t(locale, "ping.timeout").to_string(), None),
    }
}

fn serde_json_to_string<T: serde::Serialize>(val: &T) -> String {
    serde_json::to_string(val).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let srv = ApiServer::new("127.0.0.1:0".parse().unwrap(), mgr, Arc::clone(&re), Arc::clone(&nodes))
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
    async fn test_api_security_and_validation() {
        let (addr, _nodes, _re, _shutdown_tx) = spawn_test_api().await;
        let port = addr.port();

        // 1. 无通配 CORS 且拦截 DNS Rebinding / 跨源请求
        let ok_resp = raw_http(addr, &format!("GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n", port)).await;
        assert!(ok_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(!ok_resp.contains("Access-Control-Allow-Origin"));

        let evil_host = raw_http(addr, &format!("GET /api/health HTTP/1.1\r\nHost: evil.com:{}\r\n\r\n", port)).await;
        assert!(evil_host.starts_with("HTTP/1.1 403 Forbidden"));

        let evil_origin = raw_http(
            addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: http://evil.com\r\nContent-Length: 2\r\n\r\n{{}}",
                port
            ),
        )
        .await;
        assert!(evil_origin.starts_with("HTTP/1.1 403 Forbidden"));

        // 2. 拒绝未知代理协议
        let bad_proto_body = r#"{"name":"n1","protocol":"VMESS","server_addr":"1.2.3.4:1080"}"#;
        let bad_proto = raw_http(
            addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\n\r\n{}",
                port,
                bad_proto_body.len(),
                bad_proto_body
            ),
        )
        .await;
        assert!(bad_proto.starts_with("HTTP/1.1 400 Bad Request"));

        // 3. 拒绝引用不存在节点的规则与无效端口语法
        let bad_rule_body = r#"{"name":"r1","action":"Proxy","node_id":999}"#;
        let bad_rule = raw_http(
            addr,
            &format!(
                "POST /api/rules HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\n\r\n{}",
                port,
                bad_rule_body.len(),
                bad_rule_body
            ),
        )
        .await;
        assert!(bad_rule.starts_with("HTTP/1.1 400 Bad Request"));

        let bad_port_body = r#"{"name":"r2","action":"Direct","ports":"invalid"}"#;
        let bad_port = raw_http(
            addr,
            &format!(
                "POST /api/rules HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\n\r\n{}",
                port,
                bad_port_body.len(),
                bad_port_body
            ),
        )
        .await;
        assert!(bad_port.starts_with("HTTP/1.1 400 Bad Request"));

        // 4. ping 按节点 ID 查询，拒绝未注册节点与任意 addr 请求
        let ping_missing_body = r#"{"id":999}"#;
        let ping_missing = raw_http(
            addr,
            &format!(
                "POST /api/nodes/ping HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\n\r\n{}",
                port,
                ping_missing_body.len(),
                ping_missing_body
            ),
        )
        .await;
        assert!(ping_missing.starts_with("HTTP/1.1 404 Not Found"));

        let ping_ssrf_body = r#"{"addr":"192.168.1.1:22"}"#;
        let ping_ssrf = raw_http(
            addr,
            &format!(
                "POST /api/nodes/ping HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\n\r\n{}",
                port,
                ping_ssrf_body.len(),
                ping_ssrf_body
            ),
        )
        .await;
        assert!(ping_ssrf.starts_with("HTTP/1.1 400 Bad Request"));
    }

    #[tokio::test]
    async fn test_api_mutates_and_persists_xml() {
        let mut path = std::env::current_dir().unwrap().join("target");
        path.push(format!("flowx_api_persist_{}.xml", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let store = Arc::new(ConfigStore::new(&path));
        let (rt, _) = store.load_or_init(&[40001, 40080, 1053]).unwrap();

        let mgr = Arc::new(ConnectionManager::new());
        let re = Arc::new(RuleEngine::new(rt.rules, rt.default_action));
        let nodes = Arc::new(RwLock::new(rt.proxy_nodes));
        let srv = ApiServer::new("127.0.0.1:0".parse().unwrap(), mgr, Arc::clone(&re), Arc::clone(&nodes))
            .with_self_ports(vec![40001, 40080, 1053])
            .with_config_store(Arc::clone(&store));
        let listener = srv.bind().await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move { srv.run(listener, rx).await });
        let _keep_tx = tx;

        let port = addr.port();
        let add_node_body = r#"{"name":"HK-Test","protocol":"HTTP","server_addr":"10.0.0.2:8080"}"#;
        let resp = raw_http(
            addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\n\r\n{}",
                port,
                add_node_body.len(),
                add_node_body
            ),
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "resp: {}", resp);

        let (reloaded, _) = store.load_or_init(&[40001, 40080, 1053]).unwrap();
        assert_eq!(reloaded.proxy_nodes.len(), 2);
        assert!(reloaded.proxy_nodes.values().any(|n| n.name == "HK-Test" && n.protocol == "HTTP"));

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_api_system_and_rule_toggle_move() {
        let mut path = std::env::current_dir().unwrap().join("target");
        path.push(format!("flowx_api_rule_ops_{}.xml", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let store = Arc::new(ConfigStore::new(&path));
        let (rt, _) = store.load_or_init(&[40001, 40080, 1053]).unwrap();
        let rule1_id = rt.rules[0].id;
        let rule2_id = rt.rules[1].id;

        let mgr = Arc::new(ConnectionManager::new());
        let re = Arc::new(RuleEngine::new(rt.rules, rt.default_action));
        let nodes = Arc::new(RwLock::new(rt.proxy_nodes));
        let fake_pool = Arc::new(FakeIpPool::new_default());
        fake_pool.allocate("example.com");

        let sys_ctx = Arc::new(SystemRuntimeContext {
            inbound_addr: "127.0.0.1:40001".parse().unwrap(),
            dns_addr: "127.0.0.1:1053".parse().unwrap(),
            upstream_dns: "223.5.5.5:53".parse().unwrap(),
            api_addr: "127.0.0.1:40080".parse().unwrap(),
            fake_ip_pool: fake_pool,
            started_at: Instant::now(),
        });

        let srv = ApiServer::new("127.0.0.1:0".parse().unwrap(), mgr, Arc::clone(&re), Arc::clone(&nodes))
            .with_self_ports(vec![40001, 40080, 1053])
            .with_config_store(Arc::clone(&store))
            .with_runtime_context(sys_ctx);
        let listener = srv.bind().await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move { srv.run(listener, rx).await });
        let _keep_tx = tx;
        let port = addr.port();

        // 1. 系统信息端点
        let sys_resp = raw_http(
            addr,
            &format!("GET /api/system HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n", port),
        )
        .await;
        assert!(sys_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(sys_resp.contains("\"fake_ip_count\":1"));
        assert!(sys_resp.contains("\"rules_count\":2"));

        // 2. 停用规则 1 并验证持久化
        let toggle_body = format!(r#"{{"id":{},"enabled":false}}"#, rule1_id);
        let toggle_resp = raw_http(
            addr,
            &format!(
                "POST /api/rules/toggle HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\n\r\n{}",
                port,
                toggle_body.len(),
                toggle_body
            ),
        )
        .await;
        assert!(toggle_resp.contains("\"enabled\":false"));

        // 3. 将规则 2 上移到顶部并验证持久化
        let move_body = format!(r#"{{"id":{},"direction":"up"}}"#, rule2_id);
        let move_resp = raw_http(
            addr,
            &format!(
                "POST /api/rules/move HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\n\r\n{}",
                port,
                move_body.len(),
                move_body
            ),
        )
        .await;
        assert!(move_resp.contains("\"moved\":true"));

        let (reloaded, _) = store.load_or_init(&[40001, 40080, 1053]).unwrap();
        assert_eq!(reloaded.rules[0].name, "DevProxy");
        assert_eq!(reloaded.rules[1].name, "LocalBypass");
        assert!(!reloaded.rules[1].enabled);

        let _ = std::fs::remove_file(&path);
    }

    /// P1-1 & P1-3 回归测试：
    /// 1) 节点被 rule_engine.default_action 引用时禁止删除 (409 Conflict)
    /// 2) /api/connections/kill 仅发出终止通知，不提前注销活跃连接
    #[tokio::test]
    async fn test_delete_node_checks_default_action_and_kill_preserves_raii_guard() {
        let mut nodes_map = HashMap::new();
        nodes_map.insert(
            101,
            ProxyNodeEntry {
                id: 101,
                name: "Default-GW".into(),
                protocol: "SOCKS5".into(),
                server_addr: "10.0.0.99:1080".into(),
                username: None,
                client: ProxyNode::Socks5(Socks5Client::new("10.0.0.99:1080")),
            },
        );

        let mgr = Arc::new(ConnectionManager::new());
        let active = mgr.register(
            "app.exe".into(),
            "C:/app.exe".into(),
            4321,
            "example.org:443".into(),
            "Default".into(),
            "Proxy".into(),
            Some(101),
        );

        // 显式规则列表为空，仅 default_action 指向节点 101
        let re = Arc::new(RuleEngine::new(vec![], Action::Proxy(101)));
        let nodes = Arc::new(RwLock::new(nodes_map));

        let srv = ApiServer::new("127.0.0.1:0".parse().unwrap(), Arc::clone(&mgr), re, nodes);
        let listener = srv.bind().await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move { srv.run(listener, rx).await });
        let _keep_tx = tx;
        let port = addr.port();

        // 1. 删除被 default_action 引用的节点必须返回 409 Conflict
        let del_body = r#"{"id":101}"#;
        let del_resp = raw_http(
            addr,
            &format!(
                "DELETE /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\n\r\n{}",
                port,
                del_body.len(),
                del_body
            ),
        )
        .await;
        assert!(
            del_resp.starts_with("HTTP/1.1 409 Conflict"),
            "Node referenced by default_action must not be deleted: {}",
            del_resp
        );

        // 2. 切断活跃连接仅触发 cancel 状态与唤醒通知，由连接守卫负责最终注销
        let kill_body = format!(r#"{{"id":{}}}"#, active.id);
        let kill_resp = raw_http(
            addr,
            &format!(
                "POST /api/connections/kill HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\n\r\n{}",
                port,
                kill_body.len(),
                kill_body
            ),
        )
        .await;
        assert!(kill_resp.contains("\"killed\":true"));
        assert!(active.is_cancelled());
        assert_eq!(mgr.active_count(), 1, "API must not bypass ConnectionGuard to unregister connections early");

        mgr.unregister(active.id);
        assert_eq!(mgr.active_count(), 0);
    }

    #[tokio::test]
    async fn test_api_i18n_negotiation_and_localized_errors() {
        let (addr, _nodes, _re, _shutdown_tx) = spawn_test_api().await;
        let port = addr.port();

        // 1. Accept-Language: zh-CN 返回中文错误与多语言键值
        let bad_proto_body = r#"{"name":"n1","protocol":"UNKNOWN","server_addr":"1.2.3.4:1080"}"#;
        let resp_zh = raw_http(
            addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: zh-CN,zh;q=0.9\r\nContent-Length: {}\r\n\r\n{}",
                port,
                bad_proto_body.len(),
                bad_proto_body
            ),
        )
        .await;
        assert!(resp_zh.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(resp_zh.contains("不支持的代理协议"));
        assert!(resp_zh.contains("\"code\":\"ERR_UNSUPPORTED_PROTOCOL\""));
        assert!(resp_zh.contains("\"key\":\"error.unsupported_protocol\""));

        // 2. Accept-Language: en-US 返回英文错误与多语言键值
        let resp_en = raw_http(
            addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: en-US,en;q=0.9\r\nContent-Length: {}\r\n\r\n{}",
                port,
                bad_proto_body.len(),
                bad_proto_body
            ),
        )
        .await;
        assert!(resp_en.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(resp_en.contains("Unsupported proxy protocol"));
        assert!(resp_en.contains("\"code\":\"ERR_UNSUPPORTED_PROTOCOL\""));
        assert!(resp_en.contains("\"key\":\"error.unsupported_protocol\""));

        // 3. Query 参数 ?lang=zh 覆盖请求头
        let resp_query_zh = raw_http(
            addr,
            &format!(
                "POST /api/nodes?lang=zh HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: en-US\r\nContent-Length: {}\r\n\r\n{}",
                port,
                bad_proto_body.len(),
                bad_proto_body
            ),
        )
        .await;
        assert!(resp_query_zh.contains("不支持的代理协议"));

        // 4. Query 参数 ?lang=en 覆盖请求头
        let resp_query_en = raw_http(
            addr,
            &format!(
                "POST /api/nodes?lang=en HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: zh-CN\r\nContent-Length: {}\r\n\r\n{}",
                port,
                bad_proto_body.len(),
                bad_proto_body
            ),
        )
        .await;
        assert!(resp_query_en.contains("Unsupported proxy protocol"));

        // 5. System API 返回与语言匹配的动作描述
        let sys_zh = raw_http(
            addr,
            &format!("GET /api/system HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: zh-CN\r\n\r\n", port),
        )
        .await;
        assert!(sys_zh.contains("Direct (直连)"));

        let sys_en = raw_http(
            addr,
            &format!("GET /api/system HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: en-US\r\n\r\n", port),
        )
        .await;
        assert!(sys_en.contains("\"default_action\":\"Direct\""));

        // 6. 非法 Content-Length 走本地化 + 机器可读错误码（不再泄漏原始错误串）
        let bad_len_zh = raw_http(
            addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: zh-CN\r\nContent-Length: abc\r\n\r\n",
                port
            ),
        )
        .await;
        assert!(bad_len_zh.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(bad_len_zh.contains("无效的 Content-Length 请求头"));
        assert!(bad_len_zh.contains("\"code\":\"ERR_INVALID_CONTENT_LENGTH\""));
        assert!(bad_len_zh.contains("\"key\":\"error.invalid_content_length\""));

        let bad_len_en = raw_http(
            addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: en-US\r\nContent-Length: abc\r\n\r\n",
                port
            ),
        )
        .await;
        assert!(bad_len_en.contains("Invalid Content-Length header"));
    }

    /// /api/connections 的动作、兜底规则名与未知进程名必须按请求语言本地化，
    /// 同时保留 action_type / action_id 机器字段供前端过滤。
    #[tokio::test]
    async fn test_api_connections_view_is_localized() {
        let mgr = Arc::new(ConnectionManager::new());
        mgr.register(
            "app.exe".into(),
            "C:/app.exe".into(),
            4321,
            "example.org:443".into(),
            crate::router::DEFAULT_RULE_NAME.into(),
            "Proxy".into(),
            Some(101),
        );
        let re = Arc::new(RuleEngine::new(vec![], Action::Direct));
        let nodes = Arc::new(RwLock::new(HashMap::new()));
        let srv = ApiServer::new("127.0.0.1:0".parse().unwrap(), Arc::clone(&mgr), re, nodes);
        let listener = srv.bind().await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move { srv.run(listener, rx).await });
        let _keep_tx = tx;

        let zh = raw_http(
            addr,
            &format!(
                "GET /api/connections HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: zh-CN\r\n\r\n",
                addr.port()
            ),
        )
        .await;
        assert!(zh.contains("Proxy (节点-101)"), "zh action should be localized: {zh}");
        assert!(zh.contains("\"rule_name\":\"默认\""), "zh rule_name should be localized: {zh}");
        assert!(zh.contains("\"action_type\":\"Proxy\""));
        assert!(zh.contains("\"action_id\":101"));

        let en = raw_http(
            addr,
            &format!(
                "GET /api/connections HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: en-US\r\n\r\n",
                addr.port()
            ),
        )
        .await;
        assert!(en.contains("Proxy (Node-101)"), "en action should be localized: {en}");
        assert!(en.contains("\"rule_name\":\"Default\""));
    }
}
