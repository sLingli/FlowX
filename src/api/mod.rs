use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{error, info};

use crate::config::ConfigStore;
use crate::dns::FakeIpPool;
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
            .with_context(|| format!("绑定 HTTP API 服务端口失败 ({})", self.bind_addr))?;
        info!(
            "[API 接口] FlowX 状态与控制 HTTP API 服务已在 http://{} 绑定",
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
                            error!("[API 接口] 接收 HTTP API 请求失败: {}", e);
                            continue;
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    info!("[API 接口] 接收到退出信号，停止接收 API 请求");
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
                    error!("[API 接口] 处理请求超时或异常: {}", e);
                }
            });
        }
        Ok(())
    }
}

async fn read_full_http_request(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(4096);
    let mut temp = [0u8; 2048];

    loop {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&temp[..n]);
        if buffer.len() > MAX_REQUEST_SIZE {
            bail!("HTTP 请求体超出 1MB 上限");
        }

        if let Some(header_end) = find_header_end(&buffer) {
            let header_str = String::from_utf8_lossy(&buffer[..header_end]);
            let content_length = parse_content_length(&header_str)?;
            let total_needed = header_end
                .checked_add(content_length)
                .filter(|&t| t <= MAX_REQUEST_SIZE)
                .context("HTTP 请求体长度超出 1MB 上限")?;
            if buffer.len() >= total_needed {
                buffer.truncate(total_needed);
                break;
            }
        }
    }

    Ok(buffer)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn parse_content_length(headers: &str) -> Result<usize> {
    for line in headers.lines() {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("content-length")
        {
            let len = v
                .trim()
                .parse::<usize>()
                .context("非法的 Content-Length 请求头")?;
            return Ok(len);
        }
    }
    Ok(0)
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
    let req_bytes = match read_full_http_request(&mut stream).await {
        Ok(b) => b,
        Err(e) => {
            let msg = serde_json::json!({ "error": e.to_string() }).to_string();
            send_http_response(&mut stream, "400 Bad Request", "application/json; charset=utf-8", &msg).await?;
            return Ok(());
        }
    };
    if req_bytes.is_empty() {
        return Ok(());
    }

    let Some(header_end) = find_header_end(&req_bytes) else {
        send_http_response(
            &mut stream,
            "400 Bad Request",
            "application/json; charset=utf-8",
            r#"{"error":"HTTP 请求头格式不完整"}"#,
        )
        .await?;
        return Ok(());
    };

    let Ok(header_str) = std::str::from_utf8(&req_bytes[..header_end - 4]) else {
        send_http_response(
            &mut stream,
            "400 Bad Request",
            "application/json; charset=utf-8",
            r#"{"error":"HTTP 请求头包含非 UTF-8 字节"}"#,
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

    // 安全校验 1: Host 头必须为本地回环地址，防止 DNS Rebinding
    let host_ok = extract_header(&headers, "host")
        .is_some_and(|h| is_allowed_host(h, actual_port, false));
    if !host_ok {
        send_http_response(
            &mut stream,
            "403 Forbidden",
            "application/json; charset=utf-8",
            r#"{"error":"非法的 Host 请求头，仅允许本地控制台访问"}"#,
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
            r#"{"error":"拒绝跨源请求 (Origin 校验失败)"}"#,
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
            r#"{"error":"拒绝跨站 API 请求 (Sec-Fetch-Site)"}"#,
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
            r#"{"error":"拒绝跨站变更请求 (Referer 校验失败)"}"#,
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
            );
            ("200 OK", "application/json; charset=utf-8", serde_json_to_string(&info))
        }
        ("GET", "/api/stats") => {
            let stats = monitor.global_stats();
            ("200 OK", "application/json; charset=utf-8", serde_json_to_string(&stats))
        }
        ("GET", "/api/connections") => {
            let list = monitor.list_snapshots();
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
                ("400 Bad Request", "application/json; charset=utf-8", r#"{"error":"缺少连接ID"}"#.to_string())
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
                r#"{"error":"无效的节点请求体"}"#.to_string(),
            ),
            Ok(req) => {
                let res = handle_add_node(req, &proxy_nodes, &self_ports);
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
                        r#"{"error":"节点正被路由规则或默认兜底动作引用，禁止删除。请先修改或删除关联配置"}"#.to_string(),
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
                        ("404 Not Found", "application/json; charset=utf-8", r#"{"error":"代理节点不存在"}"#.to_string())
                    }
                }
            } else {
                ("400 Bad Request", "application/json; charset=utf-8", r#"{"error":"缺少节点ID"}"#.to_string())
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
                    let (ok, ms, msg) = ping_address(&addr).await;
                    let ping_res = PingResponse {
                        ok,
                        latency_ms: ms,
                        message: msg,
                    };
                    ("200 OK", "application/json; charset=utf-8", serde_json_to_string(&ping_res))
                } else {
                    ("404 Not Found", "application/json; charset=utf-8", r#"{"error":"指定的代理节点不存在"}"#.to_string())
                }
            } else {
                ("400 Bad Request", "application/json; charset=utf-8", r#"{"error":"缺少有效的节点 ID"}"#.to_string())
            }
        }
        ("GET", "/api/rules") => {
            let list = rule_engine.list_rules_view();
            ("200 OK", "application/json; charset=utf-8", serde_json_to_string(&list))
        }
        ("POST", "/api/rules") => match serde_json::from_str::<AddRuleRequest>(req_body) {
            Err(_) => (
                "400 Bad Request",
                "application/json; charset=utf-8",
                r#"{"error":"无效的规则请求体"}"#.to_string(),
            ),
            Ok(req) => {
                let res = handle_add_rule(req, &rule_engine, &proxy_nodes);
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
                r#"{"error":"无效的规则启停请求体"}"#.to_string(),
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
                    r#"{"error":"路由规则不存在"}"#.to_string(),
                ),
            },
        },
        ("POST", "/api/rules/move") => match serde_json::from_str::<MoveRuleRequest>(req_body) {
            Err(_) => (
                "400 Bad Request",
                "application/json; charset=utf-8",
                r#"{"error":"无效的规则排序请求体"}"#.to_string(),
            ),
            Ok(req) => {
                if !matches!(
                    req.direction.trim().to_ascii_lowercase().as_str(),
                    "up" | "down" | "top" | "bottom"
                ) {
                    (
                        "400 Bad Request",
                        "application/json; charset=utf-8",
                        r#"{"error":"排序方向仅支持 up / down / top / bottom"}"#.to_string(),
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
                            r#"{"error":"路由规则不存在"}"#.to_string(),
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
                    ("404 Not Found", "application/json; charset=utf-8", r#"{"error":"路由规则不存在"}"#.to_string())
                }
            } else {
                ("400 Bad Request", "application/json; charset=utf-8", r#"{"error":"缺少规则ID"}"#.to_string())
            }
        }
        _ => ("404 Not Found", "application/json; charset=utf-8", r#"{"error":"Not Found"}"#.to_string()),
    };

    send_http_response(&mut stream, status, content_type, &body).await?;
    Ok(())
}

fn handle_add_node(
    req: AddNodeRequest,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    self_ports: &[u16],
) -> (&'static str, &'static str, String) {
    let ct = "application/json; charset=utf-8";
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return ("400 Bad Request", ct, r#"{"error":"节点名称不能为空"}"#.to_string());
    }

    let protocol = req.protocol.trim().to_ascii_uppercase();
    if !matches!(protocol.as_str(), "SOCKS5" | "SOCKS4" | "HTTP") {
        return (
            "400 Bad Request",
            ct,
            r#"{"error":"不支持的代理协议，仅支持 SOCKS5 / SOCKS4 / HTTP"}"#.to_string(),
        );
    }

    let server_addr = req.server_addr.trim().to_string();
    let Ok(target_parsed) = parse_target_addr(&server_addr) else {
        return (
            "400 Bad Request",
            ct,
            r#"{"error":"节点服务器地址格式无效，应为 IP:Port 或 Host:Port"}"#.to_string(),
        );
    };
    if target_parsed.port() == 0 || target_parsed.host_string().is_empty() {
        return (
            "400 Bad Request",
            ct,
            r#"{"error":"节点服务器地址或端口无效"}"#.to_string(),
        );
    }

    if target_parsed.is_loopback_or_unspecified() && self_ports.contains(&target_parsed.port()) {
        return (
            "400 Bad Request",
            ct,
            r#"{"error":"节点地址不能指向 FlowX 自身服务端口"}"#.to_string(),
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
            r#"{"error":"代理用户名包含非法字符或超出 255 字节限制"}"#.to_string(),
        );
    }
    if let Some(p) = &password
        && (p.contains('\r') || p.contains('\n') || p.contains('\0') || p.len() > 255)
    {
        return (
            "400 Bad Request",
            ct,
            r#"{"error":"代理密码包含非法字符或超出 255 字节限制"}"#.to_string(),
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
) -> (&'static str, &'static str, String) {
    let ct = "application/json; charset=utf-8";
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return ("400 Bad Request", ct, r#"{"error":"规则名称不能为空"}"#.to_string());
    }

    let action = match req.action.trim().to_ascii_uppercase().as_str() {
        "DIRECT" => Action::Direct,
        "BLOCK" => Action::Block,
        "PROXY" => {
            let Some(nid) = req.node_id else {
                return (
                    "400 Bad Request",
                    ct,
                    r#"{"error":"Proxy 动作必须指定节点 ID"}"#.to_string(),
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
                    format!(r#"{{"error":"指定的代理节点 #{} 不存在"}}"#, nid),
                );
            }
            Action::Proxy(nid)
        }
        _ => {
            return (
                "400 Bad Request",
                ct,
                r#"{"error":"无效的规则动作，仅支持 Direct / Block / Proxy"}"#.to_string(),
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
            r#"{"error":"应用进程匹配语法无效"}"#.to_string(),
        );
    }
    if targets_clean.is_some()
        && rule.target_subnets.is_none()
        && rule.target_domains.as_ref().is_some_and(Vec::is_empty)
    {
        return (
            "400 Bad Request",
            ct,
            r#"{"error":"目标地址/域名匹配语法无效"}"#.to_string(),
        );
    }
    if ports_clean.is_some() && rule.ports.as_ref().is_some_and(Vec::is_empty) {
        return (
            "400 Bad Request",
            ct,
            r#"{"error":"端口格式无效，请使用如 80; 443; 8000-8080"}"#.to_string(),
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
) -> SystemInfoResponse {
    let nodes_count = proxy_nodes
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .len();
    let rules = rule_engine.current_rules();
    let rules_count = rules.len();
    let enabled_rules_count = rules.iter().filter(|r| r.enabled).count();
    let default_action = match &rule_engine.default_action {
        Action::Direct => "Direct (直连)".to_string(),
        Action::Block => "Block (阻断)".to_string(),
        Action::Proxy(id) => format!("Proxy (节点-{})", id),
        Action::Chain(id) => format!("Chain (链路-{})", id),
    };

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
            .unwrap_or_else(|| "仅内存模式".to_string()),
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
            "[配置中心] 自动持久化配置文件 ({}) 失败: {:#}",
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

async fn ping_address(addr: &str) -> (bool, u64, String) {
    let start = std::time::Instant::now();
    let res = tokio::time::timeout(Duration::from_millis(2000), TcpStream::connect(addr)).await;
    match res {
        Ok(Ok(stream)) => {
            drop(stream);
            let ms = start.elapsed().as_millis() as u64;
            (true, ms, format!("{} ms", ms))
        }
        Ok(Err(e)) => (false, 0, e.to_string()),
        Err(_) => (false, 0, "连接超时 (2000ms)".to_string()),
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
        let mut path = std::env::temp_dir();
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
        let mut path = std::env::temp_dir();
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
            "Proxy(101)".into(),
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
            "被 default_action 引用的节点必须禁止删除: {}",
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
        assert_eq!(mgr.active_count(), 1, "API 不得绕过 ConnectionGuard 提前注销连接");

        mgr.unregister(active.id);
        assert_eq!(mgr.active_count(), 0);
    }
}
