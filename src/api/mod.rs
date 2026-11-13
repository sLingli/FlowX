use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex, Semaphore};
use tracing::{error, info};

use crate::config::ConfigStore;
use crate::dns::FakeIpPool;
use crate::i18n::{json_error, t, Locale};
use crate::interceptor::dispatcher::ProxyNodeEntry;
use crate::monitor::{ConnectionManager, InFlightTracker};
use crate::outbound::chain::{parse_target_addr, ProxyNode};
use crate::outbound::http::HttpConnectClient;
use crate::outbound::socks4::Socks4Client;
use crate::outbound::socks5::Socks5Client;
use crate::outbound::TargetAddr;
use crate::router::{Action, Rule, RuleEngine};

const API_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_SIZE: usize = 1024 * 1024; // 1MB 上限防 DoS
const MAX_API_CONCURRENCY: usize = 128;
const MAX_PING_CONCURRENCY: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyNodeView {
    pub id: u32,
    pub name: String,
    pub protocol: String,
    pub server_addr: String,
    pub auth_configured: bool,
    #[serde(default)]
    pub password_configured: bool,
    pub username: Option<String>,
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
pub struct UpdateNodeRequest {
    pub id: u32,
    pub name: String,
    pub protocol: String,
    pub server_addr: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub keep_password: Option<bool>,
    pub clear_password: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct PatchNodeRequest {
    pub id: u32,
    pub name: Option<String>,
    pub protocol: Option<String>,
    pub server_addr: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub keep_password: Option<bool>,
    pub clear_password: Option<bool>,
    pub clear_username: Option<bool>,
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
pub struct UpdateRuleRequest {
    pub id: u64,
    pub name: String,
    pub apps: Option<String>,
    pub targets: Option<String>,
    pub ports: Option<String>,
    pub action: String, // "Direct", "Block", "Proxy"
    pub node_id: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct PatchRuleRequest {
    pub id: u64,
    pub name: Option<String>,
    pub apps: Option<String>,
    pub targets: Option<String>,
    pub ports: Option<String>,
    pub action: Option<String>,
    pub node_id: Option<u32>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct SetDefaultActionRequest {
    pub action: String, // "Direct", "Block", "Proxy"
    pub node_id: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct SimulateRouteRequest {
    pub process: Option<String>,
    pub target: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateRouteResponse {
    pub matched_rule_id: Option<u64>,
    pub matched_rule_name: String,
    pub is_default: bool,
    pub action: String,
    pub action_type: String,
    pub node_id: Option<u32>,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub target_host: Option<String>,
    pub target_ip: Option<String>,
    pub target_port: u16,
    pub trace: Vec<crate::router::RuleTraceStep>,
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
    pub block_ipv6: bool,
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
    pub default_action_type: String,
    pub default_node_id: Option<u32>,
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
    pub in_flight: Option<Arc<InFlightTracker>>,
    conn_limit: Arc<Semaphore>,
    ping_semaphore: Arc<Semaphore>,
    mutation_lock: Arc<Mutex<()>>,
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
            conn_limit: Arc::new(Semaphore::new(MAX_API_CONCURRENCY)),
            ping_semaphore: Arc::new(Semaphore::new(MAX_PING_CONCURRENCY)),
            mutation_lock: Arc::new(Mutex::new(())),
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

    pub fn with_in_flight(mut self, tracker: Arc<InFlightTracker>) -> Self {
        self.in_flight = Some(tracker);
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

    /// 启动异步 HTTP API 监听服务（支持并发连接限流、任务追踪与优雅停机）
    pub async fn run(&self, listener: TcpListener, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        let actual_port = listener.local_addr().unwrap_or(self.bind_addr).port();
        let mut self_ports = self.self_ports.clone();
        if !self_ports.contains(&actual_port) {
            self_ports.push(actual_port);
        }
        let self_ports = Arc::new(self_ports);

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
                    tokio::spawn(async move {
                        let _in_flight = _in_flight;
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
            let ping_semaphore = Arc::clone(&self.ping_semaphore);
            let mutation_lock = Arc::clone(&self.mutation_lock);
            let started_at = self.started_at;
            let _in_flight = self.in_flight.as_ref().map(|t| t.enter());

            tokio::spawn(async move {
                let _permit = permit;
                let _in_flight = _in_flight;
                if let Err(e) = handle_api_request(
                    stream,
                    actual_port,
                    self_ports_clone,
                    monitor,
                    rule_engine,
                    proxy_nodes,
                    config_store,
                    runtime_context,
                    ping_semaphore,
                    mutation_lock,
                    started_at,
                )
                .await
                {
                    error!("[API] Request processing failed: {}", e);
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
    read_full_http_request_with_timeout(stream, buffer, API_TIMEOUT).await
}

async fn read_full_http_request_with_timeout(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    timeout: Duration,
) -> std::result::Result<(), RequestReadError> {
    let read_fut = async {
        buffer.clear();
        let mut temp = [0u8; 2048];
        let mut expected_total: Option<usize> = None;

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
                if buffer.is_empty() {
                    return Ok(());
                }
                return Err(RequestReadError::IncompleteHeaders);
            }
            buffer.extend_from_slice(&temp[..n]);
            if buffer.len() > MAX_REQUEST_SIZE {
                return Err(RequestReadError::TooLarge);
            }

            if expected_total.is_none()
                && let Some(header_end) = find_header_end(buffer)
            {
                let content_length = validate_and_parse_headers(&buffer[..header_end - 4])?;
                let total_needed = header_end
                    .checked_add(content_length)
                    .filter(|&t| t <= MAX_REQUEST_SIZE)
                    .ok_or(RequestReadError::TooLarge)?;
                expected_total = Some(total_needed);
            }

            if let Some(total_needed) = expected_total
                && buffer.len() >= total_needed
            {
                buffer.truncate(total_needed);
                break;
            }
        }

        Ok(())
    };

    tokio::time::timeout(timeout, read_fut)
        .await
        .map_err(|_| RequestReadError::TimedOut)?
}

/// HTTP 请求读取阶段的可分类错误，用于生成本地化且机器可读的错误响应。
#[derive(Debug)]
enum RequestReadError {
    /// 请求体（含头部）超过 1MB 上限
    TooLarge,
    /// 请求头不完整、含早期 EOF 或缺少 \r\n\r\n
    IncompleteHeaders,
    /// 请求头包含非 UTF-8 字节
    NonUtf8Headers,
    /// HTTP 换行、obs-fold 或字段名不合法
    InvalidFraming,
    /// 不支持 Transfer-Encoding 请求传输编码
    UnsupportedTransferEncoding,
    /// 敏感请求头重复（Host / Content-Length / Origin / Referer / Sec-Fetch-Site / Content-Type）
    DuplicateHeader,
    /// `Content-Length` 请求头格式非法
    InvalidContentLength,
    /// 请求读取阶段超时
    TimedOut,
    /// 底层套接字读取失败（原始错误已记入 debug 日志）
    Io,
}

impl RequestReadError {
    fn http_status(&self) -> &'static str {
        match self {
            RequestReadError::TooLarge => "413 Payload Too Large",
            RequestReadError::UnsupportedTransferEncoding => "501 Not Implemented",
            RequestReadError::TimedOut => "408 Request Timeout",
            _ => "400 Bad Request",
        }
    }

    /// 返回（错误码, i18n 键）
    fn code_and_key(&self) -> (&'static str, &'static str) {
        match self {
            RequestReadError::TooLarge => ("ERR_REQUEST_TOO_LARGE", "error.request_too_large"),
            RequestReadError::IncompleteHeaders => ("ERR_INCOMPLETE_HEADERS", "error.incomplete_headers"),
            RequestReadError::NonUtf8Headers => ("ERR_NON_UTF8_HEADERS", "error.non_utf8_headers"),
            RequestReadError::InvalidFraming => ("ERR_INVALID_REQUEST_FRAMING", "error.invalid_request_framing"),
            RequestReadError::UnsupportedTransferEncoding => {
                ("ERR_UNSUPPORTED_TE", "error.unsupported_transfer_encoding")
            }
            RequestReadError::DuplicateHeader => ("ERR_DUPLICATE_HEADER", "error.duplicate_header"),
            RequestReadError::InvalidContentLength => {
                ("ERR_INVALID_CONTENT_LENGTH", "error.invalid_content_length")
            }
            RequestReadError::TimedOut => ("ERR_REQUEST_TIMEOUT", "error.request_timeout"),
            RequestReadError::Io => ("ERR_REQUEST_READ_FAILED", "error.request_read_failed"),
        }
    }
}

fn is_http_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

/// 严格校验原始请求头：拒绝 NUL、裸 CR/LF、obs-fold、畸形字段名、Transfer-Encoding 与重复敏感头，并解析 Content-Length。
fn validate_and_parse_headers(raw_head: &[u8]) -> std::result::Result<usize, RequestReadError> {
    if raw_head.contains(&0) {
        return Err(RequestReadError::InvalidFraming);
    }

    let mut lines = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < raw_head.len() {
        if raw_head[i] == b'\n' {
            return Err(RequestReadError::InvalidFraming);
        }
        if raw_head[i] == b'\r' {
            if i + 1 >= raw_head.len() || raw_head[i + 1] != b'\n' {
                return Err(RequestReadError::InvalidFraming);
            }
            lines.push(&raw_head[start..i]);
            i += 2;
            start = i;
            continue;
        }
        i += 1;
    }
    lines.push(&raw_head[start..]);

    if lines.is_empty() || lines[0].is_empty() {
        return Err(RequestReadError::InvalidFraming);
    }
    if std::str::from_utf8(lines[0]).is_err() {
        return Err(RequestReadError::NonUtf8Headers);
    }

    let mut content_length: Option<usize> = None;
    let mut host_seen = false;
    let mut origin_seen = false;
    let mut referer_seen = false;
    let mut fetch_site_seen = false;
    let mut content_type_seen = false;

    for line in &lines[1..] {
        if line.is_empty() || line[0] == b' ' || line[0] == b'\t' {
            return Err(RequestReadError::InvalidFraming);
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return Err(RequestReadError::InvalidFraming);
        };
        let name = &line[..colon];
        if name.is_empty() || !name.iter().all(|&b| is_http_token_byte(b)) {
            return Err(RequestReadError::InvalidFraming);
        }
        let val_bytes = &line[colon + 1..];
        if val_bytes.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err(RequestReadError::InvalidFraming);
        }
        let Ok(val) = std::str::from_utf8(val_bytes) else {
            return Err(RequestReadError::NonUtf8Headers);
        };

        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err(RequestReadError::UnsupportedTransferEncoding);
        } else if name.eq_ignore_ascii_case(b"content-length") {
            if content_length.is_some() {
                return Err(RequestReadError::DuplicateHeader);
            }
            let trimmed = val.trim_matches(|c| c == ' ' || c == '\t');
            if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
                return Err(RequestReadError::InvalidContentLength);
            }
            let parsed = trimmed
                .parse::<usize>()
                .map_err(|_| RequestReadError::InvalidContentLength)?;
            content_length = Some(parsed);
        } else if name.eq_ignore_ascii_case(b"host") {
            if host_seen {
                return Err(RequestReadError::DuplicateHeader);
            }
            host_seen = true;
        } else if name.eq_ignore_ascii_case(b"origin") {
            if origin_seen {
                return Err(RequestReadError::DuplicateHeader);
            }
            origin_seen = true;
        } else if name.eq_ignore_ascii_case(b"referer") {
            if referer_seen {
                return Err(RequestReadError::DuplicateHeader);
            }
            referer_seen = true;
        } else if name.eq_ignore_ascii_case(b"sec-fetch-site") {
            if fetch_site_seen {
                return Err(RequestReadError::DuplicateHeader);
            }
            fetch_site_seen = true;
        } else if name.eq_ignore_ascii_case(b"content-type") {
            if content_type_seen {
                return Err(RequestReadError::DuplicateHeader);
            }
            content_type_seen = true;
        }
    }

    Ok(content_length.unwrap_or(0))
}

fn has_json_content_type(headers: &[&str]) -> bool {
    extract_header(headers, "content-type").is_some_and(|ct| {
        ct.split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/json")
    })
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
    ping_semaphore: Arc<Semaphore>,
    mutation_lock: Arc<Mutex<()>>,
    started_at: Instant,
) -> Result<()> {
    let mut req_bytes = Vec::with_capacity(4096);
    if let Err(e) = read_full_http_request(&mut stream, &mut req_bytes).await {
        let (code, key) = e.code_and_key();
        let msg = json_error(best_effort_locale(&req_bytes), code, key);
        send_http_response(&mut stream, e.http_status(), "application/json; charset=utf-8", &msg).await?;
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

    let mut line_parts = first_line.split(' ');
    let (Some(method), Some(path_and_query), Some(version), None) = (
        line_parts.next(),
        line_parts.next(),
        line_parts.next(),
        line_parts.next(),
    ) else {
        send_http_response(
            &mut stream,
            "400 Bad Request",
            "application/json; charset=utf-8",
            &json_error(locale, "ERR_INVALID_REQUEST_LINE", "error.invalid_request_line"),
        )
        .await?;
        return Ok(());
    };
    if method.is_empty()
        || !method.bytes().all(is_http_token_byte)
        || path_and_query.is_empty()
        || !matches!(version, "HTTP/1.1" | "HTTP/1.0")
    {
        send_http_response(
            &mut stream,
            "400 Bad Request",
            "application/json; charset=utf-8",
            &json_error(locale, "ERR_INVALID_REQUEST_LINE", "error.invalid_request_line"),
        )
        .await?;
        return Ok(());
    }
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
    let requires_json_ct = matches!(
        (method, path),
        ("POST" | "PUT" | "PATCH", "/api/nodes" | "/api/rules")
            | (
                "POST",
                "/api/rules/default"
                    | "/api/rules/simulate"
                    | "/api/rules/toggle"
                    | "/api/rules/move"
            )
    ) || (matches!(
        (method, path),
        ("POST", "/api/connections/kill" | "/api/nodes/ping") | ("DELETE", "/api/nodes" | "/api/rules")
    ) && (!body_bytes.is_empty() || parse_query_param(query, "id").is_none()));
    if requires_json_ct && !has_json_content_type(&headers) {
        send_http_response(
            &mut stream,
            "415 Unsupported Media Type",
            "application/json; charset=utf-8",
            &json_error(locale, "ERR_UNSUPPORTED_MEDIA_TYPE", "error.unsupported_media_type"),
        )
        .await?;
        return Ok(());
    }

    let is_mutation = matches!(
        (method, path),
        ("POST" | "PUT" | "PATCH" | "DELETE", "/api/nodes")
            | ("POST" | "PUT" | "PATCH" | "DELETE", "/api/rules")
            | (
                "POST",
                "/api/rules/default" | "/api/rules/toggle" | "/api/rules/move"
            )
    );
    let _mutation_guard = if is_mutation {
        Some(mutation_lock.lock().await)
    } else {
        None
    };

    let live_proxy_nodes = Arc::clone(&proxy_nodes);
    let live_rule_engine = Arc::clone(&rule_engine);
    let (proxy_nodes, rule_engine) = if is_mutation {
        let nodes_copy = live_proxy_nodes
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let (rules_copy, default_copy) = live_rule_engine.snapshot_state();
        (
            Arc::new(RwLock::new(nodes_copy)),
            Arc::new(RuleEngine::new(rules_copy, default_copy)),
        )
    } else {
        (Arc::clone(&live_proxy_nodes), Arc::clone(&live_rule_engine))
    };

    let req_body = std::str::from_utf8(body_bytes).unwrap_or("");
    let mut should_persist = false;

    let (mut status, mut content_type, mut body) = match (method, path) {
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
                    password_configured: n.client.auth_credentials().1.is_some(),
                    username: n.username.clone(),
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
                    should_persist = true;
                }
                res
            }
        },
        ("PUT", "/api/nodes") => match serde_json::from_str::<UpdateNodeRequest>(req_body) {
            Err(_) => (
                "400 Bad Request",
                "application/json; charset=utf-8",
                json_error(locale, "ERR_INVALID_NODE_BODY", "error.invalid_node_body"),
            ),
            Ok(req) => {
                let res = handle_update_node(req, &proxy_nodes, &self_ports, locale);
                if res.0 == "200 OK" {
                    should_persist = true;
                }
                res
            }
        },
        ("PATCH", "/api/nodes") => match serde_json::from_str::<PatchNodeRequest>(req_body) {
            Err(_) => (
                "400 Bad Request",
                "application/json; charset=utf-8",
                json_error(locale, "ERR_INVALID_NODE_BODY", "error.invalid_node_body"),
            ),
            Ok(req) => {
                let res = handle_patch_node(req, &proxy_nodes, &self_ports, locale);
                if res.0 == "200 OK" {
                    should_persist = true;
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
                let current_default = rule_engine.default_action();
                let is_referenced = rules.iter().any(|r| match &r.action {
                    Action::Proxy(pid) => *pid == node_id,
                    _ => false,
                }) || matches!(current_default, Action::Proxy(pid) if pid == node_id);
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
                        should_persist = true;
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
                    let (ok, ms, msg, detail) = ping_address_with_context(
                        &addr,
                        &self_ports,
                        runtime_context.as_deref(),
                        Some(&ping_semaphore),
                        locale,
                    )
                    .await;
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
                    should_persist = true;
                }
                res
            }
        },
        ("PUT", "/api/rules") => match serde_json::from_str::<UpdateRuleRequest>(req_body) {
            Err(_) => (
                "400 Bad Request",
                "application/json; charset=utf-8",
                json_error(locale, "ERR_INVALID_RULE_BODY", "error.invalid_rule_body"),
            ),
            Ok(req) => {
                let res = handle_update_rule(req, &rule_engine, &proxy_nodes, locale);
                if res.0 == "200 OK" {
                    should_persist = true;
                }
                res
            }
        },
        ("PATCH", "/api/rules") => match serde_json::from_str::<PatchRuleRequest>(req_body) {
            Err(_) => (
                "400 Bad Request",
                "application/json; charset=utf-8",
                json_error(locale, "ERR_INVALID_RULE_BODY", "error.invalid_rule_body"),
            ),
            Ok(req) => {
                let res = handle_patch_rule(req, &rule_engine, &proxy_nodes, locale);
                if res.0 == "200 OK" {
                    should_persist = true;
                }
                res
            }
        },
        ("POST", "/api/rules/default") => {
            match serde_json::from_str::<SetDefaultActionRequest>(req_body) {
                Err(_) => (
                    "400 Bad Request",
                    "application/json; charset=utf-8",
                    json_error(
                        locale,
                        "ERR_INVALID_DEFAULT_ACTION_BODY",
                        "error.invalid_default_action_body",
                    ),
                ),
                Ok(req) => {
                    let res = handle_set_default_action(req, &rule_engine, &proxy_nodes, locale);
                    if res.0 == "200 OK" {
                        should_persist = true;
                    }
                    res
                }
            }
        }
        ("POST", "/api/rules/simulate") => {
            match serde_json::from_str::<SimulateRouteRequest>(req_body) {
                Err(_) => (
                    "400 Bad Request",
                    "application/json; charset=utf-8",
                    json_error(
                        locale,
                        "ERR_INVALID_SIMULATE_BODY",
                        "error.invalid_simulate_body",
                    ),
                ),
                Ok(req) => handle_simulate_route_with_pool(
                    req,
                    &rule_engine,
                    runtime_context.as_deref().map(|c| c.fake_ip_pool.as_ref()),
                    locale,
                ),
            }
        }
        ("POST", "/api/rules/toggle") => match serde_json::from_str::<ToggleRuleRequest>(req_body) {
            Err(_) => (
                "400 Bad Request",
                "application/json; charset=utf-8",
                json_error(locale, "ERR_INVALID_TOGGLE_BODY", "error.invalid_toggle_body"),
            ),
            Ok(req) => match rule_engine.toggle_rule(req.id, req.enabled) {
                Some(enabled) => {
                    should_persist = true;
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
                                should_persist = true;
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
                    should_persist = true;
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

    if should_persist {
        let mut persisted_ok = true;
        if let Some(store) = config_store.as_ref()
            && let Err(e) = persist_config_async(Arc::clone(store), &proxy_nodes, &rule_engine).await
        {
            error!(
                "[API] Failed to write updated config to disk, aborting commit: {:#}",
                e
            );
            status = "500 Internal Server Error";
            content_type = "application/json; charset=utf-8";
            body = json_error(
                locale,
                "ERR_CONFIG_PERSIST_FAILED",
                "error.config_persist_failed",
            );
            persisted_ok = false;
        }
        if persisted_ok {
            let committed_nodes =
                std::mem::take(&mut *proxy_nodes.write().unwrap_or_else(|e| e.into_inner()));
            {
                let mut live_nodes = live_proxy_nodes.write().unwrap_or_else(|e| e.into_inner());
                *live_nodes = committed_nodes;
            }
            let (committed_rules, committed_default) = rule_engine.snapshot_state();
            live_rule_engine.restore_state(committed_rules, committed_default);
        }
    }

    send_http_response(&mut stream, status, content_type, &body).await?;
    Ok(())
}

#[allow(clippy::type_complexity)]
fn validate_node_base(
    name_raw: &str,
    protocol_raw: &str,
    server_addr_raw: &str,
    username_raw: Option<String>,
    explicit_password: Option<String>,
    self_ports: &[u16],
    locale: Locale,
) -> std::result::Result<(String, String, String, Option<String>, Option<String>), (&'static str, &'static str, String)> {
    let ct = "application/json; charset=utf-8";
    let name = name_raw.trim().to_string();
    if name.is_empty() {
        return Err((
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_EMPTY_NODE_NAME", "error.empty_node_name"),
        ));
    }

    let protocol = protocol_raw.trim().to_ascii_uppercase();
    if !matches!(protocol.as_str(), "SOCKS5" | "SOCKS4" | "HTTP") {
        return Err((
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_UNSUPPORTED_PROTOCOL", "error.unsupported_protocol"),
        ));
    }

    let server_addr = server_addr_raw.trim().to_string();
    let Ok(target_parsed) = parse_target_addr(&server_addr) else {
        return Err((
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_INVALID_NODE_ADDR", "error.invalid_node_addr"),
        ));
    };
    if target_parsed.port() == 0 || target_parsed.host_string().is_empty() {
        return Err((
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_INVALID_NODE_PORT", "error.invalid_node_port"),
        ));
    }

    match &target_parsed {
        crate::outbound::TargetAddr::Ip(sa) => {
            if let Some(violation) = crate::outbound::direct::check_direct_ips_violation(
                &[sa.ip()],
                sa.port(),
                self_ports,
                None,
            ) {
                let (code, key) = match violation {
                    crate::outbound::direct::DirectIpViolation::FakeIp(_) => {
                        ("ERR_NODE_FAKE_IP", "error.node_fake_ip")
                    }
                    crate::outbound::direct::DirectIpViolation::SelfLoop(_) => {
                        ("ERR_NODE_SELF_LOOP", "error.node_self_loop")
                    }
                };
                return Err(("400 Bad Request", ct, json_error(locale, code, key)));
            }
        }
        crate::outbound::TargetAddr::Domain(_, port) => {
            if target_parsed.is_loopback_or_unspecified() && self_ports.contains(port) {
                return Err((
                    "400 Bad Request",
                    ct,
                    json_error(locale, "ERR_NODE_SELF_LOOP", "error.node_self_loop"),
                ));
            }
        }
    }

    let username = username_raw
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty());

    if let Some(u) = &username {
        if u.contains('\r') || u.contains('\n') || u.contains('\0') || u.len() > 255 {
            return Err((
                "400 Bad Request",
                ct,
                json_error(locale, "ERR_INVALID_USERNAME", "error.invalid_username"),
            ));
        }
        if protocol == "HTTP" && u.contains(':') {
            return Err((
                "400 Bad Request",
                ct,
                json_error(locale, "ERR_HTTP_USERNAME_COLON", "error.http_username_colon"),
            ));
        }
    }

    if let Some(p) = &explicit_password {
        if p.contains('\r') || p.contains('\n') || p.contains('\0') || p.len() > 255 {
            return Err((
                "400 Bad Request",
                ct,
                json_error(locale, "ERR_INVALID_PASSWORD", "error.invalid_password"),
            ));
        }
        if protocol != "SOCKS4" && username.is_none() && !p.is_empty() {
            return Err((
                "400 Bad Request",
                ct,
                json_error(
                    locale,
                    "ERR_PASSWORD_WITHOUT_USERNAME",
                    "error.password_without_username",
                ),
            ));
        }
    }

    Ok((name, protocol, server_addr, username, explicit_password))
}

fn build_proxy_client(
    protocol: &str,
    server_addr: &str,
    username: &Option<String>,
    password: &Option<String>,
) -> ProxyNode {
    match protocol {
        "HTTP" => {
            let mut c = HttpConnectClient::new(server_addr);
            if let (Some(u), Some(p)) = (username, password) {
                c = c.with_auth(u.clone(), p.clone());
            }
            ProxyNode::Http(c)
        }
        "SOCKS4" => {
            let mut c = Socks4Client::new(server_addr);
            if let Some(u) = username {
                c = c.with_user_id(u.clone());
            }
            ProxyNode::Socks4(c)
        }
        _ => {
            let mut c = Socks5Client::new(server_addr);
            if let (Some(u), Some(p)) = (username, password) {
                c = c.with_auth(u.clone(), p.clone());
            }
            ProxyNode::Socks5(c)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_updated_password(
    protocol: &str,
    username: &Option<String>,
    existing_username: &Option<String>,
    existing_password: Option<String>,
    explicit_password: Option<String>,
    keep_password: Option<bool>,
    default_keep_when_omitted: bool,
    clear_password: Option<bool>,
    locale: Locale,
) -> std::result::Result<Option<String>, (&'static str, &'static str, String)> {
    let ct = "application/json; charset=utf-8";
    let explicit_empty = explicit_password.as_deref() == Some("");
    let explicit_non_empty = explicit_password.filter(|p| !p.is_empty());

    if clear_password == Some(true) && (keep_password == Some(true) || explicit_non_empty.is_some()) {
        return Err((
            "400 Bad Request",
            ct,
            json_error(
                locale,
                "ERR_CONFLICTING_PASSWORD_OPTIONS",
                "error.conflicting_password_options",
            ),
        ));
    }
    if explicit_empty && (keep_password == Some(true) || clear_password == Some(false)) {
        return Err((
            "400 Bad Request",
            ct,
            json_error(
                locale,
                "ERR_CONFLICTING_PASSWORD_OPTIONS",
                "error.conflicting_password_options",
            ),
        ));
    }

    if protocol == "SOCKS4" {
        if explicit_non_empty.is_some()
            || (keep_password == Some(true) && clear_password != Some(true))
        {
            return Err((
                "400 Bad Request",
                ct,
                json_error(
                    locale,
                    "ERR_SOCKS4_PASSWORD_UNSUPPORTED",
                    "error.socks4_password_unsupported",
                ),
            ));
        }
        return Ok(None);
    }

    if username.is_none() {
        return Ok(None);
    }

    if clear_password == Some(true) || explicit_empty {
        return Ok(None);
    }
    if explicit_non_empty.is_some() {
        return Ok(explicit_non_empty);
    }
    if keep_password == Some(false) {
        return Ok(None);
    }

    if keep_password.unwrap_or(default_keep_when_omitted) {
        if username != existing_username && existing_password.is_some() {
            return Err((
                "400 Bad Request",
                ct,
                json_error(
                    locale,
                    "ERR_PASSWORD_REQUIRED_ON_USER_CHANGE",
                    "error.password_required_on_user_change",
                ),
            ));
        }
        return Ok(existing_password);
    }

    Ok(None)
}

pub(crate) fn handle_add_node(
    req: AddNodeRequest,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    self_ports: &[u16],
    locale: Locale,
) -> (&'static str, &'static str, String) {
    let ct = "application/json; charset=utf-8";
    let (name, protocol, server_addr, username, explicit_password) = match validate_node_base(
        &req.name,
        &req.protocol,
        &req.server_addr,
        req.username,
        req.password,
        self_ports,
        locale,
    ) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    if protocol == "SOCKS4" && explicit_password.is_some() {
        return (
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_SOCKS4_PASSWORD_UNSUPPORTED", "error.socks4_password_unsupported"),
        );
    }
    if explicit_password.as_deref() == Some("") {
        return (
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_EMPTY_PASSWORD", "error.empty_password"),
        );
    }
    let password = explicit_password;

    let client = build_proxy_client(&protocol, &server_addr, &username, &password);
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

pub(crate) fn handle_update_node(
    req: UpdateNodeRequest,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    self_ports: &[u16],
    locale: Locale,
) -> (&'static str, &'static str, String) {
    let ct = "application/json; charset=utf-8";
    let (name, protocol, server_addr, username, explicit_password) = match validate_node_base(
        &req.name,
        &req.protocol,
        &req.server_addr,
        req.username,
        req.password,
        self_ports,
        locale,
    ) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let mut nodes_guard = proxy_nodes.write().unwrap_or_else(|e| e.into_inner());
    let Some(existing) = nodes_guard.get(&req.id) else {
        return (
            "404 Not Found",
            ct,
            json_error(locale, "ERR_NODE_NOT_FOUND", "error.node_not_found"),
        );
    };

    let existing_password = existing.client.auth_credentials().1.map(ToString::to_string);
    let password = match resolve_updated_password(
        &protocol,
        &username,
        &existing.username,
        existing_password,
        explicit_password,
        req.keep_password,
        false,
        req.clear_password,
        locale,
    ) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    let client = build_proxy_client(&protocol, &server_addr, &username, &password);
    nodes_guard.insert(
        req.id,
        ProxyNodeEntry {
            id: req.id,
            name,
            protocol,
            server_addr,
            username,
            client,
        },
    );
    ("200 OK", ct, format!(r#"{{"ok":true,"id":{}}}"#, req.id))
}

pub(crate) fn handle_patch_node(
    req: PatchNodeRequest,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    self_ports: &[u16],
    locale: Locale,
) -> (&'static str, &'static str, String) {
    let ct = "application/json; charset=utf-8";
    let mut nodes_guard = proxy_nodes.write().unwrap_or_else(|e| e.into_inner());
    let Some(existing) = nodes_guard.get(&req.id).cloned() else {
        return (
            "404 Not Found",
            ct,
            json_error(locale, "ERR_NODE_NOT_FOUND", "error.node_not_found"),
        );
    };

    let name_raw = req.name.unwrap_or_else(|| existing.name.clone());
    let protocol_raw = req.protocol.unwrap_or_else(|| existing.protocol.clone());
    let server_addr_raw = req.server_addr.unwrap_or_else(|| existing.server_addr.clone());
    let username_raw = if req.clear_username == Some(true) {
        None
    } else if req.username.is_some() {
        req.username
    } else {
        existing.username.clone()
    };

    let (name, protocol, server_addr, username, explicit_password) = match validate_node_base(
        &name_raw,
        &protocol_raw,
        &server_addr_raw,
        username_raw,
        req.password,
        self_ports,
        locale,
    ) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let existing_password = existing.client.auth_credentials().1.map(ToString::to_string);
    let password = match resolve_updated_password(
        &protocol,
        &username,
        &existing.username,
        existing_password,
        explicit_password,
        req.keep_password,
        true,
        req.clear_password,
        locale,
    ) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    let client = build_proxy_client(&protocol, &server_addr, &username, &password);
    nodes_guard.insert(
        req.id,
        ProxyNodeEntry {
            id: req.id,
            name,
            protocol,
            server_addr,
            username,
            client,
        },
    );
    ("200 OK", ct, format!(r#"{{"ok":true,"id":{}}}"#, req.id))
}

fn parse_and_validate_action(
    action_raw: &str,
    node_id: Option<u32>,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    locale: Locale,
) -> std::result::Result<Action, (&'static str, &'static str, String)> {
    let ct = "application/json; charset=utf-8";
    match action_raw.trim().to_ascii_uppercase().as_str() {
        "DIRECT" => Ok(Action::Direct),
        "BLOCK" => Ok(Action::Block),
        "PROXY" => {
            let Some(nid) = node_id else {
                return Err((
                    "400 Bad Request",
                    ct,
                    json_error(
                        locale,
                        "ERR_MISSING_NODE_FOR_PROXY",
                        "error.missing_node_id_for_proxy",
                    ),
                ));
            };
            let exists = {
                let nodes_guard = proxy_nodes.read().unwrap_or_else(|e| e.into_inner());
                nodes_guard.contains_key(&nid)
            };
            if !exists {
                return Err((
                    "400 Bad Request",
                    ct,
                    json_error(locale, "ERR_NODE_NOT_FOUND", "error.node_not_found"),
                ));
            }
            Ok(Action::Proxy(nid))
        }
        _ => Err((
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_INVALID_RULE_ACTION", "error.invalid_rule_action"),
        )),
    }
}

fn validate_rule_probe(
    rule: &Rule,
    apps_clean: Option<&str>,
    targets_clean: Option<&str>,
    ports_clean: Option<&str>,
    locale: Locale,
) -> std::result::Result<(), (&'static str, &'static str, String)> {
    let ct = "application/json; charset=utf-8";
    if apps_clean.is_some()
        && rule.application_patterns.as_ref().is_some_and(Vec::is_empty)
    {
        return Err((
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_INVALID_APP_PATTERN", "error.invalid_app_pattern"),
        ));
    }
    if targets_clean.is_some()
        && rule.target_subnets.is_none()
        && rule.target_domains.as_ref().is_some_and(Vec::is_empty)
    {
        return Err((
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_INVALID_TARGET_PATTERN", "error.invalid_target_pattern"),
        ));
    }
    if ports_clean.is_some() && rule.ports.as_ref().is_some_and(Vec::is_empty) {
        return Err((
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_INVALID_PORT_FORMAT", "error.invalid_port_format"),
        ));
    }
    Ok(())
}

pub(crate) fn handle_add_rule(
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

    let action = match parse_and_validate_action(&req.action, req.node_id, proxy_nodes, locale) {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let apps_clean = req.apps.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let targets_clean = req.targets.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let ports_clean = req.ports.as_deref().map(str::trim).filter(|s| !s.is_empty());

    let rule = Rule::from_raw(name, true, apps_clean, targets_clean, ports_clean, action);
    if let Err(resp) = validate_rule_probe(&rule, apps_clean, targets_clean, ports_clean, locale) {
        return resp;
    }

    let id = rule.id;
    rule_engine.add_rule(rule);
    ("200 OK", ct, format!(r#"{{"ok":true,"id":{}}}"#, id))
}

pub(crate) fn handle_update_rule(
    req: UpdateRuleRequest,
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

    let action = match parse_and_validate_action(&req.action, req.node_id, proxy_nodes, locale) {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let apps_clean = req.apps.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let targets_clean = req.targets.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let ports_clean = req.ports.as_deref().map(str::trim).filter(|s| !s.is_empty());

    let probe = Rule::from_raw_with_id(
        req.id,
        &name,
        true,
        apps_clean,
        targets_clean,
        ports_clean,
        action.clone(),
    );
    if let Err(resp) = validate_rule_probe(&probe, apps_clean, targets_clean, ports_clean, locale) {
        return resp;
    }

    match rule_engine.update_rule(req.id, name, apps_clean, targets_clean, ports_clean, action) {
        Some(updated) => ("200 OK", ct, format!(r#"{{"ok":true,"id":{}}}"#, updated.id)),
        None => (
            "404 Not Found",
            ct,
            json_error(locale, "ERR_RULE_NOT_FOUND", "error.rule_not_found"),
        ),
    }
}

pub(crate) fn handle_patch_rule(
    req: PatchRuleRequest,
    rule_engine: &RuleEngine,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    locale: Locale,
) -> (&'static str, &'static str, String) {
    let ct = "application/json; charset=utf-8";
    let Some(existing) = rule_engine.current_rules().iter().find(|r| r.id == req.id).cloned() else {
        return (
            "404 Not Found",
            ct,
            json_error(locale, "ERR_RULE_NOT_FOUND", "error.rule_not_found"),
        );
    };

    let name = req.name.map(|s| s.trim().to_string()).unwrap_or_else(|| existing.name.clone());
    if name.is_empty() {
        return (
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_EMPTY_RULE_NAME", "error.empty_rule_name"),
        );
    }

    let action = if let Some(act_str) = req.action.as_deref() {
        let effective_node_id = req.node_id.or_else(|| match existing.action {
            Action::Proxy(id) if act_str.trim().eq_ignore_ascii_case("Proxy") => Some(id),
            _ => None,
        });
        match parse_and_validate_action(act_str, effective_node_id, proxy_nodes, locale) {
            Ok(a) => a,
            Err(resp) => return resp,
        }
    } else if let Some(nid) = req.node_id {
        if matches!(existing.action, Action::Proxy(_)) {
            match parse_and_validate_action("Proxy", Some(nid), proxy_nodes, locale) {
                Ok(a) => a,
                Err(resp) => return resp,
            }
        } else {
            return (
                "400 Bad Request",
                ct,
                json_error(locale, "ERR_INVALID_RULE_ACTION", "error.invalid_rule_action"),
            );
        }
    } else {
        existing.action.clone()
    };

    let apps_clean_owned: Option<String> = match req.apps {
        Some(v) => Some(v.trim().to_string()).filter(|s| !s.is_empty()),
        None => Some(existing.apps_raw.trim().to_string()).filter(|s| !s.is_empty()),
    };
    let targets_clean_owned: Option<String> = match req.targets {
        Some(v) => Some(v.trim().to_string()).filter(|s| !s.is_empty()),
        None => Some(existing.targets_raw.trim().to_string()).filter(|s| !s.is_empty()),
    };
    let ports_clean_owned: Option<String> = match req.ports {
        Some(v) => Some(v.trim().to_string()).filter(|s| !s.is_empty()),
        None => Some(existing.ports_raw.trim().to_string()).filter(|s| !s.is_empty()),
    };

    let apps_clean = apps_clean_owned.as_deref();
    let targets_clean = targets_clean_owned.as_deref();
    let ports_clean = ports_clean_owned.as_deref();

    let probe = Rule::from_raw_with_id(
        req.id,
        &name,
        req.enabled.unwrap_or(existing.enabled),
        apps_clean,
        targets_clean,
        ports_clean,
        action.clone(),
    );
    if let Err(resp) = validate_rule_probe(&probe, apps_clean, targets_clean, ports_clean, locale) {
        return resp;
    }

    match rule_engine.update_rule_with_enabled(
        req.id,
        name,
        apps_clean,
        targets_clean,
        ports_clean,
        action,
        req.enabled,
    ) {
        Some(updated) => ("200 OK", ct, format!(r#"{{"ok":true,"id":{}}}"#, updated.id)),
        None => (
            "404 Not Found",
            ct,
            json_error(locale, "ERR_RULE_NOT_FOUND", "error.rule_not_found"),
        ),
    }
}

pub(crate) fn handle_set_default_action(
    req: SetDefaultActionRequest,
    rule_engine: &RuleEngine,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    locale: Locale,
) -> (&'static str, &'static str, String) {
    let ct = "application/json; charset=utf-8";
    let action = match parse_and_validate_action(&req.action, req.node_id, proxy_nodes, locale) {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    rule_engine.set_default_action(action.clone());
    let resp = serde_json::json!({
        "ok": true,
        "default_action": crate::router::format_action_desc(&action, locale),
        "default_action_type": action.type_str(),
        "default_node_id": action.target_id(),
    });
    ("200 OK", ct, resp.to_string())
}

pub(crate) fn parse_simulate_target(
    raw: &str,
    explicit_port: Option<u16>,
) -> Option<(String, Option<std::net::IpAddr>, u16)> {
    if explicit_port == Some(0) {
        return None;
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        let port = explicit_port.unwrap_or(443);
        return Some((ip.to_string(), Some(ip), port));
    }

    let parsed = TargetAddr::parse_authority(trimmed, Some(explicit_port.unwrap_or(443)), false).ok()?;
    let port = explicit_port.unwrap_or_else(|| parsed.port());
    match parsed {
        TargetAddr::Ip(addr) => Some((addr.ip().to_string(), Some(addr.ip()), port)),
        TargetAddr::Domain(host, _) => Some((host, None, port)),
    }
}

pub(crate) fn handle_simulate_route(
    req: SimulateRouteRequest,
    rule_engine: &RuleEngine,
    locale: Locale,
) -> (&'static str, &'static str, String) {
    handle_simulate_route_with_pool(req, rule_engine, None, locale)
}

pub(crate) fn handle_simulate_route_with_pool(
    req: SimulateRouteRequest,
    rule_engine: &RuleEngine,
    fake_ip_pool: Option<&FakeIpPool>,
    locale: Locale,
) -> (&'static str, &'static str, String) {
    let ct = "application/json; charset=utf-8";
    let Some((parsed_host, ip_opt, target_port)) = parse_simulate_target(&req.target, req.port) else {
        return (
            "400 Bad Request",
            ct,
            json_error(locale, "ERR_INVALID_SIMULATE_TARGET", "error.invalid_simulate_target"),
        );
    };

    // 与真实流量调度保持完全一致：Fake-IP 还原为原域名；真实 IP 字面量不设 target_host（仅传 target_ip）
    let (target_host, target_ip) = match ip_opt {
        Some(std::net::IpAddr::V4(v4)) if fake_ip_pool.is_some_and(|p| p.is_fake_ip(&v4)) => {
            match fake_ip_pool.and_then(|p| p.restore(&v4)) {
                Some(domain) => (Some(domain), None),
                None => (None, Some(std::net::IpAddr::V4(v4))),
            }
        }
        Some(ip) => (None, Some(ip)),
        None => (Some(parsed_host), None),
    };

    let proc_raw = req
        .process
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let process_path = proc_raw.map(|s| s.to_string());
    let process_name = proc_raw.map(|p| {
        let base = p.rsplit(['/', '\\']).next().unwrap_or(p).trim();
        if base.is_empty() {
            p.to_string()
        } else {
            base.to_string()
        }
    });

    let ctx = crate::router::RouteContext {
        process_path: process_path.as_deref(),
        process_name: process_name.as_deref(),
        target_host: target_host.as_deref(),
        target_ip,
        target_port,
    };

    let sim = rule_engine.simulate(&ctx);
    let matched_rule_name = if sim.is_default {
        t(locale, "action.default_rule").to_string()
    } else {
        sim.matched_rule_name
    };
    let action_desc = crate::router::format_action_desc(&sim.action, locale);
    let action_type = sim.action.type_str().to_string();
    let node_id = sim.action.target_id();

    let resp = SimulateRouteResponse {
        matched_rule_id: sim.matched_rule_id,
        matched_rule_name,
        is_default: sim.is_default,
        action: action_desc,
        action_type,
        node_id,
        process_name,
        process_path,
        target_host,
        target_ip: target_ip.map(|ip| ip.to_string()),
        target_port,
        trace: sim.trace,
    };

    ("200 OK", ct, serde_json_to_string(&resp))
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
    let current_default = rule_engine.default_action();
    let default_action = crate::router::format_action_desc(&current_default, locale);
    let default_action_type = current_default.type_str().to_string();
    let default_node_id = current_default.target_id();

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
        default_action_type,
        default_node_id,
        nodes_count,
        rules_count,
        enabled_rules_count,
    }
}

async fn persist_config_async(
    store: Arc<ConfigStore>,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    rule_engine: &RuleEngine,
) -> Result<()> {
    let cfg = ConfigStore::snapshot_runtime(proxy_nodes, rule_engine);
    tokio::task::spawn_blocking(move || store.save_profile(&cfg))
        .await
        .context("Configuration persistence background task failed")??;
    Ok(())
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
X-Frame-Options: DENY\r\n\
Content-Security-Policy: frame-ancestors 'none'\r\n\
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
    match tokio::time::timeout(API_TIMEOUT, stream.write_all(response.as_bytes())).await {
        Ok(res) => res,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "HTTP response write timed out",
        )),
    }
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

pub(crate) async fn ping_address(
    addr: &str,
    self_ports: &[u16],
    locale: Locale,
) -> (bool, u64, String, Option<String>) {
    ping_address_with_context(addr, self_ports, None, None, locale).await
}

async fn ping_address_with_context(
    addr: &str,
    self_ports: &[u16],
    runtime_ctx: Option<&SystemRuntimeContext>,
    ping_semaphore: Option<&Semaphore>,
    locale: Locale,
) -> (bool, u64, String, Option<String>) {
    const PING_TIMEOUT: Duration = Duration::from_millis(2000);
    let start = Instant::now();

    let _permit = if let Some(sem) = ping_semaphore {
        match tokio::time::timeout(PING_TIMEOUT, sem.acquire()).await {
            Ok(Ok(p)) => Some(p),
            Ok(Err(e)) => {
                return (
                    false,
                    0,
                    t(locale, "error.ping_failed").to_string(),
                    Some(e.to_string()),
                );
            }
            Err(_) => return (false, 0, t(locale, "ping.timeout").to_string(), None),
        }
    } else {
        None
    };

    let parsed = match parse_target_addr(addr) {
        Ok(p) => p,
        Err(e) => {
            return (
                false,
                0,
                t(locale, "error.ping_failed").to_string(),
                Some(e.to_string()),
            );
        }
    };

    let default_pool;
    let fake_pool = match runtime_ctx {
        Some(ctx) => ctx.fake_ip_pool.as_ref(),
        None => {
            default_pool = FakeIpPool::new_default();
            &default_pool
        }
    };

    let (port, candidate_ips): (u16, Vec<std::net::IpAddr>) = match &parsed {
        TargetAddr::Ip(sock_addr) => (sock_addr.port(), vec![sock_addr.ip()]),
        TargetAddr::Domain(domain, port) => {
            if crate::outbound::is_loopback_domain(domain) {
                (
                    *port,
                    vec![
                        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                        std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                    ],
                )
            } else {
                let remaining = PING_TIMEOUT.saturating_sub(start.elapsed());
                if remaining.is_zero() {
                    return (false, 0, t(locale, "ping.timeout").to_string(), None);
                }
                let upstream_dns = runtime_ctx
                    .map(|c| c.upstream_dns)
                    .unwrap_or_else(|| "223.5.5.5:53".parse().unwrap());
                let include_ipv6 = runtime_ctx.is_none_or(|c| !c.block_ipv6);
                match crate::dns::server::resolve_via_upstream_dns_with_options(
                    domain,
                    upstream_dns,
                    Some(fake_pool),
                    remaining,
                    include_ipv6,
                )
                .await
                {
                    Ok(ips) => (*port, ips),
                    Err(e) => {
                        return (
                            false,
                            0,
                            t(locale, "error.ping_failed").to_string(),
                            Some(e.to_string()),
                        );
                    }
                }
            }
        }
    };

    if let Some(violation) = crate::outbound::direct::check_direct_ips_violation(
        &candidate_ips,
        port,
        self_ports,
        Some(fake_pool),
    ) {
        let (key, detail) = match violation {
            crate::outbound::direct::DirectIpViolation::FakeIp(ip) => (
                "error.node_fake_ip",
                format!(
                    "Ping probe blocked: resolved Fake-IP {} for {}:{}",
                    ip,
                    parsed.host_string(),
                    port
                ),
            ),
            crate::outbound::direct::DirectIpViolation::SelfLoop(ip) => (
                "error.node_self_loop",
                format!(
                    "Ping probe blocked due to self/loopback IP resolution ({} -> {}:{})",
                    parsed.host_string(),
                    ip,
                    port
                ),
            ),
        };
        return (false, 0, t(locale, key).to_string(), Some(detail));
    }

    let target_addrs: Vec<SocketAddr> = candidate_ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();

    let remaining = PING_TIMEOUT.saturating_sub(start.elapsed());
    if remaining.is_zero() {
        return (false, 0, t(locale, "ping.timeout").to_string(), None);
    }

    match tokio::time::timeout(remaining, TcpStream::connect(target_addrs.as_slice())).await {
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

        // 1. 无通配 CORS 且拦截 DNS Rebinding / 跨源请求，并包含反点击劫持头
        let ok_resp = raw_http(addr, &format!("GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n", port)).await;
        assert!(ok_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(!ok_resp.contains("Access-Control-Allow-Origin"));
        assert!(ok_resp.contains("X-Frame-Options: DENY"));
        assert!(ok_resp.contains("Content-Security-Policy: frame-ancestors 'none'"));

        let evil_host = raw_http(addr, &format!("GET /api/health HTTP/1.1\r\nHost: evil.com:{}\r\n\r\n", port)).await;
        assert!(evil_host.starts_with("HTTP/1.1 403 Forbidden"));

        let evil_origin = raw_http(
            addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: http://evil.com\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}",
                port
            ),
        )
        .await;
        assert!(evil_origin.starts_with("HTTP/1.1 403 Forbidden"));

        // 1.5 缺失 Content-Type: application/json 时拒绝 415 Unsupported Media Type
        let missing_ct_body = r#"{"name":"n1","protocol":"SOCKS5","server_addr":"1.2.3.4:1080"}"#;
        let missing_ct = raw_http(
            addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\n\r\n{}",
                port,
                missing_ct_body.len(),
                missing_ct_body
            ),
        )
        .await;
        assert!(missing_ct.starts_with("HTTP/1.1 415 Unsupported Media Type"));

        // 2. 拒绝未知代理协议
        let bad_proto_body = r#"{"name":"n1","protocol":"VMESS","server_addr":"1.2.3.4:1080"}"#;
        let bad_proto = raw_http(
            addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
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
                "POST /api/rules HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
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
                "POST /api/rules HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
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
                "POST /api/nodes/ping HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
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
                "POST /api/nodes/ping HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
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
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
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
            block_ipv6: true,
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
                "POST /api/rules/toggle HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
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
                "POST /api/rules/move HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
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
                "DELETE /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
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
                "POST /api/connections/kill HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
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
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: zh-CN,zh;q=0.9\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
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
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: en-US,en;q=0.9\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
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
                "POST /api/nodes?lang=zh HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: en-US\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
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
                "POST /api/nodes?lang=en HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: zh-CN\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
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

    #[tokio::test]
    async fn test_api_update_node_rule_default_and_simulate() {
        let mut path = std::env::current_dir().unwrap().join("target");
        path.push(format!("flowx_api_stage2_{}.xml", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let store = Arc::new(ConfigStore::new(&path));
        let (rt, _) = store.load_or_init(&[40001, 40080, 1053]).unwrap();
        let rule2_id = rt.rules[1].id;

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

        // 1. PUT /api/nodes 更新节点 101 并设置认证，随后 keep_password=true 仅改名保留密码
        let put_node1 = r#"{"id":101,"name":"SG-Auth","protocol":"SOCKS5","server_addr":"10.10.0.1:1080","username":"alice","password":"secret"}"#;
        let resp1 = raw_http(
            addr,
            &format!(
                "PUT /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                port,
                put_node1.len(),
                put_node1
            ),
        )
        .await;
        assert!(resp1.starts_with("HTTP/1.1 200 OK"), "resp1: {resp1}");

        let put_node2 = r#"{"id":101,"name":"SG-Auth-Renamed","protocol":"SOCKS5","server_addr":"10.10.0.1:1080","username":"alice","password":null,"keep_password":true}"#;
        let resp2 = raw_http(
            addr,
            &format!(
                "PUT /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                port,
                put_node2.len(),
                put_node2
            ),
        )
        .await;
        assert!(resp2.starts_with("HTTP/1.1 200 OK"), "resp2: {resp2}");

        // 2. PUT /api/rules 原地修改规则 2
        let put_rule = format!(
            r#"{{"id":{},"name":"GitRule","apps":"git.exe","targets":"*.github.com","ports":"443; 22","action":"Proxy","node_id":101}}"#,
            rule2_id
        );
        let resp_rule = raw_http(
            addr,
            &format!(
                "PUT /api/rules HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                port,
                put_rule.len(),
                put_rule
            ),
        )
        .await;
        assert!(resp_rule.starts_with("HTTP/1.1 200 OK"), "resp_rule: {resp_rule}");

        // 3. POST /api/rules/default 修改默认兜底动作
        let def_body = r#"{"action":"Proxy","node_id":101}"#;
        let resp_def = raw_http(
            addr,
            &format!(
                "POST /api/rules/default HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: zh-CN\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                port,
                def_body.len(),
                def_body
            ),
        )
        .await;
        assert!(resp_def.starts_with("HTTP/1.1 200 OK"), "resp_def: {resp_def}");
        assert!(resp_def.contains("\"default_action_type\":\"Proxy\""));
        assert!(resp_def.contains("\"default_node_id\":101"));

        // 4. POST /api/rules/simulate 测试路由命中与轨迹
        let sim_body = r#"{"process":"C:\\Program Files\\Git\\bin\\git.exe","target":"api.github.com:443"}"#;
        let resp_sim = raw_http(
            addr,
            &format!(
                "POST /api/rules/simulate HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: zh-CN\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                port,
                sim_body.len(),
                sim_body
            ),
        )
        .await;
        assert!(resp_sim.starts_with("HTTP/1.1 200 OK"), "resp_sim: {resp_sim}");
        assert!(resp_sim.contains("\"matched_rule_name\":\"GitRule\""));
        assert!(resp_sim.contains("\"is_default\":false"));
        assert!(resp_sim.contains("\"reason\":\"target_mismatch\""));
        assert!(resp_sim.contains("\"reason\":\"matched\""));

        // 5. 验证 XML 持久化结果
        let (reloaded, _) = store.load_or_init(&[40001, 40080, 1053]).unwrap();
        let node101 = reloaded.proxy_nodes.get(&101).unwrap();
        assert_eq!(node101.name, "SG-Auth-Renamed");
        assert_eq!(node101.client.auth_credentials(), (Some("alice"), Some("secret")));
        assert_eq!(reloaded.rules[1].name, "GitRule");
        assert_eq!(reloaded.default_action, Action::Proxy(101));

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_api_bind_non_loopback_and_framing_hardening() {
        let mgr = Arc::new(ConnectionManager::new());
        let re = Arc::new(RuleEngine::new(Vec::new(), Action::Direct));
        let nodes = Arc::new(RwLock::new(HashMap::new()));
        let non_loopback = ApiServer::new("0.0.0.0:40080".parse().unwrap(), mgr, re, nodes);
        assert!(non_loopback.bind().await.is_err());

        let (addr, _nodes, _re, _tx) = spawn_test_api().await;
        let port = addr.port();

        // 1. 拒绝 Transfer-Encoding (501)
        let te_resp = raw_http(
            addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                port
            ),
        )
        .await;
        assert!(te_resp.starts_with("HTTP/1.1 501 Not Implemented"), "te_resp: {te_resp}");

        // 2. 拒绝重复 Host 头 (400)
        let dup_host = raw_http(
            addr,
            &format!(
                "GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nHost: 127.0.0.1:{}\r\n\r\n",
                port, port
            ),
        )
        .await;
        assert!(dup_host.starts_with("HTTP/1.1 400 Bad Request"), "dup_host: {dup_host}");

        // 3. 拒绝在 EOF 前截断 Content-Length 的不完整请求
        {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(
                format!(
                    "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: 50\r\n\r\n{{\"name\":\"x\"}}",
                    port
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            s.shutdown().await.unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            let txt = String::from_utf8(buf).unwrap();
            assert!(txt.starts_with("HTTP/1.1 400 Bad Request"), "trunc eof: {txt}");
        }

        // 4. 拒绝无效请求行
        let bad_rl = raw_http(
            addr,
            &format!("GET  /api/health HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n", port),
        )
        .await;
        assert!(bad_rl.starts_with("HTTP/1.1 400 Bad Request"), "bad_rl: {bad_rl}");
    }

    #[tokio::test]
    async fn test_api_patch_and_auth_and_simulate_parity() {
        let (addr, nodes, re, _tx) = spawn_test_api().await;
        let port = addr.port();

        // 1. SOCKS4 带密码必须显式报错拒绝
        let s4_pw = r#"{"name":"s4","protocol":"SOCKS4","server_addr":"10.0.0.3:1080","username":"u","password":"p"}"#;
        let resp_s4 = raw_http(
            addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                port,
                s4_pw.len(),
                s4_pw
            ),
        )
        .await;
        assert!(resp_s4.starts_with("HTTP/1.1 400 Bad Request"), "s4_pw: {resp_s4}");
        assert!(resp_s4.contains("ERR_SOCKS4_PASSWORD_UNSUPPORTED"));

        // 2. 添加带密码 SOCKS5 节点并验证 GET /api/nodes 返回 password_configured=true
        let add_s5 = r#"{"name":"s5","protocol":"SOCKS5","server_addr":"10.0.0.4:1080","username":"alice","password":"pw1"}"#;
        let r_add = raw_http(
            addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                port,
                add_s5.len(),
                add_s5
            ),
        )
        .await;
        assert!(r_add.starts_with("HTTP/1.1 200 OK"), "r_add: {r_add}");

        let list_nodes = raw_http(
            addr,
            &format!("GET /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n", port),
        )
        .await;
        assert!(list_nodes.contains("\"password_configured\":true"));

        // 3. PATCH 仅改名保留凭证；修改用户名未给新密码则报错；clear_password=true 清除密码
        let patch_name = r#"{"id":101,"name":"s5-patched"}"#;
        let r_patch_name = raw_http(
            addr,
            &format!(
                "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                port,
                patch_name.len(),
                patch_name
            ),
        )
        .await;
        assert!(r_patch_name.starts_with("HTTP/1.1 200 OK"), "r_patch_name: {r_patch_name}");
        assert_eq!(
            nodes.read().unwrap().get(&101).unwrap().client.auth_credentials(),
            (Some("alice"), Some("pw1"))
        );

        let patch_user_only = r#"{"id":101,"username":"bob"}"#;
        let r_user_only = raw_http(
            addr,
            &format!(
                "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                port,
                patch_user_only.len(),
                patch_user_only
            ),
        )
        .await;
        assert!(r_user_only.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(r_user_only.contains("ERR_PASSWORD_REQUIRED_ON_USER_CHANGE"));

        let clear_pw = r#"{"id":101,"clear_password":true}"#;
        let r_clear = raw_http(
            addr,
            &format!(
                "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                port,
                clear_pw.len(),
                clear_pw
            ),
        )
        .await;
        assert!(r_clear.starts_with("HTTP/1.1 200 OK"), "r_clear: {r_clear}");
        {
            let guard = nodes.read().unwrap();
            let n = guard.get(&101).unwrap();
            assert_eq!(n.username.as_deref(), Some("alice"));
            assert_eq!(n.client.auth_credentials(), (None, None));
        }

        // 4. PATCH /api/rules 保留未修改条件字段
        let add_r = Rule::from_raw("R1", true, Some("curl"), Some("*.example.com"), Some("443"), Action::Direct);
        let rid = add_r.id;
        re.add_rule(add_r);
        let patch_rule_body = format!(r#"{{"id":{},"name":"R1-Renamed"}}"#, rid);
        let r_patch_rule = raw_http(
            addr,
            &format!(
                "PATCH /api/rules HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                port,
                patch_rule_body.len(),
                patch_rule_body
            ),
        )
        .await;
        assert!(r_patch_rule.starts_with("HTTP/1.1 200 OK"), "r_patch_rule: {r_patch_rule}");
        let cur_r = re.current_rules();
        let patched_r = cur_r.iter().find(|r| r.id == rid).unwrap();
        assert_eq!(patched_r.name, "R1-Renamed");
        assert_eq!(patched_r.targets_raw, "*.example.com");
        assert_eq!(patched_r.ports_raw, "443");

        // 5. Simulate parity: IP literal sets target_host=None, Fake-IP restores original domain
        let pool = FakeIpPool::new_default();
        let fake_ip = pool.allocate("secret.internal");
        let sim_ip = handle_simulate_route_with_pool(
            SimulateRouteRequest {
                process: None,
                target: "8.8.8.8:443".into(),
                port: None,
            },
            &re,
            Some(&pool),
            Locale::En,
        );
        let ip_val: serde_json::Value = serde_json::from_str(&sim_ip.2).unwrap();
        assert!(ip_val["target_host"].is_null(), "IP literal must keep target_host null: {ip_val}");
        assert_eq!(ip_val["target_ip"], "8.8.8.8");

        let sim_fake = handle_simulate_route_with_pool(
            SimulateRouteRequest {
                process: None,
                target: format!("{}:443", fake_ip),
                port: None,
            },
            &re,
            Some(&pool),
            Locale::En,
        );
        let fake_val: serde_json::Value = serde_json::from_str(&sim_fake.2).unwrap();
        assert_eq!(fake_val["target_host"], "secret.internal");
        assert!(fake_val["target_ip"].is_null());
    }

    #[tokio::test]
    async fn test_api_persist_failure_rolls_back_and_returns_500_and_auth_validation() {
        // 1. Unwritable parent path (regular file used as parent directory) forces save_profile to fail
        let mut blocker = std::env::current_dir().unwrap().join("target");
        blocker.push(format!("flowx_readonly_parent_{}.tmp", std::process::id()));
        std::fs::write(&blocker, b"not-a-directory").unwrap();
        let bad_cfg_path = blocker.join("flowx.xml");
        let store = Arc::new(ConfigStore::new(&bad_cfg_path));

        let mgr = Arc::new(ConnectionManager::new());
        let re = Arc::new(RuleEngine::new(Vec::new(), Action::Direct));
        let nodes = Arc::new(RwLock::new(HashMap::new()));
        let srv = ApiServer::new(
            "127.0.0.1:0".parse().unwrap(),
            mgr,
            Arc::clone(&re),
            Arc::clone(&nodes),
        )
        .with_self_ports(vec![40001, 40080, 1053])
        .with_config_store(store);
        let listener = srv.bind().await.unwrap();
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move { srv.run(listener, rx).await });
        let _keep_tx = tx;

        let add_node_body =
            r#"{"name":"Node-Rollback","protocol":"SOCKS5","server_addr":"10.0.0.1:1080"}"#;
        let r_node_fail = raw_http(
            addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                port,
                add_node_body.len(),
                add_node_body
            ),
        )
        .await;
        assert!(
            r_node_fail.starts_with("HTTP/1.1 500 Internal Server Error"),
            "Persist failure must return HTTP 500: {r_node_fail}"
        );
        assert!(r_node_fail.contains("ERR_CONFIG_PERSIST_FAILED"));
        assert!(
            nodes.read().unwrap().is_empty(),
            "Failed disk persistence must roll back added proxy node"
        );

        let add_rule_body = r#"{"name":"Rule-Rollback","action":"Block","targets":"example.com"}"#;
        let r_rule_fail = raw_http(
            addr,
            &format!(
                "POST /api/rules HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                port,
                add_rule_body.len(),
                add_rule_body
            ),
        )
        .await;
        assert!(r_rule_fail.starts_with("HTTP/1.1 500 Internal Server Error"));
        assert!(
            re.current_rules().is_empty(),
            "Failed disk persistence must roll back added rule"
        );
        let _ = std::fs::remove_file(&blocker);

        // 2. Password without username / HTTP ':' in username / empty string password semantics (P1-5 + P1-6b)
        let (api_addr, api_nodes, _api_re, _tx2) = spawn_test_api().await;
        let api_port = api_addr.port();

        let pw_only = r#"{"name":"bad","protocol":"SOCKS5","server_addr":"10.0.0.2:1080","password":"secret"}"#;
        let r_pw_only = raw_http(
            api_addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                api_port,
                pw_only.len(),
                pw_only
            ),
        )
        .await;
        assert!(r_pw_only.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(r_pw_only.contains("ERR_PASSWORD_WITHOUT_USERNAME"));

        let http_colon = r#"{"name":"badhttp","protocol":"HTTP","server_addr":"10.0.0.2:8080","username":"a:b","password":"secret"}"#;
        let r_colon = raw_http(
            api_addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                api_port,
                http_colon.len(),
                http_colon
            ),
        )
        .await;
        assert!(r_colon.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(r_colon.contains("ERR_HTTP_USERNAME_COLON"));

        let empty_add_pw = r#"{"name":"badadd","protocol":"SOCKS5","server_addr":"10.0.0.2:1080","username":"alice","password":""}"#;
        let r_empty_add = raw_http(
            api_addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                api_port,
                empty_add_pw.len(),
                empty_add_pw
            ),
        )
        .await;
        assert!(r_empty_add.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(r_empty_add.contains("ERR_EMPTY_PASSWORD"));

        // Create node with credentials, then PATCH {"password": ""} clears password instead of keeping old one
        let ok_add = r#"{"name":"s5ok","protocol":"SOCKS5","server_addr":"10.0.0.2:1080","username":"alice","password":"pw1"}"#;
        let r_ok_add = raw_http(
            api_addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                api_port,
                ok_add.len(),
                ok_add
            ),
        )
        .await;
        assert!(r_ok_add.starts_with("HTTP/1.1 200 OK"));

        let conflict_patch = r#"{"id":101,"password":"","keep_password":true}"#;
        let r_conflict = raw_http(
            api_addr,
            &format!(
                "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                api_port,
                conflict_patch.len(),
                conflict_patch
            ),
        )
        .await;
        assert!(r_conflict.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(r_conflict.contains("ERR_CONFLICTING_PASSWORD_OPTIONS"));

        let clear_via_empty_str = r#"{"id":101,"password":""}"#;
        let r_clear = raw_http(
            api_addr,
            &format!(
                "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                api_port,
                clear_via_empty_str.len(),
                clear_via_empty_str
            ),
        )
        .await;
        assert!(r_clear.starts_with("HTTP/1.1 200 OK"));
        assert_eq!(
            api_nodes.read().unwrap().get(&101).unwrap().client.auth_credentials(),
            (None, None),
            "PATCH with explicit empty password string must clear stored password"
        );
    }

    #[tokio::test]
    async fn test_api_update_and_patch_new_password_with_keep_false() {
        let (api_addr, api_nodes, _api_re, _tx) = spawn_test_api().await;
        let api_port = api_addr.port();

        let add_body = r#"{"name":"s5p0","protocol":"SOCKS5","server_addr":"10.0.0.2:1080","username":"alice","password":"pw1"}"#;
        let r_add = raw_http(
            api_addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                api_port,
                add_body.len(),
                add_body
            ),
        )
        .await;
        assert!(r_add.starts_with("HTTP/1.1 200 OK"));
        let added_json: serde_json::Value =
            serde_json::from_str(r_add.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        let node_id = added_json["id"].as_u64().unwrap() as u32;

        // P0: Web UI edits send explicit non-empty password alongside keep_password=false & clear_password=false
        let put_body = format!(
            r#"{{"id":{},"name":"s5p0","protocol":"SOCKS5","server_addr":"10.0.0.2:1080","username":"alice","password":"new-put-secret","keep_password":false,"clear_password":false}}"#,
            node_id
        );
        let r_put = raw_http(
            api_addr,
            &format!(
                "PUT /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                api_port,
                put_body.len(),
                put_body
            ),
        )
        .await;
        assert!(r_put.starts_with("HTTP/1.1 200 OK"), "PUT failed: {}", r_put);
        assert_eq!(
            api_nodes
                .read()
                .unwrap()
                .get(&node_id)
                .unwrap()
                .client
                .auth_credentials(),
            (Some("alice"), Some("new-put-secret")),
            "PUT must preserve newly entered password even when keep_password=false"
        );

        let patch_body = format!(
            r#"{{"id":{},"username":"bob","password":"new-patch-secret","keep_password":false,"clear_password":false}}"#,
            node_id
        );
        let r_patch = raw_http(
            api_addr,
            &format!(
                "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                api_port,
                patch_body.len(),
                patch_body
            ),
        )
        .await;
        assert!(r_patch.starts_with("HTTP/1.1 200 OK"), "PATCH failed: {}", r_patch);
        assert_eq!(
            api_nodes
                .read()
                .unwrap()
                .get(&node_id)
                .unwrap()
                .client
                .auth_credentials(),
            (Some("bob"), Some("new-patch-secret")),
            "PATCH must preserve newly entered password even when keep_password=false"
        );
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
        let node_id = serde_json::from_str::<serde_json::Value>(r_node.split("\r\n\r\n").nth(1).unwrap()).unwrap()["id"]
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
            api_re.current_rules().iter().find(|r| r.id == chain_rule_id).unwrap().action,
            Action::Chain(node_id)
        );

        let switch_with_node = format!(r#"{{"id":{},"action":"Proxy","node_id":{}}}"#, chain_rule_id, node_id);
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
            api_re.current_rules().iter().find(|r| r.id == chain_rule_id).unwrap().action,
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
        slow_client.write_all(b"POST /api/nodes HTTP/1.1\r\n").await.unwrap();
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
        let srv = ApiServer::new("127.0.0.1:0".parse().unwrap(), mgr, Arc::clone(&re), Arc::clone(&nodes))
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
    async fn test_api_node_and_ping_block_fake_ip_and_local_interface_self_ports() {
        let (api_addr, _api_nodes, _api_re, _tx) = spawn_test_api().await;
        let api_port = api_addr.port();

        // 1. Node creation with Fake-IP literal must fail with ERR_NODE_FAKE_IP
        let fake_node = r#"{"name":"fake","protocol":"SOCKS5","server_addr":"198.18.0.55:1080"}"#;
        let r_fake = raw_http(
            api_addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                api_port,
                fake_node.len(),
                fake_node
            ),
        )
        .await;
        assert!(r_fake.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(r_fake.contains("ERR_NODE_FAKE_IP"));

        // 2. Node creation with local interface non-loopback IP on self_port (40080) must fail
        let local_ips = crate::outbound::local_interface_ips();
        let non_loopback_ip = local_ips
            .iter()
            .copied()
            .find(|ip| !ip.is_loopback() && !ip.is_unspecified())
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let iface_self_addr = SocketAddr::new(non_loopback_ip, 40080).to_string();
        let iface_body = format!(
            r#"{{"name":"iface","protocol":"SOCKS5","server_addr":"{}"}}"#,
            iface_self_addr
        );
        let r_iface = raw_http(
            api_addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                api_port,
                iface_body.len(),
                iface_body
            ),
        )
        .await;
        assert!(r_iface.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(r_iface.contains("ERR_NODE_SELF_LOOP"));

        // 3. ping_address_with_context must reject Fake-IP, self_port loopback/local-interface, and DNS rebinding to self_port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound_port = listener.local_addr().unwrap().port();
        let (ok_fake, _, msg_fake, _) = ping_address("198.18.0.10:1080", &[bound_port], Locale::En).await;
        assert!(!ok_fake);
        assert!(msg_fake.contains("Fake-IP"));

        let (ok_self, _, msg_self, _) =
            ping_address(&format!("127.0.0.1:{}", bound_port), &[bound_port], Locale::En).await;
        assert!(!ok_self);
        assert!(msg_self.contains("internal service"));

        let (ok_iface, _, msg_iface, _) = ping_address(
            &SocketAddr::new(non_loopback_ip, bound_port).to_string(),
            &[bound_port],
            Locale::En,
        )
        .await;
        assert!(!ok_iface);
        assert!(msg_iface.contains("internal service"));
    }
}
