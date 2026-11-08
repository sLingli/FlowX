use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{error, info};

use crate::interceptor::dispatcher::ProxyNodeEntry;
use crate::monitor::ConnectionManager;
use crate::outbound::chain::ProxyNode;
use crate::outbound::http::HttpConnectClient;
use crate::outbound::socks4::Socks4Client;
use crate::outbound::socks5::Socks5Client;
use crate::router::{Action, Rule, RuleEngine};

const API_TIMEOUT: Duration = Duration::from_secs(5);

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
    pub addr: String,
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

pub struct ApiServer {
    pub bind_addr: SocketAddr,
    pub monitor: Arc<ConnectionManager>,
    pub rule_engine: Arc<RuleEngine>,
    pub proxy_nodes: Arc<RwLock<HashMap<u32, ProxyNodeEntry>>>,
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
        }
    }

    /// 同步绑定 TCP 监听器（Fail-Fast 检查端口占用）
    pub async fn bind(&self) -> Result<TcpListener> {
        let listener = TcpListener::bind(self.bind_addr)
            .await
            .with_context(|| format!("绑定 HTTP API 服务端口失败 ({})", self.bind_addr))?;
        info!("[API 接口] FlowX 状态与控制 HTTP API 服务已在 http://{} 绑定", self.bind_addr);
        Ok(listener)
    }

    /// 启动异步 HTTP API 监听服务（支持优雅停机）
    pub async fn run(&self, listener: TcpListener, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
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

            tokio::spawn(async move {
                if let Err(e) = tokio::time::timeout(
                    API_TIMEOUT,
                    handle_api_request(stream, monitor, rule_engine, proxy_nodes),
                ).await {
                    error!("[API 接口] 处理请求超时或异常: {}", e);
                }
            });
        }
        Ok(())
    }
}

async fn handle_api_request(
    mut stream: TcpStream,
    monitor: Arc<ConnectionManager>,
    rule_engine: Arc<RuleEngine>,
    proxy_nodes: Arc<RwLock<HashMap<u32, ProxyNodeEntry>>>,
) -> Result<()> {
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or_default();
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 2 {
        return Ok(());
    }

    let method = parts[0];
    let path_and_query = parts[1];
    let (path, query) = path_and_query.split_once('?').unwrap_or((path_and_query, ""));

    let body_start = request.find("\r\n\r\n").map(|idx| idx + 4).unwrap_or(n);
    let req_body = if body_start < n { &request[body_start..] } else { "" };

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
        ("GET", "/api/stats") => {
            let stats = monitor.global_stats();
            let json = serde_json_to_string(&stats);
            ("200 OK", "application/json; charset=utf-8", json)
        }
        ("GET", "/api/connections") => {
            let list = monitor.list_snapshots();
            let json = serde_json_to_string(&list);
            ("200 OK", "application/json; charset=utf-8", json)
        }
        ("POST", "/api/connections/kill") => {
            let id: Option<u64> = parse_query_param(query, "id")
                .and_then(|v| v.parse().ok())
                .or_else(|| {
                    serde_json::from_str::<serde_json::Value>(req_body).ok()
                        .and_then(|v| v.get("id").and_then(|i| i.as_u64()))
                });
            if let Some(conn_id) = id {
                let killed = monitor.kill_connection(conn_id);
                monitor.unregister(conn_id);
                ("200 OK", "application/json; charset=utf-8", format!(r#"{{"ok":true,"killed":{}}}"#, killed))
            } else {
                ("400 Bad Request", "application/json; charset=utf-8", r#"{"error":"缺少连接ID"}"#.to_string())
            }
        }
        ("GET", "/api/nodes") => {
            let nodes_guard = proxy_nodes.read().unwrap_or_else(|e| e.into_inner());
            let list: Vec<ProxyNodeView> = nodes_guard.values().map(|n| ProxyNodeView {
                id: n.id,
                name: n.name.clone(),
                protocol: n.protocol.clone(),
                server_addr: n.server_addr.clone(),
                auth_configured: n.username.is_some(),
            }).collect();
            let json = serde_json_to_string(&list);
            ("200 OK", "application/json; charset=utf-8", json)
        }
        ("POST", "/api/nodes") => {
            if let Ok(req) = serde_json::from_str::<AddNodeRequest>(req_body) {
                let client = match req.protocol.to_uppercase().as_str() {
                    "HTTP" => {
                        let mut c = HttpConnectClient::new(&req.server_addr);
                        if let (Some(u), Some(p)) = (&req.username, &req.password)
                            && !u.is_empty() { c = c.with_auth(u.clone(), p.clone()); }
                        ProxyNode::Http(c)
                    }
                    "SOCKS4" => {
                        let mut c = Socks4Client::new(&req.server_addr);
                        if let Some(u) = &req.username
                            && !u.is_empty() { c = c.with_user_id(u.clone()); }
                        ProxyNode::Socks4(c)
                    }
                    _ => {
                        let mut c = Socks5Client::new(&req.server_addr);
                        if let (Some(u), Some(p)) = (&req.username, &req.password)
                            && !u.is_empty() { c = c.with_auth(u.clone(), p.clone()); }
                        ProxyNode::Socks5(c)
                    }
                };

                let mut nodes_guard = proxy_nodes.write().unwrap_or_else(|e| e.into_inner());
                let new_id = nodes_guard.keys().max().copied().unwrap_or(100) + 1;
                nodes_guard.insert(new_id, ProxyNodeEntry {
                    id: new_id,
                    name: req.name,
                    protocol: req.protocol.to_uppercase(),
                    server_addr: req.server_addr,
                    username: req.username,
                    client,
                });
                ("200 OK", "application/json; charset=utf-8", format!(r#"{{"ok":true,"id":{}}}"#, new_id))
            } else {
                ("400 Bad Request", "application/json; charset=utf-8", r#"{"error":"无效的节点请求体"}"#.to_string())
            }
        }
        ("DELETE", "/api/nodes") => {
            let id: Option<u32> = parse_query_param(query, "id")
                .and_then(|v| v.parse().ok())
                .or_else(|| {
                    serde_json::from_str::<serde_json::Value>(req_body).ok()
                        .and_then(|v| v.get("id").and_then(|i| i.as_u64()).map(|n| n as u32))
                });
            if let Some(node_id) = id {
                // 级联防呆检查：若当前有任何路由规则指向该代理节点，禁止删除
                let rules = rule_engine.current_rules();
                let is_referenced = rules.iter().any(|r| match &r.action {
                    Action::Proxy(pid) => *pid == node_id,
                    _ => false,
                });
                if is_referenced {
                    ("409 Conflict", "application/json; charset=utf-8", r#"{"error":"节点正被路由规则引用，禁止删除。请先修改或删除关联规则"}"#.to_string())
                } else {
                    let mut nodes_guard = proxy_nodes.write().unwrap_or_else(|e| e.into_inner());
                    nodes_guard.remove(&node_id);
                    ("200 OK", "application/json; charset=utf-8", r#"{"ok":true}"#.to_string())
                }
            } else {
                ("400 Bad Request", "application/json; charset=utf-8", r#"{"error":"缺少节点ID"}"#.to_string())
            }
        }
        ("POST", "/api/nodes/ping") => {
            let target_addr = parse_query_param(query, "addr")
                .map(|s| s.to_string())
                .or_else(|| {
                    serde_json::from_str::<PingNodeRequest>(req_body).ok().map(|p| p.addr)
                });
            if let Some(addr) = target_addr {
                let (ok, ms, msg) = ping_address(&addr).await;
                let resp = format!(r#"{{"ok":{},"latency_ms":{},"message":"{}"}}"#, ok, ms, msg);
                ("200 OK", "application/json; charset=utf-8", resp)
            } else {
                ("400 Bad Request", "application/json; charset=utf-8", r#"{"error":"缺少节点测试地址"}"#.to_string())
            }
        }
        ("GET", "/api/rules") => {
            let list = rule_engine.list_rules_view();
            let json = serde_json_to_string(&list);
            ("200 OK", "application/json; charset=utf-8", json)
        }
        ("POST", "/api/rules") => {
            if let Ok(req) = serde_json::from_str::<AddRuleRequest>(req_body) {
                let action = match req.action.to_uppercase().as_str() {
                    "BLOCK" => Action::Block,
                    "PROXY" => Action::Proxy(req.node_id.unwrap_or(101)),
                    _ => Action::Direct,
                };
                let rule = Rule::from_raw(
                    req.name,
                    true,
                    req.apps.as_deref(),
                    req.targets.as_deref(),
                    req.ports.as_deref(),
                    action,
                );
                rule_engine.add_rule(rule);
                ("200 OK", "application/json; charset=utf-8", r#"{"ok":true}"#.to_string())
            } else {
                ("400 Bad Request", "application/json; charset=utf-8", r#"{"error":"无效的规则请求体"}"#.to_string())
            }
        }
        ("DELETE", "/api/rules") => {
            let id: Option<u64> = parse_query_param(query, "id")
                .and_then(|v| v.parse().ok())
                .or_else(|| {
                    serde_json::from_str::<serde_json::Value>(req_body).ok()
                        .and_then(|v| v.get("id").and_then(|i| i.as_u64()))
                });
            if let Some(rule_id) = id {
                let ok = rule_engine.delete_rule(rule_id);
                let resp = format!(r#"{{"ok":{}}}"#, ok);
                ("200 OK", "application/json; charset=utf-8", resp)
            } else {
                ("400 Bad Request", "application/json; charset=utf-8", r#"{"error":"缺少规则ID"}"#.to_string())
            }
        }
        _ => ("404 Not Found", "application/json; charset=utf-8", r#"{"error":"Not Found"}"#.to_string()),
    };

    let response = format!(
        "HTTP/1.1 {}\r\n\
Content-Type: {}\r\n\
Access-Control-Allow-Origin: *\r\n\
Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n\
Access-Control-Allow-Headers: *\r\n\
Content-Length: {}\r\n\
Connection: close\r\n\
\r\n\
{}",
        status,
        content_type,
        body.len(),
        body
    );

    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

fn parse_query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for part in query.split('&') {
        if let Some((k, v)) = part.split_once('=')
            && k == key {
                return Some(v);
            }
    }
    None
}

async fn ping_address(addr: &str) -> (bool, u64, String) {
    let start = std::time::Instant::now();
    let res = tokio::time::timeout(
        Duration::from_millis(2000),
        TcpStream::connect(addr),
    ).await;
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
    fn test_api_server_creation() {
        let mgr = Arc::new(ConnectionManager::new());
        let re = Arc::new(RuleEngine::new(Vec::new(), Action::Direct));
        let nodes = Arc::new(RwLock::new(HashMap::new()));
        let srv = ApiServer::new("127.0.0.1:40080".parse().unwrap(), mgr, re, nodes);
        assert_eq!(srv.bind_addr.port(), 40080);
    }
}
