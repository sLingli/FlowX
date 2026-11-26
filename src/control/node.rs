use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::control::ControlError;
use crate::control::routing::SystemRuntimeContext;
use crate::dns::FakeIpPool;
use crate::i18n::{Locale, t};
use crate::interceptor::dispatcher::ProxyNodeEntry;
use crate::outbound::TargetAddr;
use crate::outbound::chain::{ProxyNode, parse_target_addr};
use crate::outbound::http::HttpConnectClient;
use crate::outbound::socks4::Socks4Client;
use crate::outbound::socks5::Socks5Client;
use crate::router::{Action, RuleEngine};

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

pub fn proxy_node_view(n: &ProxyNodeEntry) -> ProxyNodeView {
    ProxyNodeView {
        id: n.id,
        name: n.name.clone(),
        protocol: n.protocol.clone(),
        server_addr: n.server_addr.clone(),
        auth_configured: n.is_auth_configured(),
        password_configured: n.client.auth_credentials().1.is_some(),
        username: n.username.clone(),
    }
}

pub fn list_nodes(proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>) -> Vec<ProxyNodeView> {
    let nodes_guard = proxy_nodes.read().unwrap_or_else(|e| e.into_inner());
    let mut list: Vec<ProxyNodeView> = nodes_guard.values().map(proxy_node_view).collect();
    list.sort_by_key(|n| n.id);
    list
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

#[allow(clippy::type_complexity)]
fn validate_node_base(
    name_raw: &str,
    protocol_raw: &str,
    server_addr_raw: &str,
    username_raw: Option<String>,
    explicit_password: Option<String>,
    self_ports: &[u16],
) -> Result<(String, String, String, Option<String>, Option<String>), ControlError> {
    let name = name_raw.trim().to_string();
    if name.is_empty() {
        return Err(ControlError::bad_request(
            "ERR_EMPTY_NODE_NAME",
            "error.empty_node_name",
        ));
    }
    if crate::config::has_control_or_oversize(&name, 255) {
        return Err(ControlError::bad_request(
            "ERR_INVALID_NODE_NAME",
            "error.invalid_node_name",
        ));
    }

    let protocol = protocol_raw.trim().to_ascii_uppercase();
    if !matches!(protocol.as_str(), "SOCKS5" | "SOCKS4" | "HTTP") {
        return Err(ControlError::bad_request(
            "ERR_UNSUPPORTED_PROTOCOL",
            "error.unsupported_protocol",
        ));
    }

    let server_addr = server_addr_raw.trim().to_string();
    let Ok(target_parsed) = parse_target_addr(&server_addr) else {
        return Err(ControlError::bad_request(
            "ERR_INVALID_NODE_ADDR",
            "error.invalid_node_addr",
        ));
    };
    if target_parsed.port() == 0 || target_parsed.host_string().is_empty() {
        return Err(ControlError::bad_request(
            "ERR_INVALID_NODE_PORT",
            "error.invalid_node_port",
        ));
    }

    match &target_parsed {
        TargetAddr::Ip(sa) => {
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
                return Err(ControlError::bad_request(code, key));
            }
        }
        TargetAddr::Domain(_, port) => {
            if target_parsed.is_loopback_or_unspecified() && self_ports.contains(port) {
                return Err(ControlError::bad_request(
                    "ERR_NODE_SELF_LOOP",
                    "error.node_self_loop",
                ));
            }
        }
    }

    let username = username_raw
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty());

    if let Some(u) = &username {
        if crate::config::has_control_or_oversize(u, 255) {
            return Err(ControlError::bad_request(
                "ERR_INVALID_USERNAME",
                "error.invalid_username",
            ));
        }
        if protocol == "HTTP" && u.contains(':') {
            return Err(ControlError::bad_request(
                "ERR_HTTP_USERNAME_COLON",
                "error.http_username_colon",
            ));
        }
    }

    if let Some(p) = &explicit_password {
        if crate::config::has_control_or_oversize(p, 255) {
            return Err(ControlError::bad_request(
                "ERR_INVALID_PASSWORD",
                "error.invalid_password",
            ));
        }
        if protocol != "SOCKS4" && username.is_none() && !p.is_empty() {
            return Err(ControlError::bad_request(
                "ERR_PASSWORD_WITHOUT_USERNAME",
                "error.password_without_username",
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
fn resolve_updated_credentials(
    is_patch: bool,
    protocol: &str,
    username: Option<String>,
    existing_username: &Option<String>,
    existing_password: Option<String>,
    explicit_password: Option<String>,
    keep_password: Option<bool>,
    clear_password: Option<bool>,
) -> Result<(Option<String>, Option<String>), ControlError> {
    let has_raw_password_field = explicit_password.is_some();
    let explicit_empty = explicit_password.as_deref() == Some("");
    let explicit_non_empty = explicit_password.filter(|p| !p.is_empty());

    if clear_password == Some(true) && (keep_password == Some(true) || explicit_non_empty.is_some())
    {
        return Err(ControlError::bad_request(
            "ERR_CONFLICTING_PASSWORD_OPTIONS",
            "error.conflicting_password_options",
        ));
    }
    if keep_password == Some(true) && explicit_non_empty.is_some() {
        return Err(ControlError::bad_request(
            "ERR_CONFLICTING_PASSWORD_OPTIONS",
            "error.conflicting_password_options",
        ));
    }
    if explicit_empty && (keep_password == Some(true) || clear_password == Some(false)) {
        return Err(ControlError::bad_request(
            "ERR_CONFLICTING_PASSWORD_OPTIONS",
            "error.conflicting_password_options",
        ));
    }

    if protocol == "SOCKS4" {
        if has_raw_password_field || keep_password == Some(true) {
            return Err(ControlError::bad_request(
                "ERR_SOCKS4_PASSWORD_UNSUPPORTED",
                "error.socks4_password_unsupported",
            ));
        }
        return Ok((username, None));
    }

    if username.is_none() {
        if keep_password == Some(true) && existing_password.is_some() {
            return Err(ControlError::bad_request(
                "ERR_PASSWORD_WITHOUT_USERNAME",
                "error.password_without_username",
            ));
        }
        if clear_password == Some(false) && !has_raw_password_field && existing_password.is_some() {
            return Err(ControlError::bad_request(
                "ERR_CONFLICTING_PASSWORD_OPTIONS",
                "error.conflicting_password_options",
            ));
        }
        return Ok((None, None));
    }

    let clearing_password = clear_password == Some(true) || explicit_empty;

    if clearing_password {
        if username != *existing_username {
            return Err(ControlError::bad_request(
                "ERR_USERNAME_WITHOUT_PASSWORD",
                "error.username_without_password",
            ));
        }
        return Ok((None, None));
    }

    if let Some(p) = explicit_non_empty {
        return Ok((username, Some(p)));
    }

    let should_keep = keep_password.unwrap_or(is_patch);
    if should_keep {
        if username != *existing_username {
            if existing_password.is_some() {
                return Err(ControlError::bad_request(
                    "ERR_PASSWORD_REQUIRED_ON_USER_CHANGE",
                    "error.password_required_on_user_change",
                ));
            }
            return Err(ControlError::bad_request(
                "ERR_USERNAME_WITHOUT_PASSWORD",
                "error.username_without_password",
            ));
        }
        if let Some(pw) = existing_password {
            return Ok((username, Some(pw)));
        }
    }

    Err(ControlError::bad_request(
        "ERR_USERNAME_WITHOUT_PASSWORD",
        "error.username_without_password",
    ))
}

pub fn add_node(
    req: AddNodeRequest,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    self_ports: &[u16],
) -> Result<u32, ControlError> {
    let (name, protocol, server_addr, username, explicit_password) = validate_node_base(
        &req.name,
        &req.protocol,
        &req.server_addr,
        req.username,
        req.password,
        self_ports,
    )?;

    if protocol == "SOCKS4" && explicit_password.is_some() {
        return Err(ControlError::bad_request(
            "ERR_SOCKS4_PASSWORD_UNSUPPORTED",
            "error.socks4_password_unsupported",
        ));
    }
    if explicit_password.as_deref() == Some("") {
        return Err(ControlError::bad_request(
            "ERR_EMPTY_PASSWORD",
            "error.empty_password",
        ));
    }
    if protocol != "SOCKS4" && username.is_some() && explicit_password.is_none() {
        return Err(ControlError::bad_request(
            "ERR_USERNAME_WITHOUT_PASSWORD",
            "error.username_without_password",
        ));
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
    Ok(new_id)
}

pub fn update_node(
    req: UpdateNodeRequest,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    self_ports: &[u16],
) -> Result<u32, ControlError> {
    let (name, protocol, server_addr, username, explicit_password) = validate_node_base(
        &req.name,
        &req.protocol,
        &req.server_addr,
        req.username,
        req.password,
        self_ports,
    )?;

    let mut nodes_guard = proxy_nodes.write().unwrap_or_else(|e| e.into_inner());
    let Some(existing) = nodes_guard.get(&req.id) else {
        return Err(ControlError::not_found(
            "ERR_NODE_NOT_FOUND",
            "error.node_not_found",
        ));
    };

    let existing_password = existing
        .client
        .auth_credentials()
        .1
        .map(ToString::to_string);
    let (username, password) = resolve_updated_credentials(
        false,
        &protocol,
        username,
        &existing.username,
        existing_password,
        explicit_password,
        req.keep_password,
        req.clear_password,
    )?;

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
    Ok(req.id)
}

pub fn patch_node(
    req: PatchNodeRequest,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    self_ports: &[u16],
) -> Result<u32, ControlError> {
    let mut nodes_guard = proxy_nodes.write().unwrap_or_else(|e| e.into_inner());
    let Some(existing) = nodes_guard.get(&req.id).cloned() else {
        return Err(ControlError::not_found(
            "ERR_NODE_NOT_FOUND",
            "error.node_not_found",
        ));
    };

    let name_raw = req.name.unwrap_or_else(|| existing.name.clone());
    let protocol_raw = req.protocol.unwrap_or_else(|| existing.protocol.clone());
    let server_addr_raw = req
        .server_addr
        .unwrap_or_else(|| existing.server_addr.clone());
    if req.clear_username == Some(true)
        && req
            .username
            .as_deref()
            .is_some_and(|u| !u.trim().is_empty())
    {
        return Err(ControlError::bad_request(
            "ERR_CONFLICTING_USERNAME_OPTIONS",
            "error.conflicting_username_options",
        ));
    }
    let username_raw = if req.clear_username == Some(true) {
        None
    } else if req.username.is_some() {
        req.username
    } else {
        existing.username.clone()
    };

    let (name, protocol, server_addr, username, explicit_password) = validate_node_base(
        &name_raw,
        &protocol_raw,
        &server_addr_raw,
        username_raw,
        req.password,
        self_ports,
    )?;

    let existing_password = existing
        .client
        .auth_credentials()
        .1
        .map(ToString::to_string);
    let (username, password) = resolve_updated_credentials(
        true,
        &protocol,
        username,
        &existing.username,
        existing_password,
        explicit_password,
        req.keep_password,
        req.clear_password,
    )?;

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
    Ok(req.id)
}

pub fn delete_node(
    node_id: u32,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    rule_engine: &RuleEngine,
) -> Result<(), ControlError> {
    // 级联防呆检查：若当前有任何路由规则或默认兜底动作指向该代理节点，禁止删除
    let rules = rule_engine.current_rules();
    let current_default = rule_engine.default_action();
    let is_referenced = rules.iter().any(|r| match &r.action {
        Action::Proxy(pid) => *pid == node_id,
        _ => false,
    }) || matches!(current_default, Action::Proxy(pid) if pid == node_id);
    if is_referenced {
        return Err(ControlError::conflict(
            "ERR_NODE_IN_USE",
            "error.node_in_use",
        ));
    }

    let removed = {
        let mut nodes_guard = proxy_nodes.write().unwrap_or_else(|e| e.into_inner());
        nodes_guard.remove(&node_id).is_some()
    };
    if removed {
        Ok(())
    } else {
        Err(ControlError::not_found(
            "ERR_NODE_NOT_FOUND",
            "error.node_not_found",
        ))
    }
}

pub async fn ping_address(
    addr: &str,
    self_ports: &[u16],
    locale: Locale,
) -> (bool, u64, String, Option<String>) {
    ping_address_with_context(addr, self_ports, None, None, locale).await
}

pub async fn ping_address_with_context(
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
                // block_ipv6 仅用于本地 Fake-IP DNS 防泄漏；在线节点 Ping 与 DirectOutbound 统一允许 A + AAAA 解析与拨号
                match crate::dns::server::resolve_via_upstream_dns(
                    domain,
                    upstream_dns,
                    Some(fake_pool),
                    remaining,
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

    let remaining = PING_TIMEOUT.saturating_sub(start.elapsed());
    if remaining.is_zero() {
        return (false, 0, t(locale, "ping.timeout").to_string(), None);
    }

    let deadline = tokio::time::Instant::now() + remaining;
    match crate::outbound::direct::connect_candidates_guarded_with_budget(
        &candidate_ips,
        port,
        deadline,
        Duration::from_millis(250),
        PING_TIMEOUT,
    )
    .await
    {
        Ok(stream) => {
            drop(stream);
            let ms = start.elapsed().as_millis() as u64;
            (true, ms, format!("{} ms", ms), None)
        }
        // 面向用户的文案本地化；底层 OS 错误串只放进 detail，供排障而不直接展示
        Err(crate::outbound::direct::CandidateConnectError::Io(e)) => (
            false,
            0,
            t(locale, "error.ping_failed").to_string(),
            Some(e.to_string()),
        ),
        Err(crate::outbound::direct::CandidateConnectError::TimedOut { .. }) => {
            (false, 0, t(locale, "ping.timeout").to_string(), None)
        }
        Err(crate::outbound::direct::CandidateConnectError::NoCandidates) => (
            false,
            0,
            t(locale, "error.ping_failed").to_string(),
            Some("No resolved IP candidates available".to_string()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_ping_address_with_context_guards_and_semaphore_paths() {
        // 1. Invalid address fails cleanly with detail
        let (ok, _, msg, detail) =
            ping_address_with_context("not-a-valid-addr", &[], None, None, Locale::En).await;
        assert!(!ok);
        assert!(!msg.is_empty());
        assert!(detail.is_some());

        // 2. Closed semaphore fails fast with error detail
        let closed_sem = Semaphore::new(1);
        closed_sem.close();
        let (ok, _, _, detail) =
            ping_address_with_context("127.0.0.1:80", &[], None, Some(&closed_sem), Locale::En)
                .await;
        assert!(!ok);
        assert!(detail.is_some());

        // 3. Fake-IP target is blocked before dialing
        let (ok, _, msg, detail) =
            ping_address_with_context("198.18.0.10:1080", &[], None, None, Locale::En).await;
        assert!(!ok);
        assert_eq!(msg, t(Locale::En, "error.node_fake_ip"));
        assert!(
            detail
                .as_deref()
                .is_some_and(|d| d.contains("Fake-IP") && d.contains("198.18.0.10"))
        );

        // 4. Self-port loopback target is blocked before dialing
        let (ok, _, msg, detail) =
            ping_address_with_context("127.0.0.1:40080", &[40080], None, None, Locale::En).await;
        assert!(!ok);
        assert_eq!(msg, t(Locale::En, "error.node_self_loop"));
        assert!(
            detail
                .as_deref()
                .is_some_and(|d| d.contains("self/loopback"))
        );

        // 5. Reachable local listener succeeds with semaphore permit
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let sem = Semaphore::new(2);
        let (ok, _, msg, detail) = ping_address_with_context(
            &addr.to_string(),
            &[40001, 40080, 1053],
            None,
            Some(&sem),
            Locale::En,
        )
        .await;
        let _ = accept_task.await;
        assert!(
            ok,
            "expected reachable local listener ping to succeed: {msg}"
        );
        assert!(msg.ends_with(" ms"));
        assert!(detail.is_none());

        // 6. Closed local port fails cleanly (Io refused or 2s Windows loopback SYN-retry timeout)
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let (ok, _, msg, detail) = ping_address_with_context(
            &dead_addr.to_string(),
            &[40001, 40080, 1053],
            None,
            Some(&sem),
            Locale::Zh,
        )
        .await;
        assert!(!ok);
        if detail.is_some() {
            assert_eq!(msg, t(Locale::Zh, "error.ping_failed"));
        } else {
            assert_eq!(msg, t(Locale::Zh, "ping.timeout"));
        }
    }

    #[test]
    fn test_add_update_patch_delete_and_list_nodes() {
        use crate::control::ControlErrorKind;
        use crate::router::{Action, Rule, RuleEngine};

        let nodes = RwLock::new(HashMap::new());
        let self_ports = [40001u16, 40080, 1053];

        // Validation errors on add_node
        assert_eq!(
            add_node(
                AddNodeRequest {
                    name: "  ".into(),
                    protocol: "SOCKS5".into(),
                    server_addr: "10.0.0.2:1080".into(),
                    username: None,
                    password: None,
                },
                &nodes,
                &self_ports,
            )
            .unwrap_err()
            .code,
            "ERR_EMPTY_NODE_NAME"
        );
        assert_eq!(
            add_node(
                AddNodeRequest {
                    name: "BadProto".into(),
                    protocol: "VMESS".into(),
                    server_addr: "10.0.0.2:1080".into(),
                    username: None,
                    password: None,
                },
                &nodes,
                &self_ports,
            )
            .unwrap_err()
            .code,
            "ERR_UNSUPPORTED_PROTOCOL"
        );
        assert_eq!(
            add_node(
                AddNodeRequest {
                    name: "FakeIp".into(),
                    protocol: "SOCKS5".into(),
                    server_addr: "198.18.0.5:1080".into(),
                    username: None,
                    password: None,
                },
                &nodes,
                &self_ports,
            )
            .unwrap_err()
            .code,
            "ERR_NODE_FAKE_IP"
        );
        assert_eq!(
            add_node(
                AddNodeRequest {
                    name: "SelfLoop".into(),
                    protocol: "SOCKS5".into(),
                    server_addr: "127.0.0.1:40080".into(),
                    username: None,
                    password: None,
                },
                &nodes,
                &self_ports,
            )
            .unwrap_err()
            .code,
            "ERR_NODE_SELF_LOOP"
        );
        assert_eq!(
            add_node(
                AddNodeRequest {
                    name: "BadHttpUser".into(),
                    protocol: "HTTP".into(),
                    server_addr: "10.0.0.2:8080".into(),
                    username: Some("a:b".into()),
                    password: Some("pw".into()),
                },
                &nodes,
                &self_ports,
            )
            .unwrap_err()
            .code,
            "ERR_HTTP_USERNAME_COLON"
        );
        assert_eq!(
            add_node(
                AddNodeRequest {
                    name: "Socks4Pw".into(),
                    protocol: "SOCKS4".into(),
                    server_addr: "10.0.0.2:1080".into(),
                    username: Some("uid".into()),
                    password: Some("".into()),
                },
                &nodes,
                &self_ports,
            )
            .unwrap_err()
            .code,
            "ERR_SOCKS4_PASSWORD_UNSUPPORTED"
        );
        assert_eq!(
            add_node(
                AddNodeRequest {
                    name: "EmptyPw".into(),
                    protocol: "SOCKS5".into(),
                    server_addr: "10.0.0.2:1080".into(),
                    username: Some("alice".into()),
                    password: Some("".into()),
                },
                &nodes,
                &self_ports,
            )
            .unwrap_err()
            .code,
            "ERR_EMPTY_PASSWORD"
        );
        assert_eq!(
            add_node(
                AddNodeRequest {
                    name: "NoPw".into(),
                    protocol: "SOCKS5".into(),
                    server_addr: "10.0.0.2:1080".into(),
                    username: Some("alice".into()),
                    password: None,
                },
                &nodes,
                &self_ports,
            )
            .unwrap_err()
            .code,
            "ERR_USERNAME_WITHOUT_PASSWORD"
        );
        assert_eq!(
            add_node(
                AddNodeRequest {
                    name: "PwNoUser".into(),
                    protocol: "SOCKS5".into(),
                    server_addr: "10.0.0.2:1080".into(),
                    username: None,
                    password: Some("secret".into()),
                },
                &nodes,
                &self_ports,
            )
            .unwrap_err()
            .code,
            "ERR_PASSWORD_WITHOUT_USERNAME"
        );

        // Add valid SOCKS5 (with auth) and SOCKS4 (with user_id)
        let id1 = add_node(
            AddNodeRequest {
                name: "S5".into(),
                protocol: "socks5".into(),
                server_addr: "10.0.0.2:1080".into(),
                username: Some("alice".into()),
                password: Some("secret".into()),
            },
            &nodes,
            &self_ports,
        )
        .unwrap();
        let id2 = add_node(
            AddNodeRequest {
                name: "S4".into(),
                protocol: "SOCKS4".into(),
                server_addr: "10.0.0.3:1080".into(),
                username: Some("uid".into()),
                password: None,
            },
            &nodes,
            &self_ports,
        )
        .unwrap();
        let listed = list_nodes(&nodes);
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id, id1);
        assert!(listed[0].auth_configured && listed[0].password_configured);
        assert_eq!(listed[1].id, id2);
        assert!(listed[1].auth_configured && !listed[1].password_configured);

        // update_node (PUT): keep_password defaults to false -> fails if reusing username without password
        assert_eq!(
            update_node(
                UpdateNodeRequest {
                    id: id1,
                    name: "S5".into(),
                    protocol: "SOCKS5".into(),
                    server_addr: "10.0.0.2:1080".into(),
                    username: Some("alice".into()),
                    password: None,
                    keep_password: None,
                    clear_password: None,
                },
                &nodes,
                &self_ports,
            )
            .unwrap_err()
            .code,
            "ERR_USERNAME_WITHOUT_PASSWORD"
        );
        // Changing username with keep_password=true requires new password
        assert_eq!(
            update_node(
                UpdateNodeRequest {
                    id: id1,
                    name: "S5".into(),
                    protocol: "SOCKS5".into(),
                    server_addr: "10.0.0.2:1080".into(),
                    username: Some("bob".into()),
                    password: None,
                    keep_password: Some(true),
                    clear_password: None,
                },
                &nodes,
                &self_ports,
            )
            .unwrap_err()
            .code,
            "ERR_PASSWORD_REQUIRED_ON_USER_CHANGE"
        );
        // Valid PUT with keep_password=true preserves secret
        update_node(
            UpdateNodeRequest {
                id: id1,
                name: "S5-Renamed".into(),
                protocol: "HTTP".into(),
                server_addr: "10.0.0.2:8080".into(),
                username: Some("alice".into()),
                password: None,
                keep_password: Some(true),
                clear_password: None,
            },
            &nodes,
            &self_ports,
        )
        .unwrap();
        assert_eq!(
            nodes
                .read()
                .unwrap()
                .get(&id1)
                .unwrap()
                .client
                .auth_credentials(),
            (Some("alice"), Some("secret"))
        );

        // patch_node: conflicting clear_username + username -> 400; clear_username + clear_password=false -> 400
        assert_eq!(
            patch_node(
                PatchNodeRequest {
                    id: id1,
                    name: None,
                    protocol: None,
                    server_addr: None,
                    username: Some("carol".into()),
                    password: None,
                    keep_password: None,
                    clear_password: None,
                    clear_username: Some(true),
                },
                &nodes,
                &self_ports,
            )
            .unwrap_err()
            .code,
            "ERR_CONFLICTING_USERNAME_OPTIONS"
        );
        assert_eq!(
            patch_node(
                PatchNodeRequest {
                    id: id1,
                    name: None,
                    protocol: None,
                    server_addr: None,
                    username: None,
                    password: None,
                    keep_password: None,
                    clear_password: Some(false),
                    clear_username: Some(true),
                },
                &nodes,
                &self_ports,
            )
            .unwrap_err()
            .code,
            "ERR_CONFLICTING_PASSWORD_OPTIONS"
        );
        // Valid patch with clear_username clears both username & password
        patch_node(
            PatchNodeRequest {
                id: id1,
                name: None,
                protocol: None,
                server_addr: None,
                username: None,
                password: None,
                keep_password: None,
                clear_password: None,
                clear_username: Some(true),
            },
            &nodes,
            &self_ports,
        )
        .unwrap();
        assert!(
            !nodes
                .read()
                .unwrap()
                .get(&id1)
                .unwrap()
                .is_auth_configured()
        );

        // delete_node blocks deletion when referenced by rule or default_action
        let engine_rule_ref = RuleEngine::new(
            vec![Rule::from_raw(
                "RefId1",
                true,
                None,
                None,
                None,
                Action::Proxy(id1),
            )],
            Action::Proxy(id2),
        );
        let err_rule = delete_node(id1, &nodes, &engine_rule_ref).unwrap_err();
        assert_eq!(err_rule.kind, ControlErrorKind::Conflict);
        assert_eq!(err_rule.code, "ERR_NODE_IN_USE");
        let err_def = delete_node(id2, &nodes, &engine_rule_ref).unwrap_err();
        assert_eq!(err_def.kind, ControlErrorKind::Conflict);
        assert_eq!(err_def.code, "ERR_NODE_IN_USE");

        let empty_engine = RuleEngine::new(Vec::new(), Action::Direct);
        delete_node(id2, &nodes, &empty_engine).unwrap();
        let err_missing = delete_node(id2, &nodes, &empty_engine).unwrap_err();
        assert_eq!(err_missing.kind, ControlErrorKind::NotFound);
        assert_eq!(err_missing.code, "ERR_NODE_NOT_FOUND");
    }
}
