use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::config::ConfigStore;
use crate::control::ControlError;
use crate::control::rule::parse_and_validate_action;
use crate::control::transparent::transparent_status_or_fallback;
use crate::dns::FakeIpPool;
use crate::i18n::{Locale, t};
use crate::interceptor::dispatcher::ProxyNodeEntry;
use crate::outbound::TargetAddr;
use crate::router::{RouteContext, RuleEngine, RuleTraceStep};
use crate::transparent::{TransparentManager, TransparentRuntimeStatus};

#[derive(Debug, Deserialize)]
pub struct SetDefaultActionRequest {
    pub action: String, // "Direct", "Block", "Proxy"
    pub node_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultActionResponse {
    pub ok: bool,
    pub default_action: String,
    pub default_action_type: String,
    pub default_node_id: Option<u32>,
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
    pub trace: Vec<RuleTraceStep>,
}

#[derive(Debug, Clone)]
pub struct SystemRuntimeContext {
    pub inbound_addr: SocketAddr,
    pub dns_addr: SocketAddr,
    pub upstream_dns: SocketAddr,
    pub api_addr: SocketAddr,
    pub fake_ip_pool: Arc<FakeIpPool>,
    /// 本地 Fake-IP DNS 服务是否拦截 `AAAA`/`SVCB`/`HTTPS` 防泄漏（仅作用于本地 DNS 入站）
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
    pub transparent: TransparentRuntimeStatus,
}

pub fn set_default_action(
    req: SetDefaultActionRequest,
    rule_engine: &RuleEngine,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    locale: Locale,
) -> Result<DefaultActionResponse, ControlError> {
    let action = parse_and_validate_action(&req.action, req.node_id, proxy_nodes)?;
    rule_engine.set_default_action(action.clone());
    Ok(DefaultActionResponse {
        ok: true,
        default_action: crate::router::format_action_desc(&action, locale),
        default_action_type: action.type_str().to_string(),
        default_node_id: action.target_id(),
    })
}

pub fn parse_simulate_target(
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

    let parsed =
        TargetAddr::parse_authority(trimmed, Some(explicit_port.unwrap_or(443)), false).ok()?;
    let port = explicit_port.unwrap_or_else(|| parsed.port());
    match parsed {
        TargetAddr::Ip(addr) => Some((addr.ip().to_string(), Some(addr.ip()), port)),
        TargetAddr::Domain(host, _) => Some((host, None, port)),
    }
}

pub fn simulate_route(
    req: SimulateRouteRequest,
    rule_engine: &RuleEngine,
    locale: Locale,
) -> Result<SimulateRouteResponse, ControlError> {
    simulate_route_with_pool(req, rule_engine, None, locale)
}

pub fn simulate_route_with_pool(
    req: SimulateRouteRequest,
    rule_engine: &RuleEngine,
    fake_ip_pool: Option<&FakeIpPool>,
    locale: Locale,
) -> Result<SimulateRouteResponse, ControlError> {
    let Some((parsed_host, ip_opt, target_port)) = parse_simulate_target(&req.target, req.port)
    else {
        return Err(ControlError::bad_request(
            "ERR_INVALID_SIMULATE_TARGET",
            "error.invalid_simulate_target",
        ));
    };

    // 与真实流量调度保持完全一致：Fake-IP（含 IPv4 映射 IPv6）还原为原域名；真实 IP 字面量不设 target_host（仅传 target_ip）
    let (target_host, target_ip) = match ip_opt {
        Some(ip) if fake_ip_pool.is_some_and(|p| p.is_fake_ip_addr(ip)) => {
            match fake_ip_pool.and_then(|p| p.restore_ip(ip)) {
                Some(domain) => (Some(domain), None),
                None => (None, Some(ip)),
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

    let ctx = RouteContext {
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

    Ok(SimulateRouteResponse {
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
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_system_info(
    actual_port: u16,
    runtime_ctx: Option<&SystemRuntimeContext>,
    config_store: Option<&ConfigStore>,
    transparent_manager: Option<&TransparentManager>,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    rule_engine: &RuleEngine,
    started_at: Instant,
    locale: Locale,
) -> SystemInfoResponse {
    let nodes_count = proxy_nodes.read().unwrap_or_else(|e| e.into_inner()).len();
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
        transparent: transparent_status_or_fallback(transparent_manager),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::{Action, Rule};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_parse_simulate_target_edge_cases() {
        assert_eq!(parse_simulate_target("", None), None);
        assert_eq!(parse_simulate_target("   ", Some(443)), None);
        assert_eq!(parse_simulate_target("example.com", Some(0)), None);
        assert_eq!(parse_simulate_target("example.com:0", None), None);

        assert_eq!(
            parse_simulate_target("1.1.1.1", None),
            Some((
                "1.1.1.1".to_string(),
                Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                443
            ))
        );
        assert_eq!(
            parse_simulate_target("2001:db8::1", Some(8443)),
            Some((
                "2001:db8::1".to_string(),
                Some(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap())),
                8443
            ))
        );
        assert_eq!(
            parse_simulate_target("[::1]:8080", None),
            Some((
                "::1".to_string(),
                Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                8080
            ))
        );
        assert_eq!(
            parse_simulate_target("api.github.com:8443", None),
            Some(("api.github.com".to_string(), None, 8443))
        );
        // Explicit port overrides authority port
        assert_eq!(
            parse_simulate_target("api.github.com:8443", Some(9000)),
            Some(("api.github.com".to_string(), None, 9000))
        );
    }

    #[test]
    fn test_simulate_route_with_pool_fake_ip_and_windows_process_path() {
        let pool = FakeIpPool::new_default();
        let fake_ip = pool.allocate("api.github.com");
        let rules = vec![Rule::from_raw_with_id(
            7,
            "GitProxy",
            true,
            Some("git.exe"),
            Some("*.github.com"),
            Some("443"),
            Action::Proxy(101),
        )];
        let engine = RuleEngine::new(rules, Action::Direct);

        let matched = simulate_route_with_pool(
            SimulateRouteRequest {
                process: Some(r"C:\Program Files\Git\cmd\git.exe".to_string()),
                target: format!("{fake_ip}:443"),
                port: None,
            },
            &engine,
            Some(&pool),
            Locale::En,
        )
        .unwrap();
        assert!(!matched.is_default);
        assert_eq!(matched.matched_rule_id, Some(7));
        assert_eq!(matched.process_name.as_deref(), Some("git.exe"));
        assert_eq!(
            matched.process_path.as_deref(),
            Some(r"C:\Program Files\Git\cmd\git.exe")
        );
        assert_eq!(matched.target_host.as_deref(), Some("api.github.com"));
        assert_eq!(matched.target_ip, None);
        assert_eq!(matched.action_type, "Proxy");
        assert_eq!(matched.node_id, Some(101));

        // Unmapped Fake-IP falls back to IP literal and default action
        let unmapped = simulate_route_with_pool(
            SimulateRouteRequest {
                process: None,
                target: "198.18.250.250:443".to_string(),
                port: None,
            },
            &engine,
            Some(&pool),
            Locale::Zh,
        )
        .unwrap();
        assert!(unmapped.is_default);
        assert_eq!(unmapped.target_host, None);
        assert_eq!(unmapped.target_ip.as_deref(), Some("198.18.250.250"));
        assert_eq!(unmapped.action_type, "Direct");

        // Invalid simulate targets fail with ERR_INVALID_SIMULATE_TARGET (400)
        for (bad_target, bad_port) in [
            ("", None),
            ("   ", Some(443)),
            ("example.com", Some(0)),
            ("example.com:0", None),
        ] {
            let err = simulate_route(
                SimulateRouteRequest {
                    process: None,
                    target: bad_target.to_string(),
                    port: bad_port,
                },
                &engine,
                Locale::En,
            )
            .unwrap_err();
            assert_eq!(err.code, "ERR_INVALID_SIMULATE_TARGET");
            assert_eq!(err.kind, crate::control::ControlErrorKind::BadRequest);
            assert_eq!(err.message_key, "error.invalid_simulate_target");
        }
    }

    #[test]
    fn test_set_default_action_validation_and_updates() {
        use crate::control::ControlErrorKind;
        use crate::outbound::chain::ProxyNode;
        use crate::outbound::socks5::Socks5Client;

        let engine = RuleEngine::new(Vec::new(), Action::Direct);
        let mut map = HashMap::new();
        map.insert(
            101,
            ProxyNodeEntry {
                id: 101,
                name: "Main".into(),
                protocol: "SOCKS5".into(),
                server_addr: "10.0.0.2:1080".into(),
                username: None,
                client: ProxyNode::Socks5(Socks5Client::new("10.0.0.2:1080")),
            },
        );
        let nodes = RwLock::new(map);

        // Missing proxy node -> ERR_NODE_NOT_FOUND; invalid action -> ERR_INVALID_RULE_ACTION
        let err_missing = set_default_action(
            SetDefaultActionRequest {
                action: "Proxy".into(),
                node_id: Some(999),
            },
            &engine,
            &nodes,
            Locale::En,
        )
        .unwrap_err();
        assert_eq!(err_missing.kind, ControlErrorKind::BadRequest);
        assert_eq!(err_missing.code, "ERR_NODE_NOT_FOUND");
        assert_eq!(err_missing.message_key, "error.node_not_found");

        let err_invalid = set_default_action(
            SetDefaultActionRequest {
                action: "Unknown".into(),
                node_id: None,
            },
            &engine,
            &nodes,
            Locale::En,
        )
        .unwrap_err();
        assert_eq!(err_invalid.kind, ControlErrorKind::BadRequest);
        assert_eq!(err_invalid.code, "ERR_INVALID_RULE_ACTION");
        assert_eq!(err_invalid.message_key, "error.invalid_rule_action");

        let proxy_en = set_default_action(
            SetDefaultActionRequest {
                action: "Proxy".into(),
                node_id: Some(101),
            },
            &engine,
            &nodes,
            Locale::En,
        )
        .unwrap();
        assert!(proxy_en.ok);
        assert_eq!(proxy_en.default_action_type, "Proxy");
        assert_eq!(proxy_en.default_node_id, Some(101));
        assert!(
            proxy_en.default_action.contains("101"),
            "unexpected en proxy action: {}",
            proxy_en.default_action
        );
        assert_eq!(engine.default_action(), Action::Proxy(101));

        let block_en = set_default_action(
            SetDefaultActionRequest {
                action: "Block".into(),
                node_id: None,
            },
            &engine,
            &nodes,
            Locale::En,
        )
        .unwrap();
        let block_zh = set_default_action(
            SetDefaultActionRequest {
                action: "Block".into(),
                node_id: None,
            },
            &engine,
            &nodes,
            Locale::Zh,
        )
        .unwrap();
        assert!(block_zh.ok);
        assert_eq!(block_zh.default_action_type, "Block");
        assert_eq!(block_zh.default_node_id, None);
        assert_ne!(
            block_en.default_action, block_zh.default_action,
            "localized default_action text should differ between En and Zh"
        );
        assert_eq!(engine.default_action(), Action::Block);
    }

    #[test]
    fn test_build_system_info_memory_and_runtime_context() {
        use crate::outbound::chain::ProxyNode;
        use crate::outbound::socks5::Socks5Client;

        let mut map = HashMap::new();
        map.insert(
            101,
            ProxyNodeEntry {
                id: 101,
                name: "Node101".into(),
                protocol: "SOCKS5".into(),
                server_addr: "10.0.0.2:1080".into(),
                username: None,
                client: ProxyNode::Socks5(Socks5Client::new("10.0.0.2:1080")),
            },
        );
        let nodes = RwLock::new(map);
        let engine = RuleEngine::new(
            vec![
                Rule::from_raw("R1", true, None, None, None, Action::Direct),
                Rule::from_raw("R2", false, None, None, None, Action::Block),
            ],
            Action::Proxy(101),
        );
        let started = Instant::now();

        // Memory-only fallback when runtime_ctx and config_store are None
        let mem_en = build_system_info(
            41080,
            None,
            None,
            None,
            &nodes,
            &engine,
            started,
            Locale::En,
        );
        let mem_zh = build_system_info(
            41080,
            None,
            None,
            None,
            &nodes,
            &engine,
            started,
            Locale::Zh,
        );
        assert_eq!(mem_en.api_addr, "127.0.0.1:41080");
        assert_eq!(mem_en.nodes_count, 1);
        assert_eq!(mem_en.rules_count, 2);
        assert_eq!(mem_en.enabled_rules_count, 1);
        assert_eq!(mem_en.default_action_type, "Proxy");
        assert_eq!(mem_en.default_node_id, Some(101));
        assert_eq!(mem_en.fake_ip_count, 0);
        assert_ne!(mem_en.config_path, mem_zh.config_path);

        // Full runtime_ctx + config_store populates live addresses & fake_ip_count
        let pool = Arc::new(FakeIpPool::new_default());
        let _ = pool.allocate("demo.example.com");
        let ctx = SystemRuntimeContext {
            inbound_addr: "127.0.0.1:41001".parse().unwrap(),
            dns_addr: "127.0.0.1:1153".parse().unwrap(),
            upstream_dns: "1.1.1.1:53".parse().unwrap(),
            api_addr: "127.0.0.1:41080".parse().unwrap(),
            fake_ip_pool: pool,
            block_ipv6: true,
            started_at: started,
        };
        let store = ConfigStore::new("custom-test.xml");
        let full = build_system_info(
            41080,
            Some(&ctx),
            Some(&store),
            None,
            &nodes,
            &engine,
            started,
            Locale::En,
        );
        assert_eq!(full.inbound_addr, "127.0.0.1:41001");
        assert_eq!(full.dns_addr, "127.0.0.1:1153");
        assert_eq!(full.upstream_dns, "1.1.1.1:53");
        assert_eq!(full.fake_ip_count, 1);
        assert_eq!(full.config_path, "custom-test.xml");
    }
}
