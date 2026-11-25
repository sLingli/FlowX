use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

use crate::api::http::parse_query_param;
use crate::api::{serde_json_to_string, JSON_CONTENT_TYPE};
use crate::config::ConfigStore;
use crate::control::routing::{build_system_info, SystemRuntimeContext};
use crate::i18n::{json_error, t, Locale};
use crate::interceptor::dispatcher::ProxyNodeEntry;
use crate::monitor::{ConnectionManager, ConnectionSnapshot};
use crate::router::{Action, RuleEngine};
use crate::transparent::TransparentManager;

pub(super) fn handle_dashboard() -> (&'static str, &'static str, String) {
    let html = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/frontend/index.html"));
    ("200 OK", "text/html; charset=utf-8", html.to_string())
}

pub(super) fn handle_health() -> (&'static str, &'static str, String) {
    (
        "200 OK",
        JSON_CONTENT_TYPE,
        r#"{"status":"ok","engine":"FlowX"}"#.to_string(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_system_info(
    actual_port: u16,
    runtime_context: Option<&SystemRuntimeContext>,
    config_store: Option<&ConfigStore>,
    transparent_manager: Option<&TransparentManager>,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    rule_engine: &RuleEngine,
    started_at: Instant,
    locale: Locale,
) -> (&'static str, &'static str, String) {
    let info = build_system_info(
        actual_port,
        runtime_context,
        config_store,
        transparent_manager,
        proxy_nodes,
        rule_engine,
        started_at,
        locale,
    );
    ("200 OK", JSON_CONTENT_TYPE, serde_json_to_string(&info))
}

pub(super) fn handle_stats(monitor: &ConnectionManager) -> (&'static str, &'static str, String) {
    let stats = monitor.global_stats();
    ("200 OK", JSON_CONTENT_TYPE, serde_json_to_string(&stats))
}

pub(super) fn handle_list_connections(
    monitor: &ConnectionManager,
    locale: Locale,
) -> (&'static str, &'static str, String) {
    let mut list = monitor.list_snapshots();
    for conn in &mut list {
        localize_connection_view(conn, locale);
    }
    ("200 OK", JSON_CONTENT_TYPE, serde_json_to_string(&list))
}

pub(super) fn handle_kill_connection(
    monitor: &ConnectionManager,
    query: &str,
    req_body: &str,
    locale: Locale,
) -> (&'static str, &'static str, String) {
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
            JSON_CONTENT_TYPE,
            format!(r#"{{"ok":true,"killed":{}}}"#, killed),
        )
    } else {
        (
            "400 Bad Request",
            JSON_CONTENT_TYPE,
            json_error(locale, "ERR_MISSING_CONN_ID", "error.missing_conn_id"),
        )
    }
}

/// 将连接快照中的机器可读字段按请求语言格式化为展示文案。
///
/// `action_type` / `action_id` 保持英文机器语义，供前端做分支判断与过滤；
/// `action` / `rule_name` / 进程占位名才是给人看的多语言文案。
fn localize_connection_view(conn: &mut ConnectionSnapshot, locale: Locale) {
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
