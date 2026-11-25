use std::collections::HashMap;
use std::sync::RwLock;

use tokio::sync::Semaphore;

use crate::api::http::parse_query_param;
use crate::api::{control_error_to_http, serde_json_to_string, JSON_CONTENT_TYPE};
use crate::control::node::{
    add_node, delete_node, list_nodes, patch_node, ping_address_with_context, update_node,
};
use crate::control::{
    AddNodeRequest, PatchNodeRequest, PingNodeRequest, PingResponse, SystemRuntimeContext,
    UpdateNodeRequest,
};
use crate::i18n::{json_error, Locale};
use crate::interceptor::dispatcher::ProxyNodeEntry;
use crate::router::RuleEngine;

pub(super) fn handle_list_nodes(
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
) -> (&'static str, &'static str, String) {
    let list = list_nodes(proxy_nodes);
    ("200 OK", JSON_CONTENT_TYPE, serde_json_to_string(&list))
}

pub(super) fn handle_post_node(
    req_body: &str,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    self_ports: &[u16],
    locale: Locale,
    should_persist: &mut bool,
) -> (&'static str, &'static str, String) {
    match serde_json::from_str::<AddNodeRequest>(req_body) {
        Err(_) => (
            "400 Bad Request",
            JSON_CONTENT_TYPE,
            json_error(locale, "ERR_INVALID_NODE_BODY", "error.invalid_node_body"),
        ),
        Ok(req) => match add_node(req, proxy_nodes, self_ports) {
            Ok(new_id) => {
                *should_persist = true;
                (
                    "200 OK",
                    JSON_CONTENT_TYPE,
                    format!(r#"{{"ok":true,"id":{}}}"#, new_id),
                )
            }
            Err(err) => control_error_to_http(err, locale),
        },
    }
}

pub(super) fn handle_put_node(
    req_body: &str,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    self_ports: &[u16],
    locale: Locale,
    should_persist: &mut bool,
) -> (&'static str, &'static str, String) {
    match serde_json::from_str::<UpdateNodeRequest>(req_body) {
        Err(_) => (
            "400 Bad Request",
            JSON_CONTENT_TYPE,
            json_error(locale, "ERR_INVALID_NODE_BODY", "error.invalid_node_body"),
        ),
        Ok(req) => match update_node(req, proxy_nodes, self_ports) {
            Ok(id) => {
                *should_persist = true;
                (
                    "200 OK",
                    JSON_CONTENT_TYPE,
                    format!(r#"{{"ok":true,"id":{}}}"#, id),
                )
            }
            Err(err) => control_error_to_http(err, locale),
        },
    }
}

pub(super) fn handle_patch_node_http(
    req_body: &str,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    self_ports: &[u16],
    locale: Locale,
    should_persist: &mut bool,
) -> (&'static str, &'static str, String) {
    match serde_json::from_str::<PatchNodeRequest>(req_body) {
        Err(_) => (
            "400 Bad Request",
            JSON_CONTENT_TYPE,
            json_error(locale, "ERR_INVALID_NODE_BODY", "error.invalid_node_body"),
        ),
        Ok(req) => match patch_node(req, proxy_nodes, self_ports) {
            Ok(id) => {
                *should_persist = true;
                (
                    "200 OK",
                    JSON_CONTENT_TYPE,
                    format!(r#"{{"ok":true,"id":{}}}"#, id),
                )
            }
            Err(err) => control_error_to_http(err, locale),
        },
    }
}

pub(super) fn handle_delete_node(
    query: &str,
    req_body: &str,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    rule_engine: &RuleEngine,
    locale: Locale,
    should_persist: &mut bool,
) -> (&'static str, &'static str, String) {
    let id: Option<u32> = parse_query_param(query, "id")
        .and_then(|v| v.parse().ok())
        .or_else(|| {
            serde_json::from_str::<serde_json::Value>(req_body)
                .ok()
                .and_then(|v| v.get("id").and_then(|i| i.as_u64()))
                .and_then(|n| u32::try_from(n).ok())
        });
    if let Some(node_id) = id {
        match delete_node(node_id, proxy_nodes, rule_engine) {
            Ok(()) => {
                *should_persist = true;
                ("200 OK", JSON_CONTENT_TYPE, r#"{"ok":true}"#.to_string())
            }
            Err(err) => control_error_to_http(err, locale),
        }
    } else {
        (
            "400 Bad Request",
            JSON_CONTENT_TYPE,
            json_error(locale, "ERR_MISSING_NODE_ID", "error.missing_node_id"),
        )
    }
}

pub(super) async fn handle_ping_node(
    query: &str,
    req_body: &str,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    self_ports: &[u16],
    runtime_context: Option<&SystemRuntimeContext>,
    ping_semaphore: &Semaphore,
    locale: Locale,
) -> (&'static str, &'static str, String) {
    let node_id: Option<u32> = parse_query_param(query, "id")
        .and_then(|v| v.parse().ok())
        .or_else(|| {
            serde_json::from_str::<PingNodeRequest>(req_body)
                .ok()
                .map(|p| p.id)
        });
    if let Some(id) = node_id {
        let target_addr = {
            let nodes_guard = proxy_nodes.read().unwrap_or_else(|e| e.into_inner());
            nodes_guard.get(&id).map(|n| n.server_addr.clone())
        };
        if let Some(addr) = target_addr {
            let (ok, ms, msg, detail) = ping_address_with_context(
                &addr,
                self_ports,
                runtime_context,
                Some(ping_semaphore),
                locale,
            )
            .await;
            let ping_res = PingResponse {
                ok,
                latency_ms: ms,
                message: msg,
                detail,
            };
            (
                "200 OK",
                JSON_CONTENT_TYPE,
                serde_json_to_string(&ping_res),
            )
        } else {
            (
                "404 Not Found",
                JSON_CONTENT_TYPE,
                json_error(locale, "ERR_NODE_NOT_FOUND", "error.node_not_found"),
            )
        }
    } else {
        (
            "400 Bad Request",
            JSON_CONTENT_TYPE,
            json_error(locale, "ERR_MISSING_NODE_ID", "error.missing_node_id"),
        )
    }
}
