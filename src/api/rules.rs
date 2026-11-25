use std::collections::HashMap;
use std::sync::RwLock;

use crate::api::http::parse_query_param;
use crate::api::{JSON_CONTENT_TYPE, control_error_to_http, serde_json_to_string};
use crate::control::routing::{set_default_action, simulate_route_with_pool};
use crate::control::rule::{
    add_rule, delete_rule, move_rule, patch_rule, toggle_rule, update_rule,
};
use crate::control::{
    AddRuleRequest, MoveRuleRequest, PatchRuleRequest, SetDefaultActionRequest,
    SimulateRouteRequest, SystemRuntimeContext, ToggleRuleRequest, UpdateRuleRequest,
};
use crate::i18n::{Locale, json_error};
use crate::interceptor::dispatcher::ProxyNodeEntry;
use crate::router::RuleEngine;

pub(super) fn handle_list_rules(
    rule_engine: &RuleEngine,
    locale: Locale,
) -> (&'static str, &'static str, String) {
    let list = rule_engine.list_rules_view_with_locale(locale);
    ("200 OK", JSON_CONTENT_TYPE, serde_json_to_string(&list))
}

pub(super) fn handle_post_rule(
    req_body: &str,
    rule_engine: &RuleEngine,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    locale: Locale,
    should_persist: &mut bool,
) -> (&'static str, &'static str, String) {
    match serde_json::from_str::<AddRuleRequest>(req_body) {
        Err(_) => (
            "400 Bad Request",
            JSON_CONTENT_TYPE,
            json_error(locale, "ERR_INVALID_RULE_BODY", "error.invalid_rule_body"),
        ),
        Ok(req) => match add_rule(req, rule_engine, proxy_nodes) {
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

pub(super) fn handle_put_rule(
    req_body: &str,
    rule_engine: &RuleEngine,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    locale: Locale,
    should_persist: &mut bool,
) -> (&'static str, &'static str, String) {
    match serde_json::from_str::<UpdateRuleRequest>(req_body) {
        Err(_) => (
            "400 Bad Request",
            JSON_CONTENT_TYPE,
            json_error(locale, "ERR_INVALID_RULE_BODY", "error.invalid_rule_body"),
        ),
        Ok(req) => match update_rule(req, rule_engine, proxy_nodes) {
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

pub(super) fn handle_patch_rule_http(
    req_body: &str,
    rule_engine: &RuleEngine,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    locale: Locale,
    should_persist: &mut bool,
) -> (&'static str, &'static str, String) {
    match serde_json::from_str::<PatchRuleRequest>(req_body) {
        Err(_) => (
            "400 Bad Request",
            JSON_CONTENT_TYPE,
            json_error(locale, "ERR_INVALID_RULE_BODY", "error.invalid_rule_body"),
        ),
        Ok(req) => match patch_rule(req, rule_engine, proxy_nodes) {
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

pub(super) fn handle_set_default(
    req_body: &str,
    rule_engine: &RuleEngine,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    locale: Locale,
    should_persist: &mut bool,
) -> (&'static str, &'static str, String) {
    match serde_json::from_str::<SetDefaultActionRequest>(req_body) {
        Err(_) => (
            "400 Bad Request",
            JSON_CONTENT_TYPE,
            json_error(
                locale,
                "ERR_INVALID_DEFAULT_ACTION_BODY",
                "error.invalid_default_action_body",
            ),
        ),
        Ok(req) => match set_default_action(req, rule_engine, proxy_nodes, locale) {
            Ok(resp) => {
                *should_persist = true;
                ("200 OK", JSON_CONTENT_TYPE, serde_json_to_string(&resp))
            }
            Err(err) => control_error_to_http(err, locale),
        },
    }
}

pub(super) fn handle_simulate(
    req_body: &str,
    rule_engine: &RuleEngine,
    runtime_context: Option<&SystemRuntimeContext>,
    locale: Locale,
) -> (&'static str, &'static str, String) {
    match serde_json::from_str::<SimulateRouteRequest>(req_body) {
        Err(_) => (
            "400 Bad Request",
            JSON_CONTENT_TYPE,
            json_error(
                locale,
                "ERR_INVALID_SIMULATE_BODY",
                "error.invalid_simulate_body",
            ),
        ),
        Ok(req) => match simulate_route_with_pool(
            req,
            rule_engine,
            runtime_context.map(|c| c.fake_ip_pool.as_ref()),
            locale,
        ) {
            Ok(resp) => ("200 OK", JSON_CONTENT_TYPE, serde_json_to_string(&resp)),
            Err(err) => control_error_to_http(err, locale),
        },
    }
}

pub(super) fn handle_toggle_rule(
    req_body: &str,
    rule_engine: &RuleEngine,
    locale: Locale,
    should_persist: &mut bool,
) -> (&'static str, &'static str, String) {
    match serde_json::from_str::<ToggleRuleRequest>(req_body) {
        Err(_) => (
            "400 Bad Request",
            JSON_CONTENT_TYPE,
            json_error(
                locale,
                "ERR_INVALID_TOGGLE_BODY",
                "error.invalid_toggle_body",
            ),
        ),
        Ok(req) => match toggle_rule(req, rule_engine) {
            Ok(enabled) => {
                *should_persist = true;
                (
                    "200 OK",
                    JSON_CONTENT_TYPE,
                    format!(r#"{{"ok":true,"enabled":{}}}"#, enabled),
                )
            }
            Err(err) => control_error_to_http(err, locale),
        },
    }
}

pub(super) fn handle_move_rule(
    req_body: &str,
    rule_engine: &RuleEngine,
    locale: Locale,
    should_persist: &mut bool,
) -> (&'static str, &'static str, String) {
    match serde_json::from_str::<MoveRuleRequest>(req_body) {
        Err(_) => (
            "400 Bad Request",
            JSON_CONTENT_TYPE,
            json_error(locale, "ERR_INVALID_MOVE_BODY", "error.invalid_move_body"),
        ),
        Ok(req) => match move_rule(req, rule_engine) {
            Ok(changed) => {
                if changed {
                    *should_persist = true;
                }
                (
                    "200 OK",
                    JSON_CONTENT_TYPE,
                    format!(r#"{{"ok":true,"moved":{}}}"#, changed),
                )
            }
            Err(err) => control_error_to_http(err, locale),
        },
    }
}

pub(super) fn handle_delete_rule(
    query: &str,
    req_body: &str,
    rule_engine: &RuleEngine,
    locale: Locale,
    should_persist: &mut bool,
) -> (&'static str, &'static str, String) {
    let id: Option<u64> = parse_query_param(query, "id")
        .and_then(|v| v.parse().ok())
        .or_else(|| {
            serde_json::from_str::<serde_json::Value>(req_body)
                .ok()
                .and_then(|v| v.get("id").and_then(|i| i.as_u64()))
        });
    if let Some(rule_id) = id {
        match delete_rule(rule_id, rule_engine) {
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
            json_error(locale, "ERR_MISSING_RULE_ID", "error.missing_rule_id"),
        )
    }
}
