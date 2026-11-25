use std::collections::HashMap;
use std::sync::RwLock;

use serde::Deserialize;

use crate::control::ControlError;
use crate::interceptor::dispatcher::ProxyNodeEntry;
use crate::router::{Action, Rule, RuleEngine};

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
pub struct ToggleRuleRequest {
    pub id: u64,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct MoveRuleRequest {
    pub id: u64,
    pub direction: String, // "up" | "down" | "top" | "bottom"
}

pub(crate) fn parse_and_validate_action(
    action_raw: &str,
    node_id: Option<u32>,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
) -> Result<Action, ControlError> {
    match action_raw.trim().to_ascii_uppercase().as_str() {
        "DIRECT" => Ok(Action::Direct),
        "BLOCK" => Ok(Action::Block),
        "PROXY" => {
            let Some(nid) = node_id else {
                return Err(ControlError::bad_request(
                    "ERR_MISSING_NODE_FOR_PROXY",
                    "error.missing_node_id_for_proxy",
                ));
            };
            let exists = {
                let nodes_guard = proxy_nodes.read().unwrap_or_else(|e| e.into_inner());
                nodes_guard.contains_key(&nid)
            };
            if !exists {
                return Err(ControlError::bad_request(
                    "ERR_NODE_NOT_FOUND",
                    "error.node_not_found",
                ));
            }
            Ok(Action::Proxy(nid))
        }
        _ => Err(ControlError::bad_request(
            "ERR_INVALID_RULE_ACTION",
            "error.invalid_rule_action",
        )),
    }
}

fn validate_rule_probe(
    rule: &Rule,
    apps_clean: Option<&str>,
    targets_clean: Option<&str>,
    ports_clean: Option<&str>,
) -> Result<(), ControlError> {
    if apps_clean.is_some()
        && rule
            .application_patterns
            .as_ref()
            .is_some_and(Vec::is_empty)
    {
        return Err(ControlError::bad_request(
            "ERR_INVALID_APP_PATTERN",
            "error.invalid_app_pattern",
        ));
    }
    if targets_clean.is_some()
        && rule.target_subnets.is_none()
        && rule.target_domains.as_ref().is_some_and(Vec::is_empty)
    {
        return Err(ControlError::bad_request(
            "ERR_INVALID_TARGET_PATTERN",
            "error.invalid_target_pattern",
        ));
    }
    if ports_clean.is_some() && rule.ports.as_ref().is_some_and(Vec::is_empty) {
        return Err(ControlError::bad_request(
            "ERR_INVALID_PORT_FORMAT",
            "error.invalid_port_format",
        ));
    }
    Ok(())
}

pub fn add_rule(
    req: AddRuleRequest,
    rule_engine: &RuleEngine,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
) -> Result<u64, ControlError> {
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(ControlError::bad_request(
            "ERR_EMPTY_RULE_NAME",
            "error.empty_rule_name",
        ));
    }

    let action = parse_and_validate_action(&req.action, req.node_id, proxy_nodes)?;

    let apps_clean = req.apps.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let targets_clean = req
        .targets
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let ports_clean = req
        .ports
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let rule = Rule::from_raw(name, true, apps_clean, targets_clean, ports_clean, action);
    validate_rule_probe(&rule, apps_clean, targets_clean, ports_clean)?;

    let id = rule.id;
    rule_engine.add_rule(rule);
    Ok(id)
}

pub fn update_rule(
    req: UpdateRuleRequest,
    rule_engine: &RuleEngine,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
) -> Result<u64, ControlError> {
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(ControlError::bad_request(
            "ERR_EMPTY_RULE_NAME",
            "error.empty_rule_name",
        ));
    }

    let action = parse_and_validate_action(&req.action, req.node_id, proxy_nodes)?;

    let apps_clean = req.apps.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let targets_clean = req
        .targets
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let ports_clean = req
        .ports
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let probe = Rule::from_raw_with_id(
        req.id,
        &name,
        true,
        apps_clean,
        targets_clean,
        ports_clean,
        action.clone(),
    );
    validate_rule_probe(&probe, apps_clean, targets_clean, ports_clean)?;

    match rule_engine.update_rule(req.id, name, apps_clean, targets_clean, ports_clean, action) {
        Some(updated) => Ok(updated.id),
        None => Err(ControlError::not_found(
            "ERR_RULE_NOT_FOUND",
            "error.rule_not_found",
        )),
    }
}

pub fn patch_rule(
    req: PatchRuleRequest,
    rule_engine: &RuleEngine,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
) -> Result<u64, ControlError> {
    let Some(existing) = rule_engine
        .current_rules()
        .iter()
        .find(|r| r.id == req.id)
        .cloned()
    else {
        return Err(ControlError::not_found(
            "ERR_RULE_NOT_FOUND",
            "error.rule_not_found",
        ));
    };

    let name = req
        .name
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| existing.name.clone());
    if name.is_empty() {
        return Err(ControlError::bad_request(
            "ERR_EMPTY_RULE_NAME",
            "error.empty_rule_name",
        ));
    }

    let action = if let Some(act_str) = req.action.as_deref() {
        let effective_node_id = req.node_id.or_else(|| match existing.action {
            Action::Proxy(id) if act_str.trim().eq_ignore_ascii_case("Proxy") => Some(id),
            _ => None,
        });
        parse_and_validate_action(act_str, effective_node_id, proxy_nodes)?
    } else if let Some(nid) = req.node_id {
        if matches!(existing.action, Action::Proxy(_)) {
            parse_and_validate_action("Proxy", Some(nid), proxy_nodes)?
        } else {
            return Err(ControlError::bad_request(
                "ERR_INVALID_RULE_ACTION",
                "error.invalid_rule_action",
            ));
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
    validate_rule_probe(&probe, apps_clean, targets_clean, ports_clean)?;

    match rule_engine.update_rule_with_enabled(
        req.id,
        name,
        apps_clean,
        targets_clean,
        ports_clean,
        action,
        req.enabled,
    ) {
        Some(updated) => Ok(updated.id),
        None => Err(ControlError::not_found(
            "ERR_RULE_NOT_FOUND",
            "error.rule_not_found",
        )),
    }
}

pub fn toggle_rule(req: ToggleRuleRequest, rule_engine: &RuleEngine) -> Result<bool, ControlError> {
    rule_engine
        .toggle_rule(req.id, req.enabled)
        .ok_or_else(|| ControlError::not_found("ERR_RULE_NOT_FOUND", "error.rule_not_found"))
}

pub fn move_rule(req: MoveRuleRequest, rule_engine: &RuleEngine) -> Result<bool, ControlError> {
    if !matches!(
        req.direction.trim().to_ascii_lowercase().as_str(),
        "up" | "down" | "top" | "bottom"
    ) {
        return Err(ControlError::bad_request(
            "ERR_INVALID_MOVE_DIR",
            "error.invalid_move_direction",
        ));
    }
    rule_engine
        .move_rule(req.id, &req.direction)
        .ok_or_else(|| ControlError::not_found("ERR_RULE_NOT_FOUND", "error.rule_not_found"))
}

pub fn delete_rule(rule_id: u64, rule_engine: &RuleEngine) -> Result<(), ControlError> {
    if rule_engine.delete_rule(rule_id) {
        Ok(())
    } else {
        Err(ControlError::not_found(
            "ERR_RULE_NOT_FOUND",
            "error.rule_not_found",
        ))
    }
}
