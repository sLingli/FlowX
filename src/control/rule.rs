use std::collections::HashMap;
use std::sync::RwLock;

use serde::Deserialize;

use crate::control::ControlError;
use crate::interceptor::dispatcher::ProxyNodeEntry;
use crate::router::{Action, Rule, RuleEngine};

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct ToggleRuleRequest {
    pub id: u64,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
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

fn validate_move_direction(direction: &str) -> Result<(), ControlError> {
    if !matches!(
        direction.trim().to_ascii_lowercase().as_str(),
        "up" | "down" | "top" | "bottom"
    ) {
        return Err(ControlError::bad_request(
            "ERR_INVALID_MOVE_DIR",
            "error.invalid_move_direction",
        ));
    }
    Ok(())
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
    validate_move_direction(&req.direction)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlErrorKind;
    use crate::outbound::chain::ProxyNode;
    use crate::outbound::socks5::Socks5Client;

    fn sample_nodes() -> RwLock<HashMap<u32, ProxyNodeEntry>> {
        let mut map = HashMap::new();
        for id in [101u32, 102u32] {
            map.insert(
                id,
                ProxyNodeEntry {
                    id,
                    name: format!("Node{id}"),
                    protocol: "SOCKS5".into(),
                    server_addr: format!("10.0.0.{id}:1080"),
                    username: None,
                    client: ProxyNode::Socks5(Socks5Client::new(format!("10.0.0.{id}:1080"))),
                },
            );
        }
        RwLock::new(map)
    }

    fn assert_ctrl_err(err: ControlError, kind: ControlErrorKind, code: &str, message_key: &str) {
        assert_eq!(err.kind, kind, "unexpected kind for {code}");
        assert_eq!(err.code, code);
        assert_eq!(err.message_key, message_key);
    }

    #[test]
    fn test_parse_and_validate_action_and_add_rule_validation() {
        let nodes = sample_nodes();
        let engine = RuleEngine::new(Vec::new(), Action::Direct);

        assert_eq!(
            parse_and_validate_action("direct", None, &nodes).unwrap(),
            Action::Direct
        );
        assert_eq!(
            parse_and_validate_action("BLOCK", None, &nodes).unwrap(),
            Action::Block
        );
        assert_eq!(
            parse_and_validate_action("Proxy", Some(101), &nodes).unwrap(),
            Action::Proxy(101)
        );
        assert_ctrl_err(
            parse_and_validate_action("Proxy", None, &nodes).unwrap_err(),
            ControlErrorKind::BadRequest,
            "ERR_MISSING_NODE_FOR_PROXY",
            "error.missing_node_id_for_proxy",
        );
        assert_ctrl_err(
            parse_and_validate_action("Proxy", Some(999), &nodes).unwrap_err(),
            ControlErrorKind::BadRequest,
            "ERR_NODE_NOT_FOUND",
            "error.node_not_found",
        );
        assert_ctrl_err(
            parse_and_validate_action("Bogus", None, &nodes).unwrap_err(),
            ControlErrorKind::BadRequest,
            "ERR_INVALID_RULE_ACTION",
            "error.invalid_rule_action",
        );

        // Empty rule name
        assert_ctrl_err(
            add_rule(
                AddRuleRequest {
                    name: "   ".into(),
                    apps: None,
                    targets: None,
                    ports: None,
                    action: "Direct".into(),
                    node_id: None,
                },
                &engine,
                &nodes,
            )
            .unwrap_err(),
            ControlErrorKind::BadRequest,
            "ERR_EMPTY_RULE_NAME",
            "error.empty_rule_name",
        );

        // Invalid app / target / port patterns fail closed
        assert_ctrl_err(
            add_rule(
                AddRuleRequest {
                    name: "BadApps".into(),
                    apps: Some(";;;".into()),
                    targets: None,
                    ports: None,
                    action: "Direct".into(),
                    node_id: None,
                },
                &engine,
                &nodes,
            )
            .unwrap_err(),
            ControlErrorKind::BadRequest,
            "ERR_INVALID_APP_PATTERN",
            "error.invalid_app_pattern",
        );
        assert_ctrl_err(
            add_rule(
                AddRuleRequest {
                    name: "BadTargets".into(),
                    apps: None,
                    targets: Some(";;;".into()),
                    ports: None,
                    action: "Direct".into(),
                    node_id: None,
                },
                &engine,
                &nodes,
            )
            .unwrap_err(),
            ControlErrorKind::BadRequest,
            "ERR_INVALID_TARGET_PATTERN",
            "error.invalid_target_pattern",
        );
        assert_ctrl_err(
            add_rule(
                AddRuleRequest {
                    name: "BadPorts".into(),
                    apps: None,
                    targets: None,
                    ports: Some("not-a-port".into()),
                    action: "Direct".into(),
                    node_id: None,
                },
                &engine,
                &nodes,
            )
            .unwrap_err(),
            ControlErrorKind::BadRequest,
            "ERR_INVALID_PORT_FORMAT",
            "error.invalid_port_format",
        );

        // Valid add
        let id = add_rule(
            AddRuleRequest {
                name: "DevGit".into(),
                apps: Some("git.exe".into()),
                targets: Some("*.github.com".into()),
                ports: Some("443".into()),
                action: "Proxy".into(),
                node_id: Some(101),
            },
            &engine,
            &nodes,
        )
        .unwrap();
        let rules = engine.current_rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, id);
        assert_eq!(rules[0].action, Action::Proxy(101));
    }

    #[test]
    fn test_update_patch_toggle_move_and_delete_rule() {
        let nodes = sample_nodes();
        let engine = RuleEngine::new(Vec::new(), Action::Direct);

        let id1 = add_rule(
            AddRuleRequest {
                name: "First".into(),
                apps: Some("curl.exe".into()),
                targets: Some("example.com".into()),
                ports: Some("80;443".into()),
                action: "Proxy".into(),
                node_id: Some(101),
            },
            &engine,
            &nodes,
        )
        .unwrap();
        let id2 = add_rule(
            AddRuleRequest {
                name: "Second".into(),
                apps: None,
                targets: Some("10.0.0.0/8".into()),
                ports: None,
                action: "Direct".into(),
                node_id: None,
            },
            &engine,
            &nodes,
        )
        .unwrap();

        // update_rule missing id -> 404
        assert_ctrl_err(
            update_rule(
                UpdateRuleRequest {
                    id: 999999,
                    name: "Ghost".into(),
                    apps: None,
                    targets: None,
                    ports: None,
                    action: "Direct".into(),
                    node_id: None,
                },
                &engine,
                &nodes,
            )
            .unwrap_err(),
            ControlErrorKind::NotFound,
            "ERR_RULE_NOT_FOUND",
            "error.rule_not_found",
        );

        // update_rule replaces fields on existing rule and updates RuleEngine state
        assert_eq!(
            update_rule(
                UpdateRuleRequest {
                    id: id1,
                    name: "FirstUpdated".into(),
                    apps: Some("git.exe".into()),
                    targets: Some("github.com".into()),
                    ports: Some("443".into()),
                    action: "Proxy".into(),
                    node_id: Some(101),
                },
                &engine,
                &nodes,
            )
            .unwrap(),
            id1
        );
        {
            let updated_r1 = &engine.current_rules()[0];
            assert_eq!(updated_r1.id, id1);
            assert_eq!(updated_r1.name, "FirstUpdated");
            assert_eq!(updated_r1.apps_raw, "git.exe");
            assert_eq!(updated_r1.targets_raw, "github.com");
            assert_eq!(updated_r1.ports_raw, "443");
            assert_eq!(updated_r1.action, Action::Proxy(101));
            assert!(updated_r1.enabled);
        }

        // patch_rule: node_id alone works on existing Proxy rule, clears apps via Some(""), keeps targets
        patch_rule(
            PatchRuleRequest {
                id: id1,
                name: None,
                apps: Some("".into()),
                targets: None,
                ports: None,
                action: None,
                node_id: Some(102),
                enabled: Some(false),
            },
            &engine,
            &nodes,
        )
        .unwrap();
        let r1 = engine.current_rules()[0].clone();
        assert_eq!(r1.action, Action::Proxy(102));
        assert!(r1.apps_raw.is_empty());
        assert_eq!(r1.targets_raw, "github.com");
        assert!(!r1.enabled);

        // patch_rule: node_id alone rejected on Direct rule; empty name rejected
        assert_ctrl_err(
            patch_rule(
                PatchRuleRequest {
                    id: id2,
                    name: None,
                    apps: None,
                    targets: None,
                    ports: None,
                    action: None,
                    node_id: Some(101),
                    enabled: None,
                },
                &engine,
                &nodes,
            )
            .unwrap_err(),
            ControlErrorKind::BadRequest,
            "ERR_INVALID_RULE_ACTION",
            "error.invalid_rule_action",
        );
        assert_ctrl_err(
            patch_rule(
                PatchRuleRequest {
                    id: id2,
                    name: Some("  ".into()),
                    apps: None,
                    targets: None,
                    ports: None,
                    action: None,
                    node_id: None,
                    enabled: None,
                },
                &engine,
                &nodes,
            )
            .unwrap_err(),
            ControlErrorKind::BadRequest,
            "ERR_EMPTY_RULE_NAME",
            "error.empty_rule_name",
        );

        // toggle_rule flip and explicit set + 404
        assert!(
            toggle_rule(
                ToggleRuleRequest {
                    id: id1,
                    enabled: None
                },
                &engine
            )
            .unwrap()
        );
        assert!(
            !toggle_rule(
                ToggleRuleRequest {
                    id: id1,
                    enabled: Some(false)
                },
                &engine
            )
            .unwrap()
        );
        assert_ctrl_err(
            toggle_rule(
                ToggleRuleRequest {
                    id: 999999,
                    enabled: None,
                },
                &engine,
            )
            .unwrap_err(),
            ControlErrorKind::NotFound,
            "ERR_RULE_NOT_FOUND",
            "error.rule_not_found",
        );

        // move_rule invalid direction -> 400; valid move -> reorders; missing -> 404
        assert_ctrl_err(
            move_rule(
                MoveRuleRequest {
                    id: id2,
                    direction: "sideways".into(),
                },
                &engine,
            )
            .unwrap_err(),
            ControlErrorKind::BadRequest,
            "ERR_INVALID_MOVE_DIR",
            "error.invalid_move_direction",
        );
        assert!(
            move_rule(
                MoveRuleRequest {
                    id: id2,
                    direction: "up".into()
                },
                &engine
            )
            .unwrap()
        );
        assert_eq!(engine.current_rules()[0].id, id2);
        assert_ctrl_err(
            move_rule(
                MoveRuleRequest {
                    id: 999999,
                    direction: "top".into(),
                },
                &engine,
            )
            .unwrap_err(),
            ControlErrorKind::NotFound,
            "ERR_RULE_NOT_FOUND",
            "error.rule_not_found",
        );

        // delete_rule existing + missing
        delete_rule(id1, &engine).unwrap();
        assert_eq!(engine.current_rules().len(), 1);
        assert_ctrl_err(
            delete_rule(id1, &engine).unwrap_err(),
            ControlErrorKind::NotFound,
            "ERR_RULE_NOT_FOUND",
            "error.rule_not_found",
        );
    }
}
