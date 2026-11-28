use anyhow::{Context, Result, anyhow, bail};
use serde_json::json;

use crate::cli::args::{
    ArgSpec, GlobalCliOpts, parse_flags_with_spec, resolve_id_arg, split_action_spec,
};
use crate::cli::bridge::{
    RuleBackend, control_err_to_cli, load_offline_runtime_readonly, load_rule_backend,
    mutate_offline_runtime, offline_resolve_rule_id, resolve_rule_id_from_views,
};
use crate::cli::http_client::{api_request_or_offline, api_request_strict, ensure_api_ok};
use crate::control::rule::{
    add_rule, delete_rule, move_rule, patch_rule, toggle_rule, validate_add_rule_request_static,
    validate_move_direction, validate_patch_rule_fields_static,
};
use crate::control::{
    AddRuleRequest, ControlError, MoveRuleRequest, PatchRuleRequest, ToggleRuleRequest,
};
use crate::i18n::Locale;
use crate::router::RuleView;

fn rule_not_found_cli_err(locale: Locale) -> anyhow::Error {
    control_err_to_cli(
        ControlError::not_found("ERR_RULE_NOT_FOUND", "error.rule_not_found"),
        locale,
    )
}

pub(super) async fn cmd_rule(opts: &GlobalCliOpts) -> Result<()> {
    let sub = opts.rest.get(1).map(|s| s.as_str()).unwrap_or("list");
    let tail = if opts.rest.len() > 2 {
        &opts.rest[2..]
    } else {
        &[]
    };

    match sub {
        "list" | "ls" => {
            let (_, flags) = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx rule list",
                    value_flags: &["search"],
                    bool_flags: &[],
                    min_pos: 0,
                    max_pos: 0,
                },
            )?;
            let search_lower = flags
                .get("search")
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty());
            let list: Vec<RuleView> = if let Some((st, val)) =
                api_request_or_offline(opts, "GET", "/api/rules", None).await?
            {
                serde_json::from_value(ensure_api_ok(st, val)?)?
            } else {
                let rt = load_offline_runtime_readonly(&opts.config_path)?;
                rt.engine.list_rules_view_with_locale(opts.locale)
            };

            let indexed: Vec<(usize, RuleView)> = list
                .into_iter()
                .enumerate()
                .filter(|(_, r)| match search_lower.as_deref() {
                    Some(kw) => {
                        let hay = format!(
                            "{} {} {} {} {}",
                            r.name, r.apps, r.targets, r.ports, r.action
                        )
                        .to_lowercase();
                        hay.contains(kw)
                    }
                    None => true,
                })
                .collect();

            if opts.json_output {
                let filtered: Vec<&RuleView> = indexed.iter().map(|(_, r)| r).collect();
                println!("{}", serde_json::to_string_pretty(&filtered)?);
            } else if indexed.is_empty() {
                if search_lower.is_some() {
                    println!("No matching routing rules.");
                } else {
                    println!("No routing rules configured.");
                }
            } else {
                for (idx, r) in indexed {
                    let state_str = if r.enabled { "ON " } else { "OFF" };
                    let apps = if r.apps.is_empty() { "*" } else { &r.apps };
                    let targets = if r.targets.is_empty() {
                        "*"
                    } else {
                        &r.targets
                    };
                    let ports = if r.ports.is_empty() { "*" } else { &r.ports };
                    println!(
                        "#{:<3} (id={:<3}) [{}] {:<18} action={:<16} apps={} | targets={} | ports={}",
                        idx + 1,
                        r.id,
                        state_str,
                        r.name,
                        r.action,
                        apps,
                        targets,
                        ports
                    );
                }
            }
            Ok(())
        }
        "add" => {
            let (_, flags) = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx rule add",
                    value_flags: &[
                        "name", "action", "node", "node-id", "apps", "app", "targets", "target",
                        "ports", "port",
                    ],
                    bool_flags: &[],
                    min_pos: 0,
                    max_pos: 0,
                },
            )?;
            let name = flags
                .get("name")
                .cloned()
                .ok_or_else(|| anyhow!("Missing --name <NAME>"))?;
            let action_raw = flags
                .get("action")
                .cloned()
                .ok_or_else(|| anyhow!("Missing --action <Direct|Block|Proxy[:NODE_ID]>"))?;
            let explicit_node = match flags.get("node").or_else(|| flags.get("node-id")) {
                Some(s) => Some(s.parse::<u32>().context("Invalid --node ID")?),
                None => None,
            };
            let (action, node_id) = split_action_spec(&action_raw, explicit_node)?;
            let apps = flags.get("apps").or_else(|| flags.get("app")).cloned();
            let targets = flags
                .get("targets")
                .or_else(|| flags.get("target"))
                .cloned();
            let ports = flags.get("ports").or_else(|| flags.get("port")).cloned();

            let payload = json!({
                "name": name,
                "apps": apps,
                "targets": targets,
                "ports": ports,
                "action": action,
                "node_id": node_id,
            });

            let res_val = if let Some((st, val)) =
                api_request_or_offline(opts, "POST", "/api/rules", Some(&payload)).await?
            {
                ensure_api_ok(st, val)?
            } else {
                let req: AddRuleRequest = serde_json::from_value(payload)?;
                validate_add_rule_request_static(&req)
                    .map_err(|e| control_err_to_cli(e, opts.locale))?;
                let locale = opts.locale;
                let new_id = mutate_offline_runtime(&opts.config_path, |rt| {
                    let id = add_rule(req.clone(), &rt.engine, &rt.nodes)
                        .map_err(|e| control_err_to_cli(e, locale))?;
                    Ok((id, true))
                })?;
                json!({ "ok": true, "id": new_id })
            };

            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&res_val)?);
            } else {
                println!(
                    "Added routing rule #{} ({})",
                    res_val["id"].as_u64().unwrap_or(0),
                    name
                );
            }
            Ok(())
        }
        "update" | "edit" => {
            let (pos, flags) = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx rule update",
                    value_flags: &[
                        "id", "name", "action", "node", "node-id", "apps", "app", "targets",
                        "target", "ports", "port",
                    ],
                    bool_flags: &[
                        "enable",
                        "disable",
                        "clear-apps",
                        "clear-targets",
                        "clear-ports",
                    ],
                    min_pos: 0,
                    max_pos: 1,
                },
            )?;
            let id_str = resolve_id_arg(&pos, &flags, "Missing rule <ID> for `flowx rule update`")?;
            let raw_id: u64 = id_str.parse().context("Invalid rule ID")?;

            let has_enable = flags.contains_key("enable");
            let has_disable = flags.contains_key("disable");
            if has_enable && has_disable {
                bail!("Cannot specify both --enable and --disable");
            }
            let enabled = if has_enable {
                Some(true)
            } else if has_disable {
                Some(false)
            } else {
                None
            };

            let explicit_node = match flags.get("node").or_else(|| flags.get("node-id")) {
                Some(s) => Some(s.parse::<u32>().context("Invalid --node ID")?),
                None => None,
            };
            let (action, node_id) = match flags.get("action") {
                Some(act_raw) => {
                    let (a, nid) = split_action_spec(act_raw, explicit_node)?;
                    (Some(a), nid)
                }
                None => (None, explicit_node),
            };
            let name = flags.get("name").cloned();
            let apps = if flags.contains_key("clear-apps") {
                Some(String::new())
            } else {
                flags.get("apps").or_else(|| flags.get("app")).cloned()
            };
            let targets = if flags.contains_key("clear-targets") {
                Some(String::new())
            } else {
                flags
                    .get("targets")
                    .or_else(|| flags.get("target"))
                    .cloned()
            };
            let ports = if flags.contains_key("clear-ports") {
                Some(String::new())
            } else {
                flags.get("ports").or_else(|| flags.get("port")).cloned()
            };

            let (resolved_id, res_val) = match load_rule_backend(opts).await? {
                RuleBackend::Online { rules } => {
                    let resolved_id = resolve_rule_id_from_views(&rules, raw_id)
                        .ok_or_else(|| rule_not_found_cli_err(opts.locale))?;
                    let payload = json!({
                        "id": resolved_id,
                        "name": name,
                        "apps": apps,
                        "targets": targets,
                        "ports": ports,
                        "action": action,
                        "node_id": node_id,
                        "enabled": enabled,
                    });
                    let (st, val) = api_request_strict(
                        &opts.api_addr,
                        opts.locale,
                        "PATCH",
                        "/api/rules",
                        Some(&payload),
                    )
                    .await?;
                    (resolved_id, ensure_api_ok(st, val)?)
                }
                RuleBackend::Offline => {
                    let locale = opts.locale;
                    validate_patch_rule_fields_static(
                        name.as_deref(),
                        action.as_deref(),
                        apps.as_deref(),
                        targets.as_deref(),
                        ports.as_deref(),
                    )
                    .map_err(|e| control_err_to_cli(e, locale))?;
                    mutate_offline_runtime(&opts.config_path, |rt| {
                        let resolved_id = offline_resolve_rule_id(&rt.engine, raw_id, locale)
                            .ok_or_else(|| rule_not_found_cli_err(locale))?;
                        let payload = json!({
                            "id": resolved_id,
                            "name": &name,
                            "apps": &apps,
                            "targets": &targets,
                            "ports": &ports,
                            "action": &action,
                            "node_id": node_id,
                            "enabled": enabled,
                        });
                        let req: PatchRuleRequest = serde_json::from_value(payload)?;
                        let updated_id = patch_rule(req, &rt.engine, &rt.nodes)
                            .map_err(|e| control_err_to_cli(e, locale))?;
                        Ok(((resolved_id, json!({ "ok": true, "id": updated_id })), true))
                    })?
                }
            };

            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&res_val)?);
            } else if let Some(ref n) = name {
                println!("Updated routing rule #{} ({})", resolved_id, n);
            } else {
                println!("Updated routing rule #{}", resolved_id);
            }
            Ok(())
        }
        "toggle" => {
            let (pos, flags) = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx rule toggle",
                    value_flags: &["id"],
                    bool_flags: &["enable", "disable"],
                    min_pos: 0,
                    max_pos: 1,
                },
            )?;
            let id_str = resolve_id_arg(&pos, &flags, "Missing rule <ID> for `flowx rule toggle`")?;
            let raw_id: u64 = id_str.parse().context("Invalid rule ID")?;
            let has_enable = flags.contains_key("enable");
            let has_disable = flags.contains_key("disable");
            if has_enable && has_disable {
                bail!("Cannot specify both --enable and --disable");
            }
            let enabled = if has_enable {
                Some(true)
            } else if has_disable {
                Some(false)
            } else {
                None
            };

            let (resolved_id, res_val) = match load_rule_backend(opts).await? {
                RuleBackend::Online { rules } => {
                    let resolved_id = resolve_rule_id_from_views(&rules, raw_id)
                        .ok_or_else(|| rule_not_found_cli_err(opts.locale))?;
                    let (st, val) = api_request_strict(
                        &opts.api_addr,
                        opts.locale,
                        "POST",
                        "/api/rules/toggle",
                        Some(&json!({ "id": resolved_id, "enabled": enabled })),
                    )
                    .await?;
                    (resolved_id, ensure_api_ok(st, val)?)
                }
                RuleBackend::Offline => {
                    let locale = opts.locale;
                    mutate_offline_runtime(&opts.config_path, |rt| {
                        let resolved_id = offline_resolve_rule_id(&rt.engine, raw_id, locale)
                            .ok_or_else(|| rule_not_found_cli_err(locale))?;
                        let next_state = toggle_rule(
                            ToggleRuleRequest {
                                id: resolved_id,
                                enabled,
                            },
                            &rt.engine,
                        )
                        .map_err(|e| control_err_to_cli(e, locale))?;
                        Ok((
                            (resolved_id, json!({ "ok": true, "enabled": next_state })),
                            true,
                        ))
                    })?
                }
            };

            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&res_val)?);
            } else {
                println!(
                    "Rule #{} enabled={}",
                    resolved_id,
                    res_val["enabled"].as_bool().unwrap_or(false)
                );
            }
            Ok(())
        }
        "move" | "mv" => {
            let (pos, flags) = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx rule move",
                    value_flags: &["id", "dir", "direction"],
                    bool_flags: &[],
                    min_pos: 0,
                    max_pos: 2,
                },
            )?;
            let flag_dir = flags.get("dir").or_else(|| flags.get("direction"));
            let (id_str, direction) = if let Some(flag_id) = flags.get("id") {
                if pos.len() > 1 {
                    bail!("Cannot specify both positional <ID> and --id");
                }
                let dir = match (pos.first(), flag_dir) {
                    (Some(_), Some(_)) => {
                        bail!("Cannot specify both positional <DIRECTION> and --dir/--direction")
                    }
                    (Some(p), None) => p.clone(),
                    (None, Some(f)) => f.clone(),
                    (None, None) => bail!("Missing direction <up|down|top|bottom>"),
                };
                (flag_id.clone(), dir)
            } else {
                let id = pos
                    .first()
                    .cloned()
                    .ok_or_else(|| anyhow!("Missing rule <ID> for `flowx rule move`"))?;
                let dir = match (pos.get(1), flag_dir) {
                    (Some(_), Some(_)) => {
                        bail!("Cannot specify both positional <DIRECTION> and --dir/--direction")
                    }
                    (Some(p), None) => p.clone(),
                    (None, Some(f)) => f.clone(),
                    (None, None) => bail!("Missing direction <up|down|top|bottom>"),
                };
                (id, dir)
            };
            let raw_id: u64 = id_str.parse().context("Invalid rule ID")?;

            let (resolved_id, res_val) = match load_rule_backend(opts).await? {
                RuleBackend::Online { rules } => {
                    let resolved_id = resolve_rule_id_from_views(&rules, raw_id)
                        .ok_or_else(|| rule_not_found_cli_err(opts.locale))?;
                    let (st, val) = api_request_strict(
                        &opts.api_addr,
                        opts.locale,
                        "POST",
                        "/api/rules/move",
                        Some(&json!({ "id": resolved_id, "direction": direction })),
                    )
                    .await?;
                    (resolved_id, ensure_api_ok(st, val)?)
                }
                RuleBackend::Offline => {
                    let locale = opts.locale;
                    validate_move_direction(&direction)
                        .map_err(|e| control_err_to_cli(e, locale))?;
                    mutate_offline_runtime(&opts.config_path, |rt| {
                        let resolved_id = offline_resolve_rule_id(&rt.engine, raw_id, locale)
                            .ok_or_else(|| rule_not_found_cli_err(locale))?;
                        let moved = move_rule(
                            MoveRuleRequest {
                                id: resolved_id,
                                direction: direction.clone(),
                            },
                            &rt.engine,
                        )
                        .map_err(|e| control_err_to_cli(e, locale))?;
                        Ok(((resolved_id, json!({ "ok": true, "moved": moved })), moved))
                    })?
                }
            };

            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&res_val)?);
            } else {
                println!(
                    "Rule #{} move {} (moved={})",
                    resolved_id,
                    direction,
                    res_val["moved"].as_bool().unwrap_or(false)
                );
            }
            Ok(())
        }
        "remove" | "delete" | "rm" => {
            let (pos, flags) = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx rule remove",
                    value_flags: &["id"],
                    bool_flags: &[],
                    min_pos: 0,
                    max_pos: 1,
                },
            )?;
            let id_str = resolve_id_arg(&pos, &flags, "Missing rule <ID> for `flowx rule remove`")?;
            let raw_id: u64 = id_str.parse().context("Invalid rule ID")?;

            let (resolved_id, res_val) = match load_rule_backend(opts).await? {
                RuleBackend::Online { rules } => {
                    let resolved_id = resolve_rule_id_from_views(&rules, raw_id)
                        .ok_or_else(|| rule_not_found_cli_err(opts.locale))?;
                    let (st, val) = api_request_strict(
                        &opts.api_addr,
                        opts.locale,
                        "DELETE",
                        &format!("/api/rules?id={}", resolved_id),
                        None,
                    )
                    .await?;
                    (resolved_id, ensure_api_ok(st, val)?)
                }
                RuleBackend::Offline => {
                    let locale = opts.locale;
                    mutate_offline_runtime(&opts.config_path, |rt| {
                        let resolved_id = offline_resolve_rule_id(&rt.engine, raw_id, locale)
                            .ok_or_else(|| rule_not_found_cli_err(locale))?;
                        delete_rule(resolved_id, &rt.engine)
                            .map_err(|e| control_err_to_cli(e, locale))?;
                        Ok(((resolved_id, json!({ "ok": true })), true))
                    })?
                }
            };

            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&res_val)?);
            } else {
                println!("Removed routing rule #{}", resolved_id);
            }
            Ok(())
        }
        other => bail!("Unknown `flowx rule` subcommand '{}'", other),
    }
}
