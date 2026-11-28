use anyhow::{Context, Result, bail};
use serde_json::json;

use crate::cli::args::{ArgSpec, GlobalCliOpts, parse_flags_with_spec, split_action_spec};
use crate::cli::bridge::{
    control_err_to_cli, load_offline_runtime_readonly, mutate_offline_runtime,
};
use crate::cli::http_client::{api_request_or_offline, api_request_strict, ensure_api_ok};
use crate::control::routing::{set_default_action, simulate_route};
use crate::control::{SetDefaultActionRequest, SimulateRouteRequest};
use crate::router::format_action_desc;

pub(super) async fn cmd_status(opts: &GlobalCliOpts) -> Result<()> {
    let tail = if opts.rest.len() > 1 {
        &opts.rest[1..]
    } else {
        &[]
    };
    let _ = parse_flags_with_spec(
        tail,
        ArgSpec {
            cmd_label: "flowx status",
            value_flags: &[],
            bool_flags: &[],
            min_pos: 0,
            max_pos: 0,
        },
    )?;

    if let Some((status, raw_sys)) =
        api_request_or_offline(opts, "GET", "/api/system", None).await?
    {
        let sys_val = ensure_api_ok(status, raw_sys)?;
        let (stats_status, raw_stats) =
            api_request_strict(&opts.api_addr, opts.locale, "GET", "/api/stats", None).await?;
        let stats_val = ensure_api_ok(stats_status, raw_stats)?;

        let out = json!({
            "mode": "online",
            "api_addr": opts.api_addr,
            "system": sys_val,
            "stats": stats_val,
        });
        if opts.json_output {
            println!("{}", serde_json::to_string_pretty(&out)?);
        } else {
            println!("Mode:           ONLINE (http://{})", opts.api_addr);
            println!(
                "Inbound:        {}",
                sys_val["inbound_addr"].as_str().unwrap_or("-")
            );
            println!(
                "DNS:            {} -> {}",
                sys_val["dns_addr"].as_str().unwrap_or("-"),
                sys_val["upstream_dns"].as_str().unwrap_or("-")
            );
            println!(
                "Config File:    {}",
                sys_val["config_path"].as_str().unwrap_or("-")
            );
            println!(
                "Proxy Nodes:    {}",
                sys_val["nodes_count"].as_u64().unwrap_or(0)
            );
            println!(
                "Routing Rules:  {} enabled / {} total",
                sys_val["enabled_rules_count"].as_u64().unwrap_or(0),
                sys_val["rules_count"].as_u64().unwrap_or(0)
            );
            println!(
                "Default Action: {}",
                sys_val["default_action"].as_str().unwrap_or("-")
            );
            println!(
                "Active Conns:   {}",
                stats_val["active_connections_count"].as_u64().unwrap_or(0)
            );
            if let Some(tp) = sys_val.get("transparent") {
                println!(
                    "Transparent:    enabled={} running={} elevated={} hijack_dns={} block_quic={}",
                    tp["enabled"].as_bool().unwrap_or(false),
                    tp["running"].as_bool().unwrap_or(false),
                    tp["elevated"].as_bool().unwrap_or(false),
                    tp["hijack_dns"].as_bool().unwrap_or(true),
                    tp["block_quic_for_proxied"].as_bool().unwrap_or(true),
                );
            }
        }
        return Ok(());
    }

    let rt = load_offline_runtime_readonly(&opts.config_path)?;
    let nodes_count = rt.nodes.read().unwrap_or_else(|e| e.into_inner()).len();
    let rules = rt.engine.current_rules();
    let enabled_count = rules.iter().filter(|r| r.enabled).count();
    let def_act = rt.engine.default_action();
    let def_desc = format_action_desc(&def_act, opts.locale);

    let out = json!({
        "mode": "offline",
        "config_path": rt.store.path().display().to_string(),
        "nodes_count": nodes_count,
        "rules_count": rules.len(),
        "enabled_rules_count": enabled_count,
        "default_action": def_desc,
        "default_action_type": def_act.type_str(),
        "default_node_id": def_act.target_id(),
        "transparent": rt.transparent,
    });
    if opts.json_output {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Mode:           OFFLINE (Direct XML Config)");
        println!("Config File:    {}", rt.store.path().display());
        println!("Proxy Nodes:    {}", nodes_count);
        println!(
            "Routing Rules:  {} enabled / {} total",
            enabled_count,
            rules.len()
        );
        println!("Default Action: {}", def_desc);
        println!(
            "Transparent:    enabled={} hijack_dns={} block_quic={}",
            rt.transparent.enabled,
            rt.transparent.hijack_dns,
            rt.transparent.block_quic_for_proxied
        );
    }
    Ok(())
}

pub(super) async fn cmd_default(opts: &GlobalCliOpts) -> Result<()> {
    let tail = if opts.rest.len() > 1 {
        &opts.rest[1..]
    } else {
        &[]
    };
    let (pos, flags) = parse_flags_with_spec(
        tail,
        ArgSpec {
            cmd_label: "flowx default",
            value_flags: &["action", "node", "node-id"],
            bool_flags: &[],
            min_pos: 0,
            max_pos: 1,
        },
    )?;

    let action_arg = match (pos.first(), flags.get("action")) {
        (Some(_), Some(_)) => bail!("Cannot specify both positional <ACTION> and --action"),
        (Some(p), None) => Some(p.clone()),
        (None, Some(f)) => Some(f.clone()),
        (None, None) => None,
    };
    if let Some(raw_act) = action_arg {
        let explicit_node = match flags.get("node").or_else(|| flags.get("node-id")) {
            Some(s) => Some(s.parse::<u32>().context("Invalid --node ID")?),
            None => None,
        };
        let (action, node_id) = split_action_spec(&raw_act, explicit_node)?;
        let payload = json!({
            "action": action,
            "node_id": node_id,
        });

        let res_val = if let Some((st, val)) =
            api_request_or_offline(opts, "POST", "/api/rules/default", Some(&payload)).await?
        {
            ensure_api_ok(st, val)?
        } else {
            let req: SetDefaultActionRequest = serde_json::from_value(payload)?;
            let locale = opts.locale;
            let resp = mutate_offline_runtime(&opts.config_path, |rt| {
                let r = set_default_action(req.clone(), &rt.engine, &rt.nodes, locale)
                    .map_err(|e| control_err_to_cli(e, locale))?;
                Ok((r, true))
            })?;
            serde_json::to_value(resp)?
        };

        if opts.json_output {
            println!("{}", serde_json::to_string_pretty(&res_val)?);
        } else {
            println!(
                "Default fallback action updated to: {}",
                res_val["default_action"].as_str().unwrap_or("-")
            );
        }
        return Ok(());
    }

    if flags.contains_key("node") || flags.contains_key("node-id") {
        bail!("--node requires an action argument (e.g. `flowx default Proxy --node 101`)");
    }

    // 未提供新动作时查询当前默认兜底动作
    if let Some((st, raw_sys)) = api_request_or_offline(opts, "GET", "/api/system", None).await? {
        let sys_val = ensure_api_ok(st, raw_sys)?;
        let out = json!({
            "default_action": sys_val["default_action"],
            "default_action_type": sys_val["default_action_type"],
            "default_node_id": sys_val["default_node_id"],
        });
        if opts.json_output {
            println!("{}", serde_json::to_string_pretty(&out)?);
        } else {
            println!(
                "Default Action: {}",
                sys_val["default_action"].as_str().unwrap_or("-")
            );
        }
        return Ok(());
    }

    let rt = load_offline_runtime_readonly(&opts.config_path)?;
    let act = rt.engine.default_action();
    let desc = format_action_desc(&act, opts.locale);
    let out = json!({
        "default_action": desc,
        "default_action_type": act.type_str(),
        "default_node_id": act.target_id(),
    });
    if opts.json_output {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Default Action: {}", desc);
    }
    Ok(())
}

pub(super) async fn cmd_sim(opts: &GlobalCliOpts) -> Result<()> {
    let tail = if opts.rest.len() > 1 {
        &opts.rest[1..]
    } else {
        &[]
    };
    let (pos, flags) = parse_flags_with_spec(
        tail,
        ArgSpec {
            cmd_label: "flowx sim",
            value_flags: &["target", "host", "app", "process", "proc", "port"],
            bool_flags: &[],
            min_pos: 0,
            max_pos: 1,
        },
    )?;

    let flag_target = flags.get("target").or_else(|| flags.get("host"));
    let target = match (pos.first(), flag_target) {
        (Some(_), Some(_)) => bail!("Cannot specify both positional <TARGET> and --target"),
        (Some(p), None) => p.clone(),
        (None, Some(f)) => f.clone(),
        (None, None) => bail!("Missing --target <HOST[:PORT]> for `flowx sim`"),
    };
    let process = flags
        .get("app")
        .or_else(|| flags.get("process"))
        .or_else(|| flags.get("proc"))
        .cloned();
    let port = match flags.get("port") {
        Some(p) => Some(p.parse::<u16>().context("Invalid --port value")?),
        None => None,
    };

    let payload = json!({
        "process": process,
        "target": target,
        "port": port,
    });

    let res_val = if let Some((st, val)) =
        api_request_or_offline(opts, "POST", "/api/rules/simulate", Some(&payload)).await?
    {
        ensure_api_ok(st, val)?
    } else {
        let rt = load_offline_runtime_readonly(&opts.config_path)?;
        let req: SimulateRouteRequest = serde_json::from_value(payload)?;
        let resp = simulate_route(req, &rt.engine, opts.locale)
            .map_err(|e| control_err_to_cli(e, opts.locale))?;
        serde_json::to_value(resp)?
    };

    if opts.json_output {
        println!("{}", serde_json::to_string_pretty(&res_val)?);
    } else {
        println!(
            "Matched Rule: {} (default={})",
            res_val["matched_rule_name"].as_str().unwrap_or("-"),
            res_val["is_default"].as_bool().unwrap_or(false)
        );
        println!(
            "Action:       {}",
            res_val["action"].as_str().unwrap_or("-")
        );
        if let Some(trace) = res_val["trace"].as_array() {
            println!("Trace ({} steps):", trace.len());
            for step in trace {
                println!(
                    "  #{:<2} {:<18} -> {}",
                    step["index"].as_u64().unwrap_or(0) + 1,
                    step["rule_name"].as_str().unwrap_or("-"),
                    step["reason"].as_str().unwrap_or("-")
                );
            }
        }
    }
    Ok(())
}
