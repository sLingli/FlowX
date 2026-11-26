use std::io::Write;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::cli::args::{ArgSpec, GlobalCliOpts, parse_flags_with_spec, resolve_id_arg};
use crate::cli::bridge::{
    DEFAULT_SELF_PORTS, control_err_to_cli, load_offline_runtime, load_offline_runtime_readonly,
};
use crate::cli::http_client::{
    ApiTransportError, SilentExitError, api_request_or_offline, api_request_raw, ensure_api_ok,
};
use crate::control::node::{add_node, delete_node, list_nodes, patch_node, ping_address};
use crate::control::{AddNodeRequest, ControlError, PatchNodeRequest, PingResponse, ProxyNodeView};

pub(super) async fn cmd_node(opts: &GlobalCliOpts) -> Result<()> {
    let sub = opts.rest.get(1).map(|s| s.as_str()).unwrap_or("list");
    let tail = if opts.rest.len() > 2 {
        &opts.rest[2..]
    } else {
        &[]
    };

    match sub {
        "list" | "ls" => {
            let _ = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx node list",
                    value_flags: &[],
                    bool_flags: &[],
                    min_pos: 0,
                    max_pos: 0,
                },
            )?;
            let list: Vec<ProxyNodeView> = if let Some((st, val)) =
                api_request_or_offline(opts, "GET", "/api/nodes", None).await?
            {
                let v = ensure_api_ok(st, val)?;
                serde_json::from_value(v)?
            } else {
                let rt = load_offline_runtime_readonly(&opts.config_path)?;
                list_nodes(&rt.nodes)
            };

            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else if list.is_empty() {
                println!("No proxy nodes configured.");
            } else {
                for n in list {
                    let auth = if n.auth_configured {
                        "auth=yes"
                    } else {
                        "auth=no"
                    };
                    println!(
                        "#{:<4} {:<18} {:<8} {:<22} ({})",
                        n.id, n.name, n.protocol, n.server_addr, auth
                    );
                }
            }
            Ok(())
        }
        "add" => {
            let (_, flags) = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx node add",
                    value_flags: &[
                        "name", "addr", "server", "protocol", "proto", "user", "username", "pass",
                        "password",
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
            let server_addr = flags
                .get("addr")
                .or_else(|| flags.get("server"))
                .cloned()
                .ok_or_else(|| anyhow!("Missing --addr <HOST:PORT>"))?;
            let protocol = flags
                .get("protocol")
                .or_else(|| flags.get("proto"))
                .cloned()
                .unwrap_or_else(|| "SOCKS5".to_string());
            let username = flags.get("user").or_else(|| flags.get("username")).cloned();
            let password = flags.get("pass").or_else(|| flags.get("password")).cloned();

            let payload = json!({
                "name": name,
                "protocol": protocol,
                "server_addr": server_addr,
                "username": username,
                "password": password,
            });

            let res_val = if let Some((st, val)) =
                api_request_or_offline(opts, "POST", "/api/nodes", Some(&payload)).await?
            {
                ensure_api_ok(st, val)?
            } else {
                let rt = load_offline_runtime(&opts.config_path)?;
                let req: AddNodeRequest = serde_json::from_value(payload)?;
                let new_id = add_node(req, &rt.nodes, &DEFAULT_SELF_PORTS)
                    .map_err(|e| control_err_to_cli(e, opts.locale))?;
                rt.save()?;
                json!({ "ok": true, "id": new_id })
            };

            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&res_val)?);
            } else {
                println!(
                    "Added proxy node #{} ({})",
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
                    cmd_label: "flowx node update",
                    value_flags: &[
                        "id", "name", "addr", "server", "protocol", "proto", "user", "username",
                        "pass", "password",
                    ],
                    bool_flags: &["clear-user", "clear-password"],
                    min_pos: 0,
                    max_pos: 1,
                },
            )?;
            let id_str = resolve_id_arg(&pos, &flags, "Missing node <ID> for `flowx node update`")?;
            let id: u32 = id_str.parse().context("Invalid node ID")?;

            let clear_password_flag = flags.contains_key("clear-password");
            let pass_flag = flags.get("pass").or_else(|| flags.get("password")).cloned();
            if clear_password_flag && pass_flag.is_some() {
                bail!("Cannot specify both --pass and --clear-password");
            }

            let name = flags.get("name").cloned();
            let server_addr = flags.get("addr").or_else(|| flags.get("server")).cloned();
            let protocol = flags
                .get("protocol")
                .or_else(|| flags.get("proto"))
                .cloned();
            let (username, clear_username) = if flags.contains_key("clear-user") {
                (None, Some(true))
            } else {
                match flags.get("user").or_else(|| flags.get("username")) {
                    Some(u) if u.trim().is_empty() => (None, Some(true)),
                    Some(u) => (Some(u.clone()), None),
                    None => (None, None),
                }
            };
            let clear_password = clear_password_flag.then_some(true);
            let keep_password = if clear_password_flag {
                Some(false)
            } else {
                None
            };

            let payload = json!({
                "id": id,
                "name": name,
                "protocol": protocol,
                "server_addr": server_addr,
                "username": username,
                "password": pass_flag,
                "keep_password": keep_password,
                "clear_password": clear_password,
                "clear_username": clear_username,
            });

            let res_val = if let Some((st, val)) =
                api_request_or_offline(opts, "PATCH", "/api/nodes", Some(&payload)).await?
            {
                ensure_api_ok(st, val)?
            } else {
                let rt = load_offline_runtime(&opts.config_path)?;
                let req: PatchNodeRequest = serde_json::from_value(payload)?;
                let updated_id = patch_node(req, &rt.nodes, &DEFAULT_SELF_PORTS)
                    .map_err(|e| control_err_to_cli(e, opts.locale))?;
                rt.save()?;
                json!({ "ok": true, "id": updated_id })
            };

            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&res_val)?);
            } else if let Some(ref n) = name {
                println!("Updated proxy node #{} ({})", id, n);
            } else {
                println!("Updated proxy node #{}", id);
            }
            Ok(())
        }
        "remove" | "delete" | "rm" => {
            let (pos, flags) = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx node remove",
                    value_flags: &["id"],
                    bool_flags: &[],
                    min_pos: 0,
                    max_pos: 1,
                },
            )?;
            let id_str = resolve_id_arg(&pos, &flags, "Missing node <ID> for `flowx node remove`")?;
            let id: u32 = id_str.parse().context("Invalid node ID")?;

            let res_val = if let Some((st, val)) =
                api_request_or_offline(opts, "DELETE", &format!("/api/nodes?id={}", id), None)
                    .await?
            {
                ensure_api_ok(st, val)?
            } else {
                let rt = load_offline_runtime(&opts.config_path)?;
                delete_node(id, &rt.nodes, &rt.engine)
                    .map_err(|e| control_err_to_cli(e, opts.locale))?;
                rt.save()?;
                json!({ "ok": true })
            };

            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&res_val)?);
            } else {
                println!("Removed proxy node #{}", id);
            }
            Ok(())
        }
        "ping" => {
            let (pos, flags) = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx node ping",
                    value_flags: &["id"],
                    bool_flags: &["all"],
                    min_pos: 0,
                    max_pos: 1,
                },
            )?;
            if flags.contains_key("all") {
                if !pos.is_empty() || flags.contains_key("id") {
                    bail!("Cannot specify both --all and a node <ID> for `flowx node ping`");
                }
                return ping_all_nodes(opts).await;
            }
            let id_str = resolve_id_arg(
                &pos,
                &flags,
                "Missing node <ID> or --all for `flowx node ping`",
            )?;
            let id: u32 = id_str.parse().context("Invalid node ID")?;

            let res_val = if let Some((st, val)) =
                api_request_or_offline(opts, "POST", "/api/nodes/ping", Some(&json!({ "id": id })))
                    .await?
            {
                ensure_api_ok(st, val)?
            } else {
                let rt = load_offline_runtime_readonly(&opts.config_path)?;
                let addr = {
                    let guard = rt.nodes.read().unwrap_or_else(|e| e.into_inner());
                    guard
                        .get(&id)
                        .map(|n| n.server_addr.clone())
                        .ok_or_else(|| {
                            control_err_to_cli(
                                ControlError::not_found(
                                    "ERR_NODE_NOT_FOUND",
                                    "error.node_not_found",
                                ),
                                opts.locale,
                            )
                        })?
                };
                let (ok, latency_ms, message, detail) =
                    ping_address(&addr, &DEFAULT_SELF_PORTS, opts.locale).await;
                serde_json::to_value(PingResponse {
                    ok,
                    latency_ms,
                    message,
                    detail,
                })?
            };

            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&res_val)?);
            } else if res_val["ok"].as_bool().unwrap_or(false) {
                println!(
                    "Node #{} reachable: {} ms",
                    id,
                    res_val["latency_ms"].as_u64().unwrap_or(0)
                );
            } else {
                println!(
                    "Node #{} unreachable: {}",
                    id,
                    res_val["message"].as_str().unwrap_or("failed")
                );
            }
            let _ = std::io::stdout().flush();
            if !res_val["ok"].as_bool().unwrap_or(false) {
                return Err(anyhow::Error::new(SilentExitError { code: 1 }));
            }
            Ok(())
        }
        other => bail!("Unknown `flowx node` subcommand '{}'", other),
    }
}

async fn ping_all_nodes(opts: &GlobalCliOpts) -> Result<()> {
    let (online, nodes): (bool, Vec<(u32, String, String, String)>) =
        if let Some((st, val)) = api_request_or_offline(opts, "GET", "/api/nodes", None).await? {
            let list: Vec<ProxyNodeView> = serde_json::from_value(ensure_api_ok(st, val)?)?;
            (
                true,
                list.into_iter()
                    .map(|n| (n.id, n.name, n.protocol, n.server_addr))
                    .collect(),
            )
        } else {
            let rt = load_offline_runtime_readonly(&opts.config_path)?;
            let guard = rt.nodes.read().unwrap_or_else(|e| e.into_inner());
            let mut list: Vec<_> = guard
                .values()
                .map(|n| {
                    (
                        n.id,
                        n.name.clone(),
                        n.protocol.clone(),
                        n.server_addr.clone(),
                    )
                })
                .collect();
            list.sort_by_key(|(id, _, _, _)| *id);
            (false, list)
        };

    let mut handles = Vec::with_capacity(nodes.len());
    for (id, name, protocol, server_addr) in nodes {
        let api_addr = opts.api_addr.clone();
        let locale = opts.locale;
        handles.push(tokio::spawn(async move {
            let ping_val = if online {
                match api_request_raw(
                    &api_addr,
                    locale,
                    "POST",
                    "/api/nodes/ping",
                    Some(&json!({ "id": id })),
                )
                .await
                {
                    Ok((st, val)) if (200..300).contains(&st) => val,
                    Ok((st, val)) => json!({
                        "ok": false,
                        "latency_ms": 0,
                        "message": val["error"]
                            .as_str()
                            .unwrap_or(&format!("HTTP {}", st))
                            .to_string(),
                        "detail": val.get("code").cloned().unwrap_or(Value::Null),
                    }),
                    Err(ApiTransportError::ConnectionRefused(msg)) => {
                        return Err(anyhow!("{}", msg));
                    }
                    Err(ApiTransportError::Other(e)) => {
                        return Err(e);
                    }
                }
            } else {
                let (ok, latency_ms, message, detail) =
                    ping_address(&server_addr, &DEFAULT_SELF_PORTS, locale).await;
                serde_json::to_value(PingResponse {
                    ok,
                    latency_ms,
                    message,
                    detail,
                })?
            };
            let mut entry = json!({
                "id": id,
                "name": name,
                "protocol": protocol,
                "server_addr": server_addr,
                "ok": ping_val["ok"].as_bool().unwrap_or(false),
                "latency_ms": ping_val["latency_ms"].as_u64().unwrap_or(0),
                "message": ping_val["message"].as_str().unwrap_or("").to_string(),
            });
            if let Some(detail) = ping_val.get("detail").filter(|d| !d.is_null())
                && let Some(obj) = entry.as_object_mut()
            {
                obj.insert("detail".to_string(), detail.clone());
            }
            Ok(entry)
        }));
    }

    let mut results = Vec::with_capacity(handles.len());
    for h in handles {
        let item = h.await.context("Ping task failed")??;
        results.push(item);
    }

    let total = results.len();
    let reachable = results
        .iter()
        .filter(|r| r["ok"].as_bool().unwrap_or(false))
        .count();
    let unreachable = total.saturating_sub(reachable);
    let summary = json!({
        "ok": unreachable == 0,
        "total": total,
        "reachable": reachable,
        "unreachable": unreachable,
        "results": results,
    });

    if opts.json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else if total == 0 {
        println!("No proxy nodes configured.");
    } else {
        for r in summary["results"].as_array().into_iter().flatten() {
            let id = r["id"].as_u64().unwrap_or(0);
            let name = r["name"].as_str().unwrap_or("-");
            if r["ok"].as_bool().unwrap_or(false) {
                println!(
                    "Node #{:<4} {:<18} reachable: {} ms",
                    id,
                    name,
                    r["latency_ms"].as_u64().unwrap_or(0)
                );
            } else {
                println!(
                    "Node #{:<4} {:<18} unreachable: {}",
                    id,
                    name,
                    r["message"].as_str().unwrap_or("failed")
                );
            }
        }
        println!("Ping all complete: {}/{} reachable.", reachable, total);
    }

    let _ = std::io::stdout().flush();
    if unreachable > 0 {
        return Err(anyhow::Error::new(SilentExitError { code: 1 }));
    }
    Ok(())
}
