use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::api::{
    handle_add_node, handle_add_rule, handle_set_default_action, handle_simulate_route,
    handle_update_node, handle_update_rule, ping_address, AddNodeRequest, AddRuleRequest,
    PingResponse, ProxyNodeView, SetDefaultActionRequest, SimulateRouteRequest, UpdateNodeRequest,
    UpdateRuleRequest,
};
use crate::config::ConfigStore;
use crate::i18n::Locale;
use crate::interceptor::dispatcher::ProxyNodeEntry;
use crate::router::{format_action_desc, Action, RuleEngine};

const DEFAULT_API_ADDR: &str = "127.0.0.1:40080";
const DEFAULT_SELF_PORTS: [u16; 3] = [40001, 40080, 1053];

/// 判断命令行参数是否应进入 CLI 子命令模式（无子命令或 `serve` 时返回 `false` 进入后台守护模式）
pub fn should_run_cli(args: &[String]) -> bool {
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        if arg == "--config" || arg == "--api" {
            let _ = iter.next();
            continue;
        }
        if arg.starts_with("--config=") || arg.starts_with("--api=") {
            continue;
        }
        if arg == "serve" {
            return false;
        }
        return true;
    }
    false
}

#[derive(Debug, Clone)]
pub struct GlobalCliOpts {
    pub config_path: String,
    pub api_addr: String,
    pub json_output: bool,
    pub rest: Vec<String>,
}

pub fn parse_global_opts(args: &[String]) -> Result<GlobalCliOpts> {
    let mut config_path =
        std::env::var("FLOWX_CONFIG").unwrap_or_else(|_| "flowx.xml".to_string());
    let mut api_addr =
        std::env::var("FLOWX_API").unwrap_or_else(|_| DEFAULT_API_ADDR.to_string());
    let mut json_output = false;
    let mut rest = Vec::new();

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--config" {
            i += 1;
            let val = args
                .get(i)
                .ok_or_else(|| anyhow!("Missing value for --config"))?;
            config_path = val.clone();
        } else if let Some(val) = arg.strip_prefix("--config=") {
            config_path = val.to_string();
        } else if arg == "--api" {
            i += 1;
            let val = args
                .get(i)
                .ok_or_else(|| anyhow!("Missing value for --api"))?;
            api_addr = normalize_api_addr(val);
        } else if let Some(val) = arg.strip_prefix("--api=") {
            api_addr = normalize_api_addr(val);
        } else if arg == "--json" {
            json_output = true;
        } else {
            rest.push(arg.clone());
        }
        i += 1;
    }

    api_addr = normalize_api_addr(&api_addr);
    Ok(GlobalCliOpts {
        config_path,
        api_addr,
        json_output,
        rest,
    })
}

fn normalize_api_addr(raw: &str) -> String {
    let trimmed = raw.trim();
    let without_scheme = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed);
    without_scheme.trim_end_matches('/').to_string()
}

pub async fn run_cli(args: &[String]) -> Result<()> {
    let opts = parse_global_opts(args)?;
    let Some(cmd) = opts.rest.first().map(|s| s.as_str()) else {
        print_help();
        return Ok(());
    };

    match cmd {
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        "version" | "--version" | "-V" => {
            if opts.json_output {
                println!(r#"{{"version":"{}"}}"#, env!("CARGO_PKG_VERSION"));
            } else {
                println!("flowx v{}", env!("CARGO_PKG_VERSION"));
            }
            Ok(())
        }
        "status" => cmd_status(&opts).await,
        "node" => cmd_node(&opts).await,
        "rule" => cmd_rule(&opts).await,
        "default" => cmd_default(&opts).await,
        "sim" | "simulate" => cmd_sim(&opts).await,
        "conn" | "connections" => cmd_conn(&opts).await,
        other => bail!(
            "Unknown subcommand '{}'. Run `flowx --help` for usage.",
            other
        ),
    }
}

pub fn print_help() {
    println!(
        "\
FlowX v{} — Transparent Proxy & Process Routing Engine CLI

USAGE:
  flowx [serve] [--config <flowx.xml>]
  flowx <SUBCOMMAND> [OPTIONS] [--config <flowx.xml>] [--api <127.0.0.1:40080>] [--json]

SUBCOMMANDS:
  status
      Show daemon online/offline status, endpoints, node/rule counts, and default fallback action.

  node list
  node add --name <NAME> --addr <HOST:PORT> [--protocol <SOCKS5|HTTP|SOCKS4>] [--user <U>] [--pass <P>]
  node update <ID> [--name <NAME>] [--addr <HOST:PORT>] [--protocol <SOCKS5|HTTP|SOCKS4>] [--user <U>] [--pass <P>]
  node remove <ID>
  node ping <ID>
      Manage proxy nodes (persists to XML automatically; syncs with live daemon when running).

  rule list
  rule add --name <NAME> --action <Direct|Block|Proxy[:NODE_ID]> [--node <NODE_ID>] [--apps <GLOB>] [--targets <HOSTS>] [--ports <PORTS>]
  rule update <ID> [--name <NAME>] [--action <Direct|Block|Proxy[:NODE_ID]>] [--node <NODE_ID>] [--apps <GLOB>] [--targets <HOSTS>] [--ports <PORTS>]
  rule toggle <ID> [--enable | --disable]
  rule move <ID> <up|down|top|bottom>
  rule remove <ID>
      Manage top-down routing rules (First-Match Wins).

  default [Direct | Block | Proxy:<NODE_ID>] [--node <NODE_ID>]
      Query or update the fallback default action when no enabled rule matches.

  sim --target <HOST[:PORT]> [--app <PROCESS_NAME_OR_PATH>] [--port <PORT>]
      Dry-run route evaluation and print the matched rule, action, and per-rule skip reasons.

  conn list
  conn kill <ID>
      Inspect or terminate live active connections (requires running FlowX daemon).

GLOBAL FLAGS:
  --config <PATH>   Path to XML configuration file (default: flowx.xml or $FLOWX_CONFIG)
  --api <ADDR>      FlowX HTTP API address (default: 127.0.0.1:40080 or $FLOWX_API)
  --json            Output machine-readable JSON for AI Agents and automation scripts
",
        env!("CARGO_PKG_VERSION")
    );
}

async fn api_request(
    api_addr: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result< Option<(u16, Value)> > {
    let stream_res =
        tokio::time::timeout(Duration::from_millis(800), TcpStream::connect(api_addr)).await;
    let Ok(Ok(mut stream)) = stream_res else {
        return Ok(None);
    };

    let body_str = body.map(|b| b.to_string()).unwrap_or_default();
    let req = if body.is_some() {
        format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nAccept-Language: zh-CN\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            method,
            path,
            api_addr,
            body_str.len(),
            body_str
        )
    } else {
        format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nAccept-Language: zh-CN\r\nConnection: close\r\n\r\n",
            method, path, api_addr
        )
    };

    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(4), stream.read_to_end(&mut buf)).await??;

    let raw = String::from_utf8_lossy(&buf);
    let Some((header_part, body_part)) = raw.split_once("\r\n\r\n") else {
        bail!("Invalid HTTP response from {}", api_addr);
    };
    let status_line = header_part.lines().next().unwrap_or_default();
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(500);

    let json_val = serde_json::from_str::<Value>(body_part)
        .unwrap_or_else(|_| json!({ "raw": body_part.trim() }));
    Ok(Some((status_code, json_val)))
}

fn ensure_api_ok(status: u16, val: Value) -> Result<Value> {
    if (200..300).contains(&status) {
        Ok(val)
    } else {
        let err_msg = val
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("API request failed");
        bail!("{} (HTTP {})", err_msg, status);
    }
}

type OfflineRuntime = (
    ConfigStore,
    RwLock<HashMap<u32, ProxyNodeEntry>>,
    RuleEngine,
);

fn load_offline_runtime(config_path: &str) -> Result<OfflineRuntime> {
    let store = ConfigStore::new(config_path);
    let (rt, _) = store
        .load_or_init(&DEFAULT_SELF_PORTS)
        .with_context(|| format!("Failed to load configuration file: {}", config_path))?;
    let nodes = RwLock::new(rt.proxy_nodes);
    let engine = RuleEngine::new(rt.rules, rt.default_action);
    Ok((store, nodes, engine))
}

fn offline_resolve_rule_id(rule_engine: &RuleEngine, id_or_index: u64) -> Option<u64> {
    let rules = rule_engine.current_rules();
    if rules.iter().any(|r| r.id == id_or_index) {
        return Some(id_or_index);
    }
    if id_or_index >= 1 {
        let idx = (id_or_index as usize) - 1;
        if let Some(r) = rules.get(idx) {
            return Some(r.id);
        }
    }
    None
}

fn parse_flag_map(args: &[String]) -> Result<(Vec<String>, HashMap<String, String>)> {
    let mut positionals = Vec::new();
    let mut flags = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(stripped) = arg.strip_prefix("--") {
            if let Some((k, v)) = stripped.split_once('=') {
                flags.insert(k.to_string(), v.to_string());
            } else if matches!(stripped, "enable" | "disable") {
                flags.insert(stripped.to_string(), "true".to_string());
            } else {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| anyhow!("Missing value for option --{}", stripped))?;
                flags.insert(stripped.to_string(), val.clone());
            }
        } else {
            positionals.push(arg.clone());
        }
        i += 1;
    }
    Ok((positionals, flags))
}

fn split_action_spec(raw: &str, explicit_node: Option<u32>) -> Result<(String, Option<u32>)> {
    if let Some((act_part, id_part)) = raw.split_once(':') {
        let nid = id_part
            .trim()
            .parse::<u32>()
            .with_context(|| format!("Invalid node ID in action '{}'", raw))?;
        Ok((act_part.trim().to_string(), Some(nid)))
    } else {
        Ok((raw.trim().to_string(), explicit_node))
    }
}

async fn cmd_status(opts: &GlobalCliOpts) -> Result<()> {
    if let Some((status, sys_val)) = api_request(&opts.api_addr, "GET", "/api/system", None).await?
        && status == 200
    {
        let stats_val = api_request(&opts.api_addr, "GET", "/api/stats", None)
            .await?
            .and_then(|(st, v)| (st == 200).then_some(v))
            .unwrap_or_else(|| json!({}));

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
        }
        return Ok(());
    }

    let (store, nodes, engine) = load_offline_runtime(&opts.config_path)?;
    let nodes_count = nodes.read().unwrap_or_else(|e| e.into_inner()).len();
    let rules = engine.current_rules();
    let enabled_count = rules.iter().filter(|r| r.enabled).count();
    let def_act = engine.default_action();
    let def_desc = format_action_desc(&def_act, Locale::Zh);

    let out = json!({
        "mode": "offline",
        "config_path": store.path().display().to_string(),
        "nodes_count": nodes_count,
        "rules_count": rules.len(),
        "enabled_rules_count": enabled_count,
        "default_action": def_desc,
        "default_action_type": def_act.type_str(),
        "default_node_id": def_act.target_id(),
    });
    if opts.json_output {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Mode:           OFFLINE (Direct XML Config)");
        println!("Config File:    {}", store.path().display());
        println!("Proxy Nodes:    {}", nodes_count);
        println!(
            "Routing Rules:  {} enabled / {} total",
            enabled_count,
            rules.len()
        );
        println!("Default Action: {}", def_desc);
    }
    Ok(())
}

async fn cmd_node(opts: &GlobalCliOpts) -> Result<()> {
    let sub = opts.rest.get(1).map(|s| s.as_str()).unwrap_or("list");
    let tail = if opts.rest.len() > 2 {
        &opts.rest[2..]
    } else {
        &[]
    };
    let (pos, flags) = parse_flag_map(tail)?;

    match sub {
        "list" | "ls" => {
            let list: Vec<ProxyNodeView> =
                if let Some((st, val)) = api_request(&opts.api_addr, "GET", "/api/nodes", None).await? {
                    let v = ensure_api_ok(st, val)?;
                    serde_json::from_value(v)?
                } else {
                    let (_, nodes, _) = load_offline_runtime(&opts.config_path)?;
                    let guard = nodes.read().unwrap_or_else(|e| e.into_inner());
                    let mut v: Vec<ProxyNodeView> = guard
                        .values()
                        .map(|n| ProxyNodeView {
                            id: n.id,
                            name: n.name.clone(),
                            protocol: n.protocol.clone(),
                            server_addr: n.server_addr.clone(),
                            auth_configured: n.username.is_some(),
                            username: n.username.clone(),
                        })
                        .collect();
                    v.sort_by_key(|n| n.id);
                    v
                };

            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else if list.is_empty() {
                println!("No proxy nodes configured.");
            } else {
                for n in list {
                    let auth = if n.auth_configured { "auth=yes" } else { "auth=no" };
                    println!(
                        "#{:<4} {:<18} {:<8} {:<22} ({})",
                        n.id, n.name, n.protocol, n.server_addr, auth
                    );
                }
            }
            Ok(())
        }
        "add" => {
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
                api_request(&opts.api_addr, "POST", "/api/nodes", Some(&payload)).await?
            {
                ensure_api_ok(st, val)?
            } else {
                let (store, nodes, engine) = load_offline_runtime(&opts.config_path)?;
                let req: AddNodeRequest = serde_json::from_value(payload)?;
                let (st, _, body) = handle_add_node(req, &nodes, &DEFAULT_SELF_PORTS, Locale::Zh);
                let val: Value = serde_json::from_str(&body)?;
                if st != "200 OK" {
                    bail!("{}", val["error"].as_str().unwrap_or(&body));
                }
                store.save_runtime(&nodes, &engine)?;
                val
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
            let id_str = pos
                .first()
                .or_else(|| flags.get("id"))
                .ok_or_else(|| anyhow!("Missing node <ID> for `flowx node update`"))?;
            let id: u32 = id_str.parse().context("Invalid node ID")?;

            // 先查询当前节点信息以支持部分字段更新
            let existing_list: Vec<ProxyNodeView> =
                if let Some((st, val)) = api_request(&opts.api_addr, "GET", "/api/nodes", None).await? {
                    serde_json::from_value(ensure_api_ok(st, val)?)?
                } else {
                    let (_, nodes, _) = load_offline_runtime(&opts.config_path)?;
                    let guard = nodes.read().unwrap_or_else(|e| e.into_inner());
                    guard
                        .values()
                        .map(|n| ProxyNodeView {
                            id: n.id,
                            name: n.name.clone(),
                            protocol: n.protocol.clone(),
                            server_addr: n.server_addr.clone(),
                            auth_configured: n.username.is_some(),
                            username: n.username.clone(),
                        })
                        .collect()
                };
            let current = existing_list
                .into_iter()
                .find(|n| n.id == id)
                .ok_or_else(|| anyhow!("Proxy node #{} not found", id))?;

            let name = flags.get("name").cloned().unwrap_or(current.name);
            let server_addr = flags
                .get("addr")
                .or_else(|| flags.get("server"))
                .cloned()
                .unwrap_or(current.server_addr);
            let protocol = flags
                .get("protocol")
                .or_else(|| flags.get("proto"))
                .cloned()
                .unwrap_or(current.protocol);
            let username = match flags.get("user").or_else(|| flags.get("username")) {
                Some(u) if u.is_empty() => None,
                Some(u) => Some(u.clone()),
                None => current.username,
            };
            let pass_flag = flags.get("pass").or_else(|| flags.get("password")).cloned();
            let keep_password = pass_flag.is_none() && username.is_some();

            let payload = json!({
                "id": id,
                "name": name,
                "protocol": protocol,
                "server_addr": server_addr,
                "username": username,
                "password": pass_flag,
                "keep_password": keep_password,
            });

            let res_val = if let Some((st, val)) =
                api_request(&opts.api_addr, "PUT", "/api/nodes", Some(&payload)).await?
            {
                ensure_api_ok(st, val)?
            } else {
                let (store, nodes, engine) = load_offline_runtime(&opts.config_path)?;
                let req: UpdateNodeRequest = serde_json::from_value(payload)?;
                let (st, _, body) =
                    handle_update_node(req, &nodes, &DEFAULT_SELF_PORTS, Locale::Zh);
                let val: Value = serde_json::from_str(&body)?;
                if st != "200 OK" {
                    bail!("{}", val["error"].as_str().unwrap_or(&body));
                }
                store.save_runtime(&nodes, &engine)?;
                val
            };

            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&res_val)?);
            } else {
                println!("Updated proxy node #{} ({})", id, name);
            }
            Ok(())
        }
        "remove" | "delete" | "rm" => {
            let id_str = pos
                .first()
                .or_else(|| flags.get("id"))
                .ok_or_else(|| anyhow!("Missing node <ID> for `flowx node remove`"))?;
            let id: u32 = id_str.parse().context("Invalid node ID")?;

            let res_val = if let Some((st, val)) = api_request(
                &opts.api_addr,
                "DELETE",
                &format!("/api/nodes?id={}", id),
                None,
            )
            .await?
            {
                ensure_api_ok(st, val)?
            } else {
                let (store, nodes, engine) = load_offline_runtime(&opts.config_path)?;
                let rules = engine.current_rules();
                let current_default = engine.default_action();
                let is_referenced = rules
                    .iter()
                    .any(|r| matches!(r.action, Action::Proxy(pid) if pid == id))
                    || matches!(current_default, Action::Proxy(pid) if pid == id);
                if is_referenced {
                    bail!(
                        "Node #{} is referenced by active rules or default action and cannot be removed",
                        id
                    );
                }
                let removed = nodes
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&id)
                    .is_some();
                if !removed {
                    bail!("Proxy node #{} not found", id);
                }
                store.save_runtime(&nodes, &engine)?;
                json!({ "ok": true, "id": id })
            };

            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&res_val)?);
            } else {
                println!("Removed proxy node #{}", id);
            }
            Ok(())
        }
        "ping" => {
            let id_str = pos
                .first()
                .or_else(|| flags.get("id"))
                .ok_or_else(|| anyhow!("Missing node <ID> for `flowx node ping`"))?;
            let id: u32 = id_str.parse().context("Invalid node ID")?;

            let res_val = if let Some((st, val)) = api_request(
                &opts.api_addr,
                "POST",
                "/api/nodes/ping",
                Some(&json!({ "id": id })),
            )
            .await?
            {
                ensure_api_ok(st, val)?
            } else {
                let (_, nodes, _) = load_offline_runtime(&opts.config_path)?;
                let addr = {
                    let guard = nodes.read().unwrap_or_else(|e| e.into_inner());
                    guard
                        .get(&id)
                        .map(|n| n.server_addr.clone())
                        .ok_or_else(|| anyhow!("Proxy node #{} not found", id))?
                };
                let (ok, latency_ms, message, detail) = ping_address(&addr, Locale::Zh).await;
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
            Ok(())
        }
        other => bail!("Unknown `flowx node` subcommand '{}'", other),
    }
}

async fn cmd_rule(opts: &GlobalCliOpts) -> Result<()> {
    let sub = opts.rest.get(1).map(|s| s.as_str()).unwrap_or("list");
    let tail = if opts.rest.len() > 2 {
        &opts.rest[2..]
    } else {
        &[]
    };
    let (pos, flags) = parse_flag_map(tail)?;

    match sub {
        "list" | "ls" => {
            let list: Vec<crate::router::RuleView> =
                if let Some((st, val)) = api_request(&opts.api_addr, "GET", "/api/rules", None).await? {
                    serde_json::from_value(ensure_api_ok(st, val)?)?
                } else {
                    let (_, _, engine) = load_offline_runtime(&opts.config_path)?;
                    engine.list_rules_view_with_locale(Locale::Zh)
                };

            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else if list.is_empty() {
                println!("No routing rules configured.");
            } else {
                for (idx, r) in list.iter().enumerate() {
                    let state_str = if r.enabled { "ON " } else { "OFF" };
                    let apps = if r.apps.is_empty() { "*" } else { &r.apps };
                    let targets = if r.targets.is_empty() { "*" } else { &r.targets };
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
                api_request(&opts.api_addr, "POST", "/api/rules", Some(&payload)).await?
            {
                ensure_api_ok(st, val)?
            } else {
                let (store, nodes, engine) = load_offline_runtime(&opts.config_path)?;
                let req: AddRuleRequest = serde_json::from_value(payload)?;
                let (st, _, body) = handle_add_rule(req, &engine, &nodes, Locale::Zh);
                let val: Value = serde_json::from_str(&body)?;
                if st != "200 OK" {
                    bail!("{}", val["error"].as_str().unwrap_or(&body));
                }
                store.save_runtime(&nodes, &engine)?;
                val
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
            let id_str = pos
                .first()
                .or_else(|| flags.get("id"))
                .ok_or_else(|| anyhow!("Missing rule <ID> for `flowx rule update`"))?;
            let raw_id: u64 = id_str.parse().context("Invalid rule ID")?;

            let list: Vec<crate::router::RuleView> =
                if let Some((st, val)) = api_request(&opts.api_addr, "GET", "/api/rules", None).await? {
                    serde_json::from_value(ensure_api_ok(st, val)?)?
                } else {
                    let (_, _, engine) = load_offline_runtime(&opts.config_path)?;
                    engine.list_rules_view_with_locale(Locale::Zh)
                };

            let current = list
                .iter()
                .find(|r| r.id == raw_id)
                .or_else(|| {
                    if raw_id >= 1 {
                        list.get((raw_id as usize) - 1)
                    } else {
                        None
                    }
                })
                .cloned()
                .ok_or_else(|| anyhow!("Routing rule #{} not found", raw_id))?;

            let name = flags.get("name").cloned().unwrap_or(current.name);
            let explicit_node = match flags.get("node").or_else(|| flags.get("node-id")) {
                Some(s) => Some(s.parse::<u32>().context("Invalid --node ID")?),
                None => current.node_id,
            };
            let (action, node_id) = match flags.get("action") {
                Some(act_raw) => split_action_spec(act_raw, explicit_node)?,
                None => (current.action_type, explicit_node),
            };
            let apps = flags
                .get("apps")
                .or_else(|| flags.get("app"))
                .cloned()
                .unwrap_or(current.apps);
            let targets = flags
                .get("targets")
                .or_else(|| flags.get("target"))
                .cloned()
                .unwrap_or(current.targets);
            let ports = flags
                .get("ports")
                .or_else(|| flags.get("port"))
                .cloned()
                .unwrap_or(current.ports);

            let payload = json!({
                "id": current.id,
                "name": name,
                "apps": apps,
                "targets": targets,
                "ports": ports,
                "action": action,
                "node_id": node_id,
            });

            let res_val = if let Some((st, val)) =
                api_request(&opts.api_addr, "PUT", "/api/rules", Some(&payload)).await?
            {
                ensure_api_ok(st, val)?
            } else {
                let (store, nodes, engine) = load_offline_runtime(&opts.config_path)?;
                let resolved_id = offline_resolve_rule_id(&engine, raw_id)
                    .ok_or_else(|| anyhow!("Routing rule #{} not found", raw_id))?;
                let mut req: UpdateRuleRequest = serde_json::from_value(payload)?;
                req.id = resolved_id;
                let (st, _, body) = handle_update_rule(req, &engine, &nodes, Locale::Zh);
                let val: Value = serde_json::from_str(&body)?;
                if st != "200 OK" {
                    bail!("{}", val["error"].as_str().unwrap_or(&body));
                }
                store.save_runtime(&nodes, &engine)?;
                val
            };

            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&res_val)?);
            } else {
                println!("Updated routing rule #{} ({})", current.id, name);
            }
            Ok(())
        }
        "toggle" => {
            let id_str = pos
                .first()
                .or_else(|| flags.get("id"))
                .ok_or_else(|| anyhow!("Missing rule <ID> for `flowx rule toggle`"))?;
            let raw_id: u64 = id_str.parse().context("Invalid rule ID")?;
            let enabled = if flags.contains_key("enable") {
                Some(true)
            } else if flags.contains_key("disable") {
                Some(false)
            } else {
                None
            };

            let res_val = if let Some((st, val)) = api_request(
                &opts.api_addr,
                "POST",
                "/api/rules/toggle",
                Some(&json!({ "id": raw_id, "enabled": enabled })),
            )
            .await?
            {
                ensure_api_ok(st, val)?
            } else {
                let (store, nodes, engine) = load_offline_runtime(&opts.config_path)?;
                let resolved_id = offline_resolve_rule_id(&engine, raw_id)
                    .ok_or_else(|| anyhow!("Routing rule #{} not found", raw_id))?;
                let next_state = engine
                    .toggle_rule(resolved_id, enabled)
                    .ok_or_else(|| anyhow!("Routing rule #{} not found", raw_id))?;
                store.save_runtime(&nodes, &engine)?;
                json!({ "ok": true, "id": resolved_id, "enabled": next_state })
            };

            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&res_val)?);
            } else {
                println!(
                    "Rule #{} enabled={}",
                    raw_id,
                    res_val["enabled"].as_bool().unwrap_or(false)
                );
            }
            Ok(())
        }
        "move" | "mv" => {
            let id_str = pos
                .first()
                .or_else(|| flags.get("id"))
                .ok_or_else(|| anyhow!("Missing rule <ID> for `flowx rule move`"))?;
            let raw_id: u64 = id_str.parse().context("Invalid rule ID")?;
            let direction = pos
                .get(1)
                .or_else(|| flags.get("dir"))
                .or_else(|| flags.get("direction"))
                .cloned()
                .ok_or_else(|| anyhow!("Missing direction <up|down|top|bottom>"))?;

            let res_val = if let Some((st, val)) = api_request(
                &opts.api_addr,
                "POST",
                "/api/rules/move",
                Some(&json!({ "id": raw_id, "direction": direction })),
            )
            .await?
            {
                ensure_api_ok(st, val)?
            } else {
                let (store, nodes, engine) = load_offline_runtime(&opts.config_path)?;
                let resolved_id = offline_resolve_rule_id(&engine, raw_id)
                    .ok_or_else(|| anyhow!("Routing rule #{} not found", raw_id))?;
                let moved = engine
                    .move_rule(resolved_id, &direction)
                    .ok_or_else(|| anyhow!("Invalid move target or direction '{}'", direction))?;
                if moved {
                    store.save_runtime(&nodes, &engine)?;
                }
                json!({ "ok": true, "id": resolved_id, "moved": moved })
            };

            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&res_val)?);
            } else {
                println!(
                    "Rule #{} move {} (moved={})",
                    raw_id,
                    direction,
                    res_val["moved"].as_bool().unwrap_or(false)
                );
            }
            Ok(())
        }
        "remove" | "delete" | "rm" => {
            let id_str = pos
                .first()
                .or_else(|| flags.get("id"))
                .ok_or_else(|| anyhow!("Missing rule <ID> for `flowx rule remove`"))?;
            let raw_id: u64 = id_str.parse().context("Invalid rule ID")?;

            let res_val = if let Some((st, val)) = api_request(
                &opts.api_addr,
                "DELETE",
                &format!("/api/rules?id={}", raw_id),
                None,
            )
            .await?
            {
                ensure_api_ok(st, val)?
            } else {
                let (store, nodes, engine) = load_offline_runtime(&opts.config_path)?;
                let resolved_id = offline_resolve_rule_id(&engine, raw_id)
                    .ok_or_else(|| anyhow!("Routing rule #{} not found", raw_id))?;
                if !engine.delete_rule(resolved_id) {
                    bail!("Routing rule #{} not found", raw_id);
                }
                store.save_runtime(&nodes, &engine)?;
                json!({ "ok": true, "id": resolved_id })
            };

            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&res_val)?);
            } else {
                println!("Removed routing rule #{}", raw_id);
            }
            Ok(())
        }
        other => bail!("Unknown `flowx rule` subcommand '{}'", other),
    }
}

async fn cmd_default(opts: &GlobalCliOpts) -> Result<()> {
    let tail = if opts.rest.len() > 1 {
        &opts.rest[1..]
    } else {
        &[]
    };
    let (pos, flags) = parse_flag_map(tail)?;

    let action_arg = pos.first().or_else(|| flags.get("action")).cloned();
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
            api_request(&opts.api_addr, "POST", "/api/rules/default", Some(&payload)).await?
        {
            ensure_api_ok(st, val)?
        } else {
            let (store, nodes, engine) = load_offline_runtime(&opts.config_path)?;
            let req: SetDefaultActionRequest = serde_json::from_value(payload)?;
            let (st, _, body) = handle_set_default_action(req, &engine, &nodes, Locale::Zh);
            let val: Value = serde_json::from_str(&body)?;
            if st != "200 OK" {
                bail!("{}", val["error"].as_str().unwrap_or(&body));
            }
            store.save_runtime(&nodes, &engine)?;
            val
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

    // 未提供新动作时查询当前默认兜底动作
    if let Some((st, sys_val)) = api_request(&opts.api_addr, "GET", "/api/system", None).await?
        && st == 200
    {
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

    let (_, _, engine) = load_offline_runtime(&opts.config_path)?;
    let act = engine.default_action();
    let desc = format_action_desc(&act, Locale::Zh);
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

async fn cmd_sim(opts: &GlobalCliOpts) -> Result<()> {
    let tail = if opts.rest.len() > 1 {
        &opts.rest[1..]
    } else {
        &[]
    };
    let (pos, flags) = parse_flag_map(tail)?;

    let target = flags
        .get("target")
        .or_else(|| flags.get("host"))
        .or_else(|| pos.first())
        .cloned()
        .ok_or_else(|| anyhow!("Missing --target <HOST[:PORT]> for `flowx sim`"))?;
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
        api_request(&opts.api_addr, "POST", "/api/rules/simulate", Some(&payload)).await?
    {
        ensure_api_ok(st, val)?
    } else {
        let (_, _, engine) = load_offline_runtime(&opts.config_path)?;
        let req: SimulateRouteRequest = serde_json::from_value(payload)?;
        let (st, _, body) = handle_simulate_route(req, &engine, Locale::Zh);
        let val: Value = serde_json::from_str(&body)?;
        if st != "200 OK" {
            bail!("{}", val["error"].as_str().unwrap_or(&body));
        }
        val
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

async fn cmd_conn(opts: &GlobalCliOpts) -> Result<()> {
    let sub = opts.rest.get(1).map(|s| s.as_str()).unwrap_or("list");
    let tail = if opts.rest.len() > 2 {
        &opts.rest[2..]
    } else {
        &[]
    };
    let (pos, flags) = parse_flag_map(tail)?;

    match sub {
        "list" | "ls" => {
            let Some((st, val)) =
                api_request(&opts.api_addr, "GET", "/api/connections", None).await?
            else {
                bail!("FlowX daemon is not running at {}", opts.api_addr);
            };
            let v = ensure_api_ok(st, val)?;
            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else if let Some(arr) = v.as_array() {
                if arr.is_empty() {
                    println!("No active connections.");
                } else {
                    for c in arr {
                        println!(
                            "#{:<5} {:<18} (pid={:<6}) -> {:<26} [{}] {}",
                            c["id"].as_u64().unwrap_or(0),
                            c["process_name"].as_str().unwrap_or("-"),
                            c["pid"].as_u64().unwrap_or(0),
                            c["target"].as_str().unwrap_or("-"),
                            c["rule_name"].as_str().unwrap_or("-"),
                            c["action"].as_str().unwrap_or("-")
                        );
                    }
                }
            }
            Ok(())
        }
        "kill" => {
            let id_str = pos
                .first()
                .or_else(|| flags.get("id"))
                .ok_or_else(|| anyhow!("Missing connection <ID> for `flowx conn kill`"))?;
            let id: u64 = id_str.parse().context("Invalid connection ID")?;
            let Some((st, val)) = api_request(
                &opts.api_addr,
                "POST",
                &format!("/api/connections/kill?id={}", id),
                None,
            )
            .await?
            else {
                bail!("FlowX daemon is not running at {}", opts.api_addr);
            };
            let v = ensure_api_ok(st, val)?;
            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                println!(
                    "Connection #{} kill signal sent (killed={})",
                    id,
                    v["killed"].as_bool().unwrap_or(false)
                );
            }
            Ok(())
        }
        other => bail!("Unknown `flowx conn` subcommand '{}'", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_run_cli_detection() {
        assert!(!should_run_cli(&["flowx".into()]));
        assert!(!should_run_cli(&[
            "flowx".into(),
            "--config".into(),
            "custom.xml".into()
        ]));
        assert!(!should_run_cli(&[
            "flowx".into(),
            "serve".into(),
            "--config=custom.xml".into()
        ]));
        assert!(should_run_cli(&["flowx".into(), "status".into()]));
        assert!(should_run_cli(&["flowx".into(), "--help".into()]));
        assert!(should_run_cli(&[
            "flowx".into(),
            "--config".into(),
            "a.xml".into(),
            "sim".into(),
            "--target".into(),
            "github.com".into()
        ]));
    }

    #[tokio::test]
    async fn test_cli_offline_crud_and_simulate() {
        let mut path = std::env::current_dir().unwrap().join("target");
        path.push(format!("flowx_cli_test_{}.xml", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let cfg_str = path.to_string_lossy().to_string();
        // 使用未监听端口强制触发离线 XML 模式
        let unused_api = "127.0.0.1:59999";

        // 1. 添加节点 (离线初始化并写入默认配置 + 新节点 #102)
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--api".into(),
            unused_api.into(),
            "--json".into(),
            "node".into(),
            "add".into(),
            "--name".into(),
            "JP-Socks".into(),
            "--addr".into(),
            "10.20.0.1:1080".into(),
            "--protocol".into(),
            "SOCKS5".into(),
        ])
        .await
        .unwrap();

        // 2. 添加规则指向新节点 #102
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--api".into(),
            unused_api.into(),
            "--json".into(),
            "rule".into(),
            "add".into(),
            "--name".into(),
            "GitRule".into(),
            "--apps".into(),
            "git.exe".into(),
            "--targets".into(),
            "*.github.com".into(),
            "--ports".into(),
            "443".into(),
            "--action".into(),
            "Proxy:102".into(),
        ])
        .await
        .unwrap();

        // 3. 更新默认兜底动作
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--api".into(),
            unused_api.into(),
            "--json".into(),
            "default".into(),
            "Proxy:102".into(),
        ])
        .await
        .unwrap();

        // 4. 运行离线模拟
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--api".into(),
            unused_api.into(),
            "--json".into(),
            "sim".into(),
            "--app".into(),
            "git.exe".into(),
            "--target".into(),
            "api.github.com:443".into(),
        ])
        .await
        .unwrap();

        // 验证 XML 文件中的最终状态
        let store = ConfigStore::new(&path);
        let (rt, _) = store.load_or_init(&DEFAULT_SELF_PORTS).unwrap();
        assert!(rt.proxy_nodes.contains_key(&102));
        assert!(rt.rules.iter().any(|r| r.name == "GitRule"));
        assert_eq!(rt.default_action, Action::Proxy(102));

        let _ = std::fs::remove_file(&path);
    }
}
