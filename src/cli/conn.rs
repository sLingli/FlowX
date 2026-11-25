use std::io::Write;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::cli::args::{parse_flags_with_spec, resolve_id_arg, ArgSpec, GlobalCliOpts};
use crate::cli::http_client::{api_request_strict, ensure_api_ok, SilentExitError};

pub(super) async fn cmd_conn(opts: &GlobalCliOpts) -> Result<()> {
    if opts.offline {
        bail!("`flowx conn` requires a running FlowX daemon and cannot be used with --offline");
    }
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
                    cmd_label: "flowx conn list",
                    value_flags: &["filter", "search"],
                    bool_flags: &[],
                    min_pos: 0,
                    max_pos: 0,
                },
            )?;
            let action_filter = match flags.get("filter") {
                Some(raw) => {
                    let upper = raw.trim().to_ascii_uppercase();
                    if !matches!(upper.as_str(), "ALL" | "PROXY" | "DIRECT" | "BLOCK") {
                        bail!(
                            "Invalid --filter '{}'; expected ALL, PROXY, DIRECT, or BLOCK",
                            raw
                        );
                    }
                    upper
                }
                None => "ALL".to_string(),
            };
            let search_lower = flags
                .get("search")
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty());

            let (st, val) =
                api_request_strict(&opts.api_addr, "GET", "/api/connections", None).await?;
            let v = ensure_api_ok(st, val)?;
            let filtered: Vec<Value> = v
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter(|c| conn_matches_filter(c, &action_filter, search_lower.as_deref()))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&filtered)?);
            } else if filtered.is_empty() {
                if action_filter != "ALL" || search_lower.is_some() {
                    println!("No matching active connections.");
                } else {
                    println!("No active connections.");
                }
            } else {
                for c in &filtered {
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
            Ok(())
        }
        "kill" => {
            let (pos, flags) = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx conn kill",
                    value_flags: &["id"],
                    bool_flags: &[],
                    min_pos: 0,
                    max_pos: 1,
                },
            )?;
            let id_str =
                resolve_id_arg(&pos, &flags, "Missing connection <ID> for `flowx conn kill`")?;
            let id: u64 = id_str.parse().context("Invalid connection ID")?;
            let (st, val) = api_request_strict(
                &opts.api_addr,
                "POST",
                &format!("/api/connections/kill?id={}", id),
                None,
            )
            .await?;
            let v = ensure_api_ok(st, val)?;
            let killed = v["killed"].as_bool().unwrap_or(false);
            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                println!("Connection #{} kill signal sent (killed={})", id, killed);
            }
            let _ = std::io::stdout().flush();
            if !killed {
                return Err(anyhow::Error::new(SilentExitError { code: 1 }));
            }
            Ok(())
        }
        other => bail!("Unknown `flowx conn` subcommand '{}'", other),
    }
}

pub(super) fn conn_matches_filter(
    conn: &Value,
    action_filter: &str,
    search_lower: Option<&str>,
) -> bool {
    let act = conn["action_type"]
        .as_str()
        .or_else(|| conn["action"].as_str())
        .unwrap_or("");
    let action_ok = match action_filter {
        "ALL" => true,
        "PROXY" => act.contains("Proxy") || act.contains("Chain"),
        "DIRECT" => act.contains("Direct"),
        "BLOCK" => act.contains("Block"),
        _ => true,
    };
    if !action_ok {
        return false;
    }
    if let Some(kw) = search_lower {
        let hay = format!(
            "{} {} {} {} {}",
            conn["process_name"].as_str().unwrap_or(""),
            conn["process_path"].as_str().unwrap_or(""),
            conn["target"].as_str().unwrap_or(""),
            conn["rule_name"].as_str().unwrap_or(""),
            conn["action"].as_str().unwrap_or(""),
        )
        .to_lowercase();
        if !hay.contains(kw) {
            return false;
        }
    }
    true
}
