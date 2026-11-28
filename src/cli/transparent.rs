use anyhow::{Result, bail};
use serde_json::{Value, json};

use crate::cli::args::{ArgSpec, GlobalCliOpts, parse_flags_with_spec};
use crate::cli::bridge::{
    control_err_to_cli, load_offline_runtime_readonly, mutate_offline_runtime,
};
use crate::cli::http_client::{
    API_ELEVATE_IO_TIMEOUT, api_request_or_offline, api_request_strict_with_io_timeout,
    ensure_api_ok,
};
use crate::control::TransparentConfigRequest;
use crate::control::transparent::apply_transparent_config_fields;
use crate::transparent::{TransparentSettings, probe_status};

fn print_transparent_status(st: &Value, mode_label: &str) {
    println!(
        "Transparent Proxy ({}): enabled={} running={} elevated={}",
        mode_label,
        st["enabled"].as_bool().unwrap_or(false),
        st["running"].as_bool().unwrap_or(false),
        st["elevated"].as_bool().unwrap_or(false),
    );
    println!(
        "Options:        hijack_dns={} block_quic_for_proxied={} dll_path={}",
        st["hijack_dns"].as_bool().unwrap_or(true),
        st["block_quic_for_proxied"].as_bool().unwrap_or(true),
        st["configured_dll_path"].as_str().unwrap_or("<auto>"),
    );
    println!(
        "WinDivert:      dll_found={} sys_found={} driver_ver={}",
        st["dll_found"].as_bool().unwrap_or(false),
        st["sys_found"].as_bool().unwrap_or(false),
        st["driver_version"].as_str().unwrap_or("-"),
    );
    if let Some(p) = st["dll_path"].as_str() {
        println!("DLL Resolved:   {}", p);
    }
    if let Some(p) = st["sys_path"].as_str() {
        println!("SYS Resolved:   {}", p);
    }
    println!(
        "Counters:       flows={} intercepted={} passthrough={} rst={} dns={} quic_drop={}",
        st["active_flows"].as_u64().unwrap_or(0),
        st["tcp_intercepted_total"].as_u64().unwrap_or(0),
        st["tcp_passthrough_total"].as_u64().unwrap_or(0),
        st["tcp_blocked_rst_total"].as_u64().unwrap_or(0),
        st["dns_hijacked_total"].as_u64().unwrap_or(0),
        st["quic_blocked_total"].as_u64().unwrap_or(0),
    );
    if let Some(err) = st["last_error"].as_str().filter(|s| !s.is_empty()) {
        println!("Last Error:     {}", err);
    }
    if st["low_integrity"].as_bool().unwrap_or(false) {
        println!(
            "Integrity Warn: Low Mandatory Integrity process detected (UAC elevation & USER32/SHELL32 blocked); move FlowX to a normal folder or run from an Administrator terminal."
        );
    }
}

pub(super) fn build_transparent_doctor_report(
    mode_label: &str,
    st_val: &Value,
    local_config_path: &str,
) -> Value {
    let elevated = st_val["elevated"].as_bool().unwrap_or(false);
    let low_integrity = st_val["low_integrity"].as_bool().unwrap_or(false);
    let running = st_val["running"].as_bool().unwrap_or(false);
    let dll_found = st_val["dll_found"].as_bool().unwrap_or(false);
    let sys_found = st_val["sys_found"].as_bool().unwrap_or(false);
    let dll_path = st_val["dll_path"].as_str().map(str::to_string);
    let sys_path = st_val["sys_path"].as_str().map(str::to_string);
    let configured_dll_path = st_val["configured_dll_path"].as_str().map(str::to_string);
    let searched_dirs: Vec<String> = st_val["searched_dirs"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let config_enabled = st_val["enabled"].as_bool().unwrap_or(false);
    let hijack_dns = st_val["hijack_dns"].as_bool().unwrap_or(true);
    let block_quic = st_val["block_quic_for_proxied"].as_bool().unwrap_or(true);
    let last_error = st_val["last_error"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let mut issues: Vec<String> = Vec::new();
    if low_integrity {
        issues.push(
            "Process is running at Windows Low Mandatory Integrity Level (for example inherited from a restricted/sandboxed folder); UAC elevation and USER32/SHELL32 initialization are blocked. Copy or install FlowX into a standard directory, or launch from an Administrator terminal."
                .to_string(),
        );
    }
    if !elevated {
        issues.push(
            "Target FlowX instance lacks Administrator privileges; launch an elevated shell or click 'Restart as Administrator' in Web UI.".to_string(),
        );
    }
    if !dll_found || !sys_found {
        issues.push(format!(
            "Missing WinDivert binaries (dll_found={}, sys_found={}); place WinDivert.dll and WinDivert64.sys next to flowx.exe or set --dll-path. Searched: {:?}",
            dll_found, sys_found, searched_dirs
        ));
    }
    if let Some(ref err) = last_error {
        issues.push(format!("Last runtime error: {}", err));
    }
    let ready = elevated && !low_integrity && dll_found && sys_found && last_error.is_none();
    let config_path: Option<String> = if mode_label == "ONLINE" {
        st_val["config_path"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    } else {
        Some(local_config_path.to_string())
    };
    json!({
        "mode": mode_label,
        "ready": ready,
        "running": running,
        "config_path": config_path,
        "supported": true,
        "elevated": elevated,
        "low_integrity": low_integrity,
        "dll_found": dll_found,
        "sys_found": sys_found,
        "dll_path": dll_path,
        "sys_path": sys_path,
        "configured_dll_path": configured_dll_path,
        "searched_dirs": searched_dirs,
        "config_enabled": config_enabled,
        "hijack_dns": hijack_dns,
        "block_quic_for_proxied": block_quic,
        "last_error": last_error,
        "issues": issues,
    })
}

pub(super) async fn cmd_transparent(opts: &GlobalCliOpts) -> Result<()> {
    let sub = opts.rest.get(1).map(|s| s.as_str()).unwrap_or("status");
    let tail = if opts.rest.len() > 2 {
        &opts.rest[2..]
    } else {
        &[]
    };

    match sub {
        "status" => {
            let _ = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx transparent status",
                    value_flags: &[],
                    bool_flags: &[],
                    min_pos: 0,
                    max_pos: 0,
                },
            )?;
            let (mode_label, res_val) = if let Some((st, val)) =
                api_request_or_offline(opts, "GET", "/api/transparent/status", None).await?
            {
                ("ONLINE", ensure_api_ok(st, val)?)
            } else {
                let rt = load_offline_runtime_readonly(&opts.config_path)?;
                (
                    "OFFLINE",
                    serde_json::to_value(probe_status(&rt.transparent))?,
                )
            };
            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&res_val)?);
            } else {
                print_transparent_status(&res_val, mode_label);
            }
            Ok(())
        }
        "enable" | "disable" => {
            let cmd_label = if sub == "enable" {
                "flowx transparent enable"
            } else {
                "flowx transparent disable"
            };
            let _ = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label,
                    value_flags: &[],
                    bool_flags: &[],
                    min_pos: 0,
                    max_pos: 0,
                },
            )?;
            let target_enabled = sub == "enable";
            let payload = json!({ "enabled": target_enabled });
            let (mode_label, res_val) = if let Some((st, val)) =
                api_request_or_offline(opts, "POST", "/api/transparent/toggle", Some(&payload))
                    .await?
            {
                ("ONLINE", ensure_api_ok(st, val)?)
            } else {
                let status_val = mutate_offline_runtime(&opts.config_path, |rt| {
                    rt.transparent.enabled = target_enabled;
                    let val = serde_json::to_value(probe_status(&rt.transparent))?;
                    Ok((val, true))
                })?;
                ("OFFLINE", status_val)
            };
            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&res_val)?);
            } else {
                print_transparent_status(&res_val, mode_label);
            }
            Ok(())
        }
        "config" => {
            let (_, flags) = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx transparent config",
                    value_flags: &["dll-path"],
                    bool_flags: &[
                        "hijack-dns",
                        "no-hijack-dns",
                        "block-quic",
                        "no-block-quic",
                        "clear-dll-path",
                    ],
                    min_pos: 0,
                    max_pos: 0,
                },
            )?;
            if flags.is_empty() {
                bail!(
                    "Specify at least one option: --hijack-dns | --no-hijack-dns | --block-quic | --no-block-quic | --dll-path <PATH> | --clear-dll-path"
                );
            }

            let hijack_dns = if flags.contains_key("hijack-dns") {
                Some(true)
            } else if flags.contains_key("no-hijack-dns") {
                Some(false)
            } else {
                None
            };
            let block_quic = if flags.contains_key("block-quic") {
                Some(true)
            } else if flags.contains_key("no-block-quic") {
                Some(false)
            } else {
                None
            };
            let clear_dll_path = flags.contains_key("clear-dll-path");
            let dll_path = flags.get("dll-path").cloned();

            let mut payload = serde_json::Map::new();
            if let Some(v) = hijack_dns {
                payload.insert("hijack_dns".to_string(), json!(v));
            }
            if let Some(v) = block_quic {
                payload.insert("block_quic_for_proxied".to_string(), json!(v));
            }
            if clear_dll_path {
                payload.insert("clear_dll_path".to_string(), json!(true));
            } else if let Some(ref p) = dll_path {
                payload.insert("dll_path".to_string(), json!(p));
            }
            let payload_val = Value::Object(payload);

            let (mode_label, res_val) = if let Some((st, val)) =
                api_request_or_offline(opts, "PUT", "/api/transparent/config", Some(&payload_val))
                    .await?
            {
                ("ONLINE", ensure_api_ok(st, val)?)
            } else {
                let locale = opts.locale;
                let req = TransparentConfigRequest {
                    hijack_dns,
                    block_quic_for_proxied: block_quic,
                    dll_path,
                    clear_dll_path: clear_dll_path.then_some(true),
                };
                // 离线模式加锁前复用控制层统一校验，保证带完整 `key` 且不提前创建目录或 `.lock`
                apply_transparent_config_fields(&TransparentSettings::default(), req.clone())
                    .map_err(|e| control_err_to_cli(e, locale))?;
                let status_val = mutate_offline_runtime(&opts.config_path, |rt| {
                    rt.transparent = apply_transparent_config_fields(&rt.transparent, req.clone())
                        .map_err(|e| control_err_to_cli(e, locale))?;
                    let val = serde_json::to_value(probe_status(&rt.transparent))?;
                    Ok((val, true))
                })?;
                ("OFFLINE", status_val)
            };
            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&res_val)?);
            } else {
                print_transparent_status(&res_val, mode_label);
            }
            Ok(())
        }
        "doctor" => {
            let _ = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx transparent doctor",
                    value_flags: &[],
                    bool_flags: &[],
                    min_pos: 0,
                    max_pos: 0,
                },
            )?;
            let (mode_label, st_val) = if let Some((st, val)) =
                api_request_or_offline(opts, "GET", "/api/transparent/status", None).await?
            {
                ("ONLINE", ensure_api_ok(st, val)?)
            } else {
                let settings = if std::path::Path::new(&opts.config_path).exists() {
                    load_offline_runtime_readonly(&opts.config_path)?.transparent
                } else {
                    TransparentSettings::default()
                };
                ("OFFLINE", serde_json::to_value(probe_status(&settings))?)
            };
            let report = build_transparent_doctor_report(mode_label, &st_val, &opts.config_path);
            let ready = report["ready"].as_bool().unwrap_or(false);
            let running = report["running"].as_bool().unwrap_or(false);
            let elevated = report["elevated"].as_bool().unwrap_or(false);
            let dll_found = report["dll_found"].as_bool().unwrap_or(false);
            let sys_found = report["sys_found"].as_bool().unwrap_or(false);
            let dll_path = report["dll_path"].as_str();
            let sys_path = report["sys_path"].as_str();
            let searched_dirs: Vec<&str> = report["searched_dirs"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            let issues: Vec<&str> = report["issues"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Transparent Proxy Doctor [{}]:", mode_label);
                println!("  Ready:         {}", ready);
                println!("  Running:       {}", running);
                println!("  Elevated:      {}", elevated);
                if let Some(cp) = report["config_path"].as_str() {
                    println!("  Config Path:   {}", cp);
                }
                println!(
                    "  WinDivert DLL: found={} ({})",
                    dll_found,
                    dll_path.unwrap_or("-")
                );
                println!(
                    "  WinDivert SYS: found={} ({})",
                    sys_found,
                    sys_path.unwrap_or("-")
                );
                println!("  Search Dirs:   {:?}", searched_dirs);
                if issues.is_empty() {
                    println!("  Issues:        none");
                } else {
                    println!("  Issues:");
                    for issue in &issues {
                        println!("    - {}", issue);
                    }
                }
            }
            Ok(())
        }
        "elevate" => {
            if opts.offline {
                bail!(
                    "`flowx transparent elevate` requires a running FlowX daemon and cannot be used with --offline"
                );
            }
            let _ = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx transparent elevate",
                    value_flags: &[],
                    bool_flags: &[],
                    min_pos: 0,
                    max_pos: 0,
                },
            )?;
            let (st, val) = api_request_strict_with_io_timeout(
                &opts.api_addr,
                opts.locale,
                "POST",
                "/api/transparent/elevate",
                Some(&json!({})),
                API_ELEVATE_IO_TIMEOUT,
            )
            .await?;
            let res_val = ensure_api_ok(st, val)?;
            if opts.json_output {
                println!("{}", serde_json::to_string_pretty(&res_val)?);
            } else {
                println!(
                    "Elevation accepted (relaunching={}). The elevated daemon will replace this instance cleanly.",
                    res_val["relaunching"].as_bool().unwrap_or(true)
                );
            }
            Ok(())
        }
        other => bail!("Unknown `flowx transparent` subcommand '{}'", other),
    }
}
