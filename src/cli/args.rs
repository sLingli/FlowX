use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};

use crate::i18n::Locale;

pub(super) const DEFAULT_API_ADDR: &str = "127.0.0.1:40080";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchMode {
    Serve {
        config_path: String,
        transparent_override: Option<bool>,
        replace_pid: Option<u32>,
    },
    Cli,
}

#[derive(Debug, Clone)]
pub struct GlobalCliOpts {
    pub config_path: String,
    pub api_addr: String,
    pub api_explicit: bool,
    pub offline: bool,
    pub json_output: bool,
    pub show_help: bool,
    pub locale: Locale,
    pub rest: Vec<String>,
}

#[derive(Debug)]
pub(super) struct ParsedCliInvocation {
    pub(super) mode: LaunchMode,
    pub(super) opts: GlobalCliOpts,
}

fn is_subcommand_bool_flag(name: &str) -> bool {
    matches!(
        name,
        "all"
            | "enable"
            | "disable"
            | "clear-user"
            | "clear-password"
            | "clear-apps"
            | "clear-targets"
            | "clear-ports"
            | "hijack-dns"
            | "no-hijack-dns"
            | "block-quic"
            | "no-block-quic"
            | "clear-dll-path"
    )
}

fn is_known_subcommand_value_flag(name: &str) -> bool {
    matches!(
        name,
        "id" | "name"
            | "addr"
            | "server"
            | "protocol"
            | "proto"
            | "user"
            | "username"
            | "pass"
            | "password"
            | "action"
            | "node"
            | "node-id"
            | "apps"
            | "app"
            | "targets"
            | "target"
            | "host"
            | "ports"
            | "port"
            | "dir"
            | "direction"
            | "process"
            | "proc"
            | "dll-path"
            | "filter"
            | "search"
    )
}

pub(super) fn resolve_config_path_from_env(raw: Option<&str>) -> String {
    raw.map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| "flowx.xml".to_string())
}

pub(super) fn parse_cli_invocation(args: &[String]) -> Result<ParsedCliInvocation> {
    let mut config_path =
        resolve_config_path_from_env(std::env::var("FLOWX_CONFIG").ok().as_deref());
    let locale = Locale::from_env();
    let env_api = std::env::var("FLOWX_API")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let mut api_addr = env_api
        .as_deref()
        .map(normalize_api_addr)
        .transpose()?
        .unwrap_or_else(|| DEFAULT_API_ADDR.to_string());
    let mut api_explicit = env_api.is_some();
    let mut api_cli_flag = false;
    let mut offline = false;
    let mut json_output = false;
    let mut show_help = false;
    let mut transparent_override: Option<bool> = None;
    let mut replace_pid: Option<u32> = None;
    let mut rest: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        let in_subcommand = !rest.is_empty();

        if arg == "--" {
            if in_subcommand {
                rest.extend(args[i..].iter().cloned());
            } else {
                rest.extend(args[i + 1..].iter().cloned());
            }
            break;
        }

        if arg == "--config" {
            i += 1;
            let val = args
                .get(i)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| anyhow!("Missing value for --config"))?;
            config_path = val.clone();
            i += 1;
            continue;
        }
        if let Some(val) = arg.strip_prefix("--config=") {
            if val.is_empty() {
                bail!("Missing value for --config");
            }
            config_path = val.to_string();
            i += 1;
            continue;
        }

        if arg == "--api" {
            i += 1;
            let val = args
                .get(i)
                .ok_or_else(|| anyhow!("Missing value for --api"))?;
            api_addr = normalize_api_addr(val)?;
            api_explicit = true;
            api_cli_flag = true;
            i += 1;
            continue;
        }
        if let Some(val) = arg.strip_prefix("--api=") {
            api_addr = normalize_api_addr(val)?;
            api_explicit = true;
            api_cli_flag = true;
            i += 1;
            continue;
        }

        if arg == "--json" {
            json_output = true;
            i += 1;
            continue;
        }
        if arg == "--offline" {
            offline = true;
            i += 1;
            continue;
        }
        if arg == "--help" || arg == "-h" {
            show_help = true;
            if !in_subcommand {
                rest.push(arg.clone());
            }
            i += 1;
            continue;
        }
        if (arg == "--version" || arg == "-V") && !in_subcommand {
            rest.push(arg.clone());
            i += 1;
            continue;
        }
        if !in_subcommand || rest.first().map(|s| s.as_str()) == Some("serve") {
            if arg == "--transparent" {
                if transparent_override == Some(false) {
                    bail!("Conflicting flags --transparent and --no-transparent");
                }
                transparent_override = Some(true);
                i += 1;
                continue;
            }
            if arg == "--no-transparent" {
                if transparent_override == Some(true) {
                    bail!("Conflicting flags --transparent and --no-transparent");
                }
                transparent_override = Some(false);
                i += 1;
                continue;
            }
            if arg == "--replace-pid" {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| anyhow!("Missing value for --replace-pid"))?;
                let pid: u32 = val
                    .parse()
                    .ok()
                    .filter(|&p| p > 0)
                    .ok_or_else(|| anyhow!("Invalid PID '{}' for --replace-pid", val))?;
                replace_pid = Some(pid);
                i += 1;
                continue;
            }
            if let Some(val) = arg.strip_prefix("--replace-pid=") {
                let pid: u32 = val
                    .parse()
                    .ok()
                    .filter(|&p| p > 0)
                    .ok_or_else(|| anyhow!("Invalid PID '{}' for --replace-pid", val))?;
                replace_pid = Some(pid);
                i += 1;
                continue;
            }
        }

        if let Some(stripped) = arg.strip_prefix("--") {
            if !in_subcommand || rest.first().map(|s| s.as_str()) == Some("serve") {
                bail!("Unknown option '{}'", arg);
            }
            if !stripped.contains('=') && !is_subcommand_bool_flag(stripped) {
                if !is_known_subcommand_value_flag(stripped) {
                    bail!("Unknown option '{}'", arg);
                }
                rest.push(arg.clone());
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| anyhow!("Missing value for option --{}", stripped))?;
                rest.push(val.clone());
                i += 1;
                continue;
            }
            rest.push(arg.clone());
            i += 1;
            continue;
        }

        if arg.starts_with('-') {
            bail!("Unknown option '{}'", arg);
        }

        rest.push(arg.clone());
        i += 1;
    }

    if api_cli_flag && offline {
        bail!("Cannot specify both --api and --offline");
    }

    if let Some(first) = rest.first()
        && first == "serve"
    {
        if show_help {
            return Ok(ParsedCliInvocation {
                mode: LaunchMode::Cli,
                opts: GlobalCliOpts {
                    config_path,
                    api_addr,
                    api_explicit,
                    offline,
                    json_output,
                    show_help: true,
                    locale,
                    rest: vec!["--help".to_string()],
                },
            });
        }
        if json_output {
            bail!("Global flag --json cannot be used with `serve`");
        }
        if api_cli_flag {
            bail!("Global flag --api cannot be used with `serve`");
        }
        if offline {
            bail!("Global flag --offline cannot be used with `serve`");
        }
        if rest.len() > 1 {
            bail!("Unexpected argument '{}' for `serve`", rest[1]);
        }
        return Ok(ParsedCliInvocation {
            mode: LaunchMode::Serve {
                config_path: config_path.clone(),
                transparent_override,
                replace_pid,
            },
            opts: GlobalCliOpts {
                config_path,
                api_addr,
                api_explicit,
                offline,
                json_output,
                show_help,
                locale,
                rest,
            },
        });
    }

    if rest.is_empty() && !show_help {
        if json_output {
            bail!("Global flag --json requires a CLI subcommand");
        }
        if api_cli_flag {
            bail!("Global flag --api requires a CLI subcommand");
        }
        if offline {
            bail!("Global flag --offline requires a CLI subcommand");
        }
        return Ok(ParsedCliInvocation {
            mode: LaunchMode::Serve {
                config_path: config_path.clone(),
                transparent_override,
                replace_pid,
            },
            opts: GlobalCliOpts {
                config_path,
                api_addr,
                api_explicit,
                offline,
                json_output,
                show_help,
                locale,
                rest,
            },
        });
    }

    if !show_help {
        if transparent_override.is_some() {
            bail!(
                "Flag --transparent/--no-transparent can only be used with daemon mode (`flowx [serve]`)"
            );
        }
        if replace_pid.is_some() {
            bail!("Flag --replace-pid can only be used with daemon mode (`flowx [serve]`)");
        }
    }

    Ok(ParsedCliInvocation {
        mode: LaunchMode::Cli,
        opts: GlobalCliOpts {
            config_path,
            api_addr,
            api_explicit,
            offline,
            json_output,
            show_help,
            locale,
            rest,
        },
    })
}

/// 顶层启动路由：无子命令或仅传入 `serve [--config <path>]` 时返回 `Serve`，否则进入 CLI（含参数错误）
pub fn resolve_launch_mode(args: &[String]) -> Result<LaunchMode> {
    parse_cli_invocation(args).map(|p| p.mode)
}

/// 判断命令行参数是否应进入 CLI 子命令模式（含参数解析错误时亦返回 `true` 以便输出 CLI 错误而非静默启动守护进程）
pub fn should_run_cli(args: &[String]) -> bool {
    !matches!(resolve_launch_mode(args), Ok(LaunchMode::Serve { .. }))
}

pub fn parse_global_opts(args: &[String]) -> Result<GlobalCliOpts> {
    parse_cli_invocation(args).map(|p| p.opts)
}

pub(super) fn normalize_api_addr(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("--api value cannot be empty");
    }
    if trimmed.starts_with('-') {
        bail!(
            "Invalid --api address '{}': expected HOST:PORT (got option-like token)",
            raw
        );
    }

    let bytes = trimmed.as_bytes();
    let without_scheme = if bytes.len() >= 8 && bytes[..8].eq_ignore_ascii_case(b"https://") {
        bail!("--api does not support https:// (FlowX local API uses HTTP)");
    } else if bytes.len() >= 7 && bytes[..7].eq_ignore_ascii_case(b"http://") {
        &trimmed[7..]
    } else if trimmed.contains("://") {
        bail!(
            "Invalid --api address '{}': unsupported URL scheme (expected http:// or HOST:PORT)",
            raw
        );
    } else {
        trimmed
    };

    let authority = without_scheme.trim_end_matches('/');
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
        || authority.contains('@')
        || authority.chars().any(char::is_whitespace)
    {
        bail!("Invalid --api address '{}': expected HOST:PORT", raw);
    }

    if let Ok(sock) = authority.parse::<std::net::SocketAddr>() {
        if sock.port() == 0 {
            bail!("Invalid --api address '{}': port cannot be 0", raw);
        }
        return Ok(authority.to_string());
    }

    let (host, port_str) = if let Some(rest) = authority.strip_prefix('[') {
        rest.split_once("]:").ok_or_else(|| {
            anyhow!(
                "Invalid --api address '{}': expected [IPv6]:PORT with non-zero port",
                raw
            )
        })?
    } else {
        let (h, p) = authority.rsplit_once(':').ok_or_else(|| {
            anyhow!(
                "Invalid --api address '{}': missing :PORT (expected HOST:PORT)",
                raw
            )
        })?;
        if h.contains(':') {
            bail!(
                "Invalid --api address '{}': wrap IPv6 addresses in brackets as [HOST]:PORT",
                raw
            );
        }
        (h, p)
    };

    if host.is_empty() || host.contains('[') || host.contains(']') {
        bail!("Invalid --api address '{}': invalid host in HOST:PORT", raw);
    }
    if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
        bail!(
            "Invalid --api address '{}': invalid port '{}'",
            raw,
            port_str
        );
    }
    let port: u16 = port_str.parse().map_err(|_| {
        anyhow!(
            "Invalid --api address '{}': port '{}' out of range",
            raw,
            port_str
        )
    })?;
    if port == 0 {
        bail!("Invalid --api address '{}': port cannot be 0", raw);
    }

    Ok(authority.to_string())
}

pub fn wants_json_output(args: &[String]) -> bool {
    if let Ok(parsed) = parse_cli_invocation(args) {
        return parsed.opts.json_output;
    }
    let mut expect_value = false;
    for arg in args.iter().skip(1) {
        if expect_value {
            expect_value = false;
            continue;
        }
        if arg == "--" {
            break;
        }
        if arg == "--json" {
            return true;
        }
        if matches!(arg.as_str(), "-c" | "--config" | "--api") {
            expect_value = true;
            continue;
        }
        if let Some(flag_name) = arg.strip_prefix("--")
            && !flag_name.contains('=')
            && is_known_subcommand_value_flag(flag_name)
        {
            expect_value = true;
        }
    }
    false
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ArgSpec<'a> {
    pub(super) cmd_label: &'a str,
    pub(super) value_flags: &'a [&'a str],
    pub(super) bool_flags: &'a [&'a str],
    pub(super) min_pos: usize,
    pub(super) max_pos: usize,
}

fn canonical_flag_group(flag: &str) -> &str {
    match flag {
        "server" | "addr" => "addr",
        "proto" | "protocol" => "protocol",
        "username" | "user" | "clear-user" => "user",
        "password" | "pass" | "clear-password" => "pass",
        "node-id" | "node" => "node",
        "app" | "apps" | "process" | "proc" | "clear-apps" => "apps",
        "target" | "targets" | "host" | "clear-targets" => "targets",
        "port" | "ports" | "clear-ports" => "ports",
        "dir" | "direction" => "dir",
        "hijack-dns" | "no-hijack-dns" => "hijack-dns",
        "block-quic" | "no-block-quic" => "block-quic",
        "dll-path" | "clear-dll-path" => "dll-path",
        other => other,
    }
}

pub(super) fn parse_flags_with_spec(
    args: &[String],
    spec: ArgSpec<'_>,
) -> Result<(Vec<String>, HashMap<String, String>)> {
    let mut positionals = Vec::new();
    let mut flags = HashMap::new();
    let mut seen_groups: HashMap<String, String> = HashMap::new();

    let mut after_double_dash = false;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if !after_double_dash && arg == "--" {
            after_double_dash = true;
            i += 1;
            continue;
        }
        if !after_double_dash && let Some(stripped) = arg.strip_prefix("--") {
            let (name, val) = if let Some((k, v)) = stripped.split_once('=') {
                if spec.bool_flags.contains(&k) {
                    bail!("Option '--{}' does not take a value", k);
                }
                if !spec.value_flags.contains(&k) {
                    bail!("Unknown option '--{}' for `{}`", k, spec.cmd_label);
                }
                (k, v.to_string())
            } else if spec.bool_flags.contains(&stripped) {
                (stripped, "true".to_string())
            } else if spec.value_flags.contains(&stripped) {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| anyhow!("Missing value for option --{}", stripped))?;
                (stripped, v.clone())
            } else {
                bail!("Unknown option '--{}' for `{}`", stripped, spec.cmd_label);
            };

            let group = canonical_flag_group(name).to_string();
            if let Some(prev) = seen_groups.insert(group, format!("--{}", name)) {
                bail!(
                    "Duplicate or conflicting option '--{}' (already set via '{}')",
                    name,
                    prev
                );
            }
            flags.insert(name.to_string(), val);
        } else if !after_double_dash && arg.starts_with('-') {
            bail!("Unknown option '{}' for `{}`", arg, spec.cmd_label);
        } else {
            positionals.push(arg.clone());
        }
        i += 1;
    }

    if positionals.len() > spec.max_pos {
        bail!(
            "Unexpected positional argument '{}' for `{}`",
            positionals[spec.max_pos],
            spec.cmd_label
        );
    }
    if positionals.len() < spec.min_pos {
        bail!(
            "Missing required positional argument for `{}` (expected at least {}, got {})",
            spec.cmd_label,
            spec.min_pos,
            positionals.len()
        );
    }

    Ok((positionals, flags))
}

pub(super) fn split_action_spec(
    raw: &str,
    explicit_node: Option<u32>,
) -> Result<(String, Option<u32>)> {
    if let Some((act_part, id_part)) = raw.split_once(':') {
        let parsed_nid = id_part
            .trim()
            .parse::<u32>()
            .with_context(|| format!("Invalid node ID in action '{}'", raw))?;
        if let Some(explicit) = explicit_node
            && explicit != parsed_nid
        {
            bail!(
                "Conflicting node IDs specified in --action '{}' and --node {}",
                raw,
                explicit
            );
        }
        Ok((act_part.trim().to_string(), Some(parsed_nid)))
    } else {
        Ok((raw.trim().to_string(), explicit_node))
    }
}

pub(super) fn resolve_id_arg(
    pos: &[String],
    flags: &HashMap<String, String>,
    missing_msg: &str,
) -> Result<String> {
    match (pos.first(), flags.get("id")) {
        (Some(_), Some(_)) => bail!("Cannot specify both positional <ID> and --id"),
        (Some(p), None) => Ok(p.clone()),
        (None, Some(f)) => Ok(f.clone()),
        (None, None) => bail!("{}", missing_msg),
    }
}

pub fn print_help() {
    println!(
        "\
FlowX v{} — Transparent Proxy & Process Routing Engine CLI

USAGE:
  flowx [serve] [--config <flowx.xml>] [--transparent | --no-transparent]
  flowx <SUBCOMMAND> [OPTIONS] [--config <flowx.xml>] [--api <127.0.0.1:40080>] [--offline] [--json]

SUBCOMMANDS:
  status
      Show daemon online/offline status, endpoints, node/rule counts, and default fallback action.

  transparent status
  transparent enable | disable
  transparent config [--hijack-dns | --no-hijack-dns] [--block-quic | --no-block-quic] [--dll-path <PATH> | --clear-dll-path]
  transparent doctor
  transparent elevate
      Inspect WinDivert driver diagnostics, enable/disable/elevate transparent proxying, or configure DNS/QUIC/DLL options.

  node list
  node add --name <NAME> --addr <HOST:PORT> [--protocol <SOCKS5|HTTP|SOCKS4>] [--user <U>] [--pass <P>]
  node update <ID> [--name <NAME>] [--addr <HOST:PORT>] [--protocol <SOCKS5|HTTP|SOCKS4>] [--user <U> | --clear-user] [--pass <P> | --clear-password]
  node remove <ID>
  node ping <ID> | --all
      Manage and probe proxy nodes (persists to XML automatically; syncs with live daemon when running).

  rule list [--search <TEXT>]
  rule add --name <NAME> --action <Direct|Block|Proxy[:NODE_ID]> [--node <NODE_ID>] [--apps <GLOB>] [--targets <HOSTS>] [--ports <PORTS>]
  rule update <ID_OR_INDEX> [--name <NAME>] [--action <Direct|Block|Proxy[:NODE_ID]>] [--node <NODE_ID>] [--apps <GLOB> | --clear-apps] [--targets <HOSTS> | --clear-targets] [--ports <PORTS> | --clear-ports] [--enable | --disable]
  rule toggle <ID_OR_INDEX> [--enable | --disable]
  rule move <ID_OR_INDEX> <up|down|top|bottom>
  rule remove <ID_OR_INDEX>
      Manage top-down routing rules (First-Match Wins; accepts rule ID or 1-based list index).

  default [Direct | Block | Proxy:<NODE_ID>] [--node <NODE_ID>]
      Query or update the fallback default action when no enabled rule matches.

  sim --target <HOST[:PORT]> [--app <PROCESS_NAME_OR_PATH>] [--port <PORT>]
      Dry-run route evaluation and print the matched rule, action, and per-rule skip reasons.

  conn list [--filter <ALL|PROXY|DIRECT|BLOCK>] [--search <TEXT>]
  conn kill <ID>
      Inspect, filter, or terminate live active connections (requires running FlowX daemon).

GLOBAL FLAGS:
  --config <PATH>   Path to XML configuration file (default: flowx.xml or $FLOWX_CONFIG)
  --api <ADDR>      FlowX HTTP API address (default: 127.0.0.1:40080 or $FLOWX_API; never falls back to XML)
  --offline         Operate directly on the local XML config without connecting to the daemon
  --json            Output machine-readable JSON for AI Agents and automation scripts
",
        env!("CARGO_PKG_VERSION")
    );
}
