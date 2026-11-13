use std::collections::HashMap;
use std::io::Write;
use std::sync::RwLock;
use std::time::Duration;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::api::{
    handle_add_node, handle_add_rule, handle_patch_node, handle_patch_rule,
    handle_set_default_action, handle_simulate_route, ping_address, proxy_node_view,
    AddNodeRequest, AddRuleRequest, PatchNodeRequest, PatchRuleRequest, PingResponse,
    ProxyNodeView, SetDefaultActionRequest, SimulateRouteRequest,
};
use crate::config::ConfigStore;
use crate::i18n::Locale;
use crate::interceptor::dispatcher::ProxyNodeEntry;
use crate::router::{format_action_desc, Action, RuleEngine, RuleView};

const DEFAULT_API_ADDR: &str = "127.0.0.1:40080";
const DEFAULT_SELF_PORTS: [u16; 3] = [40001, 40080, 1053];
const API_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const API_IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchMode {
    Serve { config_path: String },
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
    pub rest: Vec<String>,
}

#[derive(Debug)]
struct ParsedCliInvocation {
    mode: LaunchMode,
    opts: GlobalCliOpts,
}

fn is_subcommand_bool_flag(name: &str) -> bool {
    matches!(name, "enable" | "disable" | "clear-password")
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
    )
}

fn parse_cli_invocation(args: &[String]) -> Result<ParsedCliInvocation> {
    let mut config_path =
        std::env::var("FLOWX_CONFIG").unwrap_or_else(|_| "flowx.xml".to_string());
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
    let mut rest: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        let in_subcommand = !rest.is_empty();

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
            },
            opts: GlobalCliOpts {
                config_path,
                api_addr,
                api_explicit,
                offline,
                json_output,
                show_help,
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
            },
            opts: GlobalCliOpts {
                config_path,
                api_addr,
                api_explicit,
                offline,
                json_output,
                show_help,
                rest,
            },
        });
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

fn normalize_api_addr(raw: &str) -> Result<String> {
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

pub async fn run_cli(args: &[String]) -> Result<()> {
    let opts = parse_global_opts(args)?;
    if opts.show_help {
        print_help();
        return Ok(());
    }
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
  flowx <SUBCOMMAND> [OPTIONS] [--config <flowx.xml>] [--api <127.0.0.1:40080>] [--offline] [--json]

SUBCOMMANDS:
  status
      Show daemon online/offline status, endpoints, node/rule counts, and default fallback action.

  node list
  node add --name <NAME> --addr <HOST:PORT> [--protocol <SOCKS5|HTTP|SOCKS4>] [--user <U>] [--pass <P>]
  node update <ID> [--name <NAME>] [--addr <HOST:PORT>] [--protocol <SOCKS5|HTTP|SOCKS4>] [--user <U>] [--pass <P> | --clear-password]
  node remove <ID>
  node ping <ID>
      Manage proxy nodes (persists to XML automatically; syncs with live daemon when running).

  rule list
  rule add --name <NAME> --action <Direct|Block|Proxy[:NODE_ID]> [--node <NODE_ID>] [--apps <GLOB>] [--targets <HOSTS>] [--ports <PORTS>]
  rule update <ID_OR_INDEX> [--name <NAME>] [--action <Direct|Block|Proxy[:NODE_ID]>] [--node <NODE_ID>] [--apps <GLOB>] [--targets <HOSTS>] [--ports <PORTS>] [--enable | --disable]
  rule toggle <ID_OR_INDEX> [--enable | --disable]
  rule move <ID_OR_INDEX> <up|down|top|bottom>
  rule remove <ID_OR_INDEX>
      Manage top-down routing rules (First-Match Wins; accepts rule ID or 1-based list index).

  default [Direct | Block | Proxy:<NODE_ID>] [--node <NODE_ID>]
      Query or update the fallback default action when no enabled rule matches.

  sim --target <HOST[:PORT]> [--app <PROCESS_NAME_OR_PATH>] [--port <PORT>]
      Dry-run route evaluation and print the matched rule, action, and per-rule skip reasons.

  conn list
  conn kill <ID>
      Inspect or terminate live active connections (requires running FlowX daemon).

GLOBAL FLAGS:
  --config <PATH>   Path to XML configuration file (default: flowx.xml or $FLOWX_CONFIG)
  --api <ADDR>      FlowX HTTP API address (default: 127.0.0.1:40080 or $FLOWX_API; never falls back to XML)
  --offline         Operate directly on the local XML config without connecting to the daemon
  --json            Output machine-readable JSON for AI Agents and automation scripts
",
        env!("CARGO_PKG_VERSION")
    );
}

#[derive(Debug)]
enum ApiTransportError {
    ConnectionRefused(String),
    Other(anyhow::Error),
}

async fn api_request_raw(
    api_addr: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> std::result::Result<(u16, Value), ApiTransportError> {
    api_request_raw_with_timeouts(
        api_addr,
        method,
        path,
        body,
        API_CONNECT_TIMEOUT,
        API_IO_TIMEOUT,
    )
    .await
}

async fn api_request_raw_with_timeouts(
    api_addr: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
    connect_timeout: Duration,
    io_timeout: Duration,
) -> std::result::Result<(u16, Value), ApiTransportError> {
    let mut stream = match tokio::time::timeout(connect_timeout, TcpStream::connect(api_addr)).await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            return Err(ApiTransportError::ConnectionRefused(format!(
                "Connection refused by FlowX API at {}",
                api_addr
            )));
        }
        Ok(Err(e)) => {
            return Err(ApiTransportError::Other(anyhow!(
                "Failed to connect to FlowX API at {}: {}",
                api_addr,
                e
            )));
        }
        Err(_) => {
            return Err(ApiTransportError::Other(anyhow!(
                "Timed out connecting to FlowX API at {} after {}ms",
                api_addr,
                connect_timeout.as_millis()
            )));
        }
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

    let io_res = tokio::time::timeout(io_timeout, async {
        stream.write_all(req.as_bytes()).await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        Ok::<Vec<u8>, std::io::Error>(buf)
    })
    .await;

    let buf = match io_res {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            return Err(ApiTransportError::Other(anyhow!(
                "I/O error communicating with FlowX API at {}: {}",
                api_addr,
                e
            )));
        }
        Err(_) => {
            return Err(ApiTransportError::Other(anyhow!(
                "Timed out waiting for HTTP response from FlowX API at {} after {}ms",
                api_addr,
                io_timeout.as_millis()
            )));
        }
    };

    let Some(header_sep) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err(ApiTransportError::Other(anyhow!(
            "Invalid HTTP response from {} (missing header terminator)",
            api_addr
        )));
    };
    let header_bytes = &buf[..header_sep];
    let body_bytes = &buf[header_sep + 4..];

    let header_str = std::str::from_utf8(header_bytes).map_err(|_| {
        ApiTransportError::Other(anyhow!("Non-UTF-8 HTTP response headers from {}", api_addr))
    })?;
    let mut lines = header_str.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status_rest = status_line
        .strip_prefix("HTTP/1.1 ")
        .or_else(|| status_line.strip_prefix("HTTP/1.0 "))
        .ok_or_else(|| {
            ApiTransportError::Other(anyhow!(
                "Invalid HTTP status line from {}: '{}'",
                api_addr,
                status_line
            ))
        })?;
    let code_token = status_rest.split_whitespace().next().unwrap_or_default();
    if code_token.len() != 3 || !code_token.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ApiTransportError::Other(anyhow!(
            "Invalid HTTP status code from {}: '{}'",
            api_addr,
            status_line
        )));
    }
    let status_code: u16 = code_token.parse().map_err(|_| {
        ApiTransportError::Other(anyhow!(
            "Unparseable HTTP status code from {}: '{}'",
            api_addr,
            code_token
        ))
    })?;

    let mut content_length: Option<usize> = None;
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case("content-length") {
            let trimmed_v = v.trim();
            if trimmed_v.is_empty() || !trimmed_v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ApiTransportError::Other(anyhow!(
                    "Invalid Content-Length header '{}' from {}",
                    trimmed_v,
                    api_addr
                )));
            }
            let parsed = trimmed_v.parse::<usize>().map_err(|_| {
                ApiTransportError::Other(anyhow!(
                    "Invalid Content-Length value '{}' from {}",
                    trimmed_v,
                    api_addr
                ))
            })?;
            if let Some(prev) = content_length
                && prev != parsed
            {
                return Err(ApiTransportError::Other(anyhow!(
                    "Conflicting Content-Length headers from {}",
                    api_addr
                )));
            }
            content_length = Some(parsed);
        }
    }

    if let Some(expected_len) = content_length {
        if body_bytes.len() < expected_len {
            return Err(ApiTransportError::Other(anyhow!(
                "Truncated HTTP response from {} (expected {} bytes, got {})",
                api_addr,
                expected_len,
                body_bytes.len()
            )));
        }
        if body_bytes.len() > expected_len {
            return Err(ApiTransportError::Other(anyhow!(
                "Unexpected trailing bytes in HTTP response from {} (expected {}, got {})",
                api_addr,
                expected_len,
                body_bytes.len()
            )));
        }
    }

    let body_text = std::str::from_utf8(body_bytes).map_err(|_| {
        ApiTransportError::Other(anyhow!("Response body from {} is not valid UTF-8", api_addr))
    })?;
    let json_val = if body_text.trim().is_empty() {
        Value::Null
    } else {
        match serde_json::from_str::<Value>(body_text) {
            Ok(v) => v,
            Err(e) => {
                if (200..300).contains(&status_code) {
                    return Err(ApiTransportError::Other(anyhow!(
                        "Invalid JSON response body from {}: {}",
                        api_addr,
                        e
                    )));
                }
                json!({ "raw": body_text.trim() })
            }
        }
    };

    Ok((status_code, json_val))
}

async fn api_request_strict(
    api_addr: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<(u16, Value)> {
    match api_request_raw(api_addr, method, path, body).await {
        Ok(res) => Ok(res),
        Err(ApiTransportError::ConnectionRefused(msg)) => Err(anyhow!("{}", msg)),
        Err(ApiTransportError::Other(e)) => Err(e),
    }
}

async fn api_request_or_offline(
    opts: &GlobalCliOpts,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<Option<(u16, Value)>> {
    if opts.offline {
        return Ok(None);
    }
    match api_request_raw(&opts.api_addr, method, path, body).await {
        Ok(res) => Ok(Some(res)),
        Err(ApiTransportError::ConnectionRefused(_)) if !opts.api_explicit => Ok(None),
        Err(ApiTransportError::ConnectionRefused(msg)) => {
            bail!(
                "{} (explicit --api / $FLOWX_API target refused connection; pass --offline to edit local XML directly)",
                msg
            );
        }
        Err(ApiTransportError::Other(e)) => Err(e),
    }
}

#[derive(Debug)]
pub struct ApiHttpError {
    pub status: u16,
    pub code: Option<String>,
    pub error: String,
    pub body: Value,
    pub offline: bool,
}

impl ApiHttpError {
    fn from_value(status: u16, val: Value, offline: bool) -> Self {
        let code = val
            .get("code")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let error = val
            .get("error")
            .and_then(|v| v.as_str())
            .or_else(|| val.get("raw").and_then(|v| v.as_str()))
            .unwrap_or("API request failed")
            .to_string();
        Self {
            status,
            code,
            error,
            body: val,
            offline,
        }
    }
}

impl std::fmt::Display for ApiHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.offline {
            write!(f, "{}", self.error)
        } else {
            write!(f, "{} (HTTP {})", self.error, self.status)
        }
    }
}

impl std::error::Error for ApiHttpError {}

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

pub fn format_cli_error_json(err: &anyhow::Error) -> Value {
    if let Some(api_err) = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<ApiHttpError>())
    {
        let mut obj = match api_err.body.as_object() {
            Some(map) => map.clone(),
            None => serde_json::Map::new(),
        };
        obj.insert("ok".to_string(), Value::Bool(false));
        obj.insert(
            "code".to_string(),
            Value::String(
                api_err
                    .code
                    .clone()
                    .unwrap_or_else(|| format!("ERR_HTTP_{}", api_err.status)),
            ),
        );
        obj.insert("error".to_string(), Value::String(api_err.error.clone()));
        obj.insert(
            "status".to_string(),
            Value::Number(serde_json::Number::from(api_err.status)),
        );
        Value::Object(obj)
    } else {
        json!({
            "ok": false,
            "code": "ERR_CLI_ERROR",
            "error": format!("{:#}", err),
        })
    }
}

pub fn emit_cli_error_and_exit(err: &anyhow::Error, json_output: bool) -> ! {
    if json_output {
        let payload = format_cli_error_json(err);
        if let Ok(s) = serde_json::to_string_pretty(&payload) {
            println!("{}", s);
        } else {
            println!(
                "{{\"ok\":false,\"code\":\"ERR_CLI_ERROR\",\"error\":\"Failed to serialize error\"}}"
            );
        }
        let _ = std::io::stdout().flush();
    } else {
        eprintln!("Error: {:?}", err);
        let _ = std::io::stderr().flush();
    }
    std::process::exit(1);
}

fn ensure_api_ok(status: u16, val: Value) -> Result<Value> {
    if (200..300).contains(&status) {
        Ok(val)
    } else {
        Err(anyhow::Error::new(ApiHttpError::from_value(
            status, val, false,
        )))
    }
}

fn ensure_offline_handler_ok(status_line: &str, body: &str) -> Result<Value> {
    let val: Value =
        serde_json::from_str(body).unwrap_or_else(|_| json!({ "raw": body, "error": body }));
    let status = status_line
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(500);
    if (200..300).contains(&status) {
        Ok(val)
    } else {
        Err(anyhow::Error::new(ApiHttpError::from_value(
            status, val, true,
        )))
    }
}

type OfflineRuntime = (
    ConfigStore,
    RwLock<HashMap<u32, ProxyNodeEntry>>,
    RuleEngine,
);

fn load_offline_runtime(config_path: &str) -> Result<OfflineRuntime> {
    let store = ConfigStore::new(config_path);
    let rt = store
        .load_existing_or_default(&DEFAULT_SELF_PORTS)
        .with_context(|| format!("Failed to load configuration file: {}", config_path))?;
    let nodes = RwLock::new(rt.proxy_nodes);
    let engine = RuleEngine::new(rt.rules, rt.default_action);
    Ok((store, nodes, engine))
}

fn load_offline_runtime_readonly(config_path: &str) -> Result<OfflineRuntime> {
    let store = ConfigStore::new(config_path);
    let rt = store
        .load_existing(&DEFAULT_SELF_PORTS)
        .with_context(|| format!("Failed to load configuration file: {}", config_path))?;
    let nodes = RwLock::new(rt.proxy_nodes);
    let engine = RuleEngine::new(rt.rules, rt.default_action);
    Ok((store, nodes, engine))
}

fn resolve_rule_id_from_views(rules: &[RuleView], id_or_index: u64) -> Option<u64> {
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

fn offline_resolve_rule_id(rule_engine: &RuleEngine, id_or_index: u64) -> Option<u64> {
    let views = rule_engine.list_rules_view_with_locale(Locale::Zh);
    resolve_rule_id_from_views(&views, id_or_index)
}

#[derive(Debug, Clone, Copy)]
struct ArgSpec<'a> {
    cmd_label: &'a str,
    value_flags: &'a [&'a str],
    bool_flags: &'a [&'a str],
    min_pos: usize,
    max_pos: usize,
}

fn canonical_flag_group(flag: &str) -> &str {
    match flag {
        "server" | "addr" => "addr",
        "proto" | "protocol" => "protocol",
        "username" | "user" => "user",
        "password" | "pass" => "pass",
        "node-id" | "node" => "node",
        "app" | "apps" | "process" | "proc" => "apps",
        "target" | "targets" | "host" => "targets",
        "port" | "ports" => "ports",
        "dir" | "direction" => "dir",
        other => other,
    }
}

fn parse_flags_with_spec(
    args: &[String],
    spec: ArgSpec<'_>,
) -> Result<(Vec<String>, HashMap<String, String>)> {
    let mut positionals = Vec::new();
    let mut flags = HashMap::new();
    let mut seen_groups: HashMap<String, String> = HashMap::new();

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(stripped) = arg.strip_prefix("--") {
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
        } else if arg.starts_with('-') {
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

fn split_action_spec(raw: &str, explicit_node: Option<u32>) -> Result<(String, Option<u32>)> {
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

fn resolve_id_arg(
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

enum RuleBackend {
    Online {
        rules: Vec<RuleView>,
    },
    Offline {
        store: ConfigStore,
        nodes: RwLock<HashMap<u32, ProxyNodeEntry>>,
        engine: RuleEngine,
    },
}

async fn load_rule_backend(opts: &GlobalCliOpts) -> Result<RuleBackend> {
    if let Some((st, val)) = api_request_or_offline(opts, "GET", "/api/rules", None).await? {
        let rules: Vec<RuleView> = serde_json::from_value(ensure_api_ok(st, val)?)?;
        Ok(RuleBackend::Online { rules })
    } else {
        let (store, nodes, engine) = load_offline_runtime(&opts.config_path)?;
        Ok(RuleBackend::Offline {
            store,
            nodes,
            engine,
        })
    }
}

async fn cmd_status(opts: &GlobalCliOpts) -> Result<()> {
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

    if let Some((status, raw_sys)) = api_request_or_offline(opts, "GET", "/api/system", None).await?
    {
        let sys_val = ensure_api_ok(status, raw_sys)?;
        let (stats_status, raw_stats) =
            api_request_strict(&opts.api_addr, "GET", "/api/stats", None).await?;
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
        }
        return Ok(());
    }

    let (store, nodes, engine) = load_offline_runtime_readonly(&opts.config_path)?;
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
            let list: Vec<ProxyNodeView> =
                if let Some((st, val)) = api_request_or_offline(opts, "GET", "/api/nodes", None).await?
                {
                    let v = ensure_api_ok(st, val)?;
                    serde_json::from_value(v)?
                } else {
                    let (_, nodes, _) = load_offline_runtime_readonly(&opts.config_path)?;
                    let guard = nodes.read().unwrap_or_else(|e| e.into_inner());
                    let mut v: Vec<ProxyNodeView> = guard.values().map(proxy_node_view).collect();
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
                let (store, nodes, engine) = load_offline_runtime(&opts.config_path)?;
                let req: AddNodeRequest = serde_json::from_value(payload)?;
                let (st, _, body) = handle_add_node(req, &nodes, &DEFAULT_SELF_PORTS, Locale::Zh);
                let val = ensure_offline_handler_ok(st, &body)?;
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
            let (pos, flags) = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx node update",
                    value_flags: &[
                        "id", "name", "addr", "server", "protocol", "proto", "user", "username",
                        "pass", "password",
                    ],
                    bool_flags: &["clear-password"],
                    min_pos: 0,
                    max_pos: 1,
                },
            )?;
            let id_str = resolve_id_arg(
                &pos,
                &flags,
                "Missing node <ID> for `flowx node update`",
            )?;
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
            let (username, clear_username) =
                match flags.get("user").or_else(|| flags.get("username")) {
                    Some(u) if u.trim().is_empty() => (None, Some(true)),
                    Some(u) => (Some(u.clone()), None),
                    None => (None, None),
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
                let (store, nodes, engine) = load_offline_runtime(&opts.config_path)?;
                let req: PatchNodeRequest = serde_json::from_value(payload)?;
                let (st, _, body) =
                    handle_patch_node(req, &nodes, &DEFAULT_SELF_PORTS, Locale::Zh);
                let val = ensure_offline_handler_ok(st, &body)?;
                store.save_runtime(&nodes, &engine)?;
                val
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
            let id_str = resolve_id_arg(
                &pos,
                &flags,
                "Missing node <ID> for `flowx node remove`",
            )?;
            let id: u32 = id_str.parse().context("Invalid node ID")?;

            let res_val = if let Some((st, val)) = api_request_or_offline(
                opts,
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
            let (pos, flags) = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx node ping",
                    value_flags: &["id"],
                    bool_flags: &[],
                    min_pos: 0,
                    max_pos: 1,
                },
            )?;
            let id_str =
                resolve_id_arg(&pos, &flags, "Missing node <ID> for `flowx node ping`")?;
            let id: u32 = id_str.parse().context("Invalid node ID")?;

            let res_val = if let Some((st, val)) = api_request_or_offline(
                opts,
                "POST",
                "/api/nodes/ping",
                Some(&json!({ "id": id })),
            )
            .await?
            {
                ensure_api_ok(st, val)?
            } else {
                let (_, nodes, _) = load_offline_runtime_readonly(&opts.config_path)?;
                let addr = {
                    let guard = nodes.read().unwrap_or_else(|e| e.into_inner());
                    guard
                        .get(&id)
                        .map(|n| n.server_addr.clone())
                        .ok_or_else(|| anyhow!("Proxy node #{} not found", id))?
                };
                let (ok, latency_ms, message, detail) =
                    ping_address(&addr, &DEFAULT_SELF_PORTS, Locale::Zh).await;
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

    match sub {
        "list" | "ls" => {
            let _ = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx rule list",
                    value_flags: &[],
                    bool_flags: &[],
                    min_pos: 0,
                    max_pos: 0,
                },
            )?;
            let list: Vec<RuleView> =
                if let Some((st, val)) = api_request_or_offline(opts, "GET", "/api/rules", None).await?
                {
                    serde_json::from_value(ensure_api_ok(st, val)?)?
                } else {
                    let (_, _, engine) = load_offline_runtime_readonly(&opts.config_path)?;
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
                let (store, nodes, engine) = load_offline_runtime(&opts.config_path)?;
                let req: AddRuleRequest = serde_json::from_value(payload)?;
                let (st, _, body) = handle_add_rule(req, &engine, &nodes, Locale::Zh);
                let val = ensure_offline_handler_ok(st, &body)?;
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
            let (pos, flags) = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx rule update",
                    value_flags: &[
                        "id", "name", "action", "node", "node-id", "apps", "app", "targets",
                        "target", "ports", "port",
                    ],
                    bool_flags: &["enable", "disable"],
                    min_pos: 0,
                    max_pos: 1,
                },
            )?;
            let id_str = resolve_id_arg(
                &pos,
                &flags,
                "Missing rule <ID> for `flowx rule update`",
            )?;
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
            let apps = flags.get("apps").or_else(|| flags.get("app")).cloned();
            let targets = flags
                .get("targets")
                .or_else(|| flags.get("target"))
                .cloned();
            let ports = flags.get("ports").or_else(|| flags.get("port")).cloned();

            let (resolved_id, res_val) = match load_rule_backend(opts).await? {
                RuleBackend::Online { rules } => {
                    let resolved_id = resolve_rule_id_from_views(&rules, raw_id)
                        .ok_or_else(|| anyhow!("Routing rule #{} not found", raw_id))?;
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
                        "PATCH",
                        "/api/rules",
                        Some(&payload),
                    )
                    .await?;
                    (resolved_id, ensure_api_ok(st, val)?)
                }
                RuleBackend::Offline {
                    store,
                    nodes,
                    engine,
                } => {
                    let resolved_id = offline_resolve_rule_id(&engine, raw_id)
                        .ok_or_else(|| anyhow!("Routing rule #{} not found", raw_id))?;
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
                    let req: PatchRuleRequest = serde_json::from_value(payload)?;
                    let (st, _, body) = handle_patch_rule(req, &engine, &nodes, Locale::Zh);
                    let val = ensure_offline_handler_ok(st, &body)?;
                    store.save_runtime(&nodes, &engine)?;
                    (resolved_id, val)
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
            let id_str = resolve_id_arg(
                &pos,
                &flags,
                "Missing rule <ID> for `flowx rule toggle`",
            )?;
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
                        .ok_or_else(|| anyhow!("Routing rule #{} not found", raw_id))?;
                    let (st, val) = api_request_strict(
                        &opts.api_addr,
                        "POST",
                        "/api/rules/toggle",
                        Some(&json!({ "id": resolved_id, "enabled": enabled })),
                    )
                    .await?;
                    (resolved_id, ensure_api_ok(st, val)?)
                }
                RuleBackend::Offline {
                    store,
                    nodes,
                    engine,
                } => {
                    let resolved_id = offline_resolve_rule_id(&engine, raw_id)
                        .ok_or_else(|| anyhow!("Routing rule #{} not found", raw_id))?;
                    let next_state = engine
                        .toggle_rule(resolved_id, enabled)
                        .ok_or_else(|| anyhow!("Routing rule #{} not found", raw_id))?;
                    store.save_runtime(&nodes, &engine)?;
                    (
                        resolved_id,
                        json!({ "ok": true, "id": resolved_id, "enabled": next_state }),
                    )
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
            let id_str =
                resolve_id_arg(&pos, &flags, "Missing rule <ID> for `flowx rule move`")?;
            let raw_id: u64 = id_str.parse().context("Invalid rule ID")?;
            let flag_dir = flags.get("dir").or_else(|| flags.get("direction"));
            let direction = match (pos.get(1), flag_dir) {
                (Some(_), Some(_)) => {
                    bail!("Cannot specify both positional <DIRECTION> and --dir/--direction")
                }
                (Some(p), None) => p.clone(),
                (None, Some(f)) => f.clone(),
                (None, None) => bail!("Missing direction <up|down|top|bottom>"),
            };

            let (resolved_id, res_val) = match load_rule_backend(opts).await? {
                RuleBackend::Online { rules } => {
                    let resolved_id = resolve_rule_id_from_views(&rules, raw_id)
                        .ok_or_else(|| anyhow!("Routing rule #{} not found", raw_id))?;
                    let (st, val) = api_request_strict(
                        &opts.api_addr,
                        "POST",
                        "/api/rules/move",
                        Some(&json!({ "id": resolved_id, "direction": direction })),
                    )
                    .await?;
                    (resolved_id, ensure_api_ok(st, val)?)
                }
                RuleBackend::Offline {
                    store,
                    nodes,
                    engine,
                } => {
                    let resolved_id = offline_resolve_rule_id(&engine, raw_id)
                        .ok_or_else(|| anyhow!("Routing rule #{} not found", raw_id))?;
                    let moved = engine
                        .move_rule(resolved_id, &direction)
                        .ok_or_else(|| anyhow!("Invalid move target or direction '{}'", direction))?;
                    if moved {
                        store.save_runtime(&nodes, &engine)?;
                    }
                    (
                        resolved_id,
                        json!({ "ok": true, "id": resolved_id, "moved": moved }),
                    )
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
            let id_str = resolve_id_arg(
                &pos,
                &flags,
                "Missing rule <ID> for `flowx rule remove`",
            )?;
            let raw_id: u64 = id_str.parse().context("Invalid rule ID")?;

            let (resolved_id, res_val) = match load_rule_backend(opts).await? {
                RuleBackend::Online { rules } => {
                    let resolved_id = resolve_rule_id_from_views(&rules, raw_id)
                        .ok_or_else(|| anyhow!("Routing rule #{} not found", raw_id))?;
                    let (st, val) = api_request_strict(
                        &opts.api_addr,
                        "DELETE",
                        &format!("/api/rules?id={}", resolved_id),
                        None,
                    )
                    .await?;
                    (resolved_id, ensure_api_ok(st, val)?)
                }
                RuleBackend::Offline {
                    store,
                    nodes,
                    engine,
                } => {
                    let resolved_id = offline_resolve_rule_id(&engine, raw_id)
                        .ok_or_else(|| anyhow!("Routing rule #{} not found", raw_id))?;
                    if !engine.delete_rule(resolved_id) {
                        bail!("Routing rule #{} not found", raw_id);
                    }
                    store.save_runtime(&nodes, &engine)?;
                    (resolved_id, json!({ "ok": true, "id": resolved_id }))
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

async fn cmd_default(opts: &GlobalCliOpts) -> Result<()> {
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
            let (store, nodes, engine) = load_offline_runtime(&opts.config_path)?;
            let req: SetDefaultActionRequest = serde_json::from_value(payload)?;
            let (st, _, body) = handle_set_default_action(req, &engine, &nodes, Locale::Zh);
            let val = ensure_offline_handler_ok(st, &body)?;
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

    let (_, _, engine) = load_offline_runtime_readonly(&opts.config_path)?;
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
        let (_, _, engine) = load_offline_runtime_readonly(&opts.config_path)?;
        let req: SimulateRouteRequest = serde_json::from_value(payload)?;
        let (st, _, body) = handle_simulate_route(req, &engine, Locale::Zh);
        ensure_offline_handler_ok(st, &body)?
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
            let _ = parse_flags_with_spec(
                tail,
                ArgSpec {
                    cmd_label: "flowx conn list",
                    value_flags: &[],
                    bool_flags: &[],
                    min_pos: 0,
                    max_pos: 0,
                },
            )?;
            let (st, val) =
                api_request_strict(&opts.api_addr, "GET", "/api/connections", None).await?;
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
    use crate::api::ApiServer;
    use crate::monitor::ConnectionManager;
    use crate::outbound::{chain::ProxyNode, socks5::Socks5Client};
    use crate::router::Rule;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::watch;

    #[test]
    fn test_should_run_cli_detection() {
        assert!(!should_run_cli(&["flowx".into()]));
        assert_eq!(
            resolve_launch_mode(&["flowx".into(), "--config".into(), "custom.xml".into()]).unwrap(),
            LaunchMode::Serve {
                config_path: "custom.xml".into()
            }
        );
        assert_eq!(
            resolve_launch_mode(&["flowx".into(), "serve".into(), "--config=custom.xml".into()])
                .unwrap(),
            LaunchMode::Serve {
                config_path: "custom.xml".into()
            }
        );
        assert!(should_run_cli(&["flowx".into(), "status".into()]));
        assert!(should_run_cli(&["flowx".into(), "--help".into()]));
        assert!(should_run_cli(&[
            "flowx".into(),
            "serve".into(),
            "--help".into()
        ]));
        assert!(should_run_cli(&["flowx".into(), "--config".into()]));
        assert!(resolve_launch_mode(&["flowx".into(), "--config".into()]).is_err());
        assert!(should_run_cli(&["flowx".into(), "--json".into(), "serve".into()]));
        assert!(parse_global_opts(&["flowx".into(), "--json".into(), "serve".into()]).is_err());
        assert!(should_run_cli(&["flowx".into(), "--unknown".into()]));
        assert!(parse_global_opts(&["flowx".into(), "--unknown".into()]).is_err());

        // Value matching a global flag name (e.g. `--pass --json`) stays bound to `--pass`
        let opts = parse_global_opts(&[
            "flowx".into(),
            "node".into(),
            "add".into(),
            "--name".into(),
            "N".into(),
            "--addr".into(),
            "10.0.0.1:1080".into(),
            "--pass".into(),
            "--json".into(),
        ])
        .unwrap();
        assert!(!opts.json_output);
        assert!(opts.rest.ends_with(&["--pass".into(), "--json".into()]));
    }

    #[tokio::test]
    async fn test_cli_strict_arg_validation() {
        let mut temp_cfg = std::env::current_dir().unwrap().join("target");
        temp_cfg.push(format!("flowx_cli_unused_{}.xml", std::process::id()));
        let _ = std::fs::remove_file(&temp_cfg);
        let cfg_str = temp_cfg.to_string_lossy().to_string();

        // Unknown typo flag `--targe` must fail
        let err = run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "rule".into(),
            "add".into(),
            "--name".into(),
            "Bad".into(),
            "--action".into(),
            "Direct".into(),
            "--targe".into(),
            "github.com".into(),
        ])
        .await
        .unwrap_err();
        assert!(err.to_string().contains("Unknown option '--targe'"));

        // Extra positional argument on `status` must fail
        assert!(
            run_cli(&[
                "flowx".into(),
                "--offline".into(),
                "status".into(),
                "extra".into()
            ])
            .await
            .is_err()
        );

        // Mutually exclusive `--enable` + `--disable` must fail
        assert!(
            run_cli(&[
                "flowx".into(),
                "--config".into(),
                cfg_str.clone(),
                "--offline".into(),
                "rule".into(),
                "toggle".into(),
                "1".into(),
                "--enable".into(),
                "--disable".into(),
            ])
            .await
            .is_err()
        );

        // Mutually exclusive `--pass` + `--clear-password` must fail
        assert!(
            run_cli(&[
                "flowx".into(),
                "--config".into(),
                cfg_str.clone(),
                "--offline".into(),
                "node".into(),
                "update".into(),
                "101".into(),
                "--pass".into(),
                "secret".into(),
                "--clear-password".into(),
            ])
            .await
            .is_err()
        );

        // Mutually exclusive `--api` + `--offline` must fail
        assert!(
            run_cli(&[
                "flowx".into(),
                "--api".into(),
                "127.0.0.1:40080".into(),
                "--offline".into(),
                "status".into(),
            ])
            .await
            .is_err()
        );

        // `flowx serve --help` prints help and succeeds cleanly
        run_cli(&["flowx".into(), "serve".into(), "--help".into()])
            .await
            .unwrap();

        assert!(!temp_cfg.exists());
    }

    #[tokio::test]
    async fn test_cli_explicit_api_and_timeout_no_offline_fallback() {
        let mut temp_cfg = std::env::current_dir().unwrap().join("target");
        temp_cfg.push(format!("flowx_cli_nofallback_{}.xml", std::process::id()));
        let _ = std::fs::remove_file(&temp_cfg);
        let cfg_str = temp_cfg.to_string_lossy().to_string();

        // Bind then drop ephemeral listener to get a guaranteed refused localhost port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = listener.local_addr().unwrap().to_string();
        drop(listener);

        let err = run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--api".into(),
            closed_addr,
            "node".into(),
            "add".into(),
            "--name".into(),
            "ShouldFail".into(),
            "--addr".into(),
            "10.0.0.1:1080".into(),
        ])
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("refused"), "unexpected error message: {}", msg);
        assert!(
            !temp_cfg.exists(),
            "Explicit --api refusal must not silently create or mutate local XML"
        );

        // Stalled server socket that accepts and sleeps -> timeout error (never silent fallback)
        let stall_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stall_addr = stall_listener.local_addr().unwrap().to_string();
        let _stall_task = tokio::spawn(async move {
            if let Ok((_sock, _)) = stall_listener.accept().await {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
        let timeout_err = api_request_raw_with_timeouts(
            &stall_addr,
            "GET",
            "/api/system",
            None,
            Duration::from_millis(500),
            Duration::from_millis(80),
        )
        .await
        .unwrap_err();
        assert!(matches!(timeout_err, ApiTransportError::Other(_)));

        // Truncated HTTP response (EOF before Content-Length) must fail as Other error
        let trunc_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let trunc_addr = trunc_listener.local_addr().unwrap().to_string();
        let _trunc_task = tokio::spawn(async move {
            if let Ok((mut sock, _)) = trunc_listener.accept().await {
                let mut req_buf = [0u8; 512];
                let _ = sock.read(&mut req_buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n{\"ok\":")
                    .await;
            }
        });
        let trunc_err = run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str,
            "--api".into(),
            trunc_addr,
            "status".into(),
        ])
        .await
        .unwrap_err();
        assert!(trunc_err.to_string().contains("Truncated HTTP response"));
    }

    #[tokio::test]
    async fn test_cli_offline_crud_and_simulate() {
        let mut path = std::env::current_dir().unwrap().join("target");
        path.push(format!("flowx_cli_test_{}.xml", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let cfg_str = path.to_string_lossy().to_string();

        // 1. 添加节点 (显式 `--offline` 离线初始化并写入默认配置 + 新节点 #102，密码刻意命名为 `--json`)
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "node".into(),
            "add".into(),
            "--name".into(),
            "JP-Socks".into(),
            "--addr".into(),
            "10.20.0.1:1080".into(),
            "--protocol".into(),
            "SOCKS5".into(),
            "--user".into(),
            "alice".into(),
            "--pass".into(),
            "--json".into(),
        ])
        .await
        .unwrap();

        // 验证 `--pass --json` 写入了密码而不是被解析为全局 `--json`
        let store = ConfigStore::new(&path);
        let (rt, _) = store.load_or_init(&DEFAULT_SELF_PORTS).unwrap();
        assert_eq!(
            rt.proxy_nodes.get(&102).unwrap().client.auth_credentials().1,
            Some("--json")
        );

        // 1b. 使用 `--clear-password` 清除节点密码
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "--json".into(),
            "node".into(),
            "update".into(),
            "102".into(),
            "--clear-password".into(),
        ])
        .await
        .unwrap();
        let (rt, _) = store.load_or_init(&DEFAULT_SELF_PORTS).unwrap();
        assert_eq!(
            rt.proxy_nodes.get(&102).unwrap().client.auth_credentials().1,
            None
        );

        // 2. 添加规则指向新节点 #102
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
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
            "--offline".into(),
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
            "--offline".into(),
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
        let (rt, _) = store.load_or_init(&DEFAULT_SELF_PORTS).unwrap();
        assert!(rt.proxy_nodes.contains_key(&102));
        assert!(rt.rules.iter().any(|r| r.name == "GitRule"));
        assert_eq!(rt.default_action, Action::Proxy(102));

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_cli_online_patch_and_1based_rule_index() {
        let mut nodes_map = HashMap::new();
        nodes_map.insert(
            101,
            ProxyNodeEntry {
                id: 101,
                name: "MainProxy".into(),
                protocol: "SOCKS5".into(),
                server_addr: "127.0.0.1:10808".into(),
                username: Some("bob".into()),
                client: ProxyNode::Socks5(
                    Socks5Client::new("127.0.0.1:10808")
                        .with_auth("bob".to_string(), "oldpass".to_string()),
                ),
            },
        );
        let proxy_nodes = Arc::new(RwLock::new(nodes_map));
        let r1 = Rule::from_raw_with_id(
            100,
            "RuleOne",
            true,
            None,
            Some("example.com"),
            None,
            Action::Direct,
        );
        let r2 = Rule::from_raw_with_id(
            200,
            "RuleTwo",
            true,
            None,
            Some("github.com"),
            Some("443"),
            Action::Proxy(101),
        );
        let rule_engine = Arc::new(RuleEngine::new(vec![r1, r2], Action::Direct));
        let monitor = Arc::new(ConnectionManager::new());

        let server = ApiServer::new(
            "127.0.0.1:0".parse().unwrap(),
            monitor,
            Arc::clone(&rule_engine),
            Arc::clone(&proxy_nodes),
        );
        let listener = server.bind().await.unwrap();
        let api_addr = listener.local_addr().unwrap().to_string();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let srv_handle = tokio::spawn(async move {
            let _ = server.run(listener, shutdown_rx).await;
        });

        // 1. 在线 PATCH 节点密码，验证 --clear-password 生效
        run_cli(&[
            "flowx".into(),
            "--api".into(),
            api_addr.clone(),
            "--json".into(),
            "node".into(),
            "update".into(),
            "101".into(),
            "--clear-password".into(),
        ])
        .await
        .unwrap();
        assert_eq!(
            proxy_nodes
                .read()
                .unwrap()
                .get(&101)
                .unwrap()
                .client
                .auth_credentials()
                .1,
            None
        );

        // 2. 在线按 1-based 下标 `2` 禁用并更新规则（真实 ID 为 200）
        run_cli(&[
            "flowx".into(),
            "--api".into(),
            api_addr.clone(),
            "rule".into(),
            "toggle".into(),
            "2".into(),
            "--disable".into(),
        ])
        .await
        .unwrap();
        assert!(!rule_engine.current_rules()[1].enabled);

        run_cli(&[
            "flowx".into(),
            "--api".into(),
            api_addr.clone(),
            "rule".into(),
            "update".into(),
            "2".into(),
            "--targets".into(),
            "api.github.com".into(),
            "--enable".into(),
        ])
        .await
        .unwrap();
        let rules_after_update = rule_engine.current_rules();
        assert_eq!(rules_after_update[1].id, 200);
        assert!(rules_after_update[1].enabled);
        assert_eq!(rules_after_update[1].targets_raw, "api.github.com");

        // 3. 在线按 1-based 下标 `2` 上移至顶部，再按下标 `1` 删除
        run_cli(&[
            "flowx".into(),
            "--api".into(),
            api_addr.clone(),
            "rule".into(),
            "move".into(),
            "2".into(),
            "top".into(),
        ])
        .await
        .unwrap();
        assert_eq!(rule_engine.current_rules()[0].id, 200);

        run_cli(&[
            "flowx".into(),
            "--api".into(),
            api_addr.clone(),
            "rule".into(),
            "remove".into(),
            "1".into(),
        ])
        .await
        .unwrap();
        let remaining = rule_engine.current_rules();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, 100);

        let _ = shutdown_tx.send(true);
        let _ = srv_handle.await;
    }

    #[test]
    fn test_cli_normalize_api_addr_and_wants_json_output() {
        assert_eq!(
            normalize_api_addr("127.0.0.1:40080").unwrap(),
            "127.0.0.1:40080"
        );
        assert_eq!(
            normalize_api_addr("HTTP://127.0.0.1:40080/").unwrap(),
            "127.0.0.1:40080"
        );
        assert_eq!(normalize_api_addr("[::1]:40080").unwrap(), "[::1]:40080");
        assert_eq!(
            normalize_api_addr("localhost:40080").unwrap(),
            "localhost:40080"
        );

        for invalid in [
            "",
            "127.0.0.1",
            "127.0.0.1:0",
            "[::1]",
            "[::1]:0",
            "::1:40080",
            "HTTPS://127.0.0.1:40080",
            "ftp://127.0.0.1:40080",
            "--offline",
            "127.0.0.1:40080/api",
            "127.0.0.1:40080?x=1",
            "user@127.0.0.1:40080",
            "localhost:99999",
        ] {
            assert!(
                normalize_api_addr(invalid).is_err(),
                "expected '{}' to be rejected",
                invalid
            );
        }

        assert!(wants_json_output(&[
            "flowx".into(),
            "--json".into(),
            "status".into()
        ]));
        assert!(wants_json_output(&[
            "flowx".into(),
            "--json".into(),
            "--api".into(),
            "127.0.0.1".into(),
            "status".into()
        ]));
        assert!(!wants_json_output(&[
            "flowx".into(),
            "node".into(),
            "add".into(),
            "--pass".into(),
            "--json".into(),
            "--api".into(),
            "127.0.0.1".into()
        ]));
        assert!(!wants_json_output(&[
            "flowx".into(),
            "--api".into(),
            "--json".into(),
            "status".into()
        ]));
    }

    #[tokio::test]
    async fn test_cli_readonly_commands_do_not_create_missing_config() {
        let mut path = std::env::current_dir().unwrap().join("target");
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("flowx_cli_readonly_missing_{}.xml", ts));
        let _ = std::fs::remove_file(&path);
        let cfg_str = path.to_string_lossy().to_string();

        let cmds: &[&[&str]] = &[
            &["status"],
            &["node", "list"],
            &["node", "ping", "1"],
            &["rule", "list"],
            &["default"],
            &["sim", "--app", "git.exe", "--target", "example.com:443"],
        ];

        for sub in cmds {
            let mut argv = vec![
                "flowx".to_string(),
                "--config".to_string(),
                cfg_str.clone(),
                "--offline".to_string(),
            ];
            argv.extend(sub.iter().map(|s| (*s).to_string()));
            let err = run_cli(&argv).await.unwrap_err();
            let err_json = format_cli_error_json(&err);
            assert_eq!(err_json["ok"], Value::Bool(false));
            assert!(
                !path.exists(),
                "read-only command {:?} must not create {}",
                sub,
                cfg_str
            );
        }
    }

    #[tokio::test]
    async fn test_cli_json_errors_and_password_clear_rules() {
        let mut path = std::env::current_dir().unwrap().join("target");
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("flowx_cli_pw_rules_{}.xml", ts));
        let _ = std::fs::remove_file(&path);
        let cfg_str = path.to_string_lossy().to_string();

        // 1. Offline add with password but no username fails with structured ERR_PASSWORD_WITHOUT_USERNAME
        let err = run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "--json".into(),
            "node".into(),
            "add".into(),
            "--name".into(),
            "NoUser".into(),
            "--addr".into(),
            "10.0.0.2:1080".into(),
            "--pass".into(),
            "secret".into(),
        ])
        .await
        .unwrap_err();
        let j = format_cli_error_json(&err);
        assert_eq!(j["ok"], Value::Bool(false));
        assert_eq!(j["code"], "ERR_PASSWORD_WITHOUT_USERNAME");
        assert_eq!(j["status"], 400);

        // 2. Offline add with username + empty password fails with ERR_EMPTY_PASSWORD
        let err = run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "--json".into(),
            "node".into(),
            "add".into(),
            "--name".into(),
            "EmptyPass".into(),
            "--addr".into(),
            "10.0.0.2:1080".into(),
            "--user".into(),
            "alice".into(),
            "--pass".into(),
            "".into(),
        ])
        .await
        .unwrap_err();
        let j = format_cli_error_json(&err);
        assert_eq!(j["code"], "ERR_EMPTY_PASSWORD");
        assert_eq!(j["status"], 400);

        // 3. Offline add HTTP node with colon in username fails with ERR_HTTP_USERNAME_COLON
        let err = run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "node".into(),
            "add".into(),
            "--name".into(),
            "BadHttp".into(),
            "--protocol".into(),
            "HTTP".into(),
            "--addr".into(),
            "10.0.0.2:8080".into(),
            "--user".into(),
            "bad:user".into(),
            "--pass".into(),
            "secret".into(),
        ])
        .await
        .unwrap_err();
        let j = format_cli_error_json(&err);
        assert_eq!(j["code"], "ERR_HTTP_USERNAME_COLON");
        assert!(
            !path.exists(),
            "Failed offline mutations must not create {}",
            cfg_str
        );

        // 3b. Offline add HTTP/SOCKS5 with username but without password fails cleanly and does not create XML
        let err = run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "--json".into(),
            "node".into(),
            "add".into(),
            "--name".into(),
            "UserOnly".into(),
            "--addr".into(),
            "10.0.0.2:1080".into(),
            "--user".into(),
            "alice".into(),
        ])
        .await
        .unwrap_err();
        let j = format_cli_error_json(&err);
        assert_eq!(j["code"], "ERR_USERNAME_WITHOUT_PASSWORD");
        assert!(!path.exists());

        // 3c. Duplicate/conflicting aliases in `flowx sim` fail cleanly
        assert!(
            run_cli(&[
                "flowx".into(),
                "--config".into(),
                cfg_str.clone(),
                "--offline".into(),
                "sim".into(),
                "--target".into(),
                "example.com:443".into(),
                "--host".into(),
                "other.com".into(),
            ])
            .await
            .is_err()
        );
        assert!(
            run_cli(&[
                "flowx".into(),
                "--config".into(),
                cfg_str.clone(),
                "--offline".into(),
                "sim".into(),
                "--target".into(),
                "example.com:443".into(),
                "--app".into(),
                "curl.exe".into(),
                "--process".into(),
                "git.exe".into(),
            ])
            .await
            .is_err()
        );
        assert!(!path.exists());

        // 4. Add valid node then clear password with explicit `--pass ""` (clears username as well on SOCKS5/HTTP)
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "node".into(),
            "add".into(),
            "--name".into(),
            "ValidNode".into(),
            "--addr".into(),
            "10.0.0.2:1080".into(),
            "--user".into(),
            "alice".into(),
            "--pass".into(),
            "secret".into(),
        ])
        .await
        .unwrap();
        assert!(path.exists(), "Successful offline mutation must persist {}", cfg_str);

        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "node".into(),
            "update".into(),
            "102".into(),
            "--pass".into(),
            "".into(),
        ])
        .await
        .unwrap();

        let store = ConfigStore::new(&path);
        let rt = store.load_existing(&DEFAULT_SELF_PORTS).unwrap();
        let node = rt.proxy_nodes.get(&102).unwrap();
        assert_eq!(node.username, None);
        assert_eq!(node.client.auth_credentials(), (None, None));
        assert!(!node.is_auth_configured());

        // 5. Online API HTTP 400 response preserves structured JSON error code/status
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = listener.local_addr().unwrap().to_string();
        let srv = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut req_buf = [0u8; 2048];
                let _ = sock.read(&mut req_buf).await;
                let body = r#"{"ok":false,"code":"ERR_RULE_CONFLICT","error":"Conflict"}"#;
                let resp = format!(
                    "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });

        let api_err = run_cli(&[
            "flowx".into(),
            "--api".into(),
            mock_addr,
            "--json".into(),
            "node".into(),
            "list".into(),
        ])
        .await
        .unwrap_err();
        let _ = srv.await;
        let j = format_cli_error_json(&api_err);
        assert_eq!(j["ok"], Value::Bool(false));
        assert_eq!(j["code"], "ERR_RULE_CONFLICT");
        assert_eq!(j["error"], "Conflict");
        assert_eq!(j["status"], 409);

        let _ = std::fs::remove_file(&path);
    }
}
