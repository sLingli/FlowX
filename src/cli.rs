use std::collections::HashMap;
use std::io::Write;
use std::sync::RwLock;
use std::time::Duration;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::ConfigStore;
use crate::control::node::{add_node, list_nodes, patch_node, ping_address};
use crate::control::routing::{set_default_action, simulate_route};
use crate::control::rule::{add_rule, patch_rule};
use crate::control::{
    AddNodeRequest, AddRuleRequest, ControlError, PatchNodeRequest, PatchRuleRequest, PingResponse,
    ProxyNodeView, SetDefaultActionRequest, SimulateRouteRequest,
};
use crate::i18n::Locale;
use crate::interceptor::dispatcher::ProxyNodeEntry;
use crate::router::{format_action_desc, Action, RuleEngine, RuleView};
use crate::transparent::{probe_status, TransparentSettings};

const DEFAULT_API_ADDR: &str = "127.0.0.1:40080";
const DEFAULT_SELF_PORTS: [u16; 3] = [40001, 40080, 1053];
const API_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const API_IO_TIMEOUT: Duration = Duration::from_secs(5);
const API_ELEVATE_IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CLI_HTTP_HEADER_BYTES: usize = 64 * 1024;
const MAX_CLI_HTTP_BODY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
struct SilentExitError {
    code: i32,
}

impl std::fmt::Display for SilentExitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Command exited with status {}", self.code)
    }
}

impl std::error::Error for SilentExitError {}

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
struct ParsedCliInvocation {
    mode: LaunchMode,
    opts: GlobalCliOpts,
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

fn resolve_config_path_from_env(raw: Option<&str>) -> String {
    raw.map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| "flowx.xml".to_string())
}

fn parse_cli_invocation(args: &[String]) -> Result<ParsedCliInvocation> {
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
            bail!("Flag --transparent/--no-transparent can only be used with daemon mode (`flowx [serve]`)");
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
        "transparent" => cmd_transparent(&opts).await,
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

#[derive(Debug)]
enum ApiTransportError {
    ConnectionRefused(String),
    Other(anyhow::Error),
}

async fn api_request_raw(
    api_addr: &str,
    locale: Locale,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> std::result::Result<(u16, Value), ApiTransportError> {
    api_request_raw_with_timeouts(
        api_addr,
        locale,
        method,
        path,
        body,
        API_CONNECT_TIMEOUT,
        API_IO_TIMEOUT,
    )
    .await
}

struct ResponseCursor<'a> {
    stream: &'a mut TcpStream,
    buf: Vec<u8>,
    pos: usize,
}

impl<'a> ResponseCursor<'a> {
    fn new(stream: &'a mut TcpStream) -> Self {
        Self {
            stream,
            buf: Vec::new(),
            pos: 0,
        }
    }

    fn unread(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn compact_if_needed(&mut self) {
        if self.pos >= 4096 || (self.pos > 0 && self.pos == self.buf.len()) {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    async fn read_headers(&mut self, max_header: usize, api_addr: &str) -> Result<Vec<u8>> {
        let mut tmp = [0u8; 4096];
        let mut scanned_len = 0usize;
        loop {
            if let Some(end) = crate::outbound::find_http_header_end(&self.buf, scanned_len) {
                if end > max_header {
                    bail!(
                        "HTTP response headers from {} exceed {} bytes limit",
                        api_addr,
                        max_header
                    );
                }
                self.pos = end;
                return Ok(self.buf[..end - 4].to_vec());
            }
            scanned_len = self.buf.len();
            if self.buf.len() >= max_header {
                bail!(
                    "HTTP response headers from {} exceed {} bytes limit",
                    api_addr,
                    max_header
                );
            }
            let max_add = (max_header - self.buf.len()).min(tmp.len());
            let n = self.stream.read(&mut tmp[..max_add]).await?;
            if n == 0 {
                bail!(
                    "Invalid HTTP response from {} (missing header terminator)",
                    api_addr
                );
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
    }

    async fn read_line_crlf(&mut self, max_line: usize, api_addr: &str) -> Result<String> {
        let mut tmp = [0u8; 1024];
        loop {
            let unread = self.unread();
            if let Some(rel) = unread.windows(2).position(|w| w == b"\r\n") {
                if rel > max_line {
                    bail!(
                        "HTTP response line from {} exceeds {} bytes",
                        api_addr,
                        max_line
                    );
                }
                let line_bytes = unread[..rel].to_vec();
                self.pos += rel + 2;
                self.compact_if_needed();
                return String::from_utf8(line_bytes).map_err(|_| {
                    anyhow!(
                        "Non-UTF-8 chunk/trailer line in HTTP response from {}",
                        api_addr
                    )
                });
            }
            if unread.len() > max_line + 2 {
                bail!(
                    "HTTP response line from {} exceeds {} bytes",
                    api_addr,
                    max_line
                );
            }
            self.compact_if_needed();
            let remain_cap = ((max_line + 2) - self.unread().len()).min(tmp.len());
            let n = self.stream.read(&mut tmp[..remain_cap]).await?;
            if n == 0 {
                bail!(
                    "Unexpected EOF while reading chunked framing from {}",
                    api_addr
                );
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
    }

    async fn read_exact_into(
        &mut self,
        out: &mut Vec<u8>,
        expected_len: usize,
        api_addr: &str,
    ) -> Result<()> {
        let mut rem = expected_len;
        let mut tmp = [0u8; 8192];
        while rem > 0 {
            let unread = self.unread();
            if !unread.is_empty() {
                let take = rem.min(unread.len());
                out.extend_from_slice(&unread[..take]);
                self.pos += take;
                self.compact_if_needed();
                rem -= take;
                continue;
            }
            self.buf.clear();
            self.pos = 0;
            let to_read = rem.min(tmp.len());
            let n = self.stream.read(&mut tmp[..to_read]).await?;
            if n == 0 {
                bail!(
                    "Truncated HTTP response from {} (expected {} bytes, got {})",
                    api_addr,
                    expected_len,
                    expected_len - rem
                );
            }
            out.extend_from_slice(&tmp[..n]);
            rem -= n;
        }
        Ok(())
    }

    async fn read_to_eof_bounded(&mut self, max_body: usize, api_addr: &str) -> Result<Vec<u8>> {
        let unread_len = self.unread().len();
        if unread_len > max_body {
            bail!(
                "HTTP response body from {} exceeds {} bytes limit",
                api_addr,
                max_body
            );
        }
        let mut body = Vec::with_capacity(unread_len);
        body.extend_from_slice(self.unread());
        self.buf.clear();
        self.pos = 0;

        let mut tmp = [0u8; 8192];
        loop {
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            if body.len().saturating_add(n) > max_body {
                bail!(
                    "HTTP response body from {} exceeds {} bytes limit",
                    api_addr,
                    max_body
                );
            }
            body.extend_from_slice(&tmp[..n]);
        }
        Ok(body)
    }

    async fn read_chunked_bounded(
        &mut self,
        max_header: usize,
        max_body: usize,
        api_addr: &str,
    ) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        loop {
            let size_line = self.read_line_crlf(4096, api_addr).await?;
            let size_part = size_line
                .split(';')
                .next()
                .unwrap_or("")
                .trim_matches(|c| c == ' ' || c == '\t');
            if size_part.is_empty()
                || size_part.len() > 16
                || !size_part.bytes().all(|b| b.is_ascii_hexdigit())
            {
                bail!("Invalid HTTP chunk size '{}' from {}", size_line, api_addr);
            }
            let chunk_size = usize::from_str_radix(size_part, 16).map_err(|_| {
                anyhow!(
                    "Overflow parsing HTTP chunk size '{}' from {}",
                    size_part,
                    api_addr
                )
            })?;
            if chunk_size == 0 {
                let mut trailer_bytes = 0usize;
                loop {
                    let trailer = self.read_line_crlf(4096, api_addr).await?;
                    if trailer.is_empty() {
                        break;
                    }
                    trailer_bytes = trailer_bytes.saturating_add(trailer.len() + 2);
                    if trailer_bytes > max_header {
                        bail!(
                            "HTTP chunked trailers from {} exceed {} bytes limit",
                            api_addr,
                            max_header
                        );
                    }
                }
                break;
            }
            if chunk_size > max_body.saturating_sub(body.len()) {
                bail!(
                    "Chunked HTTP response body from {} exceeds {} bytes limit",
                    api_addr,
                    max_body
                );
            }
            self.read_exact_into(&mut body, chunk_size, api_addr).await?;
            let mut crlf = Vec::with_capacity(2);
            self.read_exact_into(&mut crlf, 2, api_addr).await?;
            if crlf != b"\r\n" {
                bail!("Invalid HTTP chunk terminator from {}", api_addr);
            }
        }
        Ok(body)
    }
}

async fn api_request_raw_with_timeouts(
    api_addr: &str,
    locale: Locale,
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

    let accept_lang = locale.accept_language_header();
    let body_str = body.map(|b| b.to_string()).unwrap_or_default();
    let req = if body.is_some() {
        format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nAccept-Language: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            method,
            path,
            api_addr,
            accept_lang,
            body_str.len(),
            body_str
        )
    } else {
        format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nAccept-Language: {}\r\nConnection: close\r\n\r\n",
            method, path, api_addr, accept_lang
        )
    };

    let io_res = tokio::time::timeout(io_timeout, async {
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(anyhow::Error::from)?;
        let mut cursor = ResponseCursor::new(&mut stream);
        let header_bytes = cursor
            .read_headers(MAX_CLI_HTTP_HEADER_BYTES, api_addr)
            .await?;

        let header_str = std::str::from_utf8(&header_bytes)
            .map_err(|_| anyhow!("Non-UTF-8 HTTP response headers from {}", api_addr))?;
        let mut lines = header_str.split("\r\n");
        let status_line = lines.next().unwrap_or_default();
        let status_rest = status_line
            .strip_prefix("HTTP/1.1 ")
            .or_else(|| status_line.strip_prefix("HTTP/1.0 "))
            .ok_or_else(|| {
                anyhow!(
                    "Invalid HTTP status line from {}: '{}'",
                    api_addr,
                    status_line
                )
            })?;
        let code_token = status_rest.split_whitespace().next().unwrap_or_default();
        if code_token.len() != 3 || !code_token.bytes().all(|b| b.is_ascii_digit()) {
            bail!(
                "Invalid HTTP status code from {}: '{}'",
                api_addr,
                status_line
            );
        }
        let status_code: u16 = code_token.parse().map_err(|_| {
            anyhow!(
                "Unparseable HTTP status code from {}: '{}'",
                api_addr,
                code_token
            )
        })?;

        let mut content_length: Option<usize> = None;
        let mut transfer_codings: Vec<String> = Vec::new();
        for line in lines {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let key = k.trim();
            if key.eq_ignore_ascii_case("content-length") {
                let trimmed_v = v.trim();
                if trimmed_v.is_empty() || !trimmed_v.bytes().all(|b| b.is_ascii_digit()) {
                    bail!("Invalid Content-Length header '{}' from {}", trimmed_v, api_addr);
                }
                let parsed = trimmed_v.parse::<usize>().map_err(|_| {
                    anyhow!(
                        "Invalid Content-Length value '{}' from {}",
                        trimmed_v,
                        api_addr
                    )
                })?;
                if parsed > MAX_CLI_HTTP_BODY_BYTES {
                    bail!(
                        "HTTP response Content-Length ({}) from {} exceeds {} bytes limit",
                        parsed,
                        api_addr,
                        MAX_CLI_HTTP_BODY_BYTES
                    );
                }
                if let Some(prev) = content_length
                    && prev != parsed
                {
                    bail!("Conflicting Content-Length headers from {}", api_addr);
                }
                content_length = Some(parsed);
            } else if key.eq_ignore_ascii_case("transfer-encoding") {
                for token in v.split(',') {
                    let coding = token.trim().to_ascii_lowercase();
                    if !coding.is_empty() {
                        transfer_codings.push(coding);
                    }
                }
            }
        }

        let transfer_chunked = if transfer_codings.is_empty() {
            false
        } else if transfer_codings.len() == 1 && transfer_codings[0] == "chunked" {
            true
        } else {
            bail!(
                "Unsupported Transfer-Encoding '{:?}' from {}",
                transfer_codings,
                api_addr
            );
        };

        if content_length.is_some() && transfer_chunked {
            bail!(
                "HTTP response from {} contains conflicting Content-Length and Transfer-Encoding headers",
                api_addr
            );
        }

        let body_bytes = if transfer_chunked {
            cursor
                .read_chunked_bounded(MAX_CLI_HTTP_HEADER_BYTES, MAX_CLI_HTTP_BODY_BYTES, api_addr)
                .await?
        } else if let Some(expected_len) = content_length {
            let mut out = Vec::with_capacity(expected_len);
            cursor
                .read_exact_into(&mut out, expected_len, api_addr)
                .await?;
            if !cursor.unread().is_empty() {
                bail!(
                    "Unexpected trailing bytes in HTTP response from {} (expected {} bytes)",
                    api_addr,
                    expected_len
                );
            }
            out
        } else {
            cursor
                .read_to_eof_bounded(MAX_CLI_HTTP_BODY_BYTES, api_addr)
                .await?
        };

        Ok::<(u16, Vec<u8>), anyhow::Error>((status_code, body_bytes))
    })
    .await;

    let (status_code, body_bytes) = match io_res {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => return Err(ApiTransportError::Other(e)),
        Err(_) => {
            return Err(ApiTransportError::Other(anyhow!(
                "Timed out waiting for HTTP response from FlowX API at {} after {}ms",
                api_addr,
                io_timeout.as_millis()
            )));
        }
    };

    let body_text = std::str::from_utf8(&body_bytes).map_err(|_| {
        ApiTransportError::Other(anyhow!("Response body from {} is not valid UTF-8", api_addr))
    })?;
    let json_val = if body_text.trim().is_empty() {
        if (200..300).contains(&status_code) {
            return Err(ApiTransportError::Other(anyhow!(
                "Empty HTTP {} JSON response body from {}",
                status_code,
                api_addr
            )));
        }
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

async fn api_request_strict_with_io_timeout(
    api_addr: &str,
    locale: Locale,
    method: &str,
    path: &str,
    body: Option<&Value>,
    io_timeout: Duration,
) -> Result<(u16, Value)> {
    match api_request_raw_with_timeouts(
        api_addr,
        locale,
        method,
        path,
        body,
        API_CONNECT_TIMEOUT,
        io_timeout,
    )
    .await
    {
        Ok(res) => Ok(res),
        Err(ApiTransportError::ConnectionRefused(msg)) => Err(anyhow!("{}", msg)),
        Err(ApiTransportError::Other(e)) => Err(e),
    }
}

async fn api_request_strict(
    api_addr: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<(u16, Value)> {
    api_request_strict_with_io_timeout(
        api_addr,
        Locale::from_env(),
        method,
        path,
        body,
        API_IO_TIMEOUT,
    )
    .await
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
    match api_request_raw(&opts.api_addr, opts.locale, method, path, body).await {
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
    if let Some(silent) = err.downcast_ref::<SilentExitError>() {
        std::process::exit(silent.code);
    }
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

fn control_err_to_cli(err: ControlError, locale: Locale) -> anyhow::Error {
    anyhow::Error::new(ApiHttpError::from_value(
        err.kind.status_code(),
        err.to_localized_value(locale),
        true,
    ))
}

struct OfflineRuntime {
    store: ConfigStore,
    nodes: RwLock<HashMap<u32, ProxyNodeEntry>>,
    engine: RuleEngine,
    transparent: TransparentSettings,
}

impl OfflineRuntime {
    fn save(&self) -> Result<()> {
        self.store
            .save_runtime_with_transparent(&self.nodes, &self.engine, Some(&self.transparent))
    }
}

fn load_offline_runtime(config_path: &str) -> Result<OfflineRuntime> {
    let store = ConfigStore::new(config_path);
    let rt = store
        .load_existing_or_default(&DEFAULT_SELF_PORTS)
        .with_context(|| format!("Failed to load configuration file: {}", config_path))?;
    Ok(OfflineRuntime {
        store,
        nodes: RwLock::new(rt.proxy_nodes),
        engine: RuleEngine::new(rt.rules, rt.default_action),
        transparent: rt.transparent_settings,
    })
}

fn load_offline_runtime_readonly(config_path: &str) -> Result<OfflineRuntime> {
    let store = ConfigStore::new(config_path);
    let rt = store
        .load_existing(&DEFAULT_SELF_PORTS)
        .with_context(|| format!("Failed to load configuration file: {}", config_path))?;
    Ok(OfflineRuntime {
        store,
        nodes: RwLock::new(rt.proxy_nodes),
        engine: RuleEngine::new(rt.rules, rt.default_action),
        transparent: rt.transparent_settings,
    })
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

fn offline_resolve_rule_id(
    rule_engine: &RuleEngine,
    id_or_index: u64,
    locale: Locale,
) -> Option<u64> {
    let views = rule_engine.list_rules_view_with_locale(locale);
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

fn parse_flags_with_spec(
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
    Online { rules: Vec<RuleView> },
    Offline(OfflineRuntime),
}

async fn load_rule_backend(opts: &GlobalCliOpts) -> Result<RuleBackend> {
    if let Some((st, val)) = api_request_or_offline(opts, "GET", "/api/rules", None).await? {
        let rules: Vec<RuleView> = serde_json::from_value(ensure_api_ok(st, val)?)?;
        Ok(RuleBackend::Online { rules })
    } else {
        Ok(RuleBackend::Offline(load_offline_runtime(&opts.config_path)?))
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

fn build_transparent_doctor_report(
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

async fn cmd_transparent(opts: &GlobalCliOpts) -> Result<()> {
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
                ("OFFLINE", serde_json::to_value(probe_status(&rt.transparent))?)
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
                let mut rt = load_offline_runtime(&opts.config_path)?;
                rt.transparent.enabled = target_enabled;
                rt.save()?;
                ("OFFLINE", serde_json::to_value(probe_status(&rt.transparent))?)
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
            if let Some(ref raw_path) = dll_path
                && !crate::transparent::is_valid_custom_dll_path_input(raw_path)
            {
                let msg = crate::i18n::t(opts.locale, "error.transparent_invalid_dll_path");
                return Err(anyhow::Error::new(ApiHttpError::from_value(
                    400,
                    json!({
                        "code": "ERR_TRANSPARENT_INVALID_DLL_PATH",
                        "error": msg,
                    }),
                    true,
                )));
            }

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
                let mut rt = load_offline_runtime(&opts.config_path)?;
                if let Some(v) = hijack_dns {
                    rt.transparent.hijack_dns = v;
                }
                if let Some(v) = block_quic {
                    rt.transparent.block_quic_for_proxied = v;
                }
                if clear_dll_path {
                    rt.transparent.dll_path = None;
                } else if let Some(raw_p) = dll_path {
                    let trimmed = raw_p.trim();
                    rt.transparent.dll_path = if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    };
                }
                rt.save()?;
                ("OFFLINE", serde_json::to_value(probe_status(&rt.transparent))?)
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
                    let rt = load_offline_runtime_readonly(&opts.config_path)?;
                    list_nodes(&rt.nodes)
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
                let rt = load_offline_runtime(&opts.config_path)?;
                let rules = rt.engine.current_rules();
                let current_default = rt.engine.default_action();
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
                let removed = rt
                    .nodes
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&id)
                    .is_some();
                if !removed {
                    bail!("Proxy node #{} not found", id);
                }
                rt.save()?;
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
            let id_str =
                resolve_id_arg(&pos, &flags, "Missing node <ID> or --all for `flowx node ping`")?;
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
                let rt = load_offline_runtime_readonly(&opts.config_path)?;
                let addr = {
                    let guard = rt.nodes.read().unwrap_or_else(|e| e.into_inner());
                    guard
                        .get(&id)
                        .map(|n| n.server_addr.clone())
                        .ok_or_else(|| anyhow!("Proxy node #{} not found", id))?
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

async fn cmd_rule(opts: &GlobalCliOpts) -> Result<()> {
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
            let list: Vec<RuleView> =
                if let Some((st, val)) = api_request_or_offline(opts, "GET", "/api/rules", None).await?
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
                let rt = load_offline_runtime(&opts.config_path)?;
                let req: AddRuleRequest = serde_json::from_value(payload)?;
                let new_id = add_rule(req, &rt.engine, &rt.nodes)
                    .map_err(|e| control_err_to_cli(e, opts.locale))?;
                rt.save()?;
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
                RuleBackend::Offline(rt) => {
                    let resolved_id = offline_resolve_rule_id(&rt.engine, raw_id, opts.locale)
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
                    let updated_id = patch_rule(req, &rt.engine, &rt.nodes)
                        .map_err(|e| control_err_to_cli(e, opts.locale))?;
                    rt.save()?;
                    (resolved_id, json!({ "ok": true, "id": updated_id }))
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
                RuleBackend::Offline(rt) => {
                    let resolved_id = offline_resolve_rule_id(&rt.engine, raw_id, opts.locale)
                        .ok_or_else(|| anyhow!("Routing rule #{} not found", raw_id))?;
                    let next_state = rt
                        .engine
                        .toggle_rule(resolved_id, enabled)
                        .ok_or_else(|| anyhow!("Routing rule #{} not found", raw_id))?;
                    rt.save()?;
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
                RuleBackend::Offline(rt) => {
                    let resolved_id = offline_resolve_rule_id(&rt.engine, raw_id, opts.locale)
                        .ok_or_else(|| anyhow!("Routing rule #{} not found", raw_id))?;
                    let moved = rt
                        .engine
                        .move_rule(resolved_id, &direction)
                        .ok_or_else(|| anyhow!("Invalid move target or direction '{}'", direction))?;
                    if moved {
                        rt.save()?;
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
                RuleBackend::Offline(rt) => {
                    let resolved_id = offline_resolve_rule_id(&rt.engine, raw_id, opts.locale)
                        .ok_or_else(|| anyhow!("Routing rule #{} not found", raw_id))?;
                    if !rt.engine.delete_rule(resolved_id) {
                        bail!("Routing rule #{} not found", raw_id);
                    }
                    rt.save()?;
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
            let rt = load_offline_runtime(&opts.config_path)?;
            let req: SetDefaultActionRequest = serde_json::from_value(payload)?;
            let resp = set_default_action(req, &rt.engine, &rt.nodes, opts.locale)
                .map_err(|e| control_err_to_cli(e, opts.locale))?;
            rt.save()?;
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

fn conn_matches_filter(conn: &Value, action_filter: &str, search_lower: Option<&str>) -> bool {
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
                config_path: "custom.xml".into(),
                transparent_override: None,
                replace_pid: None,
            }
        );
        assert_eq!(
            resolve_launch_mode(&["flowx".into(), "serve".into(), "--config=custom.xml".into()])
                .unwrap(),
            LaunchMode::Serve {
                config_path: "custom.xml".into(),
                transparent_override: None,
                replace_pid: None,
            }
        );
        assert_eq!(
            resolve_launch_mode(&[
                "flowx".into(),
                "--transparent".into(),
                "--replace-pid".into(),
                "4321".into(),
            ])
            .unwrap(),
            LaunchMode::Serve {
                config_path: resolve_config_path_from_env(std::env::var("FLOWX_CONFIG").ok().as_deref()),
                transparent_override: Some(true),
                replace_pid: Some(4321),
            }
        );
        assert_eq!(
            resolve_launch_mode(&[
                "flowx".into(),
                "serve".into(),
                "--no-transparent".into(),
                "--replace-pid=777".into(),
            ])
            .unwrap(),
            LaunchMode::Serve {
                config_path: resolve_config_path_from_env(std::env::var("FLOWX_CONFIG").ok().as_deref()),
                transparent_override: Some(false),
                replace_pid: Some(777),
            }
        );
        assert!(resolve_launch_mode(&[
            "flowx".into(),
            "--transparent".into(),
            "--no-transparent".into(),
        ])
        .is_err());
        assert!(resolve_launch_mode(&[
            "flowx".into(),
            "--replace-pid".into(),
            "0".into(),
        ])
        .is_err());
        assert!(parse_global_opts(&["flowx".into(), "--transparent".into(), "status".into()]).is_err());
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
            Locale::En,
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

    #[tokio::test]
    async fn test_cli_double_dash_empty_config_env_chunked_and_exit_status() {
        // 1. FLOWX_CONFIG empty/whitespace normalization
        assert_eq!(resolve_config_path_from_env(None), "flowx.xml");
        assert_eq!(resolve_config_path_from_env(Some("")), "flowx.xml");
        assert_eq!(resolve_config_path_from_env(Some("   ")), "flowx.xml");
        assert_eq!(
            resolve_config_path_from_env(Some("  custom.xml  ")),
            "custom.xml"
        );

        // 2. `--` end-of-options in both parse_cli_invocation and parse_flags_with_spec
        let inv = parse_cli_invocation(&[
            "flowx".into(),
            "--offline".into(),
            "--".into(),
            "node".into(),
            "list".into(),
        ])
        .unwrap();
        assert!(inv.opts.offline);
        assert_eq!(inv.opts.rest, vec!["node", "list"]);

        let (pos, flags) = parse_flags_with_spec(
            &[
                "--name".into(),
                "R1".into(),
                "--".into(),
                "-literal".into(),
            ],
            ArgSpec {
                cmd_label: "flowx test",
                value_flags: &["name"],
                bool_flags: &[],
                min_pos: 1,
                max_pos: 1,
            },
        )
        .unwrap();
        assert_eq!(flags.get("name").map(String::as_str), Some("R1"));
        assert_eq!(pos, vec!["-literal"]);

        let inv_bad_node = run_cli(&[
            "flowx".into(),
            "--offline".into(),
            "node".into(),
            "update".into(),
            "--".into(),
            "-123".into(),
        ])
        .await
        .unwrap_err();
        assert!(inv_bad_node.to_string().contains("Invalid node ID"));

        // 3. HTTP client chunked decoding + Accept-Language header from locale
        let listener_chunked = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_chunked = listener_chunked.local_addr().unwrap().to_string();
        let srv_chunked = tokio::spawn(async move {
            let (mut sock, _) = listener_chunked.accept().await.unwrap();
            let mut req_buf = [0u8; 2048];
            let n = sock.read(&mut req_buf).await.unwrap();
            let req_text = String::from_utf8_lossy(&req_buf[..n]).into_owned();
            let resp = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: application/json\r\n",
                "Transfer-Encoding: chunked\r\n\r\n",
                "8;ext=1\r\n{\"ok\":tr\r\n",
                "3\r\nue}\r\n",
                "0\r\nX-Trailer: done\r\n\r\n"
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            req_text
        });
        let (st, val) = api_request_raw_with_timeouts(
            &addr_chunked,
            Locale::En,
            "GET",
            "/api/system",
            None,
            API_CONNECT_TIMEOUT,
            API_IO_TIMEOUT,
        )
        .await
        .unwrap();
        assert_eq!(st, 200);
        assert_eq!(val["ok"], Value::Bool(true));
        let sent_req = srv_chunked.await.unwrap();
        assert!(sent_req.contains("Accept-Language: en-US\r\n"));

        // 4. CL+TE conflict, empty 200 OK body, and >16 MiB Content-Length rejection
        for mock_resp in [
            "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n",
        ] {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap().to_string();
            let raw_resp = mock_resp.to_string();
            tokio::spawn(async move {
                if let Ok((mut sock, _)) = l.accept().await {
                    let mut req_buf = [0u8; 512];
                    let _ = sock.read(&mut req_buf).await;
                    let _ = sock.write_all(raw_resp.as_bytes()).await;
                }
            });
            let err = api_request_raw_with_timeouts(
                &a,
                Locale::Zh,
                "GET",
                "/api/system",
                None,
                API_CONNECT_TIMEOUT,
                API_IO_TIMEOUT,
            )
            .await
            .unwrap_err();
            assert!(matches!(err, ApiTransportError::Other(_)));
        }

        // 5. `node ping` unreachable & `conn kill` killed=false trigger non-zero SilentExitError
        let ping_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ping_addr = ping_listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = ping_listener.accept().await {
                let mut req_buf = [0u8; 1024];
                let _ = sock.read(&mut req_buf).await;
                let body = r#"{"ok":false,"latency_ms":null,"message":"unreachable"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        let ping_err = run_cli(&[
            "flowx".into(),
            "--api".into(),
            ping_addr,
            "--json".into(),
            "node".into(),
            "ping".into(),
            "101".into(),
        ])
        .await
        .unwrap_err();
        assert!(ping_err.downcast_ref::<SilentExitError>().is_some());

        let kill_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let kill_addr = kill_listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = kill_listener.accept().await {
                let mut req_buf = [0u8; 1024];
                let _ = sock.read(&mut req_buf).await;
                let body = r#"{"ok":true,"id":42,"killed":false}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        let kill_err = run_cli(&[
            "flowx".into(),
            "--api".into(),
            kill_addr,
            "--json".into(),
            "conn".into(),
            "kill".into(),
            "42".into(),
        ])
        .await
        .unwrap_err();
        assert!(kill_err.downcast_ref::<SilentExitError>().is_some());
    }

    #[tokio::test]
    async fn test_cli_transparent_commands_and_config_preservation() {
        let cfg_path = std::env::current_dir().unwrap().join("target").join(format!(
            "flowx_cli_transparent_test_{}_{}.xml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&cfg_path);
        let cfg_str = cfg_path.to_string_lossy().to_string();

        // 1. Readonly status must not create missing config file; doctor works cleanly without one
        assert!(run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "transparent".into(),
            "status".into(),
        ])
        .await
        .is_err());
        assert!(!cfg_path.exists());

        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--json".into(),
            "transparent".into(),
            "doctor".into(),
        ])
        .await
        .unwrap();
        assert!(!cfg_path.exists());

        // 2. Conflicting options fail fast
        assert!(run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "transparent".into(),
            "config".into(),
            "--hijack-dns".into(),
            "--no-hijack-dns".into(),
        ])
        .await
        .is_err());
        assert!(run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "transparent".into(),
            "config".into(),
            "--dll-path".into(),
            r"C:\ok\WinDivert.dll".into(),
            "--clear-dll-path".into(),
        ])
        .await
        .is_err());
        assert!(run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "transparent".into(),
            "config".into(),
        ])
        .await
        .is_err());

        // 3. Configure + enable persists to XML and survives node/rule mutations
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "transparent".into(),
            "config".into(),
            "--no-hijack-dns".into(),
            "--no-block-quic".into(),
            "--dll-path".into(),
            r"C:\tools\WinDivert.dll".into(),
        ])
        .await
        .unwrap();
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "transparent".into(),
            "enable".into(),
        ])
        .await
        .unwrap();
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "node".into(),
            "add".into(),
            "--name".into(),
            "PreserveNode".into(),
            "--addr".into(),
            "10.0.0.2:1080".into(),
        ])
        .await
        .unwrap();

        let loaded = ConfigStore::new(&cfg_path).load_existing(&[]).unwrap();
        assert!(loaded.transparent_settings.enabled);
        assert!(!loaded.transparent_settings.hijack_dns);
        assert!(!loaded.transparent_settings.block_quic_for_proxied);
        assert_eq!(
            loaded.transparent_settings.dll_path.as_deref(),
            Some(r"C:\tools\WinDivert.dll")
        );

        // 4. Clear DLL path + disable updates XML cleanly
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "transparent".into(),
            "config".into(),
            "--clear-dll-path".into(),
        ])
        .await
        .unwrap();
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "transparent".into(),
            "disable".into(),
        ])
        .await
        .unwrap();

        let updated = ConfigStore::new(&cfg_path).load_existing(&[]).unwrap();
        assert!(!updated.transparent_settings.enabled);
        assert!(!updated.transparent_settings.hijack_dns);
        assert!(!updated.transparent_settings.block_quic_for_proxied);
        assert!(updated.transparent_settings.dll_path.is_none());

        let _ = std::fs::remove_file(&cfg_path);
    }

    #[tokio::test]
    async fn test_cli_transparent_doctor_respects_explicit_api() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // 1. 显式传入不可达 --api 时，doctor 必须报错，绝不静默回退离线探测
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_listener.local_addr().unwrap();
        drop(dead_listener);
        assert!(
            run_cli(&[
                "flowx".into(),
                "--api".into(),
                format!("http://{}", dead_addr),
                "--json".into(),
                "transparent".into(),
                "doctor".into(),
            ])
            .await
            .is_err(),
            "flowx transparent doctor with unreachable --api must fail instead of falling back offline"
        );

        // 2. 显式传入在线 --api 时，doctor 必须请求 /api/transparent/status
        let mock_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_listener.local_addr().unwrap();
        let (path_tx, path_rx) = tokio::sync::oneshot::channel::<String>();
        let mock_srv = tokio::spawn(async move {
            let (mut s, _) = mock_listener.accept().await.unwrap();
            let mut req_buf = [0u8; 2048];
            let n = s.read(&mut req_buf).await.unwrap();
            let req_line = String::from_utf8_lossy(&req_buf[..n])
                .lines()
                .next()
                .unwrap_or_default()
                .to_string();
            let _ = path_tx.send(req_line);
            let body = r#"{"supported":true,"enabled":true,"running":true,"elevated":true,"dll_found":true,"sys_found":true,"dll_path":"C:\\FlowX\\WinDivert.dll","sys_path":"C:\\FlowX\\WinDivert64.sys","searched_dirs":["C:\\FlowX"],"hijack_dns":true,"block_quic_for_proxied":true,"configured_dll_path":null,"last_error":null}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            s.write_all(resp.as_bytes()).await.unwrap();
        });

        run_cli(&[
            "flowx".into(),
            "--api".into(),
            format!("http://{}", mock_addr),
            "--json".into(),
            "transparent".into(),
            "doctor".into(),
        ])
        .await
        .unwrap();
        mock_srv.await.unwrap();
        let req_line = path_rx.await.unwrap();
        assert!(
            req_line.starts_with("GET /api/transparent/status "),
            "expected GET /api/transparent/status, got: {req_line}"
        );
    }

    #[tokio::test]
    async fn test_cli_transparent_dll_path_validation_and_doctor_report_semantics() {
        let cfg_path = std::env::current_dir().unwrap().join("target").join(format!(
            "flowx_cli_tp_val_{}_{}.xml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cfg_str = cfg_path.display().to_string();

        // 1. Invalid --dll-path emits structured ERR_TRANSPARENT_INVALID_DLL_PATH matching API
        for bad_path in [
            "WinDivert.dll",
            r".\driver\WinDivert.dll",
            r"..\evil\WinDivert.dll",
            r"\\fileserver\share\WinDivert.dll",
            r"C:\tools\evil.dll",
            "C:\\bad\npath\\WinDivert.dll",
        ] {
            let err = run_cli(&[
                "flowx".into(),
                "--config".into(),
                cfg_str.clone(),
                "--offline".into(),
                "--json".into(),
                "transparent".into(),
                "config".into(),
                "--dll-path".into(),
                bad_path.into(),
            ])
            .await
            .expect_err(&format!("expected invalid --dll-path rejection for {bad_path:?}"));
            let err_json = format_cli_error_json(&err);
            assert_eq!(
                err_json["code"], "ERR_TRANSPARENT_INVALID_DLL_PATH",
                "unexpected CLI JSON error for {bad_path:?}: {err_json}"
            );
        }
        assert!(!cfg_path.exists());

        // 2. doctor ready must be false when last_error is present
        let err_status = json!({
            "elevated": true,
            "running": false,
            "dll_found": true,
            "sys_found": true,
            "dll_path": r"C:\FlowX\WinDivert.dll",
            "sys_path": r"C:\FlowX\WinDivert64.sys",
            "searched_dirs": [r"C:\FlowX"],
            "enabled": true,
            "hijack_dns": true,
            "block_quic_for_proxied": true,
            "configured_dll_path": null,
            "last_error": "WinDivert driver signature check failed",
            "config_path": r"D:\Daemon\prod.xml",
        });
        let online_err_report =
            build_transparent_doctor_report("ONLINE", &err_status, "./local-cli.xml");
        assert_eq!(online_err_report["ready"], false);
        assert_eq!(online_err_report["config_path"], r"D:\Daemon\prod.xml");
        assert!(online_err_report["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str().unwrap_or("").contains("signature check failed")));

        // 3. Online doctor without server config_path reports null instead of local CLI config path
        let online_no_cfg = json!({
            "elevated": true,
            "running": true,
            "dll_found": true,
            "sys_found": true,
            "searched_dirs": [r"C:\FlowX"],
            "enabled": true,
            "last_error": null,
        });
        let online_report =
            build_transparent_doctor_report("ONLINE", &online_no_cfg, "./local-cli.xml");
        assert_eq!(online_report["ready"], true);
        assert!(online_report["config_path"].is_null());

        // 4. Offline doctor reports local CLI config path
        let offline_report =
            build_transparent_doctor_report("OFFLINE", &online_no_cfg, "./local-cli.xml");
        assert_eq!(offline_report["ready"], true);
        assert_eq!(offline_report["config_path"], "./local-cli.xml");

        // 5. Low-integrity status blocks readiness and surfaces actionable issue
        let low_il_status = json!({
            "elevated": false,
            "low_integrity": true,
            "running": false,
            "dll_found": true,
            "sys_found": true,
            "searched_dirs": [r"C:\FlowX"],
            "enabled": false,
            "last_error": null,
        });
        let low_il_report =
            build_transparent_doctor_report("ONLINE", &low_il_status, "./local-cli.xml");
        assert_eq!(low_il_report["ready"], false);
        assert_eq!(low_il_report["low_integrity"], true);
        assert!(low_il_report["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str().unwrap_or("").contains("Low Mandatory Integrity")));
    }

    #[tokio::test]
    async fn test_cli_transparent_elevate_node_clear_user_and_ping_all() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // 1. `transparent elevate --offline` fails cleanly
        assert!(
            run_cli(&[
                "flowx".into(),
                "--offline".into(),
                "--json".into(),
                "transparent".into(),
                "elevate".into(),
            ])
            .await
            .is_err()
        );

        // 2. `transparent elevate` online sends POST /api/transparent/elevate and handles 200 & 409
        let elev_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let elev_addr = elev_listener.local_addr().unwrap().to_string();
        let elev_srv = tokio::spawn(async move {
            for (status, body) in [
                ("200 OK", r#"{"ok":true,"relaunching":true}"#),
                (
                    "409 Conflict",
                    r#"{"code":"ERR_TRANSPARENT_ALREADY_ELEVATED","error":"Already Administrator"}"#,
                ),
            ] {
                let (mut sock, _) = elev_listener.accept().await.unwrap();
                let mut buf = [0u8; 2048];
                let n = sock.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                assert!(
                    req.starts_with("POST /api/transparent/elevate "),
                    "unexpected elevate request: {req}"
                );
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                sock.write_all(resp.as_bytes()).await.unwrap();
            }
        });
        run_cli(&[
            "flowx".into(),
            "--api".into(),
            elev_addr.clone(),
            "--json".into(),
            "transparent".into(),
            "elevate".into(),
        ])
        .await
        .unwrap();
        let err_409 = run_cli(&[
            "flowx".into(),
            "--api".into(),
            elev_addr,
            "--json".into(),
            "transparent".into(),
            "elevate".into(),
        ])
        .await
        .unwrap_err();
        assert_eq!(
            format_cli_error_json(&err_409)["code"],
            "ERR_TRANSPARENT_ALREADY_ELEVATED"
        );
        elev_srv.await.unwrap();

        // 3. Offline & online `node update --clear-user` + conflict rejection + `node ping --all`
        let cfg_path = std::env::current_dir().unwrap().join("target").join(format!(
            "flowx_cli_parity_{}_{}.xml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&cfg_path);
        let cfg_str = cfg_path.to_string_lossy().to_string();

        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "node".into(),
            "add".into(),
            "--name".into(),
            "AuthNode".into(),
            "--addr".into(),
            "10.0.0.5:1080".into(),
            "--user".into(),
            "alice".into(),
            "--pass".into(),
            "pw".into(),
        ])
        .await
        .unwrap();

        assert!(
            run_cli(&[
                "flowx".into(),
                "--config".into(),
                cfg_str.clone(),
                "--offline".into(),
                "node".into(),
                "update".into(),
                "102".into(),
                "--user".into(),
                "bob".into(),
                "--clear-user".into(),
            ])
            .await
            .is_err()
        );

        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "--json".into(),
            "node".into(),
            "update".into(),
            "102".into(),
            "--clear-user".into(),
        ])
        .await
        .unwrap();
        let store = ConfigStore::new(&cfg_path);
        let (rt, _) = store.load_or_init(&DEFAULT_SELF_PORTS).unwrap();
        assert_eq!(rt.proxy_nodes.get(&102).unwrap().username, None);
        assert_eq!(
            rt.proxy_nodes.get(&102).unwrap().client.auth_credentials(),
            (None, None)
        );
        let _ = std::fs::remove_file(&cfg_path);

        // `node ping --all` conflicts with positional ID
        assert!(
            run_cli(&[
                "flowx".into(),
                "--offline".into(),
                "node".into(),
                "ping".into(),
                "--all".into(),
                "101".into(),
            ])
            .await
            .is_err()
        );

        // Online `node ping --all`: all ok -> Ok(()), partial failure -> SilentExitError
        let mock_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_listener.local_addr().unwrap().to_string();
        let mock_srv = tokio::spawn(async move {
            let mut ping_count = 0usize;
            for _ in 0..6 {
                let (mut sock, _) = mock_listener.accept().await.unwrap();
                let mut buf = [0u8; 2048];
                let n = sock.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                let body = if req.starts_with("GET /api/nodes ") {
                    r#"[{"id":101,"name":"N1","protocol":"SOCKS5","server_addr":"127.0.0.1:10808","auth_configured":false},{"id":102,"name":"N2","protocol":"HTTP","server_addr":"127.0.0.1:10809","auth_configured":false}]"#
                } else {
                    ping_count += 1;
                    // Batch 1 (ping_count 1..=2): both ok; Batch 2 (ping_count 3..=4): one fails
                    if ping_count <= 3 {
                        r#"{"ok":true,"latency_ms":4,"message":"ok"}"#
                    } else {
                        r#"{"ok":false,"latency_ms":0,"message":"refused"}"#
                    }
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                sock.write_all(resp.as_bytes()).await.unwrap();
            }
        });
        run_cli(&[
            "flowx".into(),
            "--api".into(),
            mock_addr.clone(),
            "--json".into(),
            "node".into(),
            "ping".into(),
            "--all".into(),
        ])
        .await
        .unwrap();
        let batch2_err = run_cli(&[
            "flowx".into(),
            "--api".into(),
            mock_addr,
            "--json".into(),
            "node".into(),
            "ping".into(),
            "--all".into(),
        ])
        .await
        .unwrap_err();
        assert!(batch2_err.downcast_ref::<SilentExitError>().is_some());
        mock_srv.await.unwrap();
    }

    #[tokio::test]
    async fn test_cli_rule_clear_filters_and_conn_list_filters() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let cfg_path = std::env::current_dir().unwrap().join("target").join(format!(
            "flowx_cli_rule_clr_{}_{}.xml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&cfg_path);
        let cfg_str = cfg_path.to_string_lossy().to_string();

        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "rule".into(),
            "add".into(),
            "--name".into(),
            "ScopedRule".into(),
            "--apps".into(),
            "curl.exe".into(),
            "--targets".into(),
            "example.com".into(),
            "--ports".into(),
            "443".into(),
            "--action".into(),
            "Direct".into(),
        ])
        .await
        .unwrap();

        for (set_flag, set_val, clear_flag) in [
            ("--apps", "git.exe", "--clear-apps"),
            ("--targets", "github.com", "--clear-targets"),
            ("--ports", "80", "--clear-ports"),
        ] {
            assert!(
                run_cli(&[
                    "flowx".into(),
                    "--config".into(),
                    cfg_str.clone(),
                    "--offline".into(),
                    "rule".into(),
                    "update".into(),
                    "1".into(),
                    set_flag.into(),
                    set_val.into(),
                    clear_flag.into(),
                ])
                .await
                .is_err()
            );
        }

        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "--json".into(),
            "rule".into(),
            "update".into(),
            "1".into(),
            "--clear-apps".into(),
            "--clear-targets".into(),
            "--clear-ports".into(),
        ])
        .await
        .unwrap();
        let store = ConfigStore::new(&cfg_path);
        let (rt, _) = store.load_or_init(&DEFAULT_SELF_PORTS).unwrap();
        assert_eq!(rt.rules[0].apps_raw, "");
        assert_eq!(rt.rules[0].targets_raw, "");
        assert_eq!(rt.rules[0].ports_raw, "");

        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "--json".into(),
            "rule".into(),
            "list".into(),
            "--search".into(),
            "scoped".into(),
        ])
        .await
        .unwrap();
        let _ = std::fs::remove_file(&cfg_path);

        // `conn list` invalid filter validation and filtering helper
        assert!(
            run_cli(&[
                "flowx".into(),
                "--api".into(),
                "127.0.0.1:40080".into(),
                "conn".into(),
                "list".into(),
                "--filter".into(),
                "INVALID".into(),
            ])
            .await
            .is_err()
        );

        let sample_proxy = json!({
            "id": 1,
            "process_name": "chrome.exe",
            "process_path": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
            "target": "api.github.com:443",
            "rule_name": "DevProxy",
            "action": "Proxy (#101)",
            "action_type": "Proxy",
        });
        let sample_direct = json!({
            "id": 2,
            "process_name": "curl.exe",
            "process_path": "C:\\Windows\\System32\\curl.exe",
            "target": "localhost:8080",
            "rule_name": "LocalBypass",
            "action": "Direct",
            "action_type": "Direct",
        });
        assert!(conn_matches_filter(&sample_proxy, "PROXY", Some("github")));
        assert!(!conn_matches_filter(&sample_direct, "PROXY", None));
        assert!(conn_matches_filter(&sample_direct, "DIRECT", Some("curl")));
        assert!(!conn_matches_filter(&sample_proxy, "BLOCK", None));

        let conn_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let conn_addr = conn_listener.local_addr().unwrap().to_string();
        let conn_srv = tokio::spawn(async move {
            let (mut sock, _) = conn_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await.unwrap();
            let body = r#"[{"id":1,"process_name":"chrome.exe","process_path":"C:\\chrome.exe","pid":10,"target":"github.com:443","rule_name":"DevProxy","action":"Proxy (#101)","action_type":"Proxy","duration_secs":1,"uploaded_bytes":0,"downloaded_bytes":0,"upload_bytes_per_sec":0,"download_bytes_per_sec":0}]"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
        });
        run_cli(&[
            "flowx".into(),
            "--api".into(),
            conn_addr,
            "--json".into(),
            "conn".into(),
            "list".into(),
            "--filter".into(),
            "proxy".into(),
            "--search".into(),
            "chrome".into(),
        ])
        .await
        .unwrap();
        conn_srv.await.unwrap();
    }
}
