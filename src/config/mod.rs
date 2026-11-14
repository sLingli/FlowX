use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::interceptor::dispatcher::ProxyNodeEntry;
use crate::outbound::chain::{parse_target_addr, ProxyNode};
use crate::outbound::http::HttpConnectClient;
use crate::outbound::socks4::Socks4Client;
use crate::outbound::socks5::Socks5Client;
use crate::outbound::TargetAddr;
use crate::router::{Action, Rule, RuleEngine};

static NEXT_TMP_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename = "Profile", deny_unknown_fields)]
pub struct ProfileConfig {
    #[serde(rename = "@version", default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "DefaultAction", default, skip_serializing_if = "Option::is_none")]
    pub default_action: Option<RuleActionItem>,
    #[serde(rename = "ProxyList", default, skip_serializing_if = "Option::is_none")]
    pub proxy_list: Option<ProxyList>,
    #[serde(rename = "RuleList", default, skip_serializing_if = "Option::is_none")]
    pub rule_list: Option<RuleList>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ProxyList {
    #[serde(rename = "Proxy", default)]
    pub proxies: Vec<ProxyItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProxyItem {
    #[serde(rename = "@id")]
    pub id: u32,
    #[serde(rename = "@type")]
    pub proxy_type: String,
    #[serde(rename = "Name", default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "Address")]
    pub address: String,
    #[serde(rename = "Port")]
    pub port: u16,
    #[serde(rename = "Username", default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(rename = "Password", default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(rename = "Options", default, skip_serializing_if = "Option::is_none")]
    pub options: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RuleList {
    #[serde(rename = "Rule", default)]
    pub rules: Vec<RuleItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleItem {
    #[serde(rename = "@enabled", default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Applications", default, skip_serializing_if = "Option::is_none")]
    pub applications: Option<String>,
    #[serde(rename = "Targets", default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<String>,
    #[serde(rename = "Ports", default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<String>,
    #[serde(rename = "Action")]
    pub action: RuleActionItem,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleActionItem {
    #[serde(rename = "@type")]
    pub action_type: String,
    #[serde(rename = "$text", default, skip_serializing_if = "Option::is_none")]
    pub value: Option<u32>,
}

pub struct RuntimeProfile {
    pub proxy_nodes: HashMap<u32, ProxyNodeEntry>,
    pub rules: Vec<Rule>,
    pub default_action: Action,
}

impl ProfileConfig {
    pub fn from_xml(xml_content: &str) -> Result<Self> {
        validate_xml_root_profile(xml_content)?;
        quick_xml::de::from_str(xml_content).map_err(|e| anyhow::anyhow!(e))
    }

    pub fn to_xml(&self) -> Result<String> {
        let mut buf = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        let mut ser = quick_xml::se::Serializer::new(&mut buf);
        ser.indent(' ', 2);
        self.serialize(ser).context("Failed to serialize ProfileConfig to XML")?;
        buf.push('\n');
        Ok(buf)
    }

    /// 内置默认配置（首次运行且本地无 flowx.xml 时生成）
    pub fn default_profile() -> Self {
        Self {
            version: Some("1".to_string()),
            default_action: Some(RuleActionItem {
                action_type: "Direct".to_string(),
                value: None,
            }),
            proxy_list: Some(ProxyList {
                proxies: vec![ProxyItem {
                    id: 101,
                    proxy_type: "SOCKS5".to_string(),
                    name: Some("Node-101 (Primary)".to_string()),
                    address: "127.0.0.1".to_string(),
                    port: 10808,
                    username: None,
                    password: None,
                    options: None,
                }],
            }),
            rule_list: Some(RuleList {
                rules: vec![
                    RuleItem {
                        enabled: Some(true),
                        name: "LocalBypass".to_string(),
                        applications: None,
                        targets: Some("127.0.0.1; localhost; %ComputerName%; ::1; 192.168.0.0/16".to_string()),
                        ports: None,
                        action: RuleActionItem {
                            action_type: "Direct".to_string(),
                            value: None,
                        },
                    },
                    RuleItem {
                        enabled: Some(true),
                        name: "DevProxy".to_string(),
                        applications: Some("node.exe; *chrome*.exe; *git*.exe; *antigravity*.exe".to_string()),
                        targets: None,
                        ports: None,
                        action: RuleActionItem {
                            action_type: "Proxy".to_string(),
                            value: Some(101),
                        },
                    },
                ],
            }),
        }
    }

    /// 校验并转换为运行时数据结构
    pub fn into_runtime(self, self_ports: &[u16]) -> Result<RuntimeProfile> {
        let mut proxy_nodes = HashMap::new();

        if let Some(list) = self.proxy_list {
            for item in list.proxies {
                if proxy_nodes.contains_key(&item.id) {
                    bail!("Duplicate proxy node ID in configuration: {}", item.id);
                }
                let entry = build_proxy_entry(item, self_ports)?;
                proxy_nodes.insert(entry.id, entry);
            }
        }

        let default_action = match self.default_action {
            Some(act) => parse_action(&act, &proxy_nodes)?,
            None => Action::Direct,
        };

        let mut rules = Vec::new();
        if let Some(list) = self.rule_list {
            for item in list.rules {
                let name = item.name.trim();
                if name.is_empty() {
                    bail!("Configuration contains a routing rule with an empty name");
                }
                let action = parse_action(&item.action, &proxy_nodes)
                    .with_context(|| format!("Invalid action configuration for rule [{}]", name))?;
                let apps = item.applications.as_deref().map(str::trim).filter(|s| !s.is_empty());
                let targets = item.targets.as_deref().map(str::trim).filter(|s| !s.is_empty());
                let ports = item.ports.as_deref().map(str::trim).filter(|s| !s.is_empty());
                let enabled = item.enabled.unwrap_or(true);
                rules.push(Rule::from_raw(name, enabled, apps, targets, ports, action));
            }
        }

        Ok(RuntimeProfile {
            proxy_nodes,
            rules,
            default_action,
        })
    }

    /// 从当前内存运行时状态构造可持久化的配置对象
    pub fn from_runtime(
        proxy_nodes: &HashMap<u32, ProxyNodeEntry>,
        rules: &[Rule],
        default_action: &Action,
    ) -> Self {
        let mut proxies: Vec<ProxyItem> = proxy_nodes
            .values()
            .map(|entry| {
                let (address, port) = split_server_addr(&entry.server_addr);
                let (client_user, client_pass) = entry.client.auth_credentials();
                let username = entry
                    .username
                    .clone()
                    .or_else(|| client_user.map(|s| s.to_string()));
                let password = client_pass.map(|s| s.to_string());
                ProxyItem {
                    id: entry.id,
                    proxy_type: entry.protocol.clone(),
                    name: Some(entry.name.clone()),
                    address,
                    port,
                    username,
                    password,
                    options: None,
                }
            })
            .collect();
        proxies.sort_by_key(|p| p.id);

        let rule_items: Vec<RuleItem> = rules
            .iter()
            .map(|r| RuleItem {
                enabled: Some(r.enabled),
                name: r.name.clone(),
                applications: (!r.apps_raw.trim().is_empty()).then(|| r.apps_raw.clone()),
                targets: (!r.targets_raw.trim().is_empty()).then(|| r.targets_raw.clone()),
                ports: (!r.ports_raw.trim().is_empty()).then(|| r.ports_raw.clone()),
                action: action_to_item(&r.action),
            })
            .collect();

        Self {
            version: Some("1".to_string()),
            default_action: Some(action_to_item(default_action)),
            proxy_list: Some(ProxyList { proxies }),
            rule_list: Some(RuleList { rules: rule_items }),
        }
    }
}

fn action_to_item(action: &Action) -> RuleActionItem {
    match action {
        Action::Direct => RuleActionItem {
            action_type: "Direct".to_string(),
            value: None,
        },
        Action::Block => RuleActionItem {
            action_type: "Block".to_string(),
            value: None,
        },
        Action::Proxy(id) => RuleActionItem {
            action_type: "Proxy".to_string(),
            value: Some(*id),
        },
        Action::Chain(id) => RuleActionItem {
            action_type: "Chain".to_string(),
            value: Some(*id),
        },
    }
}

fn parse_action(item: &RuleActionItem, proxy_nodes: &HashMap<u32, ProxyNodeEntry>) -> Result<Action> {
    match item.action_type.trim().to_ascii_uppercase().as_str() {
        "DIRECT" => Ok(Action::Direct),
        "BLOCK" => Ok(Action::Block),
        "PROXY" => {
            let id = item
                .value
                .context("Proxy action missing node ID")?;
            if !proxy_nodes.contains_key(&id) {
                bail!("Referenced non-existent proxy node ID: {}", id);
            }
            Ok(Action::Proxy(id))
        }
        "CHAIN" => {
            bail!("Proxy chain action (Chain) is not supported yet; use Direct, Block, or Proxy");
        }
        other => bail!("Unsupported rule action type: {}", other),
    }
}

fn format_host_port(address: &str, port: u16) -> String {
    let addr = address.trim();
    if addr.contains(':') && !addr.starts_with('[') {
        format!("[{}]:{}", addr, port)
    } else {
        format!("{}:{}", addr, port)
    }
}

fn split_server_addr(server_addr: &str) -> (String, u16) {
    match parse_target_addr(server_addr) {
        Ok(TargetAddr::Ip(SocketAddr::V4(v4))) => (v4.ip().to_string(), v4.port()),
        Ok(TargetAddr::Ip(SocketAddr::V6(v6))) => (v6.ip().to_string(), v6.port()),
        Ok(TargetAddr::Domain(h, p)) => (h, p),
        Err(_) => (server_addr.to_string(), 0),
    }
}

fn build_proxy_entry(item: ProxyItem, self_ports: &[u16]) -> Result<ProxyNodeEntry> {
    let proto = item.proxy_type.trim().to_ascii_uppercase();
    if !matches!(proto.as_str(), "SOCKS5" | "SOCKS4" | "HTTP") {
        bail!("Node #{} uses unsupported proxy protocol: {}", item.id, item.proxy_type);
    }
    let address = item.address.trim();
    if address.is_empty() || item.port == 0 {
        bail!("Node #{} address or port is invalid", item.id);
    }
    let server_addr = format_host_port(address, item.port);
    let target_parsed = parse_target_addr(&server_addr)
        .with_context(|| format!("Node #{} address format is invalid: {}", item.id, server_addr))?;
    match &target_parsed {
        crate::outbound::TargetAddr::Ip(sa) => {
            crate::outbound::direct::validate_direct_ips(
                &[sa.ip()],
                sa.port(),
                self_ports,
                None,
                &server_addr,
            )
            .with_context(|| format!("Node #{} address is unsafe or reserved", item.id))?;
        }
        crate::outbound::TargetAddr::Domain(_, port) => {
            if target_parsed.is_loopback_or_unspecified() && self_ports.contains(port) {
                bail!("Node #{} address points to FlowX internal service port: {}", item.id, server_addr);
            }
        }
    }

    if proto == "SOCKS4" && item.password.is_some() {
        bail!(
            "Node #{} (SOCKS4) only supports UserID and cannot contain <Password>",
            item.id
        );
    }

    let mut username = item
        .username
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty());
    let raw_password = item.password;
    if let Some(ref raw_pw) = raw_password
        && has_control_or_oversize(raw_pw, 255)
    {
        bail!(
            "Node #{} password contains invalid control characters or exceeds 255 bytes",
            item.id
        );
    }
    let password = raw_password.filter(|p| !p.is_empty());
    if let Some(ref u) = username
        && has_control_or_oversize(u, 255)
    {
        bail!(
            "Node #{} username contains invalid control characters or exceeds 255 bytes",
            item.id
        );
    }
    if proto != "SOCKS4" {
        if username.is_none() && password.is_some() {
            bail!("Node #{} has a password configured without a username", item.id);
        }
        if let Some(orphan_user) = username.as_deref()
            && password.is_none()
        {
            warn!(
                "[Config] Node #{} ({}) has legacy standalone username '{}' without password; clearing orphan username so service can start (reconfigure paired credentials to re-enable auth)",
                item.id, proto, orphan_user
            );
            username = None;
        }
    }
    if proto == "HTTP" && username.as_deref().is_some_and(|u| u.contains(':')) {
        bail!("Node #{} HTTP proxy username cannot contain ':' (RFC 7617)", item.id);
    }
    let name = item
        .name
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| format!("Node-{} ({})", item.id, proto));
    if has_control_or_oversize(&name, 255) {
        bail!(
            "Node #{} name contains invalid control characters or exceeds 255 bytes",
            item.id
        );
    }

    let client = match proto.as_str() {
        "HTTP" => {
            let mut c = HttpConnectClient::new(&server_addr);
            if let (Some(u), Some(p)) = (&username, &password) {
                c = c.with_auth(u.clone(), p.clone());
            }
            ProxyNode::Http(c)
        }
        "SOCKS4" => {
            let mut c = Socks4Client::new(&server_addr);
            if let Some(u) = &username {
                c = c.with_user_id(u.clone());
            }
            ProxyNode::Socks4(c)
        }
        _ => {
            let mut c = Socks5Client::new(&server_addr);
            if let (Some(u), Some(p)) = (&username, &password) {
                c = c.with_auth(u.clone(), p.clone());
            }
            ProxyNode::Socks5(c)
        }
    };

    Ok(ProxyNodeEntry {
        id: item.id,
        name,
        protocol: proto,
        server_addr,
        username,
        client,
    })
}

/// Reject control characters and strings exceeding `max_bytes` across node metadata fields.
pub(crate) fn has_control_or_oversize(s: &str, max_bytes: usize) -> bool {
    s.chars().any(char::is_control) || s.len() > max_bytes
}

/// 配置文件存储管理器：负责 XML 加载与原子回写持久化
pub struct ConfigStore {
    pub path: PathBuf,
    save_lock: Mutex<()>,
}

impl ConfigStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            save_lock: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(test)]
    pub(crate) fn lock_save_for_test(&self) -> std::sync::MutexGuard<'_, ()> {
        self.save_lock.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn read_existing_opt(&self, self_ports: &[u16]) -> Result<Option<RuntimeProfile>> {
        match std::fs::read_to_string(&self.path) {
            Ok(xml) => {
                let cfg = ProfileConfig::from_xml(&xml)
                    .with_context(|| format!("Failed to parse XML configuration file: {}", self.path.display()))?;
                let runtime = cfg.into_runtime(self_ports)?;
                Ok(Some(runtime))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("Failed to read configuration file: {}", self.path.display())),
        }
    }

    /// 仅读取并解析已有配置文件；文件不存在时直接报错，绝不新建或修改磁盘文件（供只读 CLI 命令使用）
    pub fn load_existing(&self, self_ports: &[u16]) -> Result<RuntimeProfile> {
        match self.read_existing_opt(self_ports)? {
            Some(rt) => Ok(rt),
            None => bail!("Configuration file not found: {}", self.path.display()),
        }
    }

    /// 读取已有配置文件；若明确 `NotFound` 则在内存中构造默认配置，不写入磁盘（供 CLI 变更前校验使用）
    pub fn load_existing_or_default(&self, self_ports: &[u16]) -> Result<RuntimeProfile> {
        if let Some(runtime) = self.read_existing_opt(self_ports)? {
            return Ok(runtime);
        }
        ProfileConfig::default_profile().into_runtime(self_ports)
    }

    /// 从磁盘加载配置；仅在明确 `NotFound` 时生成默认配置，其他 I/O 错误直接失败以免覆盖不可读配置
    pub fn load_or_init(&self, self_ports: &[u16]) -> Result<(RuntimeProfile, bool)> {
        if let Some(runtime) = self.read_existing_opt(self_ports)? {
            return Ok((runtime, false));
        }
        let _guard = self.save_lock.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(runtime) = self.read_existing_opt(self_ports)? {
            return Ok((runtime, false));
        }
        let default_cfg = ProfileConfig::default_profile();
        self.write_config_atomic(&default_cfg)?;
        let runtime = default_cfg.into_runtime(self_ports)?;
        Ok((runtime, true))
    }

    /// 构造当前运行时状态的配置快照（仅在内存中读锁获取后立即释放）
    pub fn snapshot_runtime(
        proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
        rule_engine: &RuleEngine,
    ) -> ProfileConfig {
        let nodes_guard = proxy_nodes.read().unwrap_or_else(|e| e.into_inner());
        let rules = rule_engine.current_rules();
        let default_action = rule_engine.default_action();
        ProfileConfig::from_runtime(&nodes_guard, &rules, &default_action)
    }

    /// 串行加锁后将已构建的配置快照原子写入磁盘（适合在 `tokio::task::spawn_blocking` 中调用）
    pub fn save_profile(&self, cfg: &ProfileConfig) -> Result<()> {
        let _guard = self.save_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.write_config_atomic(cfg)
    }

    /// 串行化读取当前内存快照并原子写回 XML 文件
    pub fn save_runtime(
        &self,
        proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
        rule_engine: &RuleEngine,
    ) -> Result<()> {
        let cfg = Self::snapshot_runtime(proxy_nodes, rule_engine);
        self.save_profile(&cfg)
    }

    fn write_config_atomic(&self, cfg: &ProfileConfig) -> Result<()> {
        let xml = cfg.to_xml()?;
        let parent_dir = self.path.parent().filter(|p| !p.as_os_str().is_empty());
        if let Some(parent) = parent_dir {
            std::fs::create_dir_all(parent)?;
        }

        let file_name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.is_empty())
            .unwrap_or("flowx.xml");
        let seq = NEXT_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp_name = format!(".{}.tmp.{}.{}", file_name, std::process::id(), seq);
        let tmp_path = match parent_dir {
            Some(parent) => parent.join(&tmp_name),
            None => PathBuf::from(&tmp_name),
        };

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }

        let mut file = opts
            .open(&tmp_path)
            .with_context(|| format!("Failed to create temporary configuration file: {}", tmp_path.display()))?;

        let write_result: Result<()> = (|| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .context("Failed to restrict temporary configuration file permissions to 0600")?;
            }
            file.write_all(xml.as_bytes())
                .with_context(|| format!("Failed to write temporary configuration file: {}", tmp_path.display()))?;
            file.sync_all()
                .with_context(|| format!("Failed to fsync temporary configuration file: {}", tmp_path.display()))?;
            Ok(())
        })();

        drop(file);
        if let Err(e) = write_result {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }

        if let Err(e) = std::fs::rename(&tmp_path, &self.path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e).with_context(|| {
                format!(
                    "Failed to atomically replace configuration file: {}",
                    self.path.display()
                )
            });
        }

        #[cfg(unix)]
        {
            let dir_to_sync = parent_dir.unwrap_or_else(|| Path::new("."));
            match std::fs::File::open(dir_to_sync) {
                Ok(dir_file) => match dir_file.sync_all() {
                    Ok(()) => {}
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::InvalidInput | std::io::ErrorKind::Unsupported
                        ) => {}
                    Err(e) => {
                        return Err(e).with_context(|| {
                            format!("Failed to fsync configuration directory: {}", dir_to_sync.display())
                        });
                    }
                },
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!(
                            "Failed to open configuration directory for sync: {}",
                            dir_to_sync.display()
                        )
                    });
                }
            }
        }

        Ok(())
    }
}

fn validate_xml_root_profile(xml_content: &str) -> Result<()> {
    use quick_xml::events::Event;

    let trimmed_bom = xml_content.strip_prefix('\u{feff}').unwrap_or(xml_content);
    let mut reader = quick_xml::Reader::from_str(trimmed_bom);
    let mut depth: usize = 0;
    let mut saw_root = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let raw_name = e.name();
                if !saw_root {
                    if raw_name.as_ref() != b"Profile" {
                        let found = String::from_utf8_lossy(raw_name.as_ref());
                        bail!("Invalid XML root element <{}>: expected <Profile>", found);
                    }
                    saw_root = true;
                    depth = 1;
                } else if depth == 0 {
                    let found = String::from_utf8_lossy(raw_name.as_ref());
                    bail!("Unexpected trailing XML element <{}> after </Profile>", found);
                } else {
                    depth += 1;
                }
            }
            Ok(Event::Empty(e)) => {
                let raw_name = e.name();
                if !saw_root {
                    if raw_name.as_ref() != b"Profile" {
                        let found = String::from_utf8_lossy(raw_name.as_ref());
                        bail!("Invalid XML root element <{}>: expected <Profile>", found);
                    }
                    saw_root = true;
                } else if depth == 0 {
                    let found = String::from_utf8_lossy(raw_name.as_ref());
                    bail!("Unexpected trailing XML element <{}/> after </Profile>", found);
                }
            }
            Ok(Event::End(e)) => {
                if !saw_root || depth == 0 {
                    let raw_name = e.name();
                    let found = String::from_utf8_lossy(raw_name.as_ref());
                    bail!("Unexpected closing XML tag </{}>", found);
                }
                depth -= 1;
            }
            Ok(Event::Decl(_)) | Ok(Event::DocType(_)) => {
                if saw_root {
                    bail!("Unexpected XML declaration or DOCTYPE after <Profile> root");
                }
            }
            Ok(Event::Comment(_)) | Ok(Event::PI(_)) => continue,
            Ok(Event::Text(t)) => {
                if depth == 0 && !t.as_ref().iter().all(|b| b.is_ascii_whitespace()) {
                    if saw_root {
                        bail!("Unexpected trailing text content after </Profile>");
                    }
                    bail!("Unexpected text content before <Profile> root element");
                }
            }
            Ok(Event::CData(_)) => {
                if depth == 0 {
                    if saw_root {
                        bail!("Unexpected trailing CDATA content after </Profile>");
                    }
                    bail!("Unexpected text content before <Profile> root element");
                }
            }
            Ok(Event::Eof) => {
                if !saw_root {
                    bail!("Empty XML configuration: missing <Profile> root element");
                }
                if depth != 0 {
                    bail!("Unclosed XML <Profile> element before end of file");
                }
                return Ok(());
            }
            Err(e) => bail!("Malformed XML syntax: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xml_roundtrip_and_runtime_conversion() {
        let default_cfg = ProfileConfig::default_profile();
        let xml = default_cfg.to_xml().unwrap();
        assert!(xml.contains("<Profile version=\"1\">"), "xml:\n{}", xml);
        assert!(xml.contains("<Action type=\"Direct\"/>") || xml.contains("<Action type=\"Direct\" />"), "xml:\n{}", xml);
        assert!(xml.contains("type=\"Proxy\"") && xml.contains("101"), "xml:\n{}", xml);

        let parsed = ProfileConfig::from_xml(&xml).unwrap();
        assert_eq!(parsed, default_cfg);

        // 也验证手写紧凑 XML（如 <Action type="Proxy">101</Action>）可正常解析
        let compact_xml = r#"
        <Profile version="1">
          <ProxyList>
            <Proxy id="101" type="SOCKS5">
              <Name>Node-101</Name>
              <Address>127.0.0.1</Address>
              <Port>10808</Port>
            </Proxy>
          </ProxyList>
          <RuleList>
            <Rule enabled="true">
              <Name>R1</Name>
              <Action type="Proxy">101</Action>
            </Rule>
          </RuleList>
        </Profile>
        "#;
        let compact_rt = ProfileConfig::from_xml(compact_xml).unwrap().into_runtime(&[]).unwrap();
        assert_eq!(compact_rt.rules[0].action, Action::Proxy(101));

        let runtime = parsed.into_runtime(&[40001, 40080, 1053]).unwrap();
        assert!(runtime.proxy_nodes.contains_key(&101));
        assert_eq!(runtime.rules.len(), 2);
        assert_eq!(runtime.rules[0].name, "LocalBypass");
        assert_eq!(runtime.rules[1].action, Action::Proxy(101));

        let rebuilt = ProfileConfig::from_runtime(
            &runtime.proxy_nodes,
            &runtime.rules,
            &runtime.default_action,
        );
        assert_eq!(rebuilt, default_cfg);
    }

    #[test]
    fn test_config_store_atomic_persistence() {
        let mut path = std::env::current_dir().unwrap().join("target");
        path.push(format!("flowx_test_{}_{}.xml", std::process::id(), 1));
        let _ = std::fs::remove_file(&path);

        let store = ConfigStore::new(&path);
        let (runtime, created) = store.load_or_init(&[40001, 40080]).unwrap();
        assert!(created);
        assert!(path.exists());

        let nodes = RwLock::new(runtime.proxy_nodes);
        let engine = RuleEngine::new(runtime.rules, runtime.default_action);

        // 追加一条规则并持久化
        engine.add_rule(Rule::from_raw(
            "BlockAds",
            false,
            None,
            Some("*.ads.example"),
            Some("443"),
            Action::Block,
        ));
        store.save_runtime(&nodes, &engine).unwrap();

        // 重新加载验证
        let (reloaded, created2) = store.load_or_init(&[40001, 40080]).unwrap();
        assert!(!created2);
        assert_eq!(reloaded.rules.len(), 3);
        assert_eq!(reloaded.rules[2].name, "BlockAds");
        assert!(!reloaded.rules[2].enabled);
        assert_eq!(reloaded.rules[2].action, Action::Block);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_config_rejects_missing_referenced_node() {
        let bad_xml = r#"
        <Profile version="1">
          <RuleList>
            <Rule enabled="true">
              <Name>Broken</Name>
              <Action type="Proxy">999</Action>
            </Rule>
          </RuleList>
        </Profile>
        "#;
        let cfg = ProfileConfig::from_xml(bad_xml).unwrap();
        assert!(cfg.into_runtime(&[]).is_err());
    }

    #[test]
    fn test_config_rejects_unknown_fields_and_unsupported_chain() {
        let typo_tag_xml = r#"
        <Profile version="1">
          <RuleList>
            <Rule enabled="true">
              <Name>TypoRule</Name>
              <Target>*.evil.com</Target>
              <Action type="Block"/>
            </Rule>
          </RuleList>
        </Profile>
        "#;
        assert!(ProfileConfig::from_xml(typo_tag_xml).is_err());

        let typo_attr_xml = r#"
        <Profile version="1">
          <RuleList>
            <Rule enable="false">
              <Name>TypoAttr</Name>
              <Action type="Block"/>
            </Rule>
          </RuleList>
        </Profile>
        "#;
        assert!(ProfileConfig::from_xml(typo_attr_xml).is_err());

        let chain_xml = r#"
        <Profile version="1">
          <RuleList>
            <Rule enabled="true">
              <Name>BrokenChain</Name>
              <Action type="Chain">1</Action>
            </Rule>
          </RuleList>
        </Profile>
        "#;
        let parsed = ProfileConfig::from_xml(chain_xml).unwrap();
        assert!(parsed.into_runtime(&[]).is_err());
    }

    #[test]
    fn test_config_rejects_fake_ip_and_local_interface_self_port_node() {
        let fake_xml = r#"
        <Profile version="1">
          <ProxyList>
            <Proxy id="1" type="SOCKS5">
              <Name>FakeNode</Name>
              <Address>198.18.0.10</Address>
              <Port>1080</Port>
            </Proxy>
          </ProxyList>
        </Profile>
        "#;
        let fake_cfg = ProfileConfig::from_xml(fake_xml).unwrap();
        assert!(fake_cfg.into_runtime(&[40001, 40080]).is_err());

        let local_ip = crate::outbound::local_interface_ips()
            .into_iter()
            .find(|ip| !ip.is_loopback() && !ip.is_unspecified())
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let iface_xml = format!(
            r#"
        <Profile version="1">
          <ProxyList>
            <Proxy id="1" type="HTTP">
              <Name>SelfIface</Name>
              <Address>{}</Address>
              <Port>40080</Port>
            </Proxy>
          </ProxyList>
        </Profile>
        "#,
            local_ip
        );
        let iface_cfg = ProfileConfig::from_xml(&iface_xml).unwrap();
        assert!(iface_cfg.into_runtime(&[40001, 40080]).is_err());
    }

    #[test]
    fn test_config_legacy_orphan_username_downgrades_with_warning() {
        let legacy_xml = r#"
        <Profile version="1">
          <ProxyList>
            <Proxy id="101" type="SOCKS5">
              <Name>LegacyS5</Name>
              <Address>10.0.0.2</Address>
              <Port>1080</Port>
              <Username>orphan-user</Username>
            </Proxy>
            <Proxy id="102" type="HTTP">
              <Name>LegacyHttpEmptyPass</Name>
              <Address>10.0.0.3</Address>
              <Port>8080</Port>
              <Username>orphan:http</Username>
              <Password></Password>
            </Proxy>
          </ProxyList>
        </Profile>
        "#;
        let rt = ProfileConfig::from_xml(legacy_xml)
            .unwrap()
            .into_runtime(&[40001, 40080])
            .expect("Legacy orphan username without password (even containing ':') should downgrade cleanly on startup");
        assert_eq!(rt.proxy_nodes[&101].username, None);
        assert_eq!(rt.proxy_nodes[&101].client.auth_credentials(), (None, None));
        assert_eq!(rt.proxy_nodes[&102].username, None);
        assert_eq!(rt.proxy_nodes[&102].client.auth_credentials(), (None, None));

        // Paired HTTP username containing ':' still fails
        let bad_http_colon = r#"
        <Profile version="1">
          <ProxyList>
            <Proxy id="104" type="HTTP">
              <Name>HttpColonPaired</Name>
              <Address>10.0.0.5</Address>
              <Port>8080</Port>
              <Username>bad:user</Username>
              <Password>secret</Password>
            </Proxy>
          </ProxyList>
        </Profile>
        "#;
        assert!(ProfileConfig::from_xml(bad_http_colon).unwrap().into_runtime(&[]).is_err());

        // SOCKS4 with <Password> (even empty) and control characters on metadata fields must fail
        for bad_node_xml in [
            r#"<Profile version="1"><ProxyList><Proxy id="1" type="SOCKS4"><Address>10.0.0.2</Address><Port>1080</Port><Password></Password></Proxy></ProxyList></Profile>"#,
            r#"<Profile version="1"><ProxyList><Proxy id="1" type="SOCKS4"><Address>10.0.0.2</Address><Port>1080</Port><Password>pw</Password></Proxy></ProxyList></Profile>"#,
            "<Profile version=\"1\"><ProxyList><Proxy id=\"1\" type=\"SOCKS5\"><Name>bad\tname</Name><Address>10.0.0.2</Address><Port>1080</Port></Proxy></ProxyList></Profile>",
            "<Profile version=\"1\"><ProxyList><Proxy id=\"1\" type=\"SOCKS5\"><Address>10.0.0.2</Address><Port>1080</Port><Username>alice</Username><Password>pw&#x1b;x</Password></Proxy></ProxyList></Profile>",
        ] {
            let parsed = ProfileConfig::from_xml(bad_node_xml).unwrap();
            assert!(parsed.into_runtime(&[]).is_err(), "expected validation failure for {}", bad_node_xml);
        }

        // Password without username still fails fast
        let bad_pw_only = r#"
        <Profile version="1">
          <ProxyList>
            <Proxy id="103" type="SOCKS5">
              <Name>PwOnly</Name>
              <Address>10.0.0.4</Address>
              <Port>1080</Port>
              <Password>secret</Password>
            </Proxy>
          </ProxyList>
        </Profile>
        "#;
        assert!(ProfileConfig::from_xml(bad_pw_only).unwrap().into_runtime(&[]).is_err());
    }

    #[test]
    fn test_config_rejects_wrong_root_xml_and_empty_xml() {
        let wrong_root = r#"
        <OtherRoot version="1">
          <ProxyList />
          <RuleList />
        </OtherRoot>
        "#;
        let err = ProfileConfig::from_xml(wrong_root).unwrap_err();
        assert!(
            err.to_string().contains("expected <Profile>"),
            "unexpected error: {err}"
        );
        assert!(ProfileConfig::from_xml("   ").is_err());

        // Valid self-closing <Profile /> succeeds
        let empty_profile = r#"<?xml version="1.0" encoding="utf-8"?><Profile version="1"/>"#;
        assert!(ProfileConfig::from_xml(empty_profile).is_ok());

        // Prefixed <ns:Profile>, multiple root elements, and trailing non-whitespace content are rejected
        for bad_xml in [
            r#"<ns:Profile version="1" xmlns:ns="http://example.com"><ProxyList/></ns:Profile>"#,
            r#"<Profile version="1"/><OtherRoot/>"#,
            r#"<Profile version="1"><ProxyList/></Profile>trailing-junk"#,
        ] {
            assert!(
                ProfileConfig::from_xml(bad_xml).is_err(),
                "expected XML validation failure for {}",
                bad_xml
            );
        }

        // Concurrent load_or_init inside workspace target dir produces a valid config file cleanly
        let tmp = std::env::current_dir().unwrap().join("target").join(format!(
            "flowx_init_lock_{}_{}.xml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&tmp);
        let store = std::sync::Arc::new(ConfigStore::new(&tmp));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let s = std::sync::Arc::clone(&store);
            handles.push(std::thread::spawn(move || s.load_or_init(&[]).unwrap()));
        }
        let mut created_count = 0usize;
        for h in handles {
            let (_, created) = h.join().unwrap();
            if created {
                created_count += 1;
            }
        }
        assert_eq!(created_count, 1);
        let _ = std::fs::remove_file(&tmp);
    }
}
