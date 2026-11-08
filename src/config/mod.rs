use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::interceptor::dispatcher::ProxyNodeEntry;
use crate::outbound::chain::{parse_target_addr, ProxyNode};
use crate::outbound::http::HttpConnectClient;
use crate::outbound::socks4::Socks4Client;
use crate::outbound::socks5::Socks5Client;
use crate::outbound::TargetAddr;
use crate::router::{Action, Rule, RuleEngine};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename = "Profile")]
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
pub struct ProxyList {
    #[serde(rename = "Proxy", default)]
    pub proxies: Vec<ProxyItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
pub struct RuleList {
    #[serde(rename = "Rule", default)]
    pub rules: Vec<RuleItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    pub fn from_xml(xml_content: &str) -> Result<Self, quick_xml::DeError> {
        quick_xml::de::from_str(xml_content)
    }

    pub fn to_xml(&self) -> Result<String> {
        let mut buf = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        let mut ser = quick_xml::se::Serializer::new(&mut buf);
        ser.indent(' ', 2);
        self.serialize(ser).context("序列化 ProfileConfig 到 XML 失败")?;
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
                    name: Some("Node-101 (主节点)".to_string()),
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
                    bail!("配置文件中存在重复的代理节点 ID: {}", item.id);
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
                    bail!("配置文件中存在空名称的路由规则");
                }
                let action = parse_action(&item.action, &proxy_nodes)
                    .with_context(|| format!("规则 [{}] 的动作配置无效", name))?;
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
                .context("Proxy 动作缺少节点 ID")?;
            if !proxy_nodes.contains_key(&id) {
                bail!("引用了不存在的代理节点 ID: {}", id);
            }
            Ok(Action::Proxy(id))
        }
        "CHAIN" => {
            let id = item.value.context("Chain 动作缺少代理链 ID")?;
            Ok(Action::Chain(id))
        }
        other => bail!("不支持的规则动作类型: {}", other),
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
        bail!("节点 #{} 使用了不受支持的代理协议: {}", item.id, item.proxy_type);
    }
    let address = item.address.trim();
    if address.is_empty() || item.port == 0 {
        bail!("节点 #{} 地址或端口无效", item.id);
    }
    let server_addr = format_host_port(address, item.port);
    let target_parsed = parse_target_addr(&server_addr)
        .with_context(|| format!("节点 #{} 地址格式无效: {}", item.id, server_addr))?;
    if target_parsed.is_loopback_or_unspecified() && self_ports.contains(&target_parsed.port()) {
        bail!("节点 #{} 地址指向 FlowX 自身服务端口: {}", item.id, server_addr);
    }

    let username = item
        .username
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty());
    let password = item.password.filter(|p| !p.is_empty());
    let name = item
        .name
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| format!("Node-{} ({})", item.id, proto));

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

    /// 从磁盘加载配置；若文件不存在则生成默认配置并写入磁盘
    pub fn load_or_init(&self, self_ports: &[u16]) -> Result<(RuntimeProfile, bool)> {
        if self.path.exists() {
            let xml = std::fs::read_to_string(&self.path)
                .with_context(|| format!("读取配置文件失败: {}", self.path.display()))?;
            let cfg = ProfileConfig::from_xml(&xml)
                .with_context(|| format!("解析 XML 配置文件失败: {}", self.path.display()))?;
            let runtime = cfg.into_runtime(self_ports)?;
            Ok((runtime, false))
        } else {
            let default_cfg = ProfileConfig::default_profile();
            self.write_config_atomic(&default_cfg)?;
            let runtime = default_cfg.into_runtime(self_ports)?;
            Ok((runtime, true))
        }
    }

    /// 串行化读取当前内存快照并原子写回 XML 文件
    pub fn save_runtime(
        &self,
        proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
        rule_engine: &RuleEngine,
    ) -> Result<()> {
        let _guard = self.save_lock.lock().unwrap_or_else(|e| e.into_inner());
        let cfg = {
            let nodes_guard = proxy_nodes.read().unwrap_or_else(|e| e.into_inner());
            let rules = rule_engine.current_rules();
            ProfileConfig::from_runtime(&nodes_guard, &rules, &rule_engine.default_action)
        };
        self.write_config_atomic(&cfg)
    }

    fn write_config_atomic(&self, cfg: &ProfileConfig) -> Result<()> {
        let xml = cfg.to_xml()?;
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let mut tmp_os = self.path.as_os_str().to_os_string();
        tmp_os.push(".tmp");
        let tmp_path = PathBuf::from(tmp_os);
        std::fs::write(&tmp_path, xml.as_bytes())
            .with_context(|| format!("写入临时配置文件失败: {}", tmp_path.display()))?;
        std::fs::rename(&tmp_path, &self.path)
            .with_context(|| format!("原子替换配置文件失败: {}", self.path.display()))?;
        Ok(())
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
        let mut path = std::env::temp_dir();
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
}
