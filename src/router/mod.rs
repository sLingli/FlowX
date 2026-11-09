use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use glob::Pattern;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use self::parser::DomainMatcher;

pub mod parser;

static NEXT_RULE_ID: AtomicU64 = AtomicU64::new(1);

/// 未命中任何规则、走兜底动作时使用的规则名标记。
///
/// 该值是机器可读的内部标记（会随连接快照进入 `/api/connections`），
/// 展示层需要按当前语言替换为 `action.default_rule`，不应直接把该常量当作文案输出。
pub const DEFAULT_RULE_NAME: &str = "Default";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Direct,
    Block,
    Proxy(u32),
    Chain(u32),
}

impl Action {
    /// 机器可读的动作类型（保持英文，供 API/前端做分支判断，不参与 i18n）
    pub fn type_str(&self) -> &'static str {
        match self {
            Action::Direct => "Direct",
            Action::Block => "Block",
            Action::Proxy(_) => "Proxy",
            Action::Chain(_) => "Chain",
        }
    }

    /// 动作引用的代理节点/链路 ID；`Direct` 与 `Block` 返回 None
    pub fn target_id(&self) -> Option<u32> {
        match self {
            Action::Proxy(id) | Action::Chain(id) => Some(*id),
            Action::Direct | Action::Block => None,
        }
    }

    /// 由机器可读类型与目标 ID 还原动作，用于在展示层按语言格式化
    pub fn from_parts(type_str: &str, target_id: Option<u32>) -> Self {
        match type_str {
            "Block" => Action::Block,
            "Proxy" => Action::Proxy(target_id.unwrap_or_default()),
            "Chain" => Action::Chain(target_id.unwrap_or_default()),
            _ => Action::Direct,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleView {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub apps: String,
    pub targets: String,
    pub ports: String,
    pub action: String,
    pub action_type: String,
    pub node_id: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub apps_raw: String,
    pub targets_raw: String,
    pub ports_raw: String,
    pub application_patterns: Option<Vec<Pattern>>,
    pub target_domains: Option<Vec<DomainMatcher>>,
    pub target_subnets: Option<Vec<IpNet>>,
    pub ports: Option<Vec<PortRange>>,
    pub action: Action,
}

impl Rule {
    pub fn from_raw(
        name: impl Into<String>,
        enabled: bool,
        apps_raw: Option<&str>,
        targets_raw: Option<&str>,
        ports_raw: Option<&str>,
        action: Action,
    ) -> Self {
        let id = NEXT_RULE_ID.fetch_add(1, Ordering::Relaxed);
        let application_patterns = apps_raw.and_then(parser::parse_applications);

        let (target_domains, target_subnets) = targets_raw
            .map(parser::parse_targets)
            .unwrap_or((None, None));

        let ports = ports_raw.and_then(parser::parse_ports);

        Self {
            id,
            name: name.into(),
            enabled,
            apps_raw: apps_raw.unwrap_or_default().to_string(),
            targets_raw: targets_raw.unwrap_or_default().to_string(),
            ports_raw: ports_raw.unwrap_or_default().to_string(),
            application_patterns,
            target_domains,
            target_subnets,
            ports,
            action,
        }
    }
}

pub struct RouteContext<'a> {
    pub process_path: Option<&'a str>,
    pub process_name: Option<&'a str>,
    pub target_host: Option<&'a str>,
    pub target_ip: Option<IpAddr>,
    pub target_port: u16,
}

pub struct RuleEngine {
    rules: RwLock<Arc<Vec<Rule>>>,
    pub default_action: Action,
}

impl RuleEngine {
    pub fn new(rules: Vec<Rule>, default_action: Action) -> Self {
        Self {
            rules: RwLock::new(Arc::new(rules)),
            default_action,
        }
    }

    pub fn current_rules(&self) -> Arc<Vec<Rule>> {
        let guard = self.rules.read().unwrap_or_else(|e| e.into_inner());
        Arc::clone(&*guard)
    }

    pub fn list_rules_view(&self) -> Vec<RuleView> {
        self.list_rules_view_with_locale(crate::i18n::Locale::Zh)
    }

    pub fn list_rules_view_with_locale(&self, locale: crate::i18n::Locale) -> Vec<RuleView> {
        let rules = self.current_rules();
        rules
            .iter()
            .map(|r| {
                let action_desc = format_action_desc(&r.action, locale);
                let (action_type, node_id) = match &r.action {
                    Action::Direct => ("Direct".to_string(), None),
                    Action::Block => ("Block".to_string(), None),
                    Action::Proxy(id) => ("Proxy".to_string(), Some(*id)),
                    Action::Chain(id) => ("Chain".to_string(), Some(*id)),
                };
                RuleView {
                    id: r.id,
                    name: r.name.clone(),
                    enabled: r.enabled,
                    apps: r.apps_raw.clone(),
                    targets: r.targets_raw.clone(),
                    ports: r.ports_raw.clone(),
                    action: action_desc,
                    action_type,
                    node_id,
                }
            })
            .collect()
    }

    pub fn add_rule(&self, rule: Rule) {
        let mut guard = self.rules.write().unwrap_or_else(|e| e.into_inner());
        let mut new_rules = (**guard).clone();
        new_rules.push(rule);
        *guard = Arc::new(new_rules);
    }

    pub fn delete_rule(&self, rule_id: u64) -> bool {
        let mut guard = self.rules.write().unwrap_or_else(|e| e.into_inner());
        let before_len = guard.len();
        let new_rules: Vec<Rule> = (**guard).iter().filter(|r| r.id != rule_id).cloned().collect();
        if new_rules.len() < before_len {
            *guard = Arc::new(new_rules);
            true
        } else {
            false
        }
    }

    /// 切换或显式设置指定规则的启用状态，返回更新后的启用状态；若规则不存在返回 None
    pub fn toggle_rule(&self, rule_id: u64, enabled: Option<bool>) -> Option<bool> {
        let mut guard = self.rules.write().unwrap_or_else(|e| e.into_inner());
        let mut new_rules = (**guard).clone();
        let target = new_rules.iter_mut().find(|r| r.id == rule_id)?;
        let next = enabled.unwrap_or(!target.enabled);
        target.enabled = next;
        *guard = Arc::new(new_rules);
        Some(next)
    }

    /// 调整规则顺序 (支持 "up" / "down" / "top" / "bottom")；
    /// 返回 Some(true) 表示位置发生变化，Some(false) 表示已在边界无需移动，None 表示规则不存在
    pub fn move_rule(&self, rule_id: u64, direction: &str) -> Option<bool> {
        let mut guard = self.rules.write().unwrap_or_else(|e| e.into_inner());
        let mut new_rules = (**guard).clone();
        let idx = new_rules.iter().position(|r| r.id == rule_id)?;
        let len = new_rules.len();
        let changed = match direction.trim().to_ascii_lowercase().as_str() {
            "up" if idx > 0 => {
                new_rules.swap(idx, idx - 1);
                true
            }
            "down" if idx + 1 < len => {
                new_rules.swap(idx, idx + 1);
                true
            }
            "top" if idx > 0 => {
                let item = new_rules.remove(idx);
                new_rules.insert(0, item);
                true
            }
            "bottom" if idx + 1 < len => {
                let item = new_rules.remove(idx);
                new_rules.push(item);
                true
            }
            "up" | "down" | "top" | "bottom" => false,
            _ => return None,
        };
        if changed {
            *guard = Arc::new(new_rules);
        }
        Some(changed)
    }

    /// 按照自顶向下顺序对流量进行求值匹配 (First Match Wins)，基于不可变快照零锁争用
    pub fn evaluate(&self, ctx: &RouteContext) -> (Action, String) {
        let rules = self.current_rules();
        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            // 1. 匹配应用程序 (Fail-Closed: 若配置了规则但列表为空，绝不放行)
            if let Some(patterns) = &rule.application_patterns {
                if patterns.is_empty() {
                    continue;
                }
                let mut app_matched = false;
                if let Some(pname) = ctx.process_name {
                    let pname_normalized = pname.to_lowercase().replace('\\', "/");
                    for pat in patterns {
                        if pat.matches(&pname_normalized) {
                            app_matched = true;
                            break;
                        }
                    }
                }
                if !app_matched
                    && let Some(path) = ctx.process_path {
                        let path_normalized = path.to_lowercase().replace('\\', "/");
                        for pat in patterns {
                            if pat.matches(&path_normalized) {
                                app_matched = true;
                                break;
                            }
                        }
                }
                if !app_matched {
                    continue;
                }
            }

            // 2. 匹配端口
            if let Some(ports) = &rule.ports {
                if ports.is_empty() {
                    continue;
                }
                let port_matched = ports.iter().any(|r| {
                    ctx.target_port >= r.start && ctx.target_port <= r.end
                });
                if !port_matched {
                    continue;
                }
            }

            // 3. 匹配目标地址 (域名通配或 IP/CIDR)
            if rule.target_domains.is_some() || rule.target_subnets.is_some() {
                let mut target_matched = false;

                // 检查 IP/CIDR
                if let Some(subnets) = &rule.target_subnets
                    && let Some(ip) = ctx.target_ip
                        && subnets.iter().any(|subnet| subnet.contains(&ip)) {
                            target_matched = true;
                        }

                // 检查域名（已预编译，支持 apex 匹配与通配）
                if !target_matched
                    && let Some(domains) = &rule.target_domains
                        && let Some(host) = ctx.target_host {
                            for matcher in domains {
                                if matcher.matches(host) {
                                    target_matched = true;
                                    break;
                                }
                            }
                        }

                if !target_matched {
                    continue;
                }
            }

            return (rule.action.clone(), rule.name.clone());
        }

        (self.default_action.clone(), DEFAULT_RULE_NAME.to_string())
    }
}

pub fn format_action_desc(action: &Action, locale: crate::i18n::Locale) -> String {
    match action {
        Action::Direct => crate::i18n::t(locale, "action.direct").to_string(),
        Action::Block => crate::i18n::t(locale, "action.block").to_string(),
        Action::Proxy(id) => crate::i18n::t(locale, "action.proxy_prefix").replace("{}", &id.to_string()),
        Action::Chain(id) => crate::i18n::t(locale, "action.chain_prefix").replace("{}", &id.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_matching_flow() {
        let r1 = Rule::from_raw(
            "LocalBypass",
            true,
            None,
            Some("127.0.0.1; localhost; 192.168.0.0/16"),
            None,
            Action::Direct,
        );

        let r2 = Rule::from_raw(
            "NodeProxy",
            true,
            Some("node.exe; *code*.exe"),
            Some("*.github.com; *.npm.org"),
            Some("443; 80"),
            Action::Proxy(101),
        );

        let engine = RuleEngine::new(vec![r1, r2], Action::Block);

        // 1. 测试本地回环命中 r1
        let ctx_local = RouteContext {
            process_path: Some("C:/any.exe"),
            process_name: Some("any.exe"),
            target_host: Some("localhost"),
            target_ip: Some("127.0.0.1".parse().unwrap()),
            target_port: 8080,
        };
        let (action, rule_name) = engine.evaluate(&ctx_local);
        assert_eq!(action, Action::Direct);
        assert_eq!(rule_name, "LocalBypass");

        // 2. 测试 node 进程命中 r2 (验证 *.github.com 匹配 api.github.com 以及 github.com)
        let ctx_node = RouteContext {
            process_path: Some(r"C:\Program Files\nodejs\node.exe"),
            process_name: Some("node.exe"),
            target_host: Some("github.com"),
            target_ip: None,
            target_port: 443,
        };
        let (action_node, rule_name_node) = engine.evaluate(&ctx_node);
        assert_eq!(action_node, Action::Proxy(101));
        assert_eq!(rule_name_node, "NodeProxy");

        // 3. 测试未命中走 Default 兜底 Action::Block
        let ctx_other = RouteContext {
            process_path: Some("C:/other.exe"),
            process_name: Some("other.exe"),
            target_host: Some("blocked.com"),
            target_ip: Some("8.8.8.8".parse().unwrap()),
            target_port: 53,
        };
        let (action_other, rule_name_other) = engine.evaluate(&ctx_other);
        assert_eq!(action_other, Action::Block);
        assert_eq!(rule_name_other, "Default");
    }

    #[test]
    fn test_rule_view_and_deletion() {
        let r1 = Rule::from_raw("RuleA", true, None, None, None, Action::Direct);
        let id1 = r1.id;
        let r2 = Rule::from_raw("RuleB", true, None, None, None, Action::Block);
        let id2 = r2.id;

        let engine = RuleEngine::new(vec![r1, r2], Action::Direct);
        let views = engine.list_rules_view();
        assert_eq!(views.len(), 2);
        assert_eq!(views[0].id, id1);
        assert_eq!(views[1].id, id2);

        assert!(engine.delete_rule(id1));
        assert_eq!(engine.list_rules_view().len(), 1);
        assert_eq!(engine.list_rules_view()[0].id, id2);
        assert!(!engine.delete_rule(id1));
    }

    #[test]
    fn test_rule_toggle_and_reorder() {
        let r1 = Rule::from_raw("First", true, None, None, None, Action::Direct);
        let r2 = Rule::from_raw("Second", true, None, None, None, Action::Block);
        let r3 = Rule::from_raw("Third", true, None, None, None, Action::Direct);
        let (id1, id2, id3) = (r1.id, r2.id, r3.id);

        let engine = RuleEngine::new(vec![r1, r2, r3], Action::Direct);

        assert_eq!(engine.toggle_rule(id2, None), Some(false));
        assert!(!engine.list_rules_view()[1].enabled);
        assert_eq!(engine.toggle_rule(id2, Some(true)), Some(true));
        assert!(engine.list_rules_view()[1].enabled);
        assert_eq!(engine.toggle_rule(999999, None), None);

        // First 已经在顶部，up 返回 Some(false)
        assert_eq!(engine.move_rule(id1, "up"), Some(false));
        assert_eq!(engine.move_rule(id3, "up"), Some(true));
        let ids: Vec<u64> = engine.list_rules_view().into_iter().map(|v| v.id).collect();
        assert_eq!(ids, vec![id1, id3, id2]);

        assert_eq!(engine.move_rule(id2, "top"), Some(true));
        let ids2: Vec<u64> = engine.list_rules_view().into_iter().map(|v| v.id).collect();
        assert_eq!(ids2, vec![id2, id1, id3]);
    }
}
