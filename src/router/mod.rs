use std::net::IpAddr;
use glob::Pattern;
use ipnet::IpNet;
use self::parser::DomainMatcher;

pub mod parser;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Direct,
    Block,
    Proxy(u32),
    Chain(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub enabled: bool,
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
        let application_patterns = apps_raw.and_then(parser::parse_applications);

        let (target_domains, target_subnets) = targets_raw
            .map(parser::parse_targets)
            .unwrap_or((None, None));

        let ports = ports_raw.and_then(parser::parse_ports);

        Self {
            name: name.into(),
            enabled,
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
    pub rules: Vec<Rule>,
    pub default_action: Action,
}

impl RuleEngine {
    pub fn new(rules: Vec<Rule>, default_action: Action) -> Self {
        Self {
            rules,
            default_action,
        }
    }

    /// 按照自顶向下顺序对流量进行求值匹配 (First Match Wins)，带 Fail-Closed 约束保护
    pub fn evaluate(&self, ctx: &RouteContext) -> (Action, String) {
        for rule in &self.rules {
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
                if !app_matched && ctx.process_path.is_some() {
                    let path_normalized = ctx.process_path.unwrap().to_lowercase().replace('\\', "/");
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
                if let Some(subnets) = &rule.target_subnets {
                    if let Some(ip) = ctx.target_ip {
                        if subnets.iter().any(|subnet| subnet.contains(&ip)) {
                            target_matched = true;
                        }
                    }
                }

                // 检查域名（已预编译，支持 apex 匹配与通配）
                if !target_matched {
                    if let Some(domains) = &rule.target_domains {
                        if let Some(host) = ctx.target_host {
                            for matcher in domains {
                                if matcher.matches(host) {
                                    target_matched = true;
                                    break;
                                }
                            }
                        }
                    }
                }

                if !target_matched {
                    continue;
                }
            }

            return (rule.action.clone(), rule.name.clone());
        }

        (self.default_action.clone(), "Default".to_string())
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
}
