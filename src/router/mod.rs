use std::net::IpAddr;
use glob::Pattern;
use ipnet::IpNet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Direct,
    Block,
    Proxy(u32),
    Chain(u32),
}

#[derive(Debug, Clone)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub enabled: bool,
    pub application_patterns: Vec<Pattern>,
    pub target_patterns: Vec<String>,
    pub target_subnets: Vec<IpNet>,
    pub ports: Vec<PortRange>,
    pub action: Action,
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

    /// 按照自顶向下顺序对流量进行求值匹配 (First Match Wins)
    pub fn evaluate(&self, ctx: &RouteContext) -> Action {
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            // 1. 匹配应用程序
            if !rule.application_patterns.is_empty() {
                let mut app_matched = false;
                if let Some(pname) = ctx.process_name {
                    let pname_lower = pname.to_lowercase();
                    for pat in &rule.application_patterns {
                        if pat.matches(&pname_lower) {
                            app_matched = true;
                            break;
                        }
                    }
                }
                if !app_matched && ctx.process_path.is_some() {
                    let path_lower = ctx.process_path.unwrap().to_lowercase();
                    for pat in &rule.application_patterns {
                        if pat.matches(&path_lower) {
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
            if !rule.ports.is_empty() {
                let port_matched = rule.ports.iter().any(|r| {
                    ctx.target_port >= r.start && ctx.target_port <= r.end
                });
                if !port_matched {
                    continue;
                }
            }

            // 3. 匹配目标地址 (域名通配或 IP/CIDR)
            if !rule.target_patterns.is_empty() || !rule.target_subnets.is_empty() {
                let mut target_matched = false;

                // 检查 IP/CIDR
                if let Some(ip) = ctx.target_ip {
                    if rule.target_subnets.iter().any(|subnet| subnet.contains(&ip)) {
                        target_matched = true;
                    }
                }

                // 检查域名
                if !target_matched {
                    if let Some(host) = ctx.target_host {
                        let host_lower = host.to_lowercase();
                        for pat_str in &rule.target_patterns {
                            if let Ok(pattern) = Pattern::new(&pat_str.to_lowercase()) {
                                if pattern.matches(&host_lower) {
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

            return rule.action.clone();
        }

        self.default_action.clone()
    }
}
