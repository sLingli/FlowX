use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use self::parser::{AppMatcher, DomainMatcher};

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
    pub application_patterns: Option<Vec<AppMatcher>>,
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
        Self::from_raw_with_id(id, name, enabled, apps_raw, targets_raw, ports_raw, action)
    }

    pub fn from_raw_with_id(
        id: u64,
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

    pub fn to_view(&self, locale: crate::i18n::Locale) -> RuleView {
        let action_desc = format_action_desc(&self.action, locale);
        let (action_type, node_id) = match &self.action {
            Action::Direct => ("Direct".to_string(), None),
            Action::Block => ("Block".to_string(), None),
            Action::Proxy(id) => ("Proxy".to_string(), Some(*id)),
            Action::Chain(id) => ("Chain".to_string(), Some(*id)),
        };
        RuleView {
            id: self.id,
            name: self.name.clone(),
            enabled: self.enabled,
            apps: self.apps_raw.clone(),
            targets: self.targets_raw.clone(),
            ports: self.ports_raw.clone(),
            action: action_desc,
            action_type,
            node_id,
        }
    }

    /// 仅评估启用状态与应用进程约束（供端口无关的 DNS 预判与通用匹配复用）
    pub fn matches_app_only(&self, ctx: &RouteContext) -> Result<(), &'static str> {
        if !self.enabled {
            return Err("disabled");
        }

        // 1. 匹配应用程序 (Fail-Closed: 若配置了规则但列表为空，绝不放行)
        // 候选侧仅在末尾存在 `.exe` 时附加剥离变体（不反向凭空拼出 `.exe`），保证 `*.exe` / `*.*` 不误命中无后缀二进制；
        // 无 `/` 的规则仅匹配进程名，含 `/` 的路径规则开启字面分隔符限制匹配完整路径。
        if let Some(patterns) = &self.application_patterns {
            if patterns.is_empty() {
                return Err("app_mismatch");
            }
            let pname_norm = ctx
                .process_name
                .map(|p| p.to_lowercase().replace('\\', "/"));
            let mut name_cands: Vec<&str> = Vec::with_capacity(2);
            if let Some(ref pn) = pname_norm {
                name_cands.push(pn.as_str());
                if let Some(stem) = pn.strip_suffix(".exe")
                    && !stem.is_empty()
                {
                    name_cands.push(stem);
                }
            }

            let path_norm = ctx
                .process_path
                .map(|p| p.to_lowercase().replace('\\', "/"));
            let mut path_cands: Vec<&str> = Vec::with_capacity(2);
            if let Some(ref pp) = path_norm {
                path_cands.push(pp.as_str());
                if let Some(stem) = pp.strip_suffix(".exe")
                    && !stem.is_empty()
                {
                    path_cands.push(stem);
                }
            }

            let app_matched = patterns
                .iter()
                .any(|matcher| matcher.matches(&name_cands, &path_cands));
            if !app_matched {
                return Err("app_mismatch");
            }
        }

        Ok(())
    }

    fn matches_domain(&self, qname: &str) -> bool {
        self.target_domains
            .as_ref()
            .is_some_and(|domains| domains.iter().any(|d| d.matches(qname)))
    }

    fn matches_port_only(&self, target_port: u16) -> Result<(), &'static str> {
        if let Some(ports) = &self.ports {
            if ports.is_empty() {
                return Err("port_mismatch");
            }
            let port_matched = ports
                .iter()
                .any(|r| target_port >= r.start && target_port <= r.end);
            if !port_matched {
                return Err("port_mismatch");
            }
        }
        Ok(())
    }

    /// 仅评估启用状态、应用进程与端口约束，不校验目标域名或 IP/CIDR（供透明代理预判是否需嗅探域名）
    ///
    /// 命中返回 `Ok(())`，未命中返回 `"disabled"` | `"app_mismatch"` | `"port_mismatch"`。
    pub fn matches_app_and_port(&self, ctx: &RouteContext) -> Result<(), &'static str> {
        self.matches_app_only(ctx)?;
        self.matches_port_only(ctx.target_port)
    }

    /// 评估当前规则是否命中给定流量上下文；命中返回 `Ok(())`，未命中返回原因码：
    /// `"disabled"` | `"app_mismatch"` | `"port_mismatch"` | `"target_mismatch"`
    pub fn check_match(&self, ctx: &RouteContext) -> Result<(), &'static str> {
        self.matches_app_and_port(ctx)?;

        // 3. 匹配目标地址 (域名通配或 IP/CIDR)
        if self.target_domains.is_some() || self.target_subnets.is_some() {
            let mut target_matched = false;

            // 检查 IP/CIDR
            if let Some(subnets) = &self.target_subnets
                && let Some(ip) = ctx.target_ip
                && subnets.iter().any(|subnet| subnet.contains(&ip))
            {
                target_matched = true;
            }

            // 检查域名（已预编译，支持 apex 匹配与通配）
            if !target_matched
                && let Some(domains) = &self.target_domains
                && let Some(host) = ctx.target_host
            {
                for matcher in domains {
                    if matcher.matches(host) {
                        target_matched = true;
                        break;
                    }
                }
            }

            if !target_matched {
                return Err("target_mismatch");
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleTraceStep {
    pub index: usize,
    pub rule_id: u64,
    pub rule_name: String,
    pub enabled: bool,
    pub matched: bool,
    /// "disabled" | "app_mismatch" | "port_mismatch" | "target_mismatch" | "matched"
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteSimulationResult {
    pub matched_rule_id: Option<u64>,
    pub matched_rule_name: String,
    pub is_default: bool,
    pub action: Action,
    pub trace: Vec<RuleTraceStep>,
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
    default_action: RwLock<Action>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainNeedDecision {
    /// 无需域名嗅探即可立即确定路由动作（命中靠前无域名依赖规则、已命中 IP 规则或后续无可能命中该端口/进程的域名规则）
    Immediate(Action),
    /// 存在靠前的按域名匹配规则可能命中当前进程/端口，需等待客户端首包并嗅探 SNI / Host
    NeedsDomainSniff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsHijackDecision {
    /// 放行至真实上游 DNS（保留 AAAA / HTTPS / SVCB / QUIC / 内网记录，不注入 Fake-IP）
    Passthrough,
    /// 该 (进程, 查询域名) 可能命中非直连规则，由透明 Fake-IP DNS 接管
    Hijack,
}

fn cached_local_interface_ips() -> Vec<IpAddr> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<(std::time::Instant, Vec<IpAddr>)>> =
        std::sync::OnceLock::new();
    const TTL: std::time::Duration = std::time::Duration::from_secs(5);

    let now = std::time::Instant::now();
    let lock = CACHE.get_or_init(|| {
        std::sync::Mutex::new((now, crate::outbound::local_interface_ips()))
    });
    let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
    if now.duration_since(guard.0) >= TTL {
        guard.1 = crate::outbound::local_interface_ips();
        guard.0 = now;
    }
    guard.1.clone()
}

/// 判定是否为可安全剪枝本机/LAN域名（`localhost` / `%ComputerName%`）的远端非本机单播 IP：
/// 覆盖公网 IP 及非本机网卡持有的远端私网 (`10/8` / `172.16/12` / CGNAT / ULA)，
/// 仅对本机实际网卡 IP、链路本地 (`169.254/16`/`fe80::/10`)、环回与 Fake-IP 保留 `%ComputerName%` 域名保护。
fn is_remote_non_local_unicast_ip(ip: IpAddr) -> bool {
    let canon = ip.to_canonical();
    let basic_remote = match canon {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_multicast()
                && !v4.is_unspecified()
                && !(a == 198 && (b & 0xFE) == 18)
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                && (seg0 & 0xffc0) != 0xfe80
        }
    };
    if !basic_remote {
        return false;
    }
    let local_ips = cached_local_interface_ips();
    !crate::outbound::is_local_or_loopback_ip(canon, &local_ips)
}

fn rule_has_applicable_domain(
    domains: &[DomainMatcher],
    target_ip: Option<IpAddr>,
    local_hostname: &str,
) -> bool {
    if domains.is_empty() {
        return false;
    }
    if target_ip.is_some_and(is_remote_non_local_unicast_ip) {
        domains.iter().any(|d| !d.is_host_local(local_hostname))
    } else {
        true
    }
}

/// 绝不分配 Fake-IP 的本机 / mDNS / 反向解析 / 单标签主机名集合
fn is_non_hijackable_local_qname(qname: &str, local_hostname: &str) -> bool {
    let norm = qname.trim().trim_end_matches('.');
    if norm.is_empty() || !norm.contains('.') {
        return true;
    }
    let lower = norm.to_ascii_lowercase();
    let local_norm = local_hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    lower == "localhost"
        || lower.ends_with(".localhost")
        || lower.ends_with(".local")
        || lower.ends_with(".lan")
        || lower.ends_with(".home.arpa")
        || lower == "arpa"
        || lower.ends_with(".arpa")
        || (!local_norm.is_empty() && lower == local_norm)
}

impl RuleEngine {
    pub fn new(rules: Vec<Rule>, default_action: Action) -> Self {
        Self {
            rules: RwLock::new(Arc::new(rules)),
            default_action: RwLock::new(default_action),
        }
    }

    pub fn default_action(&self) -> Action {
        self.default_action
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn set_default_action(&self, action: Action) {
        let mut guard = self
            .default_action
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *guard = action;
    }

    pub fn current_rules(&self) -> Arc<Vec<Rule>> {
        let guard = self.rules.read().unwrap_or_else(|e| e.into_inner());
        Arc::clone(&*guard)
    }

    /// 捕获规则列表与默认兜底动作的一致性快照，供持久化失败时回滚
    pub fn snapshot_state(&self) -> (Vec<Rule>, Action) {
        let rules = self.current_rules();
        let default_action = self.default_action();
        ((*rules).clone(), default_action)
    }

    /// 将内存规则列表与默认兜底动作回滚到先前快照
    pub fn restore_state(&self, rules: Vec<Rule>, default_action: Action) {
        {
            let mut r_guard = self.rules.write().unwrap_or_else(|e| e.into_inner());
            *r_guard = Arc::new(rules);
        }
        self.set_default_action(default_action);
    }

    pub fn list_rules_view(&self) -> Vec<RuleView> {
        self.list_rules_view_with_locale(crate::i18n::Locale::Zh)
    }

    pub fn list_rules_view_with_locale(&self, locale: crate::i18n::Locale) -> Vec<RuleView> {
        let rules = self.current_rules();
        rules.iter().map(|r| r.to_view(locale)).collect()
    }

    pub fn add_rule(&self, rule: Rule) {
        let mut guard = self.rules.write().unwrap_or_else(|e| e.into_inner());
        let mut new_rules = (**guard).clone();
        new_rules.push(rule);
        *guard = Arc::new(new_rules);
    }

    /// 原地更新指定 ID 的规则（保留原规则 ID、启用状态与优先级顺序），返回更新后的规则副本
    pub fn update_rule(
        &self,
        rule_id: u64,
        name: String,
        apps_raw: Option<&str>,
        targets_raw: Option<&str>,
        ports_raw: Option<&str>,
        action: Action,
    ) -> Option<Rule> {
        self.update_rule_with_enabled(rule_id, name, apps_raw, targets_raw, ports_raw, action, None)
    }

    /// 原地更新规则，并可选原子修改启用状态（供 PATCH 端点使用）
    #[allow(clippy::too_many_arguments)]
    pub fn update_rule_with_enabled(
        &self,
        rule_id: u64,
        name: String,
        apps_raw: Option<&str>,
        targets_raw: Option<&str>,
        ports_raw: Option<&str>,
        action: Action,
        enabled: Option<bool>,
    ) -> Option<Rule> {
        let mut guard = self.rules.write().unwrap_or_else(|e| e.into_inner());
        let mut new_rules = (**guard).clone();
        let slot = new_rules.iter_mut().find(|r| r.id == rule_id)?;
        let updated = Rule::from_raw_with_id(
            rule_id,
            name,
            enabled.unwrap_or(slot.enabled),
            apps_raw,
            targets_raw,
            ports_raw,
            action,
        );
        *slot = updated.clone();
        *guard = Arc::new(new_rules);
        Some(updated)
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
            if rule.check_match(ctx).is_ok() {
                return (rule.action.clone(), rule.name.clone());
            }
        }

        (self.default_action(), DEFAULT_RULE_NAME.to_string())
    }

    /// 判断仅依据进程、端口与目标 IP 是否已可安全决定动作，或前方是否存在可能匹配当前流的域名规则
    ///
    /// 仅当返回 `DomainNeedDecision::Immediate(Action::Direct)` 且目标非 Fake-IP 时，
    /// 透明代理旁路才可直接在驱动层零拷贝放行真实 IP 连接；一旦存在靠前且与兜底动作不同的域名规则，
    /// 必须返回 `DomainNeedDecision::NeedsDomainSniff` 以便先接入用户态嗅探 SNI / Host。
    pub fn needs_domain_for_routing(
        &self,
        process_path: Option<&str>,
        process_name: Option<&str>,
        target_ip: Option<std::net::IpAddr>,
        target_port: u16,
    ) -> DomainNeedDecision {
        let ctx = RouteContext {
            process_path,
            process_name,
            target_host: None,
            target_ip,
            target_port,
        };
        let local_hostname = parser::resolve_local_hostname();
        let rules = self.current_rules();
        let mut speculative_actions: Vec<Action> = Vec::new();

        for rule in rules.iter() {
            if rule.matches_app_and_port(&ctx).is_err() {
                continue;
            }
            if rule.target_domains.is_none() && rule.target_subnets.is_none() {
                let fallback = rule.action.clone();
                if speculative_actions.iter().all(|a| a == &fallback) {
                    return DomainNeedDecision::Immediate(fallback);
                }
                return DomainNeedDecision::NeedsDomainSniff;
            }
            if let Some(subnets) = &rule.target_subnets
                && let Some(ip) = target_ip
                && subnets.iter().any(|subnet| subnet.contains(&ip))
            {
                let fallback = rule.action.clone();
                if speculative_actions.iter().all(|a| a == &fallback) {
                    return DomainNeedDecision::Immediate(fallback);
                }
                return DomainNeedDecision::NeedsDomainSniff;
            }
            if let Some(domains) = &rule.target_domains
                && rule_has_applicable_domain(domains, target_ip, &local_hostname)
            {
                speculative_actions.push(rule.action.clone());
            }
        }

        let fallback = self.default_action();
        if speculative_actions.iter().all(|a| a == &fallback) {
            DomainNeedDecision::Immediate(fallback)
        } else {
            DomainNeedDecision::NeedsDomainSniff
        }
    }

    /// 结合进程与实际 DNS QNAME 判断 UDP/53 查询是否需要注入 Fake-IP，
    /// 对共享系统 DNS 解析器（如 Windows `svchost.exe` `Dnscache`）绝不允许无域名约束的应用规则（如 `DevProxy`）污染全机缓存，
    /// 并遵守全局直连规则优先级及端口限定隔离原则。
    pub fn classify_dns_query(
        &self,
        process_path: Option<&str>,
        process_name: Option<&str>,
        qname: &str,
        is_shared_system_dns: bool,
    ) -> DnsHijackDecision {
        let local_hostname = parser::resolve_local_hostname();
        if is_non_hijackable_local_qname(qname, &local_hostname) {
            return DnsHijackDecision::Passthrough;
        }

        let ctx = RouteContext {
            process_path,
            process_name,
            target_host: Some(qname),
            target_ip: None,
            target_port: 0,
        };
        let rules = self.current_rules();
        let mut saw_other_app_domain_hijack = false;

        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }
            // 无域名目标却仅限端口的规则（如仅 port 22 -> Block）不应在无端口语义的 DNS 阶段劫持整域 Fake-IP；
            // 若规则同时限定了目标域名与端口（如 ports=22 + *.foo -> Block），必须在 DNS 阶段保留域名识别通道以免非 HTTP/TLS 协议绕过。
            if rule.target_domains.is_none() && rule.ports.is_some() {
                continue;
            }

            if !is_shared_system_dns {
                if rule.matches_app_only(&ctx).is_err() {
                    continue;
                }
                let matched_qname = (rule.target_domains.is_none()
                    && rule.target_subnets.is_none()
                    && rule.ports.is_none())
                    || rule.matches_domain(qname);
                if !matched_qname {
                    continue;
                }
                if rule.action != Action::Direct {
                    return DnsHijackDecision::Hijack;
                }
                if rule.ports.is_none() {
                    return DnsHijackDecision::Passthrough;
                }
                continue;
            }

            // 共享系统 DNS（如 svchost.exe）：
            // 1) 显式限定到其他应用的规则：仅当其明确指定域名且命中 qname 且非 Direct 时记录候选劫持，
            //    绝不允许 target_domains=None 的仅应用规则（如 DevProxy）劫持全机 Dnscache，也不抢先覆盖后续全局 Direct 规则；
            // 2) 全局无应用限定或显式匹配 svchost.exe 的规则按顺序权威生效。
            let explicitly_scoped_to_other_app = rule.application_patterns.is_some()
                && rule.matches_app_only(&ctx).is_err();

            if explicitly_scoped_to_other_app {
                if rule.target_domains.is_some()
                    && rule.matches_domain(qname)
                    && rule.action != Action::Direct
                {
                    saw_other_app_domain_hijack = true;
                }
                continue;
            }

            let matched_qname = (rule.target_domains.is_none()
                && rule.target_subnets.is_none()
                && rule.ports.is_none())
                || rule.matches_domain(qname);
            if !matched_qname {
                continue;
            }
            if rule.action != Action::Direct {
                return DnsHijackDecision::Hijack;
            }
            if rule.ports.is_none() {
                return DnsHijackDecision::Passthrough;
            }
        }

        if saw_other_app_domain_hijack || self.default_action() != Action::Direct {
            DnsHijackDecision::Hijack
        } else {
            DnsHijackDecision::Passthrough
        }
    }

    /// 当共享系统 DNS（如 `svchost.exe`）因避免污染直连进程而对某外部域名返回 `Passthrough` 时，
    /// 检查规则集内是否存在被前序全局/系统直连规则放行、后续可达的仅限应用全通代理规则（如 `DevProxy`）。
    /// 若存在，则透明层应进入 `InspectDns`（透传真实解析并缓存 IP->域名，必要时对 NXDOMAIN/投毒救援分配 Fake-IP）。
    pub fn should_inspect_shared_dns_for_app_proxy(
        &self,
        process_path: Option<&str>,
        process_name: Option<&str>,
        qname: &str,
    ) -> bool {
        let local_hostname = parser::resolve_local_hostname();
        if is_non_hijackable_local_qname(qname, &local_hostname) {
            return false;
        }

        let ctx = RouteContext {
            process_path,
            process_name,
            target_host: Some(qname),
            target_ip: None,
            target_port: 0,
        };
        let rules = self.current_rules();

        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }
            if rule.target_domains.is_none() && rule.ports.is_some() {
                continue;
            }

            let explicitly_scoped_to_other_app =
                rule.application_patterns.is_some() && rule.matches_app_only(&ctx).is_err();

            if explicitly_scoped_to_other_app {
                if rule.target_domains.is_none()
                    && rule.target_subnets.is_none()
                    && rule.ports.is_none()
                    && matches!(rule.action, Action::Proxy(_) | Action::Chain(_))
                {
                    return true;
                }
                continue;
            }

            let matched_qname = (rule.target_domains.is_none()
                && rule.target_subnets.is_none()
                && rule.ports.is_none())
                || rule.matches_domain(qname);
            if matched_qname && rule.ports.is_none() && rule.action == Action::Direct {
                return false;
            }
        }

        false
    }

    /// 当首包阶段 PID 未知时，判断给定 `(target_ip, target_port)` 前方是否存在可达的非 `Direct` 应用级规则（如 `DevProxy`）。
    ///
    /// 若在无条件全局匹配终止之前存在任何可能命中的 `application_patterns` 非 `Direct` 规则，则返回 `true`，
    /// 防止 `NetstackEngine` 在驱动层 PID 竞态缺失时误将代理流量永久写入直连 `passthrough` 缓存。
    pub fn has_reachable_app_scoped_override(
        &self,
        target_ip: Option<IpAddr>,
        target_port: u16,
    ) -> bool {
        let local_hostname = parser::resolve_local_hostname();
        let rules = self.current_rules();

        for rule in rules.iter() {
            if !rule.enabled || rule.matches_port_only(target_port).is_err() {
                continue;
            }
            let wildcard_target = rule.target_domains.is_none() && rule.target_subnets.is_none();
            let subnet_matched = rule
                .target_subnets
                .as_ref()
                .is_some_and(|subs| target_ip.is_some_and(|ip| subs.iter().any(|s| s.contains(&ip))));
            let domain_applicable = rule
                .target_domains
                .as_ref()
                .is_some_and(|domains| rule_has_applicable_domain(domains, target_ip, &local_hostname));

            if !(wildcard_target || subnet_matched || domain_applicable) {
                continue;
            }

            if rule.application_patterns.is_none() {
                // 任意应用都会命中的明确规则（无目标约束或 IP 已命中）：后续应用级规则不可能再被执行
                if (wildcard_target || subnet_matched) && rule.action == Action::Direct {
                    return false;
                }
                if rule.action != Action::Direct {
                    return true;
                }
            } else if rule.action != Action::Direct {
                return true;
            }
        }

        self.default_action() != Action::Direct
    }

    /// 模拟流量路由并返回完整的逐条规则匹配与跳过原因诊断轨迹
    pub fn simulate(&self, ctx: &RouteContext) -> RouteSimulationResult {
        let rules = self.current_rules();
        let mut trace = Vec::with_capacity(rules.len());

        for (index, rule) in rules.iter().enumerate() {
            match rule.check_match(ctx) {
                Ok(()) => {
                    trace.push(RuleTraceStep {
                        index,
                        rule_id: rule.id,
                        rule_name: rule.name.clone(),
                        enabled: rule.enabled,
                        matched: true,
                        reason: "matched".to_string(),
                    });
                    return RouteSimulationResult {
                        matched_rule_id: Some(rule.id),
                        matched_rule_name: rule.name.clone(),
                        is_default: false,
                        action: rule.action.clone(),
                        trace,
                    };
                }
                Err(reason) => {
                    trace.push(RuleTraceStep {
                        index,
                        rule_id: rule.id,
                        rule_name: rule.name.clone(),
                        enabled: rule.enabled,
                        matched: false,
                        reason: reason.to_string(),
                    });
                }
            }
        }

        RouteSimulationResult {
            matched_rule_id: None,
            matched_rule_name: DEFAULT_RULE_NAME.to_string(),
            is_default: true,
            action: self.default_action(),
            trace,
        }
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

    #[test]
    fn test_update_rule_preserves_id_and_order_and_default_action_updates() {
        let r1 = Rule::from_raw("First", true, Some("a.exe"), None, None, Action::Direct);
        let r2 = Rule::from_raw("Second", false, Some("b.exe"), Some("example.com"), Some("80"), Action::Block);
        let r3 = Rule::from_raw("Third", true, Some("c.exe"), None, None, Action::Direct);
        let (id1, id2, id3) = (r1.id, r2.id, r3.id);

        let engine = RuleEngine::new(vec![r1, r2, r3], Action::Direct);

        // 原地更新中间规则 r2，验证 ID、禁用状态与列表顺序保持不变
        let updated = engine
            .update_rule(
                id2,
                "SecondEdited".to_string(),
                Some("git.exe"),
                Some("*.github.com"),
                Some("443"),
                Action::Proxy(101),
            )
            .expect("rule should be updated");
        assert_eq!(updated.id, id2);
        assert!(!updated.enabled);
        assert_eq!(updated.name, "SecondEdited");

        let views = engine.list_rules_view();
        assert_eq!(views.iter().map(|v| v.id).collect::<Vec<_>>(), vec![id1, id2, id3]);
        assert_eq!(views[1].name, "SecondEdited");
        assert_eq!(views[1].apps, "git.exe");
        assert_eq!(views[1].targets, "*.github.com");
        assert_eq!(views[1].ports, "443");
        assert_eq!(views[1].node_id, Some(101));

        // 不存在的规则 ID 返回 None
        assert!(
            engine
                .update_rule(999999, "Nope".to_string(), None, None, None, Action::Block)
                .is_none()
        );

        // 动态修改 default_action
        assert_eq!(engine.default_action(), Action::Direct);
        engine.set_default_action(Action::Proxy(102));
        assert_eq!(engine.default_action(), Action::Proxy(102));
    }

    #[test]
    fn test_simulate_route_trace_and_reasons() {
        let r_disabled = Rule::from_raw("DisabledRule", false, None, None, None, Action::Block);
        let r_app = Rule::from_raw("OnlyCurl", true, Some("curl.exe"), None, None, Action::Direct);
        let r_port = Rule::from_raw("OnlySsh", true, Some("git.exe"), None, Some("22"), Action::Direct);
        let r_target = Rule::from_raw(
            "GitInternal",
            true,
            Some("git.exe"),
            Some("*.internal.corp"),
            Some("443"),
            Action::Direct,
        );
        let r_github = Rule::from_raw(
            "GitHubProxy",
            true,
            Some("git.exe"),
            Some("*.github.com"),
            Some("443"),
            Action::Proxy(101),
        );
        let match_id = r_github.id;

        let engine = RuleEngine::new(
            vec![r_disabled, r_app, r_port, r_target, r_github],
            Action::Block,
        );

        let ctx = RouteContext {
            process_path: Some(r"C:\Program Files\Git\bin\git.exe"),
            process_name: Some("git.exe"),
            target_host: Some("api.github.com"),
            target_ip: None,
            target_port: 443,
        };
        let sim = engine.simulate(&ctx);
        assert!(!sim.is_default);
        assert_eq!(sim.matched_rule_id, Some(match_id));
        assert_eq!(sim.matched_rule_name, "GitHubProxy");
        assert_eq!(sim.action, Action::Proxy(101));
        assert_eq!(sim.trace.len(), 5);
        assert_eq!(sim.trace[0].reason, "disabled");
        assert_eq!(sim.trace[1].reason, "app_mismatch");
        assert_eq!(sim.trace[2].reason, "port_mismatch");
        assert_eq!(sim.trace[3].reason, "target_mismatch");
        assert_eq!(sim.trace[4].reason, "matched");
        assert!(sim.trace[4].matched);

        // 未命中任何规则时回退至 Default
        let ctx_miss = RouteContext {
            process_path: Some(r"C:\Program Files\Git\bin\git.exe"),
            process_name: Some("git.exe"),
            target_host: Some("gitlab.com"),
            target_ip: None,
            target_port: 443,
        };
        let sim_miss = engine.simulate(&ctx_miss);
        assert!(sim_miss.is_default);
        assert_eq!(sim_miss.matched_rule_id, None);
        assert_eq!(sim_miss.matched_rule_name, DEFAULT_RULE_NAME);
        assert_eq!(sim_miss.action, Action::Block);
        assert_eq!(sim_miss.trace.len(), 5);
        assert!(sim_miss.trace.iter().all(|s| !s.matched));
    }

    #[test]
    fn test_cross_platform_exe_suffix_matching() {
        // Windows 风格规则 (.exe) 应命中 Linux 无后缀进程
        let win_rule = Rule::from_raw(
            "WinStyle",
            true,
            Some("node.exe; *chrome*.exe; *git*.exe"),
            None,
            None,
            Action::Proxy(101),
        );
        for (name, path) in [
            ("node", "/usr/bin/node"),
            ("google-chrome", "/opt/google/chrome/google-chrome"),
            ("git", "/usr/bin/git"),
        ] {
            let ctx = RouteContext {
                process_path: Some(path),
                process_name: Some(name),
                target_host: Some("example.com"),
                target_ip: None,
                target_port: 443,
            };
            assert!(win_rule.check_match(&ctx).is_ok(), "{name} should match .exe rule");
        }

        // 目录包含 `git` 但进程名不是 `git` 的 `/home/git/curl` 不应被 `*git*.exe` 跨 `/` 误命中
        let ctx_dir_collision = RouteContext {
            process_path: Some("/home/git/curl"),
            process_name: Some("curl"),
            target_host: Some("example.com"),
            target_ip: None,
            target_port: 443,
        };
        assert_eq!(win_rule.check_match(&ctx_dir_collision), Err("app_mismatch"));

        // `*.exe` 与 `*.*` 绝不命中无扩展名的 Linux/macOS 进程或未知进程 None
        let ext_rule = Rule::from_raw("ExeAndExt", true, Some("*.exe; *.*"), None, None, Action::Block);
        let ctx_linux_no_ext = RouteContext {
            process_path: Some("/usr/bin/curl"),
            process_name: Some("curl"),
            target_host: Some("example.com"),
            target_ip: None,
            target_port: 443,
        };
        assert_eq!(ext_rule.check_match(&ctx_linux_no_ext), Err("app_mismatch"));
        let ctx_unknown_none = RouteContext {
            process_path: None,
            process_name: None,
            target_host: Some("example.com"),
            target_ip: None,
            target_port: 443,
        };
        assert_eq!(ext_rule.check_match(&ctx_unknown_none), Err("app_mismatch"));

        // Linux 风格规则 (无后缀) 应命中 Windows .exe 进程，且路径规则同样双向兼容与字面 `/` 隔离
        let linux_rule = Rule::from_raw(
            "LinuxStyle",
            true,
            Some("curl; /usr/bin/wget; /home/*/app"),
            None,
            None,
            Action::Direct,
        );
        let ctx_win = RouteContext {
            process_path: Some(r"C:\Windows\System32\curl.exe"),
            process_name: Some("curl.exe"),
            target_host: Some("example.com"),
            target_ip: None,
            target_port: 443,
        };
        assert!(linux_rule.check_match(&ctx_win).is_ok());
        let ctx_wget = RouteContext {
            process_path: Some("/usr/bin/wget"),
            process_name: Some("wget"),
            target_host: Some("example.com"),
            target_ip: None,
            target_port: 80,
        };
        assert!(linux_rule.check_match(&ctx_wget).is_ok());
        let ctx_nested_path = RouteContext {
            process_path: Some("/home/user/sub/app"),
            process_name: Some("app"),
            target_host: Some("example.com"),
            target_ip: None,
            target_port: 80,
        };
        assert_eq!(linux_rule.check_match(&ctx_nested_path), Err("app_mismatch"));

        // 不相关进程不应误命中
        let ctx_other = RouteContext {
            process_path: Some("/usr/bin/python3"),
            process_name: Some("python3"),
            target_host: Some("example.com"),
            target_ip: None,
            target_port: 443,
        };
        assert_eq!(win_rule.check_match(&ctx_other), Err("app_mismatch"));
        assert_eq!(linux_rule.check_match(&ctx_other), Err("app_mismatch"));
    }

    #[test]
    fn test_needs_domain_for_routing_decisions() {
        let engine = RuleEngine::new(
            vec![
                Rule::from_raw("DisabledDomain", false, None, Some("disabled.example"), None, Action::Proxy(1)),
                Rule::from_raw("GameDirect", true, Some("game.exe"), None, None, Action::Direct),
                Rule::from_raw("LanDirect", true, None, Some("192.168.0.0/16"), None, Action::Direct),
                Rule::from_raw("ChromeSniProxy", true, Some("chrome.exe"), Some("*.google.com"), Some("443"), Action::Proxy(1)),
            ],
            Action::Direct,
        );

        let public_ip: std::net::IpAddr = "8.8.8.8".parse().unwrap();
        let lan_ip: std::net::IpAddr = "192.168.1.10".parse().unwrap();

        // GameDirect matches app cleanly before any domain rule -> Immediate(Direct)
        assert_eq!(
            engine.needs_domain_for_routing(Some(r"C:\Games\game.exe"), Some("game.exe"), Some(public_ip), 443),
            DomainNeedDecision::Immediate(Action::Direct)
        );

        // LAN IP matches earlier CIDR rule even for Chrome:443 -> Immediate(Direct)
        assert_eq!(
            engine.needs_domain_for_routing(Some(r"C:\Program Files\chrome.exe"), Some("chrome.exe"), Some(lan_ip), 443),
            DomainNeedDecision::Immediate(Action::Direct)
        );

        // Chrome on 443 to public IP can match ChromeSniProxy if domain is google.com -> NeedsDomainSniff
        assert_eq!(
            engine.needs_domain_for_routing(Some(r"C:\Program Files\chrome.exe"), Some("chrome.exe"), Some(public_ip), 443),
            DomainNeedDecision::NeedsDomainSniff
        );

        // Chrome on port 22 cannot match ChromeSniProxy (port 443) and DisabledDomain is ignored -> Immediate(Direct)
        assert_eq!(
            engine.needs_domain_for_routing(Some(r"C:\Program Files\chrome.exe"), Some("chrome.exe"), Some(public_ip), 22),
            DomainNeedDecision::Immediate(Action::Direct)
        );

        // Unrelated app on 443 cannot match ChromeSniProxy -> Immediate(Direct default)
        assert_eq!(
            engine.needs_domain_for_routing(Some("/usr/bin/ssh"), Some("ssh"), Some(public_ip), 443),
            DomainNeedDecision::Immediate(Action::Direct)
        );
    }

    #[test]
    fn test_local_bypass_pruning_and_selective_dns_classification() {
        let local_host = parser::resolve_local_hostname();
        let profile_engine = RuleEngine::new(
            vec![
                Rule::from_raw(
                    "LocalBypass",
                    true,
                    None,
                    Some("127.0.0.1; localhost; %ComputerName%; ::1; 192.168.0.0/16"),
                    None,
                    Action::Direct,
                ),
                Rule::from_raw(
                    "DevProxy",
                    true,
                    Some("node.exe; *chrome*.exe; *git*.exe; *antigravity*.exe"),
                    None,
                    None,
                    Action::Proxy(101),
                ),
            ],
            Action::Direct,
        );

        let public_ip: IpAddr = "142.250.1.1".parse().unwrap();
        let private_192: IpAddr = "192.168.1.50".parse().unwrap();
        let private_10: IpAddr = "10.0.0.5".parse().unwrap();

        // Direct 应用访问公网 IP：LocalBypass 仅含本机域名且与兜底 Direct 同效，绝不触发 SNI 嗅探
        assert_eq!(
            profile_engine.needs_domain_for_routing(
                Some(r"C:\Windows\System32\curl.exe"),
                Some("curl.exe"),
                Some(public_ip),
                443,
            ),
            DomainNeedDecision::Immediate(Action::Direct)
        );

        // DevProxy 应用访问公网 IP：LocalBypass 忽略本机域名 -> 直接 Immediate(Proxy(101))，免去 120ms SNI 等待
        assert_eq!(
            profile_engine.needs_domain_for_routing(
                Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
                Some("chrome.exe"),
                Some(public_ip),
                443,
            ),
            DomainNeedDecision::Immediate(Action::Proxy(101))
        );

        // DevProxy 应用访问 192.168/16 -> 命中 LocalBypass Subnet -> Immediate(Direct)
        assert_eq!(
            profile_engine.needs_domain_for_routing(
                Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
                Some("chrome.exe"),
                Some(private_192),
                8080,
            ),
            DomainNeedDecision::Immediate(Action::Direct)
        );

        // DevProxy 应用访问非本机持有的远端私网 IP（例如非本机 NIC 地址的 10/8）-> 剪枝 LocalBypass 本机域名，直接 Immediate(Proxy(101))
        let remote_10_ip = if !crate::outbound::local_interface_ips().contains(&private_10) {
            private_10
        } else {
            "10.254.254.254".parse().unwrap()
        };
        assert_eq!(
            profile_engine.needs_domain_for_routing(
                Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
                Some("chrome.exe"),
                Some(remote_10_ip),
                8080,
            ),
            DomainNeedDecision::Immediate(Action::Proxy(101))
        );
        // 若确实是本机某张网卡自身持有的地址（或环回/链路本地），则继续保留 %ComputerName% 域名保护
        if let Some(local_iface_ip) = crate::outbound::local_interface_ips()
            .into_iter()
            .find(|ip| !ip.is_loopback() && !ip.is_unspecified())
        {
            assert_eq!(
                profile_engine.needs_domain_for_routing(
                    Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
                    Some("chrome.exe"),
                    Some(local_iface_ip),
                    8080,
                ),
                DomainNeedDecision::NeedsDomainSniff
            );
        }

        // P0-1 防回归：default_profile 下 DevProxy（仅限应用且无域名条件）绝不劫持 svchost.exe 共享系统 DNS，
        // 避免 Fake-IP 198.18.x.x 污染 Dnscache 导致全机直连软件失效或丢失 AAAA/QUIC/ICMP；
        // 本地 / mDNS / 环回名及纯 Direct 规则集下同样放行 svchost.exe。
        assert_eq!(
            profile_engine.classify_dns_query(
                Some(r"C:\Windows\System32\svchost.exe"),
                Some("svchost.exe"),
                "www.baidu.com",
                true,
            ),
            DnsHijackDecision::Passthrough
        );
        assert_eq!(
            profile_engine.classify_dns_query(
                Some(r"C:\Windows\System32\svchost.exe"),
                Some("svchost.exe"),
                "github.com",
                true,
            ),
            DnsHijackDecision::Passthrough
        );
        assert_eq!(
            profile_engine.classify_dns_query(
                Some(r"C:\Windows\System32\svchost.exe"),
                Some("svchost.exe"),
                "printer.local",
                true,
            ),
            DnsHijackDecision::Passthrough
        );
        let direct_only_engine = RuleEngine::new(
            vec![Rule::from_raw(
                "LocalBypass",
                true,
                None,
                Some("127.0.0.1; localhost; %ComputerName%; ::1; 192.168.0.0/16"),
                None,
                Action::Direct,
            )],
            Action::Direct,
        );
        assert_eq!(
            direct_only_engine.classify_dns_query(
                Some(r"C:\Windows\System32\svchost.exe"),
                Some("svchost.exe"),
                "www.baidu.com",
                true,
            ),
            DnsHijackDecision::Passthrough
        );

        // 若应用自身进程直接发出 UDP/53 查询，则按其自身规则精准判定
        assert_eq!(
            profile_engine.classify_dns_query(
                Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
                Some("chrome.exe"),
                "github.com",
                false,
            ),
            DnsHijackDecision::Hijack
        );
        assert_eq!(
            profile_engine.classify_dns_query(
                Some(r"C:\Windows\System32\curl.exe"),
                Some("curl.exe"),
                "www.baidu.com",
                false,
            ),
            DnsHijackDecision::Passthrough
        );

        // P1-3：端口限定规则隔离、共享 DNS 优先级（后续全局 Direct 覆盖靠前特定应用域名代理）、本机/mDNS/rDNS/单标签主机名测试
        let mixed_engine = RuleEngine::new(
            vec![
                Rule::from_raw(
                    "BypassDirect",
                    true,
                    None,
                    Some("direct.example"),
                    None,
                    Action::Direct,
                ),
                Rule::from_raw(
                    "BypassHttpsOnly",
                    true,
                    None,
                    Some("halfdirect.example"),
                    Some("443"),
                    Action::Direct,
                ),
                Rule::from_raw(
                    "GameUdpProxy",
                    true,
                    Some("game.exe"),
                    Some("*.game.example"),
                    Some("7777"),
                    Action::Proxy(101),
                ),
                Rule::from_raw(
                    "SshPortBlock",
                    true,
                    None,
                    Some("*.sshport.example"),
                    Some("22"),
                    Action::Block,
                ),
                Rule::from_raw(
                    "PurePort22Block",
                    true,
                    None,
                    None,
                    Some("22"),
                    Action::Block,
                ),
                Rule::from_raw(
                    "ChromeCnProxy",
                    true,
                    Some("chrome.exe"),
                    Some("*.cn"),
                    None,
                    Action::Proxy(101),
                ),
                Rule::from_raw(
                    "GlobalCnDirect",
                    true,
                    None,
                    Some("*.cn"),
                    None,
                    Action::Direct,
                ),
                Rule::from_raw(
                    "AppSpecificDomainProxy",
                    true,
                    Some("ssh.exe"),
                    Some("*.corp-tunnel.example"),
                    None,
                    Action::Proxy(101),
                ),
                Rule::from_raw(
                    "FallbackGlobalProxy",
                    true,
                    None,
                    Some("*.proxy.example"),
                    None,
                    Action::Proxy(101),
                ),
            ],
            Action::Direct,
        );

        // “域名 + 端口”规则（ports=7777 + *.game.example，或 ports=22 + *.sshport.example）在 DNS 阶段必须劫持保留域名以免 SSH/二进制协议绕过；
        // 无域名目标的纯端口规则（ports=22, targets=None）不劫持无关域名 DNS；端口限定 Direct 规则也不抢先放行其它端口
        assert_eq!(
            mixed_engine.classify_dns_query(None, Some("svchost.exe"), "login.game.example", true),
            DnsHijackDecision::Hijack
        );
        assert_eq!(
            mixed_engine.classify_dns_query(None, Some("game.exe"), "login.game.example", false),
            DnsHijackDecision::Hijack
        );
        assert_eq!(
            mixed_engine.classify_dns_query(None, Some("svchost.exe"), "host.sshport.example", true),
            DnsHijackDecision::Hijack
        );
        assert_eq!(
            mixed_engine.classify_dns_query(None, Some("svchost.exe"), "unrelated.org", true),
            DnsHijackDecision::Passthrough
        );
        // 全局 Direct 域名规则不得被靠前的其他应用专属规则反超劫持 shared Dnscache
        assert_eq!(
            mixed_engine.classify_dns_query(None, Some("svchost.exe"), "www.baidu.cn", true),
            DnsHijackDecision::Passthrough
        );
        // 但 chrome.exe 自身直发 UDP/53 仍优先匹配其靠前专属规则 ChromeCnProxy
        assert_eq!(
            mixed_engine.classify_dns_query(None, Some("chrome.exe"), "www.baidu.cn", false),
            DnsHijackDecision::Hijack
        );
        // 无端口限定的显式应用域名代理规则在无后续全局 Direct 冲突时，允许在 svchost.exe 阶段预分配 Fake-IP
        assert_eq!(
            mixed_engine.classify_dns_query(None, Some("svchost.exe"), "git.corp-tunnel.example", true),
            DnsHijackDecision::Hijack
        );
        // 端口限定 Direct 规则（BypassHttpsOnly: 443）不抢先放行其它端口：若下方存在同域其它端口代理规则，仍须返回 Hijack
        let port_override_engine = RuleEngine::new(
            vec![
                Rule::from_raw("DirectHttpsOnly", true, None, Some("svc.example"), Some("443"), Action::Direct),
                Rule::from_raw("ProxyRestExample", true, None, Some("*.example"), None, Action::Proxy(101)),
            ],
            Action::Direct,
        );
        assert_eq!(
            port_override_engine.classify_dns_query(None, Some("svchost.exe"), "svc.example", true),
            DnsHijackDecision::Hijack
        );
        assert_eq!(
            mixed_engine.classify_dns_query(None, Some("svchost.exe"), "halfdirect.example", true),
            DnsHijackDecision::Passthrough
        );

        // 即使全局默认代理，mDNS / .arpa / localhost / 单标签名 / 本机主机名也绝不被 Fake-IP 劫持
        let global_proxy = RuleEngine::new(
            vec![Rule::from_raw("DirectApex", true, None, Some("direct.example"), None, Action::Direct)],
            Action::Proxy(101),
        );
        assert_eq!(
            global_proxy.classify_dns_query(None, Some("svchost.exe"), "localhost", true),
            DnsHijackDecision::Passthrough
        );
        assert_eq!(
            global_proxy.classify_dns_query(None, Some("svchost.exe"), "printer.local", true),
            DnsHijackDecision::Passthrough
        );
        assert_eq!(
            global_proxy.classify_dns_query(None, Some("svchost.exe"), "1.0.0.127.in-addr.arpa", true),
            DnsHijackDecision::Passthrough
        );
        assert_eq!(
            global_proxy.classify_dns_query(None, Some("svchost.exe"), "intranetbox", true),
            DnsHijackDecision::Passthrough
        );
        assert_eq!(
            global_proxy.classify_dns_query(None, Some("svchost.exe"), &local_host, true),
            DnsHijackDecision::Passthrough
        );
        assert_eq!(
            global_proxy.classify_dns_query(None, Some("svchost.exe"), "direct.example", true),
            DnsHijackDecision::Passthrough
        );
        assert_eq!(
            global_proxy.classify_dns_query(None, Some("svchost.exe"), "public.example", true),
            DnsHijackDecision::Hijack
        );
    }
}
