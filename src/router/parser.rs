use super::PortRange;
use glob::{MatchOptions, Pattern};
use ipnet::IpNet;
use std::net::IpAddr;

pub const APP_MATCH_OPTIONS: MatchOptions = MatchOptions {
    case_sensitive: false,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

#[derive(Debug, Clone)]
pub enum AppMatcher {
    /// 不含路径分隔符，仅匹配进程文件名（不扫完整路径，防止目录名误命中）
    Name(Pattern),
    /// 含路径分隔符，按字面分隔符 `/` 严格匹配完整进程路径
    Path(Pattern),
}

impl AppMatcher {
    pub fn matches(&self, name_candidates: &[&str], path_candidates: &[&str]) -> bool {
        match self {
            AppMatcher::Name(pat) => name_candidates
                .iter()
                .any(|cand| pat.matches_with(cand, APP_MATCH_OPTIONS)),
            AppMatcher::Path(pat) => path_candidates
                .iter()
                .any(|cand| pat.matches_with(cand, APP_MATCH_OPTIONS)),
        }
    }
}

#[derive(Debug, Clone)]
pub enum DomainMatcher {
    Exact(String),
    Suffix(String), // e.g. "google.com" for "*.google.com", matching "google.com" and "*.google.com"
    Pattern(Pattern),
}

impl DomainMatcher {
    pub fn parse(raw: &str) -> Option<Self> {
        // 统一去除末尾 FQDN 根点 `.` 并转小写，防止 `evil.com.` / `localhost.` 绕过匹配
        let s = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if s.is_empty() {
            return None;
        }
        if let Some(stripped) = s.strip_prefix("*.")
            && !stripped.is_empty()
            && !stripped.contains('*')
            && !stripped.contains('?')
            && !stripped.contains('[')
        {
            return Some(DomainMatcher::Suffix(stripped.to_string()));
        }
        if s.contains('*') || s.contains('?') || s.contains('[') {
            Pattern::new(&s).ok().map(DomainMatcher::Pattern)
        } else {
            Some(DomainMatcher::Exact(s))
        }
    }

    pub fn matches(&self, host: &str) -> bool {
        let host = host.trim().trim_end_matches('.');
        if host.is_empty() {
            return false;
        }
        match self {
            DomainMatcher::Exact(exact) => host.eq_ignore_ascii_case(exact),
            DomainMatcher::Suffix(suffix) => {
                // 无堆分配的两段式零拷贝域名后缀比对：匹配 apex 域自身或 `<sub.><suffix>`
                let suffix_bytes = suffix.as_bytes();
                let host_bytes = host.as_bytes();
                if host_bytes.len() == suffix_bytes.len() {
                    host_bytes.eq_ignore_ascii_case(suffix_bytes)
                } else if host_bytes.len() > suffix_bytes.len() + 1 {
                    let split = host_bytes.len() - suffix_bytes.len();
                    host_bytes[split - 1] == b'.'
                        && host_bytes[split..].eq_ignore_ascii_case(suffix_bytes)
                } else {
                    false
                }
            }
            DomainMatcher::Pattern(pat) => {
                if !host.bytes().any(|b| b.is_ascii_uppercase()) {
                    pat.matches(host)
                } else {
                    let host_lower = host.to_lowercase();
                    pat.matches(&host_lower)
                }
            }
        }
    }

    /// 判断域名匹配器是否仅针对本机自身标识（如 `localhost`、`*.localhost` 或当前主机名），
    /// 用于在访问公网单播 IP 时跳过不必要的 SNI/Host 嗅探，避免 `LocalBypass` 拖慢或污染透明代理。
    pub fn is_host_local(&self, local_hostname: &str) -> bool {
        let host_norm = local_hostname.trim().trim_end_matches('.');
        match self {
            DomainMatcher::Exact(exact) => {
                exact.eq_ignore_ascii_case("localhost")
                    || exact.ends_with(".localhost")
                    || (!host_norm.is_empty() && exact.eq_ignore_ascii_case(host_norm))
            }
            DomainMatcher::Suffix(suffix) => suffix.eq_ignore_ascii_case("localhost"),
            DomainMatcher::Pattern(_) => false,
        }
    }
}

/// 解析以分号分隔的应用程序路径/通配符（支持引号与 Fail-Closed 约束模式）
pub fn parse_applications(raw: &str) -> Option<Vec<AppMatcher>> {
    let trimmed_raw = raw.trim();
    if trimmed_raw.is_empty() {
        return None; // 无约束：匹配所有应用
    }

    let mut matchers = Vec::new();
    let tokens = split_quoted_tokens(trimmed_raw, ';');

    for token in tokens {
        let trimmed = token.trim().trim_matches('"').trim();
        if trimmed.is_empty() {
            continue;
        }
        // 统一转换为小写并处理路径分隔符为 '/'
        let normalized = trimmed.to_lowercase().replace('\\', "/");
        let is_path = normalized.contains('/');
        if let Ok(pat) = Pattern::new(&normalized) {
            matchers.push(if is_path {
                AppMatcher::Path(pat)
            } else {
                AppMatcher::Name(pat)
            });
        }
    }

    Some(matchers) // 即使为空也是 Some(vec![])，实现 Fail-Closed
}

/// 大小写不敏感替换纯 ASCII 占位符（利用 ASCII 字节在 UTF-8 中绝不与多字节序列重叠的性质确保切片安全）
fn replace_ascii_placeholder_ignore_case(input: &str, placeholder: &str, value: &str) -> String {
    debug_assert!(placeholder.is_ascii());
    let p_bytes = placeholder.as_bytes();
    let in_bytes = input.as_bytes();
    if p_bytes.is_empty() || in_bytes.len() < p_bytes.len() {
        return input.to_string();
    }

    let mut out: Option<String> = None;
    let mut last_copied = 0;
    let mut i = 0;
    while i + p_bytes.len() <= in_bytes.len() {
        if in_bytes[i..i + p_bytes.len()].eq_ignore_ascii_case(p_bytes) {
            let buf = out.get_or_insert_with(|| String::with_capacity(input.len()));
            buf.push_str(&input[last_copied..i]);
            buf.push_str(value);
            i += p_bytes.len();
            last_copied = i;
        } else {
            i += 1;
        }
    }

    match out {
        Some(mut buf) => {
            buf.push_str(&input[last_copied..]);
            buf
        }
        None => input.to_string(),
    }
}

/// 解析当前 Windows 主机名（读取 `COMPUTERNAME` 环境变量，缺省回退 `"localhost"`）
pub fn resolve_local_hostname() -> String {
    if let Ok(val) = std::env::var("COMPUTERNAME") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "localhost".to_string()
}

fn contains_ascii_ignore_case(haystack: &str, needle_lower: &[u8]) -> bool {
    haystack
        .as_bytes()
        .windows(needle_lower.len())
        .any(|w| w.eq_ignore_ascii_case(needle_lower))
}

fn is_safe_hostname_literal(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 255
        && !host.chars().any(|c| {
            c.is_control()
                || c.is_whitespace()
                || matches!(
                    c,
                    ';' | '"' | '\'' | '*' | '?' | '[' | ']' | '/' | '\\' | ':' | '@'
                )
        })
}

/// 仅对单个已按 `;` 拆分后的 token 展开 `%ComputerName%`（及历史兼容别名 `%HOSTNAME%`）占位符。
/// 返回 `Some((expanded, used_placeholder))` 表示可安全编译；
/// 返回 `None` 表示包含占位符但本机主机名含有分隔符/通配符/CIDR 等危险字符，已安全跳过。
fn expand_hostname_in_token(token: &str, resolved_host: Option<&str>) -> Option<(String, bool)> {
    let has_computername = contains_ascii_ignore_case(token, b"%computername%");
    let has_hostname = contains_ascii_ignore_case(token, b"%hostname%");
    if !has_computername && !has_hostname {
        return Some((token.to_string(), false));
    }

    let safe_host = resolved_host.filter(|h| is_safe_hostname_literal(h))?;
    let mut out = if has_computername {
        replace_ascii_placeholder_ignore_case(token, "%computername%", safe_host)
    } else {
        token.to_string()
    };
    if has_hostname {
        out = replace_ascii_placeholder_ignore_case(&out, "%hostname%", safe_host);
    }
    Some((out, true))
}

fn parse_targets_with_hostname(
    raw: &str,
    resolved_host_override: Option<&str>,
) -> (Option<Vec<DomainMatcher>>, Option<Vec<IpNet>>) {
    let trimmed_raw = raw.trim();
    if trimmed_raw.is_empty() {
        return (None, None);
    }

    let mut domain_patterns = Vec::new();
    let mut subnets = Vec::new();
    // 严格先按 `;` 拆分 token，再在单 token 内安全替换主机名占位符，杜绝主机名夹带 `;` 或引号发生目标注入
    let tokens = split_quoted_tokens(trimmed_raw, ';');
    let has_placeholder = tokens.iter().any(|t| {
        contains_ascii_ignore_case(t, b"%computername%")
            || contains_ascii_ignore_case(t, b"%hostname%")
    });
    let resolved_host = if has_placeholder {
        Some(
            resolved_host_override
                .map(ToString::to_string)
                .unwrap_or_else(resolve_local_hostname),
        )
    } else {
        None
    };

    for token in tokens {
        let unquoted = token.trim().trim_matches('"').trim();
        if unquoted.is_empty() {
            continue;
        }

        let Some((expanded, used_placeholder)) =
            expand_hostname_in_token(unquoted, resolved_host.as_deref())
        else {
            continue;
        };
        let trimmed = expanded.trim();
        if trimmed.is_empty() {
            continue;
        }

        if used_placeholder {
            // 经过主机名占位符展开的条目绝不允许再按 CIDR/IP 解析，且若原本就是裸占位符则仅构造成 Exact 域名匹配器
            if unquoted.eq_ignore_ascii_case("%computername%")
                || unquoted.eq_ignore_ascii_case("%hostname%")
            {
                let norm = trimmed.trim_end_matches('.').to_ascii_lowercase();
                if !norm.is_empty() {
                    domain_patterns.push(DomainMatcher::Exact(norm));
                }
            } else if let Some(matcher) = DomainMatcher::parse(trimmed) {
                domain_patterns.push(matcher);
            }
            continue;
        }

        // 1. 尝试作为 CIDR 网段解析 (如 192.168.0.0/16)
        if let Ok(net) = trimmed.parse::<IpNet>() {
            subnets.push(net);
            continue;
        }

        // 2. 尝试作为单 IP 解析 (自动转换为 /32 或 /128)
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            let net = match ip {
                IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap()),
                IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap()),
            };
            subnets.push(net);
            continue;
        }

        // 3. 作为域名匹配器预编译 (支持 *.example.com 同时匹配顶域与子域)
        if let Some(matcher) = DomainMatcher::parse(trimmed) {
            domain_patterns.push(matcher);
        }
    }

    let domains_opt = if domain_patterns.is_empty() && subnets.is_empty() {
        Some(Vec::new()) // Fail-Closed
    } else if domain_patterns.is_empty() {
        None
    } else {
        Some(domain_patterns)
    };

    let subnets_opt = if subnets.is_empty() {
        None
    } else {
        Some(subnets)
    };

    (domains_opt, subnets_opt)
}

/// 解析以分号分隔的目标主机（支持 IP, CIDR 子网与域名预编译匹配器）
pub fn parse_targets(raw: &str) -> (Option<Vec<DomainMatcher>>, Option<Vec<IpNet>>) {
    parse_targets_with_hostname(raw, None)
}

/// 解析端口配置（支持单端口、逗号/分号列表与破折号范围，如 "80; 443; 8000-8080"）
pub fn parse_ports(raw: &str) -> Option<Vec<PortRange>> {
    let trimmed_raw = raw.trim();
    if trimmed_raw.is_empty() {
        return None;
    }

    let mut ranges = Vec::new();
    let delimiters = [';', ','];
    let tokens = trimmed_raw.split(&delimiters[..]);

    for token in tokens {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some((start_s, end_s)) = trimmed.split_once('-') {
            if let (Ok(start), Ok(end)) =
                (start_s.trim().parse::<u16>(), end_s.trim().parse::<u16>())
                && start <= end
            {
                ranges.push(PortRange { start, end });
            }
        } else if let Ok(port) = trimmed.parse::<u16>() {
            ranges.push(PortRange {
                start: port,
                end: port,
            });
        }
    }

    Some(ranges) // Fail-Closed
}

/// 辅助函数：根据分隔符拆分字符串，同时尊重双引号内包含的内容
fn split_quoted_tokens(input: &str, delimiter: char) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in input.chars() {
        if ch == '"' {
            in_quotes = !in_quotes;
            current.push(ch);
        } else if ch == delimiter && !in_quotes {
            tokens.push(current.trim().to_string());
            current.clear();
        } else {
            current.push(ch);
        }
    }

    if !current.trim().is_empty() {
        tokens.push(current.trim().to_string());
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports() {
        let ranges = parse_ports("80; 443, 8000-8080").unwrap();
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges[0].start, 80);
        assert_eq!(ranges[0].end, 80);
        assert_eq!(ranges[1].start, 443);
        assert_eq!(ranges[2].start, 8000);
        assert_eq!(ranges[2].end, 8080);
    }

    #[test]
    fn test_parse_targets() {
        let (domains, subnets) = parse_targets("127.0.0.1; *.google.com; 10.0.0.0/8; localhost");
        let domains = domains.unwrap();
        let subnets = subnets.unwrap();
        assert_eq!(domains.len(), 2);
        assert!(domains[0].matches("google.com"));
        assert!(domains[0].matches("mail.google.com"));
        assert!(!domains[0].matches("google.org"));
        assert!(domains[1].matches("localhost"));
        assert_eq!(subnets.len(), 2);
    }

    #[test]
    fn test_parse_applications() {
        let pats = parse_applications(r#"node.exe; *chrome*.exe; "C:\Program Files\App\app.exe""#)
            .unwrap();
        assert_eq!(pats.len(), 3);
        assert!(pats[0].matches(&["node.exe"], &[]));
        assert!(!pats[0].matches(&["node"], &[]));
        assert!(pats[1].matches(&["google-chrome.exe"], &[]));
        assert!(!pats[1].matches(&["curl.exe"], &["c:/tools/google-chrome/curl.exe"]));
        assert!(pats[2].matches(&[], &["c:/program files/app/app.exe"]));

        // `*.exe` 与 `C:\Tools\*.exe` 仅匹配实际带 `.exe` 后缀的进程
        let wild_exe = parse_applications(r"*.exe; C:\Tools\*.exe").unwrap();
        assert_eq!(wild_exe.len(), 2);
        assert!(!wild_exe.iter().any(|m| m.matches(&["System"], &["System"])));
        assert!(wild_exe.iter().any(|m| m.matches(&["curl.exe"], &[])));
        assert!(
            wild_exe
                .iter()
                .any(|m| m.matches(&[], &["c:/tools/curl.exe"]))
        );
        assert!(
            !wild_exe
                .iter()
                .any(|m| m.matches(&[], &["c:/tools/sub/curl.exe"]))
        );
    }

    #[test]
    fn test_expand_env_vars_case_insensitive_and_injection_safe() {
        let expected_host = resolve_local_hostname();
        assert!(!expected_host.is_empty());

        // 正常安全主机名可按大小写无关展开（含历史兼容别名 %HOSTNAME%）且构造成 is_host_local() == true 的 Exact 域名匹配器
        let (domains, subnets) = parse_targets_with_hostname(
            "localhost; %ComputerName%; *.Local; %HOSTNAME%",
            Some("my-workstation"),
        );
        let domains = domains.unwrap();
        assert!(subnets.is_none());
        assert!(domains.iter().any(|d| d.matches("localhost")));
        assert!(domains.iter().any(|d| d.matches("my-workstation")));
        assert!(domains.iter().any(|d| d.matches("nas.local")));
        assert!(!domains.iter().any(|d| d.matches("%hostname%")));
        assert!(!domains.iter().any(|d| d.matches("notlocal")));
        assert!(!domains.iter().any(|d| d.matches("evil.com")));

        // 仅含 %HOSTNAME% 的存量规则展开后必须被识别为本机域名，不会对公网 IP 误触发 NeedsDomainSniff
        let (legacy_domains, _) = parse_targets_with_hostname("%HOSTNAME%", Some("my-workstation"));
        let legacy_domains = legacy_domains.unwrap();
        assert_eq!(legacy_domains.len(), 1);
        assert!(legacy_domains[0].is_host_local("my-workstation"));

        // P1-4 回归 1：主机名注入分号与通配符绝不可拆分注入 `*.evil.com`
        let (inj_domains, inj_subnets) = parse_targets_with_hostname(
            "127.0.0.1; %ComputerName%; %HostName%",
            Some("pc;*.evil.com"),
        );
        assert!(inj_subnets.is_some());
        let inj_domains = inj_domains.unwrap_or_default();
        assert!(
            !inj_domains.iter().any(|d| d.matches("sub.evil.com")),
            "Injected wildcard domain should never match"
        );

        // P1-4 回归 2：主机名伪装成 CIDR (`0.0.0.0/0`) 或全通配符 (`*`) 绝不可被编译进 subnets 或匹配任意域
        let (cidr_domains, cidr_subnets) =
            parse_targets_with_hostname("localhost; %ComputerName%", Some("0.0.0.0/0"));
        assert!(
            cidr_subnets.is_none(),
            "Injected CIDR via hostname must not compile into subnets"
        );
        let cidr_domains = cidr_domains.unwrap_or_default();
        assert!(!cidr_domains.iter().any(|d| d.matches("example.com")));

        let (wild_domains, _) = parse_targets_with_hostname("%ComputerName%", Some("*"));
        let wild_domains = wild_domains.unwrap_or_default();
        assert!(!wild_domains.iter().any(|d| d.matches("example.com")));
    }

    #[test]
    fn test_zero_alloc_domain_matcher() {
        let suffix = DomainMatcher::parse("*.Google.COM").unwrap();
        assert!(suffix.matches("google.com"));
        assert!(suffix.matches("Google.Com"));
        assert!(suffix.matches("a.b.GOOGLE.com"));
        assert!(!suffix.matches("notgoogle.com"));
        assert!(!suffix.matches(".google.com"));
        assert!(!suffix.matches("google.com.evil.org"));

        let exact = DomainMatcher::parse("Api.GitHub.com").unwrap();
        assert!(exact.matches("api.github.com"));
        assert!(exact.matches("API.GITHUB.COM"));
        assert!(exact.matches("api.github.com."));
        assert!(!exact.matches("v2.api.github.com"));

        // P1-6 回归：尾点与多重通配符不应误落入 Suffix 字面比较
        let trailing = DomainMatcher::parse("evil.com.").unwrap();
        assert!(trailing.matches("evil.com"));
        assert!(trailing.matches("evil.com."));

        let multi_wild = DomainMatcher::parse("*.google.*").unwrap();
        assert!(multi_wild.matches("mail.google.com"));
        assert!(multi_wild.matches("mail.google.co.uk."));
        assert!(!multi_wild.matches("google.com"));

        let double_star = DomainMatcher::parse("*.*.example.com").unwrap();
        assert!(double_star.matches("a.b.example.com"));
        assert!(!double_star.matches("example.com"));
    }
}
