use std::net::IpAddr;
use glob::Pattern;
use ipnet::IpNet;
use super::PortRange;

#[derive(Debug, Clone)]
pub enum DomainMatcher {
    Exact(String),
    Suffix(String), // e.g. "google.com" for "*.google.com", matching "google.com" and "*.google.com"
    Pattern(Pattern),
}

impl DomainMatcher {
    pub fn parse(raw: &str) -> Option<Self> {
        let s = raw.trim().to_lowercase();
        if s.is_empty() {
            return None;
        }
        if let Some(stripped) = s.strip_prefix("*.") {
            Some(DomainMatcher::Suffix(stripped.to_string()))
        } else if s.contains('*') || s.contains('?') || s.contains('[') {
            Pattern::new(&s).ok().map(DomainMatcher::Pattern)
        } else {
            Some(DomainMatcher::Exact(s))
        }
    }

    pub fn matches(&self, host: &str) -> bool {
        let host_lower = host.to_lowercase();
        match self {
            DomainMatcher::Exact(exact) => host_lower == *exact,
            DomainMatcher::Suffix(suffix) => {
                host_lower == *suffix || host_lower.ends_with(&format!(".{}", suffix))
            }
            DomainMatcher::Pattern(pat) => pat.matches(&host_lower),
        }
    }
}

/// 解析以分号分隔的应用程序路径/通配符（支持引号与 Fail-Closed 约束模式）
pub fn parse_applications(raw: &str) -> Option<Vec<Pattern>> {
    let trimmed_raw = raw.trim();
    if trimmed_raw.is_empty() {
        return None; // 无约束：匹配所有应用
    }

    let mut patterns = Vec::new();
    let tokens = split_quoted_tokens(trimmed_raw, ';');

    for token in tokens {
        let trimmed = token.trim().trim_matches('"').trim();
        if trimmed.is_empty() {
            continue;
        }
        // 统一转换为小写并处理路径分隔符为 '/'
        let normalized = trimmed.to_lowercase().replace('\\', "/");
        if let Ok(pat) = Pattern::new(&normalized) {
            patterns.push(pat);
        }
    }

    Some(patterns) // 即使为空也是 Some(vec![])，实现 Fail-Closed
}

/// 展开环境变量（如 %ComputerName%）
fn expand_env_vars(input: &str) -> String {
    let mut result = input.to_string();
    if result.to_lowercase().contains("%computername%") {
        let computer_name = std::env::var("COMPUTERNAME")
            .unwrap_or_else(|_| "localhost".to_string());
        result = result.replace("%COMPUTERNAME%", &computer_name)
            .replace("%computername%", &computer_name);
    }
    result
}

/// 解析以分号分隔的目标主机（支持 IP, CIDR 子网与域名预编译匹配器）
pub fn parse_targets(raw: &str) -> (Option<Vec<DomainMatcher>>, Option<Vec<IpNet>>) {
    let trimmed_raw = raw.trim();
    if trimmed_raw.is_empty() {
        return (None, None);
    }

    let expanded = expand_env_vars(trimmed_raw);
    let mut domain_patterns = Vec::new();
    let mut subnets = Vec::new();
    let tokens = split_quoted_tokens(&expanded, ';');

    for token in tokens {
        let trimmed = token.trim().trim_matches('"').trim();
        if trimmed.is_empty() {
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
            if let (Ok(start), Ok(end)) = (start_s.trim().parse::<u16>(), end_s.trim().parse::<u16>()) {
                if start <= end {
                    ranges.push(PortRange { start, end });
                }
            }
        } else if let Ok(port) = trimmed.parse::<u16>() {
            ranges.push(PortRange { start: port, end: port });
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
        let pats = parse_applications(r#"node.exe; *chrome*.exe; "C:\Program Files\App\app.exe""#).unwrap();
        assert_eq!(pats.len(), 3);
        assert!(pats[0].matches("node.exe"));
        assert!(pats[1].matches("google-chrome.exe"));
        assert!(pats[2].matches("c:/program files/app/app.exe"));
    }
}
