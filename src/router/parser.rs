use std::net::IpAddr;
use glob::Pattern;
use ipnet::IpNet;
use super::PortRange;

/// 解析以分号分隔的应用程序路径/通配符（支持引号保护包含分号或空格的路径）
pub fn parse_applications(raw: &str) -> Vec<Pattern> {
    let mut patterns = Vec::new();
    let tokens = split_quoted_tokens(raw, ';');

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
    patterns
}

/// 解析以分号分隔的目标主机（支持 IP, CIDR 子网与域名通配符）
pub fn parse_targets(raw: &str) -> (Vec<String>, Vec<IpNet>) {
    let mut domain_patterns = Vec::new();
    let mut subnets = Vec::new();
    let tokens = split_quoted_tokens(raw, ';');

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

        // 3. 作为域名通配符 (如 *.google.com, localhost, %ComputerName%)
        domain_patterns.push(trimmed.to_lowercase());
    }

    (domain_patterns, subnets)
}

/// 解析端口配置（支持单端口、逗号/分号列表与破折号范围，如 "80; 443; 8000-8080"）
pub fn parse_ports(raw: &str) -> Vec<PortRange> {
    let mut ranges = Vec::new();
    let delimiters = [';', ','];
    let tokens = raw.split(&delimiters[..]);

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

    ranges
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
        let ranges = parse_ports("80; 443, 8000-8080");
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
        assert_eq!(domains.len(), 2);
        assert!(domains.contains(&"*.google.com".to_string()));
        assert!(domains.contains(&"localhost".to_string()));
        assert_eq!(subnets.len(), 2);
    }

    #[test]
    fn test_parse_applications() {
        let pats = parse_applications(r#"node.exe; *chrome*.exe; "C:\Program Files\App\app.exe""#);
        assert_eq!(pats.len(), 3);
        assert!(pats[0].matches("node.exe"));
        assert!(pats[1].matches("google-chrome.exe"));
        assert!(pats[2].matches("c:/program files/app/app.exe"));
    }
}
