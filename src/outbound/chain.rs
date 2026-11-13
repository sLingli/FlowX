use std::net::{IpAddr, SocketAddr};
use anyhow::{bail, Context, Result};
use tokio::net::TcpStream;
use crate::dns::FakeIpPool;
use super::direct::{connect_proxy_tcp, DEFAULT_OUTBOUND_UPSTREAM_DNS};
use super::http::HttpConnectClient;
use super::socks4::Socks4Client;
use super::socks5::Socks5Client;
use super::TargetAddr;

#[derive(Debug, Clone)]
pub enum ProxyNode {
    Socks5(Socks5Client),
    Http(HttpConnectClient),
    Socks4(Socks4Client),
}

impl ProxyNode {
    pub fn server_addr(&self) -> &str {
        match self {
            ProxyNode::Socks5(c) => &c.proxy_addr,
            ProxyNode::Http(c) => &c.proxy_addr,
            ProxyNode::Socks4(c) => &c.proxy_addr,
        }
    }

    pub fn auth_credentials(&self) -> (Option<&str>, Option<&str>) {
        match self {
            ProxyNode::Socks5(c) => match &c.auth {
                Some((u, p)) => (Some(u.as_str()), Some(p.as_str())),
                None => (None, None),
            },
            ProxyNode::Http(c) => match &c.auth {
                Some((u, p)) => (Some(u.as_str()), Some(p.as_str())),
                None => (None, None),
            },
            ProxyNode::Socks4(_) => (None, None),
        }
    }

    /// 在一个既有 TCP 流上执行该节点的隧道握手
    pub async fn handshake(&self, stream: TcpStream, target: &TargetAddr) -> Result<TcpStream> {
        match self {
            ProxyNode::Socks5(c) => c.handshake(stream, target).await,
            ProxyNode::Http(c) => c.handshake(stream, target).await,
            ProxyNode::Socks4(c) => c.handshake(stream, target).await,
        }
    }
}

/// 代理链编排器：支持任意节点的多跳级联 (Proxy Chaining)
#[derive(Debug, Clone)]
pub struct ProxyChain {
    pub name: String,
    pub nodes: Vec<ProxyNode>,
}

impl ProxyChain {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            nodes: Vec::new(),
        }
    }

    pub fn add_node(mut self, node: ProxyNode) -> Self {
        self.nodes.push(node);
        self
    }

    /// Validate proxy chain nodes for loopback and circular dependency risks
    pub fn validate_loop(&self, forbidden_ports: &[u16]) -> Result<()> {
        let mut visited = std::collections::HashSet::new();
        for node in &self.nodes {
            let addr = node.server_addr();
            let target = parse_target_addr(addr)
                .with_context(|| format!("Proxy chain [{}] contains invalid node address: {}", self.name, addr))?;
            if !visited.insert(target.clone()) {
                bail!("Proxy chain [{}] contains duplicate node, circular dependency detected: {}", self.name, addr);
            }
            if target.is_loopback_or_unspecified() && forbidden_ports.contains(&target.port()) {
                bail!("Proxy chain [{}] node points to internal service port, blocked to prevent loop: {}", self.name, addr);
            }
        }
        Ok(())
    }

    /// Establish multi-hop tunnel to final target through proxy chain (with single-hop timeout and overall chain timeout)
    pub async fn connect(&self, target: &TargetAddr) -> Result<TcpStream> {
        self.connect_with_policy(target, DEFAULT_OUTBOUND_UPSTREAM_DNS, None, &[])
            .await
    }

    pub async fn connect_with_policy(
        &self,
        target: &TargetAddr,
        upstream_dns: SocketAddr,
        fake_ip_pool: Option<&FakeIpPool>,
        self_ports: &[u16],
    ) -> Result<TcpStream> {
        if self.nodes.is_empty() {
            bail!("Proxy chain '{}' does not contain any proxy nodes", self.name);
        }

        const HOP_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
        const CHAIN_TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        tokio::time::timeout(CHAIN_TOTAL_TIMEOUT, async {
            // 1. Establish basic TCP connection with first hop via upstream DNS + Fake-IP/self-loop validation
            let first_node = &self.nodes[0];
            let role = format!("Proxy chain [{}] first node", self.name);
            let mut stream = tokio::time::timeout(
                HOP_CONNECT_TIMEOUT,
                connect_proxy_tcp(
                    first_node.server_addr(),
                    upstream_dns,
                    fake_ip_pool,
                    self_ports,
                    &role,
                ),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Proxy chain [{}] first node connection timed out ({:?}): {}", self.name, HOP_CONNECT_TIMEOUT, first_node.server_addr()))??;

            // 2. Iterate and handshake through each hop, requesting CONNECT to next hop
            for i in 0..self.nodes.len() {
                let is_last = i == self.nodes.len() - 1;
                let current_node = &self.nodes[i];

                if is_last {
                    // Last hop: connect to final target
                    stream = current_node
                        .handshake(stream, target)
                        .await
                        .with_context(|| {
                            format!(
                                "Proxy chain [{}] final node ({}) failed to connect to target: {}:{}",
                                self.name,
                                current_node.server_addr(),
                                target.host_string(),
                                target.port()
                            )
                        })?;
                } else {
                    // Intermediate hop: connect to next proxy node
                    let next_node = &self.nodes[i + 1];
                    let next_target = parse_target_addr(next_node.server_addr())?;
                    if let TargetAddr::Ip(addr) = &next_target {
                        if let IpAddr::V4(v4) = addr.ip()
                            && fake_ip_pool.is_some_and(|p| p.is_fake_ip(&v4))
                        {
                            bail!("Proxy chain [{}] intermediate node {} uses Fake-IP", self.name, next_node.server_addr());
                        }
                        if next_target.is_loopback_or_unspecified() && self_ports.contains(&next_target.port()) {
                            bail!("Proxy chain [{}] intermediate node {} points to internal port", self.name, next_node.server_addr());
                        }
                    } else if next_target.is_loopback_or_unspecified() && self_ports.contains(&next_target.port()) {
                        bail!("Proxy chain [{}] intermediate node {} points to internal port", self.name, next_node.server_addr());
                    }

                    stream = current_node
                        .handshake(stream, &next_target)
                        .await
                        .with_context(|| {
                            format!(
                                "Proxy chain [{}] node {} failed to connect to next hop {}",
                                self.name,
                                current_node.server_addr(),
                                next_node.server_addr()
                            )
                        })?;
                }
            }

            Ok(stream)
        })
        .await
        .map_err(|_| anyhow::anyhow!("Proxy chain [{}] total connection time exceeded {:?}", self.name, CHAIN_TOTAL_TIMEOUT))?
    }
}

pub fn parse_target_addr(addr_str: &str) -> Result<TargetAddr> {
    TargetAddr::parse_authority(addr_str, None, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_chain_builder() {
        let chain = ProxyChain::new("Chain-1")
            .add_node(ProxyNode::Socks5(Socks5Client::new("127.0.0.1:10808")))
            .add_node(ProxyNode::Http(HttpConnectClient::new("10.0.0.1:8080")));

        assert_eq!(chain.nodes.len(), 2);
        assert_eq!(chain.nodes[0].server_addr(), "127.0.0.1:10808");
        assert_eq!(chain.nodes[1].server_addr(), "10.0.0.1:8080");

        // Verify loop detection mechanism
        assert!(chain.validate_loop(&[40001]).is_ok());

        for self_addr in [
            "127.0.0.1:40001",
            "0.0.0.0:40001",
            "[::1]:40001",
            "[::]:40001",
            "LocalHost:40001",
            "sub.localhost:40001",
        ] {
            let loop_chain = ProxyChain::new("Loop-Chain")
                .add_node(ProxyNode::Socks5(Socks5Client::new(self_addr)));
            assert!(
                loop_chain.validate_loop(&[40001]).is_err(),
                "Loopback address {} should be intercepted by loop prevention",
                self_addr
            );
        }

        // Duplicate domain with case variation should also be detected as loop
        let dup_chain = ProxyChain::new("Dup-Chain")
            .add_node(ProxyNode::Socks5(Socks5Client::new("Proxy.Example.com:1080")))
            .add_node(ProxyNode::Http(HttpConnectClient::new("proxy.example.com:1080")));
        assert!(dup_chain.validate_loop(&[40001]).is_err());
    }

    #[test]
    fn test_parse_target_addr() {
        let target_ip = parse_target_addr("127.0.0.1:8080").unwrap();
        assert_eq!(target_ip.port(), 8080);
        assert_eq!(target_ip.host_string(), "127.0.0.1");

        let target_v6 = parse_target_addr("[2001:db8::1]:1080").unwrap();
        assert_eq!(target_v6.port(), 1080);
        assert_eq!(target_v6.host_string(), "2001:db8::1");

        let target_domain = parse_target_addr("Example.COM:443").unwrap();
        assert_eq!(target_domain.port(), 443);
        assert_eq!(target_domain.host_string(), "example.com");

        assert!(parse_target_addr("example.com:0").is_err());
        assert!(parse_target_addr("bad host:443").is_err());
        assert!(parse_target_addr("user@127.0.0.1:1080").is_err());
        assert!(parse_target_addr("no-port.example.com").is_err());
    }
}
