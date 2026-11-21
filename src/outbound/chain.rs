use std::net::SocketAddr;
use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use crate::dns::FakeIpPool;
use super::bypass::OutboundTcpStream;
use super::direct::{connect_proxy_tcp_guarded, validate_direct_ips, DEFAULT_OUTBOUND_UPSTREAM_DNS};
use super::http::HttpConnectClient;
use super::socks4::Socks4Client;
use super::socks5::Socks5Client;
use super::TargetAddr;

fn validate_chain_hop_target(
    chain_name: &str,
    addr: &str,
    target: &TargetAddr,
    self_ports: &[u16],
    fake_ip_pool: Option<&FakeIpPool>,
) -> Result<()> {
    match target {
        TargetAddr::Ip(sa) => validate_direct_ips(&[sa.ip()], sa.port(), self_ports, fake_ip_pool, addr)
            .with_context(|| format!("Proxy chain [{}] hop target rejected", chain_name)),
        TargetAddr::Domain(_, port) => {
            if target.is_loopback_or_unspecified() && self_ports.contains(port) {
                bail!(
                    "Proxy chain [{}] node points to internal service port, blocked to prevent loop: {}",
                    chain_name,
                    addr
                );
            }
            Ok(())
        }
    }
}

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
        self.handshake_stream(stream, target).await
    }

    pub async fn handshake_stream<S>(&self, stream: S, target: &TargetAddr) -> Result<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match self {
            ProxyNode::Socks5(c) => c.handshake_stream(stream, target).await,
            ProxyNode::Http(c) => c.handshake_stream(stream, target).await,
            ProxyNode::Socks4(c) => c.handshake_stream(stream, target).await,
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

    /// Validate proxy chain nodes for loopback, local interface self-ports, Fake-IP, and circular risks
    pub fn validate_loop(&self, forbidden_ports: &[u16]) -> Result<()> {
        let mut visited = std::collections::HashSet::new();
        for node in &self.nodes {
            let addr = node.server_addr();
            let target = parse_target_addr(addr)
                .with_context(|| format!("Proxy chain [{}] contains invalid node address: {}", self.name, addr))?;
            if !visited.insert(target.clone()) {
                bail!("Proxy chain [{}] contains duplicate node, circular dependency detected: {}", self.name, addr);
            }
            validate_chain_hop_target(&self.name, addr, &target, forbidden_ports, None)?;
        }
        Ok(())
    }

    /// Establish multi-hop tunnel to final target through proxy chain (with overall chain timeout)
    pub async fn connect(&self, target: &TargetAddr) -> Result<OutboundTcpStream> {
        self.connect_with_policy(target, DEFAULT_OUTBOUND_UPSTREAM_DNS, None, &[])
            .await
    }

    pub async fn connect_with_policy(
        &self,
        target: &TargetAddr,
        upstream_dns: SocketAddr,
        fake_ip_pool: Option<&FakeIpPool>,
        self_ports: &[u16],
    ) -> Result<OutboundTcpStream> {
        self.connect_with_policy_guarded(target, upstream_dns, fake_ip_pool, self_ports)
            .await
    }

    pub async fn connect_with_policy_guarded(
        &self,
        target: &TargetAddr,
        upstream_dns: SocketAddr,
        fake_ip_pool: Option<&FakeIpPool>,
        self_ports: &[u16],
    ) -> Result<OutboundTcpStream> {
        if self.nodes.is_empty() {
            bail!("Proxy chain '{}' does not contain any proxy nodes", self.name);
        }

        const CHAIN_TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        tokio::time::timeout(CHAIN_TOTAL_TIMEOUT, async {
            // 1. Establish basic TCP connection with first hop via upstream DNS + Fake-IP/self-loop validation
            let first_node = &self.nodes[0];
            let role = format!("Proxy chain [{}] first node", self.name);
            let mut stream = connect_proxy_tcp_guarded(
                first_node.server_addr(),
                upstream_dns,
                fake_ip_pool,
                self_ports,
                &role,
            )
            .await?;

            // 2. Iterate and handshake through each hop, requesting CONNECT to next hop
            for i in 0..self.nodes.len() {
                let is_last = i == self.nodes.len() - 1;
                let current_node = &self.nodes[i];

                if is_last {
                    // Last hop: connect to final target
                    stream = current_node
                        .handshake_stream(stream, target)
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
                    // Intermediate hop: validate target via shared Fake-IP & local-interface self-port guards
                    let next_node = &self.nodes[i + 1];
                    let next_target = parse_target_addr(next_node.server_addr())?;
                    validate_chain_hop_target(
                        &self.name,
                        next_node.server_addr(),
                        &next_target,
                        self_ports,
                        fake_ip_pool,
                    )?;

                    stream = current_node
                        .handshake_stream(stream, &next_target)
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

    #[tokio::test]
    async fn test_proxy_chain_blocks_intermediate_local_interface_ip_and_fake_ip() {
        use tokio::net::TcpListener;

        let local_ips = super::super::local_interface_ips();
        let non_loopback_ip = local_ips
            .iter()
            .copied()
            .find(|ip| !ip.is_loopback() && !ip.is_unspecified())
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let hop2_addr = SocketAddr::new(non_loopback_ip, 40080).to_string();

        // Also validate Fake-IP literal in validate_loop and connect_with_policy
        let fake_chain = ProxyChain::new("Fake-Chain")
            .add_node(ProxyNode::Socks5(Socks5Client::new("10.0.0.1:1080")))
            .add_node(ProxyNode::Http(HttpConnectClient::new("198.18.0.5:8080")));
        assert!(fake_chain.validate_loop(&[40080]).is_err());

        // Hop 0 listens, intermediate hop points to local interface + forbidden self_port
        let hop0 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hop0_addr = hop0.local_addr().unwrap();
        tokio::spawn(async move {
            let (_s, _) = hop0.accept().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let pool = FakeIpPool::new_default();
        let chain = ProxyChain::new("Self-Iface-Chain")
            .add_node(ProxyNode::Socks5(Socks5Client::new(hop0_addr.to_string())))
            .add_node(ProxyNode::Http(HttpConnectClient::new(hop2_addr)));

        let err = chain
            .connect_with_policy(
                &TargetAddr::Domain("example.com".into(), 443),
                DEFAULT_OUTBOUND_UPSTREAM_DNS,
                Some(&pool),
                &[40080],
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("hop target rejected")
                || format!("{:#}", err).contains("self/loopback IP"),
            "Unexpected error: {:#}",
            err
        );
    }
}
