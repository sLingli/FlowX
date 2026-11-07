use anyhow::{bail, Context, Result};
use tokio::net::TcpStream;
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

    /// 校验代理链节点是否存在回环死锁风险
    pub fn validate_loop(&self, forbidden_ports: &[u16]) -> Result<()> {
        let mut visited = std::collections::HashSet::new();
        for node in &self.nodes {
            let addr = node.server_addr();
            if !visited.insert(addr.to_string()) {
                bail!("代理链 [{}] 包含重复节点，存在循环依赖: {}", self.name, addr);
            }
            if let Ok(target) = parse_target_addr(addr) {
                let is_loopback = match &target {
                    TargetAddr::Ip(ip) => ip.ip().is_loopback(),
                    TargetAddr::Domain(h, _) => h == "localhost" || h == "127.0.0.1" || h == "::1",
                };
                if is_loopback && forbidden_ports.contains(&target.port()) {
                    bail!("代理链 [{}] 节点指向自身服务端口，已被拦截防回环: {}", self.name, addr);
                }
            }
        }
        Ok(())
    }

    /// 通过代理链建立到达最终目标的多跳隧道
    pub async fn connect(&self, target: &TargetAddr) -> Result<TcpStream> {
        if self.nodes.is_empty() {
            bail!("代理链 '{}' 中未包含任何代理节点", self.name);
        }

        // 1. 与第一跳建立基础 TCP 连接
        let first_node = &self.nodes[0];
        let mut stream = TcpStream::connect(first_node.server_addr())
            .await
            .with_context(|| {
                format!(
                    "代理链 [{}] 首节点连接失败: {}",
                    self.name,
                    first_node.server_addr()
                )
            })?;

        // 2. 依次遍历并向每一跳发起握手，要求其 CONNECT 下一跳代理地址
        for i in 0..self.nodes.len() {
            let is_last = i == self.nodes.len() - 1;
            let current_node = &self.nodes[i];

            if is_last {
                // 最后一跳：要求其连接最终目标
                stream = current_node
                    .handshake(stream, target)
                    .await
                    .with_context(|| {
                        format!(
                            "代理链 [{}] 终节点 ({}) 连接目标失败: {}:{}",
                            self.name,
                            current_node.server_addr(),
                            target.host_string(),
                            target.port()
                        )
                    })?;
            } else {
                // 中间跳：要求当前节点连接下一跳代理
                let next_node = &self.nodes[i + 1];
                let next_target = parse_target_addr(next_node.server_addr())?;

                stream = current_node
                    .handshake(stream, &next_target)
                    .await
                    .with_context(|| {
                        format!(
                            "代理链 [{}] 节点 {} 连接下一跳 {} 失败",
                            self.name,
                            current_node.server_addr(),
                            next_node.server_addr()
                        )
                    })?;
            }
        }

        Ok(stream)
    }
}

pub fn parse_target_addr(addr_str: &str) -> Result<TargetAddr> {
    if let Ok(socket_addr) = addr_str.parse() {
        return Ok(TargetAddr::Ip(socket_addr));
    }
    if let Some((host, port_str)) = addr_str.split_once(':') {
        let port = port_str
            .parse::<u16>()
            .with_context(|| format!("非法端口号: {}", port_str))?;
        return Ok(TargetAddr::Domain(host.to_string(), port));
    }
    bail!("无法解析代理地址: {}", addr_str)
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

        // 校验循环检测机制
        assert!(chain.validate_loop(&[40001]).is_ok());

        let loop_chain = ProxyChain::new("Loop-Chain")
            .add_node(ProxyNode::Socks5(Socks5Client::new("127.0.0.1:40001")));
        assert!(loop_chain.validate_loop(&[40001]).is_err());
    }

    #[test]
    fn test_parse_target_addr() {
        let target_ip = parse_target_addr("127.0.0.1:8080").unwrap();
        assert_eq!(target_ip.port(), 8080);
        assert_eq!(target_ip.host_string(), "127.0.0.1");

        let target_domain = parse_target_addr("example.com:443").unwrap();
        assert_eq!(target_domain.port(), 443);
        assert_eq!(target_domain.host_string(), "example.com");
    }
}
