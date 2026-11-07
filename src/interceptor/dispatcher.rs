use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use anyhow::{bail, Result};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::dns::FakeIpPool;
use crate::interceptor::process::ProcessTracker;
use crate::outbound::chain::ProxyChain;
use crate::outbound::direct::DirectOutbound;
use crate::outbound::socks5::Socks5Client;
use crate::outbound::{relay_stream, TargetAddr};
use crate::router::{Action, RouteContext, RuleEngine};

/// 流量调度核心配置
pub struct DispatcherConfig {
    pub bind_addr: SocketAddr,
    pub tracker: Arc<ProcessTracker>,
    pub fake_ip_pool: Arc<FakeIpPool>,
    pub rule_engine: Arc<RuleEngine>,
    pub proxy_nodes: Arc<HashMap<u32, Socks5Client>>,
    pub proxy_chains: Arc<HashMap<u32, ProxyChain>>,
}

pub struct StreamDispatcher {
    config: DispatcherConfig,
}

impl StreamDispatcher {
    pub fn new(config: DispatcherConfig) -> Self {
        Self { config }
    }

    /// 启动本地透明连接调度监听服务
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.config.bind_addr).await?;
        info!(
            "[调度核心] FlowX 本地流调度服务已在 {} 启动待命",
            self.config.bind_addr
        );

        loop {
            let (local_stream, peer_addr) = match listener.accept().await {
                Ok(res) => res,
                Err(e) => {
                    error!("[调度核心] 接受新 TCP 连接失败: {}", e);
                    continue;
                }
            };

            let tracker = Arc::clone(&self.config.tracker);
            let pool = Arc::clone(&self.config.fake_ip_pool);
            let rule_engine = Arc::clone(&self.config.rule_engine);
            let proxy_nodes = Arc::clone(&self.config.proxy_nodes);
            let proxy_chains = Arc::clone(&self.config.proxy_chains);

            tokio::spawn(async move {
                if let Err(e) = handle_connection(
                    local_stream,
                    peer_addr,
                    tracker,
                    pool,
                    rule_engine,
                    proxy_nodes,
                    proxy_chains,
                )
                .await
                {
                    warn!("[调度核心] 连接中继结束或异常: {}", e);
                }
            });
        }
    }
}

async fn handle_connection(
    local_stream: TcpStream,
    peer_addr: SocketAddr,
    tracker: Arc<ProcessTracker>,
    pool: Arc<FakeIpPool>,
    rule_engine: Arc<RuleEngine>,
    proxy_nodes: Arc<HashMap<u32, Socks5Client>>,
    proxy_chains: Arc<HashMap<u32, ProxyChain>>,
) -> Result<()> {
    // 1. 通过源端口逆向追踪调用方进程
    let proc_info = tracker.find_by_addr(&peer_addr);
    let proc_name = proc_info.as_ref().map(|p| p.name.as_str());
    let proc_path = proc_info.as_ref().map(|p| p.path.as_str());

    // 2. 获取原始目标 (若经由 Fake-IP 虚拟化，尝试逆向还原原始域名)
    let dest_addr = local_stream.local_addr()?;
    let mut restored_domain: Option<String> = None;

    if let IpAddr::V4(v4) = dest_addr.ip() {
        if pool.is_fake_ip(&v4) {
            restored_domain = pool.restore(&v4);
        }
    }

    let target = match &restored_domain {
        Some(domain) => TargetAddr::Domain(domain.clone(), dest_addr.port()),
        None => TargetAddr::Ip(dest_addr),
    };

    // 3. 构建路由上下文并提交规则引擎决策
    let ctx = RouteContext {
        process_path: proc_path,
        process_name: proc_name,
        target_host: restored_domain.as_deref(),
        target_ip: Some(dest_addr.ip()),
        target_port: dest_addr.port(),
    };

    let action = rule_engine.evaluate(&ctx);

    info!(
        "[路由命中] 进程: {:?} -> 目标: {}:{} => 动作: {:?}",
        proc_name.unwrap_or("Unknown"),
        target.host_string(),
        target.port(),
        action
    );

    // 4. 根据执行动作分发并全双工对拷
    match action {
        Action::Block => {
            // 立即断开连接
            drop(local_stream);
            Ok(())
        }
        Action::Direct => {
            let remote_stream = DirectOutbound::connect(&target).await?;
            let (up, down) = relay_stream(local_stream, remote_stream).await?;
            info!(
                "[直连完成] {}:{} 上传: {} B, 下载: {} B",
                target.host_string(),
                target.port(),
                up,
                down
            );
            Ok(())
        }
        Action::Proxy(node_id) => {
            let client = match proxy_nodes.get(&node_id) {
                Some(c) => c,
                None => bail!("规则指定了不存在的代理节点 ID: {}", node_id),
            };
            let remote_stream = client.connect(&target).await?;
            let (up, down) = relay_stream(local_stream, remote_stream).await?;
            info!(
                "[代理完成] [{}] 目标 {}:{} 上传: {} B, 下载: {} B",
                node_id,
                target.host_string(),
                target.port(),
                up,
                down
            );
            Ok(())
        }
        Action::Chain(chain_id) => {
            let chain = match proxy_chains.get(&chain_id) {
                Some(c) => c,
                None => bail!("规则指定了不存在的代理链 ID: {}", chain_id),
            };
            let remote_stream = chain.connect(&target).await?;
            let (up, down) = relay_stream(local_stream, remote_stream).await?;
            info!(
                "[代理链完成] [{}] 目标 {}:{} 上传: {} B, 下载: {} B",
                chain_id,
                target.host_string(),
                target.port(),
                up,
                down
            );
            Ok(())
        }
    }
}
