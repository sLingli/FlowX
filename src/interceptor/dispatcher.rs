use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use anyhow::{bail, Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tracing::{error, info, warn};

use crate::dns::FakeIpPool;
use crate::interceptor::process::ProcessTracker;
use crate::monitor::ConnectionManager;
use crate::outbound::chain::{ProxyChain, ProxyNode};
use crate::outbound::direct::DirectOutbound;
use crate::outbound::{relay_stream_monitored, TargetAddr};
use crate::router::{Action, RouteContext, RuleEngine};

#[derive(Debug, Clone)]
pub struct ProxyNodeEntry {
    pub id: u32,
    pub name: String,
    pub protocol: String,
    pub server_addr: String,
    pub username: Option<String>,
    pub client: ProxyNode,
}

/// 流量调度核心配置
pub struct DispatcherConfig {
    pub bind_addr: SocketAddr,
    pub tracker: Arc<ProcessTracker>,
    pub fake_ip_pool: Arc<FakeIpPool>,
    pub rule_engine: Arc<RuleEngine>,
    pub monitor: Arc<ConnectionManager>,
    pub proxy_nodes: Arc<RwLock<HashMap<u32, ProxyNodeEntry>>>,
    pub proxy_chains: Arc<HashMap<u32, ProxyChain>>,
}

pub struct StreamDispatcher {
    config: Arc<DispatcherConfig>,
    concurrency_limit: Arc<Semaphore>,
}

impl StreamDispatcher {
    pub fn new(config: DispatcherConfig) -> Self {
        Self {
            config: Arc::new(config),
            concurrency_limit: Arc::new(Semaphore::new(10000)), // 最大并发连接保护
        }
    }

    /// 同步绑定 TCP 监听器（Fail-Fast 检查端口占用）
    pub async fn bind(&self) -> Result<TcpListener> {
        let listener = TcpListener::bind(self.config.bind_addr)
            .await
            .with_context(|| format!("绑定透明流调度端口失败 ({})", self.config.bind_addr))?;
        info!(
            "[调度核心] FlowX 本地流调度服务已在 {} 绑定待命",
            self.config.bind_addr
        );
        Ok(listener)
    }

    /// 启动本地透明连接调度监听服务（支持优雅停机）
    pub async fn run(&self, listener: TcpListener, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        loop {
            let (local_stream, peer_addr) = tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok(r) => r,
                        Err(e) => {
                            error!("[调度核心] 接受新 TCP 连接失败: {}", e);
                            continue;
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    info!("[调度核心] 接收到退出信号，停止接受新流");
                    break;
                }
            };

            let permit = match self.concurrency_limit.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!("[调度核心] 活跃连接数超出上限 (10000)，拒绝新连接");
                    drop(local_stream);
                    continue;
                }
            };

            let config = Arc::clone(&self.config);
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = handle_connection(local_stream, peer_addr, config).await {
                    warn!("[调度核心] 连接中继结束或异常: {}", e);
                }
            });
        }
        Ok(())
    }
}

/// RAII 守卫：确保连接注销操作在任何退出分支均能精准执行
struct ConnectionGuard {
    id: u64,
    monitor: Arc<ConnectionManager>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.monitor.unregister(self.id);
    }
}

async fn handle_connection(
    local_stream: TcpStream,
    peer_addr: SocketAddr,
    config: Arc<DispatcherConfig>,
) -> Result<()> {
    // 1. 通过源端口逆向追踪调用方进程（异步非阻塞）
    let proc_info = config.tracker.find_by_addr_async(&peer_addr).await;
    let proc_name = proc_info.as_ref().map(|p| p.name.clone()).unwrap_or_else(|| "Unknown".to_string());
    let proc_path = proc_info.as_ref().map(|p| p.path.clone()).unwrap_or_else(|| "Unknown".to_string());
    let pid = proc_info.as_ref().map(|p| p.pid).unwrap_or(0);

    // 2. 获取原始目标 (若经由 Fake-IP 虚拟化，尝试逆向还原原始域名)
    let dest_addr = local_stream.local_addr()?;
    let mut restored_domain: Option<String> = None;

    if let IpAddr::V4(v4) = dest_addr.ip()
        && config.fake_ip_pool.is_fake_ip(&v4) {
            restored_domain = config.fake_ip_pool.restore(&v4);
        }

    let target = match &restored_domain {
        Some(domain) => TargetAddr::Domain(domain.clone(), dest_addr.port()),
        None => TargetAddr::Ip(dest_addr),
    };

    // 3. 构建路由上下文并提交规则引擎决策
    let ctx = RouteContext {
        process_path: Some(&proc_path),
        process_name: Some(&proc_name),
        target_host: restored_domain.as_deref(),
        target_ip: Some(dest_addr.ip()),
        target_port: dest_addr.port(),
    };

    let (action, rule_name) = config.rule_engine.evaluate(&ctx);

    let action_str = match &action {
        Action::Direct => "Direct".to_string(),
        Action::Block => "Block".to_string(),
        Action::Proxy(id) => format!("Proxy({})", id),
        Action::Chain(id) => format!("Chain({})", id),
    };

    info!(
        "[路由命中] 进程: {} (PID: {}) -> 目标: {}:{} => 规则: {} => 动作: {}",
        proc_name,
        pid,
        target.host_string(),
        target.port(),
        rule_name,
        action_str
    );

    // 4. 注册到连接监视器并使用 RAII 守卫
    let active_conn = config.monitor.register(
        proc_name,
        proc_path,
        pid,
        format!("{}:{}", target.host_string(), target.port()),
        rule_name,
        action_str,
    );

    let _guard = ConnectionGuard {
        id: active_conn.id,
        monitor: Arc::clone(&config.monitor),
    };

    // 5. 根据执行动作分发并全双工对拷（带实时流量监视）
    match action {
        Action::Block => {
            drop(local_stream);
            Ok(())
        }
        Action::Direct => {
            let remote_stream = DirectOutbound::connect(&target).await?;
            let (up, down) = relay_stream_monitored(local_stream, remote_stream, Some(&active_conn)).await?;
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
            let client = {
                let nodes_guard = config.proxy_nodes.read().unwrap_or_else(|e| e.into_inner());
                match nodes_guard.get(&node_id) {
                    Some(e) => e.client.clone(),
                    None => bail!("规则指定了不存在的代理节点 ID: {}", node_id),
                }
            };
            let remote_stream = match &client {
                ProxyNode::Socks5(s) => s.connect(&target).await?,
                ProxyNode::Http(h) => h.connect(&target).await?,
                ProxyNode::Socks4(s) => s.connect(&target).await?,
            };
            let (up, down) = relay_stream_monitored(local_stream, remote_stream, Some(&active_conn)).await?;
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
            let chain = match config.proxy_chains.get(&chain_id) {
                Some(c) => c,
                None => bail!("规则指定了不存在的代理链 ID: {}", chain_id),
            };
            let remote_stream = chain.connect(&target).await?;
            let (up, down) = relay_stream_monitored(local_stream, remote_stream, Some(&active_conn)).await?;
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
