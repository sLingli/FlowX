pub mod api;
pub mod config;
pub mod dns;
pub mod inbound;
pub mod interceptor;
pub mod monitor;
pub mod outbound;
pub mod router;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use anyhow::Context;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use crate::api::{ApiServer, SystemRuntimeContext};
use crate::config::ConfigStore;
use crate::dns::server::DnsServer;
use crate::dns::FakeIpPool;
use crate::interceptor::dispatcher::{DispatcherConfig, StreamDispatcher};
use crate::interceptor::process::ProcessTracker;
use crate::monitor::ConnectionManager;
use crate::router::RuleEngine;

fn resolve_config_path() -> String {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config"
            && let Some(path) = args.next()
        {
            return path;
        } else if let Some(path) = arg.strip_prefix("--config=") {
            return path.to_string();
        }
    }
    std::env::var("FLOWX_CONFIG").unwrap_or_else(|_| "flowx.xml".to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. 初始化标准结构化日志
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("============================================================");
    info!("          FlowX - 现代化透明网络代理与进程分流系统           ");
    info!("============================================================");

    // 2. 初始化核心组件与端口规划
    let fake_ip_pool = Arc::new(FakeIpPool::new_default());
    let process_tracker = Arc::new(ProcessTracker::new());
    let connection_manager = Arc::new(ConnectionManager::new());

    let dns_bind: SocketAddr = "127.0.0.1:1053".parse()?;
    let upstream_dns: SocketAddr = "223.5.5.5:53".parse()?;
    let dispatcher_bind: SocketAddr = "127.0.0.1:40001".parse()?;
    let api_bind: SocketAddr = "127.0.0.1:40080".parse()?;
    let self_ports = vec![dispatcher_bind.port(), api_bind.port(), dns_bind.port()];

    // 3. 从 XML 配置文件加载代理节点与路由规则（缺失时自动生成默认配置）
    let config_path = resolve_config_path();
    let config_store = Arc::new(ConfigStore::new(&config_path));
    let (runtime_profile, created_default) = config_store
        .load_or_init(&self_ports)
        .with_context(|| format!("加载配置文件失败: {}", config_path))?;
    if created_default {
        info!("[配置中心] 未检测到配置文件，已生成默认配置: {}", config_path);
    } else {
        info!(
            "[配置中心] 已加载配置文件 {} ({} 个代理节点, {} 条路由规则)",
            config_path,
            runtime_profile.proxy_nodes.len(),
            runtime_profile.rules.len()
        );
    }

    let proxy_nodes = Arc::new(RwLock::new(runtime_profile.proxy_nodes));
    let proxy_chains = Arc::new(HashMap::new());
    let rule_engine = Arc::new(RuleEngine::new(
        runtime_profile.rules,
        runtime_profile.default_action,
    ));

    // 4. Fail-Fast 端口绑定阶段（确保核心服务端口可用，若被占用立即明确报错）
    let dns_server = DnsServer::new(
        dns_bind,
        Arc::clone(&fake_ip_pool),
        upstream_dns,
        true, // 阻断 AAAA IPv6 泄漏
    );
    let dns_socket = dns_server.bind().await?;

    let dispatcher = StreamDispatcher::new(DispatcherConfig {
        bind_addr: dispatcher_bind,
        tracker: Arc::clone(&process_tracker),
        fake_ip_pool: Arc::clone(&fake_ip_pool),
        rule_engine: Arc::clone(&rule_engine),
        monitor: Arc::clone(&connection_manager),
        proxy_nodes: Arc::clone(&proxy_nodes),
        proxy_chains: Arc::clone(&proxy_chains),
        self_ports: self_ports.clone(),
    });
    let dispatcher_listener = dispatcher.bind().await?;

    let runtime_context = Arc::new(SystemRuntimeContext {
        inbound_addr: dispatcher_bind,
        dns_addr: dns_bind,
        upstream_dns,
        api_addr: api_bind,
        fake_ip_pool: Arc::clone(&fake_ip_pool),
        started_at: Instant::now(),
    });

    let api_server = ApiServer::new(
        api_bind,
        Arc::clone(&connection_manager),
        Arc::clone(&rule_engine),
        Arc::clone(&proxy_nodes),
    )
    .with_self_ports(self_ports)
    .with_config_store(Arc::clone(&config_store))
    .with_runtime_context(runtime_context);
    let api_listener = api_server.bind().await?;

    // 5. 初始化全局优雅停机广播通知通道
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // 6. 启动异步服务工作线程
    let rx1 = shutdown_rx.clone();
    tokio::spawn(async move {
        if let Err(e) = dns_server.run(dns_socket, rx1).await {
            tracing::error!("[DNS 模块] DNS 服务异常退出: {}", e);
        }
    });

    let rx2 = shutdown_rx.clone();
    tokio::spawn(async move {
        if let Err(e) = dispatcher.run(dispatcher_listener, rx2).await {
            tracing::error!("[调度中心] 透明流调度服务异常退出: {}", e);
        }
    });

    let rx3 = shutdown_rx.clone();
    tokio::spawn(async move {
        if let Err(e) = api_server.run(api_listener, rx3).await {
            tracing::error!("[Web 控制台] API 服务异常退出: {}", e);
        }
    });

    // 7. 启动周期性内存 GC 维护任务（每 3 秒通过 blocking 线程池异步清理过期 Fake-IP 与进程缓存，避免阻塞 Tokio Worker）
    let pool_gc = Arc::clone(&fake_ip_pool);
    let tracker_gc = Arc::clone(&process_tracker);
    let mut rx_gc = shutdown_rx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let pool_task = Arc::clone(&pool_gc);
                    let tracker_task = Arc::clone(&tracker_gc);
                    if let Ok((cleaned_ips, cleaned_conns, cleaned_pids)) =
                        tokio::task::spawn_blocking(move || {
                            let cleaned_ips = pool_task.cleanup_expired();
                            let (cleaned_conns, cleaned_pids) = tracker_task.cleanup_expired();
                            (cleaned_ips, cleaned_conns, cleaned_pids)
                        })
                        .await
                        && (cleaned_ips > 0 || cleaned_conns > 0 || cleaned_pids > 0)
                    {
                        tracing::debug!(
                            "[GC 维护] 定期回收过期条目: Fake-IP={}, 进程连接={}, PID={}",
                            cleaned_ips,
                            cleaned_conns,
                            cleaned_pids
                        );
                    }
                }
                _ = rx_gc.changed() => {
                    break;
                }
            }
        }
    });

    info!("[就绪] 控制台已就绪，请在浏览器中访问: http://127.0.0.1:40080");
    info!("[就绪] 按 Ctrl+C 可安全停止 FlowX 核心引擎");

    // 8. 监听操作系统 Ctrl+C 信号并执行优雅停机
    tokio::signal::ctrl_c().await?;
    info!("[退出] 接收到退出信号，正在通知各子系统停止接收流量...");
    let _ = shutdown_tx.send(true);

    // 优雅排空：等待正在传输的活跃连接完成挥手（最多等待 10 秒）
    let drain_start = std::time::Instant::now();
    let max_drain_wait = Duration::from_secs(10);
    while drain_start.elapsed() < max_drain_wait {
        let active = connection_manager.active_count();
        if active == 0 {
            break;
        }
        info!("[退出] 正在等待 {} 个活跃连接排空挥手...", active);
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    info!("[退出] FlowX 核心引擎已安全退出");

    Ok(())
}
