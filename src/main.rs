pub mod api;
pub mod config;
pub mod dns;
pub mod interceptor;
pub mod monitor;
pub mod outbound;
pub mod router;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use crate::api::ApiServer;
use crate::dns::server::DnsServer;
use crate::dns::FakeIpPool;
use crate::interceptor::dispatcher::{DispatcherConfig, ProxyNodeEntry, StreamDispatcher};
use crate::interceptor::process::ProcessTracker;
use crate::monitor::ConnectionManager;
use crate::outbound::chain::ProxyNode;
use crate::outbound::socks5::Socks5Client;
use crate::router::{Action, Rule, RuleEngine};

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

    // 2. 初始化核心组件
    let fake_ip_pool = Arc::new(FakeIpPool::new_default());
    let process_tracker = Arc::new(ProcessTracker::new());
    let connection_manager = Arc::new(ConnectionManager::new());

    // 3. 配置默认代理节点与路由规则
    let mut proxy_nodes = HashMap::new();
    // 注册示范 SOCKS5 节点 (Node 101: 127.0.0.1:10808)
    proxy_nodes.insert(
        101,
        ProxyNodeEntry {
            id: 101,
            name: "Node-101 (主节点)".to_string(),
            protocol: "SOCKS5".to_string(),
            server_addr: "127.0.0.1:10808".to_string(),
            username: None,
            client: ProxyNode::Socks5(Socks5Client::new("127.0.0.1:10808")),
        },
    );
    let proxy_nodes = Arc::new(RwLock::new(proxy_nodes));
    let proxy_chains = Arc::new(HashMap::new());

    // 默认内置分流规则 (自顶向下匹配，带 Fail-Closed 约束保护)
    let rules = vec![
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
    ];
    let rule_engine = Arc::new(RuleEngine::new(rules, Action::Direct));

    // 4. Fail-Fast 端口绑定阶段（确保核心服务端口可用，若被占用立即明确报错）
    let dns_bind: SocketAddr = "127.0.0.1:1053".parse()?;
    let upstream_dns: SocketAddr = "223.5.5.5:53".parse()?;
    let dns_server = DnsServer::new(
        dns_bind,
        Arc::clone(&fake_ip_pool),
        upstream_dns,
        true, // 阻断 AAAA IPv6 泄漏
    );
    let dns_socket = dns_server.bind().await?;

    let dispatcher_bind: SocketAddr = "127.0.0.1:40001".parse()?;
    let dispatcher = StreamDispatcher::new(DispatcherConfig {
        bind_addr: dispatcher_bind,
        tracker: Arc::clone(&process_tracker),
        fake_ip_pool: Arc::clone(&fake_ip_pool),
        rule_engine: Arc::clone(&rule_engine),
        monitor: Arc::clone(&connection_manager),
        proxy_nodes: Arc::clone(&proxy_nodes),
        proxy_chains: Arc::clone(&proxy_chains),
    });
    let dispatcher_listener = dispatcher.bind().await?;

    let api_bind: SocketAddr = "127.0.0.1:40080".parse()?;
    let api_server = ApiServer::new(
        api_bind,
        Arc::clone(&connection_manager),
        Arc::clone(&rule_engine),
        Arc::clone(&proxy_nodes),
    );
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

    // 7. 启动周期性内存 GC 维护任务（每 30 秒自动清理过期 Fake-IP 与进程缓存）
    let pool_gc = Arc::clone(&fake_ip_pool);
    let tracker_gc = Arc::clone(&process_tracker);
    let mut rx_gc = shutdown_rx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let cleaned_ips = pool_gc.cleanup_expired();
                    tracker_gc.cleanup_expired();
                    if cleaned_ips > 0 {
                        tracing::debug!("[GC 维护] 定期回收了 {} 个过期的 Fake-IP 映射", cleaned_ips);
                    }
                }
                _ = rx_gc.changed() => {
                    break;
                }
            }
        }
    });

    // 演示：注入一条初始连通性监视会话
    let _demo_conn = connection_manager.register(
        "flowx.exe".into(),
        std::env::current_exe()?.to_string_lossy().to_string(),
        std::process::id(),
        "api.github.com:443".into(),
        "DevProxy".into(),
        "Proxy(101)".into(),
    );

    info!("[就绪] 控制台已就绪，请在浏览器中访问: http://127.0.0.1:40080");
    info!("[就绪] 按 Ctrl+C 可安全停止 FlowX 核心引擎");

    // 8. 监听操作系统 Ctrl+C 信号并执行优雅停机
    tokio::signal::ctrl_c().await?;
    info!("[退出] 接收到退出信号，正在通知各子系统停止接收流量...");
    let _ = shutdown_tx.send(true);

    // 预留 500ms 宽限时间让正在传输的活跃连接完成挥手
    tokio::time::sleep(Duration::from_millis(500)).await;
    info!("[退出] FlowX 核心引擎已安全退出");

    Ok(())
}
