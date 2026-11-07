pub mod api;
pub mod config;
pub mod dns;
pub mod interceptor;
pub mod monitor;
pub mod outbound;
pub mod router;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use crate::api::ApiServer;
use crate::dns::server::DnsServer;
use crate::dns::FakeIpPool;
use crate::interceptor::dispatcher::{DispatcherConfig, StreamDispatcher};
use crate::interceptor::process::ProcessTracker;
use crate::monitor::ConnectionManager;
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
    proxy_nodes.insert(101, Socks5Client::new("127.0.0.1:10808"));
    let proxy_nodes = Arc::new(proxy_nodes);
    let proxy_chains = Arc::new(HashMap::new());

    // 默认内置分流规则 (自顶向下匹配)
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

    // 4. 启动本地 DNS 拦截与 Fake-IP 服务 (异步任务)
    let dns_bind: SocketAddr = "127.0.0.1:1053".parse()?;
    let upstream_dns: SocketAddr = "223.5.5.5:53".parse()?;
    let dns_server = DnsServer::new(
        dns_bind,
        Arc::clone(&fake_ip_pool),
        upstream_dns,
        true, // 阻断 AAAA IPv6 泄漏
    );
    tokio::spawn(async move {
        if let Err(e) = dns_server.run().await {
            tracing::error!("[DNS 模块] DNS 服务异常退出: {}", e);
        }
    });

    // 5. 启动透明流调度中心 (异步任务)
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
    tokio::spawn(async move {
        if let Err(e) = dispatcher.run().await {
            tracing::error!("[调度中心] 透明流调度服务异常退出: {}", e);
        }
    });

    // 6. 启动现代化 Web 控制台与 REST 遥测 API 服务 (异步任务)
    let api_bind: SocketAddr = "127.0.0.1:40080".parse()?;
    let api_server = ApiServer::new(api_bind, Arc::clone(&connection_manager));
    tokio::spawn(async move {
        if let Err(e) = api_server.run().await {
            tracing::error!("[Web 控制台] API 服务异常退出: {}", e);
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

    // 7. 优雅监听系统 Ctrl+C 退出信号
    tokio::signal::ctrl_c().await?;
    info!("[退出] 接收到退出信号，FlowX 核心已安全停止");

    Ok(())
}
