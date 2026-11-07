pub mod config;
pub mod dns;
pub mod interceptor;
pub mod outbound;
pub mod router;

use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use crate::dns::FakeIpPool;
use crate::router::{Action, RouteContext, Rule, RuleEngine};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. 初始化标准日志输出
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("=== FlowX 透明代理与分流核心启动中 (Rust Edition) ===");

    // 2. 初始化 Fake-IP 分配池
    let fake_ip_pool = FakeIpPool::new_default();
    let test_domain = "api.github.com";
    let allocated_ip = fake_ip_pool.allocate(test_domain);
    info!(
        "[Fake-IP 引擎测试] 为域名 {} 分配虚拟 IP: {}",
        test_domain, allocated_ip
    );

    let restored = fake_ip_pool.restore(&allocated_ip);
    info!(
        "[Fake-IP 引擎测试] 从虚拟 IP {} 还原原始域名: {:?}",
        allocated_ip, restored
    );

    // 3. 测试规则路由求值
    let test_rule = Rule {
        name: "DevProxy".into(),
        enabled: true,
        application_patterns: vec![glob::Pattern::new("*node*.exe")?],
        target_patterns: vec![],
        target_subnets: vec![],
        ports: vec![],
        action: Action::Proxy(101),
    };

    let engine = RuleEngine::new(vec![test_rule], Action::Direct);

    let ctx = RouteContext {
        process_path: Some(r"C:\Program Files\nodejs\node.exe"),
        process_name: Some("node.exe"),
        target_host: Some("api.github.com"),
        target_ip: Some(std::net::IpAddr::V4(allocated_ip)),
        target_port: 443,
    };

    let action = engine.evaluate(&ctx);
    info!(
        "[规则路由测试] 匹配进程 '{}' 至目标 {}:{} -> 决策动作: {:?}",
        ctx.process_name.unwrap(),
        ctx.target_host.unwrap(),
        ctx.target_port,
        action
    );

    info!("=== 基础环境与核心模块验证完成，随时待命进入下一阶段 ===");

    Ok(())
}
