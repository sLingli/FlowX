pub mod api;
pub mod cli;
pub mod config;
pub mod dns;
pub mod i18n;
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
use crate::monitor::{ConnectionManager, InFlightTracker};
use crate::router::RuleEngine;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let raw_args: Vec<String> = std::env::args().collect();
    let wants_json = cli::wants_json_output(&raw_args);
    let config_path = match cli::resolve_launch_mode(&raw_args) {
        Ok(cli::LaunchMode::Serve { config_path }) => config_path,
        Ok(cli::LaunchMode::Cli) => {
            if let Err(err) = cli::run_cli(&raw_args).await {
                cli::emit_cli_error_and_exit(&err, wants_json);
            }
            return Ok(());
        }
        Err(err) => cli::emit_cli_error_and_exit(&err, wants_json),
    };

    // 1. 初始化标准结构化日志
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("============================================================");
    info!("     FlowX - Modern Transparent Proxy & Process Routing Engine      ");
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
    let config_store = Arc::new(ConfigStore::new(&config_path));
    let (runtime_profile, created_default) = config_store
        .load_or_init(&self_ports)
        .with_context(|| format!("Failed to load configuration file: {}", config_path))?;
    if created_default {
        info!("[Config] No configuration file found, generated default profile: {}", config_path);
    } else {
        info!(
            "[Config] Loaded profile {} ({} proxy nodes, {} routing rules)",
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
    let in_flight = Arc::new(InFlightTracker::new());

    let dns_server = DnsServer::new(
        dns_bind,
        Arc::clone(&fake_ip_pool),
        upstream_dns,
        true, // 阻断 AAAA IPv6 泄漏
    )
    .with_in_flight(Arc::clone(&in_flight));
    let dns_socket = dns_server.bind().await?;

    let dispatcher = StreamDispatcher::new(DispatcherConfig {
        bind_addr: dispatcher_bind,
        tracker: Arc::clone(&process_tracker),
        fake_ip_pool: Arc::clone(&fake_ip_pool),
        upstream_dns,
        rule_engine: Arc::clone(&rule_engine),
        monitor: Arc::clone(&connection_manager),
        proxy_nodes: Arc::clone(&proxy_nodes),
        proxy_chains: Arc::clone(&proxy_chains),
        self_ports: self_ports.clone(),
    })
    .with_in_flight(Arc::clone(&in_flight));
    let dispatcher_listener = dispatcher.bind().await?;

    let runtime_context = Arc::new(SystemRuntimeContext {
        inbound_addr: dispatcher_bind,
        dns_addr: dns_bind,
        upstream_dns,
        api_addr: api_bind,
        fake_ip_pool: Arc::clone(&fake_ip_pool),
        block_ipv6: true,
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
    .with_runtime_context(runtime_context)
    .with_in_flight(Arc::clone(&in_flight));
    let api_listener = api_server.bind().await?;

    // 5. 初始化全局优雅停机广播通知通道
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // 6. 在托管 JoinSet 中启动异步核心服务任务，任一核心任务异常提前退出时触发停机并向上返回错误
    let mut core_tasks: tokio::task::JoinSet<(&'static str, anyhow::Result<()>)> = tokio::task::JoinSet::new();

    let rx1 = shutdown_rx.clone();
    core_tasks.spawn(async move {
        let res = dns_server.run(dns_socket, rx1).await;
        ("dns", res)
    });

    let rx2 = shutdown_rx.clone();
    core_tasks.spawn(async move {
        let res = dispatcher.run(dispatcher_listener, rx2).await;
        ("dispatcher", res)
    });

    let rx3 = shutdown_rx.clone();
    core_tasks.spawn(async move {
        let res = api_server.run(api_listener, rx3).await;
        ("api", res)
    });

    // 7. 启动周期性内存 GC 维护任务（每 3 秒通过 blocking 线程池异步清理过期 Fake-IP 与进程缓存，避免阻塞 Tokio Worker）
    let pool_gc = Arc::clone(&fake_ip_pool);
    let tracker_gc = Arc::clone(&process_tracker);
    let mut rx_gc = shutdown_rx.clone();
    core_tasks.spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            if *rx_gc.borrow() {
                break;
            }
            tokio::select! {
                _ = interval.tick() => {
                    let pool_task = Arc::clone(&pool_gc);
                    let tracker_task = Arc::clone(&tracker_gc);
                    if let Ok((cleaned_ips, cleaned_pids, cleaned_neg)) =
                        tokio::task::spawn_blocking(move || {
                            let cleaned_ips = pool_task.cleanup_expired();
                            let (cleaned_pids, cleaned_neg) = tracker_task.cleanup_expired();
                            (cleaned_ips, cleaned_pids, cleaned_neg)
                        })
                        .await
                        && (cleaned_ips > 0 || cleaned_pids > 0 || cleaned_neg > 0)
                    {
                        tracing::debug!(
                            "[GC] Periodic expired entry collection: Fake-IP={}, PID={}, NegPID={}",
                            cleaned_ips,
                            cleaned_pids,
                            cleaned_neg
                        );
                    }
                }
                _ = rx_gc.changed() => {
                    break;
                }
            }
        }
        ("gc", Ok(()))
    });

    info!("[Ready] Web console ready at: http://127.0.0.1:40080");
    info!("[Ready] Press Ctrl+C (or send SIGTERM) to stop FlowX core");

    // 8. 同时等待 OS 停机信号与核心任务异常退出
    let mut unexpected_exit: Option<anyhow::Error> = None;
    tokio::select! {
        sig_res = wait_for_shutdown_signal() => {
            let sig_name = sig_res?;
            info!("[Shutdown] Received {} signal, stopping inbound traffic...", sig_name);
        }
        joined = core_tasks.join_next() => {
            match joined {
                Some(Ok((name, Ok(())))) => {
                    let err = anyhow::anyhow!("Core service task '{}' exited unexpectedly before shutdown signal", name);
                    tracing::error!("[Shutdown] {:#}", err);
                    unexpected_exit = Some(err);
                }
                Some(Ok((name, Err(e)))) => {
                    let err = anyhow::anyhow!("Core service task '{}' failed: {:#}", name, e);
                    tracing::error!("[Shutdown] {:#}", err);
                    unexpected_exit = Some(err);
                }
                Some(Err(join_err)) => {
                    let err = anyhow::anyhow!("Core service task panicked or was cancelled: {}", join_err);
                    tracing::error!("[Shutdown] {:#}", err);
                    unexpected_exit = Some(err);
                }
                None => {}
            }
        }
    }
    let _ = shutdown_tx.send(true);

    // 优雅排空：等待所有核心循环退出且活跃连接 + 在途请求完全排空（最多等待 10 秒）
    let drain_start = std::time::Instant::now();
    let max_drain_wait = Duration::from_secs(10);
    while !core_tasks.is_empty() && drain_start.elapsed() < max_drain_wait {
        let remaining = max_drain_wait.saturating_sub(drain_start.elapsed());
        if tokio::time::timeout(remaining, core_tasks.join_next()).await.is_err() {
            break;
        }
    }
    while drain_start.elapsed() < max_drain_wait {
        let active = connection_manager.active_count();
        let pending = in_flight.count();
        if active == 0 && pending == 0 {
            break;
        }
        info!(
            "[Shutdown] Waiting for {} active connections and {} in-flight tasks to drain...",
            active,
            pending
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    if !core_tasks.is_empty() {
        core_tasks.abort_all();
        while core_tasks.join_next().await.is_some() {}
    }

    if let Some(err) = unexpected_exit {
        return Err(err);
    }
    info!("[Shutdown] FlowX core stopped cleanly");

    Ok(())
}

async fn wait_for_shutdown_signal() -> anyhow::Result<&'static str> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())
            .context("Failed to register SIGTERM signal handler")?;
        tokio::select! {
            res = tokio::signal::ctrl_c() => {
                res.context("Failed to listen for SIGINT (Ctrl+C)")?;
                Ok("SIGINT (Ctrl+C)")
            }
            Some(()) = sigterm.recv() => {
                Ok("SIGTERM")
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("Failed to listen for Ctrl+C shutdown signal")?;
        Ok("Ctrl+C")
    }
}
