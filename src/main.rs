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
pub mod transparent;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use anyhow::Context;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use crate::api::{ApiServer, SystemRuntimeContext};
use crate::config::ConfigStore;
use crate::dns::server::DnsServer;
use crate::dns::FakeIpPool;
use crate::interceptor::dispatcher::{DispatcherConfig, StreamDispatcher};
use crate::interceptor::process::ProcessTracker;
use crate::monitor::{ConnectionManager, InFlightTracker};
use crate::router::RuleEngine;
use crate::transparent::TransparentManager;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let raw_args: Vec<String> = std::env::args().collect();
    let wants_json = cli::wants_json_output(&raw_args);
    let (config_path, transparent_override, replace_pid) = match cli::resolve_launch_mode(&raw_args) {
        Ok(cli::LaunchMode::Serve {
            config_path,
            transparent_override,
            replace_pid,
        }) => (config_path, transparent_override, replace_pid),
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

    if let Some(old_pid) = replace_pid {
        info!(
            "[Startup] Waiting up to {}s for previous FlowX instance PID {} to release ports...",
            REPLACE_PID_WAIT_TIMEOUT.as_secs(),
            old_pid
        );
        wait_for_pid_exit(old_pid, REPLACE_PID_WAIT_TIMEOUT).await;
    }

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
    let persisted_transparent_enabled = runtime_profile.transparent_settings.enabled;
    let mut effective_transparent = runtime_profile.transparent_settings;
    if let Some(ov) = transparent_override {
        effective_transparent.enabled = ov;
    }

    // 4. Fail-Fast 端口绑定阶段（确保核心服务端口可用，若被占用立即明确报错）
    let in_flight = Arc::new(InFlightTracker::new());

    let dns_server = Arc::new(
        DnsServer::new(
            dns_bind,
            Arc::clone(&fake_ip_pool),
            upstream_dns,
            true, // 阻断 AAAA IPv6 泄漏
        )
        .with_in_flight(Arc::clone(&in_flight)),
    );
    let dns_socket = dns_server.bind().await?;

    let dispatcher_config = DispatcherConfig {
        bind_addr: dispatcher_bind,
        tracker: Arc::clone(&process_tracker),
        fake_ip_pool: Arc::clone(&fake_ip_pool),
        upstream_dns,
        rule_engine: Arc::clone(&rule_engine),
        monitor: Arc::clone(&connection_manager),
        proxy_nodes: Arc::clone(&proxy_nodes),
        proxy_chains: Arc::clone(&proxy_chains),
        self_ports: self_ports.clone(),
        in_flight: Some(Arc::clone(&in_flight)),
    };
    let dispatcher = StreamDispatcher::new(dispatcher_config.clone())
        .with_in_flight(Arc::clone(&in_flight));
    let dispatcher_listener = dispatcher.bind().await?;

    let transparent_mgr = TransparentManager::new_with_persisted(
        Arc::new(dispatcher_config),
        Arc::clone(&dns_server),
        effective_transparent,
        persisted_transparent_enabled,
    );

    // 5. 初始化全局优雅停机广播通知通道
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

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
    .with_in_flight(Arc::clone(&in_flight))
    .with_transparent_manager(Arc::clone(&transparent_mgr))
    .with_shutdown_sender(shutdown_tx.clone());
    let api_listener = api_server.bind().await?;

    // 6. 若配置或启动参数开启了透明代理，则尝试加载 WinDivert 驱动；失败时保留守护进程并记录诊断供前端修复
    if transparent_mgr.settings().enabled {
        let t_mgr = Arc::clone(&transparent_mgr);
        let rt_handle = tokio::runtime::Handle::current();
        match tokio::task::spawn_blocking(move || t_mgr.start(&rt_handle)).await {
            Ok(Ok(())) => {
                if replace_pid.is_some() && transparent_override == Some(true) {
                    transparent_mgr.set_persisted_enabled(true);
                    let store = Arc::clone(&config_store);
                    let nodes = Arc::clone(&proxy_nodes);
                    let engine = Arc::clone(&rule_engine);
                    let t_settings = transparent_mgr.persisted_settings();
                    if let Err(e) = tokio::task::spawn_blocking(move || {
                        store.save_runtime_with_transparent(&nodes, &engine, Some(&t_settings))
                    })
                    .await
                    .unwrap_or_else(|je| Err(anyhow::anyhow!("save task join error: {je}")))
                    {
                        warn!("[Transparent] Started cleanly via UAC elevation, but failed to persist enabled=true: {:#}", e);
                    }
                }
            }
            Ok(Err(err_msg)) => {
                transparent_mgr.mark_boot_start_failed();
                warn!(
                    "[Transparent] Failed to start automatically on boot (daemon stays active): {}",
                    err_msg
                );
            }
            Err(join_err) => {
                transparent_mgr.mark_boot_start_failed();
                warn!(
                    "[Transparent] Background startup task panicked/cancelled: {}",
                    join_err
                );
            }
        }
    }

    // 7. 在托管 JoinSet 中启动异步核心服务任务，任一核心任务异常提前退出时触发停机并向上返回错误
    let mut core_tasks: tokio::task::JoinSet<(&'static str, anyhow::Result<()>)> = tokio::task::JoinSet::new();

    let rx1 = shutdown_rx.clone();
    let dns_task_srv = Arc::clone(&dns_server);
    core_tasks.spawn(async move {
        let res = dns_task_srv.run(dns_socket, rx1).await;
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

    // 8. 同时等待 OS 停机信号、内部停机通知（如提权交接）与核心任务异常退出
    let mut main_shutdown_rx = shutdown_rx.clone();
    let unexpected_exit = wait_for_shutdown_or_core_exit(
        &mut core_tasks,
        &mut main_shutdown_rx,
        wait_for_shutdown_signal(),
    )
    .await?;
    let _ = shutdown_tx.send(true);
    let t_stop = Arc::clone(&transparent_mgr);
    let _ = tokio::task::spawn_blocking(move || t_stop.stop()).await;

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

async fn wait_for_pid_exit(pid: u32, timeout: Duration) {
    #[cfg(windows)]
    {
        let timeout_ms = timeout.as_millis().min(u32::MAX as u128) as u32;
        let _ = tokio::task::spawn_blocking(move || {
            use windows_sys::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
            use windows_sys::Win32::System::Threading::{
                OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
            };

            let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
            if handle.is_null() {
                return;
            }
            let wait_res = unsafe { WaitForSingleObject(handle, timeout_ms) };
            unsafe {
                CloseHandle(handle);
            }
            if wait_res == WAIT_TIMEOUT {
                warn!(
                    "[Startup] Timed out waiting for PID {} to exit; continuing port bind attempt",
                    pid
                );
            }
        })
        .await;
    }
    #[cfg(not(windows))]
    {
        let _ = (pid, timeout);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
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

const REPLACE_PID_WAIT_TIMEOUT: Duration = Duration::from_secs(20);

async fn wait_for_watch_shutdown(rx: &mut tokio::sync::watch::Receiver<bool>) {
    if *rx.borrow() {
        return;
    }
    while rx.changed().await.is_ok() {
        if *rx.borrow() {
            return;
        }
    }
}

async fn wait_for_shutdown_or_core_exit<F>(
    core_tasks: &mut tokio::task::JoinSet<(&'static str, anyhow::Result<()>)>,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    os_signal_fut: F,
) -> anyhow::Result<Option<anyhow::Error>>
where
    F: std::future::Future<Output = anyhow::Result<&'static str>>,
{
    tokio::pin!(os_signal_fut);
    tokio::select! {
        biased;
        sig_res = &mut os_signal_fut => {
            let sig_name = sig_res?;
            info!("[Shutdown] Received {} signal, stopping inbound traffic...", sig_name);
            Ok(None)
        }
        _ = wait_for_watch_shutdown(shutdown_rx) => {
            info!("[Shutdown] Received internal shutdown signal, stopping inbound traffic...");
            Ok(None)
        }
        joined = core_tasks.join_next() => {
            if *shutdown_rx.borrow() {
                return Ok(None);
            }
            match joined {
                Some(Ok((name, Ok(())))) => {
                    let err = anyhow::anyhow!(
                        "Core service task '{}' exited unexpectedly before shutdown signal",
                        name
                    );
                    tracing::error!("[Shutdown] {:#}", err);
                    Ok(Some(err))
                }
                Some(Ok((name, Err(e)))) => {
                    let err = anyhow::anyhow!("Core service task '{}' failed: {:#}", name, e);
                    tracing::error!("[Shutdown] {:#}", err);
                    Ok(Some(err))
                }
                Some(Err(join_err)) => {
                    let err = anyhow::anyhow!(
                        "Core service task panicked or was cancelled: {}",
                        join_err
                    );
                    tracing::error!("[Shutdown] {:#}", err);
                    Ok(Some(err))
                }
                None => Ok(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_internal_watch_shutdown_exits_cleanly_while_unexpected_task_exit_errors() {
        const { assert!(REPLACE_PID_WAIT_TIMEOUT.as_secs() >= 20) };

        // 1. 收到内部停机信号（如 /api/transparent/elevate 发送 shutdown_tx=true）时，
        //    即使核心任务随之同步退出，也不得判定为 unexpected_exit
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        let mut tasks: tokio::task::JoinSet<(&'static str, anyhow::Result<()>)> =
            tokio::task::JoinSet::new();
        let mut rx_task = rx.clone();
        tasks.spawn(async move {
            wait_for_watch_shutdown(&mut rx_task).await;
            ("api", Ok(()))
        });

        tx.send(true).unwrap();
        let outcome = wait_for_shutdown_or_core_exit(
            &mut tasks,
            &mut rx,
            std::future::pending::<anyhow::Result<&'static str>>(),
        )
        .await
        .unwrap();
        assert!(
            outcome.is_none(),
            "internal shutdown_tx must yield clean exit: {outcome:?}"
        );

        // 2. 未触发 shutdown_tx 时若核心任务自行退出，必须返回 unexpected_exit 错误
        let (_tx2, mut rx2) = tokio::sync::watch::channel(false);
        let mut tasks2: tokio::task::JoinSet<(&'static str, anyhow::Result<()>)> =
            tokio::task::JoinSet::new();
        tasks2.spawn(async { ("dns", Ok(())) });
        let outcome2 = wait_for_shutdown_or_core_exit(
            &mut tasks2,
            &mut rx2,
            std::future::pending::<anyhow::Result<&'static str>>(),
        )
        .await
        .unwrap();
        assert!(outcome2.is_some());
    }
}
