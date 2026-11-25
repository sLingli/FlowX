#[cfg(not(windows))]
compile_error!("FlowX only supports Windows.");

#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    entry::run().await
}

#[cfg(windows)]
mod entry {
    use anyhow::Context;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, RwLock};
    use std::time::{Duration, Instant};
    use tracing::{Level, info, warn};
    use tracing_subscriber::FmtSubscriber;

    use flowx::api::{ApiServer, SystemRuntimeContext};
    use flowx::cli;
    use flowx::config::ConfigStore;
    use flowx::dns::FakeIpPool;
    use flowx::dns::server::DnsServer;
    use flowx::interceptor::dispatcher::{DispatcherConfig, StreamDispatcher};
    use flowx::interceptor::process::ProcessTracker;
    use flowx::monitor::{ConnectionManager, InFlightTracker};
    use flowx::router::RuleEngine;
    use flowx::transparent::TransparentManager;

    pub(super) const REPLACE_PID_WAIT_TIMEOUT: Duration = Duration::from_secs(20);
    const NORMAL_DRAIN_WAIT: Duration = Duration::from_secs(10);
    const URGENT_DRAIN_WAIT: Duration = Duration::from_secs(2);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) struct OsShutdownSignal {
        pub(super) name: &'static str,
        /// `CTRL_CLOSE_EVENT` / `CTRL_LOGOFF_EVENT` / `CTRL_SHUTDOWN_EVENT` 下 Windows 仅留数秒退出窗口
        pub(super) urgent: bool,
    }

    #[derive(Debug)]
    pub(super) enum ShutdownOutcome {
        OsSignal(OsShutdownSignal),
        InternalHandoff,
        UnexpectedExit(anyhow::Error),
    }

    /// 兜底守卫：保证任何异常退出或提前返回路径都会幂等停止透明代理并刷新 DNS 缓存
    struct TransparentStopGuard {
        mgr: Arc<TransparentManager>,
        stopped: bool,
    }

    impl TransparentStopGuard {
        fn new(mgr: Arc<TransparentManager>) -> Self {
            Self {
                mgr,
                stopped: false,
            }
        }

        async fn stop_async(&mut self) {
            if self.stopped {
                return;
            }
            self.stopped = true;
            let t_stop = Arc::clone(&self.mgr);
            let _ = tokio::task::spawn_blocking(move || t_stop.stop()).await;
        }
    }

    impl Drop for TransparentStopGuard {
        fn drop(&mut self) {
            if !self.stopped {
                self.stopped = true;
                self.mgr.stop();
            }
        }
    }

    pub(super) async fn run() -> anyhow::Result<()> {
        let raw_args: Vec<String> = std::env::args().collect();
        let wants_json = cli::wants_json_output(&raw_args);
        let (config_path, transparent_override, replace_pid) =
            match cli::resolve_launch_mode(&raw_args) {
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

        // 1. 初始化标准结构化日志（支持通过 FLOWX_LOG / RUST_LOG 调整日志级别，默认 INFO）
        let subscriber = FmtSubscriber::builder()
            .with_max_level(resolve_log_level())
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
        let dns_bind: SocketAddr = "127.0.0.1:1053".parse()?;
        let upstream_dns: SocketAddr = "223.5.5.5:53".parse()?;
        let dispatcher_bind: SocketAddr = "127.0.0.1:40001".parse()?;
        let api_bind: SocketAddr = "127.0.0.1:40080".parse()?;
        let self_ports = vec![dispatcher_bind.port(), api_bind.port(), dns_bind.port()];

        let fake_ip_pool = Arc::new(FakeIpPool::new_default().with_self_ports(self_ports.clone()));
        let process_tracker = Arc::new(ProcessTracker::new());
        let connection_manager = Arc::new(ConnectionManager::new());

        // 3. 从 XML 配置文件加载代理节点与路由规则（缺失时自动生成默认配置）
        let config_store = Arc::new(ConfigStore::new(&config_path));
        let (runtime_profile, created_default) = config_store
            .load_or_init(&self_ports)
            .with_context(|| format!("Failed to load configuration file: {}", config_path))?;
        if created_default {
            info!(
                "[Config] No configuration file found, generated default profile: {}",
                config_path
            );
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
        let dispatcher =
            StreamDispatcher::new(dispatcher_config.clone()).with_in_flight(Arc::clone(&in_flight));
        let dispatcher_listener = dispatcher.bind().await?;

        let transparent_mgr = TransparentManager::new_with_persisted(
            Arc::new(dispatcher_config),
            Arc::clone(&dns_server),
            effective_transparent,
            persisted_transparent_enabled,
        );
        let mut transparent_stop_guard = TransparentStopGuard::new(Arc::clone(&transparent_mgr));

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
                            warn!(
                                "[Transparent] Started cleanly via UAC elevation, but failed to persist enabled=true: {:#}",
                                e
                            );
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
        let mut core_tasks: tokio::task::JoinSet<(&'static str, anyhow::Result<()>)> =
            tokio::task::JoinSet::new();

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

        // 启动周期性内存 GC 维护任务（每 3 秒通过 blocking 线程池异步清理过期 Fake-IP 与进程缓存，避免阻塞 Tokio Worker）
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
                        if let Ok((cleaned_ips, cleaned_pids)) =
                            tokio::task::spawn_blocking(move || {
                                let cleaned_ips = pool_task.cleanup_expired();
                                let cleaned_pids = tracker_task.cleanup_expired();
                                (cleaned_ips, cleaned_pids)
                            })
                            .await
                            && (cleaned_ips > 0 || cleaned_pids > 0)
                        {
                            tracing::debug!(
                                "[GC] Periodic expired entry collection: Fake-IP={}, PID={}",
                                cleaned_ips,
                                cleaned_pids
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
        info!("[Ready] Press Ctrl+C (or close console window) to stop FlowX core");

        // 8. 同时等待 Windows 控制台停机信号、内部停机通知（如提权交接）与核心任务异常退出
        let mut main_shutdown_rx = shutdown_rx.clone();
        let wait_result = wait_for_shutdown_or_core_exit(
            &mut core_tasks,
            &mut main_shutdown_rx,
            wait_for_shutdown_signal(),
        )
        .await;

        let (urgent_shutdown, cancel_active_conns, final_error) = match wait_result {
            Ok(ShutdownOutcome::OsSignal(sig)) => (sig.urgent, sig.urgent, None),
            Ok(ShutdownOutcome::InternalHandoff) => (false, true, None),
            Ok(ShutdownOutcome::UnexpectedExit(err)) => (false, true, Some(err)),
            Err(err) => (true, true, Some(err)),
        };

        // 优先通知核心服务停机并立刻关闭 WinDivert + 冲刷系统 DNS 缓存，确保在 Windows 关窗/注销超时前消除 Fake-IP 残留
        let _ = shutdown_tx.send(true);
        transparent_stop_guard.stop_async().await;

        // 优雅排空：等待所有核心循环（包括释放监听端口与回写 /api/transparent/elevate 的 200 OK）退出
        let drain_start = Instant::now();
        let max_drain_wait = if urgent_shutdown {
            URGENT_DRAIN_WAIT
        } else {
            NORMAL_DRAIN_WAIT
        };
        while !core_tasks.is_empty() && drain_start.elapsed() < max_drain_wait {
            let remaining = max_drain_wait.saturating_sub(drain_start.elapsed());
            if tokio::time::timeout(remaining, core_tasks.join_next())
                .await
                .is_err()
            {
                break;
            }
        }
        if cancel_active_conns {
            let killed = connection_manager.kill_all_connections();
            if killed > 0 {
                info!(
                    "[Shutdown] Cancelled {} lingering active connections for fast handoff/exit",
                    killed
                );
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
                active, pending
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !core_tasks.is_empty() {
            core_tasks.abort_all();
            while core_tasks.join_next().await.is_some() {}
        }

        if let Some(err) = final_error {
            return Err(err);
        }
        info!("[Shutdown] FlowX core stopped cleanly");

        Ok(())
    }

    async fn wait_for_pid_exit(pid: u32, timeout: Duration) {
        let timeout_ms = timeout.as_millis().min(u32::MAX as u128) as u32;
        let _ = tokio::task::spawn_blocking(move || {
            use windows_sys::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
            use windows_sys::Win32::System::Threading::{
                OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
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

    async fn wait_for_shutdown_signal() -> anyhow::Result<OsShutdownSignal> {
        use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_logoff, ctrl_shutdown};

        let mut sig_c = ctrl_c().context("Failed to register Windows CTRL_C handler")?;
        let mut sig_break =
            ctrl_break().context("Failed to register Windows CTRL_BREAK handler")?;
        let mut sig_close =
            ctrl_close().context("Failed to register Windows CTRL_CLOSE handler")?;
        let mut sig_logoff =
            ctrl_logoff().context("Failed to register Windows CTRL_LOGOFF handler")?;
        let mut sig_shutdown =
            ctrl_shutdown().context("Failed to register Windows CTRL_SHUTDOWN handler")?;

        tokio::select! {
            Some(()) = sig_c.recv() => Ok(OsShutdownSignal { name: "Ctrl+C", urgent: false }),
            Some(()) = sig_break.recv() => Ok(OsShutdownSignal { name: "Ctrl+Break", urgent: false }),
            Some(()) = sig_close.recv() => Ok(OsShutdownSignal { name: "Console Close", urgent: true }),
            Some(()) = sig_logoff.recv() => Ok(OsShutdownSignal { name: "Windows Logoff", urgent: true }),
            Some(()) = sig_shutdown.recv() => Ok(OsShutdownSignal { name: "Windows Shutdown", urgent: true }),
        }
    }

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

    pub(super) async fn wait_for_shutdown_or_core_exit<F>(
        core_tasks: &mut tokio::task::JoinSet<(&'static str, anyhow::Result<()>)>,
        shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
        os_signal_fut: F,
    ) -> anyhow::Result<ShutdownOutcome>
    where
        F: std::future::Future<Output = anyhow::Result<OsShutdownSignal>>,
    {
        tokio::pin!(os_signal_fut);
        tokio::select! {
            biased;
            sig_res = &mut os_signal_fut => {
                let sig = sig_res?;
                info!("[Shutdown] Received {} signal, stopping inbound traffic...", sig.name);
                Ok(ShutdownOutcome::OsSignal(sig))
            }
            _ = wait_for_watch_shutdown(shutdown_rx) => {
                info!("[Shutdown] Received internal shutdown signal, stopping inbound traffic...");
                Ok(ShutdownOutcome::InternalHandoff)
            }
            joined = core_tasks.join_next() => {
                if *shutdown_rx.borrow() {
                    return Ok(ShutdownOutcome::InternalHandoff);
                }
                match joined {
                    Some(Ok((name, Ok(())))) => {
                        let err = anyhow::anyhow!(
                            "Core service task '{}' exited unexpectedly before shutdown signal",
                            name
                        );
                        tracing::error!("[Shutdown] {:#}", err);
                        Ok(ShutdownOutcome::UnexpectedExit(err))
                    }
                    Some(Ok((name, Err(e)))) => {
                        let err = anyhow::anyhow!("Core service task '{}' failed: {:#}", name, e);
                        tracing::error!("[Shutdown] {:#}", err);
                        Ok(ShutdownOutcome::UnexpectedExit(err))
                    }
                    Some(Err(join_err)) => {
                        let err = anyhow::anyhow!(
                            "Core service task panicked or was cancelled: {}",
                            join_err
                        );
                        tracing::error!("[Shutdown] {:#}", err);
                        Ok(ShutdownOutcome::UnexpectedExit(err))
                    }
                    None => Ok(ShutdownOutcome::InternalHandoff),
                }
            }
        }
    }

    fn parse_log_level(raw: Option<&str>) -> Level {
        match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("trace") => Level::TRACE,
            Some("debug") => Level::DEBUG,
            Some("warn" | "warning") => Level::WARN,
            Some("error") => Level::ERROR,
            _ => Level::INFO,
        }
    }

    fn resolve_log_level() -> Level {
        let raw = std::env::var("FLOWX_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .or_else(|| {
                std::env::var("RUST_LOG")
                    .ok()
                    .filter(|v| !v.trim().is_empty())
            });
        parse_log_level(raw.as_deref())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_parse_log_level() {
            assert_eq!(parse_log_level(None), Level::INFO);
            assert_eq!(parse_log_level(Some("")), Level::INFO);
            assert_eq!(parse_log_level(Some("debug")), Level::DEBUG);
            assert_eq!(parse_log_level(Some(" DEBUG ")), Level::DEBUG);
            assert_eq!(parse_log_level(Some("trace")), Level::TRACE);
            assert_eq!(parse_log_level(Some("warning")), Level::WARN);
            assert_eq!(parse_log_level(Some("error")), Level::ERROR);
        }

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
                std::future::pending::<anyhow::Result<OsShutdownSignal>>(),
            )
            .await
            .unwrap();
            assert!(
                matches!(outcome, ShutdownOutcome::InternalHandoff),
                "internal shutdown_tx must yield InternalHandoff: {outcome:?}"
            );

            // 2. 未触发 shutdown_tx 时若核心任务自行退出，必须返回 UnexpectedExit 错误
            let (_tx2, mut rx2) = tokio::sync::watch::channel(false);
            let mut tasks2: tokio::task::JoinSet<(&'static str, anyhow::Result<()>)> =
                tokio::task::JoinSet::new();
            tasks2.spawn(async { ("dns", Ok(())) });
            let outcome2 = wait_for_shutdown_or_core_exit(
                &mut tasks2,
                &mut rx2,
                std::future::pending::<anyhow::Result<OsShutdownSignal>>(),
            )
            .await
            .unwrap();
            assert!(matches!(outcome2, ShutdownOutcome::UnexpectedExit(_)));

            // 3. 紧急控制台关闭信号（CTRL_CLOSE / LOGOFF / SHUTDOWN）必须带 urgent=true 返回
            let (_tx3, mut rx3) = tokio::sync::watch::channel(false);
            let mut tasks3: tokio::task::JoinSet<(&'static str, anyhow::Result<()>)> =
                tokio::task::JoinSet::new();
            let outcome3 = wait_for_shutdown_or_core_exit(
                &mut tasks3,
                &mut rx3,
                std::future::ready(Ok(OsShutdownSignal {
                    name: "Console Close",
                    urgent: true,
                })),
            )
            .await
            .unwrap();
            assert!(matches!(
                outcome3,
                ShutdownOutcome::OsSignal(OsShutdownSignal {
                    name: "Console Close",
                    urgent: true
                })
            ));

            // 4. 信号注册失败时返回 Err，调用方可在退出前先完成透明代理停机与 DNS 清理
            let (_tx4, mut rx4) = tokio::sync::watch::channel(false);
            let mut tasks4: tokio::task::JoinSet<(&'static str, anyhow::Result<()>)> =
                tokio::task::JoinSet::new();
            let err4 = wait_for_shutdown_or_core_exit(
                &mut tasks4,
                &mut rx4,
                std::future::ready(Err(anyhow::anyhow!("signal init failed"))),
            )
            .await
            .unwrap_err();
            assert!(err4.to_string().contains("signal init failed"));
        }

        #[tokio::test]
        async fn test_windows_console_signal_handlers_register_and_kill_all_connections_cancels() {
            use tokio::signal::windows::{
                ctrl_break, ctrl_c, ctrl_close, ctrl_logoff, ctrl_shutdown,
            };
            // 验证所有 5 类 Windows 控制台事件处理器均可在当前运行环境正常注册
            assert!(ctrl_c().is_ok());
            assert!(ctrl_break().is_ok());
            assert!(ctrl_close().is_ok());
            assert!(ctrl_logoff().is_ok());
            assert!(ctrl_shutdown().is_ok());

            let mgr = ConnectionManager::new();
            let c1 = mgr.register(
                "app.exe".into(),
                r"C:\app.exe".into(),
                100,
                "1.1.1.1:443".into(),
                "R1".into(),
                "Direct".into(),
                None,
            );
            let c2 = mgr.register(
                "app.exe".into(),
                r"C:\app.exe".into(),
                100,
                "8.8.8.8:443".into(),
                "R1".into(),
                "Direct".into(),
                None,
            );
            assert_eq!(mgr.kill_all_connections(), 2);
            assert!(c1.is_cancelled());
            assert!(c2.is_cancelled());
        }
    }
}
