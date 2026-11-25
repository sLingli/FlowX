pub mod dns_hijack;
pub mod fragment;
pub mod netstack;
pub mod pid_table;
mod platform;
mod runtime;
pub mod sniffer;
pub mod windivert_ffi;

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::dns::server::DnsServer;
use crate::interceptor::dispatcher::DispatcherConfig;

pub use platform::{
    build_elevated_relaunch_args, flush_dns_cache, is_low_integrity_process, is_process_elevated,
    quote_windows_arg, relaunch_elevated_with_replace_pid,
};
#[allow(unused_imports)]
pub(crate) use platform::{
    is_low_integrity_rid, process_integrity_rid, SECURITY_MANDATORY_MEDIUM_RID,
};
#[allow(unused_imports)]
pub(crate) use runtime::{
    next_net_rx_buf_len, windivert_dns_inspect_inbound_filter, windivert_network_filter,
    INITIAL_NET_RX_BUF_LEN, MAX_NET_RX_BUF_LEN,
};

use runtime::{start_windivert_runtime, stop_windivert_runtime, ActiveRuntime};

/// 透明代理配置（持久化至 `<TransparentProxy>`）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransparentSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub hijack_dns: bool,
    #[serde(default = "default_true")]
    pub block_quic_for_proxied: bool,
    #[serde(default)]
    pub dll_path: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for TransparentSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            hijack_dns: true,
            block_quic_for_proxied: true,
            dll_path: None,
        }
    }
}

/// 透明代理运行时诊断与流量统计快照
#[derive(Debug, Clone, Serialize)]
pub struct TransparentRuntimeStatus {
    pub supported: bool,
    pub enabled: bool,
    pub running: bool,
    pub elevated: bool,
    pub low_integrity: bool,
    pub dll_found: bool,
    pub sys_found: bool,
    pub dll_path: Option<String>,
    pub sys_path: Option<String>,
    pub searched_dirs: Vec<String>,
    pub driver_version: Option<String>,
    pub active_flows: usize,
    pub tcp_intercepted_total: u64,
    pub tcp_passthrough_total: u64,
    pub tcp_blocked_rst_total: u64,
    pub dns_hijacked_total: u64,
    pub quic_blocked_total: u64,
    pub hijack_dns: bool,
    pub block_quic_for_proxied: bool,
    pub configured_dll_path: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Default)]
pub(super) struct TransparentStatsCounters {
    pub(super) active_flows: AtomicUsize,
    pub(super) tcp_intercepted_total: AtomicU64,
    pub(super) tcp_passthrough_total: AtomicU64,
    pub(super) tcp_blocked_rst_total: AtomicU64,
    pub(super) dns_hijacked_total: AtomicU64,
    pub(super) quic_blocked_total: AtomicU64,
}

/// 校验用户输入的自定义 WinDivert DLL 路径：
/// - 拒绝控制字符或超过 4096 字节的输入；
/// - 允许空/空白（语义上等同于清除自定义路径、恢复自动探测）；
/// - 非空时必须通过 `resolve_candidate_dll_path`（本机绝对路径、无 `..`/UNC、目录或 `WinDivert.dll`）。
pub(crate) fn is_valid_custom_dll_path_input(raw: &str) -> bool {
    if raw.chars().any(char::is_control) || raw.len() > 4096 {
        return false;
    }
    let trimmed = raw.trim();
    trimmed.is_empty() || windivert_ffi::resolve_candidate_dll_path(trimmed).is_some()
}

/// 基于给定静态配置构建驱动探测快照（供 CLI 离线查询与测试降级复用）
pub fn probe_status(cfg: &TransparentSettings) -> TransparentRuntimeStatus {
    let avail = windivert_ffi::locate_windivert_files(cfg.dll_path.as_deref());

    TransparentRuntimeStatus {
        supported: true,
        enabled: cfg.enabled,
        running: false,
        elevated: is_process_elevated(),
        low_integrity: is_low_integrity_process(),
        dll_found: avail.dll_found,
        sys_found: avail.sys_found,
        dll_path: avail.dll_path,
        sys_path: avail.sys_path,
        searched_dirs: avail.searched_dirs,
        driver_version: None,
        active_flows: 0,
        tcp_intercepted_total: 0,
        tcp_passthrough_total: 0,
        tcp_blocked_rst_total: 0,
        dns_hijacked_total: 0,
        quic_blocked_total: 0,
        hijack_dns: cfg.hijack_dns,
        block_quic_for_proxied: cfg.block_quic_for_proxied,
        configured_dll_path: cfg.dll_path.clone(),
        last_error: None,
    }
}

/// 透明代理全生命周期管理器：负责 WinDivert 驱动加载、双层截获线程调度、错误诊断与 Drop 安全回收
pub struct TransparentManager {
    dispatcher_config: Arc<DispatcherConfig>,
    dns_server: Arc<DnsServer>,
    settings: Mutex<TransparentSettings>,
    persisted_enabled: AtomicBool,
    live_hijack_dns: Arc<AtomicBool>,
    live_block_quic: Arc<AtomicBool>,
    stats: Arc<TransparentStatsCounters>,
    last_error: Mutex<Option<String>>,
    lifecycle_lock: Mutex<()>,
    runtime: Mutex<Option<ActiveRuntime>>,
}

impl TransparentManager {
    pub fn new(
        dispatcher_config: Arc<DispatcherConfig>,
        dns_server: Arc<DnsServer>,
        initial_settings: TransparentSettings,
    ) -> Arc<Self> {
        let persisted_enabled = initial_settings.enabled;
        Self::new_with_persisted(
            dispatcher_config,
            dns_server,
            initial_settings,
            persisted_enabled,
        )
    }

    /// 构造透明代理管理器并显式区分磁盘持久化开关 `persisted_enabled` 与临时启动覆写开关 `initial_settings.enabled`
    pub fn new_with_persisted(
        dispatcher_config: Arc<DispatcherConfig>,
        dns_server: Arc<DnsServer>,
        initial_settings: TransparentSettings,
        persisted_enabled: bool,
    ) -> Arc<Self> {
        let hijack = initial_settings.hijack_dns;
        let block_quic = initial_settings.block_quic_for_proxied;
        Arc::new(Self {
            dispatcher_config,
            dns_server,
            settings: Mutex::new(initial_settings),
            persisted_enabled: AtomicBool::new(persisted_enabled),
            live_hijack_dns: Arc::new(AtomicBool::new(hijack)),
            live_block_quic: Arc::new(AtomicBool::new(block_quic)),
            stats: Arc::new(TransparentStatsCounters::default()),
            last_error: Mutex::new(None),
            lifecycle_lock: Mutex::new(()),
            runtime: Mutex::new(None),
        })
    }

    pub fn settings(&self) -> TransparentSettings {
        self.settings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 返回应持久化写入配置文件的透明代理设置（不被 `--transparent` / `--no-transparent` 临时启动参数污染）
    pub fn persisted_settings(&self) -> TransparentSettings {
        let mut cfg = self.settings();
        cfg.enabled = self.persisted_enabled.load(Ordering::Acquire);
        cfg
    }

    pub fn set_persisted_enabled(&self, enabled: bool) {
        self.persisted_enabled.store(enabled, Ordering::Release);
    }

    pub fn is_running(&self) -> bool {
        self.runtime
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    pub fn status(&self) -> TransparentRuntimeStatus {
        let cfg = self.settings();
        let last_error = self
            .last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        let (running, driver_version) = {
            let guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            (
                guard.is_some(),
                guard.as_ref().and_then(|rt| rt.driver_version.clone()),
            )
        };

        let mut st = probe_status(&cfg);
        st.running = running;
        st.driver_version = driver_version;
        st.active_flows = self.stats.active_flows.load(Ordering::Relaxed);
        st.tcp_intercepted_total = self.stats.tcp_intercepted_total.load(Ordering::Relaxed);
        st.tcp_passthrough_total = self.stats.tcp_passthrough_total.load(Ordering::Relaxed);
        st.tcp_blocked_rst_total = self.stats.tcp_blocked_rst_total.load(Ordering::Relaxed);
        st.dns_hijacked_total = self.stats.dns_hijacked_total.load(Ordering::Relaxed);
        st.quic_blocked_total = self.stats.quic_blocked_total.load(Ordering::Relaxed);
        st.last_error = last_error;
        st
    }

    /// 根据新配置热启/热停透明代理或更新实时开关；若启用失败返回明确错误码字符串
    pub fn apply_settings(
        &self,
        next: TransparentSettings,
        rt_handle: &tokio::runtime::Handle,
    ) -> Result<(), String> {
        let _guard = self
            .lifecycle_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let prev = self
            .settings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        *self.settings.lock().unwrap_or_else(|e| e.into_inner()) = next.clone();
        self.live_hijack_dns
            .store(next.hijack_dns, Ordering::Release);
        self.live_block_quic
            .store(next.block_quic_for_proxied, Ordering::Release);

        if !next.enabled {
            self.stop_locked();
            *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = None;
            return Ok(());
        }

        if prev.dll_path != next.dll_path && self.is_running() {
            self.stop_locked();
        }

        if let Err(err) = self.start_locked(rt_handle, &next) {
            *self.settings.lock().unwrap_or_else(|e| e.into_inner()) = prev.clone();
            self.live_hijack_dns
                .store(prev.hijack_dns, Ordering::Release);
            self.live_block_quic
                .store(prev.block_quic_for_proxied, Ordering::Release);
            if prev.enabled && prev.dll_path != next.dll_path {
                let _ = self.start_locked(rt_handle, &prev);
            }
            return Err(err);
        }
        Ok(())
    }

    /// 启动期自动开启失败时将运行时 `enabled` 复位为 `false`，同时保留 `persisted_enabled` 与错误诊断，
    /// 避免后续在线更新 `dll_path` 或附加配置时因沿用 `enabled = true` 而被回滚锁死。
    pub fn mark_boot_start_failed(&self) {
        let mut guard = self.settings.lock().unwrap_or_else(|e| e.into_inner());
        guard.enabled = false;
    }

    /// 在线更新透明代理附加配置（`hijack_dns` / `block_quic_for_proxied` / `dll_path`）：
    /// 若当前处于运行态，仍按热重启 semantics 执行并在失败时回滚；若当前未运行，则直接提交新配置供后续启用或提权生效。
    pub fn apply_config_update(
        &self,
        mut next: TransparentSettings,
        rt_handle: &tokio::runtime::Handle,
    ) -> Result<(), String> {
        if self.is_running() {
            return self.apply_settings(next, rt_handle);
        }

        let _guard = self
            .lifecycle_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        self.live_hijack_dns
            .store(next.hijack_dns, Ordering::Release);
        self.live_block_quic
            .store(next.block_quic_for_proxied, Ordering::Release);

        if next.enabled {
            match self.start_locked(rt_handle, &next) {
                Ok(()) => {
                    *self.settings.lock().unwrap_or_else(|e| e.into_inner()) = next;
                    *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = None;
                }
                Err(_) => {
                    next.enabled = false;
                    *self.settings.lock().unwrap_or_else(|e| e.into_inner()) = next;
                }
            }
        } else {
            *self.settings.lock().unwrap_or_else(|e| e.into_inner()) = next;
        }
        Ok(())
    }

    /// 尝试按照当前 `settings` 启动透明代理
    pub fn start(&self, rt_handle: &tokio::runtime::Handle) -> Result<(), String> {
        let _guard = self
            .lifecycle_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let cfg = self.settings();
        self.live_hijack_dns
            .store(cfg.hijack_dns, Ordering::Release);
        self.live_block_quic
            .store(cfg.block_quic_for_proxied, Ordering::Release);
        self.start_locked(rt_handle, &cfg)
    }

    /// 幂等关闭所有 WinDivert 句柄并等待工作线程退出、冲刷 DNS 缓存
    pub fn stop(&self) {
        let _guard = self
            .lifecycle_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.stop_locked();
    }

    fn set_error(&self, msg: String) -> String {
        *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(msg.clone());
        msg
    }

    fn start_locked(
        &self,
        rt_handle: &tokio::runtime::Handle,
        cfg: &TransparentSettings,
    ) -> Result<(), String> {
        if self.runtime.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
            return Ok(());
        }

        let active = start_windivert_runtime(
            cfg,
            rt_handle,
            &self.dispatcher_config,
            &self.dns_server,
            &self.live_hijack_dns,
            &self.live_block_quic,
            &self.stats,
        )
        .map_err(|err| self.set_error(err))?;

        *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self.runtime.lock().unwrap_or_else(|e| e.into_inner()) = Some(active);
        Ok(())
    }

    fn stop_locked(&self) {
        let rt_opt = self.runtime.lock().unwrap_or_else(|e| e.into_inner()).take();
        let Some(rt) = rt_opt else {
            return;
        };
        stop_windivert_runtime(rt, &self.stats);
    }
}

impl Drop for TransparentManager {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform::{load_system32_library, resolve_system32_executable, StaComGuard};

    #[test]
    fn test_transparent_settings_defaults_and_elevation_arg_quoting() {
        let def = TransparentSettings::default();
        assert!(!def.enabled);
        assert!(def.hijack_dns);
        assert!(def.block_quic_for_proxied);
        assert!(def.dll_path.is_none());

        assert_eq!(quote_windows_arg("--transparent"), "--transparent");
        assert_eq!(quote_windows_arg(r"C:\Dir\"), r"C:\Dir\");
        assert_eq!(
            quote_windows_arg(r"C:\Program Files\FlowX\profile.xml"),
            r#""C:\Program Files\FlowX\profile.xml""#
        );
        assert_eq!(quote_windows_arg(r"C:\My Dir\"), r#""C:\My Dir\\""#);

        let args = vec![
            r"C:\FlowX\flowx.exe".to_string(),
            "--config".to_string(),
            r"C:\My Config\p.xml".to_string(),
            "--no-transparent".to_string(),
            "--replace-pid".to_string(),
            "111".to_string(),
            "--replace-pid=222".to_string(),
            "--api-addr=127.0.0.1:19999".to_string(),
        ];
        let rebuilt = build_elevated_relaunch_args(&args, 4321, &[]);
        assert_eq!(
            rebuilt,
            r#"--config "C:\My Config\p.xml" --api-addr=127.0.0.1:19999 --transparent --replace-pid 4321"#
        );
    }

    #[test]
    fn test_transparent_manager_status_and_driver_diagnostics() {
        use crate::dns::FakeIpPool;
        use crate::interceptor::process::ProcessTracker;
        use crate::monitor::ConnectionManager;
        use crate::router::{Action, RuleEngine};
        use std::collections::HashMap;
        use std::sync::RwLock;

        let rt = tokio::runtime::Runtime::new().unwrap();
        let fake_ip_pool = Arc::new(FakeIpPool::new_default());
        let tracker = Arc::new(ProcessTracker::new());
        let rule_engine = Arc::new(RuleEngine::new(vec![], Action::Direct));
        let upstream_dns = "223.5.5.5:53".parse().unwrap();

        let dispatcher_cfg = Arc::new(DispatcherConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            tracker,
            fake_ip_pool: Arc::clone(&fake_ip_pool),
            upstream_dns,
            rule_engine,
            monitor: Arc::new(ConnectionManager::new()),
            proxy_nodes: Arc::new(RwLock::new(HashMap::new())),
            proxy_chains: Arc::new(HashMap::new()),
            self_ports: Vec::new(),
            in_flight: None,
        });
        let dns_server = Arc::new(DnsServer::new(
            "127.0.0.1:0".parse().unwrap(),
            fake_ip_pool,
            upstream_dns,
            true,
        ));

        // 指定一个明确不存在的 WinDivert 目录以确定性地测试缺驱动诊断分支（不触及系统驱动）
        let mgr = TransparentManager::new(
            dispatcher_cfg,
            dns_server,
            TransparentSettings {
                enabled: false,
                hijack_dns: true,
                block_quic_for_proxied: true,
                dll_path: Some(r"Z:\__nonexistent_windivert_test_dir__\WinDivert.dll".to_string()),
            },
        );

        let st = mgr.status();
        assert!(st.supported);
        assert!(!st.running);
        assert!(!st.dll_found);
        assert!(!st.sys_found);
        assert_eq!(
            st.configured_dll_path.as_deref(),
            Some(r"Z:\__nonexistent_windivert_test_dir__\WinDivert.dll")
        );

        let _guard = rt.enter();
        let err = mgr
            .apply_settings(
                TransparentSettings {
                    enabled: true,
                    hijack_dns: true,
                    block_quic_for_proxied: true,
                    dll_path: Some(
                        r"Z:\__nonexistent_windivert_test_dir__\WinDivert.dll".to_string(),
                    ),
                },
                rt.handle(),
            )
            .expect_err("Missing driver or non-admin must fail cleanly");
        assert!(
            err.contains("ERR_TRANSPARENT_"),
            "Unexpected error code: {err}"
        );
        assert_eq!(mgr.status().last_error.as_deref(), Some(err.as_str()));
        assert!(!mgr.is_running());

        // 关闭应幂等清理 last_error
        mgr.apply_settings(TransparentSettings::default(), rt.handle())
            .unwrap();
        assert!(mgr.status().last_error.is_none());
    }

    #[test]
    fn test_system32_dll_and_exe_loaders_resolve_system32() {
        use windows_sys::Win32::Foundation::FreeLibrary;

        let dnsapi = unsafe { load_system32_library("dnsapi.dll") }
            .expect("dnsapi.dll should load cleanly from System32");
        assert!(!dnsapi.is_null());
        unsafe {
            FreeLibrary(dnsapi);
        }

        let rid = process_integrity_rid().expect("TokenIntegrityLevel should be queryable");
        if !is_low_integrity_rid(rid) {
            use windows_sys::Win32::System::LibraryLoader::GetProcAddress;

            let ole32 = unsafe { load_system32_library("ole32.dll") }
                .expect("ole32.dll should load cleanly from System32 at Medium+ integrity");
            assert!(!ole32.is_null());
            unsafe {
                FreeLibrary(ole32);
            }

            {
                let com_guard = StaComGuard::init();
                assert!(
                    com_guard.is_some(),
                    "StaComGuard should initialize COM cleanly via System32 ole32.dll"
                );
            }

            let shell32 = unsafe { load_system32_library("shell32.dll") }
                .expect("shell32.dll should load cleanly from System32 at Medium+ integrity");
            assert!(!shell32.is_null());
            let shell_exec =
                unsafe { GetProcAddress(shell32, c"ShellExecuteW".as_ptr().cast::<u8>()) };
            assert!(
                shell_exec.is_some(),
                "ShellExecuteW should resolve in System32 shell32.dll"
            );
            unsafe {
                FreeLibrary(shell32);
            }
        } else {
            assert!(is_low_integrity_process());
            let err = relaunch_elevated_with_replace_pid(&[])
                .expect_err("Low integrity process must reject in-process UAC cleanly");
            assert!(
                err.to_string().contains("ERR_TRANSPARENT_LOW_INTEGRITY:"),
                "unexpected Low integrity error: {err}"
            );
        }

        let ipconfig = resolve_system32_executable("ipconfig.exe")
            .expect("ipconfig.exe should resolve inside SystemRoot\\System32");
        assert!(ipconfig.is_absolute());
        assert!(ipconfig.is_file());
        assert!(
            ipconfig
                .parent()
                .and_then(|p| p.file_name())
                .is_some_and(|n| n.eq_ignore_ascii_case("System32")),
            "unexpected ipconfig dir: {}",
            ipconfig.display()
        );
    }

    #[test]
    fn test_low_integrity_rid_thresholds() {
        assert!(is_low_integrity_rid(0x0000)); // Untrusted
        assert!(is_low_integrity_rid(0x1000)); // Low
        assert!(is_low_integrity_rid(0x1FFF));
        assert!(!is_low_integrity_rid(SECURITY_MANDATORY_MEDIUM_RID));
        assert!(!is_low_integrity_rid(0x3000)); // High
        assert!(!is_low_integrity_rid(0x4000)); // System
    }

    #[test]
    fn test_windivert_network_filter_captures_fake_ip_udp() {
        let f = windivert_network_filter();
        assert!(f.contains("udp.DstPort == 53"));
        assert!(f.contains("udp.DstPort == 443"));
        assert!(f.contains("198.18.0.0"));
        assert!(f.contains("198.19.255.255"));
        assert!(f.contains("or fragment"));

        let inbound_f = windivert_dns_inspect_inbound_filter();
        assert!(inbound_f.contains("inbound"));
        assert!(inbound_f.contains("udp.SrcPort == 53"));
        assert!(!inbound_f.contains("or fragment"));
    }

    #[test]
    fn test_net_rx_buf_growth_bounds() {
        const { assert!(INITIAL_NET_RX_BUF_LEN > 65_575) };
        assert_eq!(next_net_rx_buf_len(INITIAL_NET_RX_BUF_LEN), Some(262_144));
        assert_eq!(
            next_net_rx_buf_len(MAX_NET_RX_BUF_LEN / 2),
            Some(MAX_NET_RX_BUF_LEN)
        );
        assert_eq!(next_net_rx_buf_len(MAX_NET_RX_BUF_LEN), None);
    }

    #[test]
    fn test_transparent_manager_persisted_enabled_isolated_from_cli_override() {
        use crate::dns::FakeIpPool;
        use crate::interceptor::process::ProcessTracker;
        use crate::monitor::ConnectionManager;
        use crate::router::{Action, RuleEngine};
        use std::collections::HashMap;
        use std::sync::RwLock;

        let fake_ip_pool = Arc::new(FakeIpPool::new_default());
        let dispatcher_cfg = Arc::new(DispatcherConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            tracker: Arc::new(ProcessTracker::new()),
            fake_ip_pool: Arc::clone(&fake_ip_pool),
            upstream_dns: "223.5.5.5:53".parse().unwrap(),
            rule_engine: Arc::new(RuleEngine::new(vec![], Action::Direct)),
            monitor: Arc::new(ConnectionManager::new()),
            proxy_nodes: Arc::new(RwLock::new(HashMap::new())),
            proxy_chains: Arc::new(HashMap::new()),
            self_ports: Vec::new(),
            in_flight: None,
        });
        let dns_server = Arc::new(DnsServer::new(
            "127.0.0.1:0".parse().unwrap(),
            fake_ip_pool,
            "223.5.5.5:53".parse().unwrap(),
            true,
        ));

        // 模拟配置中 enabled=true 但 CLI 传入 --no-transparent 的场景
        let mgr = TransparentManager::new_with_persisted(
            dispatcher_cfg,
            dns_server,
            TransparentSettings {
                enabled: false,
                hijack_dns: false,
                block_quic_for_proxied: true,
                dll_path: Some(r"C:\test\WinDivert.dll".to_string()),
            },
            true,
        );
        assert!(!mgr.settings().enabled);
        let persisted = mgr.persisted_settings();
        assert!(persisted.enabled);
        assert!(!persisted.hijack_dns);
        assert_eq!(
            persisted.dll_path.as_deref(),
            Some(r"C:\test\WinDivert.dll")
        );

        mgr.set_persisted_enabled(false);
        assert!(!mgr.persisted_settings().enabled);
    }
}
