pub mod dns_hijack;
pub mod fragment;
pub mod netstack;
pub mod sniffer;

#[cfg(windows)]
pub mod pid_table;
#[cfg(windows)]
pub mod windivert_ffi;

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::dns::server::DnsServer;
use crate::interceptor::dispatcher::{dispatch_transparent_stream, DispatcherConfig};

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
struct TransparentStatsCounters {
    active_flows: AtomicUsize,
    tcp_intercepted_total: AtomicU64,
    tcp_passthrough_total: AtomicU64,
    tcp_blocked_rst_total: AtomicU64,
    dns_hijacked_total: AtomicU64,
    quic_blocked_total: AtomicU64,
}

/// 基于给定静态配置构建驱动探测快照（供 CLI 离线查询与测试降级复用）
pub fn probe_status(cfg: &TransparentSettings) -> TransparentRuntimeStatus {
    #[cfg(windows)]
    let (dll_found, sys_found, dll_path, sys_path, searched_dirs) = {
        let avail = windivert_ffi::locate_windivert_files(cfg.dll_path.as_deref());
        (
            avail.dll_found,
            avail.sys_found,
            avail.dll_path,
            avail.sys_path,
            avail.searched_dirs,
        )
    };
    #[cfg(not(windows))]
    let (dll_found, sys_found, dll_path, sys_path, searched_dirs) =
        (false, false, None, None, Vec::new());

    TransparentRuntimeStatus {
        supported: cfg!(windows),
        enabled: cfg.enabled,
        running: false,
        elevated: is_process_elevated(),
        dll_found,
        sys_found,
        dll_path,
        sys_path,
        searched_dirs,
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

/// 检测当前进程是否拥有 Windows 管理员提升令牌（非 Windows 返回 `false`）
pub fn is_process_elevated() -> bool {
    #[cfg(windows)]
    {
        use std::ffi::c_void;
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0
                || token.is_null()
            {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut ret_len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast::<c_void>(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            );
            CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// 仅从 Windows `System32` 目录加载系统 DLL（避免高权限下被 CWD / 应用目录 / `PATH` 劫持）
#[cfg(windows)]
unsafe fn load_system32_library(dll_name: &str) -> io::Result<windows_sys::Win32::Foundation::HMODULE> {
    use windows_sys::Win32::System::LibraryLoader::{LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32};

    let wide: Vec<u16> = dll_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let module = unsafe {
        LoadLibraryExW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(module)
}

/// 解析 `%SystemRoot%\System32\<exe_name>` 完整可信路径，禁止裸名走 `PATH` / CWD
#[cfg(windows)]
fn resolve_system32_executable(exe_name: &str) -> io::Result<std::path::PathBuf> {
    let sys_root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("windir"))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Neither SystemRoot nor windir environment variable is set",
            )
        })?;
    let root_path = std::path::PathBuf::from(sys_root);
    if !root_path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("SystemRoot path is not absolute: {}", root_path.display()),
        ));
    }
    let exe_path = root_path.join("System32").join(exe_name);
    if !exe_path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("System32 executable not found: {}", exe_path.display()),
        ));
    }
    Ok(exe_path)
}

/// 刷新 Windows 系统 DNS 缓存，确保切入/退出透明模式时清理陈旧解析记录及 Fake-IP 残留
pub fn flush_dns_cache() -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::ffi::CString;
        use windows_sys::Win32::Foundation::FreeLibrary;
        use windows_sys::Win32::System::LibraryLoader::GetProcAddress;

        type FnDnsFlushResolverCache = unsafe extern "system" fn() -> i32;
        if let Ok(module) = unsafe { load_system32_library("dnsapi.dll") } {
            let sym = CString::new("DnsFlushResolverCache").unwrap();
            let proc = unsafe { GetProcAddress(module, sym.as_ptr() as *const u8) };
            let flushed = if let Some(ptr) = proc {
                let func: FnDnsFlushResolverCache =
                    unsafe { std::mem::transmute_copy(&ptr) };
                unsafe { func() != 0 }
            } else {
                false
            };
            unsafe {
                FreeLibrary(module);
            }
            if flushed {
                return Ok(());
            }
        }

        // 后备方案：仅从 %SystemRoot%\System32\ipconfig.exe 静默执行（禁止裸名走 PATH / CWD）
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let ipconfig_path = resolve_system32_executable("ipconfig.exe")?;
        let status = std::process::Command::new(ipconfig_path)
            .arg("/flushdns")
            .creation_flags(CREATE_NO_WINDOW)
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other("Failed to flush Windows DNS cache"))
        }
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

/// 按 Windows `CommandLineToArgvW` 规范转义命令行参数
pub fn quote_windows_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|c| matches!(c, ' ' | '\t' | '\n' | '\r' | '"')) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => {
                backslashes += 1;
            }
            '"' => {
                for _ in 0..(backslashes * 2 + 1) {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            _ => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(ch);
            }
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

/// 基于现有命令行参数重建提权重启参数：剔除旧的 `--replace-pid`/`--no-transparent`，并注入 `--transparent --replace-pid <pid>`
pub fn build_elevated_relaunch_args(
    raw_args: &[String],
    current_pid: u32,
    extra_args: &[String],
) -> String {
    let mut preserved: Vec<String> = Vec::new();
    let mut idx = 0usize;
    // 跳过 argv[0] 若它看上去像可执行路径
    if !raw_args.is_empty() {
        idx = 1;
    }

    while idx < raw_args.len() {
        let arg = &raw_args[idx];
        if arg == "--replace-pid" {
            idx += 2;
            continue;
        }
        if arg.starts_with("--replace-pid=")
            || arg == "--transparent"
            || arg == "--no-transparent"
        {
            idx += 1;
            continue;
        }
        preserved.push(arg.clone());
        idx += 1;
    }

    preserved.push("--transparent".to_string());
    preserved.push("--replace-pid".to_string());
    preserved.push(current_pid.to_string());
    for extra in extra_args {
        if !extra.is_empty() {
            preserved.push(extra.clone());
        }
    }

    preserved
        .into_iter()
        .map(|a| quote_windows_arg(&a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// 触发 Windows UAC 提权以 `--transparent --replace-pid <当前PID>` 重启 FlowX，由新实例平滑接管配置与端口
pub fn relaunch_elevated_with_replace_pid(extra_args: &[String]) -> io::Result<()> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{FreeLibrary, HINSTANCE, HWND};
        use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        if is_process_elevated() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Process is already running with Administrator privileges",
            ));
        }

        type ShellExecuteWFn = unsafe extern "system" fn(
            hwnd: HWND,
            lp_operation: *const u16,
            lp_file: *const u16,
            lp_parameters: *const u16,
            lp_directory: *const u16,
            n_show_cmd: i32,
        ) -> HINSTANCE;

        // 按需仅从 System32 延迟加载 shell32.dll，避免无头环境启动失败或 CWD/PATH DLL 劫持
        let shell32_mod = unsafe { load_system32_library("shell32.dll") }.map_err(|os_err| {
            io::Error::new(
                os_err.kind(),
                format!("Failed to load shell32.dll from System32 for UAC elevation: {os_err}"),
            )
        })?;

        let proc_ptr = unsafe { GetProcAddress(shell32_mod, c"ShellExecuteW".as_ptr().cast()) };
        let Some(proc_fn) = proc_ptr else {
            let os_err = io::Error::last_os_error();
            unsafe {
                FreeLibrary(shell32_mod);
            }
            return Err(io::Error::new(
                os_err.kind(),
                format!("Failed to resolve ShellExecuteW from shell32.dll: {os_err}"),
            ));
        };
        let shell_execute_w: ShellExecuteWFn = unsafe { std::mem::transmute(proc_fn) };

        let exe_path = std::env::current_exe().inspect_err(|_| unsafe {
            FreeLibrary(shell32_mod);
        })?;
        let cwd = std::env::current_dir().ok();
        let raw_args: Vec<String> = std::env::args().collect();
        let params = build_elevated_relaunch_args(&raw_args, std::process::id(), extra_args);

        let verb_w: Vec<u16> = "runas\0".encode_utf16().collect();
        let exe_w: Vec<u16> = exe_path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let params_w: Vec<u16> = params.encode_utf16().chain(std::iter::once(0)).collect();
        let cwd_w: Option<Vec<u16>> = cwd.map(|p| {
            p.to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect()
        });

        let ret = unsafe {
            shell_execute_w(
                std::ptr::null_mut(),
                verb_w.as_ptr(),
                exe_w.as_ptr(),
                params_w.as_ptr(),
                cwd_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
                SW_SHOWNORMAL,
            )
        };
        unsafe {
            FreeLibrary(shell32_mod);
        }
        let code = ret as isize;
        if code <= 32 {
            let msg = match code {
                5 | 1223 => "ERR_TRANSPARENT_UAC_CANCELLED: Administrator elevation prompt was cancelled or denied.",
                2 | 3 => "Failed to locate executable path while requesting elevation.",
                _ => "ShellExecuteW(runas) failed to launch elevated FlowX instance.",
            };
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{msg} (ShellExecute code {code})"),
            ));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = extra_args;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ERR_TRANSPARENT_UNSUPPORTED_OS: Elevated WinDivert relaunch is only supported on Windows.",
        ))
    }
}

#[cfg(windows)]
fn resolve_outbound_pid(
    table: &pid_table::SocketPidTable,
    protocol: u8,
    local: std::net::SocketAddr,
    remote: std::net::SocketAddr,
    allow_os_fallback: bool,
) -> Option<u32> {
    if let Some(pid) = table.lookup(protocol, local.ip(), local.port()) {
        return Some(pid);
    }
    if !allow_os_fallback {
        return None;
    }
    let pid = crate::interceptor::process::lookup_outbound_socket_pid(protocol, local, remote)?;
    if pid != 0 {
        table.record_resolved_pid(protocol, local.ip(), local.port(), pid);
    }
    Some(pid)
}

#[cfg(windows)]
fn shutdown_and_join_runtime(
    stop_flag: &AtomicBool,
    signal: &netstack::NetstackSignal,
    socket_handle: &windivert_ffi::WinDivertHandle,
    network_handle: &windivert_ffi::WinDivertHandle,
    threads: Vec<JoinHandle<()>>,
) {
    crate::outbound::bypass::set_transparent_active(false);
    stop_flag.store(true, Ordering::Release);
    signal.close();
    let _ = socket_handle.shutdown(windivert_ffi::WinDivertShutdownMode::Both);
    let _ = network_handle.shutdown(windivert_ffi::WinDivertShutdownMode::Both);
    for th in threads {
        let _ = th.join();
    }
}

/// 启动期原子回滚守卫：若任意子线程创建失败或发生 panic，确保已启动线程与 WinDivert 句柄全部回收
#[cfg(windows)]
struct PartialRuntimeGuard {
    armed: bool,
    stop_flag: Arc<AtomicBool>,
    signal: Arc<netstack::NetstackSignal>,
    socket_handle: Arc<windivert_ffi::WinDivertHandle>,
    network_handle: Arc<windivert_ffi::WinDivertHandle>,
    threads: Vec<JoinHandle<()>>,
}

#[cfg(windows)]
impl Drop for PartialRuntimeGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let threads = std::mem::take(&mut self.threads);
        shutdown_and_join_runtime(
            &self.stop_flag,
            &self.signal,
            &self.socket_handle,
            &self.network_handle,
            threads,
        );
    }
}

#[cfg(windows)]
struct ActiveRuntime {
    stop_flag: Arc<AtomicBool>,
    signal: Arc<netstack::NetstackSignal>,
    socket_handle: Arc<windivert_ffi::WinDivertHandle>,
    network_handle: Arc<windivert_ffi::WinDivertHandle>,
    threads: Vec<JoinHandle<()>>,
    driver_version: Option<String>,
}

/// WinDivert NETWORK 层收包初始缓冲区（128 KiB > WINDIVERT_MTU_MAX 65575）与 LSO/巨包动态扩容上限（4 MiB）
pub(crate) const INITIAL_NET_RX_BUF_LEN: usize = 131_072;
pub(crate) const MAX_NET_RX_BUF_LEN: usize = 4 * 1024 * 1024;
#[cfg(windows)]
const WINDOWS_ERROR_INSUFFICIENT_BUFFER: i32 = 122;

#[inline]
pub(crate) fn next_net_rx_buf_len(current: usize) -> Option<usize> {
    if current >= MAX_NET_RX_BUF_LEN {
        return None;
    }
    Some(current.saturating_mul(2).clamp(INITIAL_NET_RX_BUF_LEN, MAX_NET_RX_BUF_LEN))
}

/// WinDivert NETWORK 层过滤表达式：捕获全部出站非自环 TCP、UDP/53 DNS、UDP/443 QUIC、发往 Fake-IP (`198.18.0.0/15`) 的任意 UDP 以及全部 IPv4/IPv6 分片
pub(crate) fn windivert_network_filter() -> &'static str {
    "outbound and !loopback and !impostor and (tcp or udp.DstPort == 53 or udp.DstPort == 443 or (udp and ip and ip.DstAddr >= 198.18.0.0 and ip.DstAddr <= 198.19.255.255) or fragment)"
}

#[cfg(windows)]
struct NetRxContext {
    net_h: Arc<windivert_ffi::WinDivertHandle>,
    table: Arc<pid_table::SocketPidTable>,
    sig: Arc<netstack::NetstackSignal>,
    dispatcher_cfg: Arc<DispatcherConfig>,
    dns_srv: Arc<DnsServer>,
    stats: Arc<TransparentStatsCounters>,
    live_dns: Arc<AtomicBool>,
    live_quic: Arc<AtomicBool>,
    rt: tokio::runtime::Handle,
}

#[cfg(windows)]
impl NetRxContext {
    fn emit_passthrough(&self, raw: &[u8], addr: &windivert_ffi::WinDivertAddress, fallback_fragments: Option<&[netstack::EmittedIpPacket]>) {
        if let Some(frags) = fallback_fragments {
            for f in frags {
                let passthru_addr = windivert_ffi::WinDivertAddress::outbound_passthrough(
                    f.meta.if_idx,
                    f.meta.sub_if_idx,
                    f.meta.bitfield,
                );
                let _ = self.net_h.send(&f.data, &passthru_addr);
            }
        } else {
            let _ = self.net_h.send(raw, addr);
        }
    }

    /// 处理一条完整（未分片或已完成重组）的出站 IPv4/IPv6 UDP/TCP 报文；已认领返回 true
    fn handle_complete_ip_packet(
        &self,
        raw: &[u8],
        addr: &windivert_ffi::WinDivertAddress,
        fallback_fragments: Option<&[netstack::EmittedIpPacket]>,
    ) -> bool {
        let net_data = addr.network();

        if let Some(udp) = dns_hijack::parse_udp_packet(raw) {
            let local_ep = std::net::SocketAddr::new(udp.src_ip, udp.src_port);
            let remote_ep = std::net::SocketAddr::new(udp.dst_ip, udp.dst_port);
            let pid = resolve_outbound_pid(&self.table, 17, local_ep, remote_ep, true);
            let decision = dns_hijack::decide_udp_packet(
                &udp,
                pid,
                self.live_dns.load(Ordering::Acquire),
                self.live_quic.load(Ordering::Acquire),
                Some(&self.dispatcher_cfg.rule_engine),
                Some(&self.dispatcher_cfg.tracker),
                Some(&self.dispatcher_cfg.fake_ip_pool),
            );
            match decision {
                dns_hijack::UdpDecision::Passthrough => {
                    self.emit_passthrough(raw, addr, fallback_fragments);
                }
                dns_hijack::UdpDecision::DropQuic => {
                    self.stats.quic_blocked_total.fetch_add(1, Ordering::Relaxed);
                }
                dns_hijack::UdpDecision::DropFakeIp => {}
                dns_hijack::UdpDecision::HandleDns => {
                    self.stats.dns_hijacked_total.fetch_add(1, Ordering::Relaxed);
                    let owned_payload = udp.payload.to_vec();
                    let req_meta = (
                        udp.src_ip,
                        udp.dst_ip,
                        udp.src_port,
                        udp.dst_port,
                        udp.is_ipv6,
                    );
                    let net_inj = Arc::clone(&self.net_h);
                    let dns = Arc::clone(&self.dns_srv);
                    let loopback = addr.loopback();
                    self.rt.spawn(async move {
                        let orig_dns_dst = std::net::SocketAddr::new(req_meta.1, req_meta.3);
                        if let Some(resp_payload) = dns
                            .process_transparent_query_bytes(&owned_payload, orig_dns_dst)
                            .await
                        {
                            let pseudo_req = dns_hijack::ParsedUdpPacket {
                                src_ip: req_meta.0,
                                dst_ip: req_meta.1,
                                src_port: req_meta.2,
                                dst_port: req_meta.3,
                                payload: &[],
                                is_ipv6: req_meta.4,
                            };
                            if let Ok(mut reply_ip) =
                                dns_hijack::build_udp_reply_ip_packet(&pseudo_req, &resp_payload)
                            {
                                let mut inj_addr = windivert_ffi::WinDivertAddress::inbound_injection(
                                    net_data.if_idx,
                                    net_data.sub_if_idx,
                                    loopback,
                                    req_meta.4,
                                );
                                net_inj.calc_checksums(&mut reply_ip, &mut inj_addr);
                                let _ = net_inj.send(&reply_ip, &inj_addr);
                            }
                        }
                    });
                }
            }
            return true;
        }

        if let Some(tcp) = netstack::parse_tcp_packet(raw) {
            let local_ep = std::net::SocketAddr::new(tcp.src_ip, tcp.src_port);
            let remote_ep = std::net::SocketAddr::new(tcp.dst_ip, tcp.dst_port);
            let pid = resolve_outbound_pid(&self.table, 6, local_ep, remote_ep, tcp.syn && !tcp.ack);
            if crate::outbound::bypass::is_tcp_port_bypassed(tcp.src_port)
                || pid.is_some_and(pid_table::SocketPidTable::is_self_pid)
            {
                self.stats
                    .tcp_passthrough_total
                    .fetch_add(1, Ordering::Relaxed);
                self.emit_passthrough(raw, addr, fallback_fragments);
                return true;
            }

            let meta = netstack::PacketInterfaceMeta {
                if_idx: net_data.if_idx,
                sub_if_idx: net_data.sub_if_idx,
                loopback: addr.loopback(),
                is_ipv6: tcp.is_ipv6,
                bitfield: addr.raw_bitfield(),
            };
            self.sig.push_outbound_tcp(raw.to_vec(), meta, pid);
            return true;
        }

        false
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
    #[cfg(windows)]
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
            #[cfg(windows)]
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
        #[cfg(windows)]
        {
            self.runtime
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    pub fn status(&self) -> TransparentRuntimeStatus {
        let cfg = self.settings();
        let last_error = self
            .last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        #[cfg(windows)]
        let (running, driver_version) = {
            let guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            (
                guard.is_some(),
                guard.as_ref().and_then(|rt| rt.driver_version.clone()),
            )
        };
        #[cfg(not(windows))]
        let (running, driver_version) = (false, None);

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

    #[cfg(not(windows))]
    fn start_locked(
        &self,
        _rt_handle: &tokio::runtime::Handle,
        _cfg: &TransparentSettings,
    ) -> Result<(), String> {
        Err(self.set_error(
            "ERR_TRANSPARENT_UNSUPPORTED_OS: WinDivert transparent proxy is only supported on Windows."
                .to_string(),
        ))
    }

    #[cfg(not(windows))]
    fn stop_locked(&self) {}

    #[cfg(windows)]
    fn start_locked(
        &self,
        rt_handle: &tokio::runtime::Handle,
        cfg: &TransparentSettings,
    ) -> Result<(), String> {
        if self.runtime.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
            return Ok(());
        }

        if !is_process_elevated() {
            return Err(self.set_error(
                "ERR_TRANSPARENT_REQUIRES_ADMIN: Transparent proxy requires Administrator privileges to open WinDivert."
                    .to_string(),
            ));
        }

        let avail = windivert_ffi::locate_windivert_files(cfg.dll_path.as_deref());
        if !avail.dll_found || !avail.sys_found {
            let searched = if avail.searched_dirs.is_empty() {
                "executable directory".to_string()
            } else {
                avail.searched_dirs.join(", ")
            };
            return Err(self.set_error(format!(
                "ERR_TRANSPARENT_MISSING_DRIVER: Missing WinDivert.dll (found={}) or WinDivert64.sys (found={}). Place both files next to flowx.exe. Searched: {}",
                avail.dll_found, avail.sys_found, searched
            )));
        }

        let api = windivert_ffi::WinDivertApi::load(cfg.dll_path.as_deref()).map_err(|e| {
            self.set_error(format!(
                "ERR_TRANSPARENT_LOAD_FAILED: Failed to load WinDivert.dll: {e}"
            ))
        })?;

        let socket_filter =
            "(tcp or udp) and (event == BIND or event == CONNECT or event == LISTEN or event == ACCEPT or event == CLOSE)";
        let socket_handle = Arc::new(
            windivert_ffi::WinDivertHandle::open(
                Arc::clone(&api),
                socket_filter,
                windivert_ffi::WinDivertLayer::Socket,
                0,
                windivert_ffi::SOCKET_LAYER_FLAGS,
            )
            .map_err(|e| {
                self.set_error(format!(
                    "ERR_TRANSPARENT_OPEN_SOCKET_LAYER: {e}"
                ))
            })?,
        );

        let network_filter = windivert_network_filter();
        let network_handle = Arc::new(
            windivert_ffi::WinDivertHandle::open(
                Arc::clone(&api),
                network_filter,
                windivert_ffi::WinDivertLayer::Network,
                0,
                0,
            )
            .map_err(|e| {
                self.set_error(format!(
                    "ERR_TRANSPARENT_OPEN_NETWORK_LAYER: {e}"
                ))
            })?,
        );

        let _ = network_handle.set_param(
            windivert_ffi::WinDivertParam::QueueLength,
            windivert_ffi::WINDIVERT_PARAM_QUEUE_LENGTH_MAX,
        );
        let _ = network_handle.set_param(
            windivert_ffi::WinDivertParam::QueueTime,
            windivert_ffi::WINDIVERT_PARAM_QUEUE_TIME_DEFAULT,
        );
        let _ = network_handle.set_param(windivert_ffi::WinDivertParam::QueueSize, 16_777_216);

        let driver_version = network_handle
            .version()
            .map(|(maj, min)| format!("{maj}.{min}"));

        // 启动前刷新本机 DNS 缓存，确保系统不继续使用开启前的直连 IP 缓存绕开 Fake-IP
        if let Err(e) = flush_dns_cache() {
            warn!(error = %e, "Failed to flush Windows DNS cache before starting transparent mode");
        }

        let stop_flag = Arc::new(AtomicBool::new(false));
        let pid_table = Arc::new(pid_table::SocketPidTable::new());
        let signal = Arc::new(netstack::NetstackSignal::new());

        let mut startup_guard = PartialRuntimeGuard {
            armed: true,
            stop_flag: Arc::clone(&stop_flag),
            signal: Arc::clone(&signal),
            socket_handle: Arc::clone(&socket_handle),
            network_handle: Arc::clone(&network_handle),
            threads: Vec::with_capacity(3),
        };
        crate::outbound::bypass::set_transparent_active(true);

        // 1. SOCKET 层监听线程：高速维护 (proto, local_ip, local_port) -> PID，并推送 TCP 关闭事件失效旁路缓存
        {
            let stop = Arc::clone(&stop_flag);
            let sock_h = Arc::clone(&socket_handle);
            let table = Arc::clone(&pid_table);
            let sig_sock = Arc::clone(&signal);
            let handle = std::thread::Builder::new()
                .name("flowx-windivert-socket".to_string())
                .spawn(move || {
                    let mut dummy = [0u8; 64];
                    while !stop.load(Ordering::Acquire) {
                        match sock_h.recv(&mut dummy) {
                            Ok((_, addr)) => {
                                let Some(event) =
                                    windivert_ffi::WinDivertEvent::from_u8(addr.event())
                                else {
                                    continue;
                                };
                                let s = addr.socket_data();
                                let local_ip = windivert_ffi::decode_windivert_addr(
                                    &s.local_addr,
                                    addr.ipv6(),
                                );
                                table.record_event(
                                    event,
                                    s.protocol,
                                    local_ip,
                                    s.local_port,
                                    s.process_id,
                                );
                                if matches!(event, windivert_ffi::WinDivertEvent::SocketClose)
                                    && s.protocol == 6
                                {
                                    sig_sock.push_closed_tcp_endpoint(local_ip, s.local_port);
                                }
                            }
                            Err(e) => {
                                if stop.load(Ordering::Acquire)
                                    || matches!(e.raw_os_error(), Some(6 | 232 | 995))
                                {
                                    break;
                                }
                                debug!(error = %e, "WinDivert SOCKET recv returned transient error");
                                std::thread::yield_now();
                            }
                        }
                    }
                })
                .map_err(|e| self.set_error(format!("Failed to spawn socket monitor thread: {e}")))?;
            startup_guard.threads.push(handle);
        }

        // 2. NETWORK 层抓包线程：快速分流自环放行 / UDP(DNS & QUIC) / TCP 入协议栈，并对分片包实行有界重组防渗透
        {
            let stop = Arc::clone(&stop_flag);
            let ctx = NetRxContext {
                net_h: Arc::clone(&network_handle),
                table: Arc::clone(&pid_table),
                sig: Arc::clone(&signal),
                dispatcher_cfg: Arc::clone(&self.dispatcher_config),
                dns_srv: Arc::clone(&self.dns_server),
                stats: Arc::clone(&self.stats),
                live_dns: Arc::clone(&self.live_hijack_dns),
                live_quic: Arc::clone(&self.live_block_quic),
                rt: rt_handle.clone(),
            };

            let handle = std::thread::Builder::new()
                .name("flowx-windivert-net-rx".to_string())
                .spawn(move || {
                    let mut buf = vec![0u8; INITIAL_NET_RX_BUF_LEN];
                    let mut frag_tracker = fragment::FragmentTracker::new();
                    while !stop.load(Ordering::Acquire) {
                        let (len, addr) = match ctx.net_h.recv(&mut buf) {
                            Ok(res) => res,
                            Err(e) => {
                                if stop.load(Ordering::Acquire)
                                    || matches!(e.raw_os_error(), Some(6 | 232 | 995))
                                {
                                    break;
                                }
                                if e.raw_os_error() == Some(WINDOWS_ERROR_INSUFFICIENT_BUFFER)
                                    && let Some(next_len) = next_net_rx_buf_len(buf.len())
                                {
                                    buf.resize(next_len, 0);
                                    debug!(
                                        new_buf_len = next_len,
                                        "Expanded WinDivert NETWORK recv buffer after ERROR_INSUFFICIENT_BUFFER"
                                    );
                                    continue;
                                }
                                debug!(error = %e, "WinDivert NETWORK recv transient error");
                                std::thread::yield_now();
                                continue;
                            }
                        };
                        if len == 0 {
                            continue;
                        }
                        let raw = &buf[..len];
                        if ctx.handle_complete_ip_packet(raw, &addr, None) {
                            continue;
                        }

                        let net_data = addr.network();
                        let frag_meta = netstack::PacketInterfaceMeta {
                            if_idx: net_data.if_idx,
                            sub_if_idx: net_data.sub_if_idx,
                            loopback: addr.loopback(),
                            is_ipv6: addr.ipv6(),
                            bitfield: addr.raw_bitfield(),
                        };
                        match frag_tracker.ingest(
                            raw,
                            frag_meta,
                            Some(&ctx.dispatcher_cfg.fake_ip_pool),
                        ) {
                            fragment::FragmentOutcome::PassthroughSingle => {
                                let _ = ctx.net_h.send(raw, &addr);
                            }
                            fragment::FragmentOutcome::Drop
                            | fragment::FragmentOutcome::Pending => {}
                            fragment::FragmentOutcome::Reassembled {
                                full_packet,
                                orig_fragments,
                            } => {
                                let rep_meta = orig_fragments
                                    .first()
                                    .map(|f| f.meta)
                                    .unwrap_or(frag_meta);
                                let reasm_addr =
                                    windivert_ffi::WinDivertAddress::outbound_passthrough(
                                        rep_meta.if_idx,
                                        rep_meta.sub_if_idx,
                                        rep_meta.bitfield,
                                    );
                                let _ = ctx.handle_complete_ip_packet(
                                    &full_packet,
                                    &reasm_addr,
                                    Some(&orig_fragments),
                                );
                            }
                        }
                    }
                })
                .map_err(|e| self.set_error(format!("Failed to spawn network recv thread: {e}")))?;
            startup_guard.threads.push(handle);
        }

        // 3. 用户态协议栈 Actor 线程：单所有权运行 smoltcp 并协调 AsyncRead/AsyncWrite 与入站注入
        {
            let stop = Arc::clone(&stop_flag);
            let net_h = Arc::clone(&network_handle);
            let sig = Arc::clone(&signal);
            let dispatcher_cfg = Arc::clone(&self.dispatcher_config);
            let stats = Arc::clone(&self.stats);
            let rt = rt_handle.clone();

            let handle = std::thread::Builder::new()
                .name("flowx-windivert-netstack".to_string())
                .spawn(move || {
                    let mut engine = netstack::NetstackEngine::new(Arc::clone(&sig));
                    let mut batch = Vec::with_capacity(64);
                    let mut closed_endpoints = Vec::with_capacity(16);
                    let mut accepted = Vec::with_capacity(16);
                    let mut tx_packets = Vec::with_capacity(64);
                    let mut wait_budget = std::time::Duration::from_millis(20);

                    while !stop.load(Ordering::Acquire) {
                        let alive = sig.wait_drain_or_timeout(
                            wait_budget,
                            &mut batch,
                            &mut closed_endpoints,
                        );
                        if !alive || stop.load(Ordering::Acquire) {
                            break;
                        }

                        for (local_ip, local_port) in closed_endpoints.drain(..) {
                            engine.invalidate_passthrough_for_local_endpoint(local_ip, local_port);
                        }

                        for (raw_ip, meta, pid) in batch.drain(..) {
                            match engine.ingest_outbound_tcp(
                                raw_ip,
                                meta,
                                pid,
                                Some(&dispatcher_cfg.rule_engine),
                                Some(&dispatcher_cfg.tracker),
                                Some(&dispatcher_cfg.fake_ip_pool),
                                &mut accepted,
                                &mut tx_packets,
                            ) {
                                netstack::TcpIngestOutcome::Intercepted => {}
                                netstack::TcpIngestOutcome::Passthrough(pkt) => {
                                    stats.tcp_passthrough_total.fetch_add(1, Ordering::Relaxed);
                                    let passthru_addr =
                                        windivert_ffi::WinDivertAddress::outbound_passthrough(
                                            pkt.meta.if_idx,
                                            pkt.meta.sub_if_idx,
                                            pkt.meta.bitfield,
                                        );
                                    let _ = net_h.send(&pkt.data, &passthru_addr);
                                }
                                netstack::TcpIngestOutcome::InjectRst(mut rst_pkt) => {
                                    stats.tcp_blocked_rst_total.fetch_add(1, Ordering::Relaxed);
                                    let mut rst_addr =
                                        windivert_ffi::WinDivertAddress::inbound_injection(
                                            rst_pkt.meta.if_idx,
                                            rst_pkt.meta.sub_if_idx,
                                            rst_pkt.meta.loopback,
                                            rst_pkt.meta.is_ipv6,
                                        );
                                    net_h.calc_checksums(&mut rst_pkt.data, &mut rst_addr);
                                    let _ = net_h.send(&rst_pkt.data, &rst_addr);
                                }
                            }
                        }

                        for flow in accepted.drain(..) {
                            stats.tcp_intercepted_total.fetch_add(1, Ordering::Relaxed);
                            let dcfg = Arc::clone(&dispatcher_cfg);
                            rt.spawn(async move {
                                if let Err(e) = dispatch_transparent_stream(
                                    dcfg,
                                    flow.stream,
                                    flow.peer_addr,
                                    flow.orig_dst,
                                    flow.pid_hint,
                                    flow.needs_domain_sniff,
                                )
                                .await
                                {
                                    debug!(
                                        orig_dst = %flow.orig_dst,
                                        error = %e,
                                        "Transparent TCP stream finished with error"
                                    );
                                }
                            });
                        }

                        wait_budget = engine.pump(&mut tx_packets);
                        stats
                            .active_flows
                            .store(engine.active_flow_count(), Ordering::Relaxed);

                        for mut tx_pkt in tx_packets.drain(..) {
                            let mut inj_addr = windivert_ffi::WinDivertAddress::inbound_injection(
                                tx_pkt.meta.if_idx,
                                tx_pkt.meta.sub_if_idx,
                                tx_pkt.meta.loopback,
                                tx_pkt.meta.is_ipv6,
                            );
                            net_h.calc_checksums(&mut tx_pkt.data, &mut inj_addr);
                            let _ = net_h.send(&tx_pkt.data, &inj_addr);
                        }
                    }
                })
                .map_err(|e| self.set_error(format!("Failed to spawn netstack actor thread: {e}")))?;
            startup_guard.threads.push(handle);
        }

        startup_guard.armed = false;
        let threads = std::mem::take(&mut startup_guard.threads);
        *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self.runtime.lock().unwrap_or_else(|e| e.into_inner()) = Some(ActiveRuntime {
            stop_flag,
            signal,
            socket_handle,
            network_handle,
            threads,
            driver_version: driver_version.clone(),
        });

        info!(
            loaded_from = %api.loaded_from(),
            driver_version = driver_version.as_deref().unwrap_or("unknown"),
            "Transparent proxy started via WinDivert"
        );
        Ok(())
    }

    #[cfg(windows)]
    fn stop_locked(&self) {
        let rt_opt = self.runtime.lock().unwrap_or_else(|e| e.into_inner()).take();
        let Some(rt) = rt_opt else {
            return;
        };

        shutdown_and_join_runtime(
            &rt.stop_flag,
            &rt.signal,
            &rt.socket_handle,
            &rt.network_handle,
            rt.threads,
        );
        drop(rt.socket_handle);
        drop(rt.network_handle);
        self.stats.active_flows.store(0, Ordering::Relaxed);

        if let Err(e) = flush_dns_cache() {
            warn!(error = %e, "Failed to flush Windows DNS cache while stopping transparent mode");
        }
        info!("Transparent proxy stopped cleanly and DNS cache flushed");
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
        assert_eq!(
            quote_windows_arg(r"C:\My Dir\"),
            r#""C:\My Dir\\""#
        );

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
        assert_eq!(st.supported, cfg!(windows));
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
                    dll_path: Some(r"Z:\__nonexistent_windivert_test_dir__\WinDivert.dll".to_string()),
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

    #[cfg(windows)]
    #[test]
    fn test_system32_dll_and_exe_loaders_resolve_system32() {
        use windows_sys::Win32::Foundation::FreeLibrary;

        let dnsapi = unsafe { load_system32_library("dnsapi.dll") }
            .expect("dnsapi.dll should load cleanly from System32");
        assert!(!dnsapi.is_null());
        unsafe {
            FreeLibrary(dnsapi);
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
    fn test_windivert_network_filter_captures_fake_ip_udp() {
        let f = windivert_network_filter();
        assert!(f.contains("udp.DstPort == 53"));
        assert!(f.contains("udp.DstPort == 443"));
        assert!(f.contains("198.18.0.0"));
        assert!(f.contains("198.19.255.255"));
        assert!(f.contains("or fragment"));
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
        assert_eq!(persisted.dll_path.as_deref(), Some(r"C:\test\WinDivert.dll"));

        mgr.set_persisted_enabled(false);
        assert!(!mgr.persisted_settings().enabled);
    }
}
