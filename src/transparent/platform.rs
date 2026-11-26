use std::io;

use super::windivert_ffi;

/// 检测当前进程是否拥有 Windows 管理员提升令牌
pub fn is_process_elevated() -> bool {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 || token.is_null() {
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

pub(crate) const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x2000;

#[inline]
pub(crate) fn is_low_integrity_rid(rid: u32) -> bool {
    rid < SECURITY_MANDATORY_MEDIUM_RID
}

/// 查询当前进程令牌的 Windows 强制完整性级别 RID（如 Low=0x1000, Medium=0x2000, High=0x3000）
pub(crate) fn process_integrity_rid() -> Option<u32> {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, GetLastError, HANDLE,
    };
    use windows_sys::Win32::Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsValidSid,
        TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenIntegrityLevel,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 || token.is_null() {
            return None;
        }
        let mut ret_len = 0u32;
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            std::ptr::null_mut(),
            0,
            &mut ret_len,
        );
        if GetLastError() != ERROR_INSUFFICIENT_BUFFER || ret_len == 0 {
            CloseHandle(token);
            return None;
        }
        let buf_words = (ret_len as usize).div_ceil(std::mem::size_of::<u64>());
        let mut buf = vec![0u64; buf_words];
        let buf_bytes = buf.len().saturating_mul(std::mem::size_of::<u64>());
        let Ok(buf_bytes_u32) = u32::try_from(buf_bytes) else {
            CloseHandle(token);
            return None;
        };
        let ok = GetTokenInformation(
            token,
            TokenIntegrityLevel,
            buf.as_mut_ptr().cast::<c_void>(),
            buf_bytes_u32,
            &mut ret_len,
        );
        CloseHandle(token);
        if ok == 0
            || (ret_len as usize) < std::mem::size_of::<TOKEN_MANDATORY_LABEL>()
            || (ret_len as usize) > buf_bytes
        {
            return None;
        }
        let label = std::ptr::read_unaligned(buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>());
        let sid = label.Label.Sid;
        if sid.is_null() || IsValidSid(sid) == 0 {
            return None;
        }
        let count_ptr = GetSidSubAuthorityCount(sid);
        if count_ptr.is_null() {
            return None;
        }
        let count = std::ptr::read_unaligned(count_ptr);
        if count == 0 {
            return None;
        }
        let last_idx = u32::from(count - 1);
        let rid_ptr = GetSidSubAuthority(sid, last_idx);
        if rid_ptr.is_null() {
            return None;
        }
        Some(std::ptr::read_unaligned(rid_ptr))
    }
}

/// 判断当前进程是否处于 Windows 低完整性级别（`< Medium (0x2000)`，如沙盒/受限目录继承 `Low Mandatory Level`）
pub fn is_low_integrity_process() -> bool {
    process_integrity_rid().is_some_and(is_low_integrity_rid)
}

/// 仅从 Windows `System32` 目录加载系统 DLL（避免高权限下被 CWD / 应用目录 / `PATH` 劫持）
pub(super) unsafe fn load_system32_library(
    dll_name: &str,
) -> io::Result<windows_sys::Win32::Foundation::HMODULE> {
    use windows_sys::Win32::System::LibraryLoader::{LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW};

    let wide: Vec<u16> = dll_name.encode_utf16().chain(std::iter::once(0)).collect();
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

/// 解析通过 Windows API `GetSystemDirectoryW` 确认的本地可信 `System32\<exe_name>` 路径，拒绝可变环境变量、CWD 与 UNC 回退
fn get_trusted_system32_dir() -> io::Result<std::path::PathBuf> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemDirectoryW(lpBuffer: *mut u16, uSize: u32) -> u32;
    }

    let mut buf = vec![0u16; 260];
    let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    if (len as usize) > buf.len() {
        buf.resize(len as usize, 0);
        let len2 = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
        if len2 == 0 || (len2 as usize) >= buf.len() {
            return Err(io::Error::last_os_error());
        }
        return Ok(std::path::PathBuf::from(String::from_utf16_lossy(
            &buf[..len2 as usize],
        )));
    }
    Ok(std::path::PathBuf::from(String::from_utf16_lossy(
        &buf[..len as usize],
    )))
}

pub(super) fn resolve_system32_executable(exe_name: &str) -> io::Result<std::path::PathBuf> {
    let sys_dir = get_trusted_system32_dir()?;
    if !windivert_ffi::is_trusted_local_absolute_path(&sys_dir) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "GetSystemDirectoryW returned untrusted path: {}",
                sys_dir.display()
            ),
        ));
    }
    let exe_path = sys_dir.join(exe_name);
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
    use std::ffi::CString;
    use windows_sys::Win32::Foundation::FreeLibrary;
    use windows_sys::Win32::System::LibraryLoader::GetProcAddress;

    type FnDnsFlushResolverCache = unsafe extern "system" fn() -> i32;
    if let Ok(module) = unsafe { load_system32_library("dnsapi.dll") } {
        let sym = CString::new("DnsFlushResolverCache").unwrap();
        let proc = unsafe { GetProcAddress(module, sym.as_ptr() as *const u8) };
        let flushed = if let Some(ptr) = proc {
            let func: FnDnsFlushResolverCache = unsafe { std::mem::transmute_copy(&ptr) };
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

/// 按 Windows `CommandLineToArgvW` 规范转义命令行参数
pub fn quote_windows_arg(arg: &str) -> String {
    if !arg.is_empty()
        && !arg
            .chars()
            .any(|c| matches!(c, ' ' | '\t' | '\n' | '\r' | '"'))
    {
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
        if arg.starts_with("--replace-pid=") || arg == "--transparent" || arg == "--no-transparent"
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

pub(super) struct StaComGuard {
    ole32_mod: windows_sys::Win32::Foundation::HMODULE,
    should_uninit: bool,
}

impl StaComGuard {
    /// 按 ShellExecuteW 官方要求初始化线程 STA COM（COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE），并在退出作用域时配对释放
    pub(super) fn init() -> Option<Self> {
        use std::ffi::c_void;
        use windows_sys::Win32::Foundation::FreeLibrary;
        use windows_sys::Win32::System::LibraryLoader::GetProcAddress;

        const COINIT_APARTMENTTHREADED_DISABLE_OLE1DDE: u32 = 0x2 | 0x4;
        type CoInitializeExFn = unsafe extern "system" fn(*const c_void, u32) -> i32;

        let ole32_mod = unsafe { load_system32_library("ole32.dll") }.ok()?;
        let co_init_ptr =
            unsafe { GetProcAddress(ole32_mod, c"CoInitializeEx".as_ptr().cast::<u8>()) };
        let Some(co_init_fn_ptr) = co_init_ptr else {
            unsafe {
                FreeLibrary(ole32_mod);
            }
            return None;
        };
        let co_initialize_ex: CoInitializeExFn = unsafe { std::mem::transmute(co_init_fn_ptr) };
        let hr =
            unsafe { co_initialize_ex(std::ptr::null(), COINIT_APARTMENTTHREADED_DISABLE_OLE1DDE) };
        // S_OK (0) 或 S_FALSE (1) 需要配对 CoUninitialize；RPC_E_CHANGED_MODE 等则不调用
        let should_uninit = hr == 0 || hr == 1;
        Some(Self {
            ole32_mod,
            should_uninit,
        })
    }
}

impl Drop for StaComGuard {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::FreeLibrary;
        use windows_sys::Win32::System::LibraryLoader::GetProcAddress;

        type CoUninitializeFn = unsafe extern "system" fn();

        if self.should_uninit {
            let co_uninit_ptr =
                unsafe { GetProcAddress(self.ole32_mod, c"CoUninitialize".as_ptr().cast::<u8>()) };
            if let Some(ptr) = co_uninit_ptr {
                let co_uninitialize: CoUninitializeFn = unsafe { std::mem::transmute(ptr) };
                unsafe {
                    co_uninitialize();
                }
            }
        }
        unsafe {
            FreeLibrary(self.ole32_mod);
        }
    }
}

/// 触发 Windows UAC 提权以 `--transparent --replace-pid <当前PID>` 重启 FlowX，由新实例平滑接管配置与端口
pub fn relaunch_elevated_with_replace_pid(extra_args: &[String]) -> io::Result<()> {
    use windows_sys::Win32::Foundation::{FreeLibrary, HINSTANCE, HWND};
    use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    if is_process_elevated() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Process is already running with Administrator privileges",
        ));
    }

    if is_low_integrity_process() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ERR_TRANSPARENT_LOW_INTEGRITY: Current process is running at Windows Low Mandatory Integrity Level (for example when launched from a restricted or sandboxed directory); Windows blocks in-process UAC elevation and USER32/SHELL32 initialization. Move or install FlowX into a standard directory, or start FlowX from an Administrator terminal.",
        ));
    }

    // 初始化 STA COM（ShellExecuteW 在 Tokio blocking 工作线程上默认无 COM 套间），保持到 ShellExecuteW 与 FreeLibrary 完成
    let _com_guard = StaComGuard::init();

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
            5 | 1223 => {
                "ERR_TRANSPARENT_UAC_CANCELLED: Administrator elevation prompt was cancelled or denied."
            }
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
