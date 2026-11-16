use std::ffi::{c_void, CString};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use windows_sys::Win32::Foundation::{
    FreeLibrary, GetLastError, HANDLE, HMODULE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
    LOAD_LIBRARY_SEARCH_SYSTEM32,
};

pub const WINDIVERT_FLAG_SNIFF: u64 = 0x0001;
pub const WINDIVERT_FLAG_DROP: u64 = 0x0002;
pub const WINDIVERT_FLAG_RECV_ONLY: u64 = 0x0004;
pub const WINDIVERT_FLAG_SEND_ONLY: u64 = 0x0008;
pub const WINDIVERT_FLAG_NO_INSTALL: u64 = 0x0010;
pub const WINDIVERT_FLAG_FRAGMENTS: u64 = 0x0020;

/// WinDivert `SOCKET` 层必须同时开启 `SNIFF | RECV_ONLY` 旁路嗅探；仅传 `RECV_ONLY` 会按阻断分流模式挂起或失败宿主机所有 socket 操作
pub const SOCKET_LAYER_FLAGS: u64 = WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY;

pub const WINDIVERT_PARAM_QUEUE_LENGTH_DEFAULT: u64 = 4096;
pub const WINDIVERT_PARAM_QUEUE_LENGTH_MAX: u64 = 16384;
pub const WINDIVERT_PARAM_QUEUE_TIME_DEFAULT: u64 = 2000;
pub const WINDIVERT_PARAM_QUEUE_SIZE_DEFAULT: u64 = 4_194_304;
pub const WINDIVERT_PARAM_QUEUE_SIZE_MAX: u64 = 33_554_432;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinDivertLayer {
    Network = 0,
    Forward = 1,
    Flow = 2,
    Socket = 3,
    Reflect = 4,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinDivertEvent {
    NetworkPacket = 0,
    FlowEstablished = 1,
    FlowDeleted = 2,
    SocketBind = 3,
    SocketConnect = 4,
    SocketListen = 5,
    SocketAccept = 6,
    SocketClose = 7,
    ReflectOpen = 8,
    ReflectClose = 9,
}

impl WinDivertEvent {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::NetworkPacket),
            1 => Some(Self::FlowEstablished),
            2 => Some(Self::FlowDeleted),
            3 => Some(Self::SocketBind),
            4 => Some(Self::SocketConnect),
            5 => Some(Self::SocketListen),
            6 => Some(Self::SocketAccept),
            7 => Some(Self::SocketClose),
            8 => Some(Self::ReflectOpen),
            9 => Some(Self::ReflectClose),
            _ => None,
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinDivertShutdownMode {
    Recv = 1,
    Send = 2,
    Both = 3,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinDivertParam {
    QueueLength = 0,
    QueueTime = 1,
    QueueSize = 2,
    VersionMajor = 3,
    VersionMinor = 4,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct WinDivertDataNetwork {
    pub if_idx: u32,
    pub sub_if_idx: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct WinDivertDataFlow {
    pub endpoint_id: u64,
    pub parent_endpoint_id: u64,
    pub process_id: u32,
    pub local_addr: [u32; 4],
    pub remote_addr: [u32; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: u8,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct WinDivertDataSocket {
    pub endpoint_id: u64,
    pub parent_endpoint_id: u64,
    pub process_id: u32,
    pub local_addr: [u32; 4],
    pub remote_addr: [u32; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: u8,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct WinDivertDataReflect {
    pub timestamp: i64,
    pub process_id: u32,
    pub layer: u32,
    pub flags: u64,
    pub priority: i16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union WinDivertAddressUnion {
    pub network: WinDivertDataNetwork,
    pub flow: WinDivertDataFlow,
    pub socket: WinDivertDataSocket,
    pub reflect: WinDivertDataReflect,
    reserved: [u8; 64],
    _align: [u64; 8],
}

impl Default for WinDivertAddressUnion {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

/// WinDivert 2.2 `WINDIVERT_ADDRESS` C ABI 镜像（固定 80 字节，8 字节对齐）
#[repr(C)]
#[derive(Copy, Clone)]
pub struct WinDivertAddress {
    pub timestamp: i64,
    bitfield: u32,
    pub reserved: u32,
    pub union_data: WinDivertAddressUnion,
}

impl Default for WinDivertAddress {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl WinDivertAddress {
    #[inline]
    pub fn layer(&self) -> u8 {
        (self.bitfield & 0xff) as u8
    }

    #[inline]
    pub fn event(&self) -> u8 {
        ((self.bitfield >> 8) & 0xff) as u8
    }

    #[inline]
    pub fn sniffed(&self) -> bool {
        ((self.bitfield >> 16) & 1) != 0
    }

    #[inline]
    pub fn outbound(&self) -> bool {
        ((self.bitfield >> 17) & 1) != 0
    }

    #[inline]
    pub fn set_outbound(&mut self, value: bool) {
        self.set_bit(17, value);
    }

    #[inline]
    pub fn loopback(&self) -> bool {
        ((self.bitfield >> 18) & 1) != 0
    }

    #[inline]
    pub fn set_loopback(&mut self, value: bool) {
        self.set_bit(18, value);
    }

    #[inline]
    pub fn impostor(&self) -> bool {
        ((self.bitfield >> 19) & 1) != 0
    }

    #[inline]
    pub fn set_impostor(&mut self, value: bool) {
        self.set_bit(19, value);
    }

    #[inline]
    pub fn ipv6(&self) -> bool {
        ((self.bitfield >> 20) & 1) != 0
    }

    #[inline]
    pub fn set_ipv6(&mut self, value: bool) {
        self.set_bit(20, value);
    }

    #[inline]
    pub fn ip_checksum(&self) -> bool {
        ((self.bitfield >> 21) & 1) != 0
    }

    #[inline]
    pub fn set_ip_checksum(&mut self, value: bool) {
        self.set_bit(21, value);
    }

    #[inline]
    pub fn tcp_checksum(&self) -> bool {
        ((self.bitfield >> 22) & 1) != 0
    }

    #[inline]
    pub fn set_tcp_checksum(&mut self, value: bool) {
        self.set_bit(22, value);
    }

    #[inline]
    pub fn udp_checksum(&self) -> bool {
        ((self.bitfield >> 23) & 1) != 0
    }

    #[inline]
    pub fn set_udp_checksum(&mut self, value: bool) {
        self.set_bit(23, value);
    }

    #[inline]
    fn set_bit(&mut self, bit: u32, value: bool) {
        let mask = 1u32 << bit;
        if value {
            self.bitfield |= mask;
        } else {
            self.bitfield &= !mask;
        }
    }

    #[inline]
    pub fn raw_bitfield(&self) -> u32 {
        self.bitfield
    }

    /// 构造用于原始出站报文平滑放行的干净 NETWORK 层地址，完整保留原接口与校验和卸载标志
    pub fn outbound_passthrough(if_idx: u32, sub_if_idx: u32, raw_bitfield: u32) -> Self {
        let mut addr = Self {
            bitfield: raw_bitfield,
            ..Self::default()
        };
        addr.set_outbound(true);
        addr.union_data.network = WinDivertDataNetwork {
            if_idx,
            sub_if_idx,
        };
        addr
    }

    /// 构造用于入站注入的干净 NETWORK 层地址（保留原接口索引与 loopback/ipv6 标志，Outbound = false）
    pub fn inbound_injection(
        if_idx: u32,
        sub_if_idx: u32,
        loopback: bool,
        ipv6: bool,
    ) -> Self {
        let mut addr = Self::default();
        addr.set_outbound(false);
        addr.set_loopback(loopback);
        addr.set_impostor(false);
        addr.set_ipv6(ipv6);
        addr.union_data.network = WinDivertDataNetwork {
            if_idx,
            sub_if_idx,
        };
        addr
    }

    /// 安全提取 NETWORK 层接口索引
    #[inline]
    pub fn network(&self) -> WinDivertDataNetwork {
        unsafe { self.union_data.network }
    }

    /// 安全提取 SOCKET 层事件数据
    #[inline]
    pub fn socket_data(&self) -> WinDivertDataSocket {
        unsafe { self.union_data.socket }
    }
}

/// 将 WinDivert 128 位主机序 `[u32; 4]`（小端字序：`addr[0]` 为最低 32 位）转换为标准 `IpAddr`
pub fn decode_windivert_addr(raw: &[u32; 4], is_ipv6: bool) -> IpAddr {
    if !is_ipv6 {
        return IpAddr::V4(Ipv4Addr::from(raw[0]));
    }
    let v = ((raw[3] as u128) << 96)
        | ((raw[2] as u128) << 64)
        | ((raw[1] as u128) << 32)
        | (raw[0] as u128);
    IpAddr::V6(Ipv6Addr::from(v)).to_canonical()
}

type FnWinDivertOpen = unsafe extern "C" fn(
    filter: *const i8,
    layer: u32,
    priority: i16,
    flags: u64,
) -> HANDLE;
type FnWinDivertRecv = unsafe extern "C" fn(
    handle: HANDLE,
    p_packet: *mut c_void,
    packet_len: u32,
    p_recv_len: *mut u32,
    p_addr: *mut WinDivertAddress,
) -> i32;
type FnWinDivertSend = unsafe extern "C" fn(
    handle: HANDLE,
    p_packet: *const c_void,
    packet_len: u32,
    p_send_len: *mut u32,
    p_addr: *const WinDivertAddress,
) -> i32;
type FnWinDivertShutdown = unsafe extern "C" fn(handle: HANDLE, how: u32) -> i32;
type FnWinDivertClose = unsafe extern "C" fn(handle: HANDLE) -> i32;
type FnWinDivertSetParam = unsafe extern "C" fn(handle: HANDLE, param: u32, value: u64) -> i32;
type FnWinDivertGetParam =
    unsafe extern "C" fn(handle: HANDLE, param: u32, p_value: *mut u64) -> i32;
type FnWinDivertHelperCalcChecksums = unsafe extern "C" fn(
    p_packet: *mut c_void,
    packet_len: u32,
    p_addr: *mut WinDivertAddress,
    flags: u64,
) -> i32;

#[derive(Debug, Clone)]
pub struct WinDivertAvailability {
    pub dll_found: bool,
    pub sys_found: bool,
    pub dll_path: Option<String>,
    pub sys_path: Option<String>,
    pub searched_dirs: Vec<String>,
}

pub(crate) fn is_trusted_local_absolute_path(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let mut has_disk_prefix = !cfg!(windows);
    for comp in path.components() {
        match comp {
            std::path::Component::ParentDir | std::path::Component::CurDir => return false,
            #[cfg(windows)]
            std::path::Component::Prefix(prefix) => {
                use std::path::Prefix;
                match prefix.kind() {
                    Prefix::Disk(_) | Prefix::VerbatimDisk(_) => has_disk_prefix = true,
                    _ => return false,
                }
            }
            _ => {}
        }
    }
    has_disk_prefix
}

pub(crate) fn resolve_candidate_dll_path(raw: &str) -> Option<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let pb = PathBuf::from(trimmed);
    if !is_trusted_local_absolute_path(&pb) {
        return None;
    }
    let cand = if pb.is_dir()
        || (pb.extension().is_none()
            && !pb
                .file_name()
                .is_some_and(|n| n.eq_ignore_ascii_case("WinDivert.dll")))
    {
        pb.join("WinDivert.dll")
    } else {
        pb
    };
    if !cand
        .file_name()
        .is_some_and(|n| n.eq_ignore_ascii_case("WinDivert.dll"))
    {
        return None;
    }
    Some(cand)
}

fn locate_windivert_in_candidates(candidates: Vec<PathBuf>, sys_name: &str) -> WinDivertAvailability {
    let mut searched_dirs = Vec::new();
    let mut partial: Option<(Option<PathBuf>, Option<PathBuf>)> = None;

    for dll_cand in candidates {
        let abs_dll = std::path::absolute(&dll_cand).unwrap_or(dll_cand);
        let Some(parent) = abs_dll.parent() else {
            continue;
        };
        let dir_str = parent.display().to_string();
        if !searched_dirs.contains(&dir_str) {
            searched_dirs.push(dir_str);
        }

        let dll_ok = abs_dll.is_file();
        let sys_cand = parent.join(sys_name);
        let sys_ok = sys_cand.is_file();

        // DLL 与对应架构 .sys 驱动必须位于同一目录，防止跨目录混配或残缺加载
        if dll_ok && sys_ok {
            return WinDivertAvailability {
                dll_found: true,
                sys_found: true,
                dll_path: Some(abs_dll.display().to_string()),
                sys_path: Some(sys_cand.display().to_string()),
                searched_dirs,
            };
        }

        if partial.is_none() && (dll_ok || sys_ok) {
            partial = Some((
                dll_ok.then_some(abs_dll),
                sys_ok.then_some(sys_cand),
            ));
        }
    }

    let (partial_dll, partial_sys) = partial.unwrap_or((None, None));
    WinDivertAvailability {
        dll_found: partial_dll.is_some(),
        sys_found: partial_sys.is_some(),
        dll_path: partial_dll.map(|p| p.display().to_string()),
        sys_path: partial_sys.map(|p| p.display().to_string()),
        searched_dirs,
    }
}

/// 探测 `WinDivert.dll` 与对应架构内核驱动 `.sys` 是否同目录配对就位（仅检查显式配置、环境变量与程序目录，禁止回退当前工作目录）
pub fn locate_windivert_files(custom_dll_path: Option<&str>) -> WinDivertAvailability {
    let sys_name = if cfg!(target_pointer_width = "64") {
        "WinDivert64.sys"
    } else {
        "WinDivert32.sys"
    };

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(custom) = custom_dll_path.and_then(resolve_candidate_dll_path) {
        candidates.push(custom);
    } else if custom_dll_path.is_none_or(|p| p.trim().is_empty()) {
        if let Ok(exe) = std::env::current_exe()
            && let Some(dir) = exe.parent()
        {
            candidates.push(dir.join("WinDivert.dll"));
            candidates.push(dir.join("driver").join("WinDivert.dll"));
        }
        if let Ok(env_p) = std::env::var("FLOWX_WINDIVERT_DLL")
            && let Some(cand) = resolve_candidate_dll_path(&env_p)
        {
            candidates.push(cand);
        }
    }

    locate_windivert_in_candidates(candidates, sys_name)
}

/// 动态加载并托管的 `WinDivert.dll` 函数表；销毁时自动 `FreeLibrary`
pub struct WinDivertApi {
    module: HMODULE,
    loaded_from: String,
    fn_open: FnWinDivertOpen,
    fn_recv: FnWinDivertRecv,
    fn_send: FnWinDivertSend,
    fn_shutdown: FnWinDivertShutdown,
    fn_close: FnWinDivertClose,
    fn_set_param: FnWinDivertSetParam,
    fn_get_param: FnWinDivertGetParam,
    fn_calc_checksums: FnWinDivertHelperCalcChecksums,
}

unsafe impl Send for WinDivertApi {}
unsafe impl Sync for WinDivertApi {}

impl Drop for WinDivertApi {
    fn drop(&mut self) {
        if !self.module.is_null() {
            unsafe {
                FreeLibrary(self.module);
            }
        }
    }
}

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn load_proc<T>(module: HMODULE, name: &str) -> io::Result<T> {
    let cname = CString::new(name).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("invalid symbol name: {name}"))
    })?;
    let proc = unsafe { GetProcAddress(module, cname.as_ptr() as *const u8) };
    match proc {
        Some(ptr) => Ok(unsafe { std::mem::transmute_copy::<_, T>(&ptr) }),
        None => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("WinDivert.dll missing exported symbol '{name}'"),
        )),
    }
}

impl WinDivertApi {
    /// 动态加载已与对应 `.sys` 同目录配对的 `WinDivert.dll`（使用限定安全搜索路径，不回退 CWD/PATH 裸名）
    pub fn load(custom_dll_path: Option<&str>) -> io::Result<Arc<Self>> {
        let avail = locate_windivert_files(custom_dll_path);
        if !avail.dll_found || !avail.sys_found {
            let searched = if avail.searched_dirs.is_empty() {
                "executable directory".to_string()
            } else {
                avail.searched_dirs.join(", ")
            };
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "Paired WinDivert.dll (found={}) and matching .sys driver (found={}) not found in the same trusted directory. Searched dirs: {}",
                    avail.dll_found, avail.sys_found, searched
                ),
            ));
        }
        let load_target = avail.dll_path.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Paired WinDivert.dll path missing after availability check",
            )
        })?;
        let abs_target = std::path::absolute(Path::new(&load_target))
            .unwrap_or_else(|_| PathBuf::from(&load_target));
        let abs_target_str = abs_target.display().to_string();
        let wide = to_wide_null(&abs_target_str);
        let module = unsafe {
            LoadLibraryExW(
                wide.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            let err = io::Error::last_os_error();
            let detail = if avail.searched_dirs.is_empty() {
                format!(
                    "Failed to load WinDivert.dll from '{}' ({err}).",
                    abs_target_str
                )
            } else {
                format!(
                    "Failed to load WinDivert.dll from '{}' ({err}). Searched dirs: {}",
                    abs_target_str,
                    avail.searched_dirs.join(", ")
                )
            };
            return Err(io::Error::new(err.kind(), detail));
        }

        // 确保若任何符号解析失败，模块仍会被提前释放
        let load_res: io::Result<Self> = unsafe {
            Ok(Self {
                module,
                loaded_from: abs_target_str,
                fn_open: load_proc(module, "WinDivertOpen")?,
                fn_recv: load_proc(module, "WinDivertRecv")?,
                fn_send: load_proc(module, "WinDivertSend")?,
                fn_shutdown: load_proc(module, "WinDivertShutdown")?,
                fn_close: load_proc(module, "WinDivertClose")?,
                fn_set_param: load_proc(module, "WinDivertSetParam")?,
                fn_get_param: load_proc(module, "WinDivertGetParam")?,
                fn_calc_checksums: load_proc(module, "WinDivertHelperCalcChecksums")?,
            })
        };

        match load_res {
            Ok(api) => Ok(Arc::new(api)),
            Err(e) => {
                unsafe {
                    FreeLibrary(module);
                }
                Err(e)
            }
        }
    }

    pub fn loaded_from(&self) -> &str {
        &self.loaded_from
    }
}

/// 安全的 WinDivert 内核句柄封装，Drop 时自动 shutdown + close，防止服务停止后驱动残留
pub struct WinDivertHandle {
    handle: HANDLE,
    api: Arc<WinDivertApi>,
}

unsafe impl Send for WinDivertHandle {}
unsafe impl Sync for WinDivertHandle {}

impl WinDivertHandle {
    pub fn open(
        api: Arc<WinDivertApi>,
        filter: &str,
        layer: WinDivertLayer,
        priority: i16,
        flags: u64,
    ) -> io::Result<Self> {
        let c_filter = CString::new(filter).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "WinDivert filter contains interior NUL")
        })?;
        let handle = unsafe { (api.fn_open)(c_filter.as_ptr(), layer as u32, priority, flags) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            let err = io::Error::last_os_error();
            let raw = unsafe { GetLastError() };
            let msg = match raw {
                2 => format!(
                    "WinDivert driver file not found (code {raw}: {err}). Ensure WinDivert64.sys sits alongside WinDivert.dll."
                ),
                5 => format!(
                    "Administrator privilege required to open WinDivert driver (code {raw}: {err})."
                ),
                577 => format!(
                    "WinDivert64.sys driver signature verification failed (code {raw}: {err}). Update to an officially signed WinDivert release."
                ),
                87 => format!(
                    "Invalid WinDivert filter/parameters (code {raw}: {err}) for layer {layer:?}: '{filter}'."
                ),
                _ => format!("WinDivertOpen failed for layer {layer:?} (code {raw}: {err})."),
            };
            return Err(io::Error::new(err.kind(), msg));
        }

        Ok(Self { handle, api })
    }

    pub fn set_param(&self, param: WinDivertParam, value: u64) -> io::Result<()> {
        let ok = unsafe { (self.api.fn_set_param)(self.handle, param as u32, value) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn version(&self) -> Option<(u64, u64)> {
        let mut major = 0u64;
        let mut minor = 0u64;
        let ok_maj = unsafe {
            (self.api.fn_get_param)(self.handle, WinDivertParam::VersionMajor as u32, &mut major)
        };
        let ok_min = unsafe {
            (self.api.fn_get_param)(self.handle, WinDivertParam::VersionMinor as u32, &mut minor)
        };
        if ok_maj != 0 && ok_min != 0 {
            Some((major, minor))
        } else {
            None
        }
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, WinDivertAddress)> {
        let mut recv_len = 0u32;
        let mut addr = WinDivertAddress::default();
        let ok = unsafe {
            (self.api.fn_recv)(
                self.handle,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut recv_len,
                &mut addr,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((recv_len as usize, addr))
    }

    pub fn send(&self, packet: &[u8], addr: &WinDivertAddress) -> io::Result<usize> {
        let mut send_len = 0u32;
        let ok = unsafe {
            (self.api.fn_send)(
                self.handle,
                packet.as_ptr() as *const c_void,
                packet.len() as u32,
                &mut send_len,
                addr,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(send_len as usize)
    }

    pub fn calc_checksums(&self, packet: &mut [u8], addr: &mut WinDivertAddress) -> bool {
        let ok = unsafe {
            (self.api.fn_calc_checksums)(
                packet.as_mut_ptr() as *mut c_void,
                packet.len() as u32,
                addr,
                0,
            )
        };
        ok != 0
    }

    pub fn shutdown(&self, how: WinDivertShutdownMode) -> io::Result<()> {
        let ok = unsafe { (self.api.fn_shutdown)(self.handle, how as u32) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for WinDivertHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
            unsafe {
                let _ = (self.api.fn_shutdown)(self.handle, WinDivertShutdownMode::Both as u32);
                let _ = (self.api.fn_close)(self.handle);
            }
            self.handle = INVALID_HANDLE_VALUE;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    #[test]
    fn test_windivert_address_c_abi_layout() {
        assert_eq!(size_of::<WinDivertDataNetwork>(), 8);
        assert_eq!(size_of::<WinDivertAddressUnion>(), 64);
        assert_eq!(size_of::<WinDivertAddress>(), 80);
        assert_eq!(align_of::<WinDivertAddress>(), 8);
        assert_eq!(offset_of!(WinDivertAddress, timestamp), 0);
        assert_eq!(offset_of!(WinDivertAddress, reserved), 12);
        assert_eq!(offset_of!(WinDivertAddress, union_data), 16);

        assert_eq!(offset_of!(WinDivertDataSocket, endpoint_id), 0);
        assert_eq!(offset_of!(WinDivertDataSocket, parent_endpoint_id), 8);
        assert_eq!(offset_of!(WinDivertDataSocket, process_id), 16);
        assert_eq!(offset_of!(WinDivertDataSocket, local_addr), 20);
        assert_eq!(offset_of!(WinDivertDataSocket, remote_addr), 36);
        assert_eq!(offset_of!(WinDivertDataSocket, local_port), 52);
        assert_eq!(offset_of!(WinDivertDataSocket, remote_port), 54);
        assert_eq!(offset_of!(WinDivertDataSocket, protocol), 56);
    }

    #[test]
    fn test_windivert_address_bitfields_and_ip_decoding() {
        let mut addr = WinDivertAddress::default();
        assert!(!addr.outbound());
        addr.set_outbound(true);
        addr.set_loopback(true);
        addr.set_ipv6(true);
        addr.set_tcp_checksum(true);
        assert!(addr.outbound());
        assert!(addr.loopback());
        assert!(!addr.impostor());
        assert!(addr.ipv6());
        assert!(!addr.ip_checksum());
        assert!(addr.tcp_checksum());
        assert!(!addr.udp_checksum());

        let inbound = WinDivertAddress::inbound_injection(7, 2, false, false);
        assert!(!inbound.outbound());
        assert_eq!(inbound.network().if_idx, 7);
        assert_eq!(inbound.network().sub_if_idx, 2);

        // IPv4 host-order u32 (192.168.1.10)
        let v4_raw = [u32::from(Ipv4Addr::new(192, 168, 1, 10)), 0, 0, 0];
        assert_eq!(
            decode_windivert_addr(&v4_raw, false),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))
        );

        // IPv4-mapped IPv6 in WinDivert [u32; 4] host-word order -> canonicalized to IPv4
        let v4_mapped_raw = [u32::from(Ipv4Addr::new(8, 8, 8, 8)), 0x0000_ffff, 0, 0];
        assert_eq!(
            decode_windivert_addr(&v4_mapped_raw, true),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
        );

        // Full IPv6 address (2001:db8::1)
        let v6 = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let n = u128::from(v6);
        let v6_raw = [
            (n & 0xffff_ffff) as u32,
            ((n >> 32) & 0xffff_ffff) as u32,
            ((n >> 64) & 0xffff_ffff) as u32,
            ((n >> 96) & 0xffff_ffff) as u32,
        ];
        assert_eq!(decode_windivert_addr(&v6_raw, true), IpAddr::V6(v6));
    }

    #[test]
    fn test_socket_layer_flags_include_sniff_and_recv_only() {
        assert_ne!(SOCKET_LAYER_FLAGS & WINDIVERT_FLAG_SNIFF, 0);
        assert_ne!(SOCKET_LAYER_FLAGS & WINDIVERT_FLAG_RECV_ONLY, 0);
        assert_eq!(
            SOCKET_LAYER_FLAGS,
            WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY
        );
    }

    #[test]
    fn test_locate_windivert_enforces_same_dir_pairing_and_no_cwd() {
        struct CleanDir(PathBuf);
        impl Drop for CleanDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("flowx_windivert_pair_{}_{}", std::process::id(), nonce));
        let _clean = CleanDir(root.clone());
        let dir_dll_only = root.join("dll_only");
        let dir_sys_only = root.join("sys_only");
        let dir_paired = root.join("paired");
        std::fs::create_dir_all(&dir_dll_only).unwrap();
        std::fs::create_dir_all(&dir_sys_only).unwrap();
        std::fs::create_dir_all(&dir_paired).unwrap();

        let sys_name = if cfg!(target_pointer_width = "64") {
            "WinDivert64.sys"
        } else {
            "WinDivert32.sys"
        };

        std::fs::write(dir_dll_only.join("WinDivert.dll"), b"dll").unwrap();
        std::fs::write(dir_sys_only.join(sys_name), b"sys").unwrap();

        // 目录 A 仅有 DLL、目录 B 仅有 SYS：绝不能跨目录混配出 dll_found && sys_found
        let split = locate_windivert_in_candidates(
            vec![
                dir_dll_only.join("WinDivert.dll"),
                dir_sys_only.join("WinDivert.dll"),
            ],
            sys_name,
        );
        assert!(split.dll_found);
        assert!(!split.sys_found);
        assert!(split.sys_path.is_none());

        // 通过 WinDivertApi::load 加载缺少同目录 .sys 的路径时必须失败，不得裸名回退
        let err = match WinDivertApi::load(Some(&dir_dll_only.display().to_string())) {
            Err(e) => e,
            Ok(_) => panic!("WinDivertApi::load must refuse loading DLL without paired .sys"),
        };
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        // 目录 C 同时包含 DLL + SYS 时必须优先配对返回同目录路径
        std::fs::write(dir_paired.join("WinDivert.dll"), b"dll").unwrap();
        std::fs::write(dir_paired.join(sys_name), b"sys").unwrap();
        let paired = locate_windivert_in_candidates(
            vec![
                dir_dll_only.join("WinDivert.dll"),
                dir_sys_only.join("WinDivert.dll"),
                dir_paired.join("WinDivert.dll"),
            ],
            sys_name,
        );
        assert!(paired.dll_found);
        assert!(paired.sys_found);
        assert_eq!(
            paired.dll_path.as_deref(),
            Some(dir_paired.join("WinDivert.dll").display().to_string().as_str())
        );
        assert_eq!(
            paired.sys_path.as_deref(),
            Some(dir_paired.join(sys_name).display().to_string().as_str())
        );

        // 默认探测不得搜索 current_dir（除非 exe 目录恰好等于 cwd）
        if std::env::var_os("FLOWX_WINDIVERT_DLL").is_none()
            && let (Ok(cwd), Ok(exe)) = (std::env::current_dir(), std::env::current_exe())
            && exe.parent() != Some(cwd.as_path())
        {
            let auto_avail = locate_windivert_files(None);
            assert!(
                !auto_avail
                    .searched_dirs
                    .iter()
                    .any(|d| Path::new(d) == cwd.as_path()),
                "searched_dirs must never include current_dir: {:?}",
                auto_avail.searched_dirs
            );
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_resolve_candidate_dll_path_enforces_trusted_absolute_windivert_dll() {
        assert!(resolve_candidate_dll_path("").is_none());
        assert!(resolve_candidate_dll_path("WinDivert.dll").is_none());
        assert!(resolve_candidate_dll_path(r".\driver\WinDivert.dll").is_none());
        assert!(resolve_candidate_dll_path(r"..\driver\WinDivert.dll").is_none());
        assert!(resolve_candidate_dll_path(r"C:\FlowX\..\WinDivert.dll").is_none());
        assert!(resolve_candidate_dll_path(r"\\fileserver\share\WinDivert.dll").is_none());
        assert!(resolve_candidate_dll_path(r"C:\FlowX\evil.dll").is_none());

        assert_eq!(
            resolve_candidate_dll_path(r"C:\FlowX\driver\WinDivert.dll"),
            Some(PathBuf::from(r"C:\FlowX\driver\WinDivert.dll"))
        );
        assert_eq!(
            resolve_candidate_dll_path(r"C:\FlowX\driver"),
            Some(PathBuf::from(r"C:\FlowX\driver\WinDivert.dll"))
        );
    }
}
