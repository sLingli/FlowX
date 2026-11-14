use std::ffi::{c_void, CString};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use windows_sys::Win32::Foundation::{
    FreeLibrary, GetLastError, HANDLE, HMODULE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

pub const WINDIVERT_FLAG_SNIFF: u64 = 0x0001;
pub const WINDIVERT_FLAG_DROP: u64 = 0x0002;
pub const WINDIVERT_FLAG_RECV_ONLY: u64 = 0x0004;
pub const WINDIVERT_FLAG_SEND_ONLY: u64 = 0x0008;
pub const WINDIVERT_FLAG_NO_INSTALL: u64 = 0x0010;
pub const WINDIVERT_FLAG_FRAGMENTS: u64 = 0x0020;

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

/// 探测 `WinDivert.dll` 与对应架构内核驱动 `.sys` 是否就位（仅检查常见可信位置，不修改系统目录）
pub fn locate_windivert_files(custom_dll_path: Option<&str>) -> WinDivertAvailability {
    let sys_name = if cfg!(target_pointer_width = "64") {
        "WinDivert64.sys"
    } else {
        "WinDivert32.sys"
    };

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = custom_dll_path.map(str::trim).filter(|s| !s.is_empty()) {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            candidates.push(pb);
        } else if pb.is_dir() {
            candidates.push(pb.join("WinDivert.dll"));
        }
    }
    if let Ok(env_p) = std::env::var("FLOWX_WINDIVERT_DLL") {
        let trimmed = env_p.trim();
        if !trimmed.is_empty() {
            let pb = PathBuf::from(trimmed);
            candidates.push(if pb.is_dir() {
                pb.join("WinDivert.dll")
            } else {
                pb
            });
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        candidates.push(dir.join("WinDivert.dll"));
        candidates.push(dir.join("driver").join("WinDivert.dll"));
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("WinDivert.dll"));
        candidates.push(cwd.join("driver").join("WinDivert.dll"));
    }

    let mut searched_dirs = Vec::new();
    let mut found_dll: Option<PathBuf> = None;
    let mut found_sys: Option<PathBuf> = None;

    for dll_cand in candidates {
        if let Some(parent) = dll_cand.parent() {
            let dir_str = parent.display().to_string();
            if !searched_dirs.contains(&dir_str) {
                searched_dirs.push(dir_str);
            }
            if found_sys.is_none() {
                let sys_cand = parent.join(sys_name);
                if sys_cand.is_file() {
                    found_sys = Some(sys_cand);
                }
            }
        }
        if found_dll.is_none() && dll_cand.is_file() {
            found_dll = Some(dll_cand);
        }
        if found_dll.is_some() && found_sys.is_some() {
            break;
        }
    }

    if let (Some(dll), None) = (&found_dll, &found_sys)
        && let Some(parent) = dll.parent()
    {
        let sys_cand = parent.join(sys_name);
        if sys_cand.is_file() {
            found_sys = Some(sys_cand);
        }
    }

    WinDivertAvailability {
        dll_found: found_dll.is_some(),
        sys_found: found_sys.is_some(),
        dll_path: found_dll.map(|p| p.display().to_string()),
        sys_path: found_sys.map(|p| p.display().to_string()),
        searched_dirs,
    }
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
    /// 动态加载 `WinDivert.dll` 并解析所有所需导出口（零构建期 C 库或 SDK 依赖）
    pub fn load(custom_dll_path: Option<&str>) -> io::Result<Arc<Self>> {
        let avail = locate_windivert_files(custom_dll_path);
        let load_target = avail
            .dll_path
            .clone()
            .unwrap_or_else(|| "WinDivert.dll".to_string());
        let wide = to_wide_null(&load_target);
        let module = unsafe { LoadLibraryW(wide.as_ptr()) };
        if module.is_null() {
            let err = io::Error::last_os_error();
            let detail = if avail.searched_dirs.is_empty() {
                format!(
                    "Failed to load WinDivert.dll ({err}). Place WinDivert.dll and WinDivert64.sys next to flowx.exe."
                )
            } else {
                format!(
                    "Failed to load WinDivert.dll from '{}' ({err}). Searched dirs: {}",
                    load_target,
                    avail.searched_dirs.join(", ")
                )
            };
            return Err(io::Error::new(err.kind(), detail));
        }

        // 确保若任何符号解析失败，模块仍会被提前释放
        let load_res: io::Result<Self> = unsafe {
            Ok(Self {
                module,
                loaded_from: Path::new(&load_target).display().to_string(),
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
}
