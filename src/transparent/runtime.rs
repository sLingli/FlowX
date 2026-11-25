use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use tracing::{debug, info, warn};

use crate::dns::server::DnsServer;
use crate::interceptor::dispatcher::{DispatcherConfig, dispatch_transparent_stream};

use super::platform::{flush_dns_cache, is_process_elevated};
use super::{
    TransparentSettings, TransparentStatsCounters, dns_hijack, fragment, netstack, pid_table,
    windivert_ffi,
};

fn resolve_outbound_pid(
    table: &pid_table::SocketPidTable,
    protocol: u8,
    local: std::net::SocketAddr,
    remote: std::net::SocketAddr,
    allow_os_fallback: bool,
) -> Option<u32> {
    match table.lookup_status(protocol, local.ip(), local.port()) {
        pid_table::PidTableLookup::Hit(pid) => Some(pid),
        pid_table::PidTableLookup::NegativeCached => None,
        pid_table::PidTableLookup::Miss => {
            if !allow_os_fallback {
                return None;
            }
            match crate::interceptor::process::lookup_outbound_socket_pid(protocol, local, remote) {
                Some(pid) if pid != 0 => {
                    table.record_resolved_pid(protocol, local.ip(), local.port(), pid);
                    Some(pid)
                }
                _ => {
                    table.record_negative_lookup(protocol, local.ip(), local.port());
                    None
                }
            }
        }
    }
}

fn shutdown_and_join_runtime(
    stop_flag: &AtomicBool,
    signal: &netstack::NetstackSignal,
    socket_handle: &windivert_ffi::WinDivertHandle,
    network_handle: &windivert_ffi::WinDivertHandle,
    dns_inspect_handle: &windivert_ffi::WinDivertHandle,
    threads: Vec<JoinHandle<()>>,
    dns_abort_handles: &Mutex<Vec<tokio::task::AbortHandle>>,
) {
    crate::outbound::bypass::set_transparent_active(false);
    stop_flag.store(true, Ordering::Release);
    signal.close();
    let _ = socket_handle.shutdown(windivert_ffi::WinDivertShutdownMode::Both);
    let _ = network_handle.shutdown(windivert_ffi::WinDivertShutdownMode::Both);
    // 先仅关闭入站 DNS 观测句柄的 Recv 方向，确保线程把已在驱动队列中截获的应答全部原样 send 重注入 OS 后自然退出
    let _ = dns_inspect_handle.shutdown(windivert_ffi::WinDivertShutdownMode::Recv);
    for th in threads {
        let _ = th.join();
    }
    let _ = dns_inspect_handle.shutdown(windivert_ffi::WinDivertShutdownMode::Both);
    let mut handles = dns_abort_handles.lock().unwrap_or_else(|e| e.into_inner());
    for h in handles.drain(..) {
        h.abort();
    }
}

/// 在打开 WinDivert 句柄前提前激活出站旁路注册标志，若建句柄阶段失败则自动复位（消除启动瞬间 TOCTOU 窗口）
struct TransparentActiveStartupGuard {
    armed: bool,
}

impl TransparentActiveStartupGuard {
    fn activate() -> Self {
        crate::outbound::bypass::set_transparent_active(true);
        Self { armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TransparentActiveStartupGuard {
    fn drop(&mut self) {
        if self.armed {
            crate::outbound::bypass::set_transparent_active(false);
        }
    }
}

/// 启动期原子回滚守卫：若任意子线程创建失败或发生 panic，确保已启动线程与 WinDivert 句柄全部回收
struct PartialRuntimeGuard {
    armed: bool,
    stop_flag: Arc<AtomicBool>,
    signal: Arc<netstack::NetstackSignal>,
    socket_handle: Arc<windivert_ffi::WinDivertHandle>,
    network_handle: Arc<windivert_ffi::WinDivertHandle>,
    dns_inspect_handle: Arc<windivert_ffi::WinDivertHandle>,
    threads: Vec<JoinHandle<()>>,
    dns_abort_handles: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
}

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
            &self.dns_inspect_handle,
            threads,
            &self.dns_abort_handles,
        );
    }
}

pub(super) struct ActiveRuntime {
    stop_flag: Arc<AtomicBool>,
    signal: Arc<netstack::NetstackSignal>,
    socket_handle: Arc<windivert_ffi::WinDivertHandle>,
    network_handle: Arc<windivert_ffi::WinDivertHandle>,
    dns_inspect_handle: Arc<windivert_ffi::WinDivertHandle>,
    threads: Vec<JoinHandle<()>>,
    dns_abort_handles: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
    pub(super) driver_version: Option<String>,
}

/// WinDivert NETWORK 层收包初始缓冲区（128 KiB > WINDIVERT_MTU_MAX 65575）与 LSO/巨包动态扩容上限（4 MiB）
pub(crate) const INITIAL_NET_RX_BUF_LEN: usize = 131_072;
pub(crate) const MAX_NET_RX_BUF_LEN: usize = 4 * 1024 * 1024;
const WINDOWS_ERROR_INSUFFICIENT_BUFFER: i32 = 122;

#[inline]
pub(crate) fn next_net_rx_buf_len(current: usize) -> Option<usize> {
    if current >= MAX_NET_RX_BUF_LEN {
        return None;
    }
    Some(
        current
            .saturating_mul(2)
            .clamp(INITIAL_NET_RX_BUF_LEN, MAX_NET_RX_BUF_LEN),
    )
}

/// WinDivert NETWORK 层过滤表达式：捕获全部出站非自环 TCP、UDP/53 DNS、UDP/443 QUIC、发往 Fake-IP (`198.18.0.0/15`) 的任意 UDP 以及全部 IPv4/IPv6 分片
pub(crate) fn windivert_network_filter() -> &'static str {
    "outbound and !loopback and !impostor and (tcp or udp.DstPort == 53 or udp.DstPort == 443 or (udp and ip and ip.DstAddr >= 198.18.0.0 and ip.DstAddr <= 198.19.255.255) or fragment)"
}

/// WinDivert NETWORK 层入站 `InspectDns` 同步观测过滤表达式（配合 `DNS_INSPECT_LAYER_FLAGS = 0` 内联拦截-重注入）：
/// WinDivert 2.2 在未设置 `WINDIVERT_FLAG_FRAGMENTS` 时默认在内核完成入站分片重组后交付完整 UDP/53 报文（覆盖大包 DNSSEC / EDNS0），
/// 同步落盘 `real_ip -> domain` 后再无条件原样重注入 OS，消除高并发下「入站 DNS 应答 vs 业务进程 TCP SYN」竞态且绝不触碰非 DNS 入站分片
pub(crate) fn windivert_dns_inspect_inbound_filter() -> &'static str {
    "inbound and !loopback and !impostor and udp.SrcPort == 53"
}

struct NetRxContext {
    stop_flag: Arc<AtomicBool>,
    net_h: Arc<windivert_ffi::WinDivertHandle>,
    table: Arc<pid_table::SocketPidTable>,
    sig: Arc<netstack::NetstackSignal>,
    dispatcher_cfg: Arc<DispatcherConfig>,
    dns_srv: Arc<DnsServer>,
    inspect_table: Arc<dns_hijack::PendingInspectDnsTable>,
    stats: Arc<TransparentStatsCounters>,
    live_dns: Arc<AtomicBool>,
    live_quic: Arc<AtomicBool>,
    rt: tokio::runtime::Handle,
    dns_abort_handles: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
}

impl NetRxContext {
    fn emit_passthrough(
        &self,
        raw: &[u8],
        addr: &windivert_ffi::WinDivertAddress,
        fallback_fragments: Option<&[netstack::EmittedIpPacket]>,
    ) {
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
            if crate::outbound::bypass::is_udp_port_bypassed_for_family(udp.src_port, udp.is_ipv6) {
                self.emit_passthrough(raw, addr, fallback_fragments);
                return true;
            }
            let local_ep = std::net::SocketAddr::new(udp.src_ip, udp.src_port);
            let remote_ep = std::net::SocketAddr::new(udp.dst_ip, udp.dst_port);
            let allow_os_fallback = matches!(udp.dst_port, 53 | 443);
            let pid = resolve_outbound_pid(&self.table, 17, local_ep, remote_ep, allow_os_fallback);
            let decision = dns_hijack::decide_udp_packet_with_if_idx(
                &udp,
                pid,
                self.live_dns.load(Ordering::Acquire),
                self.live_quic.load(Ordering::Acquire),
                Some(&self.dispatcher_cfg.rule_engine),
                Some(&self.dispatcher_cfg.tracker),
                Some(&self.dispatcher_cfg.fake_ip_pool),
                net_data.if_idx,
            );
            match decision {
                dns_hijack::UdpDecision::Passthrough => {
                    self.emit_passthrough(raw, addr, fallback_fragments);
                }
                dns_hijack::UdpDecision::DropQuic => {
                    self.stats
                        .quic_blocked_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                dns_hijack::UdpDecision::DropFakeIp => {}
                dns_hijack::UdpDecision::InspectDns => {
                    // 严格无侵入观测：登记出站查询后立即放行原包（保留 OS 原生 socket / VPN 接口绑定 / EDNS0 尺寸 / fe80:: scope_id），
                    // 由独立入站内联句柄（flags=0）在把应答重注入 OS 之前同步学习 real_ip -> domain，消除 DNS 应答与 TCP SYN 竞态。
                    self.inspect_table.record_outbound_query(
                        udp.src_ip,
                        udp.dst_ip,
                        udp.src_port,
                        udp.dst_port,
                        udp.payload,
                    );
                    self.emit_passthrough(raw, addr, fallback_fragments);
                }
                dns_hijack::UdpDecision::HandleDns => {
                    self.stats
                        .dns_hijacked_total
                        .fetch_add(1, Ordering::Relaxed);
                    let owned_payload = udp.payload.to_vec();
                    let req_meta = (
                        udp.src_ip,
                        udp.dst_ip,
                        udp.src_port,
                        udp.dst_port,
                        udp.is_ipv6,
                    );
                    let net_inj = Arc::downgrade(&self.net_h);
                    let stop = Arc::clone(&self.stop_flag);
                    let dns = Arc::clone(&self.dns_srv);
                    let loopback = addr.loopback();
                    let join_handle = self.rt.spawn(async move {
                        // 完整保留 IPv6 链路本地 DNS（fe80::）对应的接口索引 scope_id
                        let orig_dns_dst = match req_meta.1 {
                            std::net::IpAddr::V6(v6)
                                if v6.is_unicast_link_local() && net_data.if_idx != 0 =>
                            {
                                std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                                    v6,
                                    req_meta.3,
                                    0,
                                    net_data.if_idx,
                                ))
                            }
                            ip => std::net::SocketAddr::new(ip, req_meta.3),
                        };
                        let resp_payload = dns
                            .process_transparent_query_bytes(&owned_payload, orig_dns_dst)
                            .await;
                        if let Some(resp_payload) = resp_payload {
                            if stop.load(Ordering::Acquire) {
                                return;
                            }
                            let Some(net_inj) = net_inj.upgrade() else {
                                return;
                            };
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
                                let mut inj_addr =
                                    windivert_ffi::WinDivertAddress::inbound_injection(
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
                    let mut handles = self
                        .dns_abort_handles
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    handles.retain(|h| !h.is_finished());
                    handles.push(join_handle.abort_handle());
                }
            }
            return true;
        }

        if let Some(tcp) = netstack::parse_tcp_packet(raw) {
            if crate::outbound::bypass::is_tcp_port_bypassed_for_family(tcp.src_port, tcp.is_ipv6) {
                self.stats
                    .tcp_passthrough_total
                    .fetch_add(1, Ordering::Relaxed);
                self.emit_passthrough(raw, addr, fallback_fragments);
                return true;
            }
            let local_ep = std::net::SocketAddr::new(tcp.src_ip, tcp.src_port);
            let remote_ep = std::net::SocketAddr::new(tcp.dst_ip, tcp.dst_port);
            let pid =
                resolve_outbound_pid(&self.table, 6, local_ep, remote_ep, tcp.syn && !tcp.ack);
            if pid.is_some_and(pid_table::SocketPidTable::is_self_pid) {
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
            self.sig.push_outbound_tcp_with_fragments(
                raw.to_vec(),
                meta,
                pid,
                fallback_fragments.map(|frags| frags.to_vec()),
            );
            return true;
        }

        false
    }
}

pub(super) fn start_windivert_runtime(
    cfg: &TransparentSettings,
    rt_handle: &tokio::runtime::Handle,
    dispatcher_config: &Arc<DispatcherConfig>,
    dns_server: &Arc<DnsServer>,
    live_hijack_dns: &Arc<AtomicBool>,
    live_block_quic: &Arc<AtomicBool>,
    stats: &Arc<TransparentStatsCounters>,
) -> Result<ActiveRuntime, String> {
    if !is_process_elevated() {
        return Err(
            "ERR_TRANSPARENT_REQUIRES_ADMIN: Transparent proxy requires Administrator privileges to open WinDivert."
                .to_string(),
        );
    }

    let avail = windivert_ffi::locate_windivert_files(cfg.dll_path.as_deref());
    if !avail.dll_found || !avail.sys_found {
        let searched = if avail.searched_dirs.is_empty() {
            "executable directory".to_string()
        } else {
            avail.searched_dirs.join(", ")
        };
        return Err(format!(
            "ERR_TRANSPARENT_MISSING_DRIVER: Missing WinDivert.dll (found={}) or WinDivert64.sys (found={}). Place both files next to flowx.exe. Searched: {}",
            avail.dll_found, avail.sys_found, searched
        ));
    }

    let api = windivert_ffi::WinDivertApi::load(cfg.dll_path.as_deref())
        .map_err(|e| format!("ERR_TRANSPARENT_LOAD_FAILED: Failed to load WinDivert.dll: {e}"))?;

    // 在打开 WinDivert 句柄前即置位 transparent_active，消除并发出站连接/UDP DNS 跳过 BypassPortRegistry 登记的 TOCTOU 窗口
    let mut active_startup_guard = TransparentActiveStartupGuard::activate();

    let socket_filter = "(tcp or udp) and (event == BIND or event == CONNECT or event == LISTEN or event == ACCEPT or event == CLOSE)";
    let socket_handle = Arc::new(
        windivert_ffi::WinDivertHandle::open(
            Arc::clone(&api),
            socket_filter,
            windivert_ffi::WinDivertLayer::Socket,
            0,
            windivert_ffi::SOCKET_LAYER_FLAGS,
        )
        .map_err(|e| format!("ERR_TRANSPARENT_OPEN_SOCKET_LAYER: {e}"))?,
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
        .map_err(|e| format!("ERR_TRANSPARENT_OPEN_NETWORK_LAYER: {e}"))?,
    );

    let dns_inspect_filter = windivert_dns_inspect_inbound_filter();
    // 使用 priority = 10（高于 network_handle 的 0），避免 HandleDns 注入的入站 Fake-IP 应答反复命中本句柄；
    // 使用 DNS_INSPECT_LAYER_FLAGS (0) 内联拦截-重注入，在把包交回 OS 之前同步落盘 real_ip -> domain。
    let dns_inspect_handle = Arc::new(
        windivert_ffi::WinDivertHandle::open(
            Arc::clone(&api),
            dns_inspect_filter,
            windivert_ffi::WinDivertLayer::Network,
            10,
            windivert_ffi::DNS_INSPECT_LAYER_FLAGS,
        )
        .map_err(|e| format!("ERR_TRANSPARENT_OPEN_NETWORK_LAYER: {e}"))?,
    );

    for handle in [&network_handle, &dns_inspect_handle] {
        let _ = handle.set_param(
            windivert_ffi::WinDivertParam::QueueLength,
            windivert_ffi::WINDIVERT_PARAM_QUEUE_LENGTH_MAX,
        );
        let _ = handle.set_param(
            windivert_ffi::WinDivertParam::QueueTime,
            windivert_ffi::WINDIVERT_PARAM_QUEUE_TIME_DEFAULT,
        );
        let _ = handle.set_param(windivert_ffi::WinDivertParam::QueueSize, 16_777_216);
    }

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
    let dns_abort_handles = Arc::new(Mutex::new(Vec::new()));
    let inspect_table = Arc::new(dns_hijack::PendingInspectDnsTable::new());

    let mut startup_guard = PartialRuntimeGuard {
        armed: true,
        stop_flag: Arc::clone(&stop_flag),
        signal: Arc::clone(&signal),
        socket_handle: Arc::clone(&socket_handle),
        network_handle: Arc::clone(&network_handle),
        dns_inspect_handle: Arc::clone(&dns_inspect_handle),
        threads: Vec::with_capacity(4),
        dns_abort_handles: Arc::clone(&dns_abort_handles),
    };
    // PartialRuntimeGuard 接管失败回滚时复位 transparent_active 的职责
    active_startup_guard.disarm();

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
                            let Some(event) = windivert_ffi::WinDivertEvent::from_u8(addr.event())
                            else {
                                continue;
                            };
                            let s = addr.socket_data();
                            let local_ip =
                                windivert_ffi::decode_windivert_addr(&s.local_addr, addr.ipv6());
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
            .map_err(|e| format!("Failed to spawn socket monitor thread: {e}"))?;
        startup_guard.threads.push(handle);
    }

    // 2. NETWORK 层抓包线程：快速分流自环放行 / UDP(DNS & QUIC) / TCP 入协议栈，并对分片包实行有界重组防渗透
    {
        let stop = Arc::clone(&stop_flag);
        let ctx = NetRxContext {
            stop_flag: Arc::clone(&stop_flag),
            net_h: Arc::clone(&network_handle),
            table: Arc::clone(&pid_table),
            sig: Arc::clone(&signal),
            dispatcher_cfg: Arc::clone(dispatcher_config),
            dns_srv: Arc::clone(dns_server),
            inspect_table: Arc::clone(&inspect_table),
            stats: Arc::clone(stats),
            live_dns: Arc::clone(live_hijack_dns),
            live_quic: Arc::clone(live_block_quic),
            rt: rt_handle.clone(),
            dns_abort_handles: Arc::clone(&dns_abort_handles),
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
                        fragment::FragmentOutcome::PassthroughGroup(orig_fragments) => {
                            ctx.emit_passthrough(&[], &addr, Some(&orig_fragments));
                        }
                        fragment::FragmentOutcome::Drop | fragment::FragmentOutcome::Pending => {}
                        fragment::FragmentOutcome::Reassembled {
                            full_packet,
                            orig_fragments,
                        } => {
                            let rep_meta = orig_fragments
                                .first()
                                .map(|f| f.meta)
                                .unwrap_or(frag_meta);
                            let reasm_addr = windivert_ffi::WinDivertAddress::outbound_passthrough(
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
            .map_err(|e| format!("Failed to spawn network recv thread: {e}"))?;
        startup_guard.threads.push(handle);
    }

    // 2b. 入站同步 DNS 应答观测线程（内联拦截-落盘-重注入）：依赖 WinDivert 2.2 flags=0 原生重组覆盖大包 EDNS0/DNSSEC，
    //     先同步学习 real_ip -> domain 再无条件原样重注入 OS；停机时仅关闭 Recv 方向直至排空全部排队应答再退出
    {
        let stop = Arc::clone(&stop_flag);
        let sniff_h = Arc::clone(&dns_inspect_handle);
        let inspect_tbl = Arc::clone(&inspect_table);
        let fake_ip_pool = Arc::clone(&dispatcher_config.fake_ip_pool);
        let handle = std::thread::Builder::new()
            .name("flowx-windivert-dns-sniff".to_string())
            .spawn(move || {
                let mut buf = vec![0u8; INITIAL_NET_RX_BUF_LEN];
                loop {
                    let (len, addr) = match sniff_h.recv(&mut buf) {
                        Ok(res) => res,
                        Err(e) => {
                            if matches!(e.raw_os_error(), Some(6 | 232 | 995)) {
                                break;
                            }
                            if e.raw_os_error() == Some(WINDOWS_ERROR_INSUFFICIENT_BUFFER)
                                && let Some(next_len) = next_net_rx_buf_len(buf.len())
                            {
                                buf.resize(next_len, 0);
                                continue;
                            }
                            if stop.load(Ordering::Acquire) {
                                break;
                            }
                            debug!(error = %e, "WinDivert inbound DNS observer recv transient error");
                            std::thread::yield_now();
                            continue;
                        }
                    };
                    if len == 0 {
                        continue;
                    }
                    let raw = &buf[..len];
                    let _ = dns_hijack::observe_inbound_dns_packet_for_inspect(
                        raw,
                        &inspect_tbl,
                        &fake_ip_pool,
                    );
                    // 无论是否命中观测表，都在观测完成后无条件原样重注入 OS，并记录重注入异常
                    if let Err(e) = sniff_h.send(raw, &addr) {
                        warn!(
                            error = %e,
                            packet_len = raw.len(),
                            "Failed to reinject observed inbound DNS response packet"
                        );
                    }
                }
            })
            .map_err(|e| format!("Failed to spawn inbound DNS observer thread: {e}"))?;
        startup_guard.threads.push(handle);
    }

    // 3. 用户态协议栈 Actor 线程：单所有权运行 smoltcp 并协调 AsyncRead/AsyncWrite 与入站注入
    {
        let stop = Arc::clone(&stop_flag);
        let net_h = Arc::clone(&network_handle);
        let sig = Arc::clone(&signal);
        let dispatcher_cfg = Arc::clone(dispatcher_config);
        let stats_clone = Arc::clone(stats);
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
                    let alive =
                        sig.wait_drain_or_timeout(wait_budget, &mut batch, &mut closed_endpoints);
                    if !alive || stop.load(Ordering::Acquire) {
                        break;
                    }

                    for (local_ip, local_port) in closed_endpoints.drain(..) {
                        engine.invalidate_passthrough_for_local_endpoint(local_ip, local_port);
                    }

                    for netstack::OutboundTcpQueueItem {
                        raw_ip,
                        meta,
                        pid,
                        orig_fragments,
                    } in batch.drain(..)
                    {
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
                                stats_clone
                                    .tcp_passthrough_total
                                    .fetch_add(1, Ordering::Relaxed);
                                for passthru_pkt in
                                    netstack::select_passthrough_packets(pkt, orig_fragments)
                                {
                                    let passthru_addr =
                                        windivert_ffi::WinDivertAddress::outbound_passthrough(
                                            passthru_pkt.meta.if_idx,
                                            passthru_pkt.meta.sub_if_idx,
                                            passthru_pkt.meta.bitfield,
                                        );
                                    let _ = net_h.send(&passthru_pkt.data, &passthru_addr);
                                }
                            }
                            netstack::TcpIngestOutcome::InjectRst(mut rst_pkt) => {
                                stats_clone
                                    .tcp_blocked_rst_total
                                    .fetch_add(1, Ordering::Relaxed);
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
                        stats_clone
                            .tcp_intercepted_total
                            .fetch_add(1, Ordering::Relaxed);
                        let dcfg = Arc::clone(&dispatcher_cfg);
                        let spawn_in_flight = dcfg.in_flight.as_ref().map(|t| t.enter());
                        rt.spawn(async move {
                            let _spawn_in_flight = spawn_in_flight;
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
                                warn!(
                                    orig_dst = %flow.orig_dst,
                                    error = %format!("{e:#}"),
                                    "Transparent TCP stream finished with error"
                                );
                            }
                        });
                    }

                    wait_budget = engine.pump(&mut tx_packets);
                    stats_clone
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
                engine.abort_all_sessions();
                stats_clone.active_flows.store(0, Ordering::Relaxed);
            })
            .map_err(|e| format!("Failed to spawn netstack actor thread: {e}"))?;
        startup_guard.threads.push(handle);
    }

    startup_guard.armed = false;
    let threads = std::mem::take(&mut startup_guard.threads);

    info!(
        loaded_from = %api.loaded_from(),
        driver_version = driver_version.as_deref().unwrap_or("unknown"),
        "Transparent proxy started via WinDivert"
    );

    Ok(ActiveRuntime {
        stop_flag,
        signal,
        socket_handle,
        network_handle,
        dns_inspect_handle,
        threads,
        dns_abort_handles,
        driver_version,
    })
}

pub(super) fn stop_windivert_runtime(rt: ActiveRuntime, stats: &TransparentStatsCounters) {
    shutdown_and_join_runtime(
        &rt.stop_flag,
        &rt.signal,
        &rt.socket_handle,
        &rt.network_handle,
        &rt.dns_inspect_handle,
        rt.threads,
        &rt.dns_abort_handles,
    );
    drop(rt.socket_handle);
    drop(rt.network_handle);
    drop(rt.dns_inspect_handle);
    stats.active_flows.store(0, Ordering::Relaxed);
    crate::interceptor::dispatcher::clear_server_first_endpoint_cache();

    if let Err(e) = flush_dns_cache() {
        warn!(error = %e, "Failed to flush Windows DNS cache while stopping transparent mode");
    }
    info!("Transparent proxy stopped cleanly and DNS cache flushed");
}
