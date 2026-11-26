mod bridge;
mod packet;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::Waker;
use std::time::{Duration, Instant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{self, SocketBuffer};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpListenEndpoint, Ipv4Address, Ipv6Address};

use crate::dns::FakeIpPool;
use crate::interceptor::process::ProcessTracker;
use crate::outbound::bypass::is_tcp_port_bypassed_for_family;
use crate::router::{Action, DomainNeedDecision, RuleEngine};

pub use bridge::{NetstackSignal, SmoltcpReadHalf, SmoltcpStream, SmoltcpWriteHalf};
pub use packet::{
    EmittedIpPacket, OutboundTcpQueueItem, PacketInterfaceMeta, ParsedTcpPacket, TcpFlowKey,
    build_synthetic_tcp_rst, parse_tcp_packet, select_passthrough_packets,
};

use bridge::{
    BRIDGE_BUFFER_LIMIT, SmoltcpBridge, VirtualIpDevice, close_bridge_and_collect_wakers,
};
use packet::enqueue_tcp_for_smoltcp;

const SMOLTCP_RX_BUF: usize = 128 * 1024;
const SMOLTCP_TX_BUF: usize = 128 * 1024;
const MAX_INTERCEPTED_FLOWS: usize = 4096;
const MAX_PASSTHROUGH_FLOWS: usize = 16_384;
const PASSTHROUGH_TTL: Duration = Duration::from_secs(120);
const SYN_RECEIVED_TIMEOUT: Duration = Duration::from_secs(15);
const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const TIME_WAIT_REAP_TIMEOUT: Duration = Duration::from_secs(2);

/// 已进入 `smoltcp` 的新连接上下文，交由异步调度器执行域名嗅探或直连/代理转发
pub struct AcceptedTcpFlow {
    pub stream: SmoltcpStream,
    pub peer_addr: SocketAddr,
    pub orig_dst: SocketAddr,
    pub pid_hint: Option<u32>,
    pub needs_domain_sniff: bool,
}

#[derive(Debug)]
pub enum TcpIngestOutcome {
    Intercepted,
    Passthrough(EmittedIpPacket),
    InjectRst(EmittedIpPacket),
}

#[derive(Debug, Clone, Copy)]
struct PassthroughEntry {
    last_seen: Instant,
    syn_seq: Option<u32>,
}

struct InterceptedSession {
    handle: SocketHandle,
    bridge: Arc<SmoltcpBridge>,
    meta: PacketInterfaceMeta,
    created_at: Instant,
    syn_seq: u32,
    ever_established: bool,
    last_state: tcp::State,
    teardown_since: Option<Instant>,
    time_wait_since: Option<Instant>,
}

/// 单所有权用户态 TCP/IP 协议栈引擎：负责四元组流分拣、孤立 Listen 握手防碰撞、双向缓冲泵送及异常连接清理
pub struct NetstackEngine {
    iface: Interface,
    device: VirtualIpDevice,
    sockets: SocketSet<'static>,
    intercepted: HashMap<TcpFlowKey, InterceptedSession>,
    passthrough: HashMap<TcpFlowKey, PassthroughEntry>,
    signal: Arc<NetstackSignal>,
    start_instant: Instant,
    last_prune: Instant,
}

impl NetstackEngine {
    pub fn new(signal: Arc<NetstackSignal>) -> Self {
        let mut device = VirtualIpDevice::new();
        let now_std = Instant::now();
        let now = SmolInstant::from_millis(0);
        let mut cfg = Config::new(HardwareAddress::Ip);
        cfg.random_seed =
            (std::process::id() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xA5A5_5A5A;

        let mut iface = Interface::new(cfg, &mut device, now);
        iface.set_any_ip(true);
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1));
        let _ = iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));

        Self {
            iface,
            device,
            sockets: SocketSet::new(vec![]),
            intercepted: HashMap::new(),
            passthrough: HashMap::new(),
            signal,
            start_instant: now_std,
            last_prune: now_std,
        }
    }

    pub fn signal(&self) -> &Arc<NetstackSignal> {
        &self.signal
    }

    pub fn active_flow_count(&self) -> usize {
        self.intercepted.len()
    }

    #[inline]
    fn smol_now(&self) -> SmolInstant {
        let elapsed_ms = self.start_instant.elapsed().as_millis();
        let clamped = i64::try_from(elapsed_ms).unwrap_or(i64::MAX / 2);
        SmolInstant::from_millis(clamped)
    }

    fn maybe_prune_passthrough(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_prune) < Duration::from_secs(10)
            && self.passthrough.len() <= MAX_PASSTHROUGH_FLOWS
        {
            return;
        }
        self.last_prune = now;
        self.passthrough
            .retain(|_, entry| now.saturating_duration_since(entry.last_seen) <= PASSTHROUGH_TTL);
        if self.passthrough.len() > MAX_PASSTHROUGH_FLOWS {
            let mut items: Vec<_> = self
                .passthrough
                .iter()
                .map(|(k, v)| (*k, v.last_seen))
                .collect();
            items.sort_unstable_by_key(|(_, ts)| *ts);
            let remove_cnt = self
                .passthrough
                .len()
                .saturating_sub(MAX_PASSTHROUGH_FLOWS * 3 / 4);
            for (k, _) in items.into_iter().take(remove_cnt) {
                self.passthrough.remove(&k);
            }
        }
    }

    /// 当 SOCKET 层上报本地 TCP 端点关闭时，立即失效关联的直连旁路缓存以防止同端口复用穿透规则
    pub fn invalidate_passthrough_for_local_endpoint(&mut self, local_ip: IpAddr, local_port: u16) {
        if local_port == 0 {
            return;
        }
        let canonical = local_ip.to_canonical();
        let wildcard = canonical.is_unspecified();
        self.passthrough.retain(|key, _| {
            if key.src_port != local_port {
                return true;
            }
            if wildcard {
                return false;
            }
            match (key.src_ip, canonical) {
                (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                    key.src_ip != canonical
                }
                _ => true,
            }
        });
    }

    /// 四元组复用时静默移除退场中的旧劫持会话，不向宿主注入额外 RST 以免误伤刚刚发起的新连接
    fn retire_session_silently(&mut self, key: TcpFlowKey) {
        let Some(old_sess) = self.intercepted.remove(&key) else {
            return;
        };
        let mut wake_read = None;
        let mut wake_write = None;
        let mut wake_flush = None;
        {
            let mut inner = old_sess
                .bridge
                .inner
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            close_bridge_and_collect_wakers(
                &mut inner,
                false,
                &mut wake_read,
                &mut wake_write,
                &mut wake_flush,
            );
        }
        self.sockets.remove(old_sess.handle);
        if let Some(w) = wake_read {
            w.wake();
        }
        if let Some(w) = wake_write {
            w.wake();
        }
        if let Some(w) = wake_flush {
            w.wake();
        }
    }

    /// 处理一条从 WinDivert NETWORK 层截获的出站 TCP 原始 IP 报文，并返回需注入、放行或合成 RST 的结果
    #[allow(clippy::too_many_arguments)]
    pub fn ingest_outbound_tcp(
        &mut self,
        raw_ip: Vec<u8>,
        meta: PacketInterfaceMeta,
        pid: Option<u32>,
        rule_engine: Option<&RuleEngine>,
        tracker: Option<&ProcessTracker>,
        fake_ip_pool: Option<&FakeIpPool>,
        accepted_out: &mut Vec<AcceptedTcpFlow>,
        tx_out: &mut Vec<EmittedIpPacket>,
    ) -> TcpIngestOutcome {
        let Some(pkt) = parse_tcp_packet(&raw_ip) else {
            return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
        };

        let key = pkt.flow_key();
        let now = Instant::now();
        self.maybe_prune_passthrough(now);

        // 1. 最先检查 FlowX 自身同地址族绕过端口或当前进程 PID，避免代理出口自回环
        if is_tcp_port_bypassed_for_family(pkt.src_port, pkt.is_ipv6)
            || pid.is_some_and(|p| p != 0 && p == std::process::id())
        {
            if pkt.rst {
                self.passthrough.remove(&key);
            } else {
                self.passthrough.insert(
                    key,
                    PassthroughEntry {
                        last_seen: now,
                        syn_seq: (pkt.syn && !pkt.ack).then_some(pkt.seq),
                    },
                );
            }
            return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
        }

        // 2. 属于已登记劫持会话的后续报文（ACK / PSH / FIN / RST）：直接送入 smoltcp；
        //    若旧会话已在挥手退场且迎来不同 ISN 的全新 SYN，则静默退休旧会话让位给新连接
        let mut retire_old_session = false;
        if let Some(session) = self.intercepted.get_mut(&key) {
            let state = self.sockets.get::<tcp::Socket>(session.handle).state();
            if pkt.syn
                && !pkt.ack
                && pkt.seq != session.syn_seq
                && matches!(
                    state,
                    tcp::State::Listen
                        | tcp::State::FinWait1
                        | tcp::State::FinWait2
                        | tcp::State::Closing
                        | tcp::State::LastAck
                        | tcp::State::TimeWait
                        | tcp::State::Closed
                )
            {
                retire_old_session = true;
            } else {
                session.meta = meta;
                enqueue_tcp_for_smoltcp(&mut self.device.rx_queue, raw_ip);
                self.pump_internal(now, tx_out);
                return TcpIngestOutcome::Intercepted;
            }
        }
        if retire_old_session {
            self.retire_session_silently(key);
        }

        // 3. 属于已缓存直连流或开启前已建立的存量连接（非 SYN 首包）：绝不强行劫持，平滑放行；
        //    若遭遇 RST 或不同 seq 的全新 SYN（四元组快速复用），立即失效旧旁路缓存并重走规则判断
        if let Some(entry) = self.passthrough.get_mut(&key) {
            if pkt.rst {
                self.passthrough.remove(&key);
                return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
            }
            if pkt.syn && !pkt.ack {
                if entry.syn_seq == Some(pkt.seq) {
                    entry.last_seen = now;
                    return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
                }
                self.passthrough.remove(&key);
            } else {
                entry.last_seen = now;
                return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
            }
        }
        if !pkt.syn || pkt.ack {
            return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
        }

        let insert_syn_passthrough = |passthrough: &mut HashMap<TcpFlowKey, PassthroughEntry>| {
            passthrough.insert(
                key,
                PassthroughEntry {
                    last_seen: now,
                    syn_seq: Some(pkt.seq),
                },
            );
        };

        // 4. 忽略未指定/多播/广播目标
        let is_broadcast = matches!(pkt.dst_ip, IpAddr::V4(v4) if v4.is_broadcast());
        if pkt.dst_ip.is_multicast() || pkt.dst_ip.is_unspecified() || is_broadcast {
            insert_syn_passthrough(&mut self.passthrough);
            return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
        }

        // 5. 全新 SYN 首包路由裁决
        let is_fake_ip = fake_ip_pool.is_some_and(|pool| pool.is_fake_ip_addr(pkt.dst_ip));
        let needs_domain_sniff = if is_fake_ip {
            // Fake-IP 在 DNS 阶段已绑定真实域名；由 Dispatcher 还原域名后立即走规则裁决，不空等 120ms 嗅探
            false
        } else if let Some(re) = rule_engine {
            let proc_info = pid.and_then(|p| tracker.and_then(|t| t.resolve_pid(p)));
            let proc_unresolved = pid.is_none() || (tracker.is_some() && proc_info.is_none());
            let proc_path = proc_info.as_ref().map(|i| i.path.as_str());
            let proc_name = proc_info.as_ref().map(|i| i.name.as_str());
            match re.needs_domain_for_routing(proc_path, proc_name, Some(pkt.dst_ip), pkt.dst_port)
            {
                DomainNeedDecision::Immediate(Action::Direct) => {
                    if proc_unresolved
                        && re.has_reachable_app_scoped_override(Some(pkt.dst_ip), pkt.dst_port)
                    {
                        // 首包阶段 PID 或进程名解析缺失但前方存在应用级非 Direct 规则（如 DevProxy）：接入协议栈交由 Dispatcher 异步复核进程归属，绝不盲目永久旁路
                        false
                    } else {
                        insert_syn_passthrough(&mut self.passthrough);
                        return TcpIngestOutcome::Passthrough(EmittedIpPacket {
                            data: raw_ip,
                            meta,
                        });
                    }
                }
                DomainNeedDecision::Immediate(Action::Block) => {
                    if let Some(rst) = build_synthetic_tcp_rst(&raw_ip) {
                        return TcpIngestOutcome::InjectRst(EmittedIpPacket { data: rst, meta });
                    }
                    return TcpIngestOutcome::Intercepted;
                }
                DomainNeedDecision::Immediate(Action::Proxy(_) | Action::Chain(_)) => false,
                DomainNeedDecision::NeedsDomainSniff => true,
            }
        } else {
            // 测试或无规则引擎时的安全回退：接入用户态协议栈
            false
        };

        if self.intercepted.len() >= MAX_INTERCEPTED_FLOWS {
            if let Some(rst) = build_synthetic_tcp_rst(&raw_ip) {
                return TcpIngestOutcome::InjectRst(EmittedIpPacket { data: rst, meta });
            }
            insert_syn_passthrough(&mut self.passthrough);
            return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
        }

        // 6. 原子 Listen + 单 SYN 入队并立即 poll，确保 SocketSet 中绝不残留重叠的 Listen 句柄
        let mut sock = tcp::Socket::new(
            SocketBuffer::new(vec![0u8; SMOLTCP_RX_BUF]),
            SocketBuffer::new(vec![0u8; SMOLTCP_TX_BUF]),
        );
        let listen_ep = IpListenEndpoint {
            addr: Some(IpAddress::from(pkt.dst_ip)),
            port: pkt.dst_port,
        };
        if sock.listen(listen_ep).is_err() {
            insert_syn_passthrough(&mut self.passthrough);
            return TcpIngestOutcome::Passthrough(EmittedIpPacket { data: raw_ip, meta });
        }
        let handle = self.sockets.add(sock);
        let syn_backup = raw_ip.clone();
        enqueue_tcp_for_smoltcp(&mut self.device.rx_queue, raw_ip);

        let smol_now = self.smol_now();
        self.iface
            .poll(smol_now, &mut self.device, &mut self.sockets);

        let post_state = self.sockets.get::<tcp::Socket>(handle).state();
        if post_state == tcp::State::Listen {
            // SYN 未能被 smoltcp 接受：立即清理并用原 SYN 退回 Passthrough（同时按四元组冲刷并发 TX），严禁静默吞包
            self.sockets.remove(handle);
            self.drain_tx_with_lookup(meta, tx_out);
            insert_syn_passthrough(&mut self.passthrough);
            return TcpIngestOutcome::Passthrough(EmittedIpPacket {
                data: syn_backup,
                meta,
            });
        }

        let bridge = Arc::new(SmoltcpBridge::new(Arc::clone(&self.signal)));
        let stream = SmoltcpStream::from_bridge(Arc::clone(&bridge));
        self.intercepted.insert(
            key,
            InterceptedSession {
                handle,
                bridge,
                meta,
                created_at: now,
                syn_seq: pkt.seq,
                ever_established: matches!(post_state, tcp::State::Established),
                last_state: post_state,
                teardown_since: None,
                time_wait_since: None,
            },
        );
        self.drain_tx_with_lookup(meta, tx_out);

        accepted_out.push(AcceptedTcpFlow {
            stream,
            peer_addr: key.local_addr(),
            orig_dst: key.orig_dst(),
            pid_hint: pid,
            needs_domain_sniff,
        });

        TcpIngestOutcome::Intercepted
    }

    /// 推送双向桥接缓冲与 smoltcp 定时器/发送队列，返回下一次建议等待的最大时间
    pub fn pump(&mut self, tx_out: &mut Vec<EmittedIpPacket>) -> Duration {
        let now = Instant::now();
        self.maybe_prune_passthrough(now);
        self.pump_internal(now, tx_out);

        let smol_now = self.smol_now();
        match self.iface.poll_delay(smol_now, &self.sockets) {
            Some(d) => Duration::from_millis(d.total_millis())
                .clamp(Duration::from_millis(1), Duration::from_millis(50)),
            None => Duration::from_millis(50),
        }
    }

    fn pump_internal(&mut self, now: Instant, tx_out: &mut Vec<EmittedIpPacket>) {
        // 先行运行一轮 poll 消化可能尚在 rx_queue 的控制包
        let smol_now = self.smol_now();
        self.iface
            .poll(smol_now, &mut self.device, &mut self.sockets);

        let mut closed_keys = Vec::new();
        let mut temp_rx = [0u8; 16 * 1024];

        for (&key, session) in self.intercepted.iter_mut() {
            let sock = self.sockets.get_mut::<tcp::Socket>(session.handle);
            let state = sock.state();
            if matches!(
                state,
                tcp::State::Established
                    | tcp::State::CloseWait
                    | tcp::State::FinWait1
                    | tcp::State::FinWait2
            ) {
                session.ever_established = true;
            }

            let mut wake_read: Option<Waker> = None;
            let mut wake_write: Option<Waker> = None;
            let mut wake_flush: Option<Waker> = None;
            let mut remove_session = false;

            {
                let mut inner = session
                    .bridge
                    .inner
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());

                // A. socket -> to_app（先消费缓冲区残余数据）
                if !inner.app_read_closed {
                    while sock.can_recv() && inner.to_app.len() < BRIDGE_BUFFER_LIMIT {
                        let room = BRIDGE_BUFFER_LIMIT - inner.to_app.len();
                        let max_read = room.min(temp_rx.len());
                        match sock.recv_slice(&mut temp_rx[..max_read]) {
                            Ok(n) if n > 0 => {
                                inner.to_app.extend(&temp_rx[..n]);
                                if wake_read.is_none() {
                                    wake_read = inner.read_waker.take();
                                }
                            }
                            _ => break,
                        }
                    }
                }

                // F0. Closed 或 SynReceived 遭 RST 退回的 Listen 均表示连接已终止，
                //     必须先于 Step B 处理以免误标干净 EOF 并杜绝僵尸 Listen 槽位劫持后续连接
                if matches!(state, tcp::State::Closed | tcp::State::Listen) {
                    let non_graceful_closed = state == tcp::State::Listen
                        || !matches!(
                            session.last_state,
                            tcp::State::TimeWait
                                | tcp::State::LastAck
                                | tcp::State::Closing
                                | tcp::State::Closed
                        );
                    close_bridge_and_collect_wakers(
                        &mut inner,
                        non_graceful_closed,
                        &mut wake_read,
                        &mut wake_write,
                        &mut wake_flush,
                    );
                    remove_session = true;
                } else {
                    // B. 检测远端（本地应用）是否已发送正常 FIN：
                    //    smoltcp 的 may_recv() 在三次握手尚未完成的 SynReceived 态也返回 false，
                    //    必须要求 session.ever_established 为真才判定远端已发送 FIN，避免首包即误判 EOF。
                    if session.ever_established
                        && !sock.may_recv()
                        && !sock.can_recv()
                        && !inner.socket_eof_to_app
                    {
                        inner.socket_eof_to_app = true;
                        if wake_read.is_none() {
                            wake_read = inner.read_waker.take();
                        }
                    }

                    // C. to_socket -> socket
                    while !inner.to_socket.is_empty() && sock.can_send() {
                        let (head, _) = inner.to_socket.as_slices();
                        if head.is_empty() {
                            break;
                        }
                        match sock.send_slice(head) {
                            Ok(n) if n > 0 => {
                                inner.to_socket.drain(..n);
                                if inner.to_socket.len() < BRIDGE_BUFFER_LIMIT
                                    && wake_write.is_none()
                                {
                                    wake_write = inner.write_waker.take();
                                }
                            }
                            _ => break,
                        }
                    }

                    // E. 非优雅关闭中止检查（先于 Step D！）：双端句柄均已丢弃且未完成优雅 shutdown / 未发 FIN 时立刻 abort 发 RST 并释放槽位
                    let ungraceful_drop = inner.app_read_closed
                        && inner.write_half_dropped
                        && !inner.graceful_shutdown
                        && !inner.fin_sent_to_socket;
                    let syn_timed_out = !session.ever_established
                        && state == tcp::State::SynReceived
                        && now.saturating_duration_since(session.created_at)
                            >= SYN_RECEIVED_TIMEOUT;

                    if ungraceful_drop || syn_timed_out {
                        sock.abort();
                        close_bridge_and_collect_wakers(
                            &mut inner,
                            true,
                            &mut wake_read,
                            &mut wake_write,
                            &mut wake_flush,
                        );
                        remove_session = true;
                    } else {
                        // D. 优雅半关闭写端：待 `to_socket` 完全冲刷入 smoltcp 后触发 TCP FIN
                        if inner.app_write_closed
                            && inner.to_socket.is_empty()
                            && !inner.fin_sent_to_socket
                        {
                            sock.close();
                            inner.fin_sent_to_socket = true;
                        }

                        if inner.to_socket.is_empty() && inner.flush_waker.is_some() {
                            wake_flush = inner.flush_waker.take();
                        }

                        // F1. 收割长期滞留的 FinWait1/FinWait2/Closing/LastAck/TimeWait 半关连接，防止 4096 槽位耗尽
                        if state == tcp::State::TimeWait {
                            session.teardown_since = None;
                            let tw_since = *session.time_wait_since.get_or_insert(now);
                            if now.saturating_duration_since(tw_since) >= TIME_WAIT_REAP_TIMEOUT {
                                close_bridge_and_collect_wakers(
                                    &mut inner,
                                    false,
                                    &mut wake_read,
                                    &mut wake_write,
                                    &mut wake_flush,
                                );
                                remove_session = true;
                            }
                        } else if (matches!(state, tcp::State::FinWait1 | tcp::State::FinWait2)
                            && inner.app_read_closed
                            && inner.app_write_closed)
                            || matches!(state, tcp::State::Closing | tcp::State::LastAck)
                        {
                            session.time_wait_since = None;
                            let td_since = *session.teardown_since.get_or_insert(now);
                            if now.saturating_duration_since(td_since) >= TEARDOWN_TIMEOUT {
                                sock.abort();
                                close_bridge_and_collect_wakers(
                                    &mut inner,
                                    true,
                                    &mut wake_read,
                                    &mut wake_write,
                                    &mut wake_flush,
                                );
                                remove_session = true;
                            }
                        } else {
                            session.teardown_since = None;
                            session.time_wait_since = None;
                        }
                    }
                }
            }

            if let Some(w) = wake_read {
                w.wake();
            }
            if let Some(w) = wake_write {
                w.wake();
            }
            if let Some(w) = wake_flush {
                w.wake();
            }
            if remove_session {
                closed_keys.push(key);
            }
        }

        // 第二轮 poll：立即将刚写入 smoltcp 发送队列或 close()/abort() FIN/RST 发成 IP 包吐出
        let smol_now = self.smol_now();
        self.iface
            .poll(smol_now, &mut self.device, &mut self.sockets);
        self.drain_tx_with_lookup(PacketInterfaceMeta::default(), tx_out);

        for key in closed_keys {
            if let Some(sess) = self.intercepted.remove(&key) {
                self.sockets.remove(sess.handle);
            }
        }
        for session in self.intercepted.values_mut() {
            session.last_state = self.sockets.get::<tcp::Socket>(session.handle).state();
        }
    }

    /// 精确为每一条由 `smoltcp` 吐出的入站注入报文还原来源四元组所属的网络接口元数据
    fn drain_tx_with_lookup(
        &mut self,
        fallback_meta: PacketInterfaceMeta,
        tx_out: &mut Vec<EmittedIpPacket>,
    ) {
        while let Some(pkt) = self.device.tx_queue.pop_front() {
            let meta = if let Some(parsed) = parse_tcp_packet(&pkt) {
                // TX 报文的源地址是远端目标，目的地址是本地应用，反转查回原出站四元组
                let lookup_key = TcpFlowKey::new(
                    parsed.dst_ip,
                    parsed.dst_port,
                    parsed.src_ip,
                    parsed.src_port,
                );
                self.intercepted
                    .get(&lookup_key)
                    .map(|s| s.meta)
                    .unwrap_or(PacketInterfaceMeta {
                        is_ipv6: parsed.is_ipv6,
                        ..fallback_meta
                    })
            } else {
                fallback_meta
            };
            tx_out.push(EmittedIpPacket { data: pkt, meta });
        }
    }

    /// 停机或协议栈卸载时立即关闭并唤醒全部活跃/半关闭透明连接，防止调度协程阻塞直至 120s 空闲超时
    pub fn abort_all_sessions(&mut self) {
        let drained: Vec<_> = self.intercepted.drain().map(|(_, sess)| sess).collect();
        for session in drained {
            let _ = self.sockets.remove(session.handle);
            let mut wake_read: Option<Waker> = None;
            let mut wake_write: Option<Waker> = None;
            let mut wake_flush: Option<Waker> = None;
            {
                let mut inner = session
                    .bridge
                    .inner
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                close_bridge_and_collect_wakers(
                    &mut inner,
                    true,
                    &mut wake_read,
                    &mut wake_write,
                    &mut wake_flush,
                );
            }
            if let Some(w) = wake_read {
                w.wake();
            }
            if let Some(w) = wake_write {
                w.wake();
            }
            if let Some(w) = wake_flush {
                w.wake();
            }
        }
    }
}

impl Drop for NetstackEngine {
    fn drop(&mut self) {
        self.abort_all_sessions();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::RelayStream;
    use etherparse::{PacketBuilder, SlicedPacket, TcpHeader, TransportSlice};
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::outbound::bypass::{BypassProtocol, register_bypass_port};
    use crate::router::Rule;

    fn build_syn(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, seq: u32) -> Vec<u8> {
        let mut hdr = TcpHeader::new(sport, dport, seq, 65535);
        hdr.syn = true;
        let builder = PacketBuilder::ipv4(src, dst, 64).tcp_header(hdr);
        let mut out = Vec::with_capacity(builder.size(0));
        builder.write(&mut out, &[]).unwrap();
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn build_ack(
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        seq: u32,
        ack: u32,
        fin: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut hdr = TcpHeader::new(sport, dport, seq, 65535);
        hdr.ack = true;
        hdr.acknowledgment_number = ack;
        hdr.fin = fin;
        if !payload.is_empty() {
            hdr.psh = true;
        }
        let builder = PacketBuilder::ipv4(src, dst, 64).tcp_header(hdr);
        let mut out = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut out, payload).unwrap();
        out
    }

    fn build_syn_v6(src: Ipv6Addr, sport: u16, dst: Ipv6Addr, dport: u16, seq: u32) -> Vec<u8> {
        let mut hdr = TcpHeader::new(sport, dport, seq, 65535);
        hdr.syn = true;
        let builder = PacketBuilder::ipv6(src.octets(), dst.octets(), 64).tcp_header(hdr);
        let mut out = Vec::with_capacity(builder.size(0));
        builder.write(&mut out, &[]).unwrap();
        out
    }

    #[test]
    fn test_build_synthetic_tcp_rst_ipv4_and_ipv6() {
        let syn_v4 = build_syn([10, 0, 0, 2], 51000, [1, 1, 1, 1], 443, 0x1000_0000);
        let rst_v4 = build_synthetic_tcp_rst(&syn_v4).expect("IPv4 SYN should yield RST+ACK");
        let parsed = parse_tcp_packet(&rst_v4).unwrap();
        assert_eq!(parsed.src_ip, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(parsed.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(parsed.src_port, 443);
        assert_eq!(parsed.dst_port, 51000);
        assert!(parsed.rst);
        assert!(parsed.ack);
        assert_eq!(parsed.ack_num, 0x1000_0001);

        let src6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let dst6 = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let syn_v6 = build_syn_v6(src6, 52000, dst6, 8443, 0x2000_0000);
        let rst_v6 = build_synthetic_tcp_rst(&syn_v6).expect("IPv6 SYN should yield RST+ACK");
        let parsed6 = parse_tcp_packet(&rst_v6).unwrap();
        assert!(parsed6.is_ipv6);
        assert!(parsed6.rst && parsed6.ack);
        assert_eq!(parsed6.ack_num, 0x2000_0001);
    }

    #[test]
    fn test_netstack_untracked_non_syn_bypass_and_direct_block_decisions() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);
        let mut accepted = Vec::new();
        let mut tx = Vec::new();
        let meta = PacketInterfaceMeta {
            if_idx: 7,
            sub_if_idx: 0,
            loopback: false,
            is_ipv6: false,
            bitfield: 0,
        };

        // 1. 存量连接（无 SYN 标志）未经追踪 -> 立即平滑放行
        let ack_pkt = build_ack(
            [192, 168, 1, 10],
            40010,
            [93, 184, 216, 34],
            443,
            100,
            200,
            false,
            b"hi",
        );
        assert!(matches!(
            engine.ingest_outbound_tcp(
                ack_pkt,
                meta,
                Some(99999),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Passthrough(_)
        ));
        assert!(accepted.is_empty());

        // 2. BypassPortRegistry 已登记出站 TCP 端口或自身 PID -> 首包 SYN 直接放行
        {
            // 动态占用唯一 TCP 临时端口，避免向全局 BypassPortRegistry 注册固定端口 40011 干扰并发单测
            let tcp_holder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let bypass_tcp_port = tcp_holder.local_addr().unwrap().port();
            let syn_bypass = build_syn(
                [192, 168, 1, 10],
                bypass_tcp_port,
                [93, 184, 216, 34],
                443,
                500,
            );
            let _guard = register_bypass_port(BypassProtocol::Tcp, bypass_tcp_port);
            assert!(matches!(
                engine.ingest_outbound_tcp(
                    syn_bypass,
                    meta,
                    Some(99999),
                    None,
                    None,
                    None,
                    &mut accepted,
                    &mut tx
                ),
                TcpIngestOutcome::Passthrough(_)
            ));
            drop(_guard);
            drop(tcp_holder);
        }
        assert!(matches!(
            engine.ingest_outbound_tcp(
                build_syn([192, 168, 1, 10], 40012, [93, 184, 216, 34], 443, 500),
                meta,
                Some(std::process::id()),
                None,
                None,
                None,
                &mut accepted,
                &mut tx,
            ),
            TcpIngestOutcome::Passthrough(_)
        ));

        // 3. Action::Block 规则命中 -> 秒级注入 RST，不创建用户态 socket
        let block_engine = RuleEngine::new(vec![], Action::Block);
        let syn_block = build_syn([192, 168, 1, 10], 40013, [1, 2, 3, 4], 443, 700);
        match engine.ingest_outbound_tcp(
            syn_block,
            meta,
            Some(99999),
            Some(&block_engine),
            None,
            None,
            &mut accepted,
            &mut tx,
        ) {
            TcpIngestOutcome::InjectRst(rst_pkt) => {
                assert!(parse_tcp_packet(&rst_pkt.data).unwrap().rst);
            }
            other => panic!("Expected InjectRst, got {:?}", other),
        }

        // 4. NeedsDomainSniff 标记传播验证
        let domain_engine = RuleEngine::new(
            vec![Rule::from_raw(
                "sniff-rule",
                true,
                None,
                Some("*.openai.com"),
                None,
                Action::Proxy(1),
            )],
            Action::Direct,
        );
        let syn_sniff = build_syn([192, 168, 1, 10], 40014, [104, 18, 1, 1], 443, 900);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn_sniff,
                meta,
                Some(99999),
                Some(&domain_engine),
                None,
                None,
                &mut accepted,
                &mut tx,
            ),
            TcpIngestOutcome::Intercepted
        ));
        assert_eq!(accepted.len(), 1);
        assert!(accepted[0].needs_domain_sniff);
        assert_eq!(tx.len(), 1);
        let syn_ack = parse_tcp_packet(&tx[0].data).unwrap();
        assert!(syn_ack.syn && syn_ack.ack);
    }

    #[tokio::test]
    async fn test_netstack_full_tcp_handshake_data_and_half_close_roundtrip() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(Arc::clone(&signal));
        let mut accepted = Vec::new();
        let mut tx = Vec::new();
        let meta = PacketInterfaceMeta {
            if_idx: 11,
            sub_if_idx: 2,
            loopback: false,
            is_ipv6: false,
            bitfield: 0,
        };

        let src = [10, 1, 2, 3];
        let sport = 55555;
        let dst = [93, 184, 216, 34];
        let dport = 80;
        let client_isn = 1000;

        // 1. Client SYN -> smoltcp emits SYN+ACK
        let syn = build_syn(src, sport, dst, dport, client_isn);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn,
                meta,
                Some(88888),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        assert_eq!(accepted.len(), 1);
        let flow = accepted.pop().unwrap();
        assert_eq!(
            flow.orig_dst,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(dst)), dport)
        );

        assert_eq!(tx.len(), 1);
        assert_eq!(tx[0].meta.if_idx, 11);
        let syn_ack = parse_tcp_packet(&tx.pop().unwrap().data).unwrap();
        assert!(syn_ack.syn && syn_ack.ack);
        let server_isn = syn_ack.seq;
        assert_eq!(syn_ack.ack_num, client_isn + 1);

        // 2. Client ACK + GET payload + FIN (测试客户端发完请求立即半关闭写端!)
        let req_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let ack_data_fin = build_ack(
            src,
            sport,
            dst,
            dport,
            client_isn + 1,
            server_isn + 1,
            true,
            req_payload,
        );
        assert!(matches!(
            engine.ingest_outbound_tcp(
                ack_data_fin,
                meta,
                Some(88888),
                None,
                None,
                None,
                &mut accepted,
                &mut tx,
            ),
            TcpIngestOutcome::Intercepted
        ));

        let (mut rd, mut wr) = flow.stream.split_stream();
        let reader_handle = tokio::spawn(async move {
            let mut buf = Vec::new();
            rd.read_to_end(&mut buf).await.unwrap();
            buf
        });

        let read_req = reader_handle.await.unwrap();
        assert_eq!(read_req, req_payload);

        // 3. 在客户端已 FIN（CloseWait）后，下游依旧正常回传完整 HTTP 响应并优雅 shutdown 发送 FIN
        let resp_payload = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
        let writer_handle = tokio::spawn(async move {
            wr.write_all(resp_payload).await.unwrap();
            wr.shutdown().await.unwrap();
        });

        // 推进 pump 直到 writer 完成并收集 smoltcp 吐出的所有响应+FIN 报文
        let mut received_from_smoltcp = Vec::new();
        let mut saw_server_fin = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            engine.pump(&mut tx);
            for pkt_out in tx.drain(..) {
                if let Some(parsed) = parse_tcp_packet(&pkt_out.data) {
                    let sliced = SlicedPacket::from_ip(&pkt_out.data).unwrap();
                    if let Some(TransportSlice::Tcp(t)) = sliced.transport {
                        received_from_smoltcp.extend_from_slice(t.payload());
                    }
                    if parsed.fin {
                        saw_server_fin = true;
                    }
                }
            }
            if writer_handle.is_finished() && saw_server_fin {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "Timed out waiting for smoltcp response & FIN"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        writer_handle.await.unwrap();
        assert_eq!(received_from_smoltcp, resp_payload);
        assert!(saw_server_fin);
    }

    fn build_rst(
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        seq: u32,
        ack: u32,
    ) -> Vec<u8> {
        let mut hdr = TcpHeader::new(sport, dport, seq, 65535);
        hdr.rst = true;
        hdr.ack = true;
        hdr.acknowledgment_number = ack;
        let builder = PacketBuilder::ipv4(src, dst, 64).tcp_header(hdr);
        let mut out = Vec::with_capacity(builder.size(0));
        builder.write(&mut out, &[]).unwrap();
        out
    }

    fn establish_ipv4_flow(
        engine: &mut NetstackEngine,
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
    ) -> (AcceptedTcpFlow, ParsedTcpPacket) {
        let mut accepted = Vec::new();
        let mut tx = Vec::new();
        let meta = PacketInterfaceMeta {
            if_idx: 3,
            sub_if_idx: 0,
            loopback: false,
            is_ipv6: false,
            bitfield: 0,
        };
        let syn = build_syn(src, sport, dst, dport, 1000);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn,
                meta,
                Some(9001),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        let syn_ack = parse_tcp_packet(&tx.pop().unwrap().data).unwrap();
        assert!(syn_ack.syn && syn_ack.ack);

        let ack = build_ack(src, sport, dst, dport, 1001, syn_ack.seq + 1, false, &[]);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                ack,
                meta,
                Some(9001),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        let flow = accepted.pop().unwrap();
        (flow, syn_ack)
    }

    #[test]
    fn test_netstack_ungraceful_drop_aborts_with_rst_and_frees_slot() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);
        let (flow, _syn_ack) = establish_ipv4_flow(
            &mut engine,
            [192, 168, 1, 20],
            55100,
            [93, 184, 216, 34],
            443,
        );
        assert_eq!(engine.active_flow_count(), 1);

        // 模拟 Dispatcher 因 Action::Block / 拨号失败直接丢弃双端流（未调用 shutdown）
        drop(flow);

        let mut tx = Vec::new();
        engine.pump(&mut tx);

        assert!(
            tx.iter()
                .filter_map(|p| parse_tcp_packet(&p.data))
                .any(|p| p.rst),
            "ungraceful stream drop must emit TCP RST instead of silently sticking in FinWait2"
        );
        assert_eq!(engine.active_flow_count(), 0);
    }

    #[tokio::test]
    async fn test_netstack_reaps_stalled_fin_wait_2_slot_after_teardown_timeout() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);
        let src = [192, 168, 1, 21];
        let dst = [93, 184, 216, 34];
        let sport = 55101;
        let dport = 80;
        let (flow, syn_ack) = establish_ipv4_flow(&mut engine, src, sport, dst, dport);

        let (rd, mut wr) = flow.stream.split_stream();
        drop(rd);

        let writer = tokio::spawn(async move {
            wr.shutdown().await.unwrap();
        });

        // 推进 pump 直到 smoltcp 发送 FIN 并让 writer.shutdown() 完成（进入 FinWait1）
        let mut tx = Vec::new();
        let mut fin_pkt = None;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            engine.pump(&mut tx);
            for p in tx.drain(..) {
                if let Some(parsed) = parse_tcp_packet(&p.data)
                    && parsed.fin
                {
                    fin_pkt = Some(parsed);
                }
            }
            if writer.is_finished() && fin_pkt.is_some() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "Timed out waiting for graceful FIN"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        writer.await.unwrap();

        // 客户端仅 ACK 我方 FIN 而不回 FIN -> smoltcp 进入 FinWait2
        let fin_parsed = fin_pkt.unwrap();
        let ack_only = build_ack(
            src,
            sport,
            dst,
            dport,
            1001,
            fin_parsed.seq.wrapping_add(1),
            false,
            &[],
        );
        let mut accepted = Vec::new();
        let _ = engine.ingest_outbound_tcp(
            ack_only,
            PacketInterfaceMeta::default(),
            Some(9001),
            None,
            None,
            None,
            &mut accepted,
            &mut tx,
        );
        tx.clear();

        let t0 = Instant::now();
        engine.pump_internal(t0, &mut tx);
        assert_eq!(engine.active_flow_count(), 1);
        let key = TcpFlowKey::new(IpAddr::from(src), sport, IpAddr::from(dst), dport);
        assert_eq!(
            engine
                .sockets
                .get::<tcp::Socket>(engine.intercepted.get(&key).unwrap().handle)
                .state(),
            tcp::State::FinWait2
        );

        // 超过 TEARDOWN_TIMEOUT 后应自动 abort 并回收 FinWait2 槽位
        engine.pump_internal(t0 + TEARDOWN_TIMEOUT + Duration::from_millis(50), &mut tx);
        assert_eq!(engine.active_flow_count(), 0);
        assert!(
            tx.iter()
                .filter_map(|p| parse_tcp_packet(&p.data))
                .any(|p| p.rst)
        );
        let _ = syn_ack;
    }

    #[tokio::test]
    async fn test_netstack_established_rst_wakes_and_fails_write_flush_shutdown_and_read() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);
        let src = [192, 168, 1, 22];
        let dst = [93, 184, 216, 34];
        let sport = 55102;
        let dport = 443;
        let (flow, syn_ack) = establish_ipv4_flow(&mut engine, src, sport, dst, dport);
        let (mut rd, mut wr) = flow.stream.split_stream();

        // 先写入超过桥梁+窗口容量的数据并等待 write_all 因背压进入 Poll::Pending
        let fill = vec![b'Z'; BRIDGE_BUFFER_LIMIT];
        wr.write_all(&fill).await.unwrap();

        let (tx_wr_done, rx_wr_done) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let w_res = wr.write_all(&[b'Q'; 32]).await;
            let s_res = wr.shutdown().await;
            let _ = tx_wr_done.send((w_res, s_res));
        });
        tokio::task::yield_now().await;

        let (tx_rd_done, rx_rd_done) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut buf = [0u8; 16];
            let r_res = rd.read(&mut buf).await;
            let _ = tx_rd_done.send(r_res);
        });
        tokio::task::yield_now().await;

        // 已建连会话收到客户端 RST：必须立即唤醒并报错，绝不能挂起到 120s 空闲超时
        let rst = build_rst(src, sport, dst, dport, 1001, syn_ack.seq + 1);
        let mut accepted = Vec::new();
        let mut tx = Vec::new();
        let _ = engine.ingest_outbound_tcp(
            rst,
            PacketInterfaceMeta::default(),
            Some(9001),
            None,
            None,
            None,
            &mut accepted,
            &mut tx,
        );

        let (w_res, s_res) = tokio::time::timeout(Duration::from_secs(1), rx_wr_done)
            .await
            .expect("poll_write / poll_shutdown must wake immediately on RST")
            .unwrap();
        assert_eq!(w_res.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(s_res.unwrap_err().kind(), io::ErrorKind::ConnectionReset);

        let r_res = tokio::time::timeout(Duration::from_secs(1), rx_rd_done)
            .await
            .expect("poll_read must wake immediately on RST")
            .unwrap();
        assert_eq!(r_res.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(engine.active_flow_count(), 0);
    }

    #[test]
    fn test_netstack_ipv6_and_lso_oversized_segment_accepted() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);
        let mut accepted = Vec::new();
        let mut tx = Vec::new();
        let meta = PacketInterfaceMeta {
            if_idx: 5,
            sub_if_idx: 0,
            loopback: false,
            is_ipv6: true,
            bitfield: 0,
        };

        let src6 = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6);
        let dst6 = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let syn6 = build_syn_v6(src6, 61111, dst6, 443, 5000);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn6,
                meta,
                Some(77777),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        assert_eq!(tx.len(), 1);
        let syn_ack6 = parse_tcp_packet(&tx.pop().unwrap().data).unwrap();
        assert!(syn_ack6.is_ipv6 && syn_ack6.syn && syn_ack6.ack);

        // 模拟 Windows LSO 大包（>1500B）入站到 smoltcp 不应被 MTU 丢弃
        let large_payload = vec![b'A'; 2400];
        let mut hdr = TcpHeader::new(61111, 443, 5001, 65535);
        hdr.ack = true;
        hdr.acknowledgment_number = syn_ack6.seq + 1;
        let builder = PacketBuilder::ipv6(src6.octets(), dst6.octets(), 64).tcp_header(hdr);
        let mut lso_pkt = Vec::with_capacity(builder.size(large_payload.len()));
        builder.write(&mut lso_pkt, &large_payload).unwrap();

        assert!(matches!(
            engine.ingest_outbound_tcp(
                lso_pkt,
                meta,
                Some(77777),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        let flow = accepted.pop().unwrap();
        // 数据应完整进入 bridge.to_app
        let inner = flow.stream.read.bridge.inner.lock().unwrap();
        assert_eq!(inner.to_app.len(), 2400);
    }

    #[test]
    fn test_netstack_unknown_pid_does_not_bypass_app_scoped_proxy_rule() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);
        let engine_rules = RuleEngine::new(
            vec![
                Rule::from_raw(
                    "LocalBypass",
                    true,
                    None,
                    Some("192.168.0.0/16"),
                    None,
                    Action::Direct,
                ),
                Rule::from_raw(
                    "DevProxy",
                    true,
                    Some("chrome.exe"),
                    None,
                    None,
                    Action::Proxy(101),
                ),
            ],
            Action::Direct,
        );

        let meta = PacketInterfaceMeta::default();
        let mut accepted = Vec::new();
        let mut tx = Vec::new();

        // 1. pid = None 访问 192.168/16：无条件全局 Direct 已命中，允许直接 Passthrough
        let syn_lan = build_syn([10, 0, 0, 2], 51200, [192, 168, 1, 5], 80, 100);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn_lan,
                meta,
                None,
                Some(&engine_rules),
                None,
                None,
                &mut accepted,
                &mut tx,
            ),
            TcpIngestOutcome::Passthrough(_)
        ));

        // 2. pid = None 访问公网 8.8.8.8:443：因前方存在 DevProxy (chrome.exe -> Proxy)，绝不盲目放行写入 passthrough
        let syn_pub = build_syn([10, 0, 0, 2], 51201, [8, 8, 8, 8], 443, 200);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn_pub,
                meta,
                None,
                Some(&engine_rules),
                None,
                None,
                &mut accepted,
                &mut tx,
            ),
            TcpIngestOutcome::Intercepted
        ));
        assert_eq!(engine.active_flow_count(), 1);

        // 3. 当提供真实 ProcessTracker 但 PID = Some(999999) 已退出无法解析进程路径/名称时，
        //    proc_unresolved 必须生效并接入协议栈复核，不得误写 passthrough 绕过 DevProxy
        let real_tracker = ProcessTracker::new();
        let syn_dead_pid = build_syn([10, 0, 0, 2], 51202, [8, 8, 8, 8], 443, 300);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn_dead_pid,
                meta,
                Some(999_999),
                Some(&engine_rules),
                Some(&real_tracker),
                None,
                &mut accepted,
                &mut tx,
            ),
            TcpIngestOutcome::Intercepted
        ));
        assert_eq!(engine.active_flow_count(), 2);
    }

    #[test]
    fn test_netstack_listen_fallback_returns_original_syn_and_preserves_tx_meta() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);

        // 先建立一条来自接口 7 的活跃流并写入下行响应，使 device.tx_queue 或 pump 期间有不同接口元数据
        let meta_existing = PacketInterfaceMeta {
            if_idx: 7,
            sub_if_idx: 1,
            loopback: false,
            is_ipv6: false,
            bitfield: 1,
        };
        let mut accepted = Vec::new();
        let mut tx = Vec::new();
        let syn_ok = build_syn([10, 0, 0, 2], 52001, [1, 1, 1, 1], 443, 100);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn_ok,
                meta_existing,
                Some(9001),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        let syn_ack = parse_tcp_packet(&tx.pop().unwrap().data).unwrap();
        let ack_ok = build_ack(
            [10, 0, 0, 2],
            52001,
            [1, 1, 1, 1],
            443,
            101,
            syn_ack.seq + 1,
            false,
            b"PING",
        );
        assert!(matches!(
            engine.ingest_outbound_tcp(
                ack_ok,
                meta_existing,
                Some(9001),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        let flow = accepted.pop().unwrap();
        {
            let mut inner = flow.stream.write.bridge.inner.lock().unwrap();
            inner.to_socket.extend(b"PONG");
        }
        // 在 smoltcp 下一次 poll 前故意触发 tx_queue 仅待 pump 时由另一流退回 Listen
        let flow_tx_before_listen = {
            // 将待发数据注入 smoltcp socket 缓冲区（不立即 poll 以便在 Listen fallback poll 中一并吐出）
            let key_existing = TcpFlowKey::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                52001,
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                443,
            );
            let sess = engine.intercepted.get(&key_existing).unwrap();
            let sock = engine.sockets.get_mut::<tcp::Socket>(sess.handle);
            let sent = sock.send_slice(b"RESP").unwrap();
            assert_eq!(sent, 4);
            true
        };
        assert!(flow_tx_before_listen);

        // 构造一条 etherparse 可解析、但包含非法 TCP MSS 选项长度（kind=2, len=1）导致 smoltcp 拒收留在 Listen 的 SYN
        let mut hdr = TcpHeader::new(52002, 80, 777, 65535);
        hdr.syn = true;
        hdr.set_options_raw(&[2, 1, 0, 0]).unwrap();
        let builder = PacketBuilder::ipv4([10, 0, 0, 9], [93, 184, 216, 34], 64).tcp_header(hdr);
        let mut malformed_syn = Vec::with_capacity(builder.size(0));
        builder.write(&mut malformed_syn, &[]).unwrap();
        let expected_syn_bytes = malformed_syn.clone();

        let meta_bad_syn = PacketInterfaceMeta {
            if_idx: 19,
            sub_if_idx: 2,
            loopback: false,
            is_ipv6: false,
            bitfield: 9,
        };
        tx.clear();
        let outcome = engine.ingest_outbound_tcp(
            malformed_syn,
            meta_bad_syn,
            Some(9002),
            None,
            None,
            None,
            &mut accepted,
            &mut tx,
        );
        // P1-5 修复断言 1：不得静默丢弃 SYN，必须原样以 Passthrough(syn_backup) 返回
        let TcpIngestOutcome::Passthrough(emitted) = outcome else {
            panic!("expected Passthrough fallback when smoltcp rejects malformed SYN");
        };
        assert_eq!(emitted.data, expected_syn_bytes);
        assert_eq!(emitted.meta.if_idx, 19);
        assert!(accepted.is_empty());
        // 仅应保留第一条已建连会话，失败 Listen 句柄必须已销毁
        assert_eq!(engine.active_flow_count(), 1);
        // P1-5 修复断言 2：并发期间经由 drain_tx_with_lookup 冲刷的第一条流报文必须保留其接口 7 元数据而非混用接口 19
        let resp_pkt = tx
            .iter()
            .find(|p| parse_tcp_packet(&p.data).is_some_and(|t| t.dst_port == 52001))
            .expect("expected existing flow TX packet flushed during fallback poll");
        assert_eq!(resp_pkt.meta.if_idx, 7);
    }

    #[test]
    fn test_netstack_passthrough_invalidated_on_rst_new_syn_seq_and_socket_close() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);
        let direct_rules = RuleEngine::new(vec![], Action::Direct);
        let proxy_rules = RuleEngine::new(vec![], Action::Proxy(101));

        let meta = PacketInterfaceMeta::default();
        let mut accepted = Vec::new();
        let mut tx = Vec::new();

        let src = [10, 0, 0, 2];
        let sport = 53100;
        let dst = [93, 184, 216, 34];
        let dport = 443;

        // 1. 首次 Direct 命中，记录 passthrough (syn_seq = 1000)
        let syn1 = build_syn(src, sport, dst, dport, 1000);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn1.clone(),
                meta,
                Some(1234),
                Some(&direct_rules),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Passthrough(_)
        ));
        // 同 seq 重传 SYN 即使切了 Proxy 规则仍保持同一连接快路径放行
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn1,
                meta,
                Some(1234),
                Some(&proxy_rules),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Passthrough(_)
        ));

        // 2. 端口快速复用发起不同 ISN (seq = 2000) 的全新 SYN：必须失效旧 passthrough 并按新规则接入劫持
        let syn2 = build_syn(src, sport, dst, dport, 2000);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn2,
                meta,
                Some(1234),
                Some(&proxy_rules),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        assert_eq!(engine.active_flow_count(), 1);
        accepted.clear();
        tx.clear();

        // 3. 测试 RST 立即清除 passthrough（改用端口 53101）
        let syn3 = build_syn(src, 53101, dst, dport, 3000);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn3.clone(),
                meta,
                Some(1234),
                Some(&direct_rules),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Passthrough(_)
        ));
        let rst = build_rst(src, 53101, dst, dport, 3001, 0);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                rst,
                meta,
                Some(1234),
                Some(&proxy_rules),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Passthrough(_)
        ));
        // Even same seq after RST must re-evaluate rules and intercept under proxy_rules
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn3,
                meta,
                Some(1234),
                Some(&proxy_rules),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));

        // 4. 测试 SOCKET 层 SocketClose 通知按本地端点精确清缓存（端口 53102）
        let syn4 = build_syn(src, 53102, dst, dport, 4000);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn4.clone(),
                meta,
                Some(1234),
                Some(&direct_rules),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Passthrough(_)
        ));
        engine.invalidate_passthrough_for_local_endpoint(IpAddr::V4(Ipv4Addr::from(src)), 53102);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn4,
                meta,
                Some(1234),
                Some(&proxy_rules),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
    }

    #[tokio::test]
    async fn test_netstack_intercepted_teardown_flow_retired_on_fresh_syn() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(Arc::clone(&signal));
        let src = [10, 0, 0, 2];
        let sport = 54000;
        let dst = [93, 184, 216, 34];
        let dport = 443;

        let (flow1, syn_ack1) = establish_ipv4_flow(&mut engine, src, sport, dst, dport);
        let (mut rd1, mut wr1) = flow1.stream.split_stream();
        // 客户端先发 FIN，应用端发 FIN（进入 TimeWait/FinWait2/LastAck 退场期）
        let meta = PacketInterfaceMeta::default();
        let mut accepted = Vec::new();
        let mut tx = Vec::new();
        let mut fin_hdr = TcpHeader::new(sport, dport, 1001, 65535);
        fin_hdr.ack = true;
        fin_hdr.fin = true;
        fin_hdr.acknowledgment_number = syn_ack1.seq + 1;
        let builder = PacketBuilder::ipv4(src, dst, 64).tcp_header(fin_hdr);
        let mut fin_pkt = Vec::with_capacity(builder.size(0));
        builder.write(&mut fin_pkt, &[]).unwrap();
        assert!(matches!(
            engine.ingest_outbound_tcp(
                fin_pkt,
                meta,
                Some(9001),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));

        let sh = tokio::spawn(async move {
            wr1.shutdown().await.unwrap();
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while !sh.is_finished() {
            tx.clear();
            engine.pump(&mut tx);
            assert!(
                tokio::time::Instant::now() < deadline,
                "Timed out waiting for shutdown pump"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        sh.await.unwrap();
        let mut buf = [0u8; 32];
        assert_eq!(rd1.read(&mut buf).await.unwrap(), 0);

        // 在 TIME_WAIT_REAP_TIMEOUT (2s) 到期前，立即以同一四元组和全新 ISN (seq = 9000) 建连
        tx.clear();
        accepted.clear();
        let syn2 = build_syn(src, sport, dst, dport, 9000);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn2,
                meta,
                Some(9001),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        // 不得生成延迟 RST 误伤新生 SYN，应直接返回新 SYN/ACK 且接受新连接
        assert!(
            !tx.iter()
                .any(|p| parse_tcp_packet(&p.data).is_some_and(|t| t.rst))
        );
        let syn_ack2 = tx
            .iter()
            .filter_map(|p| parse_tcp_packet(&p.data))
            .find(|t| t.syn && t.ack)
            .expect("expected fresh SYN/ACK on reused 4-tuple");
        assert_eq!(syn_ack2.ack_num, 9001);
        assert_eq!(accepted.len(), 1);
        assert_eq!(engine.active_flow_count(), 1);
    }

    #[test]
    fn test_netstack_signal_wakes_and_drains_closed_tcp_endpoints() {
        let signal = Arc::new(NetstackSignal::new());
        let local_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        signal.push_closed_tcp_endpoint(local_ip, 55123);
        let mut pkts = Vec::new();
        let mut closed = Vec::new();
        assert!(signal.wait_drain_or_timeout(Duration::from_millis(50), &mut pkts, &mut closed));
        assert!(pkts.is_empty());
        assert_eq!(closed, vec![(local_ip, 55123)]);
    }

    #[tokio::test]
    async fn test_netstack_syn_received_rst_reverts_to_listen_is_reaped_and_does_not_hijack_next_syn()
     {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);
        let meta = PacketInterfaceMeta::default();
        let mut accepted = Vec::new();
        let mut tx = Vec::new();

        let src = [10, 0, 0, 2];
        let sport = 54111;
        let dst = [93, 184, 216, 34];
        let dport = 443;

        // 1. 仅完成 SYN -> SYN/ACK，使 socket 停留在 SynReceived（非零 listen_ep）
        let syn1 = build_syn(src, sport, dst, dport, 1000);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn1,
                meta,
                Some(9001),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        let syn_ack1 = parse_tcp_packet(&tx.pop().unwrap().data).unwrap();
        let flow1 = accepted.pop().unwrap();
        assert_eq!(engine.active_flow_count(), 1);

        // 2. 客户端在 SynReceived 阶段发送 RST（如 Chrome 取消预连接）：smoltcp 会将该句柄重置回 State::Listen
        let rst = build_rst(src, sport, dst, dport, 1001, syn_ack1.seq + 1);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                rst,
                meta,
                Some(9001),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));

        // 必须立即触发 Step F0 摘除该僵尸 Listen 槽位并向调度器唤醒报错，而非误标 EOF 或泄露槽位
        assert_eq!(engine.active_flow_count(), 0);
        assert!(engine.sockets.iter().count() == 0);

        let (mut rd, mut wr) = flow1.stream.split_stream();
        let mut buf = [0u8; 16];
        let rerr = rd.read(&mut buf).await.unwrap_err();
        assert_eq!(rerr.kind(), io::ErrorKind::ConnectionReset);
        let werr = wr.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap_err();
        assert_eq!(werr.kind(), io::ErrorKind::ConnectionReset);

        // 3. 不同源端口再连同一个 (dst_ip, dst_port)：不得被僵尸 Listen 句柄抢占触发回退 Passthrough
        tx.clear();
        accepted.clear();
        let syn2 = build_syn(src, 54112, dst, dport, 2000);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn2,
                meta,
                Some(9001),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        assert_eq!(accepted.len(), 1);
        assert_eq!(engine.active_flow_count(), 1);
        let syn_ack2 = parse_tcp_packet(&tx.pop().unwrap().data).unwrap();
        assert!(syn_ack2.syn && syn_ack2.ack && syn_ack2.ack_num == 2001);
    }

    #[test]
    fn test_netstack_lso_over_64kb_and_zero_header_len_ipv4_and_ipv6() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);

        // 1. IPv4 70,000B LSO 包（Total Length = 0，总长 > 65,535，启用 WSCALE 窗口扩大以容纳 >64KB 单次突发）
        let meta4 = PacketInterfaceMeta {
            if_idx: 3,
            sub_if_idx: 0,
            loopback: false,
            is_ipv6: false,
            bitfield: 0,
        };
        let mut accepted = Vec::new();
        let mut tx = Vec::new();
        let mut syn4_hdr = TcpHeader::new(56001, 443, 1000, 65535);
        syn4_hdr.syn = true;
        syn4_hdr.set_options_raw(&[3, 3, 8, 1]).unwrap();
        let syn4_b = PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64).tcp_header(syn4_hdr);
        let mut syn4 = Vec::with_capacity(syn4_b.size(0));
        syn4_b.write(&mut syn4, &[]).unwrap();
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn4,
                meta4,
                Some(8888),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        let syn_ack4 = parse_tcp_packet(&tx.pop().unwrap().data).unwrap();
        let ack4 = build_ack(
            [10, 0, 0, 2],
            56001,
            [1, 1, 1, 1],
            443,
            1001,
            syn_ack4.seq + 1,
            false,
            &[],
        );
        assert!(matches!(
            engine.ingest_outbound_tcp(
                ack4,
                meta4,
                Some(8888),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        let flow4 = accepted.pop().unwrap();

        let payload4 = vec![0x5Au8; 70_000];
        let mut hdr4 = TcpHeader::new(56001, 443, 1001, 65535);
        hdr4.ack = true;
        hdr4.psh = true;
        hdr4.acknowledgment_number = syn_ack4.seq + 1;
        let lso4 = PacketBuilder::ipv4([10, 0, 0, 2], [1, 1, 1, 1], 64).tcp_header(hdr4);
        let mut pkt4 = Vec::with_capacity(20 + 20 + payload4.len());
        lso4.write(&mut pkt4, &payload4[..1000]).unwrap();
        // 手动拼接完整 70,000 字节并按 NDIS LSO 规范将 IPv4 Total Length 置 0
        pkt4.extend_from_slice(&payload4[1000..]);
        pkt4[2..4].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(pkt4.len(), 20 + 20 + 70_000);

        let parsed4 = parse_tcp_packet(&pkt4).expect("IPv4 LSO >64KB with total_len=0 must parse");
        assert_eq!(parsed4.payload_len, 70_000);

        tx.clear();
        accepted.clear();
        assert!(matches!(
            engine.ingest_outbound_tcp(
                pkt4,
                meta4,
                Some(8888),
                None,
                None,
                None,
                &mut accepted,
                &mut tx,
            ),
            TcpIngestOutcome::Intercepted
        ));
        {
            let inner = flow4.stream.read.bridge.inner.lock().unwrap();
            assert_eq!(inner.to_app.len(), 70_000);
            assert!(inner.to_app.iter().all(|&b| b == 0x5A));
        }

        // 2. IPv6 70,000B LSO 包（Payload Length = 0，总长 > 65,575）
        let src6 = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6);
        let dst6 = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let meta6 = PacketInterfaceMeta {
            if_idx: 2,
            is_ipv6: true,
            ..Default::default()
        };
        let mut syn6_hdr = TcpHeader::new(61122, 443, 8000, 65535);
        syn6_hdr.syn = true;
        syn6_hdr.set_options_raw(&[3, 3, 8, 1]).unwrap();
        let syn6_b = PacketBuilder::ipv6(src6.octets(), dst6.octets(), 64).tcp_header(syn6_hdr);
        let mut syn6 = Vec::with_capacity(syn6_b.size(0));
        syn6_b.write(&mut syn6, &[]).unwrap();
        tx.clear();
        accepted.clear();
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn6,
                meta6,
                Some(8889),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        let syn_ack6 = parse_tcp_packet(&tx.pop().unwrap().data).unwrap();
        let mut ack6_hdr = TcpHeader::new(61122, 443, 8001, 65535);
        ack6_hdr.ack = true;
        ack6_hdr.acknowledgment_number = syn_ack6.seq + 1;
        let ack6_builder =
            PacketBuilder::ipv6(src6.octets(), dst6.octets(), 64).tcp_header(ack6_hdr);
        let mut ack6 = Vec::with_capacity(ack6_builder.size(0));
        ack6_builder.write(&mut ack6, &[]).unwrap();
        assert!(matches!(
            engine.ingest_outbound_tcp(
                ack6,
                meta6,
                Some(8889),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        let flow6 = accepted.pop().unwrap();

        let payload6 = vec![0x3Cu8; 70_000];
        let mut hdr6 = TcpHeader::new(61122, 443, 8001, 65535);
        hdr6.ack = true;
        hdr6.psh = true;
        hdr6.acknowledgment_number = syn_ack6.seq + 1;
        let lso6 = PacketBuilder::ipv6(src6.octets(), dst6.octets(), 64).tcp_header(hdr6);
        let mut pkt6 = Vec::with_capacity(40 + 20 + payload6.len());
        lso6.write(&mut pkt6, &payload6[..1000]).unwrap();
        pkt6.extend_from_slice(&payload6[1000..]);
        pkt6[4..6].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(pkt6.len(), 40 + 20 + 70_000);

        let parsed6 =
            parse_tcp_packet(&pkt6).expect("IPv6 LSO >64KB with payload_len=0 must parse");
        assert_eq!(parsed6.payload_len, 70_000);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                pkt6,
                meta6,
                Some(8889),
                None,
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        {
            let inner = flow6.stream.read.bridge.inner.lock().unwrap();
            assert_eq!(inner.to_app.len(), 70_000);
            assert!(inner.to_app.iter().all(|&b| b == 0x3C));
        }
    }

    #[test]
    fn test_fragmented_tcp_passthrough_preserves_original_fragments_and_ext_headers() {
        use crate::transparent::fragment::{FragmentOutcome, FragmentTracker};

        let src6 = Ipv6Addr::new(0x2001, 0xdb8, 10, 20, 0, 0, 0, 1);
        let dst6 = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);

        let mut syn_hdr = TcpHeader::new(59111, 443, 123456, 65535);
        syn_hdr.syn = true;
        let payload = vec![0xABu8; 16];
        let builder = PacketBuilder::ipv6(src6.octets(), dst6.octets(), 64).tcp_header(syn_hdr);
        let mut base_tcp = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut base_tcp, &payload).unwrap();
        let tcp_seg = &base_tcp[40..];

        // 构造带后置 DestOpt (nh=60 -> TCP 6) 扩展头的两片 IPv6 分片包
        let mut fragmentable = Vec::with_capacity(8 + tcp_seg.len());
        fragmentable.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
        fragmentable.extend_from_slice(tcp_seg);

        let make_frag = |off: usize, mf: bool, chunk: &[u8]| -> Vec<u8> {
            let mut out = Vec::with_capacity(40 + 8 + chunk.len());
            out.extend_from_slice(&[0x60, 0, 0, 0]);
            out.extend_from_slice(&((8 + chunk.len()) as u16).to_be_bytes());
            out.push(44);
            out.push(64);
            out.extend_from_slice(&src6.octets());
            out.extend_from_slice(&dst6.octets());
            out.push(60); // post-Fragment DestOpt
            out.push(0);
            let off_m = ((off as u16) & 0xFFF8) | if mf { 1 } else { 0 };
            out.extend_from_slice(&off_m.to_be_bytes());
            out.extend_from_slice(&0x5566_7788u32.to_be_bytes());
            out.extend_from_slice(chunk);
            out
        };
        let frag0 = make_frag(0, true, &fragmentable[..24]);
        let frag1 = make_frag(24, false, &fragmentable[24..]);

        let frag_meta = PacketInterfaceMeta {
            if_idx: 7,
            sub_if_idx: 2,
            loopback: false,
            is_ipv6: true,
            bitfield: 0x0100,
        };
        let mut tracker = FragmentTracker::new();
        assert!(matches!(
            tracker.ingest(&frag0, frag_meta, None),
            FragmentOutcome::Pending
        ));
        let FragmentOutcome::Reassembled {
            full_packet,
            orig_fragments,
        } = tracker.ingest(&frag1, frag_meta, None)
        else {
            panic!("expected reassembled IPv6 TCP packet");
        };
        assert_eq!(orig_fragments.len(), 2);

        // 模拟 NetRxContext -> NetstackSignal -> NetstackEngine(Action::Direct -> Passthrough)
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(Arc::clone(&signal));
        signal.push_outbound_tcp_with_fragments(
            full_packet,
            frag_meta,
            Some(9999),
            Some(orig_fragments.clone()),
        );
        let mut drained = Vec::new();
        let mut closed = Vec::new();
        assert!(signal.wait_drain_or_timeout(Duration::from_millis(50), &mut drained, &mut closed));
        assert_eq!(drained.len(), 1);
        let item = drained.pop().unwrap();

        let re = RuleEngine::new(Vec::new(), Action::Direct);
        let mut accepted = Vec::new();
        let mut tx = Vec::new();
        let outcome = engine.ingest_outbound_tcp(
            item.raw_ip,
            item.meta,
            item.pid,
            Some(&re),
            None,
            None,
            &mut accepted,
            &mut tx,
        );
        let TcpIngestOutcome::Passthrough(single_pkt) = outcome else {
            panic!("Direct rule must return TcpIngestOutcome::Passthrough");
        };
        assert!(accepted.is_empty());

        let emitted = select_passthrough_packets(single_pkt, item.orig_fragments);
        assert_eq!(
            emitted.len(),
            2,
            "must emit exact original fragments instead of stripped single packet"
        );
        assert_eq!(emitted[0].data, frag0);
        assert_eq!(emitted[1].data, frag1);
        assert_eq!(emitted[0].meta.if_idx, 7);
        assert_eq!(emitted[0].meta.sub_if_idx, 2);
        assert_eq!(
            emitted[0].data[6], 44,
            "original Fragment header must stay intact"
        );
        assert_eq!(
            emitted[0].data[40], 60,
            "original DestOpt extension header must stay intact"
        );
    }

    #[tokio::test]
    async fn test_netstack_engine_drop_wakes_pending_read_write_and_shutdown() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(Arc::clone(&signal));
        let meta = PacketInterfaceMeta::default();
        let re = RuleEngine::new(
            vec![Rule::from_raw(
                "ProxyAll",
                true,
                None,
                None,
                None,
                Action::Proxy(1),
            )],
            Action::Direct,
        );
        let mut accepted = Vec::new();
        let mut tx = Vec::new();

        // 连接 1 与连接 2 先完成握手，避免后续 ack2 的 pump_internal 排空连接 1 的 to_socket 缓冲
        let syn1 = build_syn([10, 0, 0, 2], 59201, [93, 184, 216, 34], 443, 100);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn1,
                meta,
                Some(7001),
                Some(&re),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        let sa1 = parse_tcp_packet(&tx.pop().unwrap().data).unwrap();
        let ack1 = build_ack(
            [10, 0, 0, 2],
            59201,
            [93, 184, 216, 34],
            443,
            101,
            sa1.seq + 1,
            false,
            &[],
        );
        assert!(matches!(
            engine.ingest_outbound_tcp(
                ack1,
                meta,
                Some(7001),
                Some(&re),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        let flow1 = accepted.pop().unwrap();

        let syn2 = build_syn([10, 0, 0, 2], 59202, [93, 184, 216, 34], 443, 200);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn2,
                meta,
                Some(7002),
                Some(&re),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        let sa2 = parse_tcp_packet(&tx.pop().unwrap().data).unwrap();
        let ack2 = build_ack(
            [10, 0, 0, 2],
            59202,
            [93, 184, 216, 34],
            443,
            201,
            sa2.seq + 1,
            false,
            &[],
        );
        assert!(matches!(
            engine.ingest_outbound_tcp(
                ack2,
                meta,
                Some(7002),
                Some(&re),
                None,
                None,
                &mut accepted,
                &mut tx
            ),
            TcpIngestOutcome::Intercepted
        ));
        let flow2 = accepted.pop().unwrap();

        // 连接 1：阻塞在 pending read() 和写满 BRIDGE_BUFFER_LIMIT 后的 pending write_all()
        let (mut rd1, mut wr1) = flow1.stream.split_stream();
        let fill_chunk = vec![0x41u8; BRIDGE_BUFFER_LIMIT];
        wr1.write_all(&fill_chunk).await.unwrap();

        let rd1_task = tokio::spawn(async move {
            let mut buf = [0u8; 32];
            rd1.read(&mut buf).await
        });
        let wr1_task = tokio::spawn(async move { wr1.write_all(b"BLOCKED_WRITE").await });

        // 连接 2：阻塞在 pending read() 和 pending shutdown()
        let (mut rd2, mut wr2) = flow2.stream.split_stream();
        let rd2_task = tokio::spawn(async move {
            let mut buf = [0u8; 32];
            rd2.read(&mut buf).await
        });
        let sh2_task = tokio::spawn(async move { wr2.shutdown().await });

        // 让各任务先进入 Poll::Pending 并注册 waker
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(engine.active_flow_count(), 2);

        // 卸载/释放 NetstackEngine：所有活跃会话必须立刻唤醒报错并清理，不得永久挂起
        drop(engine);

        let r1 = tokio::time::timeout(Duration::from_secs(1), rd1_task)
            .await
            .expect("rd1 must wake promptly on engine drop")
            .unwrap()
            .unwrap_err();
        assert_eq!(r1.kind(), io::ErrorKind::ConnectionReset);

        let w1 = tokio::time::timeout(Duration::from_secs(1), wr1_task)
            .await
            .expect("wr1 must wake promptly on engine drop")
            .unwrap()
            .unwrap_err();
        assert_eq!(w1.kind(), io::ErrorKind::ConnectionReset);

        let r2 = tokio::time::timeout(Duration::from_secs(1), rd2_task)
            .await
            .expect("rd2 must wake promptly on engine drop")
            .unwrap()
            .unwrap_err();
        assert_eq!(r2.kind(), io::ErrorKind::ConnectionReset);

        let s2 = tokio::time::timeout(Duration::from_secs(1), sh2_task)
            .await
            .expect("sh2 must wake promptly on engine drop")
            .unwrap()
            .unwrap_err();
        assert_eq!(s2.kind(), io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn test_cancelled_poll_shutdown_with_buffered_data_aborts_and_frees_slot() {
        use tokio::io::AsyncWriteExt;

        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(signal);
        let meta = PacketInterfaceMeta::default();
        let client_ip = [10, 0, 0, 42];
        let server_ip = [93, 184, 216, 88];
        let mut accepted = Vec::new();
        let mut tx_out = Vec::new();

        // 完成 TCP 三次握手进入 Established
        let syn = build_syn(client_ip, 52010, server_ip, 443, 1000);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn,
                meta,
                None,
                None,
                None,
                None,
                &mut accepted,
                &mut tx_out
            ),
            TcpIngestOutcome::Intercepted
        ));
        let syn_ack = parse_tcp_packet(&tx_out[0].data).unwrap();
        assert!(syn_ack.syn && syn_ack.ack);
        tx_out.clear();
        let ack = build_ack(
            client_ip,
            52010,
            server_ip,
            443,
            1001,
            syn_ack.seq.wrapping_add(1),
            false,
            &[],
        );
        assert!(matches!(
            engine.ingest_outbound_tcp(
                ack,
                meta,
                None,
                None,
                None,
                None,
                &mut accepted,
                &mut tx_out
            ),
            TcpIngestOutcome::Intercepted
        ));
        assert_eq!(engine.active_flow_count(), 1);
        let flow = accepted.pop().unwrap();
        let (rd, mut wr) = flow.stream.split_stream();

        // 写入超 smoltcp 发送缓冲 (128 KiB) 的数据，让 bridge.to_socket 保持非空
        let big_payload = vec![0x5Au8; 256 * 1024];
        wr.write_all(&big_payload).await.unwrap();
        tx_out.clear();
        engine.pump(&mut tx_out);

        // 发起 shutdown()，poll 一次进入 Pending 后立即取消 future 并丢弃读/写双端句柄
        {
            let shutdown_fut = wr.shutdown();
            let timed_out = tokio::time::timeout(Duration::from_millis(20), shutdown_fut).await;
            assert!(
                timed_out.is_err(),
                "shutdown must remain pending while to_socket cannot drain"
            );
        }
        drop(wr);
        drop(rd);

        // 再次 pump：必须触发 sock.abort() 吐出 RST 并释放槽位（绝不因提前置 graceful_shutdown=true 而永久泄漏）
        tx_out.clear();
        engine.pump(&mut tx_out);
        assert_eq!(
            engine.active_flow_count(),
            0,
            "dropping halves after cancelled poll_shutdown must abort and free slot"
        );
        assert!(
            tx_out
                .iter()
                .any(|p| parse_tcp_packet(&p.data).is_some_and(|t| t.rst)),
            "ungraceful abort after cancelled poll_shutdown should emit RST"
        );
    }

    #[tokio::test]
    async fn test_netstack_pump_during_syn_received_does_not_trigger_premature_eof() {
        let signal = Arc::new(NetstackSignal::new());
        let mut engine = NetstackEngine::new(Arc::clone(&signal));
        let meta = PacketInterfaceMeta {
            if_idx: 1,
            sub_if_idx: 0,
            loopback: false,
            is_ipv6: false,
            bitfield: 0,
        };
        let client_ip = [10, 0, 0, 2];
        let server_ip = [172, 66, 147, 243];
        let mut accepted = Vec::new();
        let mut tx_out = Vec::new();

        // 1. 收到 SYN 后进入 SynReceived，并模拟 actor 主循环紧接着调用 engine.pump()
        let syn = build_syn(client_ip, 52020, server_ip, 443, 1000);
        assert!(matches!(
            engine.ingest_outbound_tcp(
                syn,
                meta,
                None,
                None,
                None,
                None,
                &mut accepted,
                &mut tx_out
            ),
            TcpIngestOutcome::Intercepted
        ));
        let syn_ack = parse_tcp_packet(&tx_out[0].data).unwrap();
        assert!(syn_ack.syn && syn_ack.ack);
        tx_out.clear();

        engine.pump(&mut tx_out);

        // 2. 在客户端 ACK 与首个载荷到达前，AsyncRead 必须处于 Pending，绝不能因 SynReceived 返回 Ok(0) EOF
        let mut flow = accepted.pop().unwrap();
        let mut buf = [0u8; 64];
        let early_read =
            tokio::time::timeout(Duration::from_millis(20), flow.stream.read(&mut buf)).await;
        assert!(
            early_read.is_err(),
            "read() during SynReceived must stay Pending rather than returning premature EOF"
        );

        // 3. 客户端发来 ACK + 首批 TLS 数据后，流必须继续可读且不会在后续读完当前载荷后误判 EOF
        let ack_data = build_ack(
            client_ip,
            52020,
            server_ip,
            443,
            1001,
            syn_ack.seq.wrapping_add(1),
            false,
            b"\x16\x03\x01\x00\x05hello",
        );
        assert!(matches!(
            engine.ingest_outbound_tcp(
                ack_data,
                meta,
                None,
                None,
                None,
                None,
                &mut accepted,
                &mut tx_out
            ),
            TcpIngestOutcome::Intercepted
        ));
        let n = tokio::time::timeout(Duration::from_millis(100), flow.stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"\x16\x03\x01\x00\x05hello");

        let second_read =
            tokio::time::timeout(Duration::from_millis(20), flow.stream.read(&mut buf)).await;
        assert!(
            second_read.is_err(),
            "read() after consuming first flight without FIN must remain Pending"
        );
    }
}
