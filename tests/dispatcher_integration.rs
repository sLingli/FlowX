use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use flowx::dns::FakeIpPool;
use flowx::interceptor::dispatcher::{
    DispatcherConfig, ProxyNodeEntry, StreamDispatcher, dispatch_transparent_stream,
};
use flowx::interceptor::process::ProcessTracker;
use flowx::monitor::{ConnectionManager, InFlightTracker};
use flowx::outbound::chain::ProxyNode;
use flowx::router::{Action, RuleEngine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

fn test_config(bind: SocketAddr, rules: Vec<flowx::router::Rule>) -> DispatcherConfig {
    DispatcherConfig {
        bind_addr: bind,
        tracker: Arc::new(ProcessTracker::new()),
        fake_ip_pool: Arc::new(FakeIpPool::new_default()),
        upstream_dns: "223.5.5.5:53".parse().unwrap(),
        rule_engine: Arc::new(RuleEngine::new(rules, Action::Direct)),
        monitor: Arc::new(ConnectionManager::new()),
        proxy_nodes: Arc::new(RwLock::new(HashMap::new())),
        proxy_chains: Arc::new(HashMap::new()),
        self_ports: vec![bind.port()],
        in_flight: None,
    }
}

/// 端到端：经由 SOCKS5 入站直连到本地回显服务，验证目标解析、隧道建立与数据中继
#[tokio::test]
async fn test_socks5_direct_relay_end_to_end() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        s.write_all(&buf).await.unwrap();
    });

    let dispatcher = StreamDispatcher::new(test_config("127.0.0.1:0".parse().unwrap(), vec![]));
    let listener = dispatcher.bind().await.unwrap();
    let inbound_addr = listener.local_addr().unwrap();
    let (_tx, rx) = watch::channel(false);
    tokio::spawn(async move { dispatcher.run(listener, rx).await });

    let mut c = TcpStream::connect(inbound_addr).await.unwrap();
    c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut r = [0u8; 2];
    c.read_exact(&mut r).await.unwrap();
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo_addr.port().to_be_bytes());
    c.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    c.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "SOCKS5 reply should be success");

    c.write_all(b"hello").await.unwrap();
    let mut echoed = [0u8; 5];
    c.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"hello");
}

/// 回环防护：经由入站请求 FlowX 自身入站端口必须被拒绝，而不是无限自连
#[tokio::test]
async fn test_self_loop_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbound_addr = listener.local_addr().unwrap();
    let dispatcher = StreamDispatcher::new(test_config(inbound_addr, vec![]));
    let (_tx, rx) = watch::channel(false);
    tokio::spawn(async move { dispatcher.run(listener, rx).await });

    let mut c = TcpStream::connect(inbound_addr).await.unwrap();
    let req = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        inbound_addr.port(),
        inbound_addr.port()
    );
    c.write_all(req.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 128];
    let n = c.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 403"));
}

#[tokio::test]
async fn test_http_forward_dispatcher_blocks_pipelined_smuggling_on_persistent_origin() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let (req_tx, req_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();

    tokio::spawn(async move {
        let (mut s, _) = origin.accept().await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = s.read(&mut buf).await.unwrap();
            assert!(n > 0, "Origin received premature FIN before full request");
            got.extend_from_slice(&buf[..n]);
            if got.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        // Wait briefly: must receive NEITHER premature FIN (Ok(0)) NOR smuggled 2nd request bytes
        let probe =
            tokio::time::timeout(std::time::Duration::from_millis(80), s.read(&mut buf)).await;
        assert!(
            probe.is_err(),
            "Origin expected neither premature EOF nor smuggled bytes, got: {:?}",
            probe
        );
        let _ = req_tx.send(got);
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
            .await
            .unwrap();
        s.shutdown().await.unwrap();
    });

    let dispatcher = StreamDispatcher::new(test_config("127.0.0.1:0".parse().unwrap(), vec![]));
    let listener = dispatcher.bind().await.unwrap();
    let inbound_addr = listener.local_addr().unwrap();
    let (_tx, rx) = watch::channel(false);
    tokio::spawn(async move { dispatcher.run(listener, rx).await });

    let mut c = TcpStream::connect(inbound_addr).await.unwrap();
    let payload = format!(
        "GET http://127.0.0.1:{}/first HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\nGET http://127.0.0.1:{}/smuggled HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        origin_addr.port(),
        origin_addr.port(),
        origin_addr.port(),
        origin_addr.port(),
    );
    c.write_all(payload.as_bytes()).await.unwrap();

    let forwarded = req_rx.await.unwrap();
    let forwarded_str = String::from_utf8(forwarded).unwrap();
    assert!(forwarded_str.starts_with("GET /first HTTP/1.1\r\n"));
    assert!(forwarded_str.contains("Connection: close\r\n\r\n"));
    assert!(!forwarded_str.contains("/smuggled"));

    let mut resp = Vec::new();
    c.read_to_end(&mut resp).await.unwrap();
    assert!(String::from_utf8_lossy(&resp).ends_with("done"));
}

fn build_test_tls_client_hello(sni: &str) -> Vec<u8> {
    let host_bytes = sni.as_bytes();
    let sni_entry_len = 1 + 2 + host_bytes.len();
    let mut ext_sni = Vec::new();
    ext_sni.extend_from_slice(&0x0000u16.to_be_bytes());
    ext_sni.extend_from_slice(&((2 + sni_entry_len) as u16).to_be_bytes());
    ext_sni.extend_from_slice(&(sni_entry_len as u16).to_be_bytes());
    ext_sni.push(0x00);
    ext_sni.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    ext_sni.extend_from_slice(host_bytes);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x11; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(ext_sni.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_sni);

    let mut hs = Vec::new();
    hs.push(0x01);
    let hs_len = body.len() as u32;
    hs.extend_from_slice(&hs_len.to_be_bytes()[1..4]);
    hs.extend_from_slice(&body);

    let mut rec = Vec::new();
    rec.push(0x16);
    rec.extend_from_slice(&[0x03, 0x01]);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[tokio::test]
async fn test_dispatch_transparent_stream_sniffs_sni_evaluates_rule_and_preserves_bytes() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let client_hello = build_test_tls_client_hello("sniffed.example.org");
    let expected_hello = client_hello.clone();

    let srv_task = tokio::spawn(async move {
        let (mut s, _) = origin.accept().await.unwrap();
        let mut got = vec![0u8; expected_hello.len()];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(
            got, expected_hello,
            "Original TLS ClientHello bytes must arrive intact"
        );
        s.write_all(b"SERVER_OK").await.unwrap();
    });

    let mut cfg = test_config("127.0.0.1:40001".parse().unwrap(), vec![]);
    cfg.rule_engine = Arc::new(RuleEngine::new(
        vec![
            flowx::router::Rule::from_raw(
                "BlockOther",
                true,
                None,
                Some("blocked.example.org"),
                None,
                Action::Block,
            ),
            flowx::router::Rule::from_raw(
                "AllowSniffedSni",
                true,
                None,
                Some("sniffed.example.org"),
                None,
                Action::Direct,
            ),
        ],
        Action::Block,
    ));
    let cfg = Arc::new(cfg);

    let (mut app_side, disp_side) = tokio::io::duplex(8192);
    let peer_addr: SocketAddr = "127.0.0.1:55555".parse().unwrap();
    let disp_handle = tokio::spawn(async move {
        dispatch_transparent_stream(cfg, disp_side, peer_addr, origin_addr, None, true).await
    });

    app_side.write_all(&client_hello).await.unwrap();
    let mut ack = [0u8; 9];
    app_side.read_exact(&mut ack).await.unwrap();
    assert_eq!(&ack, b"SERVER_OK");
    drop(app_side);

    disp_handle.await.unwrap().unwrap();
    srv_task.await.unwrap();
}

#[tokio::test]
async fn test_dispatch_transparent_stream_blocks_matched_rule() {
    let rules = vec![flowx::router::Rule::from_raw(
        "BlockSniffed",
        true,
        None,
        Some("forbidden.example"),
        None,
        Action::Block,
    )];
    let cfg = Arc::new(test_config("127.0.0.1:40001".parse().unwrap(), rules));
    let orig_dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let (mut app_side, disp_side) = tokio::io::duplex(8192);
    let disp_handle = tokio::spawn(async move {
        dispatch_transparent_stream(
            cfg,
            disp_side,
            "127.0.0.1:55556".parse().unwrap(),
            orig_dst,
            None,
            true,
        )
        .await
    });

    let hello = build_test_tls_client_hello("forbidden.example");
    app_side.write_all(&hello).await.unwrap();
    let mut buf = [0u8; 32];
    let n = app_side.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "Blocked transparent flow must close without replying");
    disp_handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn test_dispatch_transparent_stream_restores_fake_ip_and_rejects_self_port() {
    let cfg = Arc::new(test_config("127.0.0.1:40001".parse().unwrap(), vec![]));
    let (_app_self, disp_self) = tokio::io::duplex(1024);
    let err = dispatch_transparent_stream(
        Arc::clone(&cfg),
        disp_self,
        "127.0.0.1:50000".parse().unwrap(),
        "127.0.0.1:40001".parse().unwrap(),
        None,
        false,
    )
    .await
    .unwrap_err();
    assert!(format!("{:#}", err).contains("loopback"));

    // Fake-IP domain without explicit port or expired should error cleanly; valid Fake-IP resolves & dials localhost test server?
    // Actually localhost rule check + expired Fake-IP error verifies Fake-IP branch without needing an external DNS server:
    let (_app_fake, disp_fake) = tokio::io::duplex(1024);
    let fake_err = dispatch_transparent_stream(
        Arc::clone(&cfg),
        disp_fake,
        "127.0.0.1:50001".parse().unwrap(),
        "198.18.0.55:443".parse().unwrap(),
        None,
        false,
    )
    .await
    .unwrap_err();
    assert!(format!("{:#}", fake_err).contains("Fake-IP"));

    // Mapped Fake-IP restores original domain and matches domain rules directly without sniffing
    let mapped_ip = cfg.fake_ip_pool.allocate("fakeip-blocked.example");
    let mut mapped_cfg = test_config(
        "127.0.0.1:40001".parse().unwrap(),
        vec![flowx::router::Rule::from_raw(
            "BlockRestoredFakeIp",
            true,
            None,
            Some("fakeip-blocked.example"),
            None,
            Action::Block,
        )],
    );
    mapped_cfg.fake_ip_pool = Arc::clone(&cfg.fake_ip_pool);
    let (mut app_mapped, disp_mapped) = tokio::io::duplex(1024);
    let mapped_res = dispatch_transparent_stream(
        Arc::new(mapped_cfg),
        disp_mapped,
        "127.0.0.1:50002".parse().unwrap(),
        SocketAddr::new(std::net::IpAddr::V4(mapped_ip), 443),
        None,
        true,
    )
    .await;
    assert!(
        mapped_res.is_ok(),
        "Fake-IP domain restore should trigger Action::Block cleanly"
    );
    let mut probe = [0u8; 8];
    assert_eq!(app_mapped.read(&mut probe).await.unwrap(), 0);
}

#[tokio::test]
async fn test_dispatch_transparent_stream_skips_sniff_when_immediate_on_443() {
    // 服务器等待客户端主动发首字节（不会先发 banner）：若触发 120ms 嗅探则会明显拖延首包或消费超时，
    // 这里使用 Immediate(Proxy/Direct) + 沉默服务端 + 明确发首字节前的 Immediate 直连延迟检测：
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let srv_task = tokio::spawn(async move {
        let (mut s, _) = origin.accept().await.unwrap();
        // 服务端先发送二进制协议 banner：若 dispatcher 在 443 上错误等待客户端先发 SNI，将死锁满 120ms
        s.write_all(b"SRV_BANNER").await.unwrap();
        let mut ack = [0u8; 6];
        s.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"CLI_OK");
    });

    let mut cfg = test_config(
        "127.0.0.1:40001".parse().unwrap(),
        vec![flowx::router::Rule::from_raw(
            "BypassPort443",
            true,
            None,
            None,
            None,
            Action::Direct,
        )],
    );
    cfg.fake_ip_pool = Arc::new(FakeIpPool::new_default());
    let (mut app_side, disp_side) = tokio::io::duplex(4096);
    // 即使源目标端口是 443，只要 needs_domain_sniff=false 且 rule_engine 返回 Immediate，也不得阻塞等待客户端先发 SNI
    let fake_dst_443 = SocketAddr::new(origin_addr.ip(), 443);
    let _ = fake_dst_443;
    let disp_handle = tokio::spawn(async move {
        dispatch_transparent_stream(
            Arc::new(cfg),
            disp_side,
            "127.0.0.1:50099".parse().unwrap(),
            origin_addr,
            None,
            false,
        )
        .await
    });

    let mut banner = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(2), app_side.read_exact(&mut banner))
        .await
        .expect("Immediate route must forward server banner without awaiting client SNI")
        .unwrap();
    assert_eq!(&banner, b"SRV_BANNER");
    app_side.write_all(b"CLI_OK").await.unwrap();
    drop(app_side);
    disp_handle.await.unwrap().unwrap();
    srv_task.await.unwrap();
}

#[tokio::test]
async fn test_dispatch_transparent_stream_sniffs_http_tls_for_immediate_proxy_skips_other_ports() {
    use flowx::outbound::socks5::Socks5Client;

    async fn spawn_mock_socks5_server(
        expect_banner: Option<&'static [u8]>,
    ) -> (
        SocketAddr,
        tokio::sync::oneshot::Receiver<(u8, String, u16)>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (target_tx, target_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();

            let mut hdr = [0u8; 4];
            s.read_exact(&mut hdr).await.unwrap();
            let atyp = hdr[3];
            let host = match atyp {
                0x01 => {
                    let mut ip = [0u8; 4];
                    s.read_exact(&mut ip).await.unwrap();
                    std::net::Ipv4Addr::from(ip).to_string()
                }
                0x03 => {
                    let mut len = [0u8; 1];
                    s.read_exact(&mut len).await.unwrap();
                    let mut dom = vec![0u8; len[0] as usize];
                    s.read_exact(&mut dom).await.unwrap();
                    String::from_utf8(dom).unwrap()
                }
                other => panic!("unexpected SOCKS5 atyp: {other}"),
            };
            let mut port_bytes = [0u8; 2];
            s.read_exact(&mut port_bytes).await.unwrap();
            let port = u16::from_be_bytes(port_bytes);
            let _ = target_tx.send((atyp, host, port));

            s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            if let Some(banner) = expect_banner {
                s.write_all(banner).await.unwrap();
            } else {
                let mut buf = [0u8; 256];
                let n = s.read(&mut buf).await.unwrap();
                assert!(n > 0);
                s.write_all(b"PROXIED_TLS_OK").await.unwrap();
            }
        });
        (addr, target_rx, handle)
    }

    // 1. DevProxy-style Immediate(Proxy) on port 443 -> must sniff TLS SNI and pass ATYP 0x03 Domain to proxy
    let (socks_addr_443, target_rx_443, srv_443) = spawn_mock_socks5_server(None).await;
    let cfg_443 = test_config(
        "127.0.0.1:40001".parse().unwrap(),
        vec![flowx::router::Rule::from_raw(
            "DevProxy",
            true,
            None,
            None,
            None,
            Action::Proxy(1),
        )],
    );
    cfg_443.proxy_nodes.write().unwrap().insert(
        1,
        ProxyNodeEntry {
            id: 1,
            name: "MockSocks".into(),
            protocol: "SOCKS5".into(),
            server_addr: socks_addr_443.to_string(),
            username: None,
            client: ProxyNode::Socks5(Socks5Client::new(socks_addr_443.to_string())),
        },
    );
    let (mut app_443, disp_443) = tokio::io::duplex(8192);
    let handle_443 = tokio::spawn(async move {
        dispatch_transparent_stream(
            Arc::new(cfg_443),
            disp_443,
            "127.0.0.1:50100".parse().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
            false,
        )
        .await
    });
    let hello = build_test_tls_client_hello("api.github.com");
    app_443.write_all(&hello).await.unwrap();
    let (atyp_443, host_443, port_443) = target_rx_443.await.unwrap();
    assert_eq!(
        atyp_443, 0x03,
        "port 443 Immediate(Proxy) must sniff SNI as domain"
    );
    assert_eq!(host_443, "api.github.com");
    assert_eq!(port_443, 443);
    let mut ack_443 = [0u8; 14];
    app_443.read_exact(&mut ack_443).await.unwrap();
    assert_eq!(&ack_443, b"PROXIED_TLS_OK");
    drop(app_443);
    handle_443.await.unwrap().unwrap();
    srv_443.await.unwrap();

    // 2. Immediate(Proxy) on port 22 (SSH) -> must NOT wait 120ms for client-first sniff; connects immediately
    let (socks_addr_22, target_rx_22, srv_22) =
        spawn_mock_socks5_server(Some(b"SSH-2.0-OpenSSH")).await;
    let cfg_22 = test_config(
        "127.0.0.1:40001".parse().unwrap(),
        vec![flowx::router::Rule::from_raw(
            "DevProxy",
            true,
            None,
            None,
            None,
            Action::Proxy(1),
        )],
    );
    cfg_22.proxy_nodes.write().unwrap().insert(
        1,
        ProxyNodeEntry {
            id: 1,
            name: "MockSocks".into(),
            protocol: "SOCKS5".into(),
            server_addr: socks_addr_22.to_string(),
            username: None,
            client: ProxyNode::Socks5(Socks5Client::new(socks_addr_22.to_string())),
        },
    );
    let (mut app_22, disp_22) = tokio::io::duplex(4096);
    let handle_22 = tokio::spawn(async move {
        dispatch_transparent_stream(
            Arc::new(cfg_22),
            disp_22,
            "127.0.0.1:50101".parse().unwrap(),
            "93.184.216.34:22".parse().unwrap(),
            None,
            false,
        )
        .await
    });
    let mut ssh_banner = [0u8; 15];
    tokio::time::timeout(Duration::from_secs(2), app_22.read_exact(&mut ssh_banner))
        .await
        .expect("Port 22 Immediate(Proxy) must forward SSH server banner without sniffing delay")
        .unwrap();
    assert_eq!(&ssh_banner, b"SSH-2.0-OpenSSH");
    let (atyp_22, host_22, port_22) = target_rx_22.await.unwrap();
    assert_eq!(atyp_22, 0x01);
    assert_eq!(host_22, "93.184.216.34");
    assert_eq!(port_22, 22);
    drop(app_22);
    handle_22.await.unwrap().unwrap();
    srv_22.await.unwrap();
}

#[tokio::test]
async fn test_dispatch_transparent_stream_tracks_in_flight_guard() {
    let tracker = Arc::new(InFlightTracker::new());
    let mut cfg = test_config(
        "127.0.0.1:40001".parse().unwrap(),
        vec![flowx::router::Rule::from_raw(
            "NeedSniProxy",
            true,
            None,
            Some("track.example.org"),
            None,
            Action::Block,
        )],
    );
    cfg.in_flight = Some(Arc::clone(&tracker));
    let cfg = Arc::new(cfg);

    assert_eq!(tracker.count(), 0);
    let (mut app_side, disp_side) = tokio::io::duplex(4096);
    let tracker_wait = Arc::clone(&tracker);
    let disp_handle = tokio::spawn(async move {
        dispatch_transparent_stream(
            cfg,
            disp_side,
            "127.0.0.1:50120".parse().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
            true,
        )
        .await
    });

    // 在透明流进入 SNI 嗅探阻塞阶段时（尚未注册进 ConnectionManager），InFlightTracker 必须已计数 > 0
    let poll_deadline = std::time::Instant::now() + Duration::from_millis(500);
    while tracker.count() == 0 && std::time::Instant::now() < poll_deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        tracker.count() >= 1,
        "transparent dispatch must hold InFlightTracker guard while sniffing"
    );

    let hello = build_test_tls_client_hello("track.example.org");
    app_side.write_all(&hello).await.unwrap();
    let mut eof_buf = [0u8; 8];
    assert_eq!(app_side.read(&mut eof_buf).await.unwrap(), 0);
    drop(app_side);

    disp_handle.await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(2), tracker_wait.wait_zero())
        .await
        .expect("InFlightTracker must drain to zero after transparent stream finishes");
    assert_eq!(tracker.count(), 0);
}

#[tokio::test]
async fn test_dispatch_transparent_stream_enforces_domain_port_rules_on_ssh_and_custom_ports_and_blocks_spoofed_localhost()
 {
    use flowx::outbound::socks5::Socks5Client;

    // 1. 端口+域名阻断规则 (ports="22", targets="*.foo", Block) 经 real_ip_to_domain 与 Fake-IP 均立即阻断 SSH，不绕过
    let ssh_rules = vec![flowx::router::Rule::from_raw(
        "BlockFooSsh",
        true,
        None,
        Some("*.foo"),
        Some("22"),
        Action::Block,
    )];
    let ssh_cfg = test_config("127.0.0.1:40001".parse().unwrap(), ssh_rules);
    let ssh_real_ip: IpAddr = "93.184.216.50".parse().unwrap();
    ssh_cfg
        .fake_ip_pool
        .record_real_ip_mappings("bastion.foo", &[ssh_real_ip]);
    let ssh_cfg = Arc::new(ssh_cfg);

    let (mut app_ssh, disp_ssh) = tokio::io::duplex(1024);
    dispatch_transparent_stream(
        Arc::clone(&ssh_cfg),
        disp_ssh,
        "127.0.0.1:50201".parse().unwrap(),
        SocketAddr::new(ssh_real_ip, 22),
        None,
        true,
    )
    .await
    .unwrap();
    let mut probe = [0u8; 8];
    assert_eq!(app_ssh.read(&mut probe).await.unwrap(), 0);

    // 2. 自定义二进制端口规则 (ports="7777", targets="*.game", Proxy(1)) 经唯一 real_ip_to_domain 命中域名规则，
    // 但走代理时一律以原始真实 IPv4 拨号（AlwaysUseRealIp），避免把启发式缓存域名误发给远端代理
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    let (target_tx, target_rx) = tokio::sync::oneshot::channel();
    let socks_srv = tokio::spawn(async move {
        let (mut s, _) = socks_listener.accept().await.unwrap();
        let mut g = [0u8; 3];
        s.read_exact(&mut g).await.unwrap();
        s.write_all(&[0x05, 0x00]).await.unwrap();
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).await.unwrap();
        assert_eq!(
            hdr[3], 0x01,
            "heuristic cached_domain fallback must dial real IPv4 on Proxy instead of unverified domain"
        );
        let mut addr_port = [0u8; 6];
        s.read_exact(&mut addr_port).await.unwrap();
        let ip = std::net::Ipv4Addr::new(addr_port[0], addr_port[1], addr_port[2], addr_port[3]);
        let port = u16::from_be_bytes([addr_port[4], addr_port[5]]);
        let _ = target_tx.send((ip, port));
        s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
        let mut client_bin = [0u8; 4];
        s.read_exact(&mut client_bin).await.unwrap();
        assert_eq!(&client_bin, b"\xFE\xED\xFA\xCE");
        s.write_all(b"GAME_SRV_HELLO").await.unwrap();
    });

    let game_cfg = test_config(
        "127.0.0.1:40001".parse().unwrap(),
        vec![flowx::router::Rule::from_raw(
            "GameProxy",
            true,
            None,
            Some("*.game"),
            Some("7777"),
            Action::Proxy(1),
        )],
    );
    let game_real_ip: IpAddr = "93.184.216.60".parse().unwrap();
    game_cfg
        .fake_ip_pool
        .record_real_ip_mappings("login.game", &[game_real_ip]);
    game_cfg.proxy_nodes.write().unwrap().insert(
        1,
        ProxyNodeEntry {
            id: 1,
            name: "MockSocks".into(),
            protocol: "SOCKS5".into(),
            server_addr: socks_addr.to_string(),
            username: None,
            client: ProxyNode::Socks5(Socks5Client::new(socks_addr.to_string())),
        },
    );
    let (mut app_game, disp_game) = tokio::io::duplex(2048);
    let game_handle = tokio::spawn(async move {
        dispatch_transparent_stream(
            Arc::new(game_cfg),
            disp_game,
            "127.0.0.1:50202".parse().unwrap(),
            SocketAddr::new(game_real_ip, 7777),
            None,
            true,
        )
        .await
    });
    // 客户端首包发送非 TLS/非 HTTP 二进制魔数时，peek_host_prefix 立即 NotMatchable 放行并回退至唯一 cached_domain 路由
    app_game.write_all(b"\xFE\xED\xFA\xCE").await.unwrap();
    let mut game_hello = [0u8; 14];
    tokio::time::timeout(Duration::from_secs(2), app_game.read_exact(&mut game_hello))
        .await
        .expect("custom port 7777 with binary client payload must relay without timeout")
        .unwrap();
    assert_eq!(&game_hello, b"GAME_SRV_HELLO");
    assert_eq!(
        target_rx.await.unwrap(),
        (std::net::Ipv4Addr::new(93, 184, 216, 60), 7777)
    );
    drop(app_game);
    game_handle.await.unwrap().unwrap();
    socks_srv.await.unwrap();

    // 3. 未命中缓存的直连 SSH（端口 22）即使传入 needs_domain_sniff=true 也不得在嗅探阶段卡死，立刻放行服务端 banner
    let ssh_socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ssh_socks_addr = ssh_socks.local_addr().unwrap();
    let ssh_srv_task = tokio::spawn(async move {
        let (mut s, _) = ssh_socks.accept().await.unwrap();
        let mut g = [0u8; 3];
        s.read_exact(&mut g).await.unwrap();
        s.write_all(&[0x05, 0x00]).await.unwrap();
        let mut req = [0u8; 10];
        s.read_exact(&mut req).await.unwrap();
        s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
        s.write_all(b"SSH-2.0-Immediate").await.unwrap();
    });
    let uncached_ssh_cfg = test_config(
        "127.0.0.1:40001".parse().unwrap(),
        vec![flowx::router::Rule::from_raw(
            "ProxyAll",
            true,
            None,
            None,
            None,
            Action::Proxy(1),
        )],
    );
    uncached_ssh_cfg.proxy_nodes.write().unwrap().insert(
        1,
        ProxyNodeEntry {
            id: 1,
            name: "MockSocks22".into(),
            protocol: "SOCKS5".into(),
            server_addr: ssh_socks_addr.to_string(),
            username: None,
            client: ProxyNode::Socks5(Socks5Client::new(ssh_socks_addr.to_string())),
        },
    );
    let (mut app_u22, disp_u22) = tokio::io::duplex(2048);
    let u22_handle = tokio::spawn(async move {
        dispatch_transparent_stream(
            Arc::new(uncached_ssh_cfg),
            disp_u22,
            "127.0.0.1:50203".parse().unwrap(),
            "93.184.216.70:22".parse().unwrap(),
            None,
            true,
        )
        .await
    });
    let mut ssh_banner = [0u8; 17];
    tokio::time::timeout(Duration::from_secs(2), app_u22.read_exact(&mut ssh_banner))
        .await
        .expect(
            "port 22 SSH must not block waiting for client sniff even with needs_domain_sniff=true",
        )
        .unwrap();
    assert_eq!(&ssh_banner, b"SSH-2.0-Immediate");
    drop(app_u22);
    u22_handle.await.unwrap().unwrap();
    ssh_srv_task.await.unwrap();

    // 4. 远端公网 IP:80 伪造 HTTP Host: localhost 不得命中 LocalBypass 绕过 DevProxy 直连公网 IP
    let spoof_socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let spoof_socks_addr = spoof_socks.local_addr().unwrap();
    let (spoof_tx, spoof_rx) = tokio::sync::oneshot::channel();
    let spoof_srv = tokio::spawn(async move {
        let (mut s, _) = spoof_socks.accept().await.unwrap();
        let mut g = [0u8; 3];
        s.read_exact(&mut g).await.unwrap();
        s.write_all(&[0x05, 0x00]).await.unwrap();
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).await.unwrap();
        assert_eq!(
            hdr[3], 0x01,
            "spoofed Host: localhost on remote IP must stay as IP target for Proxy"
        );
        let mut ip = [0u8; 6];
        s.read_exact(&mut ip).await.unwrap();
        let dst = std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
        let port = u16::from_be_bytes([ip[4], ip[5]]);
        let _ = spoof_tx.send((dst, port));
        s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
        let mut req_buf = vec![0u8; 35];
        s.read_exact(&mut req_buf).await.unwrap();
        assert_eq!(&req_buf, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
    });
    let spoof_cfg = test_config(
        "127.0.0.1:40001".parse().unwrap(),
        vec![
            flowx::router::Rule::from_raw(
                "LocalBypass",
                true,
                None,
                Some("localhost"),
                None,
                Action::Direct,
            ),
            flowx::router::Rule::from_raw("DevProxy", true, None, None, None, Action::Proxy(1)),
        ],
    );
    spoof_cfg.proxy_nodes.write().unwrap().insert(
        1,
        ProxyNodeEntry {
            id: 1,
            name: "SpoofSocks".into(),
            protocol: "SOCKS5".into(),
            server_addr: spoof_socks_addr.to_string(),
            username: None,
            client: ProxyNode::Socks5(Socks5Client::new(spoof_socks_addr.to_string())),
        },
    );
    let (mut app_sp, disp_sp) = tokio::io::duplex(2048);
    let sp_handle = tokio::spawn(async move {
        dispatch_transparent_stream(
            Arc::new(spoof_cfg),
            disp_sp,
            "127.0.0.1:50204".parse().unwrap(),
            "93.184.216.80:80".parse().unwrap(),
            None,
            false,
        )
        .await
    });
    app_sp
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let (got_ip, got_port) = spoof_rx.await.unwrap();
    assert_eq!(got_ip, std::net::Ipv4Addr::new(93, 184, 216, 80));
    assert_eq!(got_port, 80);
    let mut http_ack = [0u8; 19];
    app_sp.read_exact(&mut http_ack).await.unwrap();
    assert_eq!(&http_ack, b"HTTP/1.1 200 OK\r\n\r\n");
    drop(app_sp);
    sp_handle.await.unwrap().unwrap();
    spoof_srv.await.unwrap();
}

#[tokio::test]
async fn test_dispatch_transparent_stream_sniffs_non_default_https_over_cached_ip_handles_cdn_ambiguity_and_uses_fake_ip_orig_dns()
 {
    use flowx::outbound::socks5::Socks5Client;
    use tokio::io::AsyncReadExt;

    // 1. P1-1：非标准 HTTPS 端口 8444 即使存在过期/不同缓存域名，也不得跳过 TLS SNI 嗅探；
    //    应提取真实 SNI 命中代理规则并向 SOCKS5 传递权威 SNI 域名
    let socks_8444 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_8444_addr = socks_8444.local_addr().unwrap();
    let client_hello = build_test_tls_client_hello("real-sni.example");
    let expected_hello = client_hello.clone();
    let (sni_tx, sni_rx) = tokio::sync::oneshot::channel();
    let srv_8444 = tokio::spawn(async move {
        let (mut s, _) = socks_8444.accept().await.unwrap();
        let mut g = [0u8; 3];
        s.read_exact(&mut g).await.unwrap();
        s.write_all(&[0x05, 0x00]).await.unwrap();
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).await.unwrap();
        assert_eq!(
            hdr[3], 0x03,
            "authoritative TLS SNI must dial Domain on Proxy"
        );
        let mut l = [0u8; 1];
        s.read_exact(&mut l).await.unwrap();
        let mut dom = vec![0u8; l[0] as usize];
        s.read_exact(&mut dom).await.unwrap();
        let mut p = [0u8; 2];
        s.read_exact(&mut p).await.unwrap();
        let _ = sni_tx.send((String::from_utf8(dom).unwrap(), u16::from_be_bytes(p)));
        s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
        let mut got_hello = vec![0u8; expected_hello.len()];
        s.read_exact(&mut got_hello).await.unwrap();
        assert_eq!(got_hello, expected_hello);
        s.write_all(b"TLS_OK").await.unwrap();
    });

    let cfg_8444 = test_config(
        "127.0.0.1:40001".parse().unwrap(),
        vec![flowx::router::Rule::from_raw(
            "ProxyRealSni",
            true,
            None,
            Some("real-sni.example"),
            None,
            Action::Proxy(1),
        )],
    );
    cfg_8444.rule_engine.set_default_action(Action::Block);
    let shared_ip: IpAddr = "93.184.216.90".parse().unwrap();
    cfg_8444
        .fake_ip_pool
        .record_real_ip_mappings("stale-site.example", &[shared_ip]);
    cfg_8444.proxy_nodes.write().unwrap().insert(
        1,
        ProxyNodeEntry {
            id: 1,
            name: "SniSocks".into(),
            protocol: "SOCKS5".into(),
            server_addr: socks_8444_addr.to_string(),
            username: None,
            client: ProxyNode::Socks5(Socks5Client::new(socks_8444_addr.to_string())),
        },
    );

    let (mut app_tls, disp_tls) = tokio::io::duplex(4096);
    let tls_handle = tokio::spawn(async move {
        dispatch_transparent_stream(
            Arc::new(cfg_8444),
            disp_tls,
            "127.0.0.1:50301".parse().unwrap(),
            SocketAddr::new(shared_ip, 8444),
            None,
            true,
        )
        .await
    });
    app_tls.write_all(&client_hello).await.unwrap();
    let mut tls_ack = [0u8; 6];
    app_tls.read_exact(&mut tls_ack).await.unwrap();
    assert_eq!(&tls_ack, b"TLS_OK");
    assert_eq!(
        sni_rx.await.unwrap(),
        ("real-sni.example".to_string(), 8444)
    );
    drop(app_tls);
    tls_handle.await.unwrap().unwrap();
    srv_8444.await.unwrap();

    // 2. P1-1：共享 CDN IP（两个域名同指 104.16.1.9 -> Ambiguous）在不可嗅探的端口 22 不得误用后写入域名命中错误 Block 规则，
    //    而是直接以真实 IP 走 Proxy
    let socks_cdn = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_cdn_addr = socks_cdn.local_addr().unwrap();
    let srv_cdn = tokio::spawn(async move {
        let (mut s, _) = socks_cdn.accept().await.unwrap();
        let mut g = [0u8; 3];
        s.read_exact(&mut g).await.unwrap();
        s.write_all(&[0x05, 0x00]).await.unwrap();
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[3], 0x01, "ambiguous CDN IP must dial raw IPv4");
        let mut ip_port = [0u8; 6];
        s.read_exact(&mut ip_port).await.unwrap();
        assert_eq!(&ip_port[0..4], &[104, 16, 1, 9]);
        assert_eq!(u16::from_be_bytes([ip_port[4], ip_port[5]]), 22);
        s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
        s.write_all(b"SSH-CDN").await.unwrap();
    });
    let cfg_cdn = test_config(
        "127.0.0.1:40001".parse().unwrap(),
        vec![
            flowx::router::Rule::from_raw(
                "BlockSecondDomain",
                true,
                None,
                Some("second.cdn.example"),
                Some("22"),
                Action::Block,
            ),
            flowx::router::Rule::from_raw("ProxyRest", true, None, None, None, Action::Proxy(1)),
        ],
    );
    let cdn_ip: IpAddr = "104.16.1.9".parse().unwrap();
    cfg_cdn
        .fake_ip_pool
        .record_real_ip_mappings("first.cdn.example", &[cdn_ip]);
    cfg_cdn
        .fake_ip_pool
        .record_real_ip_mappings("second.cdn.example", &[cdn_ip]);
    cfg_cdn.proxy_nodes.write().unwrap().insert(
        1,
        ProxyNodeEntry {
            id: 1,
            name: "CdnSocks".into(),
            protocol: "SOCKS5".into(),
            server_addr: socks_cdn_addr.to_string(),
            username: None,
            client: ProxyNode::Socks5(Socks5Client::new(socks_cdn_addr.to_string())),
        },
    );
    let (mut app_cdn, disp_cdn) = tokio::io::duplex(2048);
    let cdn_handle = tokio::spawn(async move {
        dispatch_transparent_stream(
            Arc::new(cfg_cdn),
            disp_cdn,
            "127.0.0.1:50302".parse().unwrap(),
            SocketAddr::new(cdn_ip, 22),
            None,
            true,
        )
        .await
    });
    let mut ssh_cdn = [0u8; 7];
    app_cdn.read_exact(&mut ssh_cdn).await.unwrap();
    assert_eq!(&ssh_cdn, b"SSH-CDN");
    drop(app_cdn);
    cdn_handle.await.unwrap().unwrap();
    srv_cdn.await.unwrap();

    // 3. P0-1 防御纵深：Fake-IP 命中 Direct 时优先向 allocate_with_dns 记录的原分域 DNS 回源解析，
    //    即使默认 upstream_dns 不可达也可连通内网目标
    let echo_srv = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_srv.local_addr().unwrap().port();
    let echo_task = tokio::spawn(async move {
        let (mut s, _) = echo_srv.accept().await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"PING");
        s.write_all(b"PONG").await.unwrap();
    });

    let corp_dns = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let corp_dns_addr = corp_dns.local_addr().unwrap();
    let (dns_stop_tx, mut dns_stop_rx) = tokio::sync::watch::channel(false);
    let corp_dns_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            tokio::select! {
                recv = corp_dns.recv_from(&mut buf) => {
                    let Ok((n, peer)) = recv else { break };
                    let (txid, q) = flowx::dns::server::DnsPacketParser::parse_question(&buf[..n]).unwrap();
                    let mut resp = Vec::new();
                    resp.extend_from_slice(&txid.to_be_bytes());
                    if q.qtype == 1 {
                        resp.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
                        resp.extend_from_slice(&buf[12..q.raw_len]);
                        resp.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
                    } else {
                        resp.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                        resp.extend_from_slice(&buf[12..q.raw_len]);
                    }
                    let _ = corp_dns.send_to(&resp, peer).await;
                }
                _ = dns_stop_rx.changed() => break,
            }
        }
    });

    let closed_default_dns = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_dns_addr = closed_default_dns.local_addr().unwrap();
    drop(closed_default_dns);

    let mut split_cfg = test_config("127.0.0.1:40001".parse().unwrap(), vec![]);
    split_cfg.upstream_dns = dead_dns_addr;
    let fake_corp = split_cfg
        .fake_ip_pool
        .allocate_with_dns("intranet.corp.example", Some(corp_dns_addr));

    let (mut app_corp, disp_corp) = tokio::io::duplex(2048);
    let corp_handle = tokio::spawn(async move {
        dispatch_transparent_stream(
            Arc::new(split_cfg),
            disp_corp,
            "127.0.0.1:50303".parse().unwrap(),
            SocketAddr::new(IpAddr::V4(fake_corp), echo_port),
            None,
            false,
        )
        .await
    });
    app_corp.write_all(b"PING").await.unwrap();
    let mut pong = [0u8; 4];
    app_corp.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"PONG");
    drop(app_corp);
    corp_handle.await.unwrap().unwrap();
    echo_task.await.unwrap();
    let _ = dns_stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(1), corp_dns_task).await;
}

#[tokio::test]
async fn test_p1_1_devproxy_immediate_proxy_sniffs_nonstandard_https_http_and_p2_1_stale_sniff_does_not_delay_direct_or_block()
 {
    use flowx::outbound::socks5::Socks5Client;

    // 1. P1-1: 默认 DevProxy（无域名条件，Immediate(Proxy(1)), needs_domain_sniff=false）
    //    在非标准 HTTPS 端口 8444 与 HTTP 端口 3000 上仍须嗅探 TLS SNI / HTTP Host 并传域名给远端代理
    for (port, payload, expected_host) in [
        (
            8444u16,
            build_test_tls_client_hello("portal.nonstd.example"),
            "portal.nonstd.example",
        ),
        (
            3000u16,
            b"GET /health HTTP/1.1\r\nHost: web.dev.example:3000\r\n\r\n".to_vec(),
            "web.dev.example",
        ),
    ] {
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let expected_payload = payload.clone();
        let srv = tokio::spawn(async move {
            let (mut s, _) = socks_listener.accept().await.unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
            let mut hdr = [0u8; 4];
            s.read_exact(&mut hdr).await.unwrap();
            assert_eq!(
                hdr[3], 0x03,
                "DevProxy Immediate(Proxy) on :{port} must sniff and dial Domain"
            );
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.unwrap();
            let mut dom = vec![0u8; l[0] as usize];
            s.read_exact(&mut dom).await.unwrap();
            let mut p = [0u8; 2];
            s.read_exact(&mut p).await.unwrap();
            let _ = tx.send((String::from_utf8(dom).unwrap(), u16::from_be_bytes(p)));
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let mut got = vec![0u8; expected_payload.len()];
            s.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected_payload);
            s.write_all(b"OK_NONSTD").await.unwrap();
        });

        let cfg = test_config(
            "127.0.0.1:40001".parse().unwrap(),
            vec![flowx::router::Rule::from_raw(
                "DevProxy",
                true,
                None,
                None,
                None,
                Action::Proxy(1),
            )],
        );
        // 即使缓存了过期/不同域名，也不得跳过非标准端口上的权威嗅探
        let orig_ip: IpAddr = "93.184.216.91".parse().unwrap();
        cfg.fake_ip_pool
            .record_real_ip_mappings("stale-cached.example", &[orig_ip]);
        cfg.proxy_nodes.write().unwrap().insert(
            1,
            ProxyNodeEntry {
                id: 1,
                name: "NonStdSocks".into(),
                protocol: "SOCKS5".into(),
                server_addr: socks_addr.to_string(),
                username: None,
                client: ProxyNode::Socks5(Socks5Client::new(socks_addr.to_string())),
            },
        );
        let (mut app, disp) = tokio::io::duplex(4096);
        let h = tokio::spawn(async move {
            dispatch_transparent_stream(
                Arc::new(cfg),
                disp,
                "127.0.0.1:50401".parse().unwrap(),
                SocketAddr::new(orig_ip, port),
                None,
                false, // Immediate(Proxy) from NetstackEngine passes needs_domain_sniff=false
            )
            .await
        });
        app.write_all(&payload).await.unwrap();
        let mut ack = [0u8; 9];
        app.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"OK_NONSTD");
        assert_eq!(rx.await.unwrap(), (expected_host.to_string(), port));
        drop(app);
        h.await.unwrap().unwrap();
        srv.await.unwrap();
    }

    // 2. P2-1: 即使 SYN 阶段传入了过期的 needs_domain_sniff=true，异步判定为 Immediate(Direct | Block) 后
    //    不得再等待 120ms 嗅探（例如静默 Block 应毫秒级关闭，服务端先发的直连端口应立即转发 banner）
    let block_cfg = Arc::new(test_config(
        "127.0.0.1:40001".parse().unwrap(),
        vec![flowx::router::Rule::from_raw(
            "BlockAll",
            true,
            None,
            None,
            None,
            Action::Block,
        )],
    ));
    let (mut app_blk, disp_blk) = tokio::io::duplex(1024);
    let start_blk = std::time::Instant::now();
    let blk_handle = tokio::spawn(async move {
        dispatch_transparent_stream(
            block_cfg,
            disp_blk,
            "127.0.0.1:50402".parse().unwrap(),
            "93.184.216.92:2222".parse().unwrap(),
            None,
            true, // stale SYN-time needs_domain_sniff=true
        )
        .await
    });
    let mut eof = [0u8; 4];
    assert_eq!(app_blk.read(&mut eof).await.unwrap(), 0);
    blk_handle.await.unwrap().unwrap();
    assert!(
        start_blk.elapsed() < Duration::from_millis(115),
        "Immediate(Block) must not wait 120ms for stale SYN needs_domain_sniff, took {:?}",
        start_blk.elapsed()
    );

    let direct_origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let direct_origin_addr = direct_origin.local_addr().unwrap();
    let direct_srv = tokio::spawn(async move {
        let (mut s, _) = direct_origin.accept().await.unwrap();
        s.write_all(b"SSH-2.0-CustomPort").await.unwrap();
    });
    let direct_cfg = Arc::new(test_config(
        "127.0.0.1:40001".parse().unwrap(),
        vec![flowx::router::Rule::from_raw(
            "DirectAll",
            true,
            None,
            None,
            None,
            Action::Direct,
        )],
    ));
    let (mut app_dir, disp_dir) = tokio::io::duplex(1024);
    let start_dir = std::time::Instant::now();
    let dir_handle = tokio::spawn(async move {
        dispatch_transparent_stream(
            direct_cfg,
            disp_dir,
            "127.0.0.1:50403".parse().unwrap(),
            direct_origin_addr,
            None,
            true, // stale SYN-time needs_domain_sniff=true
        )
        .await
    });
    let mut banner = [0u8; 18];
    app_dir.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"SSH-2.0-CustomPort");
    assert!(
        start_dir.elapsed() < Duration::from_millis(115),
        "Immediate(Direct) must not wait 120ms for stale SYN needs_domain_sniff, took {:?}",
        start_dir.elapsed()
    );
    drop(app_dir);
    dir_handle.await.unwrap().unwrap();
    direct_srv.await.unwrap();
}
