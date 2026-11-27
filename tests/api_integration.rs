mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use flowx::api::ApiServer;
use flowx::config::ConfigStore;
use flowx::control::node::{ping_address, ping_address_with_context};
use flowx::control::routing::simulate_route_with_pool;
use flowx::control::{ProxyNodeView, SimulateRouteRequest, SystemRuntimeContext};
use flowx::dns::FakeIpPool;
use flowx::i18n::Locale;
use flowx::interceptor::dispatcher::ProxyNodeEntry;
use flowx::monitor::ConnectionManager;
use flowx::outbound::chain::ProxyNode;
use flowx::outbound::socks5::Socks5Client;
use flowx::router::{Action, Rule, RuleEngine};
use flowx::transparent::{TransparentManager, TransparentSettings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use common::{raw_http, spawn_test_api};

#[tokio::test]
async fn test_api_security_and_validation() {
    let (addr, _nodes, _re, _shutdown_tx) = spawn_test_api().await;
    let port = addr.port();

    // 1. 无通配 CORS 且拦截 DNS Rebinding / 跨源请求，并包含反点击劫持头
    let ok_resp = raw_http(
        addr,
        &format!(
            "GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            port
        ),
    )
    .await;
    assert!(ok_resp.starts_with("HTTP/1.1 200 OK"));
    assert!(!ok_resp.contains("Access-Control-Allow-Origin"));
    assert!(ok_resp.contains("X-Frame-Options: DENY"));
    assert!(ok_resp.contains("Content-Security-Policy: frame-ancestors 'none'"));

    let evil_host = raw_http(
        addr,
        &format!(
            "GET /api/health HTTP/1.1\r\nHost: evil.com:{}\r\n\r\n",
            port
        ),
    )
    .await;
    assert!(evil_host.starts_with("HTTP/1.1 403 Forbidden"));

    let evil_origin = raw_http(
        addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: http://evil.com\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}",
            port
        ),
    )
    .await;
    assert!(evil_origin.starts_with("HTTP/1.1 403 Forbidden"));

    // 1.5 缺失 Content-Type: application/json 时拒绝 415 Unsupported Media Type
    let missing_ct_body = r#"{"name":"n1","protocol":"SOCKS5","server_addr":"1.2.3.4:1080"}"#;
    let missing_ct = raw_http(
        addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\n\r\n{}",
            port,
            missing_ct_body.len(),
            missing_ct_body
        ),
    )
    .await;
    assert!(missing_ct.starts_with("HTTP/1.1 415 Unsupported Media Type"));

    // 2. 拒绝未知代理协议
    let bad_proto_body = r#"{"name":"n1","protocol":"VMESS","server_addr":"1.2.3.4:1080"}"#;
    let bad_proto = raw_http(
        addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            bad_proto_body.len(),
            bad_proto_body
        ),
    )
    .await;
    assert!(bad_proto.starts_with("HTTP/1.1 400 Bad Request"));

    // 3. 拒绝引用不存在节点的规则与无效端口语法
    let bad_rule_body = r#"{"name":"r1","action":"Proxy","node_id":999}"#;
    let bad_rule = raw_http(
        addr,
        &format!(
            "POST /api/rules HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            bad_rule_body.len(),
            bad_rule_body
        ),
    )
    .await;
    assert!(bad_rule.starts_with("HTTP/1.1 400 Bad Request"));

    let bad_port_body = r#"{"name":"r2","action":"Direct","ports":"invalid"}"#;
    let bad_port = raw_http(
        addr,
        &format!(
            "POST /api/rules HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            bad_port_body.len(),
            bad_port_body
        ),
    )
    .await;
    assert!(bad_port.starts_with("HTTP/1.1 400 Bad Request"));

    // 4. ping 按节点 ID 查询，拒绝未注册节点与任意 addr 请求
    let ping_missing_body = r#"{"id":999}"#;
    let ping_missing = raw_http(
        addr,
        &format!(
            "POST /api/nodes/ping HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            ping_missing_body.len(),
            ping_missing_body
        ),
    )
    .await;
    assert!(ping_missing.starts_with("HTTP/1.1 404 Not Found"));

    let ping_ssrf_body = r#"{"addr":"192.168.1.1:22"}"#;
    let ping_ssrf = raw_http(
        addr,
        &format!(
            "POST /api/nodes/ping HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            ping_ssrf_body.len(),
            ping_ssrf_body
        ),
    )
    .await;
    assert!(ping_ssrf.starts_with("HTTP/1.1 400 Bad Request"));
}

#[tokio::test]
async fn test_api_mutates_and_persists_xml() {
    let cfg_guard = common::TempConfigGuard::new("flowx_api_persist");
    let store = Arc::new(ConfigStore::new(cfg_guard.path()));
    let (rt, _) = store.load_or_init(&[40001, 40080, 1053]).unwrap();

    let mgr = Arc::new(ConnectionManager::new());
    let re = Arc::new(RuleEngine::new(rt.rules, rt.default_action));
    let nodes = Arc::new(RwLock::new(rt.proxy_nodes));
    let srv = ApiServer::new(
        "127.0.0.1:0".parse().unwrap(),
        mgr,
        Arc::clone(&re),
        Arc::clone(&nodes),
    )
    .with_self_ports(vec![40001, 40080, 1053])
    .with_config_store(Arc::clone(&store));
    let listener = srv.bind().await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move { srv.run(listener, rx).await });
    let _keep_tx = tx;

    let port = addr.port();
    let add_node_body = r#"{"name":"HK-Test","protocol":"HTTP","server_addr":"10.0.0.2:8080"}"#;
    let resp = raw_http(
        addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            add_node_body.len(),
            add_node_body
        ),
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "resp: {}", resp);

    let (reloaded, _) = store.load_or_init(&[40001, 40080, 1053]).unwrap();
    assert_eq!(reloaded.proxy_nodes.len(), 2);
    assert!(
        reloaded
            .proxy_nodes
            .values()
            .any(|n| n.name == "HK-Test" && n.protocol == "HTTP")
    );
}

#[tokio::test]
async fn test_api_system_and_rule_toggle_move() {
    let cfg_guard = common::TempConfigGuard::new("flowx_api_rule_ops");
    let store = Arc::new(ConfigStore::new(cfg_guard.path()));
    let (rt, _) = store.load_or_init(&[40001, 40080, 1053]).unwrap();
    let rule1_id = rt.rules[0].id;
    let rule2_id = rt.rules[1].id;

    let mgr = Arc::new(ConnectionManager::new());
    let re = Arc::new(RuleEngine::new(rt.rules, rt.default_action));
    let nodes = Arc::new(RwLock::new(rt.proxy_nodes));
    let fake_pool = Arc::new(FakeIpPool::new_default());
    fake_pool.allocate("example.com");

    let sys_ctx = Arc::new(SystemRuntimeContext {
        inbound_addr: "127.0.0.1:40001".parse().unwrap(),
        dns_addr: "127.0.0.1:1053".parse().unwrap(),
        upstream_dns: "223.5.5.5:53".parse().unwrap(),
        api_addr: "127.0.0.1:40080".parse().unwrap(),
        fake_ip_pool: fake_pool,
        block_ipv6: true,
        started_at: Instant::now(),
    });

    let srv = ApiServer::new(
        "127.0.0.1:0".parse().unwrap(),
        mgr,
        Arc::clone(&re),
        Arc::clone(&nodes),
    )
    .with_self_ports(vec![40001, 40080, 1053])
    .with_config_store(Arc::clone(&store))
    .with_runtime_context(sys_ctx);
    let listener = srv.bind().await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move { srv.run(listener, rx).await });
    let _keep_tx = tx;
    let port = addr.port();

    // 1. 系统信息端点
    let sys_resp = raw_http(
        addr,
        &format!(
            "GET /api/system HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            port
        ),
    )
    .await;
    assert!(sys_resp.starts_with("HTTP/1.1 200 OK"));
    assert!(sys_resp.contains("\"fake_ip_count\":1"));
    assert!(sys_resp.contains("\"rules_count\":2"));

    // 2. 停用规则 1 并验证持久化
    let toggle_body = format!(r#"{{"id":{},"enabled":false}}"#, rule1_id);
    let toggle_resp = raw_http(
        addr,
        &format!(
            "POST /api/rules/toggle HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            toggle_body.len(),
            toggle_body
        ),
    )
    .await;
    assert!(toggle_resp.contains("\"enabled\":false"));

    // 3. 将规则 2 上移到顶部并验证持久化
    let move_body = format!(r#"{{"id":{},"direction":"up"}}"#, rule2_id);
    let move_resp = raw_http(
        addr,
        &format!(
            "POST /api/rules/move HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            move_body.len(),
            move_body
        ),
    )
    .await;
    assert!(move_resp.contains("\"moved\":true"));

    let (reloaded, _) = store.load_or_init(&[40001, 40080, 1053]).unwrap();
    assert_eq!(reloaded.rules[0].name, "DevProxy");
    assert_eq!(reloaded.rules[1].name, "LocalBypass");
    assert!(!reloaded.rules[1].enabled);
}

/// P1-1 & P1-3 回归测试：
/// 1) 节点被 rule_engine.default_action 引用时禁止删除 (409 Conflict)
/// 2) /api/connections/kill 仅发出终止通知，不提前注销活跃连接
#[tokio::test]
async fn test_delete_node_checks_default_action_and_kill_preserves_raii_guard() {
    let mut nodes_map = HashMap::new();
    nodes_map.insert(
        101,
        ProxyNodeEntry {
            id: 101,
            name: "Default-GW".into(),
            protocol: "SOCKS5".into(),
            server_addr: "10.0.0.99:1080".into(),
            username: None,
            client: ProxyNode::Socks5(Socks5Client::new("10.0.0.99:1080")),
        },
    );

    let mgr = Arc::new(ConnectionManager::new());
    let active = mgr.register(
        "app.exe".into(),
        "C:/app.exe".into(),
        4321,
        "example.org:443".into(),
        "Default".into(),
        "Proxy".into(),
        Some(101),
    );

    // 显式规则列表为空，仅 default_action 指向节点 101
    let re = Arc::new(RuleEngine::new(vec![], Action::Proxy(101)));
    let nodes = Arc::new(RwLock::new(nodes_map));

    let srv = ApiServer::new("127.0.0.1:0".parse().unwrap(), Arc::clone(&mgr), re, nodes);
    let listener = srv.bind().await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move { srv.run(listener, rx).await });
    let _keep_tx = tx;
    let port = addr.port();

    // 1. 删除被 default_action 引用的节点必须返回 409 Conflict
    let del_body = r#"{"id":101}"#;
    let del_resp = raw_http(
        addr,
        &format!(
            "DELETE /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            del_body.len(),
            del_body
        ),
    )
    .await;
    assert!(
        del_resp.starts_with("HTTP/1.1 409 Conflict"),
        "Node referenced by default_action must not be deleted: {}",
        del_resp
    );

    // 2. 切断活跃连接仅触发 cancel 状态与唤醒通知，由连接守卫负责最终注销
    let kill_body = format!(r#"{{"id":{}}}"#, active.id);
    let kill_resp = raw_http(
        addr,
        &format!(
            "POST /api/connections/kill HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            kill_body.len(),
            kill_body
        ),
    )
    .await;
    assert!(kill_resp.contains("\"killed\":true"));
    assert!(active.is_cancelled());
    assert_eq!(
        mgr.active_count(),
        1,
        "API must not bypass ConnectionGuard to unregister connections early"
    );

    mgr.unregister(active.id);
    assert_eq!(mgr.active_count(), 0);
}

#[tokio::test]
async fn test_api_i18n_negotiation_and_localized_errors() {
    let (addr, _nodes, _re, _shutdown_tx) = spawn_test_api().await;
    let port = addr.port();

    // 1. Accept-Language: zh-CN 返回中文错误与多语言键值
    let bad_proto_body = r#"{"name":"n1","protocol":"UNKNOWN","server_addr":"1.2.3.4:1080"}"#;
    let resp_zh = raw_http(
        addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: zh-CN,zh;q=0.9\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            bad_proto_body.len(),
            bad_proto_body
        ),
    )
    .await;
    assert!(resp_zh.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(resp_zh.contains("不支持的代理协议"));
    assert!(resp_zh.contains("\"code\":\"ERR_UNSUPPORTED_PROTOCOL\""));
    assert!(resp_zh.contains("\"key\":\"error.unsupported_protocol\""));

    // 2. Accept-Language: en-US 返回英文错误与多语言键值
    let resp_en = raw_http(
        addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: en-US,en;q=0.9\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            bad_proto_body.len(),
            bad_proto_body
        ),
    )
    .await;
    assert!(resp_en.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(resp_en.contains("Unsupported proxy protocol"));
    assert!(resp_en.contains("\"code\":\"ERR_UNSUPPORTED_PROTOCOL\""));
    assert!(resp_en.contains("\"key\":\"error.unsupported_protocol\""));

    // 3. Query 参数 ?lang=zh 覆盖请求头
    let resp_query_zh = raw_http(
        addr,
        &format!(
            "POST /api/nodes?lang=zh HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: en-US\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            bad_proto_body.len(),
            bad_proto_body
        ),
    )
    .await;
    assert!(resp_query_zh.contains("不支持的代理协议"));

    // 4. Query 参数 ?lang=en 覆盖请求头
    let resp_query_en = raw_http(
        addr,
        &format!(
            "POST /api/nodes?lang=en HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: zh-CN\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            bad_proto_body.len(),
            bad_proto_body
        ),
    )
    .await;
    assert!(resp_query_en.contains("Unsupported proxy protocol"));

    // 5. System API 返回与语言匹配的动作描述
    let sys_zh = raw_http(
        addr,
        &format!(
            "GET /api/system HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: zh-CN\r\n\r\n",
            port
        ),
    )
    .await;
    assert!(sys_zh.contains("Direct (直连)"));

    let sys_en = raw_http(
        addr,
        &format!(
            "GET /api/system HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: en-US\r\n\r\n",
            port
        ),
    )
    .await;
    assert!(sys_en.contains("\"default_action\":\"Direct\""));

    // 6. 非法 Content-Length 走本地化 + 机器可读错误码（不再泄漏原始错误串）
    let bad_len_zh = raw_http(
        addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: zh-CN\r\nContent-Length: abc\r\n\r\n",
            port
        ),
    )
    .await;
    assert!(bad_len_zh.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(bad_len_zh.contains("无效的 Content-Length 请求头"));
    assert!(bad_len_zh.contains("\"code\":\"ERR_INVALID_CONTENT_LENGTH\""));
    assert!(bad_len_zh.contains("\"key\":\"error.invalid_content_length\""));

    let bad_len_en = raw_http(
        addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: en-US\r\nContent-Length: abc\r\n\r\n",
            port
        ),
    )
    .await;
    assert!(bad_len_en.contains("Invalid Content-Length header"));
}

/// /api/connections 的动作、兜底规则名与未知进程名必须按请求语言本地化，
/// 同时保留 action_type / action_id 机器字段供前端过滤。
#[tokio::test]
async fn test_api_connections_view_is_localized() {
    let mgr = Arc::new(ConnectionManager::new());
    mgr.register(
        "app.exe".into(),
        "C:/app.exe".into(),
        4321,
        "example.org:443".into(),
        flowx::router::DEFAULT_RULE_NAME.into(),
        "Proxy".into(),
        Some(101),
    );
    let re = Arc::new(RuleEngine::new(vec![], Action::Direct));
    let nodes = Arc::new(RwLock::new(HashMap::new()));
    let srv = ApiServer::new("127.0.0.1:0".parse().unwrap(), Arc::clone(&mgr), re, nodes);
    let listener = srv.bind().await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move { srv.run(listener, rx).await });
    let _keep_tx = tx;

    let zh = raw_http(
        addr,
        &format!(
            "GET /api/connections HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: zh-CN\r\n\r\n",
            addr.port()
        ),
    )
    .await;
    assert!(
        zh.contains("Proxy (节点-101)"),
        "zh action should be localized: {zh}"
    );
    assert!(
        zh.contains("\"rule_name\":\"默认\""),
        "zh rule_name should be localized: {zh}"
    );
    assert!(zh.contains("\"action_type\":\"Proxy\""));
    assert!(zh.contains("\"action_id\":101"));

    let en = raw_http(
        addr,
        &format!(
            "GET /api/connections HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: en-US\r\n\r\n",
            addr.port()
        ),
    )
    .await;
    assert!(
        en.contains("Proxy (Node-101)"),
        "en action should be localized: {en}"
    );
    assert!(en.contains("\"rule_name\":\"Default\""));
}

#[tokio::test]
async fn test_api_update_node_rule_default_and_simulate() {
    let cfg_guard = common::TempConfigGuard::new("flowx_api_stage2");
    let store = Arc::new(ConfigStore::new(cfg_guard.path()));
    let (rt, _) = store.load_or_init(&[40001, 40080, 1053]).unwrap();
    let rule2_id = rt.rules[1].id;

    let mgr = Arc::new(ConnectionManager::new());
    let re = Arc::new(RuleEngine::new(rt.rules, rt.default_action));
    let nodes = Arc::new(RwLock::new(rt.proxy_nodes));
    let srv = ApiServer::new(
        "127.0.0.1:0".parse().unwrap(),
        mgr,
        Arc::clone(&re),
        Arc::clone(&nodes),
    )
    .with_self_ports(vec![40001, 40080, 1053])
    .with_config_store(Arc::clone(&store));
    let listener = srv.bind().await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move { srv.run(listener, rx).await });
    let _keep_tx = tx;
    let port = addr.port();

    // 1. PUT /api/nodes 更新节点 101 并设置认证，随后 keep_password=true 仅改名保留密码
    let put_node1 = r#"{"id":101,"name":"SG-Auth","protocol":"SOCKS5","server_addr":"10.10.0.1:1080","username":"alice","password":"secret"}"#;
    let resp1 = raw_http(
        addr,
        &format!(
            "PUT /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            put_node1.len(),
            put_node1
        ),
    )
    .await;
    assert!(resp1.starts_with("HTTP/1.1 200 OK"), "resp1: {resp1}");

    let put_node2 = r#"{"id":101,"name":"SG-Auth-Renamed","protocol":"SOCKS5","server_addr":"10.10.0.1:1080","username":"alice","password":null,"keep_password":true}"#;
    let resp2 = raw_http(
        addr,
        &format!(
            "PUT /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            put_node2.len(),
            put_node2
        ),
    )
    .await;
    assert!(resp2.starts_with("HTTP/1.1 200 OK"), "resp2: {resp2}");

    // 2. PUT /api/rules 原地修改规则 2
    let put_rule = format!(
        r#"{{"id":{},"name":"GitRule","apps":"git.exe","targets":"*.github.com","ports":"443; 22","action":"Proxy","node_id":101}}"#,
        rule2_id
    );
    let resp_rule = raw_http(
        addr,
        &format!(
            "PUT /api/rules HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            put_rule.len(),
            put_rule
        ),
    )
    .await;
    assert!(
        resp_rule.starts_with("HTTP/1.1 200 OK"),
        "resp_rule: {resp_rule}"
    );

    // 3. POST /api/rules/default 修改默认兜底动作
    let def_body = r#"{"action":"Proxy","node_id":101}"#;
    let resp_def = raw_http(
        addr,
        &format!(
            "POST /api/rules/default HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: zh-CN\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            def_body.len(),
            def_body
        ),
    )
    .await;
    assert!(
        resp_def.starts_with("HTTP/1.1 200 OK"),
        "resp_def: {resp_def}"
    );
    assert!(resp_def.contains("\"default_action_type\":\"Proxy\""));
    assert!(resp_def.contains("\"default_node_id\":101"));

    // 4. POST /api/rules/simulate 测试路由命中与轨迹
    let sim_body =
        r#"{"process":"C:\\Program Files\\Git\\bin\\git.exe","target":"api.github.com:443"}"#;
    let resp_sim = raw_http(
        addr,
        &format!(
            "POST /api/rules/simulate HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept-Language: zh-CN\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            sim_body.len(),
            sim_body
        ),
    )
    .await;
    assert!(
        resp_sim.starts_with("HTTP/1.1 200 OK"),
        "resp_sim: {resp_sim}"
    );
    assert!(resp_sim.contains("\"matched_rule_name\":\"GitRule\""));
    assert!(resp_sim.contains("\"is_default\":false"));
    assert!(resp_sim.contains("\"reason\":\"target_mismatch\""));
    assert!(resp_sim.contains("\"reason\":\"matched\""));

    // 5. 验证 XML 持久化结果
    let (reloaded, _) = store.load_or_init(&[40001, 40080, 1053]).unwrap();
    let node101 = reloaded.proxy_nodes.get(&101).unwrap();
    assert_eq!(node101.name, "SG-Auth-Renamed");
    assert_eq!(
        node101.client.auth_credentials(),
        (Some("alice"), Some("secret"))
    );
    assert_eq!(reloaded.rules[1].name, "GitRule");
    assert_eq!(reloaded.default_action, Action::Proxy(101));
}

#[tokio::test]
async fn test_api_bind_non_loopback_and_framing_hardening() {
    let mgr = Arc::new(ConnectionManager::new());
    let re = Arc::new(RuleEngine::new(Vec::new(), Action::Direct));
    let nodes = Arc::new(RwLock::new(HashMap::new()));
    let non_loopback = ApiServer::new("0.0.0.0:40080".parse().unwrap(), mgr, re, nodes);
    assert!(non_loopback.bind().await.is_err());

    let (addr, _nodes, _re, _tx) = spawn_test_api().await;
    let port = addr.port();

    // 1. 拒绝 Transfer-Encoding (501)
    let te_resp = raw_http(
        addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            port
        ),
    )
    .await;
    assert!(
        te_resp.starts_with("HTTP/1.1 501 Not Implemented"),
        "te_resp: {te_resp}"
    );

    // 2. 拒绝重复 Host 头 (400)
    let dup_host = raw_http(
        addr,
        &format!(
            "GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nHost: 127.0.0.1:{}\r\n\r\n",
            port, port
        ),
    )
    .await;
    assert!(
        dup_host.starts_with("HTTP/1.1 400 Bad Request"),
        "dup_host: {dup_host}"
    );

    // 3. 拒绝在 EOF 前截断 Content-Length 的不完整请求
    {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(
            format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: 50\r\n\r\n{{\"name\":\"x\"}}",
                port
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        s.shutdown().await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        let txt = String::from_utf8(buf).unwrap();
        assert!(
            txt.starts_with("HTTP/1.1 400 Bad Request"),
            "trunc eof: {txt}"
        );
    }

    // 4. 拒绝无效请求行
    let bad_rl = raw_http(
        addr,
        &format!(
            "GET  /api/health HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            port
        ),
    )
    .await;
    assert!(
        bad_rl.starts_with("HTTP/1.1 400 Bad Request"),
        "bad_rl: {bad_rl}"
    );
}

#[tokio::test]
async fn test_api_patch_and_auth_and_simulate_parity() {
    let (addr, nodes, re, _tx) = spawn_test_api().await;
    let port = addr.port();

    // 1. SOCKS4 带密码必须显式报错拒绝
    let s4_pw = r#"{"name":"s4","protocol":"SOCKS4","server_addr":"10.0.0.3:1080","username":"u","password":"p"}"#;
    let resp_s4 = raw_http(
        addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            s4_pw.len(),
            s4_pw
        ),
    )
    .await;
    assert!(
        resp_s4.starts_with("HTTP/1.1 400 Bad Request"),
        "s4_pw: {resp_s4}"
    );
    assert!(resp_s4.contains("ERR_SOCKS4_PASSWORD_UNSUPPORTED"));

    // 2. 添加带密码 SOCKS5 节点并验证 GET /api/nodes 返回 password_configured=true
    let add_s5 = r#"{"name":"s5","protocol":"SOCKS5","server_addr":"10.0.0.4:1080","username":"alice","password":"pw1"}"#;
    let r_add = raw_http(
        addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            add_s5.len(),
            add_s5
        ),
    )
    .await;
    assert!(r_add.starts_with("HTTP/1.1 200 OK"), "r_add: {r_add}");

    let list_nodes = raw_http(
        addr,
        &format!(
            "GET /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            port
        ),
    )
    .await;
    assert!(list_nodes.contains("\"password_configured\":true"));

    // 3. PATCH 仅改名保留凭证；修改用户名未给新密码则报错；clear_password=true 清除密码
    let patch_name = r#"{"id":101,"name":"s5-patched"}"#;
    let r_patch_name = raw_http(
        addr,
        &format!(
            "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            patch_name.len(),
            patch_name
        ),
    )
    .await;
    assert!(
        r_patch_name.starts_with("HTTP/1.1 200 OK"),
        "r_patch_name: {r_patch_name}"
    );
    assert_eq!(
        nodes
            .read()
            .unwrap()
            .get(&101)
            .unwrap()
            .client
            .auth_credentials(),
        (Some("alice"), Some("pw1"))
    );

    let patch_user_only = r#"{"id":101,"username":"bob"}"#;
    let r_user_only = raw_http(
        addr,
        &format!(
            "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            patch_user_only.len(),
            patch_user_only
        ),
    )
    .await;
    assert!(r_user_only.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(r_user_only.contains("ERR_PASSWORD_REQUIRED_ON_USER_CHANGE"));

    let clear_pw = r#"{"id":101,"clear_password":true}"#;
    let r_clear = raw_http(
        addr,
        &format!(
            "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            clear_pw.len(),
            clear_pw
        ),
    )
    .await;
    assert!(r_clear.starts_with("HTTP/1.1 200 OK"), "r_clear: {r_clear}");
    {
        let guard = nodes.read().unwrap();
        let n = guard.get(&101).unwrap();
        assert_eq!(n.username, None);
        assert_eq!(n.client.auth_credentials(), (None, None));
    }

    // 4. PATCH /api/rules 保留未修改条件字段
    let add_r = Rule::from_raw(
        "R1",
        true,
        Some("curl"),
        Some("*.example.com"),
        Some("443"),
        Action::Direct,
    );
    let rid = add_r.id;
    re.add_rule(add_r);
    let patch_rule_body = format!(r#"{{"id":{},"name":"R1-Renamed"}}"#, rid);
    let r_patch_rule = raw_http(
        addr,
        &format!(
            "PATCH /api/rules HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            patch_rule_body.len(),
            patch_rule_body
        ),
    )
    .await;
    assert!(
        r_patch_rule.starts_with("HTTP/1.1 200 OK"),
        "r_patch_rule: {r_patch_rule}"
    );
    let cur_r = re.current_rules();
    let patched_r = cur_r.iter().find(|r| r.id == rid).unwrap();
    assert_eq!(patched_r.name, "R1-Renamed");
    assert_eq!(patched_r.targets_raw, "*.example.com");
    assert_eq!(patched_r.ports_raw, "443");

    // 5. Simulate parity: IP literal sets target_host=None, Fake-IP restores original domain
    let pool = flowx::dns::FakeIpPool::new_default();
    let fake_ip = pool.allocate("secret.internal");
    let sim_ip = simulate_route_with_pool(
        SimulateRouteRequest {
            process: None,
            target: "8.8.8.8:443".into(),
            port: None,
        },
        &re,
        Some(&pool),
        Locale::En,
    )
    .unwrap();
    assert!(
        sim_ip.target_host.is_none(),
        "IP literal must keep target_host null: {sim_ip:?}"
    );
    assert_eq!(sim_ip.target_ip.as_deref(), Some("8.8.8.8"));

    let sim_fake = simulate_route_with_pool(
        SimulateRouteRequest {
            process: None,
            target: format!("{}:443", fake_ip),
            port: None,
        },
        &re,
        Some(&pool),
        Locale::En,
    )
    .unwrap();
    assert_eq!(sim_fake.target_host.as_deref(), Some("secret.internal"));
    assert!(sim_fake.target_ip.is_none());
}

#[tokio::test]
async fn test_api_persist_failure_rolls_back_and_returns_500_and_auth_validation() {
    // 1. Unwritable parent path (regular file used as parent directory) forces save_profile to fail
    let blocker_guard = common::TempConfigGuard::with_ext("flowx_readonly_parent", "tmp");
    let blocker = blocker_guard.path();
    std::fs::write(blocker, b"not-a-directory").unwrap();
    let bad_cfg_path = blocker.join("flowx.xml");
    let store = Arc::new(ConfigStore::new(&bad_cfg_path));

    let mgr = Arc::new(ConnectionManager::new());
    let re = Arc::new(RuleEngine::new(Vec::new(), Action::Direct));
    let nodes = Arc::new(RwLock::new(HashMap::new()));
    let srv = ApiServer::new(
        "127.0.0.1:0".parse().unwrap(),
        mgr,
        Arc::clone(&re),
        Arc::clone(&nodes),
    )
    .with_self_ports(vec![40001, 40080, 1053])
    .with_config_store(store);
    let listener = srv.bind().await.unwrap();
    let addr = listener.local_addr().unwrap();
    let port = addr.port();
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move { srv.run(listener, rx).await });
    let _keep_tx = tx;

    let add_node_body =
        r#"{"name":"Node-Rollback","protocol":"SOCKS5","server_addr":"10.0.0.1:1080"}"#;
    let r_node_fail = raw_http(
        addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            add_node_body.len(),
            add_node_body
        ),
    )
    .await;
    assert!(
        r_node_fail.starts_with("HTTP/1.1 500 Internal Server Error"),
        "Persist failure must return HTTP 500: {r_node_fail}"
    );
    assert!(r_node_fail.contains("ERR_CONFIG_PERSIST_FAILED"));
    assert!(
        nodes.read().unwrap().is_empty(),
        "Failed disk persistence must roll back added proxy node"
    );

    let add_rule_body = r#"{"name":"Rule-Rollback","action":"Block","targets":"example.com"}"#;
    let r_rule_fail = raw_http(
        addr,
        &format!(
            "POST /api/rules HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            add_rule_body.len(),
            add_rule_body
        ),
    )
    .await;
    assert!(r_rule_fail.starts_with("HTTP/1.1 500 Internal Server Error"));
    assert!(
        re.current_rules().is_empty(),
        "Failed disk persistence must roll back added rule"
    );
    drop(blocker_guard);

    // 2. Password without username / HTTP ':' in username / empty string password semantics (P1-5 + P1-6b)
    let (api_addr, api_nodes, _api_re, _tx2) = spawn_test_api().await;
    let api_port = api_addr.port();

    let pw_only =
        r#"{"name":"bad","protocol":"SOCKS5","server_addr":"10.0.0.2:1080","password":"secret"}"#;
    let r_pw_only = raw_http(
        api_addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            pw_only.len(),
            pw_only
        ),
    )
    .await;
    assert!(r_pw_only.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(r_pw_only.contains("ERR_PASSWORD_WITHOUT_USERNAME"));

    let http_colon = r#"{"name":"badhttp","protocol":"HTTP","server_addr":"10.0.0.2:8080","username":"a:b","password":"secret"}"#;
    let r_colon = raw_http(
        api_addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            http_colon.len(),
            http_colon
        ),
    )
    .await;
    assert!(r_colon.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(r_colon.contains("ERR_HTTP_USERNAME_COLON"));

    let empty_add_pw = r#"{"name":"badadd","protocol":"SOCKS5","server_addr":"10.0.0.2:1080","username":"alice","password":""}"#;
    let r_empty_add = raw_http(
        api_addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            empty_add_pw.len(),
            empty_add_pw
        ),
    )
    .await;
    assert!(r_empty_add.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(r_empty_add.contains("ERR_EMPTY_PASSWORD"));

    // Create node with credentials, then PATCH {"password": ""} clears password instead of keeping old one
    let ok_add = r#"{"name":"s5ok","protocol":"SOCKS5","server_addr":"10.0.0.2:1080","username":"alice","password":"pw1"}"#;
    let r_ok_add = raw_http(
        api_addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            ok_add.len(),
            ok_add
        ),
    )
    .await;
    assert!(r_ok_add.starts_with("HTTP/1.1 200 OK"));

    let conflict_patch = r#"{"id":101,"password":"","keep_password":true}"#;
    let r_conflict = raw_http(
        api_addr,
        &format!(
            "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            conflict_patch.len(),
            conflict_patch
        ),
    )
    .await;
    assert!(r_conflict.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(r_conflict.contains("ERR_CONFLICTING_PASSWORD_OPTIONS"));

    let clear_via_empty_str = r#"{"id":101,"password":""}"#;
    let r_clear = raw_http(
        api_addr,
        &format!(
            "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            clear_via_empty_str.len(),
            clear_via_empty_str
        ),
    )
    .await;
    assert!(r_clear.starts_with("HTTP/1.1 200 OK"));
    {
        let guard = api_nodes.read().unwrap();
        let n = guard.get(&101).unwrap();
        assert_eq!(n.username, None);
        assert_eq!(
            n.client.auth_credentials(),
            (None, None),
            "PATCH with explicit empty password string must clear stored credentials"
        );
    }
}

#[tokio::test]
async fn test_api_update_and_patch_new_password_with_keep_false() {
    let (api_addr, api_nodes, _api_re, _tx) = spawn_test_api().await;
    let api_port = api_addr.port();

    let add_body = r#"{"name":"s5p0","protocol":"SOCKS5","server_addr":"10.0.0.2:1080","username":"alice","password":"pw1"}"#;
    let r_add = raw_http(
        api_addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            add_body.len(),
            add_body
        ),
    )
    .await;
    assert!(r_add.starts_with("HTTP/1.1 200 OK"));
    let added_json: serde_json::Value =
        serde_json::from_str(r_add.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    let node_id = added_json["id"].as_u64().unwrap() as u32;

    // P0: Web UI edits send explicit non-empty password alongside keep_password=false & clear_password=false
    let put_body = format!(
        r#"{{"id":{},"name":"s5p0","protocol":"SOCKS5","server_addr":"10.0.0.2:1080","username":"alice","password":"new-put-secret","keep_password":false,"clear_password":false}}"#,
        node_id
    );
    let r_put = raw_http(
        api_addr,
        &format!(
            "PUT /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            put_body.len(),
            put_body
        ),
    )
    .await;
    assert!(
        r_put.starts_with("HTTP/1.1 200 OK"),
        "PUT failed: {}",
        r_put
    );
    assert_eq!(
        api_nodes
            .read()
            .unwrap()
            .get(&node_id)
            .unwrap()
            .client
            .auth_credentials(),
        (Some("alice"), Some("new-put-secret")),
        "PUT must preserve newly entered password even when keep_password=false"
    );

    let patch_body = format!(
        r#"{{"id":{},"username":"bob","password":"new-patch-secret","keep_password":false,"clear_password":false}}"#,
        node_id
    );
    let r_patch = raw_http(
        api_addr,
        &format!(
            "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            patch_body.len(),
            patch_body
        ),
    )
    .await;
    assert!(
        r_patch.starts_with("HTTP/1.1 200 OK"),
        "PATCH failed: {}",
        r_patch
    );
    assert_eq!(
        api_nodes
            .read()
            .unwrap()
            .get(&node_id)
            .unwrap()
            .client
            .auth_credentials(),
        (Some("bob"), Some("new-patch-secret")),
        "PATCH must preserve newly entered password even when keep_password=false"
    );
}

#[tokio::test]
async fn test_api_node_and_ping_block_fake_ip_and_local_interface_self_ports() {
    let (api_addr, _api_nodes, _api_re, _tx) = spawn_test_api().await;
    let api_port = api_addr.port();

    // 1. Node creation with Fake-IP literal must fail with ERR_NODE_FAKE_IP
    let fake_node = r#"{"name":"fake","protocol":"SOCKS5","server_addr":"198.18.0.55:1080"}"#;
    let r_fake = raw_http(
        api_addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            fake_node.len(),
            fake_node
        ),
    )
    .await;
    assert!(r_fake.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(r_fake.contains("ERR_NODE_FAKE_IP"));

    // 2. Node creation with local interface non-loopback IP on self_port (40080) must fail
    let local_ips = flowx::outbound::local_interface_ips();
    let non_loopback_ip = local_ips
        .iter()
        .copied()
        .find(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let iface_self_addr = SocketAddr::new(non_loopback_ip, 40080).to_string();
    let iface_body = format!(
        r#"{{"name":"iface","protocol":"SOCKS5","server_addr":"{}"}}"#,
        iface_self_addr
    );
    let r_iface = raw_http(
        api_addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            iface_body.len(),
            iface_body
        ),
    )
    .await;
    assert!(r_iface.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(r_iface.contains("ERR_NODE_SELF_LOOP"));

    // 3. ping_address_with_context must reject Fake-IP, self_port loopback/local-interface, and DNS rebinding to self_port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound_port = listener.local_addr().unwrap().port();
    let (ok_fake, _, msg_fake, _) =
        ping_address("198.18.0.10:1080", &[bound_port], Locale::En).await;
    assert!(!ok_fake);
    assert!(msg_fake.contains("Fake-IP"));

    let (ok_self, _, msg_self, _) = ping_address(
        &format!("127.0.0.1:{}", bound_port),
        &[bound_port],
        Locale::En,
    )
    .await;
    assert!(!ok_self);
    assert!(msg_self.contains("internal service"));

    let (ok_iface, _, msg_iface, _) = ping_address(
        &SocketAddr::new(non_loopback_ip, bound_port).to_string(),
        &[bound_port],
        Locale::En,
    )
    .await;
    assert!(!ok_iface);
    assert!(msg_iface.contains("internal service"));

    // 4. Online ping_address_with_context resolves pure-AAAA domain even when runtime_ctx.block_ipv6 == true
    if let Ok(v6_listener) = TcpListener::bind("[::1]:0").await {
        let v6_port = v6_listener.local_addr().unwrap().port();
        let accept_v6 = tokio::spawn(async move {
            let _ = v6_listener.accept().await;
        });
        let mock_dns = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_dns_addr = mock_dns.local_addr().unwrap();
        let dns_task = tokio::spawn(async move {
            for _ in 0..2 {
                let mut buf = [0u8; 512];
                let (n, src) = mock_dns.recv_from(&mut buf).await.unwrap();
                let (tx, q) =
                    flowx::dns::server::DnsPacketParser::parse_question(&buf[..n]).unwrap();
                let resp = if q.qtype == 28 {
                    let mut r = Vec::new();
                    r.extend_from_slice(&tx.to_be_bytes());
                    r.extend_from_slice(&[
                        0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                    ]);
                    r.extend_from_slice(&buf[12..q.raw_len]);
                    r.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0, 0, 0, 5, 0, 16]);
                    r.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
                    r
                } else {
                    flowx::dns::server::DnsPacketParser::build_empty_response(tx, &buf, q.raw_len)
                };
                mock_dns.send_to(&resp, src).await.unwrap();
            }
        });
        let ctx = SystemRuntimeContext {
            dns_addr: "127.0.0.1:1053".parse().unwrap(),
            upstream_dns: mock_dns_addr,
            inbound_addr: "127.0.0.1:40001".parse().unwrap(),
            api_addr: "127.0.0.1:40080".parse().unwrap(),
            fake_ip_pool: Arc::new(FakeIpPool::new_default()),
            block_ipv6: true,
            started_at: Instant::now(),
        };
        let (ok_aaaa, _, msg_aaaa, _) = ping_address_with_context(
            &format!("v6only.example:{}", v6_port),
            &[40080],
            Some(&ctx),
            None,
            Locale::En,
        )
        .await;
        assert!(
            ok_aaaa,
            "pure-AAAA ping should succeed when block_ipv6=true: {}",
            msg_aaaa
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), dns_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), accept_v6).await;
    }

    // Mapped Fake-IP literal also rejected in ping
    let (ok_mapped_fake, _, msg_mapped_fake, _) =
        ping_address("[::ffff:198.18.0.10]:1080", &[bound_port], Locale::En).await;
    assert!(!ok_mapped_fake);
    assert!(msg_mapped_fake.contains("Fake-IP"));

    // 5. Dual-candidate ping falls back cleanly when first IP fails/blackholes before reachable second IP
    let v4_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let v4_port = v4_listener.local_addr().unwrap().port();
    let accept_v4 = tokio::spawn(async move {
        let _ = v4_listener.accept().await;
    });
    let mock_dns_multi = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mock_dns_multi_addr = mock_dns_multi.local_addr().unwrap();
    let dns_multi_task = tokio::spawn(async move {
        for _ in 0..2 {
            let mut buf = [0u8; 512];
            let (n, src) = mock_dns_multi.recv_from(&mut buf).await.unwrap();
            let (tx, q) = flowx::dns::server::DnsPacketParser::parse_question(&buf[..n]).unwrap();
            let resp = if q.qtype == 1 {
                let mut r = Vec::new();
                r.extend_from_slice(&tx.to_be_bytes());
                r.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]);
                r.extend_from_slice(&buf[12..q.raw_len]);
                // First candidate: TEST-NET-2 blackhole/unreachable, second candidate: reachable 127.0.0.1
                r.extend_from_slice(&[
                    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 5, 0, 4, 198, 51, 100, 1,
                ]);
                r.extend_from_slice(&[
                    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 5, 0, 4, 127, 0, 0, 1,
                ]);
                r
            } else {
                flowx::dns::server::DnsPacketParser::build_empty_response(tx, &buf, q.raw_len)
            };
            mock_dns_multi.send_to(&resp, src).await.unwrap();
        }
    });
    let ctx_multi = SystemRuntimeContext {
        dns_addr: "127.0.0.1:1053".parse().unwrap(),
        upstream_dns: mock_dns_multi_addr,
        inbound_addr: "127.0.0.1:40001".parse().unwrap(),
        api_addr: "127.0.0.1:40080".parse().unwrap(),
        fake_ip_pool: Arc::new(FakeIpPool::new_default()),
        block_ipv6: true,
        started_at: Instant::now(),
    };
    let (ok_multi, _, msg_multi, _) = ping_address_with_context(
        &format!("dual.example:{}", v4_port),
        &[40080],
        Some(&ctx_multi),
        None,
        Locale::En,
    )
    .await;
    assert!(
        ok_multi,
        "multi-IP ping should failover within 2s budget: {}",
        msg_multi
    );
    let _ = tokio::time::timeout(Duration::from_secs(1), dns_multi_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), accept_v4).await;
}

#[tokio::test]
async fn test_api_paired_credentials_and_auth_configured() {
    let (api_addr, api_nodes, _api_re, _tx) = spawn_test_api().await;
    let api_port = api_addr.port();

    // 1. HTTP / SOCKS5 POST with username but without password rejects with ERR_USERNAME_WITHOUT_PASSWORD
    for proto in ["SOCKS5", "HTTP"] {
        let body = format!(
            r#"{{"name":"uonly","protocol":"{}","server_addr":"10.0.0.2:1080","username":"alice"}}"#,
            proto
        );
        let r = raw_http(
            api_addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                api_port,
                body.len(),
                body
            ),
        )
        .await;
        assert!(
            r.starts_with("HTTP/1.1 400 Bad Request"),
            "proto {} resp: {}",
            proto,
            r
        );
        assert!(r.contains("ERR_USERNAME_WITHOUT_PASSWORD"));
    }

    // 2. SOCKS4 POST with standalone UserID succeeds and auth_configured == true
    let s4_body =
        r#"{"name":"s4user","protocol":"SOCKS4","server_addr":"10.0.0.2:1080","username":"s4id"}"#;
    let r_s4 = raw_http(
        api_addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            s4_body.len(),
            s4_body
        ),
    )
    .await;
    assert!(r_s4.starts_with("HTTP/1.1 200 OK"), "s4 resp: {}", r_s4);
    let s4_id = serde_json::from_str::<serde_json::Value>(r_s4.split("\r\n\r\n").nth(1).unwrap())
        .unwrap()["id"]
        .as_u64()
        .unwrap() as u32;

    // 3. Switching SOCKS4 node (with UserID) to SOCKS5 without supplying a password must reject
    let upgrade_no_pw = format!(r#"{{"id":{},"protocol":"SOCKS5"}}"#, s4_id);
    let r_upgrade = raw_http(
        api_addr,
        &format!(
            "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            upgrade_no_pw.len(),
            upgrade_no_pw
        ),
    )
    .await;
    assert!(r_upgrade.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(r_upgrade.contains("ERR_USERNAME_WITHOUT_PASSWORD"));

    // 4. Add paired SOCKS5 node, check GET /api/nodes auth_configured=true, then PUT clear_password clears username too
    let s5_body = r#"{"name":"s5pair","protocol":"SOCKS5","server_addr":"10.0.0.2:1080","username":"alice","password":"pw1"}"#;
    let r_s5 = raw_http(
        api_addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            s5_body.len(),
            s5_body
        ),
    )
    .await;
    assert!(r_s5.starts_with("HTTP/1.1 200 OK"));
    let s5_id = serde_json::from_str::<serde_json::Value>(r_s5.split("\r\n\r\n").nth(1).unwrap())
        .unwrap()["id"]
        .as_u64()
        .unwrap() as u32;

    // Setting a new username alongside clear_password on PUT/PATCH rejects
    let patch_new_user_clear = format!(
        r#"{{"id":{},"username":"bob","clear_password":true}}"#,
        s5_id
    );
    let r_bad_patch = raw_http(
        api_addr,
        &format!(
            "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            patch_new_user_clear.len(),
            patch_new_user_clear
        ),
    )
    .await;
    assert!(r_bad_patch.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(r_bad_patch.contains("ERR_USERNAME_WITHOUT_PASSWORD"));

    // PUT with clear_password clears both password and username
    let put_clear = format!(
        r#"{{"id":{},"name":"s5pair","protocol":"SOCKS5","server_addr":"10.0.0.2:1080","username":"alice","clear_password":true}}"#,
        s5_id
    );
    let r_put_clear = raw_http(
        api_addr,
        &format!(
            "PUT /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            put_clear.len(),
            put_clear
        ),
    )
    .await;
    assert!(
        r_put_clear.starts_with("HTTP/1.1 200 OK"),
        "put_clear: {}",
        r_put_clear
    );
    {
        let guard = api_nodes.read().unwrap();
        let s5 = guard.get(&s5_id).unwrap();
        assert_eq!(s5.username, None);
        assert_eq!(s5.client.auth_credentials(), (None, None));
    }

    let r_list = raw_http(
        api_addr,
        &format!(
            "GET /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            api_port
        ),
    )
    .await;
    assert!(r_list.starts_with("HTTP/1.1 200 OK"));
    let views: Vec<ProxyNodeView> =
        serde_json::from_str(r_list.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    let s4_view = views.iter().find(|v| v.id == s4_id).unwrap();
    assert!(s4_view.auth_configured);
    assert!(!s4_view.password_configured);
    let s5_view = views.iter().find(|v| v.id == s5_id).unwrap();
    assert!(!s5_view.auth_configured);
    assert!(!s5_view.password_configured);
    assert_eq!(s5_view.username, None);

    // 5. PUT same username with keep_password=false, clear_password=false (e.g. SOCKS4 -> SOCKS5 without password) must reject
    let put_s4_to_s5_no_pw = format!(
        r#"{{"id":{},"name":"s4user","protocol":"SOCKS5","server_addr":"10.0.0.2:1080","username":"s4id","password":null,"keep_password":false,"clear_password":false}}"#,
        s4_id
    );
    let r_put_s4_s5 = raw_http(
        api_addr,
        &format!(
            "PUT /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            put_s4_to_s5_no_pw.len(),
            put_s4_to_s5_no_pw
        ),
    )
    .await;
    assert!(
        r_put_s4_s5.starts_with("HTTP/1.1 400 Bad Request"),
        "resp: {}",
        r_put_s4_s5
    );
    assert!(r_put_s4_s5.contains("ERR_USERNAME_WITHOUT_PASSWORD"));
    {
        let guard = api_nodes.read().unwrap();
        let s4 = guard.get(&s4_id).unwrap();
        assert_eq!(s4.protocol, "SOCKS4");
        assert_eq!(s4.username.as_deref(), Some("s4id"));
    }

    // 6. PUT/PATCH credential flag parity: keep_password=true + non-empty password, clear_username + username, SOCKS4 + ""
    let keep_and_pw_patch = format!(
        r#"{{"id":{},"username":"alice","password":"pw2","keep_password":true}}"#,
        s5_id
    );
    let r_keep_and_pw = raw_http(
        api_addr,
        &format!(
            "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            keep_and_pw_patch.len(),
            keep_and_pw_patch
        ),
    )
    .await;
    assert!(r_keep_and_pw.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(r_keep_and_pw.contains("ERR_CONFLICTING_PASSWORD_OPTIONS"));

    let keep_and_pw_put = format!(
        r#"{{"id":{},"name":"s5pair","protocol":"SOCKS5","server_addr":"10.0.0.2:1080","username":"alice","password":"pw2","keep_password":true}}"#,
        s5_id
    );
    let r_keep_and_pw_put = raw_http(
        api_addr,
        &format!(
            "PUT /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            keep_and_pw_put.len(),
            keep_and_pw_put
        ),
    )
    .await;
    assert!(r_keep_and_pw_put.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(r_keep_and_pw_put.contains("ERR_CONFLICTING_PASSWORD_OPTIONS"));

    let conflict_user_patch = format!(
        r#"{{"id":{},"username":"bob","clear_username":true}}"#,
        s5_id
    );
    let r_clear_user_conflict = raw_http(
        api_addr,
        &format!(
            "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            conflict_user_patch.len(),
            conflict_user_patch
        ),
    )
    .await;
    assert!(r_clear_user_conflict.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(r_clear_user_conflict.contains("ERR_CONFLICTING_USERNAME_OPTIONS"));

    let s4_empty_pw_patch = format!(r#"{{"id":{},"password":""}}"#, s4_id);
    let r_s4_empty_pw = raw_http(
        api_addr,
        &format!(
            "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            s4_empty_pw_patch.len(),
            s4_empty_pw_patch
        ),
    )
    .await;
    assert!(r_s4_empty_pw.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(r_s4_empty_pw.contains("ERR_SOCKS4_PASSWORD_UNSUPPORTED"));

    let s4_empty_pw_put = format!(
        r#"{{"id":{},"name":"s4user","protocol":"SOCKS4","server_addr":"10.0.0.2:1080","username":"s4id","password":""}}"#,
        s4_id
    );
    let r_s4_empty_pw_put = raw_http(
        api_addr,
        &format!(
            "PUT /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            s4_empty_pw_put.len(),
            s4_empty_pw_put
        ),
    )
    .await;
    assert!(r_s4_empty_pw_put.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(r_s4_empty_pw_put.contains("ERR_SOCKS4_PASSWORD_UNSUPPORTED"));
}

#[tokio::test]
async fn test_api_patch_clear_password_parity_conflict_and_control_chars() {
    let monitor = Arc::new(ConnectionManager::new());
    let rule_engine = Arc::new(RuleEngine::new(Vec::new(), Action::Direct));
    let nodes = Arc::new(RwLock::new(HashMap::new()));
    let server = ApiServer::new(
        "127.0.0.1:0".parse().unwrap(),
        monitor,
        rule_engine,
        Arc::clone(&nodes),
    );
    let listener = server.bind().await.unwrap();
    let api_addr = listener.local_addr().unwrap();
    let api_port = api_addr.port();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(async move { server.run(listener, shutdown_rx).await });

    // 1. Add SOCKS5 node with credentials
    let add_body = r#"{"name":"p2node","protocol":"SOCKS5","server_addr":"10.0.0.5:1080","username":"alice","password":"secret"}"#;
    let r_add = raw_http(
        api_addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            add_body.len(),
            add_body
        ),
    )
    .await;
    assert!(r_add.starts_with("HTTP/1.1 200 OK"), "add: {}", r_add);
    let id = serde_json::from_str::<serde_json::Value>(r_add.split("\r\n\r\n").nth(1).unwrap())
        .unwrap()["id"]
        .as_u64()
        .unwrap() as u32;

    // 2. PATCH clear_username + clear_password=false without keep_password must NOT silently clear password
    let patch_conflict = format!(
        r#"{{"id":{},"clear_username":true,"clear_password":false}}"#,
        id
    );
    let r_patch_conflict = raw_http(
        api_addr,
        &format!(
            "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            patch_conflict.len(),
            patch_conflict
        ),
    )
    .await;
    assert!(r_patch_conflict.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(r_patch_conflict.contains("ERR_CONFLICTING_PASSWORD_OPTIONS"));
    {
        let guard = nodes.read().unwrap();
        let entry = guard.get(&id).unwrap();
        assert_eq!(entry.username.as_deref(), Some("alice"));
        assert_eq!(
            entry.client.auth_credentials(),
            (Some("alice"), Some("secret"))
        );
    }

    // PUT with null username + clear_password=false + omitted keep_password also rejects cleanly
    let put_conflict = format!(
        r#"{{"id":{},"name":"p2node","protocol":"SOCKS5","server_addr":"10.0.0.5:1080","username":null,"clear_password":false}}"#,
        id
    );
    let r_put_conflict = raw_http(
        api_addr,
        &format!(
            "PUT /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            put_conflict.len(),
            put_conflict
        ),
    )
    .await;
    assert!(r_put_conflict.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(r_put_conflict.contains("ERR_CONFLICTING_PASSWORD_OPTIONS"));

    // 3. PATCH echoing existing username alongside clear_password=true clears both (parity with PUT)
    let patch_clear_same_user = format!(
        r#"{{"id":{},"username":"alice","clear_password":true}}"#,
        id
    );
    let r_patch_clear = raw_http(
        api_addr,
        &format!(
            "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            patch_clear_same_user.len(),
            patch_clear_same_user
        ),
    )
    .await;
    assert!(
        r_patch_clear.starts_with("HTTP/1.1 200 OK"),
        "patch_clear: {}",
        r_patch_clear
    );
    {
        let guard = nodes.read().unwrap();
        let entry = guard.get(&id).unwrap();
        assert_eq!(entry.username, None);
        assert_eq!(entry.client.auth_credentials(), (None, None));
    }

    // PATCH changing username alongside clear_password=true still rejects
    let patch_clear_diff_user =
        format!(r#"{{"id":{},"username":"bob","clear_password":true}}"#, id);
    let r_patch_diff = raw_http(
        api_addr,
        &format!(
            "PATCH /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            api_port,
            patch_clear_diff_user.len(),
            patch_clear_diff_user
        ),
    )
    .await;
    assert!(r_patch_diff.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(r_patch_diff.contains("ERR_USERNAME_WITHOUT_PASSWORD"));

    // 4. Control characters (\t, \x1b, \x7f) rejected on name, username, and password
    for (bad_body, expected_code) in [
        (
            r#"{"name":"bad\tname","protocol":"SOCKS5","server_addr":"10.0.0.5:1080"}"#,
            "ERR_INVALID_NODE_NAME",
        ),
        (
            r#"{"name":"ok","protocol":"SOCKS5","server_addr":"10.0.0.5:1080","username":"bad\u001buser","password":"secret"}"#,
            "ERR_INVALID_USERNAME",
        ),
        (
            r#"{"name":"ok","protocol":"SOCKS5","server_addr":"10.0.0.5:1080","username":"alice","password":"bad\u007fpass"}"#,
            "ERR_INVALID_PASSWORD",
        ),
    ] {
        let r_bad = raw_http(
            api_addr,
            &format!(
                "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                api_port,
                bad_body.len(),
                bad_body
            ),
        )
        .await;
        assert!(
            r_bad.starts_with("HTTP/1.1 400 Bad Request"),
            "resp: {}",
            r_bad
        );
        assert!(
            r_bad.contains(expected_code),
            "expected {} in {}",
            expected_code,
            r_bad
        );
    }

    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
}

#[tokio::test]
async fn test_api_mutations_preserve_persisted_transparent_enabled_across_cli_override() {
    use flowx::dns::FakeIpPool;
    use flowx::dns::server::DnsServer;
    use flowx::interceptor::dispatcher::DispatcherConfig;
    use flowx::interceptor::process::ProcessTracker;

    let cfg_guard = common::TempConfigGuard::new("flowx_api_transparent_override_test");
    let store = Arc::new(ConfigStore::new(cfg_guard.path()));
    let mgr = Arc::new(ConnectionManager::new());
    let re = Arc::new(RuleEngine::new(Vec::new(), Action::Direct));
    let nodes = Arc::new(RwLock::new(HashMap::new()));
    let fake_ip_pool = Arc::new(FakeIpPool::new_default());
    let tracker = Arc::new(ProcessTracker::new());
    let upstream_dns: SocketAddr = "223.5.5.5:53".parse().unwrap();

    let dispatcher_cfg = Arc::new(DispatcherConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        tracker,
        fake_ip_pool: Arc::clone(&fake_ip_pool),
        upstream_dns,
        rule_engine: Arc::clone(&re),
        monitor: Arc::clone(&mgr),
        proxy_nodes: Arc::clone(&nodes),
        proxy_chains: Arc::new(HashMap::new()),
        self_ports: vec![40001, 1053],
        in_flight: None,
    });
    let dns_server = Arc::new(DnsServer::new(
        "127.0.0.1:0".parse().unwrap(),
        fake_ip_pool,
        upstream_dns,
        true,
    ));
    // 模拟配置磁盘 enabled=true，但以 --no-transparent 临时启动（runtime enabled=false）
    let t_mgr = TransparentManager::new_with_persisted(
        dispatcher_cfg,
        dns_server,
        TransparentSettings {
            enabled: false,
            hijack_dns: true,
            block_quic_for_proxied: true,
            dll_path: None,
        },
        true,
    );

    let srv = ApiServer::new(
        "127.0.0.1:0".parse().unwrap(),
        mgr,
        Arc::clone(&re),
        Arc::clone(&nodes),
    )
    .with_self_ports(vec![40001, 40080, 1053])
    .with_config_store(Arc::clone(&store))
    .with_transparent_manager(Arc::clone(&t_mgr));
    let listener = srv.bind().await.unwrap();
    let addr = listener.local_addr().unwrap();
    let port = addr.port();
    let (shutdown_tx, rx) = watch::channel(false);
    let server_task = tokio::spawn(async move { srv.run(listener, rx).await });

    // 1. 新增代理节点触发持久化，不应把临时 --no-transparent 的 false 覆写到磁盘
    let node_body = r#"{"name":"n1","protocol":"SOCKS5","server_addr":"8.8.8.8:1080"}"#;
    let resp = raw_http(
        addr,
        &format!(
            "POST /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            node_body.len(),
            node_body
        ),
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "resp: {resp}");
    let saved1 = store.load_existing(&[]).unwrap();
    assert!(
        saved1.transparent_settings.enabled,
        "node mutation must preserve persisted enabled=true across --no-transparent"
    );
    assert!(!t_mgr.settings().enabled);

    // 2. 更新透明代理附加设置同样不得破坏 persisted enabled=true
    let cfg_body = r#"{"hijack_dns":false}"#;
    let resp2 = raw_http(
        addr,
        &format!(
            "PUT /api/transparent/config HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            cfg_body.len(),
            cfg_body
        ),
    )
    .await;
    assert!(resp2.starts_with("HTTP/1.1 200 OK"), "resp2: {resp2}");
    let saved2 = store.load_existing(&[]).unwrap();
    assert!(saved2.transparent_settings.enabled);
    assert!(!saved2.transparent_settings.hijack_dns);

    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
}

#[tokio::test]
async fn test_api_transparent_config_succeeds_after_boot_start_failure() {
    use flowx::dns::FakeIpPool;
    use flowx::dns::server::DnsServer;
    use flowx::interceptor::dispatcher::DispatcherConfig;
    use flowx::interceptor::process::ProcessTracker;

    let cfg_guard = common::TempConfigGuard::new("flowx_api_boot_fail_cfg_test");
    let store = Arc::new(ConfigStore::new(cfg_guard.path()));
    let mgr = Arc::new(ConnectionManager::new());
    let re = Arc::new(RuleEngine::new(Vec::new(), Action::Direct));
    let nodes = Arc::new(RwLock::new(HashMap::new()));
    let fake_ip_pool = Arc::new(FakeIpPool::new_default());
    let tracker = Arc::new(ProcessTracker::new());
    let upstream_dns: SocketAddr = "223.5.5.5:53".parse().unwrap();

    let dispatcher_cfg = Arc::new(DispatcherConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        tracker,
        fake_ip_pool: Arc::clone(&fake_ip_pool),
        upstream_dns,
        rule_engine: Arc::clone(&re),
        monitor: Arc::clone(&mgr),
        proxy_nodes: Arc::clone(&nodes),
        proxy_chains: Arc::new(HashMap::new()),
        self_ports: vec![40001, 1053],
        in_flight: None,
    });
    let dns_server = Arc::new(DnsServer::new(
        "127.0.0.1:0".parse().unwrap(),
        fake_ip_pool,
        upstream_dns,
        true,
    ));
    // 模拟配置 enabled=true，启动时驱动缺失导致 start 失败后调用 mark_boot_start_failed
    let t_mgr = TransparentManager::new_with_persisted(
        dispatcher_cfg,
        dns_server,
        TransparentSettings {
            enabled: true,
            hijack_dns: true,
            block_quic_for_proxied: true,
            dll_path: Some(r"C:\__missing__\WinDivert.dll".to_string()),
        },
        true,
    );
    let err = t_mgr
        .start(&tokio::runtime::Handle::current())
        .expect_err("missing driver or non-admin must fail on boot");
    assert!(err.contains("ERR_TRANSPARENT_"));
    t_mgr.mark_boot_start_failed();
    assert!(!t_mgr.settings().enabled);
    assert!(t_mgr.persisted_settings().enabled);

    let srv = ApiServer::new(
        "127.0.0.1:0".parse().unwrap(),
        mgr,
        Arc::clone(&re),
        Arc::clone(&nodes),
    )
    .with_self_ports(vec![40001, 40080, 1053])
    .with_config_store(Arc::clone(&store))
    .with_transparent_manager(Arc::clone(&t_mgr));
    let listener = srv.bind().await.unwrap();
    let addr = listener.local_addr().unwrap();
    let port = addr.port();
    let (shutdown_tx, rx) = watch::channel(false);
    let server_task = tokio::spawn(async move { srv.run(listener, rx).await });

    let cfg_body = r#"{"hijack_dns":false,"dll_path":"C:\\FlowX\\driver\\WinDivert.dll"}"#;
    let resp = raw_http(
        addr,
        &format!(
            "PUT /api/transparent/config HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            port,
            cfg_body.len(),
            cfg_body
        ),
    )
    .await;
    assert!(
        resp.starts_with("HTTP/1.1 200 OK"),
        "config update must not lock out: {resp}"
    );
    let saved = store.load_existing(&[]).unwrap();
    assert!(saved.transparent_settings.enabled);
    assert!(!saved.transparent_settings.hijack_dns);
    assert_eq!(
        saved.transparent_settings.dll_path.as_deref(),
        Some(r"C:\FlowX\driver\WinDivert.dll")
    );

    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
}
