mod common;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use flowx::api::ApiServer;
use flowx::cli::{CliEnv, format_cli_error_json, run_cli_with_env};
use flowx::config::ConfigStore;
use flowx::interceptor::dispatcher::ProxyNodeEntry;
use flowx::monitor::ConnectionManager;
use flowx::outbound::chain::ProxyNode;
use flowx::outbound::socks5::Socks5Client;
use flowx::router::{Action, Rule, RuleEngine};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

use common::DEFAULT_SELF_PORTS;

/// Run CLI in an explicit clean environment so host `FLOWX_API` / `FLOWX_CONFIG` / `FLOWX_LANG`
/// variables cannot pollute test outcomes.
async fn run_cli(args: &[String]) -> anyhow::Result<()> {
    run_cli_with_env(args, &CliEnv::clean()).await
}

/// RAII temp XML config guard that removes both the config file and its `.filename.lock` sidecar.
struct TempConfigGuard {
    path: std::path::PathBuf,
}

impl TempConfigGuard {
    fn new(prefix: &str) -> Self {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("{prefix}_{}_{}.xml", std::process::id(), ts));
        let guard = Self { path };
        guard.cleanup();
        guard
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn as_str(&self) -> String {
        self.path.to_string_lossy().to_string()
    }

    fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.path);
        if let (Some(parent), Some(name)) = (self.path.parent(), self.path.file_name()) {
            let lock_path = parent.join(format!(".{}.lock", name.to_string_lossy()));
            let _ = std::fs::remove_file(lock_path);
        }
    }
}

impl Drop for TempConfigGuard {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[tokio::test]
async fn test_cli_strict_arg_validation() {
    let temp_cfg_guard = TempConfigGuard::new("flowx_cli_unused");
    let temp_cfg = temp_cfg_guard.path();
    let cfg_str = temp_cfg_guard.as_str();

    // Unknown typo flag `--targe` must fail
    let err = run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "rule".into(),
        "add".into(),
        "--name".into(),
        "Bad".into(),
        "--action".into(),
        "Direct".into(),
        "--targe".into(),
        "github.com".into(),
    ])
    .await
    .unwrap_err();
    assert!(err.to_string().contains("Unknown option '--targe'"));

    // Extra positional argument on `status` must fail
    assert!(
        run_cli(&[
            "flowx".into(),
            "--offline".into(),
            "status".into(),
            "extra".into()
        ])
        .await
        .is_err()
    );

    // Mutually exclusive `--enable` + `--disable` must fail
    assert!(
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "rule".into(),
            "toggle".into(),
            "1".into(),
            "--enable".into(),
            "--disable".into(),
        ])
        .await
        .is_err()
    );

    // Mutually exclusive `--pass` + `--clear-password` must fail
    assert!(
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "node".into(),
            "update".into(),
            "101".into(),
            "--pass".into(),
            "secret".into(),
            "--clear-password".into(),
        ])
        .await
        .is_err()
    );

    // Mutually exclusive `--api` + `--offline` must fail
    assert!(
        run_cli(&[
            "flowx".into(),
            "--api".into(),
            "127.0.0.1:40080".into(),
            "--offline".into(),
            "status".into(),
        ])
        .await
        .is_err()
    );

    // `flowx serve --help` prints help and succeeds cleanly
    run_cli(&["flowx".into(), "serve".into(), "--help".into()])
        .await
        .unwrap();

    assert!(!temp_cfg.exists());
}

#[tokio::test]
async fn test_cli_offline_crud_and_simulate() {
    let cfg_guard = TempConfigGuard::new("flowx_cli_test");
    let path = cfg_guard.path();
    let cfg_str = cfg_guard.as_str();

    // 1. 添加节点 (显式 `--offline` 离线初始化并写入默认配置 + 新节点 #102，密码刻意命名为 `--json`)
    run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "node".into(),
        "add".into(),
        "--name".into(),
        "JP-Socks".into(),
        "--addr".into(),
        "10.20.0.1:1080".into(),
        "--protocol".into(),
        "SOCKS5".into(),
        "--user".into(),
        "alice".into(),
        "--pass".into(),
        "--json".into(),
    ])
    .await
    .unwrap();

    // 验证 `--pass --json` 写入了密码而不是被解析为全局 `--json`
    let store = ConfigStore::new(path);
    let (rt, _) = store.load_or_init(&DEFAULT_SELF_PORTS).unwrap();
    assert_eq!(
        rt.proxy_nodes
            .get(&102)
            .unwrap()
            .client
            .auth_credentials()
            .1,
        Some("--json")
    );

    // 1b. 使用 `--clear-password` 清除节点密码
    run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "--json".into(),
        "node".into(),
        "update".into(),
        "102".into(),
        "--clear-password".into(),
    ])
    .await
    .unwrap();
    let (rt, _) = store.load_or_init(&DEFAULT_SELF_PORTS).unwrap();
    assert_eq!(
        rt.proxy_nodes
            .get(&102)
            .unwrap()
            .client
            .auth_credentials()
            .1,
        None
    );

    // 2. 添加规则指向新节点 #102
    run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "--json".into(),
        "rule".into(),
        "add".into(),
        "--name".into(),
        "GitRule".into(),
        "--apps".into(),
        "git.exe".into(),
        "--targets".into(),
        "*.github.com".into(),
        "--ports".into(),
        "443".into(),
        "--action".into(),
        "Proxy:102".into(),
    ])
    .await
    .unwrap();

    // 3. 更新默认兜底动作
    run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "--json".into(),
        "default".into(),
        "Proxy:102".into(),
    ])
    .await
    .unwrap();

    // 4. 运行离线模拟
    run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "--json".into(),
        "sim".into(),
        "--app".into(),
        "git.exe".into(),
        "--target".into(),
        "api.github.com:443".into(),
    ])
    .await
    .unwrap();

    // 验证 XML 文件中的最终状态
    let (rt, _) = store.load_or_init(&DEFAULT_SELF_PORTS).unwrap();
    assert!(rt.proxy_nodes.contains_key(&102));
    assert!(rt.rules.iter().any(|r| r.name == "GitRule"));
    assert_eq!(rt.default_action, Action::Proxy(102));
}

#[tokio::test]
async fn test_cli_online_patch_and_1based_rule_index() {
    let mut nodes_map = HashMap::new();
    nodes_map.insert(
        101,
        ProxyNodeEntry {
            id: 101,
            name: "MainProxy".into(),
            protocol: "SOCKS5".into(),
            server_addr: "127.0.0.1:10808".into(),
            username: Some("bob".into()),
            client: ProxyNode::Socks5(
                Socks5Client::new("127.0.0.1:10808")
                    .with_auth("bob".to_string(), "oldpass".to_string()),
            ),
        },
    );
    let proxy_nodes = Arc::new(RwLock::new(nodes_map));
    let r1 = Rule::from_raw_with_id(
        100,
        "RuleOne",
        true,
        None,
        Some("example.com"),
        None,
        Action::Direct,
    );
    let r2 = Rule::from_raw_with_id(
        200,
        "RuleTwo",
        true,
        None,
        Some("github.com"),
        Some("443"),
        Action::Proxy(101),
    );
    let rule_engine = Arc::new(RuleEngine::new(vec![r1, r2], Action::Direct));
    let monitor = Arc::new(ConnectionManager::new());

    let server = ApiServer::new(
        "127.0.0.1:0".parse().unwrap(),
        monitor,
        Arc::clone(&rule_engine),
        Arc::clone(&proxy_nodes),
    );
    let listener = server.bind().await.unwrap();
    let api_addr = listener.local_addr().unwrap().to_string();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let srv_handle = tokio::spawn(async move {
        let _ = server.run(listener, shutdown_rx).await;
    });

    // 1. 在线 PATCH 节点密码，验证 --clear-password 生效
    run_cli(&[
        "flowx".into(),
        "--api".into(),
        api_addr.clone(),
        "--json".into(),
        "node".into(),
        "update".into(),
        "101".into(),
        "--clear-password".into(),
    ])
    .await
    .unwrap();
    assert_eq!(
        proxy_nodes
            .read()
            .unwrap()
            .get(&101)
            .unwrap()
            .client
            .auth_credentials()
            .1,
        None
    );

    // 2. 在线按 1-based 下标 `2` 禁用并更新规则（真实 ID 为 200）
    run_cli(&[
        "flowx".into(),
        "--api".into(),
        api_addr.clone(),
        "rule".into(),
        "toggle".into(),
        "2".into(),
        "--disable".into(),
    ])
    .await
    .unwrap();
    assert!(!rule_engine.current_rules()[1].enabled);

    run_cli(&[
        "flowx".into(),
        "--api".into(),
        api_addr.clone(),
        "rule".into(),
        "update".into(),
        "2".into(),
        "--targets".into(),
        "api.github.com".into(),
        "--enable".into(),
    ])
    .await
    .unwrap();
    let rules_after_update = rule_engine.current_rules();
    assert_eq!(rules_after_update[1].id, 200);
    assert!(rules_after_update[1].enabled);
    assert_eq!(rules_after_update[1].targets_raw, "api.github.com");

    // 3. 在线按 1-based 下标 `2` 上移至顶部，再按下标 `1` 删除
    run_cli(&[
        "flowx".into(),
        "--api".into(),
        api_addr.clone(),
        "rule".into(),
        "move".into(),
        "2".into(),
        "top".into(),
    ])
    .await
    .unwrap();
    assert_eq!(rule_engine.current_rules()[0].id, 200);

    run_cli(&[
        "flowx".into(),
        "--api".into(),
        api_addr.clone(),
        "rule".into(),
        "remove".into(),
        "1".into(),
    ])
    .await
    .unwrap();
    let remaining = rule_engine.current_rules();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, 100);

    let _ = shutdown_tx.send(true);
    let _ = srv_handle.await;
}

#[tokio::test]
async fn test_cli_readonly_commands_do_not_create_missing_config() {
    let cfg_guard = TempConfigGuard::new("flowx_cli_readonly_missing");
    let path = cfg_guard.path();
    let cfg_str = cfg_guard.as_str();

    let cmds: &[&[&str]] = &[
        &["status"],
        &["node", "list"],
        &["node", "ping", "1"],
        &["rule", "list"],
        &["default"],
        &["sim", "--app", "git.exe", "--target", "example.com:443"],
    ];

    for sub in cmds {
        let mut argv = vec![
            "flowx".to_string(),
            "--config".to_string(),
            cfg_str.clone(),
            "--offline".to_string(),
        ];
        argv.extend(sub.iter().map(|s| (*s).to_string()));
        let err = run_cli(&argv).await.unwrap_err();
        let err_json = format_cli_error_json(&err);
        assert_eq!(err_json["ok"], Value::Bool(false));
        assert!(
            !path.exists(),
            "read-only command {:?} must not create {}",
            sub,
            cfg_str
        );
    }
}

#[tokio::test]
async fn test_cli_json_errors_and_password_clear_rules() {
    let cfg_guard = TempConfigGuard::new("flowx_cli_pw_rules");
    let path = cfg_guard.path();
    let cfg_str = cfg_guard.as_str();

    // 1. Offline add with password but no username fails with structured ERR_PASSWORD_WITHOUT_USERNAME
    let err = run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "--json".into(),
        "node".into(),
        "add".into(),
        "--name".into(),
        "NoUser".into(),
        "--addr".into(),
        "10.0.0.2:1080".into(),
        "--pass".into(),
        "secret".into(),
    ])
    .await
    .unwrap_err();
    let j = format_cli_error_json(&err);
    assert_eq!(j["ok"], Value::Bool(false));
    assert_eq!(j["code"], "ERR_PASSWORD_WITHOUT_USERNAME");
    assert_eq!(j["status"], 400);

    // 2. Offline add with username + empty password fails with ERR_EMPTY_PASSWORD
    let err = run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "--json".into(),
        "node".into(),
        "add".into(),
        "--name".into(),
        "EmptyPass".into(),
        "--addr".into(),
        "10.0.0.2:1080".into(),
        "--user".into(),
        "alice".into(),
        "--pass".into(),
        "".into(),
    ])
    .await
    .unwrap_err();
    let j = format_cli_error_json(&err);
    assert_eq!(j["code"], "ERR_EMPTY_PASSWORD");
    assert_eq!(j["status"], 400);

    // 3. Offline add HTTP node with colon in username fails with ERR_HTTP_USERNAME_COLON
    let err = run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "node".into(),
        "add".into(),
        "--name".into(),
        "BadHttp".into(),
        "--protocol".into(),
        "HTTP".into(),
        "--addr".into(),
        "10.0.0.2:8080".into(),
        "--user".into(),
        "bad:user".into(),
        "--pass".into(),
        "secret".into(),
    ])
    .await
    .unwrap_err();
    let j = format_cli_error_json(&err);
    assert_eq!(j["code"], "ERR_HTTP_USERNAME_COLON");
    assert!(
        !path.exists(),
        "Failed offline mutations must not create {}",
        cfg_str
    );

    // 3b. Offline add HTTP/SOCKS5 with username but without password fails cleanly and does not create XML
    let err = run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "--json".into(),
        "node".into(),
        "add".into(),
        "--name".into(),
        "UserOnly".into(),
        "--addr".into(),
        "10.0.0.2:1080".into(),
        "--user".into(),
        "alice".into(),
    ])
    .await
    .unwrap_err();
    let j = format_cli_error_json(&err);
    assert_eq!(j["code"], "ERR_USERNAME_WITHOUT_PASSWORD");
    assert!(!path.exists());

    // 3c. Duplicate/conflicting aliases in `flowx sim` fail cleanly
    assert!(
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "sim".into(),
            "--target".into(),
            "example.com:443".into(),
            "--host".into(),
            "other.com".into(),
        ])
        .await
        .is_err()
    );
    assert!(
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "sim".into(),
            "--target".into(),
            "example.com:443".into(),
            "--app".into(),
            "curl.exe".into(),
            "--process".into(),
            "git.exe".into(),
        ])
        .await
        .is_err()
    );
    assert!(!path.exists());

    // 4. Add valid node then clear password with explicit `--pass ""` (clears username as well on SOCKS5/HTTP)
    run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "node".into(),
        "add".into(),
        "--name".into(),
        "ValidNode".into(),
        "--addr".into(),
        "10.0.0.2:1080".into(),
        "--user".into(),
        "alice".into(),
        "--pass".into(),
        "secret".into(),
    ])
    .await
    .unwrap();
    assert!(
        path.exists(),
        "Successful offline mutation must persist {}",
        cfg_str
    );

    run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "node".into(),
        "update".into(),
        "102".into(),
        "--pass".into(),
        "".into(),
    ])
    .await
    .unwrap();

    let store = ConfigStore::new(path);
    let rt = store.load_existing(&DEFAULT_SELF_PORTS).unwrap();
    let node = rt.proxy_nodes.get(&102).unwrap();
    assert_eq!(node.username, None);
    assert_eq!(node.client.auth_credentials(), (None, None));
    assert!(!node.is_auth_configured());

    // 5. Online API HTTP 400 response preserves structured JSON error code/status
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = listener.local_addr().unwrap().to_string();
    let srv = tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut req_buf = [0u8; 2048];
            let _ = sock.read(&mut req_buf).await;
            let body = r#"{"ok":false,"code":"ERR_RULE_CONFLICT","error":"Conflict"}"#;
            let resp = format!(
                "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        }
    });

    let api_err = run_cli(&[
        "flowx".into(),
        "--api".into(),
        mock_addr,
        "--json".into(),
        "node".into(),
        "list".into(),
    ])
    .await
    .unwrap_err();
    let _ = srv.await;
    let j = format_cli_error_json(&api_err);
    assert_eq!(j["ok"], Value::Bool(false));
    assert_eq!(j["code"], "ERR_RULE_CONFLICT");
    assert_eq!(j["error"], "Conflict");
    assert_eq!(j["status"], 409);
}

#[tokio::test]
async fn test_cli_transparent_commands_and_config_preservation() {
    let cfg_guard = TempConfigGuard::new("flowx_cli_transparent_test");
    let cfg_path = cfg_guard.path();
    let cfg_str = cfg_guard.as_str();

    // 1. Readonly status must not create missing config file; offline doctor works cleanly without one
    assert!(
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "transparent".into(),
            "status".into(),
        ])
        .await
        .is_err()
    );
    assert!(!cfg_path.exists());

    run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "--json".into(),
        "transparent".into(),
        "doctor".into(),
    ])
    .await
    .unwrap();
    assert!(!cfg_path.exists());

    // 2. Conflicting options fail fast
    assert!(
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "transparent".into(),
            "config".into(),
            "--hijack-dns".into(),
            "--no-hijack-dns".into(),
        ])
        .await
        .is_err()
    );
    assert!(
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "transparent".into(),
            "config".into(),
            "--dll-path".into(),
            r"C:\ok\WinDivert.dll".into(),
            "--clear-dll-path".into(),
        ])
        .await
        .is_err()
    );
    assert!(
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "transparent".into(),
            "config".into(),
        ])
        .await
        .is_err()
    );

    // 3. Configure + enable persists to XML and survives node/rule mutations
    run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "transparent".into(),
        "config".into(),
        "--no-hijack-dns".into(),
        "--no-block-quic".into(),
        "--dll-path".into(),
        r"C:\tools\WinDivert.dll".into(),
    ])
    .await
    .unwrap();
    run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "transparent".into(),
        "enable".into(),
    ])
    .await
    .unwrap();
    run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "node".into(),
        "add".into(),
        "--name".into(),
        "PreserveNode".into(),
        "--addr".into(),
        "10.0.0.2:1080".into(),
    ])
    .await
    .unwrap();

    let loaded = ConfigStore::new(cfg_path).load_existing(&[]).unwrap();
    assert!(loaded.transparent_settings.enabled);
    assert!(!loaded.transparent_settings.hijack_dns);
    assert!(!loaded.transparent_settings.block_quic_for_proxied);
    assert_eq!(
        loaded.transparent_settings.dll_path.as_deref(),
        Some(r"C:\tools\WinDivert.dll")
    );

    // 4. Clear DLL path + disable updates XML cleanly
    run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "transparent".into(),
        "config".into(),
        "--clear-dll-path".into(),
    ])
    .await
    .unwrap();
    run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "transparent".into(),
        "disable".into(),
    ])
    .await
    .unwrap();

    let updated = ConfigStore::new(cfg_path).load_existing(&[]).unwrap();
    assert!(!updated.transparent_settings.enabled);
    assert!(!updated.transparent_settings.hijack_dns);
    assert!(!updated.transparent_settings.block_quic_for_proxied);
    assert!(updated.transparent_settings.dll_path.is_none());
}

#[tokio::test]
async fn test_cli_transparent_doctor_respects_explicit_api() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // 1. 显式传入不可达 --api 时，doctor 必须报错，绝不静默回退离线探测
    let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead_listener.local_addr().unwrap();
    drop(dead_listener);
    assert!(
        run_cli(&[
            "flowx".into(),
            "--api".into(),
            format!("http://{}", dead_addr),
            "--json".into(),
            "transparent".into(),
            "doctor".into(),
        ])
        .await
        .is_err(),
        "flowx transparent doctor with unreachable --api must fail instead of falling back offline"
    );

    // 2. 显式传入在线 --api 时，doctor 必须请求 /api/transparent/status
    let mock_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_listener.local_addr().unwrap();
    let (path_tx, path_rx) = tokio::sync::oneshot::channel::<String>();
    let mock_srv = tokio::spawn(async move {
        let (mut s, _) = mock_listener.accept().await.unwrap();
        let mut req_buf = [0u8; 2048];
        let n = s.read(&mut req_buf).await.unwrap();
        let req_line = String::from_utf8_lossy(&req_buf[..n])
            .lines()
            .next()
            .unwrap_or_default()
            .to_string();
        let _ = path_tx.send(req_line);
        let body = r#"{"supported":true,"enabled":true,"running":true,"elevated":true,"dll_found":true,"sys_found":true,"dll_path":"C:\\FlowX\\WinDivert.dll","sys_path":"C:\\FlowX\\WinDivert64.sys","searched_dirs":["C:\\FlowX"],"hijack_dns":true,"block_quic_for_proxied":true,"configured_dll_path":null,"last_error":null}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        s.write_all(resp.as_bytes()).await.unwrap();
    });

    run_cli(&[
        "flowx".into(),
        "--api".into(),
        format!("http://{}", mock_addr),
        "--json".into(),
        "transparent".into(),
        "doctor".into(),
    ])
    .await
    .unwrap();
    mock_srv.await.unwrap();
    let req_line = path_rx.await.unwrap();
    assert!(
        req_line.starts_with("GET /api/transparent/status "),
        "expected GET /api/transparent/status, got: {req_line}"
    );
}

#[tokio::test]
async fn test_cli_offline_control_errors_rule_move_flag_and_ping_all() {
    use tokio::net::TcpListener;

    let cfg_guard = TempConfigGuard::new("flowx_cli_offline_ctrl");
    let cfg_path = cfg_guard.path();
    let cfg_str = cfg_guard.as_str();

    // 1. Create a reachable local node and a rule referencing it
    let alive_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let alive_addr = alive_listener.local_addr().unwrap();
    let accept_task = tokio::spawn(async move {
        for _ in 0..4 {
            if let Ok((s, _)) = alive_listener.accept().await {
                drop(s);
            }
        }
    });

    // Save a minimal initial profile pointing default proxy #101 to the reachable local listener
    let store = ConfigStore::new(cfg_path);
    let mut profile = flowx::config::ProfileConfig::default_profile();
    let p101 = &mut profile.proxy_list.as_mut().unwrap().proxies[0];
    p101.id = 101;
    p101.name = Some("AliveLocal".into());
    p101.address = alive_addr.ip().to_string();
    p101.port = alive_addr.port();
    store.save_profile(&profile).unwrap();

    // 2. Offline `node ping --all --json` succeeds when every node is reachable
    run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "--json".into(),
        "node".into(),
        "ping".into(),
        "--all".into(),
    ])
    .await
    .unwrap();

    // 3. Offline `node remove` of a referenced node returns structured 409 ERR_NODE_IN_USE
    let in_use_err = run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "--json".into(),
        "node".into(),
        "remove".into(),
        "101".into(),
    ])
    .await
    .unwrap_err();
    let j = format_cli_error_json(&in_use_err);
    assert_eq!(j["code"], "ERR_NODE_IN_USE");
    assert_eq!(j["status"], 409);

    // 4. Offline `node remove` / `node ping` of missing node returns structured 404 ERR_NODE_NOT_FOUND
    for sub in ["remove", "ping"] {
        let missing_err = run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "--json".into(),
            "node".into(),
            sub.into(),
            "999".into(),
        ])
        .await
        .unwrap_err();
        let j = format_cli_error_json(&missing_err);
        assert_eq!(j["code"], "ERR_NODE_NOT_FOUND");
        assert_eq!(j["status"], 404);
    }

    // 5. Offline `rule toggle` / `rule move` / `rule remove` missing rule -> 404 ERR_RULE_NOT_FOUND
    for args in [
        vec!["rule", "toggle", "999"],
        vec!["rule", "move", "999", "up"],
        vec!["rule", "remove", "999"],
    ] {
        let mut argv = vec![
            "flowx".to_string(),
            "--config".to_string(),
            cfg_str.clone(),
            "--offline".to_string(),
            "--json".to_string(),
        ];
        argv.extend(args.into_iter().map(String::from));
        let err = run_cli(&argv).await.unwrap_err();
        let j = format_cli_error_json(&err);
        assert_eq!(j["code"], "ERR_RULE_NOT_FOUND");
        assert_eq!(j["status"], 404);
    }

    // 6. Offline `rule move` with invalid direction -> 400 ERR_INVALID_MOVE_DIR
    let bad_dir_err = run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "--json".into(),
        "rule".into(),
        "move".into(),
        "1".into(),
        "sideways".into(),
    ])
    .await
    .unwrap_err();
    let j = format_cli_error_json(&bad_dir_err);
    assert_eq!(j["code"], "ERR_INVALID_MOVE_DIR");
    assert_eq!(j["status"], 400);

    // 7. Offline `rule move --id 2 up` (flag + positional direction, 1-based index) swaps rules cleanly
    let before = store.load_existing(&DEFAULT_SELF_PORTS).unwrap().rules;
    assert!(before.len() >= 2);
    let second_name = before[1].name.clone();
    run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "--json".into(),
        "rule".into(),
        "move".into(),
        "--id".into(),
        "2".into(),
        "up".into(),
    ])
    .await
    .unwrap();
    let after = store.load_existing(&DEFAULT_SELF_PORTS).unwrap().rules;
    assert_eq!(after[0].name, second_name);

    // 8. Add an unreachable closed local node; offline `node ping --all --json` exits with status 1
    let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead_listener.local_addr().unwrap();
    drop(dead_listener);
    run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "node".into(),
        "add".into(),
        "--name".into(),
        "DeadLocal".into(),
        "--addr".into(),
        dead_addr.to_string(),
    ])
    .await
    .unwrap();

    let ping_all_err = run_cli(&[
        "flowx".into(),
        "--config".into(),
        cfg_str.clone(),
        "--offline".into(),
        "--json".into(),
        "node".into(),
        "ping".into(),
        "--all".into(),
    ])
    .await
    .unwrap_err();
    assert!(
        ping_all_err.to_string().contains("status 1"),
        "expected SilentExitError status 1 when any node is unreachable, got: {ping_all_err}"
    );

    accept_task.abort();
    let _ = accept_task.await;
}

#[tokio::test]
async fn test_cli_online_clear_user_clear_apps_and_rule_move_id_flag() {
    use flowx::outbound::socks4::Socks4Client;

    let mut nodes_map = HashMap::new();
    nodes_map.insert(
        101,
        ProxyNodeEntry {
            id: 101,
            name: "Socks4WithUser".into(),
            protocol: "SOCKS4".into(),
            server_addr: "127.0.0.1:10804".into(),
            username: Some("legacy-uid".into()),
            client: ProxyNode::Socks4(
                Socks4Client::new("127.0.0.1:10804").with_user_id("legacy-uid".to_string()),
            ),
        },
    );
    let proxy_nodes = Arc::new(RwLock::new(nodes_map));
    let r1 = Rule::from_raw_with_id(
        10,
        "FirstRule",
        true,
        Some("curl.exe"),
        Some("example.com"),
        Some("443"),
        Action::Direct,
    );
    let r2 = Rule::from_raw_with_id(
        20,
        "SecondRule",
        true,
        Some("git.exe"),
        Some("github.com"),
        Some("443"),
        Action::Proxy(101),
    );
    let rule_engine = Arc::new(RuleEngine::new(vec![r1, r2], Action::Direct));
    let monitor = Arc::new(ConnectionManager::new());

    let server = ApiServer::new(
        "127.0.0.1:0".parse().unwrap(),
        monitor,
        Arc::clone(&rule_engine),
        Arc::clone(&proxy_nodes),
    );
    let listener = server.bind().await.unwrap();
    let api_addr = listener.local_addr().unwrap().to_string();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let srv_handle = tokio::spawn(async move {
        let _ = server.run(listener, shutdown_rx).await;
    });

    // 1. Online `node update 101 --clear-user` clears SOCKS4 UserID cleanly
    run_cli(&[
        "flowx".into(),
        "--api".into(),
        api_addr.clone(),
        "--json".into(),
        "node".into(),
        "update".into(),
        "101".into(),
        "--clear-user".into(),
    ])
    .await
    .unwrap();
    {
        let guard = proxy_nodes.read().unwrap();
        let node = guard.get(&101).unwrap();
        assert_eq!(node.username, None);
        assert_eq!(node.client.auth_credentials(), (None, None));
        assert!(!node.is_auth_configured());
    }

    // 2. Online `rule update 10 --clear-apps` clears apps while preserving targets & ports
    run_cli(&[
        "flowx".into(),
        "--api".into(),
        api_addr.clone(),
        "--json".into(),
        "rule".into(),
        "update".into(),
        "10".into(),
        "--clear-apps".into(),
    ])
    .await
    .unwrap();
    {
        let rules = rule_engine.current_rules();
        assert_eq!(rules[0].id, 10);
        assert!(rules[0].apps_raw.is_empty());
        assert_eq!(rules[0].targets_raw, "example.com");
        assert_eq!(rules[0].ports_raw, "443");
    }

    // 3. Online `rule move --id 20 up` moves rule #20 ahead of rule #10
    run_cli(&[
        "flowx".into(),
        "--api".into(),
        api_addr.clone(),
        "--json".into(),
        "rule".into(),
        "move".into(),
        "--id".into(),
        "20".into(),
        "up".into(),
    ])
    .await
    .unwrap();
    assert_eq!(rule_engine.current_rules()[0].id, 20);
    assert_eq!(rule_engine.current_rules()[1].id, 10);

    let _ = shutdown_tx.send(true);
    let _ = srv_handle.await;
}
