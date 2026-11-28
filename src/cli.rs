mod args;
mod bridge;
mod conn;
mod http_client;
mod node;
mod rule;
mod status_sim;
mod transparent;

use anyhow::{Result, bail};

pub use args::{
    CliEnv, GlobalCliOpts, LaunchMode, parse_global_opts, parse_global_opts_with_env, print_help,
    resolve_launch_mode, resolve_launch_mode_with_env, should_run_cli, should_run_cli_with_env,
    wants_json_output, wants_json_output_with_env,
};
pub use http_client::{ApiHttpError, emit_cli_error_and_exit, format_cli_error_json};

pub async fn run_cli(args: &[String]) -> Result<()> {
    run_cli_with_env(args, &CliEnv::from_process()).await
}

pub async fn run_cli_with_env(args: &[String], env: &CliEnv) -> Result<()> {
    let opts = parse_global_opts_with_env(args, env)?;
    if opts.show_help {
        print_help();
        return Ok(());
    }
    let Some(cmd) = opts.rest.first().map(|s| s.as_str()) else {
        print_help();
        return Ok(());
    };

    match cmd {
        "help" | "--help" | "-h" => {
            if cmd == "help" {
                let tail = if opts.rest.len() > 1 {
                    &opts.rest[1..]
                } else {
                    &[]
                };
                let _ = args::parse_flags_with_spec(
                    tail,
                    args::ArgSpec {
                        cmd_label: "flowx help",
                        value_flags: &[],
                        bool_flags: &[],
                        min_pos: 0,
                        max_pos: 0,
                    },
                )?;
            }
            print_help();
            Ok(())
        }
        "version" | "--version" | "-V" => {
            let tail = if opts.rest.len() > 1 {
                &opts.rest[1..]
            } else {
                &[]
            };
            let _ = args::parse_flags_with_spec(
                tail,
                args::ArgSpec {
                    cmd_label: "flowx version",
                    value_flags: &[],
                    bool_flags: &[],
                    min_pos: 0,
                    max_pos: 0,
                },
            )?;
            if opts.json_output {
                println!(r#"{{"version":"{}"}}"#, env!("CARGO_PKG_VERSION"));
            } else {
                println!("flowx v{}", env!("CARGO_PKG_VERSION"));
            }
            Ok(())
        }
        "status" => status_sim::cmd_status(&opts).await,
        "transparent" => transparent::cmd_transparent(&opts).await,
        "node" => node::cmd_node(&opts).await,
        "rule" => rule::cmd_rule(&opts).await,
        "default" => status_sim::cmd_default(&opts).await,
        "sim" | "simulate" => status_sim::cmd_sim(&opts).await,
        "conn" | "connections" => conn::cmd_conn(&opts).await,
        other => bail!(
            "Unknown subcommand '{}'. Run `flowx --help` for usage.",
            other
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CliEnv, GlobalCliOpts, LaunchMode, format_cli_error_json, wants_json_output,
        wants_json_output_with_env,
    };
    use crate::cli::args::{
        ArgSpec, ParsedCliInvocation, normalize_api_addr, parse_cli_invocation_with_env,
        parse_flags_with_spec, resolve_config_path_from_env,
    };
    use crate::cli::bridge::DEFAULT_SELF_PORTS;
    use crate::cli::conn::conn_matches_filter;
    use crate::cli::http_client::{
        API_CONNECT_TIMEOUT, API_IO_TIMEOUT, ApiTransportError, SilentExitError,
        api_request_raw_with_timeouts,
    };
    use crate::cli::transparent::build_transparent_doctor_report;
    use crate::config::ConfigStore;
    use crate::i18n::Locale;
    use anyhow::Result;
    use serde_json::{Value, json};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct TempConfigGuard {
        path: std::path::PathBuf,
    }

    impl TempConfigGuard {
        fn new(prefix: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};

            static NEXT_SEQ: AtomicU64 = AtomicU64::new(1);
            let seq = NEXT_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::current_dir()
                .unwrap()
                .join("target")
                .join(format!(
                    "{prefix}_{}_{}_{}.xml",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos(),
                    seq
                ));
            let g = Self { path };
            g.cleanup();
            g
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
                let file_name = name.to_string_lossy();
                let _ = std::fs::remove_file(parent.join(format!(".{file_name}.lock")));
                let tmp_prefix = format!(".{file_name}.tmp.");
                if let Ok(entries) = std::fs::read_dir(parent) {
                    for entry in entries.flatten() {
                        if entry.file_name().to_string_lossy().starts_with(&tmp_prefix) {
                            let _ = std::fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
    }

    impl Drop for TempConfigGuard {
        fn drop(&mut self) {
            self.cleanup();
        }
    }

    async fn run_cli(args: &[String]) -> Result<()> {
        super::run_cli_with_env(args, &CliEnv::clean()).await
    }

    fn parse_cli_invocation(args: &[String]) -> Result<ParsedCliInvocation> {
        parse_cli_invocation_with_env(args, &CliEnv::clean())
    }

    fn parse_global_opts(args: &[String]) -> Result<GlobalCliOpts> {
        super::parse_global_opts_with_env(args, &CliEnv::clean())
    }

    fn resolve_launch_mode(args: &[String]) -> Result<LaunchMode> {
        super::resolve_launch_mode_with_env(args, &CliEnv::clean())
    }

    fn should_run_cli(args: &[String]) -> bool {
        super::should_run_cli_with_env(args, &CliEnv::clean())
    }

    #[test]
    fn test_cli_env_isolation_and_lazy_flowx_api_validation() {
        let poisoned = CliEnv {
            flowx_config: Some("env-custom.xml".into()),
            flowx_api: Some("://invalid-host-env".into()),
            locale: Locale::Zh,
        };

        // `--offline`, explicit `--api`, `--help`, and `serve` must ignore an invalid ambient FLOWX_API
        let offline = parse_cli_invocation_with_env(
            &["flowx".into(), "--offline".into(), "status".into()],
            &poisoned,
        )
        .unwrap();
        assert!(offline.opts.offline);
        assert_eq!(offline.opts.config_path, "env-custom.xml");

        let explicit = parse_cli_invocation_with_env(
            &[
                "flowx".into(),
                "--api".into(),
                "127.0.0.1:41234".into(),
                "status".into(),
            ],
            &poisoned,
        )
        .unwrap();
        assert_eq!(explicit.opts.api_addr, "127.0.0.1:41234");
        assert!(explicit.opts.api_explicit);

        let help =
            parse_cli_invocation_with_env(&["flowx".into(), "--help".into()], &poisoned).unwrap();
        assert!(help.opts.show_help);

        // Local meta subcommands `help`, `version`, `--version`, `-V` also ignore invalid FLOWX_API
        for meta in ["help", "version", "--version", "-V"] {
            let parsed =
                parse_cli_invocation_with_env(&["flowx".into(), meta.into()], &poisoned).unwrap();
            assert_eq!(parsed.opts.rest.first().map(String::as_str), Some(meta));
        }

        // `wants_json_output_with_env` handles `--replace-pid` value flag and ignores poisoned env
        assert!(!wants_json_output_with_env(
            &[
                "flowx".into(),
                "--replace-pid".into(),
                "--json".into(),
                "serve".into(),
            ],
            &poisoned
        ));
        assert!(wants_json_output_with_env(
            &[
                "flowx".into(),
                "--offline".into(),
                "--json".into(),
                "status".into(),
            ],
            &poisoned
        ));

        let serve =
            parse_cli_invocation_with_env(&["flowx".into(), "serve".into()], &poisoned).unwrap();
        assert_eq!(
            serve.mode,
            LaunchMode::Serve {
                config_path: "env-custom.xml".into(),
                transparent_override: None,
                replace_pid: None,
            }
        );

        // Plain online CLI subcommand without `--api`/`--offline` still validates FLOWX_API
        assert!(
            parse_cli_invocation_with_env(&["flowx".into(), "status".into()], &poisoned).is_err()
        );

        // Valid FLOWX_API is normalized and marks api_explicit=true
        let valid_env = CliEnv {
            flowx_config: None,
            flowx_api: Some("http://127.0.0.1:49080/".into()),
            locale: Locale::En,
        };
        let online =
            parse_cli_invocation_with_env(&["flowx".into(), "status".into()], &valid_env).unwrap();
        assert_eq!(online.opts.api_addr, "127.0.0.1:49080");
        assert!(online.opts.api_explicit);
    }

    #[test]
    fn test_should_run_cli_detection() {
        assert!(!should_run_cli(&["flowx".into()]));
        assert_eq!(
            resolve_launch_mode(&["flowx".into(), "--config".into(), "custom.xml".into()]).unwrap(),
            LaunchMode::Serve {
                config_path: "custom.xml".into(),
                transparent_override: None,
                replace_pid: None,
            }
        );
        assert_eq!(
            resolve_launch_mode(&["flowx".into(), "serve".into(), "--config=custom.xml".into()])
                .unwrap(),
            LaunchMode::Serve {
                config_path: "custom.xml".into(),
                transparent_override: None,
                replace_pid: None,
            }
        );
        assert_eq!(
            resolve_launch_mode(&[
                "flowx".into(),
                "--transparent".into(),
                "--replace-pid".into(),
                "4321".into(),
            ])
            .unwrap(),
            LaunchMode::Serve {
                config_path: "flowx.xml".into(),
                transparent_override: Some(true),
                replace_pid: Some(4321),
            }
        );
        assert_eq!(
            resolve_launch_mode(&[
                "flowx".into(),
                "serve".into(),
                "--no-transparent".into(),
                "--replace-pid=777".into(),
            ])
            .unwrap(),
            LaunchMode::Serve {
                config_path: "flowx.xml".into(),
                transparent_override: Some(false),
                replace_pid: Some(777),
            }
        );
        assert!(
            resolve_launch_mode(&[
                "flowx".into(),
                "--transparent".into(),
                "--no-transparent".into(),
            ])
            .is_err()
        );
        assert!(
            resolve_launch_mode(&["flowx".into(), "--replace-pid".into(), "0".into(),]).is_err()
        );
        assert!(
            parse_global_opts(&["flowx".into(), "--transparent".into(), "status".into()]).is_err()
        );
        assert!(should_run_cli(&["flowx".into(), "status".into()]));
        assert!(should_run_cli(&["flowx".into(), "--help".into()]));
        assert!(should_run_cli(&[
            "flowx".into(),
            "serve".into(),
            "--help".into()
        ]));
        assert!(should_run_cli(&["flowx".into(), "--config".into()]));
        assert!(resolve_launch_mode(&["flowx".into(), "--config".into()]).is_err());
        assert!(should_run_cli(&[
            "flowx".into(),
            "--json".into(),
            "serve".into()
        ]));
        assert!(parse_global_opts(&["flowx".into(), "--json".into(), "serve".into()]).is_err());
        assert!(should_run_cli(&["flowx".into(), "--unknown".into()]));
        assert!(parse_global_opts(&["flowx".into(), "--unknown".into()]).is_err());

        // Value matching a global flag name (e.g. `--pass --json`) stays bound to `--pass`
        let opts = parse_global_opts(&[
            "flowx".into(),
            "node".into(),
            "add".into(),
            "--name".into(),
            "N".into(),
            "--addr".into(),
            "10.0.0.1:1080".into(),
            "--pass".into(),
            "--json".into(),
        ])
        .unwrap();
        assert!(!opts.json_output);
        assert!(opts.rest.ends_with(&["--pass".into(), "--json".into()]));
    }

    #[tokio::test]
    async fn test_cli_explicit_api_and_timeout_no_offline_fallback() {
        let temp_cfg_guard = TempConfigGuard::new("flowx_cli_nofallback");
        let temp_cfg = temp_cfg_guard.path();
        let cfg_str = temp_cfg_guard.as_str();

        // Bind then drop ephemeral listener to get a guaranteed refused localhost port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = listener.local_addr().unwrap().to_string();
        drop(listener);

        let err = run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--api".into(),
            closed_addr,
            "node".into(),
            "add".into(),
            "--name".into(),
            "ShouldFail".into(),
            "--addr".into(),
            "10.0.0.1:1080".into(),
        ])
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("refused"), "unexpected error message: {}", msg);
        assert!(
            !temp_cfg.exists(),
            "Explicit --api refusal must not silently create or mutate local XML"
        );

        // Stalled server socket that accepts and sleeps -> timeout error (never silent fallback)
        let stall_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stall_addr = stall_listener.local_addr().unwrap().to_string();
        let _stall_task = tokio::spawn(async move {
            if let Ok((_sock, _)) = stall_listener.accept().await {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
        let timeout_err = api_request_raw_with_timeouts(
            &stall_addr,
            Locale::En,
            "GET",
            "/api/system",
            None,
            Duration::from_millis(500),
            Duration::from_millis(80),
        )
        .await
        .unwrap_err();
        assert!(matches!(timeout_err, ApiTransportError::Other(_)));

        // Truncated HTTP response (EOF before Content-Length) must fail as Other error
        let trunc_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let trunc_addr = trunc_listener.local_addr().unwrap().to_string();
        let _trunc_task = tokio::spawn(async move {
            if let Ok((mut sock, _)) = trunc_listener.accept().await {
                let mut req_buf = [0u8; 512];
                let _ = sock.read(&mut req_buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n{\"ok\":")
                    .await;
            }
        });
        let trunc_err = run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str,
            "--api".into(),
            trunc_addr,
            "status".into(),
        ])
        .await
        .unwrap_err();
        assert!(trunc_err.to_string().contains("Truncated HTTP response"));
    }

    #[test]
    fn test_cli_normalize_api_addr_and_wants_json_output() {
        assert_eq!(
            normalize_api_addr("127.0.0.1:40080").unwrap(),
            "127.0.0.1:40080"
        );
        assert_eq!(
            normalize_api_addr("HTTP://127.0.0.1:40080/").unwrap(),
            "127.0.0.1:40080"
        );
        assert_eq!(normalize_api_addr("[::1]:40080").unwrap(), "[::1]:40080");
        assert_eq!(
            normalize_api_addr("localhost:40080").unwrap(),
            "localhost:40080"
        );

        for invalid in [
            "",
            "127.0.0.1",
            "127.0.0.1:0",
            "[::1]",
            "[::1]:0",
            "::1:40080",
            "HTTPS://127.0.0.1:40080",
            "ftp://127.0.0.1:40080",
            "--offline",
            "127.0.0.1:40080/api",
            "127.0.0.1:40080?x=1",
            "user@127.0.0.1:40080",
            "localhost:99999",
        ] {
            assert!(
                normalize_api_addr(invalid).is_err(),
                "expected '{}' to be rejected",
                invalid
            );
        }

        assert!(wants_json_output(&[
            "flowx".into(),
            "--json".into(),
            "status".into()
        ]));
        assert!(wants_json_output(&[
            "flowx".into(),
            "--json".into(),
            "--api".into(),
            "127.0.0.1".into(),
            "status".into()
        ]));
        assert!(!wants_json_output(&[
            "flowx".into(),
            "node".into(),
            "add".into(),
            "--pass".into(),
            "--json".into(),
            "--api".into(),
            "127.0.0.1".into()
        ]));
        assert!(!wants_json_output(&[
            "flowx".into(),
            "--api".into(),
            "--json".into(),
            "status".into()
        ]));
    }

    #[tokio::test]
    async fn test_cli_double_dash_empty_config_env_chunked_and_exit_status() {
        // 1. FLOWX_CONFIG empty/whitespace normalization
        assert_eq!(resolve_config_path_from_env(None), "flowx.xml");
        assert_eq!(resolve_config_path_from_env(Some("")), "flowx.xml");
        assert_eq!(resolve_config_path_from_env(Some("   ")), "flowx.xml");
        assert_eq!(
            resolve_config_path_from_env(Some("  custom.xml  ")),
            "custom.xml"
        );

        // 2. `--` end-of-options in both parse_cli_invocation and parse_flags_with_spec
        let inv = parse_cli_invocation(&[
            "flowx".into(),
            "--offline".into(),
            "--".into(),
            "node".into(),
            "list".into(),
        ])
        .unwrap();
        assert!(inv.opts.offline);
        assert_eq!(inv.opts.rest, vec!["node", "list"]);

        let (pos, flags) = parse_flags_with_spec(
            &["--name".into(), "R1".into(), "--".into(), "-literal".into()],
            ArgSpec {
                cmd_label: "flowx test",
                value_flags: &["name"],
                bool_flags: &[],
                min_pos: 1,
                max_pos: 1,
            },
        )
        .unwrap();
        assert_eq!(flags.get("name").map(String::as_str), Some("R1"));
        assert_eq!(pos, vec!["-literal"]);

        let inv_bad_node = run_cli(&[
            "flowx".into(),
            "--offline".into(),
            "node".into(),
            "update".into(),
            "--".into(),
            "-123".into(),
        ])
        .await
        .unwrap_err();
        assert!(inv_bad_node.to_string().contains("Invalid node ID"));

        // 3. HTTP client chunked decoding + Accept-Language header from locale
        let listener_chunked = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_chunked = listener_chunked.local_addr().unwrap().to_string();
        let srv_chunked = tokio::spawn(async move {
            let (mut sock, _) = listener_chunked.accept().await.unwrap();
            let mut req_buf = [0u8; 2048];
            let n = sock.read(&mut req_buf).await.unwrap();
            let req_text = String::from_utf8_lossy(&req_buf[..n]).into_owned();
            let resp = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: application/json\r\n",
                "Transfer-Encoding: chunked\r\n\r\n",
                "8;ext=1\r\n{\"ok\":tr\r\n",
                "3\r\nue}\r\n",
                "0\r\nX-Trailer: done\r\n\r\n"
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            req_text
        });
        let (st, val) = api_request_raw_with_timeouts(
            &addr_chunked,
            Locale::En,
            "GET",
            "/api/system",
            None,
            API_CONNECT_TIMEOUT,
            API_IO_TIMEOUT,
        )
        .await
        .unwrap();
        assert_eq!(st, 200);
        assert_eq!(val["ok"], Value::Bool(true));
        let sent_req = srv_chunked.await.unwrap();
        assert!(sent_req.contains("Accept-Language: en-US\r\n"));

        // 4. CL+TE conflict, empty 200 OK body, and >16 MiB Content-Length rejection
        for mock_resp in [
            "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n",
        ] {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap().to_string();
            let raw_resp = mock_resp.to_string();
            tokio::spawn(async move {
                if let Ok((mut sock, _)) = l.accept().await {
                    let mut req_buf = [0u8; 512];
                    let _ = sock.read(&mut req_buf).await;
                    let _ = sock.write_all(raw_resp.as_bytes()).await;
                }
            });
            let err = api_request_raw_with_timeouts(
                &a,
                Locale::Zh,
                "GET",
                "/api/system",
                None,
                API_CONNECT_TIMEOUT,
                API_IO_TIMEOUT,
            )
            .await
            .unwrap_err();
            assert!(matches!(err, ApiTransportError::Other(_)));
        }

        // 5. `node ping` unreachable & `conn kill` killed=false trigger non-zero SilentExitError
        let ping_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ping_addr = ping_listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = ping_listener.accept().await {
                let mut req_buf = [0u8; 1024];
                let _ = sock.read(&mut req_buf).await;
                let body = r#"{"ok":false,"latency_ms":null,"message":"unreachable"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        let ping_err = run_cli(&[
            "flowx".into(),
            "--api".into(),
            ping_addr,
            "--json".into(),
            "node".into(),
            "ping".into(),
            "101".into(),
        ])
        .await
        .unwrap_err();
        assert!(ping_err.downcast_ref::<SilentExitError>().is_some());

        let kill_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let kill_addr = kill_listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = kill_listener.accept().await {
                let mut req_buf = [0u8; 1024];
                let _ = sock.read(&mut req_buf).await;
                let body = r#"{"ok":true,"id":42,"killed":false}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        let kill_err = run_cli(&[
            "flowx".into(),
            "--api".into(),
            kill_addr,
            "--json".into(),
            "conn".into(),
            "kill".into(),
            "42".into(),
        ])
        .await
        .unwrap_err();
        assert!(kill_err.downcast_ref::<SilentExitError>().is_some());
    }

    #[tokio::test]
    async fn test_cli_transparent_dll_path_validation_and_doctor_report_semantics() {
        let cfg_guard = TempConfigGuard::new("flowx_cli_tp_val");
        let cfg_path = cfg_guard.path();
        let cfg_str = cfg_guard.as_str();

        // 1. Invalid --dll-path emits structured ERR_TRANSPARENT_INVALID_DLL_PATH matching API
        for bad_path in [
            "WinDivert.dll",
            r".\driver\WinDivert.dll",
            r"..\evil\WinDivert.dll",
            r"\\fileserver\share\WinDivert.dll",
            r"C:\tools\evil.dll",
            "C:\\bad\npath\\WinDivert.dll",
        ] {
            let err = run_cli(&[
                "flowx".into(),
                "--config".into(),
                cfg_str.clone(),
                "--offline".into(),
                "--json".into(),
                "transparent".into(),
                "config".into(),
                "--dll-path".into(),
                bad_path.into(),
            ])
            .await
            .expect_err(&format!(
                "expected invalid --dll-path rejection for {bad_path:?}"
            ));
            let err_json = format_cli_error_json(&err);
            assert_eq!(
                err_json["code"], "ERR_TRANSPARENT_INVALID_DLL_PATH",
                "unexpected CLI JSON error for {bad_path:?}: {err_json}"
            );
            assert_eq!(
                err_json["key"], "error.transparent_invalid_dll_path",
                "missing localized key in CLI JSON error for {bad_path:?}: {err_json}"
            );
        }
        assert!(!cfg_path.exists());

        // 2. doctor ready must be false when last_error is present
        let err_status = json!({
            "elevated": true,
            "running": false,
            "dll_found": true,
            "sys_found": true,
            "dll_path": r"C:\FlowX\WinDivert.dll",
            "sys_path": r"C:\FlowX\WinDivert64.sys",
            "searched_dirs": [r"C:\FlowX"],
            "enabled": true,
            "hijack_dns": true,
            "block_quic_for_proxied": true,
            "configured_dll_path": null,
            "last_error": "WinDivert driver signature check failed",
            "config_path": r"D:\Daemon\prod.xml",
        });
        let online_err_report =
            build_transparent_doctor_report("ONLINE", &err_status, "./local-cli.xml");
        assert_eq!(online_err_report["ready"], false);
        assert_eq!(online_err_report["config_path"], r"D:\Daemon\prod.xml");
        assert!(
            online_err_report["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str().unwrap_or("").contains("signature check failed"))
        );

        // 3. Online doctor without server config_path reports null instead of local CLI config path
        let online_no_cfg = json!({
            "elevated": true,
            "running": true,
            "dll_found": true,
            "sys_found": true,
            "searched_dirs": [r"C:\FlowX"],
            "enabled": true,
            "last_error": null,
        });
        let online_report =
            build_transparent_doctor_report("ONLINE", &online_no_cfg, "./local-cli.xml");
        assert_eq!(online_report["ready"], true);
        assert!(online_report["config_path"].is_null());

        // 4. Offline doctor reports local CLI config path
        let offline_report =
            build_transparent_doctor_report("OFFLINE", &online_no_cfg, "./local-cli.xml");
        assert_eq!(offline_report["ready"], true);
        assert_eq!(offline_report["config_path"], "./local-cli.xml");
        assert_eq!(offline_report["warnings"].as_array().unwrap().len(), 0);

        // 5. Ignored untrusted FLOWX_WINDIVERT_DLL after fallback surfaces in `warnings` while keeping `ready: true`
        let ignored_env_status = json!({
            "elevated": true,
            "running": false,
            "dll_found": true,
            "sys_found": true,
            "dll_path": r"C:\FlowX\driver\WinDivert.dll",
            "sys_path": r"C:\FlowX\driver\WinDivert64.sys",
            "searched_dirs": [
                r"FLOWX_WINDIVERT_DLL (ignored untrusted/invalid: \\server\share\WinDivert.dll)",
                r"C:\FlowX\driver",
            ],
            "enabled": false,
            "last_error": null,
        });
        let warn_report =
            build_transparent_doctor_report("OFFLINE", &ignored_env_status, "./local-cli.xml");
        assert_eq!(warn_report["ready"], true);
        assert!(warn_report["issues"].as_array().unwrap().is_empty());
        let warnings = warn_report["warnings"].as_array().unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0]
                .as_str()
                .unwrap()
                .contains("FLOWX_WINDIVERT_DLL"),
            "unexpected warning: {warnings:?}"
        );

        // 5. Low-integrity status blocks readiness and surfaces actionable issue
        let low_il_status = json!({
            "elevated": false,
            "low_integrity": true,
            "running": false,
            "dll_found": true,
            "sys_found": true,
            "searched_dirs": [r"C:\FlowX"],
            "enabled": false,
            "last_error": null,
        });
        let low_il_report =
            build_transparent_doctor_report("ONLINE", &low_il_status, "./local-cli.xml");
        assert_eq!(low_il_report["ready"], false);
        assert_eq!(low_il_report["low_integrity"], true);
        assert!(
            low_il_report["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str().unwrap_or("").contains("Low Mandatory Integrity"))
        );
    }

    #[tokio::test]
    async fn test_cli_transparent_elevate_node_clear_user_and_ping_all() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // 1. `transparent elevate --offline` fails cleanly
        assert!(
            run_cli(&[
                "flowx".into(),
                "--offline".into(),
                "--json".into(),
                "transparent".into(),
                "elevate".into(),
            ])
            .await
            .is_err()
        );

        // 2. `transparent elevate` online sends POST /api/transparent/elevate and handles 200 & 409
        let elev_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let elev_addr = elev_listener.local_addr().unwrap().to_string();
        let elev_srv = tokio::spawn(async move {
            for (status, body) in [
                ("200 OK", r#"{"ok":true,"relaunching":true}"#),
                (
                    "409 Conflict",
                    r#"{"code":"ERR_TRANSPARENT_ALREADY_ELEVATED","error":"Already Administrator"}"#,
                ),
            ] {
                let (mut sock, _) = elev_listener.accept().await.unwrap();
                let mut buf = [0u8; 2048];
                let n = sock.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                assert!(
                    req.starts_with("POST /api/transparent/elevate "),
                    "unexpected elevate request: {req}"
                );
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                sock.write_all(resp.as_bytes()).await.unwrap();
            }
        });
        run_cli(&[
            "flowx".into(),
            "--api".into(),
            elev_addr.clone(),
            "--json".into(),
            "transparent".into(),
            "elevate".into(),
        ])
        .await
        .unwrap();
        let err_409 = run_cli(&[
            "flowx".into(),
            "--api".into(),
            elev_addr,
            "--json".into(),
            "transparent".into(),
            "elevate".into(),
        ])
        .await
        .unwrap_err();
        assert_eq!(
            format_cli_error_json(&err_409)["code"],
            "ERR_TRANSPARENT_ALREADY_ELEVATED"
        );
        elev_srv.await.unwrap();

        // 3. Offline & online `node update --clear-user` + conflict rejection + `node ping --all`
        let cfg_guard = TempConfigGuard::new("flowx_cli_parity");
        let cfg_str = cfg_guard.as_str();

        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "node".into(),
            "add".into(),
            "--name".into(),
            "AuthNode".into(),
            "--addr".into(),
            "10.0.0.5:1080".into(),
            "--user".into(),
            "alice".into(),
            "--pass".into(),
            "pw".into(),
        ])
        .await
        .unwrap();

        assert!(
            run_cli(&[
                "flowx".into(),
                "--config".into(),
                cfg_str.clone(),
                "--offline".into(),
                "node".into(),
                "update".into(),
                "102".into(),
                "--user".into(),
                "bob".into(),
                "--clear-user".into(),
            ])
            .await
            .is_err()
        );

        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "--json".into(),
            "node".into(),
            "update".into(),
            "102".into(),
            "--clear-user".into(),
        ])
        .await
        .unwrap();
        let store = ConfigStore::new(cfg_guard.path());
        let (rt, _) = store.load_or_init(&DEFAULT_SELF_PORTS).unwrap();
        assert_eq!(rt.proxy_nodes.get(&102).unwrap().username, None);
        assert_eq!(
            rt.proxy_nodes.get(&102).unwrap().client.auth_credentials(),
            (None, None)
        );
        drop(cfg_guard);

        // `node ping --all` conflicts with positional ID
        assert!(
            run_cli(&[
                "flowx".into(),
                "--offline".into(),
                "node".into(),
                "ping".into(),
                "--all".into(),
                "101".into(),
            ])
            .await
            .is_err()
        );

        // Online `node ping --all`: all ok -> Ok(()), partial failure -> SilentExitError
        let mock_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_listener.local_addr().unwrap().to_string();
        let mock_srv = tokio::spawn(async move {
            let mut ping_count = 0usize;
            for _ in 0..6 {
                let (mut sock, _) = mock_listener.accept().await.unwrap();
                let mut buf = [0u8; 2048];
                let n = sock.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                let body = if req.starts_with("GET /api/nodes ") {
                    r#"[{"id":101,"name":"N1","protocol":"SOCKS5","server_addr":"127.0.0.1:10808","auth_configured":false},{"id":102,"name":"N2","protocol":"HTTP","server_addr":"127.0.0.1:10809","auth_configured":false}]"#
                } else {
                    ping_count += 1;
                    // Batch 1 (ping_count 1..=2): both ok; Batch 2 (ping_count 3..=4): one fails
                    if ping_count <= 3 {
                        r#"{"ok":true,"latency_ms":4,"message":"ok"}"#
                    } else {
                        r#"{"ok":false,"latency_ms":0,"message":"refused"}"#
                    }
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                sock.write_all(resp.as_bytes()).await.unwrap();
            }
        });
        run_cli(&[
            "flowx".into(),
            "--api".into(),
            mock_addr.clone(),
            "--json".into(),
            "node".into(),
            "ping".into(),
            "--all".into(),
        ])
        .await
        .unwrap();
        let batch2_err = run_cli(&[
            "flowx".into(),
            "--api".into(),
            mock_addr,
            "--json".into(),
            "node".into(),
            "ping".into(),
            "--all".into(),
        ])
        .await
        .unwrap_err();
        assert!(batch2_err.downcast_ref::<SilentExitError>().is_some());
        mock_srv.await.unwrap();
    }

    #[tokio::test]
    async fn test_cli_rule_clear_filters_and_conn_list_filters() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let cfg_guard = TempConfigGuard::new("flowx_cli_rule_clr");
        let cfg_str = cfg_guard.as_str();

        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "rule".into(),
            "add".into(),
            "--name".into(),
            "ScopedRule".into(),
            "--apps".into(),
            "curl.exe".into(),
            "--targets".into(),
            "example.com".into(),
            "--ports".into(),
            "443".into(),
            "--action".into(),
            "Direct".into(),
        ])
        .await
        .unwrap();

        for (set_flag, set_val, clear_flag) in [
            ("--apps", "git.exe", "--clear-apps"),
            ("--targets", "github.com", "--clear-targets"),
            ("--ports", "80", "--clear-ports"),
        ] {
            assert!(
                run_cli(&[
                    "flowx".into(),
                    "--config".into(),
                    cfg_str.clone(),
                    "--offline".into(),
                    "rule".into(),
                    "update".into(),
                    "1".into(),
                    set_flag.into(),
                    set_val.into(),
                    clear_flag.into(),
                ])
                .await
                .is_err()
            );
        }

        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "--json".into(),
            "rule".into(),
            "update".into(),
            "1".into(),
            "--clear-apps".into(),
            "--clear-targets".into(),
            "--clear-ports".into(),
        ])
        .await
        .unwrap();
        let store = ConfigStore::new(cfg_guard.path());
        let (rt, _) = store.load_or_init(&DEFAULT_SELF_PORTS).unwrap();
        assert_eq!(rt.rules[0].apps_raw, "");
        assert_eq!(rt.rules[0].targets_raw, "");
        assert_eq!(rt.rules[0].ports_raw, "");

        run_cli(&[
            "flowx".into(),
            "--config".into(),
            cfg_str.clone(),
            "--offline".into(),
            "--json".into(),
            "rule".into(),
            "list".into(),
            "--search".into(),
            "scoped".into(),
        ])
        .await
        .unwrap();
        drop(cfg_guard);

        // `conn list` invalid filter validation and filtering helper
        assert!(
            run_cli(&[
                "flowx".into(),
                "--api".into(),
                "127.0.0.1:40080".into(),
                "conn".into(),
                "list".into(),
                "--filter".into(),
                "INVALID".into(),
            ])
            .await
            .is_err()
        );

        let sample_proxy = json!({
            "id": 1,
            "process_name": "chrome.exe",
            "process_path": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
            "target": "api.github.com:443",
            "rule_name": "DevProxy",
            "action": "Proxy (#101)",
            "action_type": "Proxy",
        });
        let sample_direct = json!({
            "id": 2,
            "process_name": "curl.exe",
            "process_path": "C:\\Windows\\System32\\curl.exe",
            "target": "localhost:8080",
            "rule_name": "LocalBypass",
            "action": "Direct",
            "action_type": "Direct",
        });
        assert!(conn_matches_filter(&sample_proxy, "PROXY", Some("github")));
        assert!(!conn_matches_filter(&sample_direct, "PROXY", None));
        assert!(conn_matches_filter(&sample_direct, "DIRECT", Some("curl")));
        assert!(!conn_matches_filter(&sample_proxy, "BLOCK", None));

        let conn_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let conn_addr = conn_listener.local_addr().unwrap().to_string();
        let (hdr_tx, hdr_rx) = tokio::sync::oneshot::channel::<String>();
        let conn_srv = tokio::spawn(async move {
            let (mut sock, _) = conn_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = sock.read(&mut buf).await.unwrap();
            let _ = hdr_tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
            let body = r#"[{"id":1,"process_name":"chrome.exe","process_path":"C:\\chrome.exe","pid":10,"target":"github.com:443","rule_name":"DevProxy","action":"Proxy (#101)","action_type":"Proxy","duration_secs":1,"uploaded_bytes":0,"downloaded_bytes":0,"upload_bytes_per_sec":0,"download_bytes_per_sec":0}]"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
        });
        let zh_env = CliEnv {
            flowx_config: None,
            flowx_api: None,
            locale: Locale::Zh,
        };
        super::run_cli_with_env(
            &[
                "flowx".into(),
                "--api".into(),
                conn_addr,
                "--json".into(),
                "conn".into(),
                "list".into(),
                "--filter".into(),
                "proxy".into(),
                "--search".into(),
                "chrome".into(),
            ],
            &zh_env,
        )
        .await
        .unwrap();
        conn_srv.await.unwrap();
        let raw_req = hdr_rx.await.unwrap();
        assert!(
            raw_req
                .to_ascii_lowercase()
                .contains("accept-language: zh-cn"),
            "api_request_strict must forward CliEnv.locale in Accept-Language, got: {raw_req}"
        );
    }

    #[tokio::test]
    async fn test_cli_version_strict_args_and_offline_zero_lock_side_effects() {
        let poisoned = CliEnv {
            flowx_config: None,
            flowx_api: Some("://invalid-host-env".into()),
            locale: Locale::En,
        };

        // 1. Valid idempotent version invocations succeed even under poisoned FLOWX_API
        for ok_args in [
            vec!["flowx", "version"],
            vec!["flowx", "--version"],
            vec!["flowx", "-V"],
            vec!["flowx", "--version", "--version"],
            vec!["flowx", "-V", "-V"],
            vec!["flowx", "version", "--version"],
            vec!["flowx", "--version", "-V", "--json"],
        ] {
            let owned: Vec<String> = ok_args.into_iter().map(String::from).collect();
            super::run_cli_with_env(&owned, &poisoned)
                .await
                .unwrap_or_else(|e| panic!("expected success for {:?}, got: {e:#}", owned));
        }

        // 2. Trailing positional args, unknown/subcommand flags, `--` before flag-like subcommands, or `help extra` must fail
        for bad_args in [
            vec!["flowx", "version", "bogus"],
            vec!["flowx", "--version", "--name", "foo"],
            vec!["flowx", "-V", "--all"],
            vec!["flowx", "--version", "--", "extra"],
            vec!["flowx", "status", "--version"],
            vec!["flowx", "--", "--version"],
            vec!["flowx", "--", "--help"],
            vec!["flowx", "--", "-V"],
            vec!["flowx", "help", "extra"],
            vec!["flowx", "help", "--name", "foo"],
        ] {
            let owned: Vec<String> = bad_args.into_iter().map(String::from).collect();
            assert!(
                super::run_cli_with_env(&owned, &poisoned).await.is_err(),
                "expected error for {:?}",
                owned
            );
        }

        // 3. Offline invalid requests, missing dynamic IDs, and no-op moves must NOT create nonexistent parent dir or .lock
        let missing_dir = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "flowx_no_side_effect_dir_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        struct DirCleanup(std::path::PathBuf);
        impl Drop for DirCleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _dir_cleanup = DirCleanup(missing_dir.clone());
        let missing_cfg = missing_dir.join("nested").join("flowx.xml");
        let missing_cfg_str = missing_cfg.to_string_lossy().to_string();

        let err_cases: &[&[&str]] = &[
            &["node", "add", "--name", "Bad", "--addr", "not-a-valid-addr"],
            &["node", "update", "101", "--name", ""],
            &["node", "update", "101", "--addr", "bad-addr"],
            &["node", "update", "999", "--name", "MissingNode"],
            &["node", "remove", "999"],
            &["rule", "add", "--name", "", "--action", "Direct"],
            &["rule", "add", "--name", "R", "--action", "Bogus"],
            &["rule", "add", "--name", "R", "--action", "Proxy:999"],
            &[
                "rule", "add", "--name", "R", "--action", "Direct", "--ports", "abc",
            ],
            &["rule", "update", "1", "--name", ""],
            &["rule", "update", "1", "--action", "Bogus"],
            &["rule", "update", "1", "--ports", "abc"],
            &["rule", "update", "999", "--name", "MissingRule"],
            &["rule", "move", "1", "sideways"],
            &["rule", "move", "999", "up"],
            &["default", "Bogus"],
            &["default", "Proxy"],
            &["default", "Proxy:999"],
            &[
                "transparent",
                "config",
                "--dll-path",
                r"..\evil\WinDivert.dll",
            ],
        ];
        for tail in err_cases {
            let mut argv = vec![
                "flowx".to_string(),
                "--config".to_string(),
                missing_cfg_str.clone(),
                "--offline".to_string(),
            ];
            argv.extend(tail.iter().map(|s| s.to_string()));
            assert!(
                run_cli(&argv).await.is_err(),
                "expected failure for offline case {:?}",
                tail
            );
            assert!(
                !missing_dir.exists(),
                "failed offline case {:?} must not create parent directory {:?}",
                tail,
                missing_dir
            );
        }

        // No-op `rule move 1 up` (rule #1 already at top of default profile) also must not create dir/.lock
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            missing_cfg_str,
            "--offline".into(),
            "rule".into(),
            "move".into(),
            "1".into(),
            "up".into(),
        ])
        .await
        .unwrap();
        assert!(
            !missing_dir.exists(),
            "no-op offline rule move must not create parent directory or .lock"
        );

        // 4. Existing config file without .lock: static errors, dynamic errors, no-op moves,
        // and online/offline error-priority parity must all hold without creating .lock
        let existing_guard = TempConfigGuard::new("flowx_existing_nolock");
        let existing_path = existing_guard.path();
        let existing_str = existing_guard.as_str();
        let existing_lock = existing_path.parent().unwrap().join(format!(
            ".{}.lock",
            existing_path.file_name().unwrap().to_string_lossy()
        ));
        let mut seeded_profile = crate::config::ProfileConfig::default_profile();
        seeded_profile
            .proxy_list
            .as_mut()
            .unwrap()
            .proxies
            .push(crate::config::ProxyItem {
                id: 102,
                proxy_type: "SOCKS4".to_string(),
                name: Some("Socks4Node".to_string()),
                address: "10.0.0.2".to_string(),
                port: 1080,
                username: None,
                password: None,
                options: None,
            });
        std::fs::write(existing_path, seeded_profile.to_xml().unwrap()).unwrap();
        assert!(!existing_lock.exists());

        for tail in [
            &["node", "update", "101", "--protocol", "BOGUS"][..],
            &["rule", "add", "--name", "R", "--action", "Bogus"][..],
            &["rule", "update", "1", "--action", "Bogus"][..],
            &["rule", "move", "1", "sideways"][..],
            &["default", "Bogus"][..],
            &["transparent", "config", "--dll-path", "WinDivert.dll"][..],
            &["rule", "update", "999", "--name", "Missing"][..],
            &["node", "update", "999", "--name", "Missing"][..],
        ] {
            let mut argv = vec![
                "flowx".to_string(),
                "--config".to_string(),
                existing_str.clone(),
                "--offline".to_string(),
            ];
            argv.extend(tail.iter().map(|s| s.to_string()));
            assert!(
                run_cli(&argv).await.is_err(),
                "expected failure for {:?}",
                tail
            );
            assert!(
                !existing_lock.exists(),
                "error for {:?} must not create lock file {:?}",
                tail,
                existing_lock
            );
        }

        // No-op `rule move 1 up` on existing unlocked XML must not create .lock
        run_cli(&[
            "flowx".into(),
            "--config".into(),
            existing_str.clone(),
            "--offline".into(),
            "rule".into(),
            "move".into(),
            "1".into(),
            "up".into(),
        ])
        .await
        .unwrap();
        assert!(!existing_lock.exists());

        // Online/offline error-priority parity: missing ID + invalid field reports 404 (not 400)
        let rule_404 = run_cli(&[
            "flowx".into(),
            "--config".into(),
            existing_str.clone(),
            "--offline".into(),
            "rule".into(),
            "update".into(),
            "999".into(),
            "--name".into(),
            "".into(),
        ])
        .await
        .unwrap_err();
        let rule_404_json = format_cli_error_json(&rule_404);
        assert_eq!(rule_404_json["status"], 404);
        assert_eq!(rule_404_json["code"], "ERR_RULE_NOT_FOUND");
        assert!(!existing_lock.exists());

        let node_404 = run_cli(&[
            "flowx".into(),
            "--config".into(),
            existing_str.clone(),
            "--offline".into(),
            "node".into(),
            "update".into(),
            "999".into(),
            "--name".into(),
            "".into(),
        ])
        .await
        .unwrap_err();
        let node_404_json = format_cli_error_json(&node_404);
        assert_eq!(node_404_json["status"], 404);
        assert_eq!(node_404_json["code"], "ERR_NODE_NOT_FOUND");
        assert!(!existing_lock.exists());

        // Existing SOCKS4 node updated with `--clear-user --pass x` reports ERR_SOCKS4_PASSWORD_UNSUPPORTED
        let socks4_err = run_cli(&[
            "flowx".into(),
            "--config".into(),
            existing_str,
            "--offline".into(),
            "node".into(),
            "update".into(),
            "102".into(),
            "--clear-user".into(),
            "--pass".into(),
            "x".into(),
        ])
        .await
        .unwrap_err();
        let socks4_json = format_cli_error_json(&socks4_err);
        assert_eq!(socks4_json["status"], 400);
        assert_eq!(socks4_json["code"], "ERR_SOCKS4_PASSWORD_UNSUPPORTED");
        assert!(!existing_lock.exists());
    }
}
