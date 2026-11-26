use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore, watch};
use tracing::error;

use crate::api::http::{
    best_effort_locale, extract_header, has_json_content_type, is_allowed_host, is_allowed_origin,
    is_allowed_referer, is_http_token_byte, parse_query_param, read_full_http_request,
    send_http_response,
};
use crate::api::transparent::{
    TransparentRollbackState, finalize_elevate_response_and_log, handle_transparent_config,
    handle_transparent_elevate_after_gate, handle_transparent_status, handle_transparent_toggle,
};
use crate::api::{ElevateRunner, JSON_CONTENT_TYPE, nodes, rules, system};
use crate::config::ConfigStore;
use crate::control::SystemRuntimeContext;
use crate::i18n::{Locale, json_error};
use crate::interceptor::dispatcher::ProxyNodeEntry;
use crate::monitor::ConnectionManager;
use crate::router::RuleEngine;
use crate::transparent::{TransparentManager, TransparentSettings};

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_api_request(
    mut stream: TcpStream,
    actual_port: u16,
    self_ports: Arc<Vec<u16>>,
    monitor: Arc<ConnectionManager>,
    rule_engine: Arc<RuleEngine>,
    proxy_nodes: Arc<RwLock<HashMap<u32, ProxyNodeEntry>>>,
    config_store: Option<Arc<ConfigStore>>,
    runtime_context: Option<Arc<SystemRuntimeContext>>,
    transparent_manager: Option<Arc<TransparentManager>>,
    shutdown_tx: Option<watch::Sender<bool>>,
    ping_semaphore: Arc<Semaphore>,
    mutation_semaphore: Arc<Semaphore>,
    mutation_lock: Arc<Mutex<()>>,
    elevating: Arc<AtomicBool>,
    elevate_runner: Option<ElevateRunner>,
    persist_timeout: Duration,
    started_at: Instant,
) -> Result<()> {
    let mut req_bytes = Vec::with_capacity(4096);
    if let Err(e) = read_full_http_request(&mut stream, &mut req_bytes).await {
        let (code, key) = e.code_and_key();
        let msg = json_error(best_effort_locale(&req_bytes), code, key);
        send_http_response(&mut stream, e.http_status(), JSON_CONTENT_TYPE, &msg).await?;
        return Ok(());
    }
    if req_bytes.is_empty() {
        return Ok(());
    }

    // 协议早期错误（头部不完整/非 UTF-8）同样按 best-effort 语言偏好本地化
    let locale = best_effort_locale(&req_bytes);

    let Some(header_end) = crate::outbound::find_http_header_end(&req_bytes, 0) else {
        send_http_response(
            &mut stream,
            "400 Bad Request",
            JSON_CONTENT_TYPE,
            &json_error(locale, "ERR_INCOMPLETE_HEADERS", "error.incomplete_headers"),
        )
        .await?;
        return Ok(());
    };

    let Ok(header_str) = std::str::from_utf8(&req_bytes[..header_end - 4]) else {
        send_http_response(
            &mut stream,
            "400 Bad Request",
            JSON_CONTENT_TYPE,
            &json_error(locale, "ERR_NON_UTF8_HEADERS", "error.non_utf8_headers"),
        )
        .await?;
        return Ok(());
    };

    let mut header_lines = header_str.split("\r\n");
    let first_line = header_lines.next().unwrap_or_default();
    let headers: Vec<&str> = header_lines.collect();

    let mut line_parts = first_line.split(' ');
    let (Some(method), Some(path_and_query), Some(version), None) = (
        line_parts.next(),
        line_parts.next(),
        line_parts.next(),
        line_parts.next(),
    ) else {
        send_http_response(
            &mut stream,
            "400 Bad Request",
            JSON_CONTENT_TYPE,
            &json_error(
                locale,
                "ERR_INVALID_REQUEST_LINE",
                "error.invalid_request_line",
            ),
        )
        .await?;
        return Ok(());
    };
    if method.is_empty()
        || !method.bytes().all(is_http_token_byte)
        || path_and_query.is_empty()
        || !matches!(version, "HTTP/1.1" | "HTTP/1.0")
    {
        send_http_response(
            &mut stream,
            "400 Bad Request",
            JSON_CONTENT_TYPE,
            &json_error(
                locale,
                "ERR_INVALID_REQUEST_LINE",
                "error.invalid_request_line",
            ),
        )
        .await?;
        return Ok(());
    }
    let (path, query) = path_and_query
        .split_once('?')
        .unwrap_or((path_and_query, ""));

    let accept_lang = extract_header(&headers, "accept-language");
    // 只取 lang 查询参数本身，避免把整段 query 交给子串匹配（如 ?keywords=lang=zh 误命中）
    let locale = Locale::from_header_or_query(accept_lang, parse_query_param(query, "lang"));

    // 安全校验 1: Host 头必须为本地回环地址，防止 DNS Rebinding
    let host_ok =
        extract_header(&headers, "host").is_some_and(|h| is_allowed_host(h, actual_port, false));
    if !host_ok {
        send_http_response(
            &mut stream,
            "403 Forbidden",
            JSON_CONTENT_TYPE,
            &json_error(locale, "ERR_FORBIDDEN_HOST", "error.invalid_host"),
        )
        .await?;
        return Ok(());
    }

    // 安全校验 2: Origin / Sec-Fetch-Site / Referer 同源检查，防止跨站 CSRF
    if let Some(origin) = extract_header(&headers, "origin")
        && !is_allowed_origin(origin, actual_port)
    {
        send_http_response(
            &mut stream,
            "403 Forbidden",
            JSON_CONTENT_TYPE,
            &json_error(locale, "ERR_FORBIDDEN_ORIGIN", "error.invalid_origin"),
        )
        .await?;
        return Ok(());
    }

    if let Some(fetch_site) = extract_header(&headers, "sec-fetch-site")
        && fetch_site.eq_ignore_ascii_case("cross-site")
        && (path.starts_with("/api/") || !matches!(method, "GET" | "HEAD"))
    {
        send_http_response(
            &mut stream,
            "403 Forbidden",
            JSON_CONTENT_TYPE,
            &json_error(
                locale,
                "ERR_FORBIDDEN_FETCH_SITE",
                "error.invalid_fetch_site",
            ),
        )
        .await?;
        return Ok(());
    }

    if !matches!(method, "GET" | "HEAD" | "OPTIONS")
        && let Some(referer) = extract_header(&headers, "referer")
        && !is_allowed_referer(referer, actual_port)
    {
        send_http_response(
            &mut stream,
            "403 Forbidden",
            JSON_CONTENT_TYPE,
            &json_error(locale, "ERR_FORBIDDEN_REFERER", "error.invalid_referer"),
        )
        .await?;
        return Ok(());
    }

    let body_bytes = &req_bytes[header_end..];
    let requires_json_ct = matches!(
        (method, path),
        ("POST" | "PUT" | "PATCH", "/api/nodes" | "/api/rules")
            | (
                "POST",
                "/api/rules/default"
                    | "/api/rules/simulate"
                    | "/api/rules/toggle"
                    | "/api/rules/move"
                    | "/api/transparent/toggle"
            )
            | ("PUT" | "POST", "/api/transparent/config")
    ) || (matches!(
        (method, path),
        ("POST", "/api/connections/kill" | "/api/nodes/ping")
            | ("DELETE", "/api/nodes" | "/api/rules")
    ) && (!body_bytes.is_empty()
        || parse_query_param(query, "id").is_none()))
        || (method == "POST" && path == "/api/transparent/elevate" && !body_bytes.is_empty());
    if requires_json_ct && !has_json_content_type(&headers) {
        send_http_response(
            &mut stream,
            "415 Unsupported Media Type",
            JSON_CONTENT_TYPE,
            &json_error(
                locale,
                "ERR_UNSUPPORTED_MEDIA_TYPE",
                "error.unsupported_media_type",
            ),
        )
        .await?;
        return Ok(());
    }

    let req_body = std::str::from_utf8(body_bytes).unwrap_or("");

    // POST /api/transparent/elevate 采用前置无锁一次性原子闸门：
    // 1) 在排队等待 mutation_lock 之前先检查 elevating，避免 UAC 弹窗超过 5s 时并发请求返回 503 或取消后连续弹第二个 UAC；
    // 2) 不持 mutation_lock 等待交互式 UAC 对话框，防止阻塞其它配置变更写接口。
    if method == "POST" && path == "/api/transparent/elevate" {
        if !req_body.trim().is_empty()
            && serde_json::from_str::<serde_json::Value>(req_body).is_err()
        {
            send_http_response(
                &mut stream,
                "400 Bad Request",
                JSON_CONTENT_TYPE,
                &json_error(
                    locale,
                    "ERR_INVALID_TRANSPARENT_BODY",
                    "error.invalid_transparent_body",
                ),
            )
            .await?;
            return Ok(());
        }

        if elevating.load(Ordering::Acquire) {
            send_http_response(
                &mut stream,
                "409 Conflict",
                JSON_CONTENT_TYPE,
                &json_error(
                    locale,
                    "ERR_TRANSPARENT_ELEVATE_IN_PROGRESS",
                    "error.transparent_elevate_in_progress",
                ),
            )
            .await?;
            return Ok(());
        }
        if shutdown_tx.as_ref().is_some_and(|tx| *tx.borrow()) {
            send_http_response(
                &mut stream,
                "503 Service Unavailable",
                JSON_CONTENT_TYPE,
                &json_error(
                    locale,
                    "ERR_SERVER_SHUTTING_DOWN",
                    "error.server_shutting_down",
                ),
            )
            .await?;
            return Ok(());
        }
        if elevating
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            send_http_response(
                &mut stream,
                "409 Conflict",
                JSON_CONTENT_TYPE,
                &json_error(
                    locale,
                    "ERR_TRANSPARENT_ELEVATE_IN_PROGRESS",
                    "error.transparent_elevate_in_progress",
                ),
            )
            .await?;
            return Ok(());
        }
        // Double-check 防止刚拿到闸门的同时收到 Ctrl+C 停机信号
        if shutdown_tx.as_ref().is_some_and(|tx| *tx.borrow()) {
            elevating.store(false, Ordering::Release);
            send_http_response(
                &mut stream,
                "503 Service Unavailable",
                JSON_CONTENT_TYPE,
                &json_error(
                    locale,
                    "ERR_SERVER_SHUTTING_DOWN",
                    "error.server_shutting_down",
                ),
            )
            .await?;
            return Ok(());
        }

        let mut trigger_elevated_shutdown = false;
        let (status, content_type, body) = handle_transparent_elevate_after_gate(
            locale,
            Arc::clone(&elevating),
            shutdown_tx.clone(),
            elevate_runner,
            &mut trigger_elevated_shutdown,
        )
        .await;
        let (status, body) = finalize_elevate_response_and_log(locale, status, body);
        finish_api_response_and_maybe_shutdown(
            &mut stream,
            status,
            content_type,
            &body,
            trigger_elevated_shutdown,
            shutdown_tx.as_ref(),
        )
        .await?;
        return Ok(());
    }

    let is_mutation = is_mutation_endpoint(method, path);
    let (mut mutation_guard, mut mutation_sem_permit) = if is_mutation {
        let Ok(sem_permit) = mutation_semaphore.try_acquire() else {
            send_http_response(
                &mut stream,
                "503 Service Unavailable",
                JSON_CONTENT_TYPE,
                &json_error(locale, "ERR_OVERLOADED", "error.mutation_overloaded"),
            )
            .await?;
            return Ok(());
        };
        let Ok(lock_guard) = tokio::time::timeout(persist_timeout, mutation_lock.lock()).await
        else {
            drop(sem_permit);
            send_http_response(
                &mut stream,
                "503 Service Unavailable",
                JSON_CONTENT_TYPE,
                &json_error(locale, "ERR_OVERLOADED", "error.mutation_overloaded"),
            )
            .await?;
            return Ok(());
        };
        if shutdown_tx.as_ref().is_some_and(|tx| *tx.borrow()) {
            drop(lock_guard);
            drop(sem_permit);
            let (st, code, key) = if elevating.load(Ordering::Acquire) {
                (
                    "409 Conflict",
                    "ERR_TRANSPARENT_ELEVATE_IN_PROGRESS",
                    "error.transparent_elevate_in_progress",
                )
            } else {
                (
                    "503 Service Unavailable",
                    "ERR_SERVER_SHUTTING_DOWN",
                    "error.server_shutting_down",
                )
            };
            send_http_response(
                &mut stream,
                st,
                JSON_CONTENT_TYPE,
                &json_error(locale, code, key),
            )
            .await?;
            return Ok(());
        }
        (Some(lock_guard), Some(sem_permit))
    } else {
        (None, None)
    };

    let live_proxy_nodes = Arc::clone(&proxy_nodes);
    let live_rule_engine = Arc::clone(&rule_engine);
    let (proxy_nodes, rule_engine) = if is_mutation {
        let nodes_copy = live_proxy_nodes
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let (rules_copy, default_copy) = live_rule_engine.snapshot_state();
        (
            Arc::new(RwLock::new(nodes_copy)),
            Arc::new(RuleEngine::new(rules_copy, default_copy)),
        )
    } else {
        (Arc::clone(&live_proxy_nodes), Arc::clone(&live_rule_engine))
    };

    let mut should_persist = false;
    let mut rollback_transparent: Option<TransparentRollbackState> = None;
    let trigger_elevated_shutdown = false;

    let (mut status, mut content_type, mut body) = match (method, path) {
        ("OPTIONS", _) => ("204 No Content", "text/plain", String::new()),
        ("GET", "/") | ("GET", "/dashboard") => system::handle_dashboard(),
        ("GET", "/api/health") => system::handle_health(),
        ("GET", "/api/system") => system::handle_system_info(
            actual_port,
            runtime_context.as_deref(),
            config_store.as_deref(),
            transparent_manager.as_deref(),
            &proxy_nodes,
            &rule_engine,
            started_at,
            locale,
        ),
        ("GET", "/api/stats") => system::handle_stats(&monitor),
        ("GET", "/api/connections") => system::handle_list_connections(&monitor, locale),
        ("POST", "/api/connections/kill") => {
            system::handle_kill_connection(&monitor, query, req_body, locale)
        }
        ("GET", "/api/nodes") => nodes::handle_list_nodes(&proxy_nodes),
        ("POST", "/api/nodes") => nodes::handle_post_node(
            req_body,
            &proxy_nodes,
            &self_ports,
            locale,
            &mut should_persist,
        ),
        ("PUT", "/api/nodes") => nodes::handle_put_node(
            req_body,
            &proxy_nodes,
            &self_ports,
            locale,
            &mut should_persist,
        ),
        ("PATCH", "/api/nodes") => nodes::handle_patch_node_http(
            req_body,
            &proxy_nodes,
            &self_ports,
            locale,
            &mut should_persist,
        ),
        ("DELETE", "/api/nodes") => nodes::handle_delete_node(
            query,
            req_body,
            &proxy_nodes,
            &rule_engine,
            locale,
            &mut should_persist,
        ),
        ("POST", "/api/nodes/ping") => {
            nodes::handle_ping_node(
                query,
                req_body,
                &proxy_nodes,
                &self_ports,
                runtime_context.as_deref(),
                &ping_semaphore,
                locale,
            )
            .await
        }
        ("GET", "/api/rules") => rules::handle_list_rules(&rule_engine, locale),
        ("POST", "/api/rules") => rules::handle_post_rule(
            req_body,
            &rule_engine,
            &proxy_nodes,
            locale,
            &mut should_persist,
        ),
        ("PUT", "/api/rules") => rules::handle_put_rule(
            req_body,
            &rule_engine,
            &proxy_nodes,
            locale,
            &mut should_persist,
        ),
        ("PATCH", "/api/rules") => rules::handle_patch_rule_http(
            req_body,
            &rule_engine,
            &proxy_nodes,
            locale,
            &mut should_persist,
        ),
        ("POST", "/api/rules/default") => rules::handle_set_default(
            req_body,
            &rule_engine,
            &proxy_nodes,
            locale,
            &mut should_persist,
        ),
        ("POST", "/api/rules/simulate") => {
            rules::handle_simulate(req_body, &rule_engine, runtime_context.as_deref(), locale)
        }
        ("POST", "/api/rules/toggle") => {
            rules::handle_toggle_rule(req_body, &rule_engine, locale, &mut should_persist)
        }
        ("POST", "/api/rules/move") => {
            rules::handle_move_rule(req_body, &rule_engine, locale, &mut should_persist)
        }
        ("DELETE", "/api/rules") => {
            rules::handle_delete_rule(query, req_body, &rule_engine, locale, &mut should_persist)
        }
        ("GET", "/api/transparent/status") => {
            handle_transparent_status(transparent_manager.as_deref(), config_store.as_deref())
        }
        ("POST", "/api/transparent/toggle") => {
            handle_transparent_toggle(
                transparent_manager.as_ref(),
                req_body,
                locale,
                &mut should_persist,
                &mut rollback_transparent,
            )
            .await
        }
        ("PUT" | "POST", "/api/transparent/config") => {
            handle_transparent_config(
                transparent_manager.as_ref(),
                req_body,
                locale,
                &mut should_persist,
                &mut rollback_transparent,
            )
            .await
        }
        _ => (
            "404 Not Found",
            JSON_CONTENT_TYPE,
            json_error(locale, "ERR_NOT_FOUND", "error.not_found"),
        ),
    };

    if should_persist {
        let mut persisted_ok = true;
        let persist_transparent = transparent_manager.as_ref().map(|m| m.persisted_settings());
        if let Some(store) = config_store.as_ref()
            && let Err(e) = persist_config_async_with_timeout(
                Arc::clone(store),
                &proxy_nodes,
                &rule_engine,
                persist_transparent,
                persist_timeout,
            )
            .await
        {
            error!(
                "[API] Failed to write updated config to disk, aborting commit: {:#}",
                e
            );
            if let (Some(mgr), Some(rb)) =
                (transparent_manager.as_ref(), rollback_transparent.take())
            {
                if let Some(prev_pe) = rb.prev_persisted_enabled {
                    mgr.set_persisted_enabled(prev_pe);
                }
                let is_shutting_down = mgr.is_shutting_down()
                    || shutdown_tx.as_ref().is_some_and(|tx| *tx.borrow());
                let mut rollback_settings = rb.prev_settings;
                if is_shutting_down && rollback_settings.enabled {
                    // 停机排空期间严禁因配置回滚重新拉起 WinDivert，仅还原非启用态配置
                    rollback_settings.enabled = false;
                }
                let mgr_clone = Arc::clone(mgr);
                let rt_handle = tokio::runtime::Handle::current();
                if let Err(rb_err) = tokio::task::spawn_blocking(move || {
                    mgr_clone.apply_settings(rollback_settings, &rt_handle)
                })
                .await
                .unwrap_or_else(|join_err| Err(format!("rollback task failed: {join_err}")))
                {
                    error!(
                        "[API] Failed to roll back transparent proxy settings: {}",
                        rb_err
                    );
                }
            }
            status = "500 Internal Server Error";
            content_type = JSON_CONTENT_TYPE;
            body = json_error(
                locale,
                "ERR_CONFIG_PERSIST_FAILED",
                "error.config_persist_failed",
            );
            persisted_ok = false;
        }
        if persisted_ok {
            let committed_nodes =
                std::mem::take(&mut *proxy_nodes.write().unwrap_or_else(|e| e.into_inner()));
            {
                let mut live_nodes = live_proxy_nodes.write().unwrap_or_else(|e| e.into_inner());
                *live_nodes = committed_nodes;
            }
            let (committed_rules, committed_default) = rule_engine.snapshot_state();
            live_rule_engine.restore_state(committed_rules, committed_default);
        }
    }

    // 内存与磁盘均提交/回滚完毕后立即释放写锁与并发许可，避免慢读客户端占用写通路；
    // 若触发了提权交接停机，必须在释放 mutation_guard 之前先触发 shutdown_tx 止停接单窗口
    release_mutation_locks_before_response(
        &mut mutation_guard,
        &mut mutation_sem_permit,
        trigger_elevated_shutdown,
        shutdown_tx.as_ref(),
    );

    finish_api_response_and_maybe_shutdown(
        &mut stream,
        status,
        content_type,
        &body,
        trigger_elevated_shutdown,
        shutdown_tx.as_ref(),
    )
    .await?;
    Ok(())
}

pub(super) fn release_mutation_locks_before_response(
    mutation_guard: &mut Option<tokio::sync::MutexGuard<'_, ()>>,
    mutation_sem_permit: &mut Option<tokio::sync::SemaphorePermit<'_>>,
    trigger_elevated_shutdown: bool,
    shutdown_tx: Option<&watch::Sender<bool>>,
) {
    if trigger_elevated_shutdown && let Some(tx) = shutdown_tx {
        let _ = tx.send(true);
    }
    drop(mutation_guard.take());
    drop(mutation_sem_permit.take());
}

#[inline]
pub(super) fn is_mutation_endpoint(method: &str, path: &str) -> bool {
    matches!(
        (method, path),
        ("POST" | "PUT" | "PATCH" | "DELETE", "/api/nodes")
            | ("POST" | "PUT" | "PATCH" | "DELETE", "/api/rules")
            | (
                "POST",
                "/api/rules/default"
                    | "/api/rules/toggle"
                    | "/api/rules/move"
                    | "/api/transparent/toggle"
            )
            | ("PUT" | "POST", "/api/transparent/config")
    )
}

pub(super) async fn finish_api_response_and_maybe_shutdown(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
    trigger_elevated_shutdown: bool,
    shutdown_tx: Option<&watch::Sender<bool>>,
) -> std::io::Result<()> {
    let send_res = send_http_response(stream, status, content_type, body).await;
    if trigger_elevated_shutdown {
        let _ = stream.shutdown().await;
        if let Some(tx) = shutdown_tx {
            let _ = tx.send(true);
        }
    }
    send_res
}

async fn persist_config_async_with_timeout(
    store: Arc<ConfigStore>,
    proxy_nodes: &RwLock<HashMap<u32, ProxyNodeEntry>>,
    rule_engine: &RuleEngine,
    transparent: Option<TransparentSettings>,
    timeout: Duration,
) -> Result<()> {
    let cfg = ConfigStore::snapshot_runtime_with_transparent(
        proxy_nodes,
        rule_engine,
        transparent.as_ref(),
    );
    let cancel_token = Arc::new(crate::config::PersistCancelToken::new());
    let token_for_task = Arc::clone(&cancel_token);
    let mut handle =
        tokio::task::spawn_blocking(move || store.save_profile_cancellable(&cfg, &token_for_task));
    match tokio::time::timeout(timeout, &mut handle).await {
        Ok(join_res) => {
            join_res.context("Configuration persistence background task failed")??;
            Ok(())
        }
        Err(_) => {
            if cancel_token.try_cancel() {
                anyhow::bail!("Configuration persistence timed out after {:?}", timeout);
            }
            // 后台写盘线程已跨过提交闸门进入最终原子 rename：等待其完成以确保内存状态与磁盘严格一致
            handle
                .await
                .context("Configuration persistence background task failed")??;
            Ok(())
        }
    }
}
