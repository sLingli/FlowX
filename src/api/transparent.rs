use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::watch;

use crate::api::{ElevateRunner, JSON_CONTENT_TYPE, control_error_to_http, serde_json_to_string};
use crate::config::ConfigStore;
use crate::control::transparent::{
    apply_transparent_config_fields, classify_transparent_apply_error,
    classify_transparent_elevate_error, transparent_status_or_fallback,
};
use crate::control::{TransparentConfigRequest, TransparentToggleRequest};
use crate::i18n::{Locale, json_error, t};
use crate::transparent::{
    TransparentManager, TransparentSettings, relaunch_elevated_with_replace_pid,
};

pub(super) struct TransparentRollbackState {
    pub(super) prev_settings: TransparentSettings,
    pub(super) prev_persisted_enabled: Option<bool>,
}

pub(super) fn handle_transparent_status(
    transparent_manager: Option<&TransparentManager>,
    config_store: Option<&ConfigStore>,
) -> (&'static str, &'static str, String) {
    let status_view = transparent_status_or_fallback(transparent_manager);
    let mut body_val = serde_json::to_value(&status_view).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(obj) = body_val.as_object_mut() {
        obj.insert(
            "config_path".to_string(),
            config_store
                .map(|s| serde_json::Value::String(s.path().display().to_string()))
                .unwrap_or(serde_json::Value::Null),
        );
    }
    ("200 OK", JSON_CONTENT_TYPE, serde_json_to_string(&body_val))
}

pub(super) fn finalize_elevate_response_and_log(
    locale: Locale,
    status: &'static str,
    body: String,
) -> (&'static str, String) {
    if status.starts_with("200") {
        return (status, body);
    }

    let (out_status, out_body) = if status == "500 Internal Server Error" {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body) {
            if let Some(detail) = val.get("detail").and_then(|v| v.as_str()) {
                if detail.starts_with("ERR_TRANSPARENT_LOW_INTEGRITY:") {
                    (
                        "409 Conflict",
                        serde_json::json!({
                            "error": t(locale, "error.transparent_low_integrity"),
                            "code": "ERR_TRANSPARENT_LOW_INTEGRITY",
                            "detail": detail,
                        })
                        .to_string(),
                    )
                } else {
                    (status, body)
                }
            } else {
                (status, body)
            }
        } else {
            (status, body)
        }
    } else {
        (status, body)
    };

    tracing::warn!(
        "[API] POST /api/transparent/elevate failed ({}): {}",
        out_status,
        out_body
    );
    (out_status, out_body)
}

fn map_transparent_apply_error(
    locale: Locale,
    raw_err: &str,
) -> (&'static str, &'static str, String) {
    control_error_to_http(classify_transparent_apply_error(raw_err), locale)
}

async fn apply_transparent_and_stage(
    mgr: &Arc<TransparentManager>,
    next: TransparentSettings,
    is_config_only: bool,
    update_persisted_enabled: Option<bool>,
    locale: Locale,
    should_persist: &mut bool,
    rollback_transparent: &mut Option<TransparentRollbackState>,
) -> (&'static str, &'static str, String) {
    let prev = mgr.settings();
    let prev_persisted = update_persisted_enabled.map(|_| mgr.persisted_settings().enabled);
    let mgr_clone = Arc::clone(mgr);
    let rt_handle = tokio::runtime::Handle::current();
    match tokio::task::spawn_blocking(move || {
        if is_config_only {
            mgr_clone.apply_config_update(next, &rt_handle)
        } else {
            mgr_clone.apply_settings(next, &rt_handle)
        }
    })
    .await
    {
        Ok(Ok(())) => {
            if let Some(new_pe) = update_persisted_enabled {
                mgr.set_persisted_enabled(new_pe);
            }
            *rollback_transparent = Some(TransparentRollbackState {
                prev_settings: prev,
                prev_persisted_enabled: prev_persisted,
            });
            *should_persist = true;
            (
                "200 OK",
                JSON_CONTENT_TYPE,
                serde_json_to_string(&mgr.status()),
            )
        }
        Ok(Err(raw_err)) => map_transparent_apply_error(locale, &raw_err),
        Err(join_err) => map_transparent_apply_error(
            locale,
            &format!("Transparent manager background task failed: {join_err}"),
        ),
    }
}

pub(super) async fn handle_transparent_toggle(
    mgr: Option<&Arc<TransparentManager>>,
    req_body: &str,
    locale: Locale,
    should_persist: &mut bool,
    rollback_transparent: &mut Option<TransparentRollbackState>,
) -> (&'static str, &'static str, String) {
    let Some(mgr) = mgr else {
        return (
            "503 Service Unavailable",
            JSON_CONTENT_TYPE,
            json_error(
                locale,
                "ERR_TRANSPARENT_UNAVAILABLE",
                "error.transparent_unavailable",
            ),
        );
    };
    let Ok(req) = serde_json::from_str::<TransparentToggleRequest>(req_body) else {
        return (
            "400 Bad Request",
            JSON_CONTENT_TYPE,
            json_error(
                locale,
                "ERR_INVALID_TRANSPARENT_BODY",
                "error.invalid_transparent_body",
            ),
        );
    };

    let mut next = mgr.settings();
    next.enabled = req.enabled;
    apply_transparent_and_stage(
        mgr,
        next,
        false,
        Some(req.enabled),
        locale,
        should_persist,
        rollback_transparent,
    )
    .await
}

pub(super) async fn handle_transparent_config(
    mgr: Option<&Arc<TransparentManager>>,
    req_body: &str,
    locale: Locale,
    should_persist: &mut bool,
    rollback_transparent: &mut Option<TransparentRollbackState>,
) -> (&'static str, &'static str, String) {
    let Some(mgr) = mgr else {
        return (
            "503 Service Unavailable",
            JSON_CONTENT_TYPE,
            json_error(
                locale,
                "ERR_TRANSPARENT_UNAVAILABLE",
                "error.transparent_unavailable",
            ),
        );
    };
    let Ok(req) = serde_json::from_str::<TransparentConfigRequest>(req_body) else {
        return (
            "400 Bad Request",
            JSON_CONTENT_TYPE,
            json_error(
                locale,
                "ERR_INVALID_TRANSPARENT_BODY",
                "error.invalid_transparent_body",
            ),
        );
    };

    let next = match apply_transparent_config_fields(&mgr.settings(), req) {
        Ok(next) => next,
        Err(err) => return control_error_to_http(err, locale),
    };

    apply_transparent_and_stage(
        mgr,
        next,
        true,
        None,
        locale,
        should_persist,
        rollback_transparent,
    )
    .await
}

struct ElevateFlagResetGuard {
    flag: Arc<AtomicBool>,
    armed: bool,
}

impl Drop for ElevateFlagResetGuard {
    fn drop(&mut self) {
        if self.armed {
            self.flag.store(false, Ordering::Release);
        }
    }
}

pub(super) async fn handle_transparent_elevate_after_gate(
    locale: Locale,
    elevating: Arc<AtomicBool>,
    shutdown_tx: Option<watch::Sender<bool>>,
    elevate_runner: Option<ElevateRunner>,
    trigger_elevated_shutdown: &mut bool,
) -> (&'static str, &'static str, String) {
    // 将 ElevateFlagResetGuard 与 shutdown_tx 同步迁入 spawn_blocking 内部：
    // 1) 若客户端在 UAC 弹窗期间断开或取消异步 future，elevating 绝不会提前复位（杜绝弹第二个 UAC），
    //    且用户最终点允许后阻塞线程仍会立即发送 shutdown_tx(true) 平滑交接端口；
    // 2) ShellExecuteW 返回 Ok(()) 的同一阻塞线程内立刻广播 shutdown_tx(true)，彻底消除返回到主协程间的竞态窗口。
    let launch_fut = tokio::task::spawn_blocking(move || {
        let mut reset_guard = ElevateFlagResetGuard {
            flag: elevating,
            armed: true,
        };
        #[cfg(test)]
        let res = match elevate_runner {
            Some(runner) => runner(),
            None => relaunch_elevated_with_replace_pid(&[]),
        };
        #[cfg(not(test))]
        let res = {
            let _ = elevate_runner;
            relaunch_elevated_with_replace_pid(&[])
        };
        if res.is_ok() {
            reset_guard.armed = false;
            if let Some(tx) = shutdown_tx.as_ref() {
                let _ = tx.send(true);
            }
        }
        res
    });

    match launch_fut.await {
        Ok(Ok(())) => {
            *trigger_elevated_shutdown = true;
            (
                "200 OK",
                JSON_CONTENT_TYPE,
                r#"{"ok":true,"relaunching":true}"#.to_string(),
            )
        }
        Ok(Err(e)) => control_error_to_http(classify_transparent_elevate_error(&e), locale),
        Err(join_err) => (
            "500 Internal Server Error",
            JSON_CONTENT_TYPE,
            serde_json::json!({
                "error": t(locale, "error.transparent_elevate_failed"),
                "code": "ERR_TRANSPARENT_ELEVATE_FAILED",
                "detail": format!("Elevation background task failed: {join_err}"),
            })
            .to_string(),
        ),
    }
}
