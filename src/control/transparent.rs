use serde::Deserialize;

use crate::control::ControlError;
use crate::transparent::{
    TransparentManager, TransparentRuntimeStatus, TransparentSettings,
    is_valid_custom_dll_path_input, probe_status,
};

#[derive(Debug, Deserialize)]
pub struct TransparentToggleRequest {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct TransparentConfigRequest {
    pub hijack_dns: Option<bool>,
    pub block_quic_for_proxied: Option<bool>,
    pub dll_path: Option<String>,
    pub clear_dll_path: Option<bool>,
}

pub fn transparent_status_or_fallback(
    mgr: Option<&TransparentManager>,
) -> TransparentRuntimeStatus {
    mgr.map_or_else(
        || probe_status(&TransparentSettings::default()),
        |m| m.status(),
    )
}

/// 校验并应用透明代理配置更新请求（供在线 API 与离线 CLI 复用）
pub fn apply_transparent_config_fields(
    current: &TransparentSettings,
    req: TransparentConfigRequest,
) -> Result<TransparentSettings, ControlError> {
    if req.clear_dll_path == Some(true)
        && req
            .dll_path
            .as_deref()
            .map(str::trim)
            .is_some_and(|s| !s.is_empty())
    {
        return Err(ControlError::bad_request(
            "ERR_TRANSPARENT_INVALID_DLL_PATH",
            "error.transparent_invalid_dll_path",
        ));
    }

    if let Some(ref raw_path) = req.dll_path
        && !is_valid_custom_dll_path_input(raw_path)
    {
        return Err(ControlError::bad_request(
            "ERR_TRANSPARENT_INVALID_DLL_PATH",
            "error.transparent_invalid_dll_path",
        ));
    }

    let mut next = current.clone();
    if let Some(v) = req.hijack_dns {
        next.hijack_dns = v;
    }
    if let Some(v) = req.block_quic_for_proxied {
        next.block_quic_for_proxied = v;
    }
    if req.clear_dll_path == Some(true) {
        next.dll_path = None;
    } else if let Some(raw_path) = req.dll_path {
        let trimmed = raw_path.trim();
        next.dll_path = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
    }

    Ok(next)
}

pub fn classify_transparent_apply_error(raw_err: &str) -> ControlError {
    if raw_err.starts_with("ERR_TRANSPARENT_REQUIRES_ADMIN:") {
        ControlError::conflict_with_detail(
            "ERR_TRANSPARENT_REQUIRES_ADMIN",
            "error.transparent_requires_admin",
            raw_err,
        )
    } else if raw_err.starts_with("ERR_TRANSPARENT_MISSING_DRIVER:") {
        ControlError::conflict_with_detail(
            "ERR_TRANSPARENT_MISSING_DRIVER",
            "error.transparent_missing_driver",
            raw_err,
        )
    } else {
        ControlError::internal_with_detail(
            "ERR_TRANSPARENT_START_FAILED",
            "error.transparent_start_failed",
            raw_err,
        )
    }
}

pub fn classify_transparent_elevate_error(err: &std::io::Error) -> ControlError {
    let msg = err.to_string();
    if msg.contains("ERR_TRANSPARENT_UAC_CANCELLED") {
        ControlError::conflict_with_detail(
            "ERR_TRANSPARENT_UAC_CANCELLED",
            "error.transparent_uac_cancelled",
            msg,
        )
    } else if msg.starts_with("ERR_TRANSPARENT_LOW_INTEGRITY:") {
        ControlError::conflict_with_detail(
            "ERR_TRANSPARENT_LOW_INTEGRITY",
            "error.transparent_low_integrity",
            msg,
        )
    } else if err.kind() == std::io::ErrorKind::AlreadyExists {
        ControlError::conflict_with_detail(
            "ERR_TRANSPARENT_ALREADY_ELEVATED",
            "error.transparent_already_elevated",
            msg,
        )
    } else {
        ControlError::internal_with_detail(
            "ERR_TRANSPARENT_ELEVATE_FAILED",
            "error.transparent_elevate_failed",
            msg,
        )
    }
}
