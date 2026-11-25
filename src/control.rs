pub mod node;
pub mod routing;
pub mod rule;
pub mod transparent;

use crate::i18n::{json_error, t, Locale};

pub use node::{
    AddNodeRequest, PatchNodeRequest, PingNodeRequest, PingResponse, ProxyNodeView,
    UpdateNodeRequest,
};
pub use routing::{
    DefaultActionResponse, SetDefaultActionRequest, SimulateRouteRequest, SimulateRouteResponse,
    SystemInfoResponse, SystemRuntimeContext,
};
pub use rule::{
    AddRuleRequest, MoveRuleRequest, PatchRuleRequest, ToggleRuleRequest, UpdateRuleRequest,
};
pub use transparent::{TransparentConfigRequest, TransparentToggleRequest};

/// 传输无关的控制面错误类别（由 `api` 映射为 HTTP 状态码，由 `cli` 映射为结构化错误码）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlErrorKind {
    BadRequest,
    NotFound,
    Conflict,
    ServiceUnavailable,
    Internal,
}

impl ControlErrorKind {
    pub const fn status_code(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::ServiceUnavailable => 503,
            Self::Internal => 500,
        }
    }

    pub const fn http_status_line(self) -> &'static str {
        match self {
            Self::BadRequest => "400 Bad Request",
            Self::NotFound => "404 Not Found",
            Self::Conflict => "409 Conflict",
            Self::ServiceUnavailable => "503 Service Unavailable",
            Self::Internal => "500 Internal Server Error",
        }
    }
}

/// 传输无关的控制面业务错误模型
#[derive(Debug, Clone)]
pub struct ControlError {
    pub kind: ControlErrorKind,
    pub code: &'static str,
    pub message_key: &'static str,
    pub detail: Option<String>,
}

impl ControlError {
    pub const fn bad_request(code: &'static str, message_key: &'static str) -> Self {
        Self {
            kind: ControlErrorKind::BadRequest,
            code,
            message_key,
            detail: None,
        }
    }

    pub const fn not_found(code: &'static str, message_key: &'static str) -> Self {
        Self {
            kind: ControlErrorKind::NotFound,
            code,
            message_key,
            detail: None,
        }
    }

    pub const fn conflict(code: &'static str, message_key: &'static str) -> Self {
        Self {
            kind: ControlErrorKind::Conflict,
            code,
            message_key,
            detail: None,
        }
    }

    pub fn conflict_with_detail(
        code: &'static str,
        message_key: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind: ControlErrorKind::Conflict,
            code,
            message_key,
            detail: Some(detail.into()),
        }
    }

    pub const fn service_unavailable(code: &'static str, message_key: &'static str) -> Self {
        Self {
            kind: ControlErrorKind::ServiceUnavailable,
            code,
            message_key,
            detail: None,
        }
    }

    pub fn internal_with_detail(
        code: &'static str,
        message_key: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind: ControlErrorKind::Internal,
            code,
            message_key,
            detail: Some(detail.into()),
        }
    }

    /// 序列化为与 HTTP API / CLI 离线路径完全一致的本地化错误 JSON
    pub fn to_localized_json(&self, locale: Locale) -> String {
        match &self.detail {
            Some(detail) => serde_json::json!({
                "error": t(locale, self.message_key),
                "code": self.code,
                "detail": detail,
            })
            .to_string(),
            None => json_error(locale, self.code, self.message_key),
        }
    }

    pub fn to_localized_value(&self, locale: Locale) -> serde_json::Value {
        serde_json::from_str(&self.to_localized_json(locale)).unwrap_or_else(|_| {
            serde_json::json!({
                "error": t(locale, self.message_key),
                "code": self.code,
            })
        })
    }
}
