use serde::{Deserialize, Serialize};

/// 进程归属无法反查时写入连接快照的占位标记。
///
/// 该值是机器可读的内部标记，展示层需要按当前语言替换为 `label.unknown_process`，
/// 不应直接把该常量当作文案输出。
pub const UNKNOWN_PROCESS: &str = "Unknown";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Locale {
    #[serde(rename = "zh-CN")]
    Zh,
    #[serde(rename = "en-US")]
    #[default]
    En,
}

impl Locale {
    pub fn as_str(&self) -> &'static str {
        match self {
            Locale::Zh => "zh-CN",
            Locale::En => "en-US",
        }
    }

    /// 从单个语言标记（如 `zh-CN` / `en-US` / `zh`）解析受支持的语言
    fn from_tag(tag: &str) -> Option<Self> {
        let tag = tag.trim().to_ascii_lowercase();
        if tag == "zh" || tag.starts_with("zh-") || tag.starts_with("zh_") {
            Some(Locale::Zh)
        } else if tag == "en" || tag.starts_with("en-") || tag.starts_with("en_") {
            Some(Locale::En)
        } else {
            None
        }
    }

    /// 从 HTTP `Accept-Language` 请求头或 `lang` 查询参数中解析语言偏好。
    ///
    /// - `header_opt`：原始 `Accept-Language` 头，按 q 权重（缺省 1.0）选择受支持语言中优先级最高者；
    /// - `query_opt`：`lang` 查询参数的原始值（兼容旧调用传入 `lang=xx` 形式），优先级高于请求头。
    pub fn from_header_or_query(header_opt: Option<&str>, query_opt: Option<&str>) -> Self {
        if let Some(query) = query_opt {
            let value = query.trim();
            let value = value
                .strip_prefix("lang=")
                .or_else(|| value.strip_prefix("LANG="))
                .unwrap_or(value);
            if let Some(locale) = Locale::from_tag(value) {
                return locale;
            }
        }

        if let Some(header) = header_opt
            && let Some(locale) = Locale::from_accept_language(header)
        {
            return locale;
        }

        Locale::En
    }

    /// 解析 `Accept-Language`，按 q 权重取受支持语言中优先级最高者
    fn from_accept_language(header: &str) -> Option<Self> {
        let mut best: Option<(f32, Self)> = None;
        for item in header.split(',') {
            let mut parts = item.split(';');
            let Some(locale) = Locale::from_tag(parts.next().unwrap_or_default()) else {
                continue;
            };
            let weight = parts
                .find_map(|p| {
                    let p = p.trim();
                    p.strip_prefix("q=")
                        .or_else(|| p.strip_prefix("Q="))
                        .and_then(|v| v.trim().parse::<f32>().ok())
                })
                .unwrap_or(1.0);
            if best.is_none_or(|(best_weight, _)| weight > best_weight) {
                best = Some((weight, locale));
            }
        }
        // 显式 q=0 表示客户端拒绝该语言，不应被选中
        best.filter(|(weight, _)| *weight > 0.0).map(|(_, locale)| locale)
    }
}

/// 国际化翻译入口
pub fn t(locale: Locale, key: &str) -> &'static str {
    match locale {
        Locale::Zh => translate_zh(key),
        Locale::En => translate_en(key),
    }
}

/// 构造标准化、多语言且带机器可读错误码的 JSON 错误响应
pub fn json_error(locale: Locale, code: &str, key: &str) -> String {
    let msg = t(locale, key);
    format!(r#"{{"error":"{}","code":"{}","key":"{}"}}"#, msg, code, key)
}

fn translate_zh(key: &str) -> &'static str {
    match key {
        // 请求与安全校验
        "error.incomplete_headers" => "HTTP 请求头格式不完整",
        "error.non_utf8_headers" => "HTTP 请求头包含非 UTF-8 字节",
        "error.invalid_request_line" => "HTTP 请求行格式无效",
        "error.invalid_request_framing" => "HTTP 请求换行或结构非法",
        "error.unsupported_transfer_encoding" => "不支持的 Transfer-Encoding 请求头",
        "error.duplicate_header" => "包含重复的敏感 HTTP 请求头",
        "error.unsupported_media_type" => "请求 Content-Type 必须为 application/json",
        "error.invalid_host" => "非法的 Host 请求头，仅允许本地控制台访问",
        "error.invalid_origin" => "拒绝跨源请求 (Origin 校验失败)",
        "error.invalid_fetch_site" => "拒绝跨站 API 请求 (Sec-Fetch-Site)",
        "error.invalid_referer" => "拒绝跨站变更请求 (Referer 校验失败)",
        "error.request_too_large" => "HTTP 请求体超出 1MB 上限",
        "error.invalid_content_length" => "无效的 Content-Length 请求头",
        "error.request_read_failed" => "读取 HTTP 请求失败",
        "error.not_found" => "请求的资源未找到",

        // 连接管理
        "error.missing_conn_id" => "缺少连接 ID",

        // 节点管理
        "error.invalid_node_body" => "无效的节点请求体",
        "error.empty_node_name" => "节点名称不能为空",
        "error.unsupported_protocol" => "不支持的代理协议，仅支持 SOCKS5 / SOCKS4 / HTTP",
        "error.invalid_node_addr" => "节点服务器地址格式无效，应为 IP:Port 或 Host:Port",
        "error.invalid_node_port" => "节点服务器地址或端口无效",
        "error.node_self_loop" => "节点地址不能指向 FlowX 自身服务端口",
        "error.invalid_username" => "代理用户名包含非法字符或超出 255 字节限制",
        "error.invalid_password" => "代理密码包含非法字符或超出 255 字节限制",
        "error.password_required_on_user_change" => "修改代理用户名时必须提供新密码",
        "error.socks4_password_unsupported" => "SOCKS4 协议仅支持 UserID，不支持密码认证",
        "error.missing_node_id" => "缺少节点 ID",
        "error.node_not_found" => "指定的代理节点不存在",
        "error.node_in_use" => "节点正被路由规则或默认兜底动作引用，禁止删除。请先修改或删除关联配置",
        "ping.timeout" => "连接超时 (2000ms)",
        "error.ping_failed" => "节点连通性探测失败",

        // 规则管理
        "error.invalid_rule_body" => "无效的规则请求体",
        "error.empty_rule_name" => "规则名称不能为空",
        "error.missing_node_id_for_proxy" => "Proxy 动作必须指定节点 ID",
        "error.invalid_rule_action" => "无效的规则动作，仅支持 Direct / Block / Proxy",
        "error.invalid_app_pattern" => "应用进程匹配语法无效",
        "error.invalid_target_pattern" => "目标地址/域名匹配语法无效",
        "error.invalid_port_format" => "端口格式无效，请使用如 80; 443; 8000-8080",
        "error.missing_rule_id" => "缺少规则 ID",
        "error.rule_not_found" => "路由规则不存在",
        "error.invalid_toggle_body" => "无效的规则启停请求体",
        "error.invalid_move_body" => "无效的规则排序请求体",
        "error.invalid_move_direction" => "排序方向仅支持 up / down / top / bottom",
        "error.invalid_default_action_body" => "无效的默认兜底动作请求体",
        "error.invalid_simulate_body" => "无效的路由模拟请求体",
        "error.invalid_simulate_target" => "模拟目标地址不能为空，且端口需在 1-65535 之间",

        // 系统与动作描述
        "status.ok" => "运行正常",
        "action.direct" => "Direct (直连)",
        "action.block" => "Block (阻断)",
        "action.proxy_prefix" => "Proxy (节点-{})",
        "action.chain_prefix" => "Chain (链路-{})",
        "action.default_rule" => "默认",
        "label.unknown_process" => "未知进程",
        "system.memory_mode" => "仅内存模式",

        _ => "未知错误",
    }
}

fn translate_en(key: &str) -> &'static str {
    match key {
        // Request & Security validation
        "error.incomplete_headers" => "Incomplete HTTP request headers",
        "error.non_utf8_headers" => "HTTP headers contain non-UTF-8 bytes",
        "error.invalid_request_line" => "Invalid HTTP request line",
        "error.invalid_request_framing" => "Malformed HTTP request framing",
        "error.unsupported_transfer_encoding" => "Unsupported Transfer-Encoding header",
        "error.duplicate_header" => "Duplicate sensitive HTTP header",
        "error.unsupported_media_type" => "Content-Type must be application/json",
        "error.invalid_host" => "Invalid Host header, local console access only",
        "error.invalid_origin" => "Cross-origin request rejected (Origin validation failed)",
        "error.invalid_fetch_site" => "Cross-site API request rejected (Sec-Fetch-Site)",
        "error.invalid_referer" => "Cross-site mutation request rejected (Referer validation failed)",
        "error.request_too_large" => "HTTP request body exceeds 1MB limit",
        "error.invalid_content_length" => "Invalid Content-Length header",
        "error.request_read_failed" => "Failed to read HTTP request",
        "error.not_found" => "Requested resource not found",

        // Connection management
        "error.missing_conn_id" => "Connection ID is required",

        // Node management
        "error.invalid_node_body" => "Invalid node request payload",
        "error.empty_node_name" => "Node name cannot be empty",
        "error.unsupported_protocol" => "Unsupported proxy protocol, only SOCKS5 / SOCKS4 / HTTP supported",
        "error.invalid_node_addr" => "Invalid node server address format, expected IP:Port or Host:Port",
        "error.invalid_node_port" => "Invalid node server address or port",
        "error.node_self_loop" => "Node address cannot point to FlowX internal service ports",
        "error.invalid_username" => "Proxy username contains invalid characters or exceeds 255 bytes",
        "error.invalid_password" => "Proxy password contains invalid characters or exceeds 255 bytes",
        "error.password_required_on_user_change" => "A new password must be provided when changing the proxy username",
        "error.socks4_password_unsupported" => "SOCKS4 only supports UserID and does not support passwords",
        "error.missing_node_id" => "Node ID is required",
        "error.node_not_found" => "Specified proxy node not found",
        "error.node_in_use" => "Node is referenced by active rules or default fallback action and cannot be deleted. Please modify or remove related configurations first",
        "ping.timeout" => "Connection timed out (2000ms)",
        "error.ping_failed" => "Node connectivity probe failed",

        // Rule management
        "error.invalid_rule_body" => "Invalid rule request payload",
        "error.empty_rule_name" => "Rule name cannot be empty",
        "error.missing_node_id_for_proxy" => "Proxy action requires a node ID",
        "error.invalid_rule_action" => "Invalid rule action, only Direct / Block / Proxy supported",
        "error.invalid_app_pattern" => "Invalid application matching syntax",
        "error.invalid_target_pattern" => "Invalid target host/domain matching syntax",
        "error.invalid_port_format" => "Invalid port format, please use format like 80; 443; 8000-8080",
        "error.missing_rule_id" => "Rule ID is required",
        "error.rule_not_found" => "Routing rule not found",
        "error.invalid_toggle_body" => "Invalid rule toggle request payload",
        "error.invalid_move_body" => "Invalid rule move request payload",
        "error.invalid_move_direction" => "Move direction only supports up / down / top / bottom",
        "error.invalid_default_action_body" => "Invalid default fallback action request payload",
        "error.invalid_simulate_body" => "Invalid route simulation request payload",
        "error.invalid_simulate_target" => "Simulation target host cannot be empty and port must be between 1 and 65535",

        // Status & Actions
        "status.ok" => "Operational",
        "action.direct" => "Direct",
        "action.block" => "Block",
        "action.proxy_prefix" => "Proxy (Node-{})",
        "action.chain_prefix" => "Chain (Chain-{})",
        "action.default_rule" => "Default",
        "label.unknown_process" => "Unknown process",
        "system.memory_mode" => "Memory-only mode",

        _ => "Unknown error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locale_resolution() {
        assert_eq!(Locale::from_header_or_query(Some("zh-CN,zh;q=0.9"), None), Locale::Zh);
        assert_eq!(Locale::from_header_or_query(Some("en-US,en;q=0.9"), None), Locale::En);
        assert_eq!(Locale::from_header_or_query(None, Some("lang=zh")), Locale::Zh);
        assert_eq!(Locale::from_header_or_query(None, Some("lang=en")), Locale::En);
        assert_eq!(Locale::from_header_or_query(None, None), Locale::En);
        // 查询参数优先于请求头
        assert_eq!(Locale::from_header_or_query(Some("zh-CN"), Some("en-US")), Locale::En);
        // 不支持的语言回退到默认 En
        assert_eq!(Locale::from_header_or_query(Some("fr-FR,fr;q=0.9"), None), Locale::En);
        // q 权重：en 权重更高时不应因为 zh 出现在前面而误选 zh
        assert_eq!(
            Locale::from_header_or_query(Some("zh-CN;q=0.1,en-US;q=0.9"), None),
            Locale::En
        );
        // q=0 表示客户端拒绝该语言
        assert_eq!(Locale::from_header_or_query(Some("zh-CN;q=0,en-US;q=0.8"), None), Locale::En);
        // 查询参数为裸语言标记（不强制要求 lang= 前缀）
        assert_eq!(Locale::from_header_or_query(None, Some("zh-cn")), Locale::Zh);
    }

    #[test]
    fn test_action_placeholders_present() {
        for locale in [Locale::Zh, Locale::En] {
            for key in ["action.proxy_prefix", "action.chain_prefix"] {
                assert!(t(locale, key).contains("{}"), "missing placeholder for {key}");
            }
        }
    }

    #[test]
    fn test_translation_keys() {
        assert_eq!(t(Locale::Zh, "error.missing_conn_id"), "缺少连接 ID");
        assert_eq!(t(Locale::En, "error.missing_conn_id"), "Connection ID is required");
        assert_eq!(t(Locale::Zh, "status.ok"), "运行正常");
        assert_eq!(t(Locale::En, "status.ok"), "Operational");
    }

    #[test]
    fn test_json_error_format() {
        let err_zh = json_error(Locale::Zh, "ERR_NODE_IN_USE", "error.node_in_use");
        assert!(err_zh.contains(r#""error":"节点正被路由规则"#));
        assert!(err_zh.contains(r#""code":"ERR_NODE_IN_USE""#));

        let err_en = json_error(Locale::En, "ERR_NODE_IN_USE", "error.node_in_use");
        assert!(err_en.contains(r#""error":"Node is referenced"#));
        assert!(err_en.contains(r#""code":"ERR_NODE_IN_USE""#));
    }
}
