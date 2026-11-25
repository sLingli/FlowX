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
            let mut weight = 1.0f32;
            let mut valid_q = true;
            for param in parts {
                let param = param.trim();
                if let Some(raw_q) = param
                    .strip_prefix("q=")
                    .or_else(|| param.strip_prefix("Q="))
                {
                    match raw_q.trim().parse::<f32>() {
                        Ok(w) if w.is_finite() && (0.0..=1.0).contains(&w) => {
                            weight = w;
                            break;
                        }
                        _ => {
                            valid_q = false;
                            break;
                        }
                    }
                }
            }
            if !valid_q {
                continue;
            }
            if best.is_none_or(|(best_weight, _)| weight > best_weight) {
                best = Some((weight, locale));
            }
        }
        // 显式 q=0 表示客户端拒绝该语言，不应被选中
        best.filter(|(weight, _)| *weight > 0.0)
            .map(|(_, locale)| locale)
    }

    /// 从进程环境变量按 POSIX 优先级 (`FLOWX_LANG` -> `LC_ALL` -> `LC_MESSAGES` -> `LANG`) 自动探测语言
    pub fn from_env() -> Self {
        Self::from_env_lookup(|key| std::env::var(key).ok())
    }

    /// 使用自定义查询闭包解析环境变量语言设置（默认回落至英文）
    pub fn from_env_lookup<F>(mut get_var: F) -> Self
    where
        F: FnMut(&str) -> Option<String>,
    {
        for key in ["FLOWX_LANG", "LC_ALL", "LC_MESSAGES", "LANG"] {
            if let Some(raw) = get_var(key) {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    continue;
                }
                return Self::from_posix_locale(trimmed);
            }
        }
        Locale::En
    }

    fn from_posix_locale(raw: &str) -> Self {
        let stripped = raw
            .trim()
            .split(['.', '@'])
            .next()
            .unwrap_or_default()
            .replace('_', "-")
            .to_ascii_lowercase();
        if stripped == "zh" || stripped.starts_with("zh-") {
            Locale::Zh
        } else {
            Locale::En
        }
    }

    pub fn accept_language_header(&self) -> &'static str {
        match self {
            Locale::Zh => "zh-CN",
            Locale::En => "en-US",
        }
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
        "error.request_timeout" => "读取 HTTP 请求超时",
        "error.not_found" => "请求的资源未找到",

        // 连接管理
        "error.missing_conn_id" => "缺少连接 ID",

        // 节点管理
        "error.invalid_node_body" => "无效的节点请求体",
        "error.empty_node_name" => "节点名称不能为空",
        "error.invalid_node_name" => "节点名称包含非法控制字符或超出 255 字节限制",
        "error.unsupported_protocol" => "不支持的代理协议，仅支持 SOCKS5 / SOCKS4 / HTTP",
        "error.invalid_node_addr" => "节点服务器地址格式无效，应为 IP:Port 或 Host:Port",
        "error.invalid_node_port" => "节点服务器地址或端口无效",
        "error.node_self_loop" => "节点地址不能指向 FlowX 自身服务端口",
        "error.node_fake_ip" => "节点地址不能为 Fake-IP 保留网段 IP",
        "error.invalid_username" => "代理用户名包含非法字符或超出 255 字节限制",
        "error.http_username_colon" => "HTTP 代理用户名不能包含冒号 ':'",
        "error.invalid_password" => "代理密码包含非法字符或超出 255 字节限制",
        "error.empty_password" => "新增节点时密码不能为空字符串；若无需密码请留空或不传",
        "error.password_without_username" => "配置代理密码时必须同时提供用户名",
        "error.username_without_password" => {
            "HTTP/SOCKS5 代理配置用户名时必须同时提供密码（仅 SOCKS4 支持单独配置 UserID）"
        }
        "error.conflicting_password_options" => "密码参数冲突：清空密码与保留旧密码不可同时启用",
        "error.conflicting_username_options" => {
            "用户名参数冲突：clear_username 与非空 username 不能同时使用"
        }
        "error.password_required_on_user_change" => "修改代理用户名时必须提供新密码",
        "error.socks4_password_unsupported" => "SOCKS4 协议仅支持 UserID，不支持密码认证",
        "error.config_persist_failed" => "配置持久化写入磁盘失败，已回滚本次内存变更",
        "error.mutation_overloaded" => "当前配置写入并发过高，请稍后重试",
        "error.missing_node_id" => "缺少节点 ID",
        "error.node_not_found" => "指定的代理节点不存在",
        "error.node_in_use" => {
            "节点正被路由规则或默认兜底动作引用，禁止删除。请先修改或删除关联配置"
        }
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

        // 透明代理
        "error.transparent_unavailable" => "透明代理管理器尚未初始化",
        "error.invalid_transparent_body" => "透明代理请求体格式无效",
        "error.transparent_invalid_dll_path" => "WinDivert DLL 路径格式无效或包含非法字符",
        "error.transparent_requires_admin" => "开启系统级透明代理需要以管理员身份运行 FlowX",
        "error.transparent_missing_driver" => {
            "未找到 WinDivert.dll 或 WinDivert64.sys，请将驱动文件置于程序同级目录或指定路径"
        }
        "error.transparent_uac_cancelled" => "管理员提权授权已取消或被系统拒绝",
        "error.transparent_already_elevated" => "当前进程已具备管理员权限",
        "error.transparent_elevate_in_progress" => {
            "管理员提权重启正在进行中，请完成当前 UAC 授权或等待重启完成"
        }
        "error.transparent_low_integrity" => {
            "当前进程处于 Windows 低完整性级别（通常源于沙盒或受限目录继承了低完整性标签），无法触发 UAC 提权，请将程序移至普通目录或以管理员终端启动"
        }
        "error.transparent_elevate_failed" => "触发管理员提权重启失败",
        "error.transparent_start_failed" => "WinDivert 透明代理启动失败",
        "error.server_shutting_down" => "FlowX 服务正在关闭，暂不接受新的变更请求",

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
        "error.invalid_referer" => {
            "Cross-site mutation request rejected (Referer validation failed)"
        }
        "error.request_too_large" => "HTTP request body exceeds 1MB limit",
        "error.invalid_content_length" => "Invalid Content-Length header",
        "error.request_read_failed" => "Failed to read HTTP request",
        "error.request_timeout" => "HTTP request read timed out",
        "error.not_found" => "Requested resource not found",

        // Connection management
        "error.missing_conn_id" => "Connection ID is required",

        // Node management
        "error.invalid_node_body" => "Invalid node request payload",
        "error.empty_node_name" => "Node name cannot be empty",
        "error.invalid_node_name" => {
            "Node name contains invalid control characters or exceeds 255 bytes"
        }
        "error.unsupported_protocol" => {
            "Unsupported proxy protocol, only SOCKS5 / SOCKS4 / HTTP supported"
        }
        "error.invalid_node_addr" => {
            "Invalid node server address format, expected IP:Port or Host:Port"
        }
        "error.invalid_node_port" => "Invalid node server address or port",
        "error.node_self_loop" => "Node address cannot point to FlowX internal service ports",
        "error.node_fake_ip" => "Node server address cannot use a Fake-IP reserved address",
        "error.invalid_username" => {
            "Proxy username contains invalid characters or exceeds 255 bytes"
        }
        "error.http_username_colon" => "HTTP proxy Basic username cannot contain ':'",
        "error.invalid_password" => {
            "Proxy password contains invalid characters or exceeds 255 bytes"
        }
        "error.empty_password" => {
            "Password cannot be empty when creating a node; omit or pass null if unused"
        }
        "error.password_without_username" => {
            "Proxy password cannot be configured without a username"
        }
        "error.username_without_password" => {
            "HTTP/SOCKS5 proxy username requires a password (only SOCKS4 allows standalone UserID)"
        }
        "error.conflicting_password_options" => {
            "Conflicting password options: cannot combine clearing and keeping password"
        }
        "error.conflicting_username_options" => {
            "Conflicting username options: cannot combine clear_username with a non-empty username"
        }
        "error.password_required_on_user_change" => {
            "A new password must be provided when changing the proxy username"
        }
        "error.socks4_password_unsupported" => {
            "SOCKS4 only supports UserID and does not support passwords"
        }
        "error.config_persist_failed" => {
            "Failed to persist configuration changes to disk; in-memory state rolled back"
        }
        "error.mutation_overloaded" => {
            "Too many concurrent configuration mutations; please retry later"
        }
        "error.missing_node_id" => "Node ID is required",
        "error.node_not_found" => "Specified proxy node not found",
        "error.node_in_use" => {
            "Node is referenced by active rules or default fallback action and cannot be deleted. Please modify or remove related configurations first"
        }
        "ping.timeout" => "Connection timed out (2000ms)",
        "error.ping_failed" => "Node connectivity probe failed",

        // Rule management
        "error.invalid_rule_body" => "Invalid rule request payload",
        "error.empty_rule_name" => "Rule name cannot be empty",
        "error.missing_node_id_for_proxy" => "Proxy action requires a node ID",
        "error.invalid_rule_action" => "Invalid rule action, only Direct / Block / Proxy supported",
        "error.invalid_app_pattern" => "Invalid application matching syntax",
        "error.invalid_target_pattern" => "Invalid target host/domain matching syntax",
        "error.invalid_port_format" => {
            "Invalid port format, please use format like 80; 443; 8000-8080"
        }
        "error.missing_rule_id" => "Rule ID is required",
        "error.rule_not_found" => "Routing rule not found",
        "error.invalid_toggle_body" => "Invalid rule toggle request payload",
        "error.invalid_move_body" => "Invalid rule move request payload",
        "error.invalid_move_direction" => "Move direction only supports up / down / top / bottom",
        "error.invalid_default_action_body" => "Invalid default fallback action request payload",
        "error.invalid_simulate_body" => "Invalid route simulation request payload",
        "error.invalid_simulate_target" => {
            "Simulation target host cannot be empty and port must be between 1 and 65535"
        }

        // Status & Actions
        "status.ok" => "Operational",
        "action.direct" => "Direct",
        "action.block" => "Block",
        "action.proxy_prefix" => "Proxy (Node-{})",
        "action.chain_prefix" => "Chain (Chain-{})",
        "action.default_rule" => "Default",
        "label.unknown_process" => "Unknown process",
        "system.memory_mode" => "Memory-only mode",

        // Transparent proxy
        "error.transparent_unavailable" => "Transparent proxy manager is not initialized",
        "error.invalid_transparent_body" => "Invalid transparent proxy request payload",
        "error.transparent_invalid_dll_path" => {
            "Invalid WinDivert DLL path format or illegal characters"
        }
        "error.transparent_requires_admin" => {
            "Transparent proxy requires running FlowX as Administrator"
        }
        "error.transparent_missing_driver" => {
            "WinDivert.dll or WinDivert64.sys not found; place both files next to flowx.exe or set DllPath"
        }
        "error.transparent_uac_cancelled" => {
            "Administrator UAC elevation prompt was cancelled or denied"
        }
        "error.transparent_already_elevated" => {
            "FlowX is already running with Administrator privileges"
        }
        "error.transparent_elevate_in_progress" => {
            "Administrator elevation relaunch is already in progress"
        }
        "error.transparent_low_integrity" => {
            "Current process is running at Windows Low Integrity Level (often inherited from a restricted/sandboxed folder) and cannot trigger UAC elevation; move FlowX to a standard directory or run from an Administrator terminal"
        }
        "error.transparent_elevate_failed" => "Failed to launch elevated FlowX instance",
        "error.transparent_start_failed" => "Failed to start WinDivert transparent proxy",
        "error.server_shutting_down" => {
            "FlowX server is shutting down and cannot accept new mutations"
        }

        _ => "Unknown error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locale_resolution() {
        assert_eq!(
            Locale::from_header_or_query(Some("zh-CN,zh;q=0.9"), None),
            Locale::Zh
        );
        assert_eq!(
            Locale::from_header_or_query(Some("en-US,en;q=0.9"), None),
            Locale::En
        );
        assert_eq!(
            Locale::from_header_or_query(None, Some("lang=zh")),
            Locale::Zh
        );
        assert_eq!(
            Locale::from_header_or_query(None, Some("lang=en")),
            Locale::En
        );
        assert_eq!(Locale::from_header_or_query(None, None), Locale::En);
        // 查询参数优先于请求头
        assert_eq!(
            Locale::from_header_or_query(Some("zh-CN"), Some("en-US")),
            Locale::En
        );
        // 不支持的语言回退到默认 En
        assert_eq!(
            Locale::from_header_or_query(Some("fr-FR,fr;q=0.9"), None),
            Locale::En
        );
        // q 权重：en 权重更高时不应因为 zh 出现在前面而误选 zh
        assert_eq!(
            Locale::from_header_or_query(Some("zh-CN;q=0.1,en-US;q=0.9"), None),
            Locale::En
        );
        // q=0 表示客户端拒绝该语言
        assert_eq!(
            Locale::from_header_or_query(Some("zh-CN;q=0,en-US;q=0.8"), None),
            Locale::En
        );
        // 查询参数为裸语言标记（不强制要求 lang= 前缀）
        assert_eq!(
            Locale::from_header_or_query(None, Some("zh-cn")),
            Locale::Zh
        );
    }

    #[test]
    fn test_action_placeholders_present() {
        for locale in [Locale::Zh, Locale::En] {
            for key in ["action.proxy_prefix", "action.chain_prefix"] {
                assert!(
                    t(locale, key).contains("{}"),
                    "missing placeholder for {key}"
                );
            }
        }
    }

    #[test]
    fn test_translation_keys() {
        assert_eq!(t(Locale::Zh, "error.missing_conn_id"), "缺少连接 ID");
        assert_eq!(
            t(Locale::En, "error.missing_conn_id"),
            "Connection ID is required"
        );
        assert_eq!(t(Locale::Zh, "status.ok"), "运行正常");
        assert_eq!(t(Locale::En, "status.ok"), "Operational");

        for key in [
            "error.transparent_unavailable",
            "error.invalid_transparent_body",
            "error.transparent_invalid_dll_path",
            "error.transparent_requires_admin",
            "error.transparent_missing_driver",
            "error.transparent_uac_cancelled",
            "error.transparent_already_elevated",
            "error.transparent_elevate_in_progress",
            "error.transparent_low_integrity",
            "error.transparent_elevate_failed",
            "error.transparent_start_failed",
            "error.server_shutting_down",
        ] {
            assert_ne!(t(Locale::Zh, key), "未知错误", "missing zh key: {key}");
            assert_ne!(t(Locale::En, key), "Unknown error", "missing en key: {key}");
        }
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

    #[test]
    fn test_accept_language_q_validation_and_from_env_precedence() {
        // Out-of-range / NaN / Inf / non-numeric q values must be ignored cleanly
        assert_eq!(
            Locale::from_header_or_query(Some("zh-CN;q=NaN, en-US;q=0.5"), None),
            Locale::En
        );
        assert_eq!(
            Locale::from_header_or_query(Some("zh-CN;q=inf, en-US;q=0.4"), None),
            Locale::En
        );
        assert_eq!(
            Locale::from_header_or_query(Some("zh-CN;q=1.5, en-US;q=0.4"), None),
            Locale::En
        );
        assert_eq!(
            Locale::from_header_or_query(Some("zh-CN;q=-0.2, en-US;q=0.3"), None),
            Locale::En
        );
        assert_eq!(
            Locale::from_header_or_query(Some("en-US;q=bad, zh-CN;q=0.8"), None),
            Locale::Zh
        );
        assert_eq!(
            Locale::from_header_or_query(Some("zh-CN;q=1.0, en-US;q=0.8"), None),
            Locale::Zh
        );

        // Env precedence: FLOWX_LANG -> LC_ALL -> LC_MESSAGES -> LANG -> En
        assert_eq!(
            Locale::from_env_lookup(|k| match k {
                "FLOWX_LANG" => Some("zh-CN".into()),
                "LC_ALL" => Some("en_US.UTF-8".into()),
                _ => None,
            }),
            Locale::Zh
        );
        assert_eq!(
            Locale::from_env_lookup(|k| match k {
                "FLOWX_LANG" => Some("  ".into()),
                "LC_ALL" => Some("C.UTF-8".into()),
                "LANG" => Some("zh_CN.UTF-8".into()),
                _ => None,
            }),
            Locale::En
        );
        assert_eq!(
            Locale::from_env_lookup(|k| match k {
                "LC_MESSAGES" => Some("zh_TW.UTF-8".into()),
                "LANG" => Some("en_US.UTF-8".into()),
                _ => None,
            }),
            Locale::Zh
        );
        assert_eq!(Locale::from_env_lookup(|_| None), Locale::En);
        assert_eq!(Locale::Zh.accept_language_header(), "zh-CN");
        assert_eq!(Locale::En.accept_language_header(), "en-US");
    }
}
