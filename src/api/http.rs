use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::i18n::Locale;

pub(super) const API_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_SIZE: usize = 1024 * 1024; // 1MB 上限防 DoS

pub(super) async fn read_full_http_request(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
) -> std::result::Result<(), RequestReadError> {
    read_full_http_request_with_timeout(stream, buffer, API_TIMEOUT).await
}

pub(super) async fn read_full_http_request_with_timeout(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    timeout: Duration,
) -> std::result::Result<(), RequestReadError> {
    let read_fut = async {
        buffer.clear();
        let mut temp = [0u8; 2048];
        let mut expected_total: Option<usize> = None;
        let mut scanned_len = 0usize;

        loop {
            let n = match stream.read(&mut temp).await {
                Ok(n) => n,
                Err(e) => {
                    // 客户端提前断开等读错误较常见，保留原始错误到 debug 日志，对外只返回本地化文案
                    tracing::debug!("[API] HTTP request read failed: {}", e);
                    return Err(RequestReadError::Io);
                }
            };
            if n == 0 {
                if buffer.is_empty() {
                    return Ok(());
                }
                return Err(RequestReadError::IncompleteHeaders);
            }
            buffer.extend_from_slice(&temp[..n]);
            if buffer.len() > MAX_REQUEST_SIZE {
                return Err(RequestReadError::TooLarge);
            }

            if expected_total.is_none() {
                if let Some(header_end) = crate::outbound::find_http_header_end(buffer, scanned_len)
                {
                    let content_length = validate_and_parse_headers(&buffer[..header_end - 4])?;
                    let total_needed = header_end
                        .checked_add(content_length)
                        .filter(|&t| t <= MAX_REQUEST_SIZE)
                        .ok_or(RequestReadError::TooLarge)?;
                    expected_total = Some(total_needed);
                }
                scanned_len = buffer.len();
            }

            if let Some(total_needed) = expected_total
                && buffer.len() >= total_needed
            {
                buffer.truncate(total_needed);
                break;
            }
        }

        Ok(())
    };

    tokio::time::timeout(timeout, read_fut)
        .await
        .map_err(|_| RequestReadError::TimedOut)?
}

/// HTTP 请求读取阶段的可分类错误，用于生成本地化且机器可读的错误响应。
#[derive(Debug)]
pub(super) enum RequestReadError {
    /// 请求体（含头部）超过 1MB 上限
    TooLarge,
    /// 请求头不完整、含早期 EOF 或缺少 \r\n\r\n
    IncompleteHeaders,
    /// 请求头包含非 UTF-8 字节
    NonUtf8Headers,
    /// HTTP 换行、obs-fold 或字段名不合法
    InvalidFraming,
    /// 不支持 Transfer-Encoding 请求传输编码
    UnsupportedTransferEncoding,
    /// 敏感请求头重复（Host / Content-Length / Origin / Referer / Sec-Fetch-Site / Content-Type）
    DuplicateHeader,
    /// `Content-Length` 请求头格式非法
    InvalidContentLength,
    /// 请求读取阶段超时
    TimedOut,
    /// 底层套接字读取失败（原始错误已记入 debug 日志）
    Io,
}

impl RequestReadError {
    pub(super) fn http_status(&self) -> &'static str {
        match self {
            RequestReadError::TooLarge => "413 Payload Too Large",
            RequestReadError::UnsupportedTransferEncoding => "501 Not Implemented",
            RequestReadError::TimedOut => "408 Request Timeout",
            _ => "400 Bad Request",
        }
    }

    /// 返回（错误码, i18n 键）
    pub(super) fn code_and_key(&self) -> (&'static str, &'static str) {
        match self {
            RequestReadError::TooLarge => ("ERR_REQUEST_TOO_LARGE", "error.request_too_large"),
            RequestReadError::IncompleteHeaders => {
                ("ERR_INCOMPLETE_HEADERS", "error.incomplete_headers")
            }
            RequestReadError::NonUtf8Headers => ("ERR_NON_UTF8_HEADERS", "error.non_utf8_headers"),
            RequestReadError::InvalidFraming => (
                "ERR_INVALID_REQUEST_FRAMING",
                "error.invalid_request_framing",
            ),
            RequestReadError::UnsupportedTransferEncoding => {
                ("ERR_UNSUPPORTED_TE", "error.unsupported_transfer_encoding")
            }
            RequestReadError::DuplicateHeader => ("ERR_DUPLICATE_HEADER", "error.duplicate_header"),
            RequestReadError::InvalidContentLength => {
                ("ERR_INVALID_CONTENT_LENGTH", "error.invalid_content_length")
            }
            RequestReadError::TimedOut => ("ERR_REQUEST_TIMEOUT", "error.request_timeout"),
            RequestReadError::Io => ("ERR_REQUEST_READ_FAILED", "error.request_read_failed"),
        }
    }
}

pub(super) fn is_http_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// 严格校验原始请求头：拒绝 NUL、裸 CR/LF、obs-fold、畸形字段名、Transfer-Encoding 与重复敏感头，并解析 Content-Length。
pub(super) fn validate_and_parse_headers(
    raw_head: &[u8],
) -> std::result::Result<usize, RequestReadError> {
    if raw_head.contains(&0) {
        return Err(RequestReadError::InvalidFraming);
    }

    let mut lines = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < raw_head.len() {
        if raw_head[i] == b'\n' {
            return Err(RequestReadError::InvalidFraming);
        }
        if raw_head[i] == b'\r' {
            if i + 1 >= raw_head.len() || raw_head[i + 1] != b'\n' {
                return Err(RequestReadError::InvalidFraming);
            }
            lines.push(&raw_head[start..i]);
            i += 2;
            start = i;
            continue;
        }
        i += 1;
    }
    lines.push(&raw_head[start..]);

    if lines.is_empty() || lines[0].is_empty() {
        return Err(RequestReadError::InvalidFraming);
    }
    if std::str::from_utf8(lines[0]).is_err() {
        return Err(RequestReadError::NonUtf8Headers);
    }

    let mut content_length: Option<usize> = None;
    let mut host_seen = false;
    let mut origin_seen = false;
    let mut referer_seen = false;
    let mut fetch_site_seen = false;
    let mut content_type_seen = false;

    for line in &lines[1..] {
        if line.is_empty() || line[0] == b' ' || line[0] == b'\t' {
            return Err(RequestReadError::InvalidFraming);
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return Err(RequestReadError::InvalidFraming);
        };
        let name = &line[..colon];
        if name.is_empty() || !name.iter().all(|&b| is_http_token_byte(b)) {
            return Err(RequestReadError::InvalidFraming);
        }
        let val_bytes = &line[colon + 1..];
        if val_bytes
            .iter()
            .any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f)
        {
            return Err(RequestReadError::InvalidFraming);
        }
        let Ok(val) = std::str::from_utf8(val_bytes) else {
            return Err(RequestReadError::NonUtf8Headers);
        };

        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err(RequestReadError::UnsupportedTransferEncoding);
        } else if name.eq_ignore_ascii_case(b"content-length") {
            if content_length.is_some() {
                return Err(RequestReadError::DuplicateHeader);
            }
            let trimmed = val.trim_matches(|c| c == ' ' || c == '\t');
            if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
                return Err(RequestReadError::InvalidContentLength);
            }
            let parsed = trimmed
                .parse::<usize>()
                .map_err(|_| RequestReadError::InvalidContentLength)?;
            content_length = Some(parsed);
        } else if name.eq_ignore_ascii_case(b"host") {
            if host_seen {
                return Err(RequestReadError::DuplicateHeader);
            }
            host_seen = true;
        } else if name.eq_ignore_ascii_case(b"origin") {
            if origin_seen {
                return Err(RequestReadError::DuplicateHeader);
            }
            origin_seen = true;
        } else if name.eq_ignore_ascii_case(b"referer") {
            if referer_seen {
                return Err(RequestReadError::DuplicateHeader);
            }
            referer_seen = true;
        } else if name.eq_ignore_ascii_case(b"sec-fetch-site") {
            if fetch_site_seen {
                return Err(RequestReadError::DuplicateHeader);
            }
            fetch_site_seen = true;
        } else if name.eq_ignore_ascii_case(b"content-type") {
            if content_type_seen {
                return Err(RequestReadError::DuplicateHeader);
            }
            content_type_seen = true;
        }
    }

    Ok(content_length.unwrap_or(0))
}

pub(super) fn has_json_content_type(headers: &[&str]) -> bool {
    extract_header(headers, "content-type").is_some_and(|ct| {
        ct.split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/json")
    })
}

/// 在请求头尚未完整解析（或包含非 UTF-8 字节）时，尽力从已读到的字节中提取语言偏好，
/// 避免 zh 用户在最早期错误上只能拿到英文。
pub(super) fn best_effort_locale(buffer: &[u8]) -> Locale {
    let text = String::from_utf8_lossy(buffer);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let query = request_line
        .split_whitespace()
        .nth(1)
        .and_then(|target| target.split_once('?'))
        .map(|(_, q)| q)
        .unwrap_or("");
    let mut accept_language = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("accept-language")
        {
            accept_language = Some(value.trim());
        }
    }
    Locale::from_header_or_query(accept_language, parse_query_param(query, "lang"))
}

pub(super) fn extract_header<'a>(headers: &[&'a str], target_name: &str) -> Option<&'a str> {
    for line in headers {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case(target_name)
        {
            return Some(v.trim());
        }
    }
    None
}

/// 校验 Host 请求头是否为本地回环地址（防止 DNS Rebinding 攻击）
pub(super) fn is_allowed_host(
    host_header: &str,
    expected_port: u16,
    require_exact_port: bool,
) -> bool {
    let trimmed = host_header.trim();
    if trimmed.is_empty() {
        return false;
    }

    let (host, port_opt) = if let Some(rest) = trimmed.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return false;
        };
        let host = &trimmed[..=end + 1]; // 保留 "[::1]"
        let after = &rest[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => match p.parse::<u16>() {
                Ok(n) => Some(n),
                Err(_) => return false,
            },
            None if after.is_empty() => None,
            None => return false,
        };
        (host, port)
    } else if let Some((h, p)) = trimmed.rsplit_once(':') {
        let Ok(n) = p.parse::<u16>() else {
            return false;
        };
        (h, Some(n))
    } else {
        (trimmed, None)
    };

    let is_loopback_name = host.eq_ignore_ascii_case("127.0.0.1")
        || host.eq_ignore_ascii_case("localhost")
        || host == "[::1]";
    if !is_loopback_name {
        return false;
    }

    match port_opt {
        Some(p) => p == expected_port,
        None => !require_exact_port || expected_port == 80,
    }
}

/// 校验 Origin / Referer 是否来自当前控制台同源（防止 CSRF 与跨站脚本调用本地 API）
pub(super) fn is_allowed_origin(origin: &str, expected_port: u16) -> bool {
    let trimmed = origin.trim().trim_end_matches('/');
    let Some(rest) = strip_prefix_ignore_case(trimmed, "http://") else {
        return false;
    };
    is_allowed_host(rest, expected_port, true)
}

pub(super) fn is_allowed_referer(referer: &str, expected_port: u16) -> bool {
    let trimmed = referer.trim();
    let Some(rest) = strip_prefix_ignore_case(trimmed, "http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    is_allowed_host(authority, expected_port, true)
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

pub(super) fn parse_query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for part in query.split('&') {
        if let Some((k, v)) = part.split_once('=')
            && k == key
        {
            return Some(v);
        }
    }
    None
}

pub(super) async fn send_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {}\r\n\
Content-Type: {}\r\n\
X-Content-Type-Options: nosniff\r\n\
X-Frame-Options: DENY\r\n\
Content-Security-Policy: frame-ancestors 'none'\r\n\
Cache-Control: no-store\r\n\
Content-Length: {}\r\n\
Connection: close\r\n\
\r\n\
{}",
        status,
        content_type,
        body.len(),
        body
    );
    match tokio::time::timeout(API_TIMEOUT, async {
        stream.write_all(response.as_bytes()).await?;
        stream.flush().await
    })
    .await
    {
        Ok(res) => res,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "HTTP response write timed out",
        )),
    }
}
