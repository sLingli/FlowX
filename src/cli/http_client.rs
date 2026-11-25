use std::io::Write;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::cli::args::GlobalCliOpts;
use crate::i18n::Locale;

pub(super) const API_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
pub(super) const API_IO_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const API_ELEVATE_IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CLI_HTTP_HEADER_BYTES: usize = 64 * 1024;
const MAX_CLI_HTTP_BODY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct SilentExitError {
    pub(super) code: i32,
}

impl std::fmt::Display for SilentExitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Command exited with status {}", self.code)
    }
}

impl std::error::Error for SilentExitError {}

#[derive(Debug)]
pub(super) enum ApiTransportError {
    ConnectionRefused(String),
    Other(anyhow::Error),
}

pub(super) async fn api_request_raw(
    api_addr: &str,
    locale: Locale,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> std::result::Result<(u16, Value), ApiTransportError> {
    api_request_raw_with_timeouts(
        api_addr,
        locale,
        method,
        path,
        body,
        API_CONNECT_TIMEOUT,
        API_IO_TIMEOUT,
    )
    .await
}

struct ResponseCursor<'a> {
    stream: &'a mut TcpStream,
    buf: Vec<u8>,
    pos: usize,
}

impl<'a> ResponseCursor<'a> {
    fn new(stream: &'a mut TcpStream) -> Self {
        Self {
            stream,
            buf: Vec::new(),
            pos: 0,
        }
    }

    fn unread(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn compact_if_needed(&mut self) {
        if self.pos >= 4096 || (self.pos > 0 && self.pos == self.buf.len()) {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    async fn read_headers(&mut self, max_header: usize, api_addr: &str) -> Result<Vec<u8>> {
        let mut tmp = [0u8; 4096];
        let mut scanned_len = 0usize;
        loop {
            if let Some(end) = crate::outbound::find_http_header_end(&self.buf, scanned_len) {
                if end > max_header {
                    bail!(
                        "HTTP response headers from {} exceed {} bytes limit",
                        api_addr,
                        max_header
                    );
                }
                self.pos = end;
                return Ok(self.buf[..end - 4].to_vec());
            }
            scanned_len = self.buf.len();
            if self.buf.len() >= max_header {
                bail!(
                    "HTTP response headers from {} exceed {} bytes limit",
                    api_addr,
                    max_header
                );
            }
            let max_add = (max_header - self.buf.len()).min(tmp.len());
            let n = self.stream.read(&mut tmp[..max_add]).await?;
            if n == 0 {
                bail!(
                    "Invalid HTTP response from {} (missing header terminator)",
                    api_addr
                );
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
    }

    async fn read_line_crlf(&mut self, max_line: usize, api_addr: &str) -> Result<String> {
        let mut tmp = [0u8; 1024];
        loop {
            let unread = self.unread();
            if let Some(rel) = unread.windows(2).position(|w| w == b"\r\n") {
                if rel > max_line {
                    bail!(
                        "HTTP response line from {} exceeds {} bytes",
                        api_addr,
                        max_line
                    );
                }
                let line_bytes = unread[..rel].to_vec();
                self.pos += rel + 2;
                self.compact_if_needed();
                return String::from_utf8(line_bytes).map_err(|_| {
                    anyhow!(
                        "Non-UTF-8 chunk/trailer line in HTTP response from {}",
                        api_addr
                    )
                });
            }
            if unread.len() > max_line + 2 {
                bail!(
                    "HTTP response line from {} exceeds {} bytes",
                    api_addr,
                    max_line
                );
            }
            self.compact_if_needed();
            let remain_cap = ((max_line + 2) - self.unread().len()).min(tmp.len());
            let n = self.stream.read(&mut tmp[..remain_cap]).await?;
            if n == 0 {
                bail!(
                    "Unexpected EOF while reading chunked framing from {}",
                    api_addr
                );
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
    }

    async fn read_exact_into(
        &mut self,
        out: &mut Vec<u8>,
        expected_len: usize,
        api_addr: &str,
    ) -> Result<()> {
        let mut rem = expected_len;
        let mut tmp = [0u8; 8192];
        while rem > 0 {
            let unread = self.unread();
            if !unread.is_empty() {
                let take = rem.min(unread.len());
                out.extend_from_slice(&unread[..take]);
                self.pos += take;
                self.compact_if_needed();
                rem -= take;
                continue;
            }
            self.buf.clear();
            self.pos = 0;
            let to_read = rem.min(tmp.len());
            let n = self.stream.read(&mut tmp[..to_read]).await?;
            if n == 0 {
                bail!(
                    "Truncated HTTP response from {} (expected {} bytes, got {})",
                    api_addr,
                    expected_len,
                    expected_len - rem
                );
            }
            out.extend_from_slice(&tmp[..n]);
            rem -= n;
        }
        Ok(())
    }

    async fn read_to_eof_bounded(&mut self, max_body: usize, api_addr: &str) -> Result<Vec<u8>> {
        let unread_len = self.unread().len();
        if unread_len > max_body {
            bail!(
                "HTTP response body from {} exceeds {} bytes limit",
                api_addr,
                max_body
            );
        }
        let mut body = Vec::with_capacity(unread_len);
        body.extend_from_slice(self.unread());
        self.buf.clear();
        self.pos = 0;

        let mut tmp = [0u8; 8192];
        loop {
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            if body.len().saturating_add(n) > max_body {
                bail!(
                    "HTTP response body from {} exceeds {} bytes limit",
                    api_addr,
                    max_body
                );
            }
            body.extend_from_slice(&tmp[..n]);
        }
        Ok(body)
    }

    async fn read_chunked_bounded(
        &mut self,
        max_header: usize,
        max_body: usize,
        api_addr: &str,
    ) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        loop {
            let size_line = self.read_line_crlf(4096, api_addr).await?;
            let size_part = size_line
                .split(';')
                .next()
                .unwrap_or("")
                .trim_matches(|c| c == ' ' || c == '\t');
            if size_part.is_empty()
                || size_part.len() > 16
                || !size_part.bytes().all(|b| b.is_ascii_hexdigit())
            {
                bail!("Invalid HTTP chunk size '{}' from {}", size_line, api_addr);
            }
            let chunk_size = usize::from_str_radix(size_part, 16).map_err(|_| {
                anyhow!(
                    "Overflow parsing HTTP chunk size '{}' from {}",
                    size_part,
                    api_addr
                )
            })?;
            if chunk_size == 0 {
                let mut trailer_bytes = 0usize;
                loop {
                    let trailer = self.read_line_crlf(4096, api_addr).await?;
                    if trailer.is_empty() {
                        break;
                    }
                    trailer_bytes = trailer_bytes.saturating_add(trailer.len() + 2);
                    if trailer_bytes > max_header {
                        bail!(
                            "HTTP chunked trailers from {} exceed {} bytes limit",
                            api_addr,
                            max_header
                        );
                    }
                }
                break;
            }
            if chunk_size > max_body.saturating_sub(body.len()) {
                bail!(
                    "Chunked HTTP response body from {} exceeds {} bytes limit",
                    api_addr,
                    max_body
                );
            }
            self.read_exact_into(&mut body, chunk_size, api_addr)
                .await?;
            let mut crlf = Vec::with_capacity(2);
            self.read_exact_into(&mut crlf, 2, api_addr).await?;
            if crlf != b"\r\n" {
                bail!("Invalid HTTP chunk terminator from {}", api_addr);
            }
        }
        Ok(body)
    }
}

pub(super) async fn api_request_raw_with_timeouts(
    api_addr: &str,
    locale: Locale,
    method: &str,
    path: &str,
    body: Option<&Value>,
    connect_timeout: Duration,
    io_timeout: Duration,
) -> std::result::Result<(u16, Value), ApiTransportError> {
    let mut stream = match tokio::time::timeout(connect_timeout, TcpStream::connect(api_addr)).await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            return Err(ApiTransportError::ConnectionRefused(format!(
                "Connection refused by FlowX API at {}",
                api_addr
            )));
        }
        Ok(Err(e)) => {
            return Err(ApiTransportError::Other(anyhow!(
                "Failed to connect to FlowX API at {}: {}",
                api_addr,
                e
            )));
        }
        Err(_) => {
            return Err(ApiTransportError::Other(anyhow!(
                "Timed out connecting to FlowX API at {} after {}ms",
                api_addr,
                connect_timeout.as_millis()
            )));
        }
    };

    let accept_lang = locale.accept_language_header();
    let body_str = body.map(|b| b.to_string()).unwrap_or_default();
    let req = if body.is_some() {
        format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nAccept-Language: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            method,
            path,
            api_addr,
            accept_lang,
            body_str.len(),
            body_str
        )
    } else {
        format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nAccept-Language: {}\r\nConnection: close\r\n\r\n",
            method, path, api_addr, accept_lang
        )
    };

    let io_res = tokio::time::timeout(io_timeout, async {
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(anyhow::Error::from)?;
        let mut cursor = ResponseCursor::new(&mut stream);
        let header_bytes = cursor
            .read_headers(MAX_CLI_HTTP_HEADER_BYTES, api_addr)
            .await?;

        let header_str = std::str::from_utf8(&header_bytes)
            .map_err(|_| anyhow!("Non-UTF-8 HTTP response headers from {}", api_addr))?;
        let mut lines = header_str.split("\r\n");
        let status_line = lines.next().unwrap_or_default();
        let status_rest = status_line
            .strip_prefix("HTTP/1.1 ")
            .or_else(|| status_line.strip_prefix("HTTP/1.0 "))
            .ok_or_else(|| {
                anyhow!(
                    "Invalid HTTP status line from {}: '{}'",
                    api_addr,
                    status_line
                )
            })?;
        let code_token = status_rest.split_whitespace().next().unwrap_or_default();
        if code_token.len() != 3 || !code_token.bytes().all(|b| b.is_ascii_digit()) {
            bail!(
                "Invalid HTTP status code from {}: '{}'",
                api_addr,
                status_line
            );
        }
        let status_code: u16 = code_token.parse().map_err(|_| {
            anyhow!(
                "Unparseable HTTP status code from {}: '{}'",
                api_addr,
                code_token
            )
        })?;

        let mut content_length: Option<usize> = None;
        let mut transfer_codings: Vec<String> = Vec::new();
        for line in lines {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let key = k.trim();
            if key.eq_ignore_ascii_case("content-length") {
                let trimmed_v = v.trim();
                if trimmed_v.is_empty() || !trimmed_v.bytes().all(|b| b.is_ascii_digit()) {
                    bail!(
                        "Invalid Content-Length header '{}' from {}",
                        trimmed_v,
                        api_addr
                    );
                }
                let parsed = trimmed_v.parse::<usize>().map_err(|_| {
                    anyhow!(
                        "Invalid Content-Length value '{}' from {}",
                        trimmed_v,
                        api_addr
                    )
                })?;
                if parsed > MAX_CLI_HTTP_BODY_BYTES {
                    bail!(
                        "HTTP response Content-Length ({}) from {} exceeds {} bytes limit",
                        parsed,
                        api_addr,
                        MAX_CLI_HTTP_BODY_BYTES
                    );
                }
                if let Some(prev) = content_length
                    && prev != parsed
                {
                    bail!("Conflicting Content-Length headers from {}", api_addr);
                }
                content_length = Some(parsed);
            } else if key.eq_ignore_ascii_case("transfer-encoding") {
                for token in v.split(',') {
                    let coding = token.trim().to_ascii_lowercase();
                    if !coding.is_empty() {
                        transfer_codings.push(coding);
                    }
                }
            }
        }

        let transfer_chunked = if transfer_codings.is_empty() {
            false
        } else if transfer_codings.len() == 1 && transfer_codings[0] == "chunked" {
            true
        } else {
            bail!(
                "Unsupported Transfer-Encoding '{:?}' from {}",
                transfer_codings,
                api_addr
            );
        };

        if content_length.is_some() && transfer_chunked {
            bail!(
                "HTTP response from {} contains conflicting Content-Length and Transfer-Encoding headers",
                api_addr
            );
        }

        let body_bytes = if transfer_chunked {
            cursor
                .read_chunked_bounded(MAX_CLI_HTTP_HEADER_BYTES, MAX_CLI_HTTP_BODY_BYTES, api_addr)
                .await?
        } else if let Some(expected_len) = content_length {
            let mut out = Vec::with_capacity(expected_len);
            cursor
                .read_exact_into(&mut out, expected_len, api_addr)
                .await?;
            if !cursor.unread().is_empty() {
                bail!(
                    "Unexpected trailing bytes in HTTP response from {} (expected {} bytes)",
                    api_addr,
                    expected_len
                );
            }
            out
        } else {
            cursor
                .read_to_eof_bounded(MAX_CLI_HTTP_BODY_BYTES, api_addr)
                .await?
        };

        Ok::<(u16, Vec<u8>), anyhow::Error>((status_code, body_bytes))
    })
    .await;

    let (status_code, body_bytes) = match io_res {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => return Err(ApiTransportError::Other(e)),
        Err(_) => {
            return Err(ApiTransportError::Other(anyhow!(
                "Timed out waiting for HTTP response from FlowX API at {} after {}ms",
                api_addr,
                io_timeout.as_millis()
            )));
        }
    };

    let body_text = std::str::from_utf8(&body_bytes).map_err(|_| {
        ApiTransportError::Other(anyhow!(
            "Response body from {} is not valid UTF-8",
            api_addr
        ))
    })?;
    let json_val = if body_text.trim().is_empty() {
        if (200..300).contains(&status_code) {
            return Err(ApiTransportError::Other(anyhow!(
                "Empty HTTP {} JSON response body from {}",
                status_code,
                api_addr
            )));
        }
        Value::Null
    } else {
        match serde_json::from_str::<Value>(body_text) {
            Ok(v) => v,
            Err(e) => {
                if (200..300).contains(&status_code) {
                    return Err(ApiTransportError::Other(anyhow!(
                        "Invalid JSON response body from {}: {}",
                        api_addr,
                        e
                    )));
                }
                json!({ "raw": body_text.trim() })
            }
        }
    };

    Ok((status_code, json_val))
}

pub(super) async fn api_request_strict_with_io_timeout(
    api_addr: &str,
    locale: Locale,
    method: &str,
    path: &str,
    body: Option<&Value>,
    io_timeout: Duration,
) -> Result<(u16, Value)> {
    match api_request_raw_with_timeouts(
        api_addr,
        locale,
        method,
        path,
        body,
        API_CONNECT_TIMEOUT,
        io_timeout,
    )
    .await
    {
        Ok(res) => Ok(res),
        Err(ApiTransportError::ConnectionRefused(msg)) => Err(anyhow!("{}", msg)),
        Err(ApiTransportError::Other(e)) => Err(e),
    }
}

pub(super) async fn api_request_strict(
    api_addr: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<(u16, Value)> {
    api_request_strict_with_io_timeout(
        api_addr,
        Locale::from_env(),
        method,
        path,
        body,
        API_IO_TIMEOUT,
    )
    .await
}

pub(super) async fn api_request_or_offline(
    opts: &GlobalCliOpts,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<Option<(u16, Value)>> {
    if opts.offline {
        return Ok(None);
    }
    match api_request_raw(&opts.api_addr, opts.locale, method, path, body).await {
        Ok(res) => Ok(Some(res)),
        Err(ApiTransportError::ConnectionRefused(_)) if !opts.api_explicit => Ok(None),
        Err(ApiTransportError::ConnectionRefused(msg)) => {
            bail!(
                "{} (explicit --api / $FLOWX_API target refused connection; pass --offline to edit local XML directly)",
                msg
            );
        }
        Err(ApiTransportError::Other(e)) => Err(e),
    }
}

#[derive(Debug)]
pub struct ApiHttpError {
    pub status: u16,
    pub code: Option<String>,
    pub error: String,
    pub body: Value,
    pub offline: bool,
}

impl ApiHttpError {
    pub(super) fn from_value(status: u16, val: Value, offline: bool) -> Self {
        let code = val
            .get("code")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let error = val
            .get("error")
            .and_then(|v| v.as_str())
            .or_else(|| val.get("raw").and_then(|v| v.as_str()))
            .unwrap_or("API request failed")
            .to_string();
        Self {
            status,
            code,
            error,
            body: val,
            offline,
        }
    }
}

impl std::fmt::Display for ApiHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.offline {
            write!(f, "{}", self.error)
        } else {
            write!(f, "{} (HTTP {})", self.error, self.status)
        }
    }
}

impl std::error::Error for ApiHttpError {}

pub fn format_cli_error_json(err: &anyhow::Error) -> Value {
    if let Some(api_err) = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<ApiHttpError>())
    {
        let mut obj = match api_err.body.as_object() {
            Some(map) => map.clone(),
            None => serde_json::Map::new(),
        };
        obj.insert("ok".to_string(), Value::Bool(false));
        obj.insert(
            "code".to_string(),
            Value::String(
                api_err
                    .code
                    .clone()
                    .unwrap_or_else(|| format!("ERR_HTTP_{}", api_err.status)),
            ),
        );
        obj.insert("error".to_string(), Value::String(api_err.error.clone()));
        obj.insert(
            "status".to_string(),
            Value::Number(serde_json::Number::from(api_err.status)),
        );
        Value::Object(obj)
    } else {
        json!({
            "ok": false,
            "code": "ERR_CLI_ERROR",
            "error": format!("{:#}", err),
        })
    }
}

pub fn emit_cli_error_and_exit(err: &anyhow::Error, json_output: bool) -> ! {
    if let Some(silent) = err.downcast_ref::<SilentExitError>() {
        std::process::exit(silent.code);
    }
    if json_output {
        let payload = format_cli_error_json(err);
        if let Ok(s) = serde_json::to_string_pretty(&payload) {
            println!("{}", s);
        } else {
            println!(
                "{{\"ok\":false,\"code\":\"ERR_CLI_ERROR\",\"error\":\"Failed to serialize error\"}}"
            );
        }
        let _ = std::io::stdout().flush();
    } else {
        eprintln!("Error: {:?}", err);
        let _ = std::io::stderr().flush();
    }
    std::process::exit(1);
}

pub(super) fn ensure_api_ok(status: u16, val: Value) -> Result<Value> {
    if (200..300).contains(&status) {
        Ok(val)
    } else {
        Err(anyhow::Error::new(ApiHttpError::from_value(
            status, val, false,
        )))
    }
}
