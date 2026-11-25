use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::monitor::ActiveConnection;

use super::relay::{await_relay_with_watchdog, record_activity_us};
use super::RelayStream;

/// Trim HTTP optional whitespace (`SP` and `HTAB`, per RFC 9110) without stripping Unicode whitespace.
pub(crate) fn trim_http_ows(s: &str) -> &str {
    s.trim_matches(|c| c == ' ' || c == '\t')
}

/// Incrementally locate the end offset (right after `\r\n\r\n`) of an HTTP header block.
/// Scans from `scanned_len.saturating_sub(3)` so repeated calls across chunked reads stay O(N).
pub(crate) fn find_http_header_end(buf: &[u8], scanned_len: usize) -> Option<usize> {
    let start = scanned_len.min(buf.len()).saturating_sub(3);
    buf[start..]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|rel| start + rel + 4)
}

/// 预读前缀 + 底层的顺序流读取器，用于精确消费 HTTP 请求/响应体边界而绝不溢出到后续流水线报文
struct PrefixedTcpReader<R> {
    buf: Vec<u8>,
    pos: usize,
    inner: R,
}

impl<R: AsyncRead + Unpin> PrefixedTcpReader<R> {
    fn new(prefix: Vec<u8>, inner: R) -> Self {
        Self {
            buf: prefix,
            pos: 0,
            inner,
        }
    }

    async fn fill(&mut self) -> std::io::Result<usize> {
        if self.pos < self.buf.len() {
            return Ok(self.buf.len() - self.pos);
        }
        self.buf.clear();
        self.pos = 0;
        if self.buf.capacity() < 16384 {
            self.buf.reserve(16384 - self.buf.capacity());
        }
        self.inner.read_buf(&mut self.buf).await
    }

    async fn read_byte(&mut self) -> std::io::Result<Option<u8>> {
        if self.fill().await? == 0 {
            return Ok(None);
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(Some(b))
    }

    async fn read_exact_bytes(&mut self, dst: &mut [u8]) -> std::io::Result<()> {
        let mut written = 0usize;
        while written < dst.len() {
            let n = self.fill().await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF while reading framed HTTP body",
                ));
            }
            let take = n.min(dst.len() - written);
            dst[written..written + take].copy_from_slice(&self.buf[self.pos..self.pos + take]);
            self.pos += take;
            written += take;
        }
        Ok(())
    }

    /// 读取一行 CRLF 结尾内容（返回不含 `\r\n` 的内容），拒绝裸 `\n` 与 NUL 字节
    async fn read_crlf_line(&mut self, max_len: usize) -> std::io::Result<Vec<u8>> {
        let mut line = Vec::new();
        loop {
            let Some(b) = self.read_byte().await? else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF while reading HTTP chunk line",
                ));
            };
            if b == b'\0' {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "NUL byte not allowed in HTTP chunked framing",
                ));
            }
            if b == b'\n' {
                if !line.ends_with(b"\r") {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Bare LF line ending not allowed in HTTP chunked framing",
                    ));
                }
                line.pop();
                return Ok(line);
            }
            if line.len() >= max_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP chunked line exceeds maximum allowed length",
                ));
            }
            line.push(b);
        }
    }

    /// 读取以 `\r\n\r\n` 结束的 HTTP 头部块（不包含末尾 `\r\n\r\n`），严格受限于 `max_bytes`
    /// 若在首字节前即遇到 clean EOF，则返回 `Ok(None)`
    async fn read_http_header_block(&mut self, max_bytes: usize) -> std::io::Result<Option<Vec<u8>>> {
        let mut tmp = [0u8; 4096];
        let mut scanned_len = 0usize;
        loop {
            let unconsumed = &self.buf[self.pos..];
            if let Some(end) = find_http_header_end(unconsumed, scanned_len) {
                if end > max_bytes {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "HTTP response headers exceed maximum allowed size",
                    ));
                }
                let head = unconsumed[..end - 4].to_vec();
                self.pos += end;
                return Ok(Some(head));
            }
            scanned_len = unconsumed.len();
            if self.pos > 0 {
                self.buf.drain(..self.pos);
                self.pos = 0;
            }
            if self.buf.len() >= max_bytes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP response headers exceed maximum allowed size",
                ));
            }
            let cap = (max_bytes - self.buf.len()).min(tmp.len());
            let n = self.inner.read(&mut tmp[..cap]).await?;
            if n == 0 {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF before HTTP response headers terminated",
                ));
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayDirection {
    Upload,
    Download,
}

enum BodyRelayError {
    PeerWriteClosed(std::io::Error),
    Fatal(std::io::Error),
}

impl BodyRelayError {
    fn into_io_error(self) -> std::io::Error {
        match self {
            BodyRelayError::PeerWriteClosed(e) | BodyRelayError::Fatal(e) => e,
        }
    }
}

impl From<std::io::Error> for BodyRelayError {
    fn from(e: std::io::Error) -> Self {
        Self::Fatal(e)
    }
}

/// 统一带活跃计时与全局/单连接字节计数的有界 HTTP 体写入端，同时复用在上行请求体与下行响应体路径
struct TrackedBodySink<'a, W> {
    writer: W,
    total_bytes: &'a std::sync::atomic::AtomicU64,
    conn: &'a Option<Arc<ActiveConnection>>,
    start: &'a tokio::time::Instant,
    last_activity_us: &'a Arc<std::sync::atomic::AtomicU64>,
    direction: RelayDirection,
}

impl<'a, W: AsyncWrite + Unpin> TrackedBodySink<'a, W> {
    async fn write_all(&mut self, bytes: &[u8]) -> std::result::Result<(), BodyRelayError> {
        if bytes.is_empty() {
            return Ok(());
        }
        record_activity_us(self.start, self.last_activity_us);
        self.writer.write_all(bytes).await.map_err(|e| {
            if matches!(
                e.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            ) {
                BodyRelayError::PeerWriteClosed(e)
            } else {
                BodyRelayError::Fatal(e)
            }
        })?;
        record_activity_us(self.start, self.last_activity_us);
        self.total_bytes
            .fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
        if let Some(c) = self.conn {
            match self.direction {
                RelayDirection::Upload => c.add_upload(bytes.len() as u64),
                RelayDirection::Download => c.add_download(bytes.len() as u64),
            }
        }
        Ok(())
    }
}

async fn copy_exact_body<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut PrefixedTcpReader<R>,
    sink: &mut TrackedBodySink<'_, W>,
    mut remaining: u64,
) -> std::result::Result<(), BodyRelayError> {
    while remaining > 0 {
        let avail = reader.fill().await?;
        if avail == 0 {
            return Err(BodyRelayError::Fatal(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Truncated HTTP body before reaching declared length",
            )));
        }
        let take = (avail as u64).min(remaining) as usize;
        sink.write_all(&reader.buf[reader.pos..reader.pos + take])
            .await?;
        reader.pos += take;
        remaining -= take as u64;
    }
    Ok(())
}

async fn copy_until_eof<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut PrefixedTcpReader<R>,
    sink: &mut TrackedBodySink<'_, W>,
) -> std::result::Result<(), BodyRelayError> {
    loop {
        let avail = reader.fill().await?;
        if avail == 0 {
            return Ok(());
        }
        sink.write_all(&reader.buf[reader.pos..reader.pos + avail])
            .await?;
        reader.pos += avail;
    }
}

fn parse_chunk_size_line(line: &[u8]) -> std::io::Result<u64> {
    let size_part = match line.iter().position(|&b| b == b';') {
        Some(idx) => {
            let ext = &line[idx + 1..];
            if ext.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Control character in HTTP chunk extension",
                ));
            }
            &line[..idx]
        }
        None => line,
    };
    let trimmed = {
        let mut end = size_part.len();
        while end > 0 && matches!(size_part[end - 1], b' ' | b'\t') {
            end -= 1;
        }
        &size_part[..end]
    };
    if trimmed.is_empty() || !trimmed.iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid HTTP chunk size hex digits",
        ));
    }
    let hex_str = std::str::from_utf8(trimmed).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "Non-ASCII HTTP chunk size")
    })?;
    u64::from_str_radix(hex_str, 16).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP chunk size overflows u64",
        )
    })
}

fn validate_chunk_trailer_line(line: &[u8]) -> std::io::Result<()> {
    if line.is_empty() || matches!(line[0], b' ' | b'\t') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Malformed or folded HTTP chunk trailer header",
        ));
    }
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP chunk trailer missing colon",
        ));
    };
    let name = &line[..colon];
    let val = &line[colon + 1..];
    if name.is_empty() || !name.iter().all(|&b| crate::inbound::is_http_token_byte(b)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid HTTP chunk trailer header name",
        ));
    }
    if val.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid control character in HTTP chunk trailer value",
        ));
    }
    if name.eq_ignore_ascii_case(b"host")
        || name.eq_ignore_ascii_case(b"content-length")
        || name.eq_ignore_ascii_case(b"transfer-encoding")
        || name.eq_ignore_ascii_case(b"trailer")
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Forbidden framing header in HTTP chunk trailer",
        ));
    }
    Ok(())
}

async fn forward_chunked_body<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut PrefixedTcpReader<R>,
    sink: &mut TrackedBodySink<'_, W>,
) -> std::result::Result<(), BodyRelayError> {
    const MAX_CHUNK_LINE_BYTES: usize = 8 * 1024;
    const MAX_TRAILER_BYTES: usize = 16 * 1024;

    loop {
        let size_line = reader.read_crlf_line(MAX_CHUNK_LINE_BYTES).await?;
        let chunk_size = parse_chunk_size_line(&size_line)?;
        sink.write_all(&size_line).await?;
        sink.write_all(b"\r\n").await?;

        if chunk_size == 0 {
            let mut trailer_bytes = 0usize;
            loop {
                let trailer = reader.read_crlf_line(MAX_CHUNK_LINE_BYTES).await?;
                if trailer.is_empty() {
                    sink.write_all(b"\r\n").await?;
                    return Ok(());
                }
                trailer_bytes = trailer_bytes.saturating_add(trailer.len() + 2);
                if trailer_bytes > MAX_TRAILER_BYTES {
                    return Err(BodyRelayError::Fatal(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "HTTP chunk trailers exceed size limit",
                    )));
                }
                validate_chunk_trailer_line(&trailer)?;
                sink.write_all(&trailer).await?;
                sink.write_all(b"\r\n").await?;
            }
        }

        copy_exact_body(reader, sink, chunk_size).await?;
        let mut crlf = [0u8; 2];
        reader.read_exact_bytes(&mut crlf).await?;
        if &crlf != b"\r\n" {
            return Err(BodyRelayError::Fatal(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Missing CRLF terminator after HTTP chunk payload",
            )));
        }
        sink.write_all(b"\r\n").await?;
    }
}

pub(super) enum HttpResponseFraming {
    Empty,
    ContentLength(u64),
    Chunked,
    UntilEof,
}

pub(super) enum ParsedHttpResponseHead {
    Interim(Vec<u8>),
    Final {
        rewritten_head: Vec<u8>,
        framing: HttpResponseFraming,
    },
}

pub(super) fn parse_and_rewrite_http_response_head(
    head: &[u8],
    is_head_request: bool,
) -> std::io::Result<ParsedHttpResponseHead> {
    let invalid = |msg: &'static str| std::io::Error::new(std::io::ErrorKind::InvalidData, msg);
    let lines = crate::inbound::split_crlf_lines(head)
        .ok_or_else(|| invalid("HTTP response contains invalid line endings or NUL byte"))?;
    let mut lines_iter = lines.into_iter();
    let status_line_bytes = lines_iter
        .next()
        .ok_or_else(|| invalid("Empty HTTP response status line"))?;
    let status_line = std::str::from_utf8(status_line_bytes)
        .map_err(|_| invalid("HTTP response status line is not valid UTF-8"))?;
    let after_ver = status_line
        .strip_prefix("HTTP/1.1 ")
        .or_else(|| status_line.strip_prefix("HTTP/1.0 "))
        .ok_or_else(|| invalid("Invalid HTTP response status line version"))?;
    if after_ver.len() < 3
        || !after_ver.as_bytes()[..3].iter().all(|b| b.is_ascii_digit())
        || after_ver.as_bytes().get(3).is_some_and(|&b| b != b' ')
    {
        return Err(invalid("Malformed HTTP response status code"));
    }
    let status_code: u16 = after_ver[..3]
        .parse()
        .map_err(|_| invalid("Unparseable HTTP response status code"))?;
    if !(100..=599).contains(&status_code) {
        return Err(invalid("HTTP response status code out of range"));
    }
    if status_code == 101 {
        return Err(invalid(
            "Unexpected 101 Switching Protocols on non-upgrade HTTP forward",
        ));
    }

    let mut header_lines: Vec<(&[u8], &[u8])> = Vec::new();
    let mut content_length: Option<u64> = None;
    let mut te_codings: Vec<String> = Vec::new();
    let mut te_seen = false;

    for line in lines_iter {
        if line.is_empty() || matches!(line[0], b' ' | b'\t') {
            return Err(invalid("Malformed or obs-fold HTTP response header line"));
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return Err(invalid("HTTP response header missing colon"));
        };
        let name = &line[..colon];
        let val = &line[colon + 1..];
        if name.is_empty() || !name.iter().all(|&b| crate::inbound::is_http_token_byte(b)) {
            return Err(invalid("Invalid HTTP response header name"));
        }
        if val.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err(invalid(
                "HTTP response header value contains control characters",
            ));
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            let raw_v = std::str::from_utf8(val)
                .map_err(|_| invalid("Non-UTF-8 response Content-Length header"))?;
            let v = trim_http_ows(raw_v);
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid("Invalid response Content-Length header"));
            }
            let parsed = v
                .parse::<u64>()
                .map_err(|_| invalid("Overflow in response Content-Length header"))?;
            if let Some(prev) = content_length
                && prev != parsed
            {
                return Err(invalid(
                    "Conflicting Content-Length headers in HTTP response",
                ));
            }
            content_length = Some(parsed);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            te_seen = true;
            let v = std::str::from_utf8(val)
                .map_err(|_| invalid("Non-UTF-8 response Transfer-Encoding header"))?;
            for part in v.split(',') {
                let coding = trim_http_ows(part).to_ascii_lowercase();
                if coding.is_empty() || !coding.bytes().all(crate::inbound::is_http_token_byte) {
                    return Err(invalid(
                        "Invalid Transfer-Encoding coding in HTTP response",
                    ));
                }
                te_codings.push(coding);
            }
        }
        header_lines.push((line, name));
    }

    if (100..200).contains(&status_code) {
        if content_length.is_some() || te_seen {
            return Err(invalid(
                "1xx interim HTTP response must not contain body framing headers",
            ));
        }
        let mut raw = Vec::with_capacity(head.len() + 4);
        raw.extend_from_slice(head);
        raw.extend_from_slice(b"\r\n\r\n");
        return Ok(ParsedHttpResponseHead::Interim(raw));
    }

    if content_length.is_some() && te_seen {
        return Err(invalid(
            "HTTP response contains both Content-Length and Transfer-Encoding",
        ));
    }
    let chunked_count = te_codings.iter().filter(|c| c.as_str() == "chunked").count();
    let is_chunked = if chunked_count > 1 {
        return Err(invalid(
            "Duplicate chunked coding in response Transfer-Encoding",
        ));
    } else if chunked_count == 1 {
        if te_codings.last().map(|s| s.as_str()) != Some("chunked") {
            return Err(invalid("chunked must be the final Transfer-Encoding coding"));
        }
        true
    } else {
        false
    };

    // 剥离源站 keep-alive/逐跳声明并强制注入 Connection: close，告知客户端响应结束后即可断连
    let mut rewritten = Vec::with_capacity(head.len() + 32);
    rewritten.extend_from_slice(status_line_bytes);
    rewritten.extend_from_slice(b"\r\n");
    for (line, name) in header_lines {
        let is_conn_hop = name.eq_ignore_ascii_case(b"connection")
            || name.eq_ignore_ascii_case(b"keep-alive")
            || name.eq_ignore_ascii_case(b"proxy-connection");
        if !is_conn_hop {
            rewritten.extend_from_slice(line);
            rewritten.extend_from_slice(b"\r\n");
        }
    }
    rewritten.extend_from_slice(b"Connection: close\r\n\r\n");

    let framing = if is_head_request || status_code == 204 || status_code == 304 {
        HttpResponseFraming::Empty
    } else if is_chunked {
        HttpResponseFraming::Chunked
    } else if let Some(len) = content_length {
        HttpResponseFraming::ContentLength(len)
    } else {
        HttpResponseFraming::UntilEof
    };

    Ok(ParsedHttpResponseHead::Final {
        rewritten_head: rewritten,
        framing,
    })
}

async fn relay_http_response_downlink<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    rr: R,
    sink: &mut TrackedBodySink<'_, W>,
    is_head_request: bool,
) -> std::io::Result<u64> {
    const MAX_HTTP_RESPONSE_HEADER: usize = 64 * 1024;
    const MAX_INTERIM_RESPONSES: usize = 16;

    let mut reader = PrefixedTcpReader::new(Vec::new(), rr);
    let mut interim_count = 0usize;

    let framing = loop {
        let Some(head) = reader
            .read_http_header_block(MAX_HTTP_RESPONSE_HEADER)
            .await?
        else {
            sink.writer.shutdown().await.ok();
            return Ok(sink.total_bytes.load(std::sync::atomic::Ordering::Relaxed));
        };
        match parse_and_rewrite_http_response_head(&head, is_head_request)? {
            ParsedHttpResponseHead::Interim(raw) => {
                interim_count += 1;
                if interim_count > MAX_INTERIM_RESPONSES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Too many 1xx interim HTTP responses",
                    ));
                }
                sink.write_all(&raw)
                    .await
                    .map_err(BodyRelayError::into_io_error)?;
                sink.writer.flush().await?;
            }
            ParsedHttpResponseHead::Final {
                rewritten_head,
                framing,
            } => {
                sink.write_all(&rewritten_head)
                    .await
                    .map_err(BodyRelayError::into_io_error)?;
                break framing;
            }
        }
    };

    match framing {
        HttpResponseFraming::Empty => {}
        HttpResponseFraming::ContentLength(len) => {
            copy_exact_body(&mut reader, sink, len)
                .await
                .map_err(BodyRelayError::into_io_error)?;
        }
        HttpResponseFraming::Chunked => {
            forward_chunked_body(&mut reader, sink)
                .await
                .map_err(BodyRelayError::into_io_error)?;
        }
        HttpResponseFraming::UntilEof => {
            copy_until_eof(&mut reader, sink)
                .await
                .map_err(BodyRelayError::into_io_error)?;
        }
    }

    sink.writer.flush().await.ok();
    sink.writer.shutdown().await.ok();
    Ok(sink.total_bytes.load(std::sync::atomic::Ordering::Relaxed))
}

/// 明文 HTTP 代理有界双向报文转发：请求侧严格按 `Content-Length` / `chunked` 截断并隔离流水线走私；
/// 响应侧解析 HTTP/1.x 响应头与有界响应体（重写 `Connection: close`），响应体完毕即主动优雅关闭双方连接，
/// 防止忽略 `Connection: close` 的 HTTP/1.1 Keep-Alive 源站拖挂至 120s 空闲超时，同时兼容延迟响应与早期 4xx 拒绝。
pub async fn relay_http_forward_monitored<L: RelayStream, R: RelayStream>(
    local: L,
    remote: R,
    conn: Option<&Arc<ActiveConnection>>,
    framing: crate::inbound::HttpBodyFraming,
    body_prefix: Vec<u8>,
    is_head_request: bool,
) -> Result<(u64, u64)> {
    const RELAY_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
    relay_http_forward_monitored_with_timeout(
        local,
        remote,
        conn,
        framing,
        body_prefix,
        is_head_request,
        RELAY_IDLE_TIMEOUT,
    )
    .await
}

pub async fn relay_http_forward_monitored_with_timeout<L: RelayStream, R: RelayStream>(
    local: L,
    remote: R,
    conn: Option<&Arc<ActiveConnection>>,
    framing: crate::inbound::HttpBodyFraming,
    body_prefix: Vec<u8>,
    is_head_request: bool,
    idle_timeout: std::time::Duration,
) -> Result<(u64, u64)> {
    use std::sync::atomic::{AtomicU64, Ordering};

    if conn.is_some_and(|c| c.is_cancelled()) {
        anyhow::bail!("Connection aborted by administrator");
    }

    let (lr, lw) = local.split_stream();
    let (rr, rw) = remote.split_stream();

    let conn_up = conn.cloned();
    let conn_down = conn.cloned();

    let start = tokio::time::Instant::now();
    let last_activity_us = Arc::new(AtomicU64::new(0));
    let last_up = Arc::clone(&last_activity_us);
    let last_down = Arc::clone(&last_activity_us);
    let up_bytes = Arc::new(AtomicU64::new(0));
    let up_bytes_ref = Arc::clone(&up_bytes);
    let down_bytes = Arc::new(AtomicU64::new(0));
    let down_bytes_ref = Arc::clone(&down_bytes);

    let up_task = async move {
        let mut reader = PrefixedTcpReader::new(body_prefix, lr);
        let mut up_sink = TrackedBodySink {
            writer: rw,
            total_bytes: &up_bytes_ref,
            conn: &conn_up,
            start: &start,
            last_activity_us: &last_up,
            direction: RelayDirection::Upload,
        };
        match framing {
            crate::inbound::HttpBodyFraming::ContentLength(len) => {
                copy_exact_body(&mut reader, &mut up_sink, len).await?;
            }
            crate::inbound::HttpBodyFraming::Chunked => {
                forward_chunked_body(&mut reader, &mut up_sink).await?;
            }
        }
        // 丢弃 client 读端（阻断后续流水线请求字节），同时保留写端至响应完成，不发送提前 FIN
        drop(reader);
        Ok::<R::WriteHalf, BodyRelayError>(up_sink.writer)
    };

    let down_task = async move {
        let mut down_sink = TrackedBodySink {
            writer: lw,
            total_bytes: &down_bytes_ref,
            conn: &conn_down,
            start: &start,
            last_activity_us: &last_down,
            direction: RelayDirection::Download,
        };
        relay_http_response_downlink(rr, &mut down_sink, is_head_request).await
    };

    let relay_fut = async {
        tokio::pin!(up_task);
        tokio::pin!(down_task);
        let mut up_done = false;
        let mut rw_keepalive: Option<R::WriteHalf> = None;
        let mut pending_up_write_err: Option<std::io::Error> = None;

        loop {
            tokio::select! {
                up_res = &mut up_task, if !up_done => {
                    match up_res {
                        Ok(rw_done) => {
                            rw_keepalive = Some(rw_done);
                            up_done = true;
                        }
                        Err(BodyRelayError::PeerWriteClosed(e)) => {
                            // 源站可能已发送 4xx/413 响应并关闭接收端；继续完成下行读取以免吞掉响应体
                            pending_up_write_err = Some(e);
                            up_done = true;
                        }
                        Err(BodyRelayError::Fatal(e)) => return Err(e),
                    }
                }
                down_res = &mut down_task => {
                    let down_bytes = down_res?;
                    if let Some(mut rw_open) = rw_keepalive.take() {
                        rw_open.shutdown().await.ok();
                    }
                    if down_bytes == 0
                        && let Some(e) = pending_up_write_err
                    {
                        return Err(e);
                    }
                    return Ok((up_bytes.load(Ordering::Relaxed), down_bytes));
                }
            }
        }
    };

    await_relay_with_watchdog(relay_fut, start, last_activity_us, conn, idle_timeout).await
}
