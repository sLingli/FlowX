use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

const MAX_SNIFF_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniffOutcome {
    pub host: Option<String>,
    pub buffered: Vec<u8>,
    pub timed_out: bool,
}

/// 按 RFC 1035 / RFC 1123 / RFC 6066 严格校验嗅探到的域名：
/// 排除标准与非规范数字 IPv4（`127.1` / `0177.0.0.1` / `0x7f000001` / `2130706433`）、IPv6 字面量、
/// 任意首尾空白（含 Unicode `\u{00a0}`）、空标签（前导点/连续点/多尾点如 `example.com..`）、下划线、
/// 超 63 字节标签以及以 `-` 开头或结尾的标签。
pub fn is_valid_sniffed_host(host: &str) -> bool {
    let trimmed = host.strip_suffix('.').unwrap_or(host);
    if trimmed.is_empty() || trimmed.len() > 253 {
        return false;
    }
    if trimmed.parse::<IpAddr>().is_ok()
        || crate::outbound::parse_noncanonical_ipv4(trimmed).is_some()
    {
        return false;
    }
    for label in trimmed.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return false;
        }
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return false;
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return false;
        }
    }
    true
}

/// 非破坏性预读客户端首段载荷，提取 TLS `ClientHello` SNI 或 HTTP `Host` 请求头，并原样保留所有已读字节以便后续转发。
pub async fn peek_host_prefix<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_wait: Duration,
) -> std::io::Result<SniffOutcome> {
    let mut buffered = Vec::with_capacity(512);
    let mut tmp = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + max_wait;
    let mut timed_out = false;

    loop {
        if buffered.len() >= MAX_SNIFF_BYTES {
            break;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            timed_out = true;
            break;
        }

        let max_read = tmp.len().min(MAX_SNIFF_BYTES - buffered.len());
        let read_res = tokio::time::timeout(remaining, reader.read(&mut tmp[..max_read])).await;
        match read_res {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buffered.extend_from_slice(&tmp[..n]);
                match inspect_protocol_host(&buffered) {
                    SniffProbe::Found(host) => {
                        return Ok(SniffOutcome {
                            host: Some(host),
                            buffered,
                            timed_out: false,
                        });
                    }
                    SniffProbe::NotMatchable => break,
                    SniffProbe::NeedMore => continue,
                }
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                timed_out = true;
                break;
            }
        }
    }

    let host = match inspect_protocol_host(&buffered) {
        SniffProbe::Found(h) => Some(h),
        SniffProbe::NotMatchable | SniffProbe::NeedMore => None,
    };
    Ok(SniffOutcome {
        host,
        buffered,
        timed_out,
    })
}

#[derive(Debug, PartialEq, Eq)]
enum SniffProbe {
    Found(String),
    NeedMore,
    NotMatchable,
}

fn inspect_protocol_host(buf: &[u8]) -> SniffProbe {
    if buf.is_empty() {
        return SniffProbe::NeedMore;
    }
    if buf[0] == 0x16 {
        return parse_tls_client_hello_sni(buf);
    }
    if looks_like_http_request(buf) {
        return parse_http_host_header(buf);
    }
    SniffProbe::NotMatchable
}

fn looks_like_http_request(buf: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"TRACE ",
    ];
    for m in METHODS {
        if buf.len() < m.len() {
            if m.starts_with(buf) {
                return true;
            }
        } else if buf.starts_with(m) {
            return true;
        }
    }
    false
}

fn parse_http_host_value(raw_val: &str) -> Option<String> {
    let val = raw_val.trim_matches(|c| c == ' ' || c == '\t');
    // 严格仅允许可见 ASCII（0x21..=0x7E），彻底拦截控制字符、内部空格及 Unicode 空白（如 \u{00a0}）
    if val.is_empty() || !val.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return None;
    }
    if val.starts_with('[') {
        // IPv6 `[::1]:80` 字面量直接跳过，不作为域名
        return None;
    }
    let host_part = if let Some((h, p)) = val.split_once(':') {
        // 严格要求冒号右侧为无前导零的合法十进制端口号 (1..=65535)，杜绝未加方括号的 IPv6（如 dead:beef::1）、`:080` 或畸形端口串
        if p.is_empty() || p.starts_with('0') || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let port = p.parse::<u16>().ok()?;
        if port == 0 {
            return None;
        }
        h
    } else {
        val
    };
    if !is_valid_sniffed_host(host_part) {
        return None;
    }
    Some(
        host_part
            .strip_suffix('.')
            .unwrap_or(host_part)
            .to_ascii_lowercase(),
    )
}

fn parse_http_host_header(buf: &[u8]) -> SniffProbe {
    // 扫描请求头直至空行（\r\n\r\n），校验端口合法性、拒绝行内孤立 \r、obs-fold 续行与重复 Host 冲突；
    // 仅在完整见到头部结束空行时才返回 Found(host)，防止超过 MAX_SNIFF_BYTES 时绕过后续重复 Host 或末端残片检查
    let mut start = 0usize;
    let mut is_request_line = true;
    let mut header_end = false;
    let mut found_host: Option<String> = None;

    while let Some(rel_lf) = buf[start..].iter().position(|&b| b == b'\n') {
        let line_end = start + rel_lf;
        let line = buf[start..line_end]
            .strip_suffix(b"\r")
            .unwrap_or(&buf[start..line_end]);
        start = line_end + 1;

        // 拒绝任何行内孤立 \r（防止 CR/LF 拆分走私）
        if line.contains(&b'\r') {
            return SniffProbe::NotMatchable;
        }

        if is_request_line {
            is_request_line = false;
            continue;
        }
        if line.is_empty() {
            header_end = true;
            break;
        }
        // RFC 9112 禁止 obs-fold（前导空格/Tab 续行），防止 Host 续行走私
        if matches!(line.first(), Some(b' ' | b'\t')) {
            return SniffProbe::NotMatchable;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return SniffProbe::NotMatchable;
        };
        let name = &line[..colon];
        if name.trim_ascii_end().eq_ignore_ascii_case(b"host") {
            if name.len() != 4 || found_host.is_some() {
                return SniffProbe::NotMatchable;
            }
            let Ok(raw_val) = std::str::from_utf8(&line[colon + 1..]) else {
                return SniffProbe::NotMatchable;
            };
            let Some(host) = parse_http_host_value(raw_val) else {
                return SniffProbe::NotMatchable;
            };
            found_host = Some(host);
        }
    }

    if header_end {
        match found_host {
            Some(host) => SniffProbe::Found(host),
            None => SniffProbe::NotMatchable,
        }
    } else if buf.len() >= MAX_SNIFF_BYTES {
        SniffProbe::NotMatchable
    } else {
        SniffProbe::NeedMore
    }
}

/// 解析单条或跨多条 TLS Record 拆分的 Handshake(ClientHello) -> Extensions -> SNI (`server_name`, ext type `0x0000`)
fn parse_tls_client_hello_sni(buf: &[u8]) -> SniffProbe {
    // 1. 顺序解包连续的 TLS Handshake (0x16) 记录载荷，重组逻辑握手字节流（不修改原始 buffered）
    let mut hs_stream = Vec::with_capacity(buf.len());
    let mut pos = 0usize;
    let mut handshake_terminated = false;
    while pos < buf.len() {
        let rem = buf.len() - pos;
        if rem < 5 {
            if buf[pos] != 0x16
                || (rem >= 2 && buf[pos + 1] != 0x03)
                || (rem >= 3 && buf[pos + 2] > 0x04)
            {
                if pos == 0 {
                    return SniffProbe::NotMatchable;
                }
                handshake_terminated = true;
                break;
            }
            break;
        }
        if buf[pos] != 0x16 || buf[pos + 1] != 0x03 || buf[pos + 2] > 0x04 {
            if pos == 0 {
                return SniffProbe::NotMatchable;
            }
            handshake_terminated = true;
            break;
        }
        let rec_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
        if rec_len == 0 || rec_len > 16_384 {
            if pos == 0 {
                return SniffProbe::NotMatchable;
            }
            handshake_terminated = true;
            break;
        }
        pos += 5;
        let avail = buf.len() - pos;
        if avail < rec_len {
            hs_stream.extend_from_slice(&buf[pos..]);
            break;
        }
        hs_stream.extend_from_slice(&buf[pos..pos + rec_len]);
        pos += rec_len;
    }

    // 2. Handshake header = 4 bytes: HandshakeType(1)=0x01 (ClientHello), Length(3)
    if hs_stream.len() < 4 {
        return if !handshake_terminated && buf.len() < MAX_SNIFF_BYTES {
            SniffProbe::NeedMore
        } else {
            SniffProbe::NotMatchable
        };
    }
    if hs_stream[0] != 0x01 {
        return SniffProbe::NotMatchable;
    }
    let hs_len =
        ((hs_stream[1] as usize) << 16) | ((hs_stream[2] as usize) << 8) | (hs_stream[3] as usize);
    let body_all = &hs_stream[4..];
    let body = &body_all[..body_all.len().min(hs_len)];

    let need_more_if_incomplete = |body_len: usize| {
        if !handshake_terminated && body_len < hs_len && buf.len() < MAX_SNIFF_BYTES {
            SniffProbe::NeedMore
        } else {
            SniffProbe::NotMatchable
        }
    };

    // ClientHello: Version(2) + Random(32) + SessionIdLen(1)
    let mut off = 34usize;
    if body.len() <= off {
        return need_more_if_incomplete(body.len());
    }
    let sid_len = body[off] as usize;
    off += 1 + sid_len;

    // CipherSuitesLen(2)
    if body.len() < off + 2 {
        return need_more_if_incomplete(body.len());
    }
    let cs_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2 + cs_len;

    // CompressionMethodsLen(1)
    if body.len() <= off {
        return need_more_if_incomplete(body.len());
    }
    let comp_len = body[off] as usize;
    off += 1 + comp_len;

    // ExtensionsLen(2)
    if body.len() < off + 2 {
        return need_more_if_incomplete(body.len());
    }
    let ext_total = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    let ext_end = off.saturating_add(ext_total).min(hs_len);

    while off + 4 <= body.len() && off + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[off], body[off + 1]]);
        let ext_len = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
        off += 4;
        if off + ext_len > ext_end {
            return SniffProbe::NotMatchable;
        }
        if off + ext_len > body.len() {
            return need_more_if_incomplete(body.len());
        }
        if ext_type == 0x0000 {
            // server_name list: list_len(2) + entries [name_type(1) + name_len(2) + host]
            let ext_data = &body[off..off + ext_len];
            if ext_data.len() >= 5 {
                let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                let list_end = (2 + list_len).min(ext_data.len());
                let mut pos = 2usize;
                while pos + 3 <= list_end {
                    let name_type = ext_data[pos];
                    let name_len =
                        u16::from_be_bytes([ext_data[pos + 1], ext_data[pos + 2]]) as usize;
                    pos += 3;
                    if pos + name_len > list_end {
                        break;
                    }
                    if name_type == 0x00
                        && let Ok(s) = std::str::from_utf8(&ext_data[pos..pos + name_len])
                        && is_valid_sniffed_host(s)
                    {
                        let normalized = s.strip_suffix('.').unwrap_or(s).to_ascii_lowercase();
                        return SniffProbe::Found(normalized);
                    }
                    pos += name_len;
                }
            }
            return SniffProbe::NotMatchable;
        }
        off += ext_len;
    }

    if body.len() < ext_end {
        need_more_if_incomplete(body.len())
    } else {
        SniffProbe::NotMatchable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn build_tls_client_hello(sni: &str) -> Vec<u8> {
        let name_bytes = sni.as_bytes();
        let mut sni_ext = Vec::new();
        let entry_len = 1 + 2 + name_bytes.len();
        sni_ext.extend_from_slice(&(entry_len as u16).to_be_bytes());
        sni_ext.push(0x00); // host_name
        sni_ext.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name_bytes);

        let mut exts = Vec::new();
        exts.extend_from_slice(&0x0000u16.to_be_bytes()); // server_name
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);

        let mut hello_body = Vec::new();
        hello_body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 legacy version
        hello_body.extend_from_slice(&[0xAB; 32]); // Random
        hello_body.push(0); // SessionID len
        hello_body.extend_from_slice(&2u16.to_be_bytes()); // CipherSuites len
        hello_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        hello_body.push(1); // Compression methods len
        hello_body.push(0); // null compression
        hello_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hello_body.extend_from_slice(&exts);

        let hs_len = hello_body.len();
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record layer
        record.extend_from_slice(&((4 + hs_len) as u16).to_be_bytes());
        record.push(0x01); // ClientHello
        record.push(((hs_len >> 16) & 0xff) as u8);
        record.push(((hs_len >> 8) & 0xff) as u8);
        record.push((hs_len & 0xff) as u8);
        record.extend_from_slice(&hello_body);
        record
    }

    #[tokio::test]
    async fn test_peek_tls_sni_complete_and_fragmented() {
        let pkt = build_tls_client_hello("API.GitHub.COM");
        let (mut client, mut server) = tokio::io::duplex(4096);
        let expected = pkt.clone();

        let writer = tokio::spawn(async move {
            let split = pkt.len() / 2;
            client.write_all(&pkt[..split]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            client.write_all(&pkt[split..]).await.unwrap();
        });

        let out = peek_host_prefix(&mut server, Duration::from_millis(300))
            .await
            .unwrap();
        writer.await.unwrap();
        assert_eq!(out.host.as_deref(), Some("api.github.com"));
        assert_eq!(out.buffered, expected);
    }

    #[tokio::test]
    async fn test_peek_http_host_preserves_bytes() {
        let req = b"GET /v1/models HTTP/1.1\r\nUser-Agent: test\r\nHost: OpenAI.Com:443\r\n\r\n";
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(req).await.unwrap();
        drop(client);

        let out = peek_host_prefix(&mut server, Duration::from_millis(200))
            .await
            .unwrap();
        assert_eq!(out.host.as_deref(), Some("openai.com"));
        assert_eq!(out.buffered, req);
    }

    #[tokio::test]
    async fn test_peek_non_http_ssh_and_silent_timeout() {
        let ssh = b"SSH-2.0-OpenSSH_9.6\r\n";
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(ssh).await.unwrap();

        let out = peek_host_prefix(&mut server, Duration::from_millis(200))
            .await
            .unwrap();
        assert_eq!(out.host, None);
        assert_eq!(out.buffered, ssh);

        let (_silent_client, mut silent_server) = tokio::io::duplex(1024);
        let out_silent = peek_host_prefix(&mut silent_server, Duration::from_millis(25))
            .await
            .unwrap();
        assert_eq!(out_silent.host, None);
        assert!(out_silent.buffered.is_empty());
    }

    #[test]
    fn test_strict_sniffed_host_validation() {
        assert!(is_valid_sniffed_host("api-1.github.com"));
        assert!(is_valid_sniffed_host("localhost."));
        for invalid in [
            "",
            ".example.com",
            "example.com..",
            " example.com",
            "example.com ",
            "\u{00a0}example.com",
            "example.com\u{00a0}",
            "a..b.com",
            "bad_host.example",
            "-leading.example",
            "trailing-.example",
            "127.0.0.1",
            "::1",
            "127.1",
            "0177.0.0.1",
            "0x7f000001",
            "2130706433",
            &format!("{}.example", "a".repeat(64)),
        ] {
            assert!(
                !is_valid_sniffed_host(invalid),
                "expected invalid host to be rejected: {invalid:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_peek_multi_record_tls_client_hello_sni_preserves_raw_records() {
        let single = build_tls_client_hello("Multi-Record.Example.ORG");
        let hs_bytes = &single[5..];
        // 将同一个 ClientHello 握手拆分成 4 条独立 TLS Record（跨 4B 握手头与 SNI 域名内部）
        let mut multi_record = Vec::new();
        for chunk in [
            &hs_bytes[..2],
            &hs_bytes[2..25],
            &hs_bytes[25..hs_bytes.len() - 8],
            &hs_bytes[hs_bytes.len() - 8..],
        ] {
            multi_record.push(0x16);
            multi_record.extend_from_slice(&[0x03, 0x01]);
            multi_record.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            multi_record.extend_from_slice(chunk);
        }
        let expected_raw = multi_record.clone();

        let (mut client, mut server) = tokio::io::duplex(4096);
        let writer = tokio::spawn(async move {
            for part in multi_record.chunks(17) {
                client.write_all(part).await.unwrap();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        let out = peek_host_prefix(&mut server, Duration::from_millis(400))
            .await
            .unwrap();
        writer.await.unwrap();
        assert_eq!(out.host.as_deref(), Some("multi-record.example.org"));
        assert_eq!(out.buffered, expected_raw);
    }

    #[tokio::test]
    async fn test_p2_1_incomplete_tls_client_hello_followed_by_non_handshake_fails_immediately() {
        let single = build_tls_client_hello("fast-fail.example");
        let hs_bytes = &single[5..];
        // 首条 0x16 Record 仅包含不完整的 ClientHello，紧跟一条非 0x16 (Alert 0x15) Record
        let partial = &hs_bytes[..18];
        let mut malformed = Vec::new();
        malformed.push(0x16);
        malformed.extend_from_slice(&[0x03, 0x01]);
        malformed.extend_from_slice(&(partial.len() as u16).to_be_bytes());
        malformed.extend_from_slice(partial);
        malformed.extend_from_slice(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]);

        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(&malformed).await.unwrap();

        let started = std::time::Instant::now();
        // 客户端保持打开不发新数据：必须立即返回 NotMatchable，绝不卡满 250ms 超时
        let out = peek_host_prefix(&mut server, Duration::from_millis(250))
            .await
            .unwrap();
        assert_eq!(out.host, None);
        assert!(!out.timed_out);
        assert_eq!(out.buffered, malformed);
        assert!(
            started.elapsed() < Duration::from_millis(80),
            "incomplete ClientHello followed by non-0x16 record stalled for {:?}",
            started.elapsed()
        );
        drop(client);

        // 若首条 0x16 Record 已包含完整 ClientHello + SNI，后接 0x14 CCS (TLS 1.3 0-RTT) 仍可提取 SNI
        let mut with_ccs = single.clone();
        with_ccs.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
        let (mut c2, mut s2) = tokio::io::duplex(4096);
        c2.write_all(&with_ccs).await.unwrap();
        let out2 = peek_host_prefix(&mut s2, Duration::from_millis(200))
            .await
            .unwrap();
        assert_eq!(out2.host.as_deref(), Some("fast-fail.example"));
        assert!(!out2.timed_out);
        drop(c2);
    }

    #[tokio::test]
    async fn test_p2_2_http_host_validates_port_rejects_unbracketed_ipv6_duplicate_host_and_obs_fold()
     {
        for bad_req in [
            b"GET / HTTP/1.1\r\nHost: dead:beef::1\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: example.com:notaport\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: example.com:0\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: example.com:080\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: example.com:99999\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: example.com:\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: example.com..\r\n\r\n".as_slice(),
            "GET / HTTP/1.1\r\nHost: \u{00a0}example.com\r\n\r\n".as_bytes(),
            b"GET / HTTP/1.1\r\nHost: good.example\r\nX-Bare: a\rb\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: good.example\r\nHost: evil.example\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: good.example\r\nHost: good.example\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: good.example\r\n .continued.example\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nX-Test: a\r\n\tfolded\r\nHost: good.example\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost : good.example\r\n\r\n".as_slice(),
        ] {
            let (mut client, mut server) = tokio::io::duplex(1024);
            client.write_all(bad_req).await.unwrap();
            let started = std::time::Instant::now();
            let out = peek_host_prefix(&mut server, Duration::from_millis(200))
                .await
                .unwrap();
            assert_eq!(
                out.host,
                None,
                "malformed/conflicting HTTP Host must be rejected: {:?}",
                String::from_utf8_lossy(bad_req)
            );
            assert!(!out.timed_out);
            assert_eq!(out.buffered, bad_req);
            assert!(started.elapsed() < Duration::from_millis(80));
            drop(client);
        }

        // 合法带端口的 HTTP Host 正常提取并保留完整报文
        let good_req = b"GET /api HTTP/1.1\r\nHost: Service.Example.COM:8444\r\nX-Ok: 1\r\n\r\n";
        let (mut c_ok, mut s_ok) = tokio::io::duplex(1024);
        c_ok.write_all(good_req).await.unwrap();
        let out_ok = peek_host_prefix(&mut s_ok, Duration::from_millis(200))
            .await
            .unwrap();
        assert_eq!(out_ok.host.as_deref(), Some("service.example.com"));
        assert!(!out_ok.timed_out);
        assert_eq!(out_ok.buffered, good_req);

        // 1. 合法超大 Cookie 请求头（超过 32 KiB 但在 64 KiB 上限内且见到完整 \r\n\r\n）应正常提取 Host
        let large_cookie = "c".repeat(40_960);
        let large_req = format!(
            "GET /sso HTTP/1.1\r\nHost: huge-cookie.example\r\nCookie: tok={large_cookie}\r\n\r\n"
        );
        let large_bytes = large_req.into_bytes();
        assert!(large_bytes.len() > 32_768 && large_bytes.len() < MAX_SNIFF_BYTES);
        let (mut c_large, mut s_large) = tokio::io::duplex(MAX_SNIFF_BYTES + 4096);
        let write_large = large_bytes.clone();
        let w_large = tokio::spawn(async move {
            let _ = c_large.write_all(&write_large).await;
        });
        let out_large = peek_host_prefix(&mut s_large, Duration::from_millis(500))
            .await
            .unwrap();
        assert_eq!(out_large.host.as_deref(), Some("huge-cookie.example"));
        assert!(!out_large.timed_out);
        assert_eq!(out_large.buffered, large_bytes);
        drop(s_large);
        let _ = w_large.await;

        // 2. 超过 MAX_SNIFF_BYTES (64 KiB) 仍未见完整空行（含截断后隐藏冲突重复 Host 的走私请求）必须退回 NotMatchable (None)
        let huge_cookie = "c".repeat(MAX_SNIFF_BYTES + 2048);
        let smuggle_req = format!(
            "GET /sso HTTP/1.1\r\nHost: benign.example\r\nCookie: tok={huge_cookie}\r\nHost: evil.example\r\n\r\n"
        );
        let (mut c_huge, mut s_huge) = tokio::io::duplex(MAX_SNIFF_BYTES + 8192);
        let req_bytes = smuggle_req.into_bytes();
        let write_bytes = req_bytes.clone();
        let w = tokio::spawn(async move {
            let _ = c_huge.write_all(&write_bytes).await;
        });
        let out_huge = peek_host_prefix(&mut s_huge, Duration::from_millis(500))
            .await
            .unwrap();
        assert_eq!(
            out_huge.host, None,
            "oversized incomplete HTTP header past MAX_SNIFF_BYTES must not return early Found(host)"
        );
        assert!(!out_huge.timed_out);
        assert_eq!(out_huge.buffered.len(), MAX_SNIFF_BYTES);
        assert_eq!(out_huge.buffered.as_slice(), &req_bytes[..MAX_SNIFF_BYTES]);
        drop(s_huge);
        let _ = w.await;
    }
}
