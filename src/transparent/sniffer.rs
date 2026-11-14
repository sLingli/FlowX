use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

const MAX_SNIFF_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniffOutcome {
    pub host: Option<String>,
    pub buffered: Vec<u8>,
}

/// 校验嗅探到的域名是否合法（ASCII 可打印主机名，排除 IP 字面量与控制/路径危险字符）
pub fn is_valid_sniffed_host(host: &str) -> bool {
    let trimmed = host.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return false;
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return false;
    }
    trimmed.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')
    })
}

/// 非破坏性预读客户端首段载荷，提取 TLS `ClientHello` SNI 或 HTTP `Host` 请求头，并原样保留所有已读字节以便后续转发。
pub async fn peek_host_prefix<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_wait: Duration,
) -> std::io::Result<SniffOutcome> {
    let mut buffered = Vec::with_capacity(512);
    let mut tmp = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + max_wait;

    loop {
        if buffered.len() >= MAX_SNIFF_BYTES {
            break;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
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
                        });
                    }
                    SniffProbe::NotMatchable => break,
                    SniffProbe::NeedMore => continue,
                }
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => break,
        }
    }

    let host = match inspect_protocol_host(&buffered) {
        SniffProbe::Found(h) => Some(h),
        SniffProbe::NotMatchable | SniffProbe::NeedMore => None,
    };
    Ok(SniffOutcome { host, buffered })
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

fn parse_http_host_header(buf: &[u8]) -> SniffProbe {
    // 扫描按 CRLF 切分的行；未见头尾且仍有剩余缓冲额度时可继续读取
    let mut start = 0usize;
    let mut header_end = false;
    while let Some(rel_lf) = buf[start..].iter().position(|&b| b == b'\n') {
        let line_end = start + rel_lf;
        let line = buf[start..line_end].strip_suffix(b"\r").unwrap_or(&buf[start..line_end]);
        start = line_end + 1;
        if line.is_empty() {
            header_end = true;
            break;
        }
        if line.len() > 5 && line[..5].eq_ignore_ascii_case(b"host:") {
            if let Ok(raw_val) = std::str::from_utf8(&line[5..]) {
                let val = raw_val.trim();
                let host = if let Some(rest) = val.strip_prefix('[') {
                    // IPv6 `[::1]:80` 字面量直接跳过，不作为域名
                    rest.split(']').next().unwrap_or("")
                } else {
                    val.split(':').next().unwrap_or("")
                };
                let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
                if is_valid_sniffed_host(&normalized) {
                    return SniffProbe::Found(normalized);
                }
                return SniffProbe::NotMatchable;
            }
            return SniffProbe::NotMatchable;
        }
    }
    if header_end || buf.len() >= MAX_SNIFF_BYTES {
        SniffProbe::NotMatchable
    } else {
        SniffProbe::NeedMore
    }
}

/// 解析 TLS Record -> Handshake(ClientHello) -> Extensions -> SNI (`server_name`, ext type `0x0000`)
fn parse_tls_client_hello_sni(buf: &[u8]) -> SniffProbe {
    // TLS Record header = 5 bytes: ContentType(1)=0x16, LegacyVer(2)=0x03 0x00..0x04, Length(2)
    if buf.len() < 5 {
        return SniffProbe::NeedMore;
    }
    if buf[0] != 0x16 || buf[1] != 0x03 || buf[2] > 0x04 {
        return SniffProbe::NotMatchable;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let payload = &buf[5..];
    let declared_total = rec_len.min(MAX_SNIFF_BYTES - 5);

    // Handshake header = 4 bytes: HandshakeType(1)=0x01 (ClientHello), Length(3)
    if payload.len() < 4 {
        return if payload.len() < declared_total {
            SniffProbe::NeedMore
        } else {
            SniffProbe::NotMatchable
        };
    }
    if payload[0] != 0x01 {
        return SniffProbe::NotMatchable;
    }
    let hs_len = ((payload[1] as usize) << 16) | ((payload[2] as usize) << 8) | (payload[3] as usize);
    let body = &payload[4..];
    let need_bytes = hs_len.min(declared_total.saturating_sub(4));

    // ClientHello: Version(2) + Random(32) + SessionIdLen(1)
    let mut off = 34usize;
    if body.len() <= off {
        return if body.len() < need_bytes && buf.len() < MAX_SNIFF_BYTES {
            SniffProbe::NeedMore
        } else {
            SniffProbe::NotMatchable
        };
    }
    let sid_len = body[off] as usize;
    off += 1 + sid_len;

    // CipherSuitesLen(2)
    if body.len() < off + 2 {
        return if body.len() < need_bytes && buf.len() < MAX_SNIFF_BYTES {
            SniffProbe::NeedMore
        } else {
            SniffProbe::NotMatchable
        };
    }
    let cs_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2 + cs_len;

    // CompressionMethodsLen(1)
    if body.len() <= off {
        return if body.len() < need_bytes && buf.len() < MAX_SNIFF_BYTES {
            SniffProbe::NeedMore
        } else {
            SniffProbe::NotMatchable
        };
    }
    let comp_len = body[off] as usize;
    off += 1 + comp_len;

    // ExtensionsLen(2)
    if body.len() < off + 2 {
        return if body.len() < need_bytes && buf.len() < MAX_SNIFF_BYTES {
            SniffProbe::NeedMore
        } else {
            SniffProbe::NotMatchable
        };
    }
    let ext_total = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    let ext_end = off.saturating_add(ext_total);

    while off + 4 <= body.len() && off + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[off], body[off + 1]]);
        let ext_len = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
        off += 4;
        if off + ext_len > body.len() {
            return if buf.len() < MAX_SNIFF_BYTES {
                SniffProbe::NeedMore
            } else {
                SniffProbe::NotMatchable
            };
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
                    let name_len = u16::from_be_bytes([ext_data[pos + 1], ext_data[pos + 2]]) as usize;
                    pos += 3;
                    if pos + name_len > list_end {
                        break;
                    }
                    if name_type == 0x00
                        && let Ok(s) = std::str::from_utf8(&ext_data[pos..pos + name_len])
                    {
                        let normalized = s.trim().trim_end_matches('.').to_ascii_lowercase();
                        if is_valid_sniffed_host(&normalized) {
                            return SniffProbe::Found(normalized);
                        }
                    }
                    pos += name_len;
                }
            }
            return SniffProbe::NotMatchable;
        }
        off += ext_len;
    }

    if body.len() < ext_end && body.len() < need_bytes && buf.len() < MAX_SNIFF_BYTES {
        SniffProbe::NeedMore
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
}
