use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use super::codec::{
    DnsQuestion, build_dns_query_packet, csprng_u16, parse_answer_ips,
    validate_upstream_dns_response,
};
use super::{FakeIpPool, canonicalize_socket_addr_preserving_scope};

pub(super) const MAX_DNS_UPSTREAM_CONCURRENCY: usize = 1024;
pub(super) const UPSTREAM_DNS_TIMEOUT: Duration = Duration::from_secs(2);
/// 双栈并行查询（A + AAAA）中，当一族地址已返回可用 IP 或权威 NXDOMAIN 后，等待另一族的宽限窗口，
/// 避免丢弃 AAAA 的企业/路由器 DNS 将每次 Direct 建连拖满 1.5s~3s 超时。
const DUAL_STACK_SECOND_FAMILY_GRACE: Duration = Duration::from_millis(150);
pub(super) const MAX_UDP_DNS_PACKET_LEN: usize = 65_535;
static UPSTREAM_RESOLVE_SEMAPHORE: OnceLock<Semaphore> = OnceLock::new();

/// 上游 DNS 明确返回权威 `NXDOMAIN` (`RCODE=3`) 时的类型化错误，
/// 供 `DirectOutbound` 识别并禁止将内网不存在主机名回退泄露至公网 `upstream_dns`。
#[derive(Debug, Clone)]
pub(crate) struct DnsNxDomainError {
    pub domain: String,
    pub server: SocketAddr,
}

impl std::fmt::Display for DnsNxDomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Upstream DNS {} returned NXDOMAIN for {}",
            self.server, self.domain
        )
    }
}

impl std::error::Error for DnsNxDomainError {}

fn upstream_resolve_semaphore() -> &'static Semaphore {
    UPSTREAM_RESOLVE_SEMAPHORE.get_or_init(|| Semaphore::new(MAX_DNS_UPSTREAM_CONCURRENCY))
}

/// 规范化套接字地址，避免双栈环境下的 IPv4-mapped IPv6 形式影响源地址核验，同时保留 IPv6 `scope_id`
fn normalize_socket_addr(addr: SocketAddr) -> SocketAddr {
    canonicalize_socket_addr_preserving_scope(addr)
}

pub(super) fn is_transient_udp_recv_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::Interrupted
    ) || err.raw_os_error() == Some(10040) // WSAEMSGSIZE: UDP datagram truncated by socket receive buffer
}

pub(super) async fn forward_upstream_udp(
    upstream_dns: SocketAddr,
    query_bytes: &[u8],
    tx_id: u16,
    question: &DnsQuestion,
    timeout: Duration,
) -> Result<Option<(Vec<u8>, usize)>> {
    // 先将 [::ffff:a.b.c.d]:53 规范化为原生 IPv4，保留纯 IPv6 的 scope_id，避免 Windows V6ONLY 套接字发包失败
    let upstream_dns = normalize_socket_addr(upstream_dns);
    let local_bind = if upstream_dns.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = crate::outbound::bypass::bind_udp_guarded(local_bind)
        .await
        .context("Failed to bind ephemeral upstream DNS socket")?;
    sock.send_to(query_bytes, upstream_dns)
        .await
        .context("Failed to send upstream DNS query")?;

    let expected_upstream = upstream_dns;
    let mut buf = vec![0u8; MAX_UDP_DNS_PACKET_LEN];
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        let rem = deadline - now;
        match tokio::time::timeout(rem, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, src_addr))) => {
                if normalize_socket_addr(src_addr) != expected_upstream {
                    warn!(
                        "[DNS Engine] Dropped response packet from unexpected upstream source {} (expected {})",
                        src_addr, expected_upstream
                    );
                    continue;
                }
                match validate_upstream_dns_response(tx_id, question, &buf[..n]) {
                    Ok(answer_off) => return Ok(Some((buf[..n].to_vec(), answer_off))),
                    Err(e) => {
                        debug!(
                            "[DNS Engine] Ignored invalid upstream packet from {}: {}",
                            src_addr, e
                        );
                        continue;
                    }
                }
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                debug!("[DNS Engine] Upstream UDP endpoint unreachable: {}", e);
                bail!(
                    "Upstream DNS endpoint {} unreachable (connection reset): {}",
                    upstream_dns,
                    e
                );
            }
            Ok(Err(e)) if is_transient_udp_recv_error(&e) => {
                debug!(
                    "[DNS Engine] Transient upstream UDP receive error from {} ignored: {}",
                    upstream_dns, e
                );
                tokio::task::yield_now().await;
                continue;
            }
            Ok(Err(e)) => {
                debug!("[DNS Engine] Upstream UDP receive error: {}", e);
                bail!("Upstream DNS {} UDP receive error: {}", upstream_dns, e);
            }
            Err(_) => return Ok(None),
        }
    }
}

/// 显式经由上游 DNS 解析域名的 A + AAAA 记录（完全绕过 OS getaddrinfo 与 Fake-IP 冲突）
pub(crate) async fn resolve_via_upstream_dns(
    domain: &str,
    upstream_dns: SocketAddr,
    fake_ip_pool: Option<&FakeIpPool>,
    timeout: Duration,
) -> Result<Vec<IpAddr>> {
    resolve_via_upstream_dns_with_options(domain, upstream_dns, fake_ip_pool, timeout, true).await
}

struct ParsedFamilyOutcome {
    ips: Vec<IpAddr>,
    got_response: bool,
    saw_nxdomain: bool,
    saw_noerror: bool,
    err: Option<anyhow::Error>,
}

fn evaluate_family_response(
    res: Result<Option<(Vec<u8>, usize)>>,
    q: &DnsQuestion,
    fake_ip_pool: Option<&FakeIpPool>,
) -> ParsedFamilyOutcome {
    match res {
        Ok(Some((resp, ans_off))) => {
            let rcode = resp[3] & 0x0F;
            let saw_nxdomain = rcode == 3;
            let saw_noerror = rcode == 0;
            match parse_answer_ips(&resp, q, ans_off, fake_ip_pool) {
                Ok(parsed) => ParsedFamilyOutcome {
                    ips: parsed,
                    got_response: true,
                    saw_nxdomain,
                    saw_noerror,
                    err: None,
                },
                Err(e) => ParsedFamilyOutcome {
                    ips: Vec::new(),
                    got_response: true,
                    saw_nxdomain,
                    saw_noerror,
                    err: Some(e),
                },
            }
        }
        Ok(None) => ParsedFamilyOutcome {
            ips: Vec::new(),
            got_response: false,
            saw_nxdomain: false,
            saw_noerror: false,
            err: None,
        },
        Err(e) => ParsedFamilyOutcome {
            ips: Vec::new(),
            got_response: false,
            saw_nxdomain: false,
            saw_noerror: false,
            err: Some(e),
        },
    }
}

pub(crate) async fn resolve_via_upstream_dns_with_options(
    domain: &str,
    upstream_dns: SocketAddr,
    fake_ip_pool: Option<&FakeIpPool>,
    timeout: Duration,
    include_ipv6: bool,
) -> Result<Vec<IpAddr>> {
    let deadline = tokio::time::Instant::now() + timeout;
    let _permit = tokio::time::timeout(timeout, upstream_resolve_semaphore().acquire())
        .await
        .map_err(|_| anyhow::anyhow!("Upstream DNS concurrency wait timed out for {}", domain))?
        .context("Upstream DNS semaphore closed")?;

    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        bail!(
            "Upstream DNS resolution timed out for {} (server: {})",
            domain,
            upstream_dns
        );
    }

    let tx_a = csprng_u16();
    let (pkt_a, q_a) = build_dns_query_packet(tx_a, domain, 1)?;

    let (out_a, out_aaaa) = if include_ipv6 {
        let tx_aaaa = csprng_u16();
        let (pkt_aaaa, q_aaaa) = build_dns_query_packet(tx_aaaa, domain, 28)?;
        let fut_a = forward_upstream_udp(upstream_dns, &pkt_a, tx_a, &q_a, remaining);
        let fut_aaaa = forward_upstream_udp(upstream_dns, &pkt_aaaa, tx_aaaa, &q_aaaa, remaining);
        tokio::pin!(fut_a);
        tokio::pin!(fut_aaaa);

        // 先等任意一族返回；若已获有效 IP 或权威 NXDOMAIN，仅再给另一族短暂宽限窗口 (150ms)，
        // 避免企业/路由器 DNS 静默丢弃 AAAA 时把每次 Direct 建连拉满 1.5s~3s。
        tokio::select! {
            res_a = &mut fut_a => {
                let first = evaluate_family_response(res_a, &q_a, fake_ip_pool);
                let rem_now = deadline.saturating_duration_since(tokio::time::Instant::now());
                let wait_second = if !first.ips.is_empty() || first.saw_nxdomain {
                    DUAL_STACK_SECOND_FAMILY_GRACE.min(rem_now)
                } else {
                    rem_now
                };
                let second = if wait_second.is_zero() {
                    evaluate_family_response(Ok(None), &q_aaaa, fake_ip_pool)
                } else {
                    match tokio::time::timeout(wait_second, fut_aaaa).await {
                        Ok(res_aaaa) => evaluate_family_response(res_aaaa, &q_aaaa, fake_ip_pool),
                        Err(_) => evaluate_family_response(Ok(None), &q_aaaa, fake_ip_pool),
                    }
                };
                (first, Some(second))
            }
            res_aaaa = &mut fut_aaaa => {
                let first = evaluate_family_response(res_aaaa, &q_aaaa, fake_ip_pool);
                let rem_now = deadline.saturating_duration_since(tokio::time::Instant::now());
                let wait_second = if !first.ips.is_empty() || first.saw_nxdomain {
                    DUAL_STACK_SECOND_FAMILY_GRACE.min(rem_now)
                } else {
                    rem_now
                };
                let second = if wait_second.is_zero() {
                    evaluate_family_response(Ok(None), &q_a, fake_ip_pool)
                } else {
                    match tokio::time::timeout(wait_second, fut_a).await {
                        Ok(res_a) => evaluate_family_response(res_a, &q_a, fake_ip_pool),
                        Err(_) => evaluate_family_response(Ok(None), &q_a, fake_ip_pool),
                    }
                };
                (second, Some(first))
            }
        }
    } else {
        let res_a = forward_upstream_udp(upstream_dns, &pkt_a, tx_a, &q_a, remaining).await;
        (evaluate_family_response(res_a, &q_a, fake_ip_pool), None)
    };

    let mut ips = Vec::new();
    let mut got_response = false;
    let mut saw_nxdomain = false;
    let mut saw_noerror = false;
    let mut last_err: Option<anyhow::Error> = None;

    for outcome in [Some(out_a), out_aaaa].into_iter().flatten() {
        got_response |= outcome.got_response;
        saw_nxdomain |= outcome.saw_nxdomain;
        saw_noerror |= outcome.saw_noerror;
        for ip in outcome.ips {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
        if let Some(e) = outcome.err {
            last_err = Some(e);
        }
    }

    if !ips.is_empty() {
        return Ok(ips);
    }
    if saw_nxdomain && !saw_noerror {
        return Err(anyhow::Error::new(DnsNxDomainError {
            domain: domain.to_string(),
            server: upstream_dns,
        }));
    }
    if let Some(err) = last_err {
        return Err(err);
    }
    if !got_response {
        bail!(
            "Upstream DNS resolution timed out for {} (server: {})",
            domain,
            upstream_dns
        );
    }
    bail!(
        "No usable IP records returned by upstream DNS {} for {}",
        upstream_dns,
        domain
    )
}

pub(super) enum ForwardQueryOutcome {
    RateLimited,
    NoResponse,
    Response { bytes: Vec<u8>, ans_off: usize },
}

pub(super) async fn forward_raw_query_with_limit(
    upstream_limit: &Arc<Semaphore>,
    upstream_dns: SocketAddr,
    query_bytes: &[u8],
    client_tx_id: u16,
    question: &DnsQuestion,
    log_ctx: &str,
) -> ForwardQueryOutcome {
    let Ok(_up_permit) = Arc::clone(upstream_limit).try_acquire_owned() else {
        warn!(
            "[DNS Engine] Upstream forwarding limit reached ({}), dropping query: {}",
            log_ctx, question.name
        );
        return ForwardQueryOutcome::RateLimited;
    };
    let upstream_tx_id = csprng_u16();
    let mut forward_bytes = query_bytes.to_vec();
    forward_bytes[0..2].copy_from_slice(&upstream_tx_id.to_be_bytes());

    if let Ok(Some((mut resp_bytes, ans_off))) = forward_upstream_udp(
        upstream_dns,
        &forward_bytes,
        upstream_tx_id,
        question,
        UPSTREAM_DNS_TIMEOUT,
    )
    .await
    {
        resp_bytes[0..2].copy_from_slice(&client_tx_id.to_be_bytes());
        return ForwardQueryOutcome::Response {
            bytes: resp_bytes,
            ans_off,
        };
    }
    ForwardQueryOutcome::NoResponse
}
