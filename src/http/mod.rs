use crate::error::HttpError;
use crate::scope::VerifiedScopeUrl;
use crate::storage::{AuditLogEntry, StorageEngine};
use bytes::{Bytes, BytesMut};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;

/// Maximum allowable HTTP response body size in bytes (5 MiB).
pub const MAX_RESPONSE_BODY_BYTES: usize = 5 * 1024 * 1024;

/// Structured response container for safe HTTP probes.
#[derive(Debug, Clone)]
pub struct HttpProbeResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    pub redirect_location: Option<String>,
    pub duration_ms: u64,
    pub rate_limited: bool,
}

impl HttpProbeResponse {
    /// Helper to retrieve the `Content-Type` header value, if present.
    pub fn content_type(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
    }

    /// Attempts to interpret response bytes as a UTF-8 string slice.
    pub fn body_as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }
}

/// Extracts the underlying IPv4 address if `ip` is an IPv4-mapped or IPv4-compatible IPv6 address.
pub fn unmap_ipv4_in_ipv6(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            // IPv4-mapped IPv6: ::ffff:a.b.c.d
            if octets[0..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff {
                IpAddr::V4(Ipv4Addr::new(
                    octets[12], octets[13], octets[14], octets[15],
                ))
            } else if octets[0..12] == [0; 12]
                && (octets[12] != 0 || octets[13] != 0 || octets[14] != 0 || octets[15] > 1)
            {
                // IPv4-compatible IPv6: ::a.b.c.d
                IpAddr::V4(Ipv4Addr::new(
                    octets[12], octets[13], octets[14], octets[15],
                ))
            } else {
                IpAddr::V6(v6)
            }
        }
    }
}

/// Evaluates whether an IP address belongs to loopback, private RFC 1918, link-local,
/// carrier-grade NAT (CGNAT), multicast, documentation, or unspecified non-public ranges.
pub fn is_restricted_ip(ip: IpAddr) -> bool {
    let unmapped = unmap_ipv4_in_ipv6(ip);
    match unmapped {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // Loopback 127.0.0.0/8
            o[0] == 127
            // RFC 1918 Private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            || o[0] == 10
            || (o[0] == 172 && (16..=31).contains(&o[1]))
            || (o[0] == 192 && o[1] == 168)
            // Link-local: 169.254.0.0/16
            || (o[0] == 169 && o[1] == 254)
            // CGNAT (RFC 6598): 100.64.0.0/10 (100.64.0.0 to 100.127.255.255)
            || (o[0] == 100 && (64..=127).contains(&o[1]))
            // Unspecified 0.0.0.0/8
            || o[0] == 0
            // Broadcast 255.255.255.255
            || v4.is_broadcast()
            // Multicast 224.0.0.0/4
            || v4.is_multicast()
            // IETF Protocol / Documentation: 192.0.0.0/24, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 198.18.0.0/15
            || (o[0] == 192 && o[1] == 0 && (o[2] == 0 || o[2] == 2))
            || (o[0] == 198 && o[1] == 51 && o[2] == 100)
            || (o[0] == 203 && o[1] == 0 && o[2] == 113)
            || (o[0] == 198 && (18..=19).contains(&o[1]))
            // Reserved for future use (240.0.0.0/4)
            || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            // Loopback ::1
            v6.is_loopback()
            // Unspecified ::
            || v6.is_unspecified()
            // Multicast ff00::/8
            || v6.is_multicast()
            // Link-local unicast fe80::/10
            || (o[0] == 0xfe && (o[1] & 0xc0) == 0x80)
            // Unique local unicast fc00::/7 (fc00:: - fdff::)
            || (o[0] & 0xfe) == 0xfc
            // Documentation 2001:db8::/32
            || (o[0] == 0x20 && o[1] == 0x01 && o[2] == 0x0d && o[3] == 0xb8)
            // Discard 100::/64
            || (o[0] == 0x01 && o[1] == 0x00 && o[2..8] == [0; 6])
        }
    }
}

/// Determines if a resolved IP address is permitted for a specific target host.
///
/// Public IPs are always permitted. Non-public / restricted IPs are strictly rejected
/// unless the target host or exact IP was explicitly allowlisted in `allowed_domains`
/// (e.g. `127.0.0.1` or `localhost` for local lab testing).
pub fn is_ip_allowed_for_host(ip: IpAddr, host: &str, allowed_domains: &[String]) -> bool {
    if !is_restricted_ip(ip) {
        return true;
    }

    let clean_host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let unmapped = unmap_ipv4_in_ipv6(ip);

    for pattern in allowed_domains {
        let clean_pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();

        // 1. Loopback target host explicitly allowlisted (e.g. localhost or 127.0.0.1)
        if (clean_host == "localhost" || clean_host == "127.0.0.1" || clean_host == "::1")
            && (clean_pattern == "localhost"
                || clean_pattern == "127.0.0.1"
                || clean_pattern == "::1")
        {
            return true;
        }

        // 2. Exact match where host is an explicit IP that matches the allowlist pattern
        if clean_host == clean_pattern {
            if let Ok(pat_ip) = clean_pattern.parse::<IpAddr>() {
                if unmap_ipv4_in_ipv6(pat_ip) == unmapped {
                    return true;
                }
            }
        }
    }

    false
}

type CustomLookupFn = Arc<dyn Fn(&str) -> Option<Vec<SocketAddr>> + Send + Sync>;

/// Custom DNS resolver enforcing socket-level IP boundary guards right before TCP socket creation.
///
/// Intercepts hostname resolution and verifies that every resolved `SocketAddr` points to a permitted
/// destination, preventing DNS rebinding and Server-Side Request Forgery (SSRF) targeting internal IPs.
#[derive(Clone)]
pub struct ScopeAwareDnsResolver {
    allowed_domains: Vec<String>,
    custom_lookup: Option<CustomLookupFn>,
}

impl ScopeAwareDnsResolver {
    /// Creates a new `ScopeAwareDnsResolver` bound to the program's configured `allowed_domains`.
    pub fn new(allowed_domains: Vec<String>) -> Self {
        Self {
            allowed_domains,
            custom_lookup: None,
        }
    }

    /// Attaches an optional simulated lookup hook (primarily for deterministic unit testing).
    pub fn with_custom_lookup<F>(mut self, lookup: F) -> Self
    where
        F: Fn(&str) -> Option<Vec<SocketAddr>> + Send + Sync + 'static,
    {
        self.custom_lookup = Some(Arc::new(lookup));
        self
    }
}

impl Resolve for ScopeAwareDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let allowed_domains = self.allowed_domains.clone();
        let custom_lookup = self.custom_lookup.clone();

        Box::pin(async move {
            let mut resolved_addrs: Vec<SocketAddr> = Vec::new();

            if let Some(ref lookup) = custom_lookup {
                if let Some(simulated) = lookup(&host) {
                    resolved_addrs.extend(simulated);
                }
            }

            if resolved_addrs.is_empty() {
                match tokio::net::lookup_host((host.as_str(), 0)).await {
                    Ok(iter) => {
                        resolved_addrs.extend(iter);
                    }
                    Err(err) => {
                        return Err(Box::new(std::io::Error::other(format!(
                            "DNS resolution failed for '{host}': {err}"
                        )))
                            as Box<dyn std::error::Error + Send + Sync>);
                    }
                }
            }

            let mut allowed_addrs: Vec<SocketAddr> = Vec::new();
            let mut blocked_ips: Vec<IpAddr> = Vec::new();

            for addr in resolved_addrs {
                if is_ip_allowed_for_host(addr.ip(), &host, &allowed_domains) {
                    allowed_addrs.push(addr);
                } else {
                    blocked_ips.push(addr.ip());
                }
            }

            if allowed_addrs.is_empty() {
                let err_msg = if !blocked_ips.is_empty() {
                    let ips_str = blocked_ips
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!(
                        "DNS resolution for '{host}' blocked by scope policy: resolved to restricted IP address(es) [{ips_str}]"
                    )
                } else {
                    format!("DNS resolution for '{host}' returned no valid IP addresses")
                };

                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    err_msg,
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            let addrs_box: Addrs = Box::new(allowed_addrs.into_iter());
            Ok(addrs_box)
        })
    }
}

/// Internal state tracker for deterministic inter-request spacing.
struct RateLimiterState {
    last_request_instant: Option<Instant>,
}

/// A scope-locked, rate-limited HTTP probe client.
///
/// Compile-Time Invariant:
/// Outbound requests can ONLY be initiated by passing a `&VerifiedScopeUrl`.
/// Passing a raw `&str` or arbitrary `Url` is prohibited at compile time.
#[derive(Clone)]
pub struct ScopedHttpClient {
    client: reqwest::Client,
    storage: StorageEngine,
    program_id: String,
    rate_limiter: Arc<Mutex<RateLimiterState>>,
    min_interval: Duration,
    researcher_handle: Option<String>,
}

impl ScopedHttpClient {
    /// Creates a new `ScopedHttpClient` bound to a specific target program and rate limit.
    pub fn new(
        storage: StorageEngine,
        program_id: String,
        rate_limit_rps: u32,
    ) -> Result<Self, HttpError> {
        let allowed_domains = storage.get_allowed_domains(&program_id).unwrap_or_default();
        let resolver = Arc::new(ScopeAwareDnsResolver::new(allowed_domains));
        Self::new_with_resolver(storage, program_id, rate_limit_rps, resolver)
    }

    /// Creates a `ScopedHttpClient` with a customized `ScopeAwareDnsResolver`.
    pub fn new_with_resolver(
        storage: StorageEngine,
        program_id: String,
        rate_limit_rps: u32,
        resolver: Arc<ScopeAwareDnsResolver>,
    ) -> Result<Self, HttpError> {
        let rps = if rate_limit_rps == 0 {
            2
        } else {
            rate_limit_rps.min(100)
        };

        let min_interval = Duration::from_nanos(1_000_000_000 / rps as u64);

        // Client configured to strictly refuse automatic redirect following, enforce 10s timeout,
        // and enforce socket-level DNS IP inspection via ScopeAwareDnsResolver
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .dns_resolver(resolver)
            .build()
            .map_err(|e| {
                HttpError::Initialization(format!("failed to configure HTTP client: {e}"))
            })?;

        Ok(Self {
            client,
            storage,
            program_id,
            rate_limiter: Arc::new(Mutex::new(RateLimiterState {
                last_request_instant: None,
            })),
            min_interval,
            researcher_handle: None,
        })
    }

    /// Attaches an optional researcher handle for attribution via `X-Bug-Bounty` on outbound requests.
    pub fn with_researcher_handle(mut self, handle: Option<String>) -> Self {
        self.researcher_handle = handle;
        self
    }

    /// Dispatches a safe, rate-limited GET request to a verified target URL.
    ///
    /// The compile-time lock guarantees that `target` has been authenticated by `ScopeEnforcer`.
    pub async fn get(&self, target: &VerifiedScopeUrl) -> Result<HttpProbeResponse, HttpError> {
        self.get_with_headers(target, &[]).await
    }

    /// Dispatches a safe, rate-limited GET request to a verified target URL with custom headers.
    ///
    /// Dispatches a safe, rate-limited GET request to a verified target URL with custom headers.
    ///
    /// Useful for passive auditing checks such as CORS origin reflection probes.
    pub async fn get_with_headers(
        &self,
        target: &VerifiedScopeUrl,
        headers: &[(&str, &str)],
    ) -> Result<HttpProbeResponse, HttpError> {
        const MAX_RATE_LIMIT_RETRIES: u32 = 2;
        const MAX_RETRY_AFTER_SECS: u64 = 5;

        let mut was_rate_limited = false;

        for attempt in 0..=MAX_RATE_LIMIT_RETRIES {
            let mut limiter = self.rate_limiter.lock().await;

            if let Some(last) = limiter.last_request_instant {
                let elapsed = last.elapsed();
                if elapsed < self.min_interval {
                    let delay = self.min_interval - elapsed;
                    was_rate_limited = true;
                    tokio::time::sleep(delay).await;
                }
            }

            limiter.last_request_instant = Some(Instant::now());
            drop(limiter);

            let mut req_builder = self.client.get(target.as_str());
            if let Some(handle) = &self.researcher_handle {
                req_builder = req_builder.header("X-Bug-Bounty", handle);
            }
            for (name, val) in headers {
                req_builder = req_builder.header(*name, *val);
            }

            let start_time = std::time::Instant::now();
            let request_result = req_builder.send().await;
            let duration_ms = start_time.elapsed().as_millis() as u64;

            match request_result {
                Ok(mut resp) => {
                    let status_code = resp.status().as_u16();

                    if status_code == 429 || status_code == 503 {
                        was_rate_limited = true;
                        let audit_entry = AuditLogEntry {
                            program_id: self.program_id.clone(),
                            target_url: target.as_str().to_string(),
                            http_method: "GET".to_string(),
                            status_code: Some(status_code),
                            duration_ms,
                            rate_limited: true,
                        };
                        self.storage.record_audit_log(&audit_entry)?;

                        if attempt < MAX_RATE_LIMIT_RETRIES {
                            let backoff = if let Some(retry_after_val) =
                                resp.headers().get(reqwest::header::RETRY_AFTER)
                            {
                                if let Ok(retry_str) = retry_after_val.to_str() {
                                    if let Ok(secs) = retry_str.trim().parse::<u64>() {
                                        Duration::from_secs(secs.min(MAX_RETRY_AFTER_SECS))
                                    } else {
                                        Duration::from_millis(if attempt == 0 { 500 } else { 1000 })
                                    }
                                } else {
                                    Duration::from_millis(if attempt == 0 { 500 } else { 1000 })
                                }
                            } else {
                                Duration::from_millis(if attempt == 0 { 500 } else { 1000 })
                            };

                            tokio::time::sleep(backoff).await;
                            continue;
                        } else {
                            return Err(HttpError::RateLimitExhausted(status_code));
                        }
                    }

                    // Capture redirect location header if present (301, 302, 307, 308)
                    let redirect_location = resp
                        .headers()
                        .get(reqwest::header::LOCATION)
                        .and_then(|val| val.to_str().ok().map(|s| s.to_string()));

                    let mut resp_headers = Vec::new();
                    for (name, val) in resp.headers() {
                        if let Ok(v) = val.to_str() {
                            resp_headers.push((name.as_str().to_string(), v.to_string()));
                        }
                    }

                    // Enforce maximum payload size limit on Content-Length header if available
                    if let Some(content_length) = resp.content_length() {
                        if content_length > MAX_RESPONSE_BODY_BYTES as u64 {
                            let audit_entry = AuditLogEntry {
                                program_id: self.program_id.clone(),
                                target_url: target.as_str().to_string(),
                                http_method: "GET".to_string(),
                                status_code: Some(status_code),
                                duration_ms,
                                rate_limited: was_rate_limited,
                            };
                            self.storage.record_audit_log(&audit_entry)?;
                            return Err(HttpError::PayloadTooLarge(
                                content_length as usize,
                                MAX_RESPONSE_BODY_BYTES,
                            ));
                        }
                    }

                    // Stream response body chunks while enforcing maximum payload size limit
                    let mut body_buf = BytesMut::new();
                    while let Some(chunk) = resp.chunk().await.map_err(|e| {
                        HttpError::Network(format!("failed to read response chunk: {e}"))
                    })? {
                        if body_buf.len() + chunk.len() > MAX_RESPONSE_BODY_BYTES {
                            let audit_entry = AuditLogEntry {
                                program_id: self.program_id.clone(),
                                target_url: target.as_str().to_string(),
                                http_method: "GET".to_string(),
                                status_code: Some(status_code),
                                duration_ms,
                                rate_limited: was_rate_limited,
                            };
                            self.storage.record_audit_log(&audit_entry)?;
                            return Err(HttpError::PayloadTooLarge(
                                body_buf.len() + chunk.len(),
                                MAX_RESPONSE_BODY_BYTES,
                            ));
                        }
                        body_buf.extend_from_slice(&chunk);
                    }
                    let body = body_buf.freeze();

                    // Persist outbound request metadata in the audit log
                    let audit_entry = AuditLogEntry {
                        program_id: self.program_id.clone(),
                        target_url: target.as_str().to_string(),
                        http_method: "GET".to_string(),
                        status_code: Some(status_code),
                        duration_ms,
                        rate_limited: was_rate_limited,
                    };
                    self.storage.record_audit_log(&audit_entry)?;

                    return Ok(HttpProbeResponse {
                        status_code,
                        headers: resp_headers,
                        body,
                        redirect_location,
                        duration_ms,
                        rate_limited: was_rate_limited,
                    });
                }
                Err(err) => {
                    // Record failed interaction in audit log for transparency
                    let audit_entry = AuditLogEntry {
                        program_id: self.program_id.clone(),
                        target_url: target.as_str().to_string(),
                        http_method: "GET".to_string(),
                        status_code: None,
                        duration_ms,
                        rate_limited: was_rate_limited,
                    };
                    self.storage.record_audit_log(&audit_entry)?;

                    let mut detailed_msg = err.to_string();
                    let mut current_err: Option<&(dyn std::error::Error + 'static)> =
                        std::error::Error::source(&err);
                    while let Some(cause) = current_err {
                        detailed_msg.push_str(": ");
                        detailed_msg.push_str(&cause.to_string());
                        current_err = cause.source();
                    }

                    return Err(HttpError::Network(format!(
                        "HTTP request failed: {detailed_msg}"
                    )));
                }
            }
        }

        Err(HttpError::Network(
            "unexpected retry termination".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::{ScopeConfig, ScopeEnforcer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn test_scope_config(_port: u16) -> ScopeConfig {
        ScopeConfig {
            program_name: "test-http-program".to_string(),
            platform: "local".to_string(),
            allowed_domains: vec!["127.0.0.1".to_string()],
            excluded_domains: vec![],
            excluded_paths: vec![],
            rate_limit_rps: 10,
            safe_mode: true,
            researcher_handle: None,
            policy_url: None,
            excluded_checks: vec![],
        }
    }

    #[tokio::test]
    async fn test_redirect_not_followed_automatically() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
        let addr = listener.local_addr().expect("local_addr failed");
        let port = addr.port();

        // Spawn mock server returning HTTP 302 Found with Location
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:8080/redirected\r\nContent-Length: 0\r\n\r\n";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let storage = StorageEngine::open_in_memory().expect("storage open failed");
        let config = test_scope_config(port);
        let program_id = storage
            .upsert_program_scope(&config)
            .expect("upsert failed");
        let enforcer = ScopeEnforcer::new(config).expect("enforcer failed");

        let client =
            ScopedHttpClient::new(storage, program_id, 10).expect("client creation failed");
        let target_url = format!("http://127.0.0.1:{}/redirect-source", port);
        let verified = enforcer
            .validate_url(&target_url)
            .expect("scope validation failed");

        let response = client.get(&verified).await.expect("request failed");

        // Must preserve 302 status code and NOT follow to target
        assert_eq!(response.status_code, 302);
        assert_eq!(
            response.redirect_location,
            Some("http://127.0.0.1:8080/redirected".to_string())
        );
    }

    #[tokio::test]
    async fn test_rate_limiting_spacing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
        let addr = listener.local_addr().expect("local_addr failed");
        let port = addr.port();

        tokio::spawn(async move {
            for _ in 0..2 {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                    let _ = socket.write_all(response.as_bytes()).await;
                }
            }
        });

        let storage = StorageEngine::open_in_memory().expect("storage open failed");
        let mut config = test_scope_config(port);
        config.rate_limit_rps = 1; // 1000ms spacing between requests
        let program_id = storage
            .upsert_program_scope(&config)
            .expect("upsert failed");
        let enforcer = ScopeEnforcer::new(config).expect("enforcer failed");

        let client =
            ScopedHttpClient::new(storage.clone(), program_id.clone(), 1).expect("client failed");
        let target_url = format!("http://127.0.0.1:{}/test", port);
        let verified = enforcer
            .validate_url(&target_url)
            .expect("validation failed");

        let (res1, res2) = tokio::join!(client.get(&verified), client.get(&verified));
        let r1 = res1.expect("call 1 failed");
        let r2 = res2.expect("call 2 failed");

        assert_eq!(r1.status_code, 200);
        assert_eq!(r2.status_code, 200);
        assert!(r1.rate_limited || r2.rate_limited);

        let logs = storage.get_audit_logs(&program_id).expect("logs failed");
        assert_eq!(logs.len(), 2);
        assert!(logs.iter().any(|l| l.rate_limited));
        assert!(logs.iter().any(|l| !l.rate_limited));
    }

    #[tokio::test]
    async fn test_payload_too_large_rejection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
        let addr = listener.local_addr().expect("local_addr failed");
        let port = addr.port();

        // Server advertises Content-Length exceeding MAX_RESPONSE_BODY_BYTES
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let oversized = (MAX_RESPONSE_BODY_BYTES + 1024).to_string();
                let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {oversized}\r\n\r\n");
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let storage = StorageEngine::open_in_memory().expect("storage open failed");
        let config = test_scope_config(port);
        let program_id = storage
            .upsert_program_scope(&config)
            .expect("upsert failed");
        let enforcer = ScopeEnforcer::new(config).expect("enforcer failed");

        let client =
            ScopedHttpClient::new(storage.clone(), program_id.clone(), 10).expect("client failed");
        let target_url = format!("http://127.0.0.1:{}/oversized", port);
        let verified = enforcer
            .validate_url(&target_url)
            .expect("validation failed");

        let result = client.get(&verified).await;
        match result {
            Err(HttpError::PayloadTooLarge(size, limit)) => {
                assert_eq!(size, MAX_RESPONSE_BODY_BYTES + 1024);
                assert_eq!(limit, MAX_RESPONSE_BODY_BYTES);
            }
            other => panic!("expected PayloadTooLarge error, got {:?}", other),
        }

        // Verify audit log entry was still recorded
        let logs = storage.get_audit_logs(&program_id).expect("logs failed");
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].status_code, Some(200));
    }

    #[tokio::test]
    async fn test_researcher_handle_attribution_header() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
        let addr = listener.local_addr().expect("local_addr failed");
        let port = addr.port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                let has_handle = req.contains("x-bug-bounty: bug-hunter-123");
                let status = if has_handle {
                    "200 OK"
                } else {
                    "400 Bad Request"
                };
                let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n");
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let storage = StorageEngine::open_in_memory().expect("storage open failed");
        let config = test_scope_config(port);
        let program_id = storage
            .upsert_program_scope(&config)
            .expect("upsert failed");
        let enforcer = ScopeEnforcer::new(config).expect("enforcer failed");

        let client = ScopedHttpClient::new(storage.clone(), program_id.clone(), 10)
            .expect("client failed")
            .with_researcher_handle(Some("bug-hunter-123".to_string()));

        let target_url = format!("http://127.0.0.1:{}/attribution", port);
        let verified = enforcer
            .validate_url(&target_url)
            .expect("validation failed");

        let response = client.get(&verified).await.expect("request failed");
        assert_eq!(response.status_code, 200);
    }

    #[tokio::test]
    async fn test_retry_after_backoff_and_rate_limited_audit_logging() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
        let addr = listener.local_addr().expect("local_addr failed");
        let port = addr.port();

        // Spawn mock server returning HTTP 429 on first attempt, then HTTP 200 on retry
        tokio::spawn(async move {
            let mut attempt = 0;
            while attempt < 2 {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    if attempt == 0 {
                        let response = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else {
                        let response =
                            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nOK";
                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                    attempt += 1;
                }
            }
        });

        let storage = StorageEngine::open_in_memory().expect("storage open failed");
        let mut config = test_scope_config(port);
        config.rate_limit_rps = 100;
        let program_id = storage
            .upsert_program_scope(&config)
            .expect("upsert failed");
        let enforcer = ScopeEnforcer::new(config).expect("enforcer failed");

        let client =
            ScopedHttpClient::new(storage.clone(), program_id.clone(), 100).expect("client failed");
        let target_url = format!("http://127.0.0.1:{}/rate-limit-test", port);
        let verified = enforcer
            .validate_url(&target_url)
            .expect("validation failed");

        let response = client
            .get(&verified)
            .await
            .expect("request should succeed after retry");
        assert_eq!(response.status_code, 200);
        assert!(response.rate_limited);

        let logs = storage.get_audit_logs(&program_id).expect("logs failed");
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].status_code, Some(429));
        assert!(logs[0].rate_limited);
        assert_eq!(logs[1].status_code, Some(200));
        assert!(logs[1].rate_limited);
    }

    #[tokio::test]
    async fn test_retry_exhausted_on_consecutive_429() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
        let addr = listener.local_addr().expect("local_addr failed");
        let port = addr.port();

        // Spawn mock server returning HTTP 429 on all attempts
        tokio::spawn(async move {
            let mut attempt = 0;
            while attempt < 3 {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    let response = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                    let _ = socket.write_all(response.as_bytes()).await;
                    attempt += 1;
                }
            }
        });

        let storage = StorageEngine::open_in_memory().expect("storage open failed");
        let mut config = test_scope_config(port);
        config.rate_limit_rps = 100;
        let program_id = storage
            .upsert_program_scope(&config)
            .expect("upsert failed");
        let enforcer = ScopeEnforcer::new(config).expect("enforcer failed");

        let client =
            ScopedHttpClient::new(storage.clone(), program_id.clone(), 100).expect("client failed");
        let target_url = format!("http://127.0.0.1:{}/exhaust-test", port);
        let verified = enforcer
            .validate_url(&target_url)
            .expect("validation failed");

        let result = client.get(&verified).await;
        match result {
            Err(HttpError::RateLimitExhausted(status)) => {
                assert_eq!(status, 429);
            }
            other => panic!("expected RateLimitExhausted(429), got {:?}", other),
        }

        let logs = storage.get_audit_logs(&program_id).expect("logs failed");
        assert_eq!(logs.len(), 3);
        for entry in &logs {
            assert_eq!(entry.status_code, Some(429));
            assert!(entry.rate_limited);
        }
    }

    #[test]
    fn test_ip_classification_restricted_and_allowed_rules() {
        // 1. Loopback addresses
        assert!(is_restricted_ip("127.0.0.1".parse().expect("ip")));
        assert!(is_restricted_ip("127.255.0.1".parse().expect("ip")));
        assert!(is_restricted_ip("::1".parse().expect("ip")));

        // 2. RFC 1918 private addresses
        assert!(is_restricted_ip("10.0.0.1".parse().expect("ip")));
        assert!(is_restricted_ip("10.254.1.1".parse().expect("ip")));
        assert!(is_restricted_ip("172.16.0.1".parse().expect("ip")));
        assert!(is_restricted_ip("172.31.255.254".parse().expect("ip")));
        assert!(is_restricted_ip("192.168.1.1".parse().expect("ip")));

        // 3. Link-local (including AWS metadata)
        assert!(is_restricted_ip("169.254.169.254".parse().expect("ip")));
        assert!(is_restricted_ip("fe80::1".parse().expect("ip")));

        // 4. CGNAT (RFC 6598)
        assert!(is_restricted_ip("100.64.0.1".parse().expect("ip")));
        assert!(is_restricted_ip("100.127.255.254".parse().expect("ip")));

        // 5. Unspecified & multicast
        assert!(is_restricted_ip("0.0.0.0".parse().expect("ip")));
        assert!(is_restricted_ip("::".parse().expect("ip")));
        assert!(is_restricted_ip("224.0.0.1".parse().expect("ip")));
        assert!(is_restricted_ip("ff02::1".parse().expect("ip")));

        // 6. IPv4-mapped IPv6 addresses
        assert!(is_restricted_ip("::ffff:127.0.0.1".parse().expect("ip")));
        assert!(is_restricted_ip(
            "::ffff:169.254.169.254".parse().expect("ip")
        ));
        assert!(is_restricted_ip("::ffff:10.0.0.1".parse().expect("ip")));
        assert!(is_restricted_ip("::ffff:192.168.0.1".parse().expect("ip")));

        // 7. Public routable IP addresses (must NOT be restricted)
        assert!(!is_restricted_ip("93.184.216.34".parse().expect("ip")));
        assert!(!is_restricted_ip("8.8.8.8".parse().expect("ip")));
        assert!(!is_restricted_ip("1.1.1.1".parse().expect("ip")));
        assert!(!is_restricted_ip(
            "2606:2800:220:1:248:1893:25c8:1946".parse().expect("ip")
        ));

        // Test host-level evaluation with allowlist
        let standard_allowed = vec!["example.com".to_string(), "*.example.com".to_string()];
        // Public IP is allowed
        assert!(is_ip_allowed_for_host(
            "93.184.216.34".parse().expect("ip"),
            "sub.example.com",
            &standard_allowed
        ));
        // Restricted IPs are blocked for standard domain names
        assert!(!is_ip_allowed_for_host(
            "127.0.0.1".parse().expect("ip"),
            "sub.example.com",
            &standard_allowed
        ));
        assert!(!is_ip_allowed_for_host(
            "10.0.0.1".parse().expect("ip"),
            "sub.example.com",
            &standard_allowed
        ));
        assert!(!is_ip_allowed_for_host(
            "169.254.169.254".parse().expect("ip"),
            "sub.example.com",
            &standard_allowed
        ));
        assert!(!is_ip_allowed_for_host(
            "::ffff:127.0.0.1".parse().expect("ip"),
            "sub.example.com",
            &standard_allowed
        ));

        // When loopback is explicitly allowlisted
        let local_allowed = vec!["127.0.0.1".to_string(), "localhost".to_string()];
        assert!(is_ip_allowed_for_host(
            "127.0.0.1".parse().expect("ip"),
            "127.0.0.1",
            &local_allowed
        ));
        assert!(is_ip_allowed_for_host(
            "127.0.0.1".parse().expect("ip"),
            "localhost",
            &local_allowed
        ));
        assert!(is_ip_allowed_for_host(
            "::1".parse().expect("ip"),
            "localhost",
            &local_allowed
        ));
        // But a rebind domain is still blocked even if local lab allowlists 127.0.0.1!
        assert!(!is_ip_allowed_for_host(
            "127.0.0.1".parse().expect("ip"),
            "rebind.example.com",
            &local_allowed
        ));
    }

    #[tokio::test]
    async fn test_explicit_allowlisted_loopback_connects_normally() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
        let addr = listener.local_addr().expect("local_addr failed");
        let port = addr.port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let storage = StorageEngine::open_in_memory().expect("storage open failed");
        let config = test_scope_config(port);
        let program_id = storage
            .upsert_program_scope(&config)
            .expect("upsert failed");
        let enforcer = ScopeEnforcer::new(config).expect("enforcer failed");

        let client =
            ScopedHttpClient::new(storage.clone(), program_id.clone(), 10).expect("client failed");
        let target_url = format!("http://127.0.0.1:{}/lab-test", port);
        let verified = enforcer
            .validate_url(&target_url)
            .expect("validation failed");

        let response = client.get(&verified).await.expect("request should succeed");
        assert_eq!(response.status_code, 200);
    }

    #[tokio::test]
    async fn test_hostname_resolving_to_blocked_internal_ip_fails_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
        let addr = listener.local_addr().expect("local_addr failed");
        let port = addr.port();

        // Server should NOT receive any request because DNS fails closed before socket connect
        let server_received = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server_flag = server_received.clone();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                server_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let storage = StorageEngine::open_in_memory().expect("storage open failed");
        let mut config = test_scope_config(port);
        // Only public domains allowed - no 127.0.0.1 allowlisted
        config.allowed_domains = vec!["example.com".to_string(), "*.example.com".to_string()];
        let program_id = storage
            .upsert_program_scope(&config)
            .expect("upsert failed");
        let enforcer = ScopeEnforcer::new(config).expect("enforcer failed");

        // Custom resolver simulating DNS resolution for rebind.example.com returning 127.0.0.1
        let resolver = Arc::new(
            ScopeAwareDnsResolver::new(vec![
                "example.com".to_string(),
                "*.example.com".to_string(),
            ])
            .with_custom_lookup(move |host| {
                if host == "rebind.example.com" {
                    Some(vec![SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                        port,
                    )])
                } else {
                    None
                }
            }),
        );

        let client =
            ScopedHttpClient::new_with_resolver(storage.clone(), program_id.clone(), 10, resolver)
                .expect("client creation failed");

        let target_url = format!("http://rebind.example.com:{}/admin/secret", port);
        let verified = enforcer
            .validate_url(&target_url)
            .expect("ScopeEnforcer approves domain since *.example.com is in scope");

        let result = client.get(&verified).await;
        match result {
            Err(HttpError::Network(msg)) => {
                assert!(
                    msg.contains("DNS resolution for 'rebind.example.com' blocked by scope policy"),
                    "unexpected error message: {msg}"
                );
                assert!(msg.contains("127.0.0.1"), "unexpected error message: {msg}");
            }
            other => panic!("expected Network error due to DNS block, got {:?}", other),
        }

        // Verify that no connection reached the mock server
        assert!(
            !server_received.load(std::sync::atomic::Ordering::SeqCst),
            "mock server received unexpected connection"
        );

        // Verify audit log captured the failed interaction
        let logs = storage.get_audit_logs(&program_id).expect("logs failed");
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].status_code, None);
    }

    #[tokio::test]
    async fn test_hostname_resolving_to_ipv4_mapped_internal_ip_fails_closed() {
        let storage = StorageEngine::open_in_memory().expect("storage open failed");
        let mut config = test_scope_config(8080);
        config.allowed_domains = vec!["example.com".to_string(), "*.example.com".to_string()];
        let program_id = storage
            .upsert_program_scope(&config)
            .expect("upsert failed");
        let enforcer = ScopeEnforcer::new(config).expect("enforcer failed");

        // Custom resolver simulating DNS resolution for metadata.example.com returning ::ffff:169.254.169.254
        let resolver = Arc::new(
            ScopeAwareDnsResolver::new(vec![
                "example.com".to_string(),
                "*.example.com".to_string(),
            ])
            .with_custom_lookup(|host| {
                if host == "metadata.example.com" {
                    let mapped_v6: IpAddr = "::ffff:169.254.169.254".parse().expect("mapped ip");
                    Some(vec![SocketAddr::new(mapped_v6, 80)])
                } else {
                    None
                }
            }),
        );

        let client =
            ScopedHttpClient::new_with_resolver(storage.clone(), program_id.clone(), 10, resolver)
                .expect("client creation failed");

        let target_url = "http://metadata.example.com/latest/meta-data/";
        let verified = enforcer.validate_url(target_url).expect("domain in scope");

        let result = client.get(&verified).await;
        match result {
            Err(HttpError::Network(msg)) => {
                assert!(
                    msg.contains(
                        "DNS resolution for 'metadata.example.com' blocked by scope policy"
                    ),
                    "unexpected error message: {msg}"
                );
                assert!(
                    msg.contains("169.254.169.254"),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected Network error due to DNS block, got {:?}", other),
        }
    }
}
