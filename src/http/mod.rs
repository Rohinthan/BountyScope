use crate::error::HttpError;
use crate::scope::VerifiedScopeUrl;
use crate::storage::{AuditLogEntry, StorageEngine};
use bytes::{Bytes, BytesMut};
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
}

impl ScopedHttpClient {
    /// Creates a new `ScopedHttpClient` bound to a specific target program and rate limit.
    pub fn new(
        storage: StorageEngine,
        program_id: String,
        rate_limit_rps: u32,
    ) -> Result<Self, HttpError> {
        let rps = if rate_limit_rps == 0 {
            2
        } else {
            rate_limit_rps.min(100)
        };

        let min_interval = Duration::from_nanos(1_000_000_000 / rps as u64);

        // Client configured to strictly refuse automatic redirect following and enforce 10s timeout
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
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
        })
    }

    /// Dispatches a safe, rate-limited GET request to a verified target URL.
    ///
    /// The compile-time lock guarantees that `target` has been authenticated by `ScopeEnforcer`.
    pub async fn get(&self, target: &VerifiedScopeUrl) -> Result<HttpProbeResponse, HttpError> {
        self.get_with_headers(target, &[]).await
    }

    /// Dispatches a safe, rate-limited GET request to a verified target URL with custom headers.
    ///
    /// Useful for passive auditing checks such as CORS origin reflection probes.
    pub async fn get_with_headers(
        &self,
        target: &VerifiedScopeUrl,
        headers: &[(&str, &str)],
    ) -> Result<HttpProbeResponse, HttpError> {
        let mut limiter = self.rate_limiter.lock().await;
        let mut was_rate_limited = false;

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
        for (name, val) in headers {
            req_builder = req_builder.header(*name, *val);
        }

        let start_time = std::time::Instant::now();
        let request_result = req_builder.send().await;
        let duration_ms = start_time.elapsed().as_millis() as u64;

        match request_result {
            Ok(mut resp) => {
                let status_code = resp.status().as_u16();

                // Capture redirect location header if present (301, 302, 307, 308)
                let redirect_location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|val| val.to_str().ok().map(|s| s.to_string()));

                let mut headers = Vec::new();
                for (name, val) in resp.headers() {
                    if let Ok(v) = val.to_str() {
                        headers.push((name.as_str().to_string(), v.to_string()));
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

                Ok(HttpProbeResponse {
                    status_code,
                    headers,
                    body,
                    redirect_location,
                    duration_ms,
                    rate_limited: was_rate_limited,
                })
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

                Err(HttpError::Network(format!("HTTP request failed: {err}")))
            }
        }
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
}
