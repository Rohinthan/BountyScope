use crate::error::CtError;
use crate::scope::ScopeEnforcer;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;
use std::time::Duration;

/// Represents a passively discovered subdomain from Certificate Transparency logs.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct DiscoveredSubdomain {
    pub hostname: String,
    pub url: String,
    pub source: String,
}

/// Raw certificate record returned by crt.sh JSON API.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CrtShEntry {
    pub issuer_ca_id: Option<i64>,
    pub issuer_name: Option<String>,
    pub common_name: Option<String>,
    pub name_value: Option<String>,
    pub id: Option<i64>,
    pub entry_timestamp: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub serial_number: Option<String>,
}

/// Passive Certificate Transparency client for querying public CT logs (crt.sh).
#[derive(Clone)]
pub struct CtLogDiscoverer {
    client: reqwest::Client,
    timeout: Duration,
    user_agent: String,
    base_endpoint: String,
}

impl CtLogDiscoverer {
    /// Creates a new `CtLogDiscoverer` with configurable timeout and operator attribution.
    pub fn new(
        timeout: Duration,
        user_agent: Option<&str>,
        researcher_handle: Option<&str>,
    ) -> Result<Self, CtError> {
        let ua = match (user_agent, researcher_handle) {
            (Some(ua), _) => ua.to_string(),
            (None, Some(h)) => format!(
                "BountyScope/0.17.1 (Security Assessment Engine; handle: {}; +https://github.com/Rohinthan/BountyScope)",
                h
            ),
            (None, None) => {
                "BountyScope/0.17.1 (Security Assessment Engine; +https://github.com/Rohinthan/BountyScope)".to_string()
            }
        };

        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| CtError::Network(e.to_string()))?;

        Ok(Self {
            client,
            timeout,
            user_agent: ua,
            base_endpoint: "https://crt.sh".to_string(),
        })
    }

    /// Returns the configured query timeout duration.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Overrides the base endpoint for offline unit & integration testing.
    pub fn with_base_endpoint(mut self, endpoint: &str) -> Self {
        self.base_endpoint = endpoint.trim_end_matches('/').to_string();
        self
    }

    /// Extracts eligible registered base domains from `allowed_domains`.
    ///
    /// Filters out:
    /// - Raw IPv4 and IPv6 addresses
    /// - Localhost, loopback, and local/reserved TLDs (`.local`, `.internal`, `.lan`, `.invalid`, etc.)
    /// - Single-label hostnames or public suffix wildcards (`*`, `com`)
    /// - Subsumed subdomains when a parent domain is already present (e.g. `example.com` covers `api.example.com`)
    pub fn extract_eligible_base_domains(allowed_domains: &[String]) -> Vec<String> {
        let mut candidates = HashSet::new();

        for domain in allowed_domains {
            let trimmed = domain.trim().to_ascii_lowercase();
            let stripped = trimmed.trim_start_matches('*').trim_start_matches('.');

            if stripped.is_empty() || stripped.contains('*') {
                continue;
            }

            // Exclude IP addresses
            if stripped.parse::<IpAddr>().is_ok() {
                continue;
            }

            // Exclude localhost and reserved / internal suffixes
            if stripped == "localhost"
                || stripped.ends_with(".local")
                || stripped.ends_with(".internal")
                || stripped.ends_with(".lan")
                || stripped.ends_with(".home")
                || stripped.ends_with(".invalid")
                || stripped.ends_with(".example")
                || stripped.ends_with(".test")
                || stripped.ends_with(".onion")
            {
                continue;
            }

            // Must contain at least one dot (not a top-level domain alone)
            if !stripped.contains('.') || stripped.starts_with('.') || stripped.ends_with('.') {
                continue;
            }

            candidates.insert(stripped.to_string());
        }

        // Deduplicate child domains if their parent domain is also present
        let mut sorted: Vec<String> = candidates.into_iter().collect();
        sorted.sort_by_key(|d| d.len());

        let mut eligible: Vec<String> = Vec::new();
        for domain in sorted {
            let is_subsumed = eligible
                .iter()
                .any(|parent| domain.ends_with(&format!(".{parent}")));
            if !is_subsumed {
                eligible.push(domain);
            }
        }

        eligible.sort();
        eligible
    }

    /// Parses crt.sh JSON array string, extracts hostnames from `common_name` and `name_value` SANs,
    /// normalizes them, and enforces strict `ScopeEnforcer::validate_url` boundaries.
    pub fn parse_crtsh_json(
        json_str: &str,
        enforcer: &ScopeEnforcer,
    ) -> Result<Vec<DiscoveredSubdomain>, CtError> {
        let trimmed = json_str.trim();
        if trimmed.is_empty() || trimmed == "[]" {
            return Ok(Vec::new());
        }

        let entries: Vec<CrtShEntry> = serde_json::from_str(trimmed)?;
        let mut seen = BTreeSet::new();

        for entry in entries {
            let mut raw_names = Vec::new();
            if let Some(ref cn) = entry.common_name {
                raw_names.push(cn.as_str());
            }
            if let Some(ref nv) = entry.name_value {
                for line in nv.lines() {
                    raw_names.push(line);
                }
            }

            for raw in raw_names {
                let trimmed_name = raw.trim();
                if trimmed_name.is_empty() {
                    continue;
                }

                // Lowercase
                let lower = trimmed_name.to_ascii_lowercase();

                // Strip leading wildcards (*. or *)
                let mut stripped = lower.as_str();
                while stripped.starts_with('*') || stripped.starts_with('.') {
                    stripped = stripped.trim_start_matches('*').trim_start_matches('.');
                }

                if stripped.is_empty() {
                    continue;
                }

                // Validate hostname contains only valid domain characters
                if !stripped
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
                {
                    continue;
                }

                // Hostname must contain at least one dot and cannot end with dot
                if !stripped.contains('.') || stripped.ends_with('.') {
                    continue;
                }

                // Strict Scope Gate: validate URL through ScopeEnforcer
                let candidate_url = format!("https://{stripped}/");
                if let Ok(verified) = enforcer.validate_url(&candidate_url) {
                    let host = verified.as_url().host_str().unwrap_or(stripped).to_string();
                    let url = format!("https://{host}/");
                    seen.insert(DiscoveredSubdomain {
                        hostname: host,
                        url,
                        source: "ct_log".to_string(),
                    });
                }
            }
        }

        Ok(seen.into_iter().collect())
    }

    /// Queries the crt.sh JSON endpoint for a single base domain.
    pub async fn query_crtsh(&self, base_domain: &str) -> Result<String, CtError> {
        let endpoint = format!("{}/?q=%.{}&output=json", self.base_endpoint, base_domain);

        let resp = self
            .client
            .get(&endpoint)
            .header(reqwest::header::USER_AGENT, &self.user_agent)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| CtError::Network(e.to_string()))?;

        let status = resp.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(CtError::RateLimited(429));
        }
        if status.is_server_error() {
            return Err(CtError::ServiceUnavailable(status.as_u16()));
        }
        if !status.is_success() {
            return Err(CtError::Network(format!(
                "HTTP status {status} from CT log provider"
            )));
        }

        let body = resp
            .text()
            .await
            .map_err(|e| CtError::Network(e.to_string()))?;
        Ok(body)
    }

    /// Discovers in-scope subdomains for a single base domain.
    ///
    /// Catches rate limits, timeouts, service outages, and parsing errors gracefully,
    /// logging a diagnostic warning without interrupting execution.
    pub async fn discover_subdomains_for_domain(
        &self,
        base_domain: &str,
        enforcer: &ScopeEnforcer,
    ) -> Vec<DiscoveredSubdomain> {
        match self.query_crtsh(base_domain).await {
            Ok(body) => match Self::parse_crtsh_json(&body, enforcer) {
                Ok(subs) => subs,
                Err(e) => {
                    eprintln!(
                        "[WARN] Failed to parse Certificate Transparency response for '{}': {}",
                        base_domain, e
                    );
                    Vec::new()
                }
            },
            Err(CtError::RateLimited(code)) => {
                eprintln!(
                    "[WARN] Certificate Transparency provider rate limited (HTTP {}) for '{}'",
                    code, base_domain
                );
                Vec::new()
            }
            Err(CtError::ServiceUnavailable(code)) => {
                eprintln!(
                    "[WARN] Certificate Transparency provider unavailable (HTTP {}) for '{}'",
                    code, base_domain
                );
                Vec::new()
            }
            Err(err) => {
                eprintln!(
                    "[WARN] Certificate Transparency query failed for '{}': {}",
                    base_domain, err
                );
                Vec::new()
            }
        }
    }

    /// Discovers in-scope subdomains across all eligible base domains configured in scope.
    pub async fn discover_all_subdomains(
        &self,
        enforcer: &ScopeEnforcer,
    ) -> Vec<DiscoveredSubdomain> {
        let eligible = Self::extract_eligible_base_domains(&enforcer.config().allowed_domains);
        let mut all_subs = BTreeSet::new();

        for base in &eligible {
            let subs = self.discover_subdomains_for_domain(base, enforcer).await;
            for s in subs {
                all_subs.insert(s);
            }
        }

        all_subs.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::ScopeConfig;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;

    fn test_scope_enforcer(
        allowed_domains: Vec<&str>,
        excluded_domains: Vec<&str>,
    ) -> ScopeEnforcer {
        let config = ScopeConfig {
            program_name: "ct-test-app".to_string(),
            platform: "hackerone".to_string(),
            allowed_domains: allowed_domains.into_iter().map(String::from).collect(),
            excluded_domains: excluded_domains.into_iter().map(String::from).collect(),
            excluded_paths: Vec::new(),
            rate_limit_rps: 5,
            safe_mode: true,
            allow_raw_ip_targets: false,
            max_depth: None,
            user_agent: None,
            researcher_handle: Some("ct-researcher".to_string()),
            policy_url: None,
            excluded_checks: Vec::new(),
        };
        ScopeEnforcer::new(config).expect("enforcer creation failed")
    }

    #[test]
    fn test_extract_eligible_base_domains() {
        let domains = vec![
            "*.example.com".to_string(),
            "example.com".to_string(),
            "api.example.com".to_string(), // Subsumed by example.com
            "other-corp.org".to_string(),
            "127.0.0.1".to_string(),  // IP skipped
            "::1".to_string(),        // IP skipped
            "localhost".to_string(),  // Localhost skipped
            "*.local".to_string(),    // Internal suffix skipped
            "*.internal".to_string(), // Internal suffix skipped
            "com".to_string(),        // Single label skipped
            "*".to_string(),          // Catch-all skipped
        ];

        let base_domains = CtLogDiscoverer::extract_eligible_base_domains(&domains);
        assert_eq!(base_domains, vec!["example.com", "other-corp.org"]);
    }

    #[test]
    fn test_parse_crtsh_json_realistic_san_payload() {
        let enforcer = test_scope_enforcer(
            vec!["*.example.com", "example.com"],
            vec!["excluded.example.com", "secret.example.com"],
        );

        let fixture = r#"[
            {
                "issuer_ca_id": 16418,
                "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                "common_name": "EXAMPLE.COM",
                "name_value": "example.com\n*.example.com\napi.example.com\nAUTH.EXAMPLE.COM",
                "id": 1001
            },
            {
                "issuer_ca_id": 16418,
                "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                "common_name": "staging.example.com",
                "name_value": "staging.example.com\nexcluded.example.com\n*.corp.example.com",
                "id": 1002
            },
            {
                "issuer_ca_id": 16418,
                "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                "common_name": "out-of-scope-attacker.org",
                "name_value": "out-of-scope-attacker.org\n*.attacker.org",
                "id": 1003
            }
        ]"#;

        let discovered =
            CtLogDiscoverer::parse_crtsh_json(fixture, &enforcer).expect("parse json failed");

        let hostnames: Vec<&str> = discovered.iter().map(|d| d.hostname.as_str()).collect();

        // Must include in-scope subdomains (lowercased, duplicates removed, wildcards stripped)
        assert!(hostnames.contains(&"example.com"));
        assert!(hostnames.contains(&"api.example.com"));
        assert!(hostnames.contains(&"auth.example.com"));
        assert!(hostnames.contains(&"staging.example.com"));
        assert!(hostnames.contains(&"corp.example.com"));

        // Must strictly exclude out-of-scope and excluded domains
        assert!(!hostnames.contains(&"excluded.example.com"));
        assert!(!hostnames.contains(&"secret.example.com"));
        assert!(!hostnames.contains(&"out-of-scope-attacker.org"));
        assert!(!hostnames.contains(&"attacker.org"));

        // Discovery source must be ct_log
        for d in &discovered {
            assert_eq!(d.source, "ct_log");
            assert_eq!(d.url, format!("https://{}/", d.hostname));
        }
    }

    #[test]
    fn test_strict_scope_enforcement_rejects_excluded_and_out_of_scope() {
        let enforcer = test_scope_enforcer(
            vec!["*.target.io"],
            vec!["admin.target.io", "payment.target.io"],
        );

        let fixture = r#"[
            {
                "common_name": "api.target.io",
                "name_value": "api.target.io\nadmin.target.io\npayment.target.io\nattacker.com"
            }
        ]"#;

        let discovered =
            CtLogDiscoverer::parse_crtsh_json(fixture, &enforcer).expect("parse json failed");

        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].hostname, "api.target.io");
        assert_eq!(discovered[0].url, "https://api.target.io/");
    }

    #[test]
    fn test_parse_crtsh_json_empty_and_malformed() {
        let enforcer = test_scope_enforcer(vec!["example.com"], vec![]);

        // Empty string
        let empty = CtLogDiscoverer::parse_crtsh_json("", &enforcer).expect("empty failed");
        assert!(empty.is_empty());

        // Empty array
        let empty_arr =
            CtLogDiscoverer::parse_crtsh_json("[]", &enforcer).expect("empty arr failed");
        assert!(empty_arr.is_empty());

        // Malformed JSON should return error
        let bad = CtLogDiscoverer::parse_crtsh_json("<html>502 Bad Gateway</html>", &enforcer);
        assert!(bad.is_err());
    }

    #[tokio::test]
    async fn test_query_crtsh_offline_mock_server_and_error_handling() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
        let port = listener.local_addr().expect("local addr").port();
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        let handle = thread::spawn(move || {
            while running_clone.load(Ordering::Relaxed) {
                if let Ok((mut socket, _)) = listener.accept() {
                    let mut buf = [0u8; 2048];
                    let n = socket.read(&mut buf).unwrap_or(0);
                    if n > 0 {
                        let req = String::from_utf8_lossy(&buf[..n]);
                        if req.contains("q=%.rate-limit.com") {
                            let resp =
                                "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n";
                            let _ = socket.write_all(resp.as_bytes());
                        } else if req.contains("q=%.service-error.com") {
                            let resp =
                                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
                            let _ = socket.write_all(resp.as_bytes());
                        } else if req.contains("q=%.valid.com") {
                            let body = r#"[{"common_name": "sub.valid.com", "name_value": "sub.valid.com"}]"#;
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = socket.write_all(resp.as_bytes());
                        } else {
                            let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                            let _ = socket.write_all(resp.as_bytes());
                        }
                        let _ = socket.flush();
                    }
                }
            }
        });

        let enforcer = test_scope_enforcer(
            vec!["*.rate-limit.com", "*.service-error.com", "*.valid.com"],
            vec![],
        );

        let discoverer = CtLogDiscoverer::new(Duration::from_secs(2), None, None)
            .expect("discoverer creation")
            .with_base_endpoint(&format!("http://127.0.0.1:{}", port));

        // 1. Valid domain returns parsed subdomains
        let valid_subs = discoverer
            .discover_subdomains_for_domain("valid.com", &enforcer)
            .await;
        assert_eq!(valid_subs.len(), 1);
        assert_eq!(valid_subs[0].hostname, "sub.valid.com");

        // 2. Rate-limited 429 returns empty vector cleanly without crashing
        let rl_subs = discoverer
            .discover_subdomains_for_domain("rate-limit.com", &enforcer)
            .await;
        assert!(rl_subs.is_empty());

        // 3. Service outage 503 returns empty vector cleanly without crashing
        let se_subs = discoverer
            .discover_subdomains_for_domain("service-error.com", &enforcer)
            .await;
        assert!(se_subs.is_empty());

        // Shutdown mock server
        running.store(false, Ordering::Relaxed);
        let _ = std::net::TcpStream::connect(format!("127.0.0.1:{}", port));
        let _ = handle.join();
    }
}
