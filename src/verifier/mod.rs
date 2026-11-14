use crate::error::VerifierError;
use crate::http::ScopedHttpClient;
use crate::scope::ScopeEnforcer;
use crate::storage::{FindingEntry, StorageEngine};

/// Summary metrics of a completed verification assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationSummary {
    pub total_audited: usize,
    pub findings_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

/// Safe verification runner.
///
/// Executes strictly non-destructive, read-only configuration and policy audits
/// across mapped in-scope endpoints:
/// - HTTP security headers (CSP, HSTS, X-Content-Type-Options, clickjacking protections)
/// - CORS policy evaluation with static-asset exemptions and credentialed reflection detection
/// - Exposed specification documents (/openapi.json, /swagger.json) and verbose version headers
/// - Passive AI / MCP gateway posture inspection (/sse, /messages, /mcp, /v1/models)
pub struct SafeVerificationRunner<'a> {
    enforcer: &'a ScopeEnforcer,
    http_client: &'a ScopedHttpClient,
    storage: &'a StorageEngine,
    program_id: String,
}

impl<'a> SafeVerificationRunner<'a> {
    /// Creates a new `SafeVerificationRunner` bound to enforcer, scoped HTTP client, and storage engine.
    pub fn new(
        enforcer: &'a ScopeEnforcer,
        http_client: &'a ScopedHttpClient,
        storage: &'a StorageEngine,
        program_id: String,
    ) -> Self {
        Self {
            enforcer,
            http_client,
            storage,
            program_id,
        }
    }

    /// Checks if a given URI path points to a static media or style asset exempt from CORS checks.
    pub fn is_static_asset(path: &str) -> bool {
        let p = path.to_ascii_lowercase();
        let extensions = [
            ".woff", ".woff2", ".ttf", ".eot", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".webp", ".css", ".map",
        ];
        extensions.iter().any(|ext| p.ends_with(ext))
    }

    /// Executes safe verification checks across all persisted endpoints for the configured program.
    pub async fn run(&self) -> Result<VerificationSummary, VerifierError> {
        let endpoints = self.storage.get_endpoints_for_program(&self.program_id)?;

        for endpoint in &endpoints {
            // Validate endpoint URL into compile-time safe VerifiedScopeUrl
            let verified_url = match self.enforcer.validate_url(&endpoint.url) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Check 1: Exposed specification discovery
            if endpoint.discovered_via == "openapi_spec" {
                let finding = FindingEntry {
                    program_id: self.program_id.clone(),
                    endpoint_id: Some(endpoint.id.clone()),
                    finding_type: "exposed_api_spec".to_string(),
                    severity: "LOW".to_string(),
                    title: "Exposed API Specification Document".to_string(),
                    description: format!(
                        "The application exposes a machine-readable API specification at '{}'.",
                        endpoint.url
                    ),
                    evidence: serde_json::json!({
                        "url": endpoint.url,
                        "path": endpoint.path,
                        "discovered_via": endpoint.discovered_via,
                        "status_code": endpoint.status_code,
                    })
                    .to_string(),
                    remediation: Some(
                        "Restrict public exposure of internal API specifications in production. Enforce authentication or restrict access to internal networks.".to_string(),
                    ),
                };
                self.storage.upsert_finding(&finding)?;
            }

            // Check 2: Baseline probe for security headers and technology disclosure
            if let Ok(resp) = self.http_client.get(&verified_url).await {
                // Technology disclosure: X-Powered-By
                if let Some((_, x_powered_by)) = resp
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("x-powered-by"))
                {
                    let finding = FindingEntry {
                        program_id: self.program_id.clone(),
                        endpoint_id: Some(endpoint.id.clone()),
                        finding_type: "information_disclosure".to_string(),
                        severity: "INFO".to_string(),
                        title: "Technology Disclosure Header (X-Powered-By)".to_string(),
                        description: format!(
                            "The server discloses backend framework details via 'X-Powered-By: {}'.",
                            x_powered_by
                        ),
                        evidence: serde_json::json!({
                            "url": endpoint.url,
                            "header": "X-Powered-By",
                            "value": x_powered_by,
                        })
                        .to_string(),
                        remediation: Some(
                            "Disable or remove the 'X-Powered-By' header in production server configuration.".to_string(),
                        ),
                    };
                    self.storage.upsert_finding(&finding)?;
                }

                // Technology disclosure: Server banner with version
                if let Some((_, server)) = resp
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("server"))
                {
                    if server.chars().any(|c| c.is_ascii_digit()) {
                        let finding = FindingEntry {
                            program_id: self.program_id.clone(),
                            endpoint_id: Some(endpoint.id.clone()),
                            finding_type: "information_disclosure".to_string(),
                            severity: "INFO".to_string(),
                            title: "Verbose Server Version Banner Disclosure".to_string(),
                            description: format!(
                                "The server discloses specific software version information: '{}'.",
                                server
                            ),
                            evidence: serde_json::json!({
                                "url": endpoint.url,
                                "header": "Server",
                                "value": server,
                            })
                            .to_string(),
                            remediation: Some(
                                "Configure web servers to omit granular software versions (e.g., 'ServerTokens Prod' in Apache or 'server_tokens off' in nginx).".to_string(),
                            ),
                        };
                        self.storage.upsert_finding(&finding)?;
                    }
                }

                // Security headers: Content-Security-Policy (CSP)
                let csp_header = resp
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-security-policy"))
                    .map(|(_, v)| v.as_str());

                let mut has_frame_ancestors = false;
                match csp_header {
                    Some(csp) => {
                        let lower_csp = csp.to_ascii_lowercase();
                        if lower_csp.contains("frame-ancestors") {
                            has_frame_ancestors = true;
                        }
                        if lower_csp.contains("'unsafe-inline'")
                            || lower_csp.contains("'unsafe-eval'")
                        {
                            let finding = FindingEntry {
                                program_id: self.program_id.clone(),
                                endpoint_id: Some(endpoint.id.clone()),
                                finding_type: "weak_security_headers".to_string(),
                                severity: "LOW".to_string(),
                                title: "Permissive Content-Security-Policy Directives".to_string(),
                                description: "The Content-Security-Policy permits 'unsafe-inline' or 'unsafe-eval', weakening script injection defenses.".to_string(),
                                evidence: serde_json::json!({
                                    "url": endpoint.url,
                                    "csp": csp,
                                })
                                .to_string(),
                                remediation: Some(
                                    "Refactor inline scripts and dynamic evaluations to eliminate 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes.".to_string(),
                                ),
                            };
                            self.storage.upsert_finding(&finding)?;
                        }
                    }
                    None => {
                        let finding = FindingEntry {
                            program_id: self.program_id.clone(),
                            endpoint_id: Some(endpoint.id.clone()),
                            finding_type: "missing_security_headers".to_string(),
                            severity: "LOW".to_string(),
                            title: "Missing Content-Security-Policy Header".to_string(),
                            description: "The endpoint does not return a Content-Security-Policy header.".to_string(),
                            evidence: serde_json::json!({
                                "url": endpoint.url,
                                "missing_header": "Content-Security-Policy",
                            })
                            .to_string(),
                            remediation: Some(
                                "Implement a restrictive Content-Security-Policy header defining authorized script-src and default-src directives.".to_string(),
                            ),
                        };
                        self.storage.upsert_finding(&finding)?;
                    }
                }

                // Security headers: Strict-Transport-Security (HSTS) on HTTPS endpoints
                if verified_url.as_url().scheme() == "https" {
                    let hsts_present = resp.headers.iter().any(|(k, v)| {
                        k.eq_ignore_ascii_case("strict-transport-security")
                            && v.to_ascii_lowercase().contains("max-age")
                    });

                    if !hsts_present {
                        let finding = FindingEntry {
                            program_id: self.program_id.clone(),
                            endpoint_id: Some(endpoint.id.clone()),
                            finding_type: "missing_security_headers".to_string(),
                            severity: "LOW".to_string(),
                            title: "Missing Strict-Transport-Security (HSTS) Header".to_string(),
                            description: "The HTTPS endpoint does not enforce Strict-Transport-Security with a max-age directive.".to_string(),
                            evidence: serde_json::json!({
                                "url": endpoint.url,
                                "missing_header": "Strict-Transport-Security",
                            })
                            .to_string(),
                            remediation: Some(
                                "Enable Strict-Transport-Security with 'max-age=31536000; includeSubDomains'.".to_string(),
                            ),
                        };
                        self.storage.upsert_finding(&finding)?;
                    }
                }

                // Security headers: X-Content-Type-Options
                let xcto_nosniff = resp.headers.iter().any(|(k, v)| {
                    k.eq_ignore_ascii_case("x-content-type-options")
                        && v.trim().eq_ignore_ascii_case("nosniff")
                });

                if !xcto_nosniff {
                    let finding = FindingEntry {
                        program_id: self.program_id.clone(),
                        endpoint_id: Some(endpoint.id.clone()),
                        finding_type: "missing_security_headers".to_string(),
                        severity: "LOW".to_string(),
                        title: "Missing X-Content-Type-Options Header".to_string(),
                        description: "The endpoint does not declare 'X-Content-Type-Options: nosniff'.".to_string(),
                        evidence: serde_json::json!({
                            "url": endpoint.url,
                            "missing_header": "X-Content-Type-Options",
                        })
                        .to_string(),
                        remediation: Some(
                            "Configure web servers to send 'X-Content-Type-Options: nosniff' across all responses.".to_string(),
                        ),
                    };
                    self.storage.upsert_finding(&finding)?;
                }

                // Security headers: Clickjacking protection (X-Frame-Options or CSP frame-ancestors)
                if !has_frame_ancestors {
                    let xfo_valid = resp.headers.iter().any(|(k, v)| {
                        k.eq_ignore_ascii_case("x-frame-options")
                            && (v.trim().eq_ignore_ascii_case("deny")
                                || v.trim().eq_ignore_ascii_case("sameorigin"))
                    });

                    if !xfo_valid {
                        let finding = FindingEntry {
                            program_id: self.program_id.clone(),
                            endpoint_id: Some(endpoint.id.clone()),
                            finding_type: "missing_security_headers".to_string(),
                            severity: "LOW".to_string(),
                            title: "Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)".to_string(),
                            description: "The endpoint lacks both CSP 'frame-ancestors' and 'X-Frame-Options: DENY/SAMEORIGIN'.".to_string(),
                            evidence: serde_json::json!({
                                "url": endpoint.url,
                                "csp_frame_ancestors": false,
                                "x_frame_options": null,
                            })
                            .to_string(),
                            remediation: Some(
                                "Configure Content-Security-Policy with 'frame-ancestors 'none'' or set 'X-Frame-Options: DENY'.".to_string(),
                            ),
                        };
                        self.storage.upsert_finding(&finding)?;
                    }
                }

                // Check 4: Passive AI / MCP Endpoint Posture Check
                let ai_mcp_patterns = ["/sse", "/messages", "/mcp", "/v1/models"];
                if ai_mcp_patterns.iter().any(|p| endpoint.path.contains(p))
                    && (200..=299).contains(&resp.status_code)
                {
                    let has_auth_challenge = resp
                        .headers
                        .iter()
                        .any(|(k, _)| k.eq_ignore_ascii_case("www-authenticate"));

                    if !has_auth_challenge {
                        let finding = FindingEntry {
                            program_id: self.program_id.clone(),
                            endpoint_id: Some(endpoint.id.clone()),
                            finding_type: "unauthenticated_ai_endpoint".to_string(),
                            severity: "HIGH".to_string(),
                            title: "Unauthenticated AI / Model Context Protocol (MCP) Interface".to_string(),
                            description: format!(
                                "The endpoint '{}' responds with HTTP {} without requiring authentication or presenting an authorization challenge.",
                                endpoint.url, resp.status_code
                            ),
                            evidence: serde_json::json!({
                                "url": endpoint.url,
                                "path": endpoint.path,
                                "status_code": resp.status_code,
                                "content_type": resp.content_type(),
                            })
                            .to_string(),
                            remediation: Some(
                                "Enforce token authentication (such as Bearer tokens or mTLS) on AI gateway and Model Context Protocol interfaces.".to_string(),
                            ),
                        };
                        self.storage.upsert_finding(&finding)?;
                    }
                }
            }

            // Check 3: CORS Policy Inspection (with static asset exemption)
            if !Self::is_static_asset(&endpoint.path) {
                let test_origins = ["https://untrusted.example.invalid", "null"];

                for test_origin in &test_origins {
                    if let Ok(cors_resp) = self
                        .http_client
                        .get_with_headers(&verified_url, &[("Origin", test_origin)])
                        .await
                    {
                        let acao_header = cors_resp
                            .headers
                            .iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case("access-control-allow-origin"))
                            .map(|(_, v)| v.trim());

                        let credentials_allowed = cors_resp.headers.iter().any(|(k, v)| {
                            k.eq_ignore_ascii_case("access-control-allow-credentials")
                                && v.trim().eq_ignore_ascii_case("true")
                        });

                        if let Some(acao) = acao_header {
                            if acao == *test_origin {
                                let severity = if credentials_allowed {
                                    "HIGH"
                                } else {
                                    "MEDIUM"
                                };

                                let title = if *test_origin == "null" {
                                    if credentials_allowed {
                                        "CORS Misconfiguration: Null Origin Reflection with Credentials Allowed"
                                    } else {
                                        "CORS Misconfiguration: Null Origin Reflection"
                                    }
                                } else if credentials_allowed {
                                    "CORS Misconfiguration: Arbitrary Origin Reflection with Credentials Allowed"
                                } else {
                                    "CORS Misconfiguration: Arbitrary Origin Reflection"
                                };

                                let description = format!(
                                    "The endpoint dynamically reflects the origin '{}' in Access-Control-Allow-Origin (credentials allowed: {}).",
                                    test_origin, credentials_allowed
                                );

                                let finding = FindingEntry {
                                    program_id: self.program_id.clone(),
                                    endpoint_id: Some(endpoint.id.clone()),
                                    finding_type: "cors_misconfiguration".to_string(),
                                    severity: severity.to_string(),
                                    title: title.to_string(),
                                    description,
                                    evidence: serde_json::json!({
                                        "url": endpoint.url,
                                        "tested_origin": test_origin,
                                        "reflected_acao": acao,
                                        "credentials_allowed": credentials_allowed,
                                    })
                                    .to_string(),
                                    remediation: Some(
                                        "Do not dynamically reflect untrusted Origin headers. Maintain an explicit whitelist of trusted origins, and avoid permitting the 'null' origin or credentials on untrusted domains.".to_string(),
                                    ),
                                };
                                self.storage.upsert_finding(&finding)?;
                            }
                        }
                    }
                }
            }
        }

        // Calculate summary metrics from persisted findings
        let findings = self.storage.get_findings_for_program(&self.program_id)?;
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut info_count = 0;

        for f in &findings {
            match f.severity.as_str() {
                "CRITICAL" => critical_count += 1,
                "HIGH" => high_count += 1,
                "MEDIUM" => medium_count += 1,
                "LOW" => low_count += 1,
                "INFO" => info_count += 1,
                _ => {}
            }
        }

        Ok(VerificationSummary {
            total_audited: endpoints.len(),
            findings_count: findings.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::ScopeConfig;
    use crate::storage::EndpointEntry;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn test_scope_config(_port: u16) -> ScopeConfig {
        ScopeConfig {
            program_name: "test-verifier-program".to_string(),
            platform: "local".to_string(),
            allowed_domains: vec!["127.0.0.1".to_string()],
            excluded_domains: vec![],
            excluded_paths: vec![],
            rate_limit_rps: 50,
            safe_mode: true,
        }
    }

    #[test]
    fn test_static_asset_exemption_rules() {
        assert!(SafeVerificationRunner::is_static_asset(
            "/fonts/roboto.woff2"
        ));
        assert!(SafeVerificationRunner::is_static_asset("/assets/app.css"));
        assert!(SafeVerificationRunner::is_static_asset("/images/logo.png"));
        assert!(!SafeVerificationRunner::is_static_asset("/api/v1/users"));
        assert!(!SafeVerificationRunner::is_static_asset("/dashboard"));
    }

    #[tokio::test]
    async fn test_verifier_cors_and_header_audit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
        let addr = listener.local_addr().expect("local_addr failed");
        let port = addr.port();

        tokio::spawn(async move {
            loop {
                if let Ok((mut socket, _)) = listener.accept().await {
                    let mut buf = [0u8; 4096];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);

                    let req_lower = req.to_ascii_lowercase();
                    let response = if req.contains("GET /api/data ") {
                        if req_lower.contains("origin: https://untrusted.example.invalid") {
                            "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://untrusted.example.invalid\r\nAccess-Control-Allow-Credentials: true\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".to_string()
                        } else {
                            // Missing CSP, missing XCTO, missing XFO
                            "HTTP/1.1 200 OK\r\nX-Powered-By: Express\r\nServer: Apache/2.4.41\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".to_string()
                        }
                    } else if req.contains("GET /static/font.woff2 ") {
                        // Static asset reflecting origin (should be exempted)
                        "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://untrusted.example.invalid\r\nContent-Type: font/woff2\r\nContent-Length: 4\r\n\r\nFONT".to_string()
                    } else {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
                    };

                    let _ = socket.write_all(response.as_bytes()).await;
                }
            }
        });

        let storage = StorageEngine::open_in_memory().expect("storage open failed");
        let config = test_scope_config(port);
        let program_id = storage
            .upsert_program_scope(&config)
            .expect("upsert failed");
        let enforcer = ScopeEnforcer::new(config).expect("enforcer failed");
        let client =
            ScopedHttpClient::new(storage.clone(), program_id.clone(), 50).expect("client failed");

        // Insert API endpoint and static font endpoint
        let ep_api = EndpointEntry {
            program_id: program_id.clone(),
            url: format!("http://127.0.0.1:{}/api/data", port),
            host: "127.0.0.1".to_string(),
            path: "/api/data".to_string(),
            method: "GET".to_string(),
            discovered_via: "seed".to_string(),
            status_code: Some(200),
            response_size: Some(2),
            content_type: Some("application/json".to_string()),
        };
        storage.upsert_endpoint(&ep_api).expect("upsert api failed");

        let ep_font = EndpointEntry {
            program_id: program_id.clone(),
            url: format!("http://127.0.0.1:{}/static/font.woff2", port),
            host: "127.0.0.1".to_string(),
            path: "/static/font.woff2".to_string(),
            method: "GET".to_string(),
            discovered_via: "html_link".to_string(),
            status_code: Some(200),
            response_size: Some(4),
            content_type: Some("font/woff2".to_string()),
        };
        storage
            .upsert_endpoint(&ep_font)
            .expect("upsert font failed");

        let runner = SafeVerificationRunner::new(&enforcer, &client, &storage, program_id.clone());
        let summary = runner.run().await.expect("runner execution failed");

        assert_eq!(summary.total_audited, 2);
        assert!(summary.findings_count > 0);
        // Credentialed CORS reflection on /api/data must produce a HIGH severity finding
        assert!(summary.high_count >= 1);

        let findings = storage
            .get_findings_for_program(&program_id)
            .expect("query findings failed");
        // Verify font endpoint did NOT generate a CORS misconfiguration finding
        assert!(!findings
            .iter()
            .any(|f| f.endpoint_id.as_deref() == Some(&ep_font.url)
                && f.finding_type == "cors_misconfiguration"));
        // Verify technology disclosure was detected
        assert!(findings.iter().any(
            |f| f.finding_type == "information_disclosure" && f.title.contains("X-Powered-By")
        ));
        assert!(findings
            .iter()
            .any(|f| f.finding_type == "information_disclosure" && f.title.contains("Server")));
    }
}
