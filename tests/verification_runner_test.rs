use bountyscope::http::ScopedHttpClient;
use bountyscope::report::ReportGenerator;
use bountyscope::scope::{ScopeConfig, ScopeEnforcer};
use bountyscope::storage::{EndpointEntry, StorageEngine};
use bountyscope::verifier::SafeVerificationRunner;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_offline_verification_runner_and_report_generation() {
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
                let response = if req.contains("GET /api/v1/user ") {
                    if req_lower.contains("origin: https://untrusted.example.invalid") {
                        // Vulnerable CORS: Dynamic reflection of untrusted origin with credentials
                        "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://untrusted.example.invalid\r\nAccess-Control-Allow-Credentials: true\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"user\":\"admin\"}".to_string()
                    } else {
                        // Missing CSP, missing XCTO, missing XFO, verbose headers
                        "HTTP/1.1 200 OK\r\nX-Powered-By: Express/4.18\r\nServer: Apache/2.4.52 (Ubuntu)\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"user\":\"admin\"}".to_string()
                    }
                } else if req.contains("GET /dashboard ") {
                    // HTML endpoint missing CSP and clickjacking headers
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 13\r\n\r\n<h1>Admin</h1>".to_string()
                } else if req.contains("GET /static/font.woff2 ") {
                    // Static asset: reflects origin, but must be exempted
                    "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://untrusted.example.invalid\r\nContent-Type: font/woff2\r\nContent-Length: 4\r\n\r\nFONT".to_string()
                } else if req.contains("GET /v1/models ") {
                    // Exposed AI / MCP endpoint without authentication challenge
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"models\":[\"m1\"]}".to_string()
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
                };

                let _ = socket.write_all(response.as_bytes()).await;
            }
        }
    });

    let storage = StorageEngine::open_in_memory().expect("open storage failed");
    let config = ScopeConfig {
        program_name: "verification-lab-app".to_string(),
        platform: "local".to_string(),
        allowed_domains: vec!["127.0.0.1".to_string()],
        excluded_domains: vec![],
        excluded_paths: vec!["/logout".to_string()],
        rate_limit_rps: 50,
        safe_mode: true,
        allow_raw_ip_targets: true,
        max_depth: None,
        user_agent: None,
        researcher_handle: Some("security-tester".to_string()),
        policy_url: Some("https://example.com/policy".to_string()),
        excluded_checks: vec![],
    };

    let program_id = storage
        .upsert_program_scope(&config)
        .expect("upsert program failed");
    let enforcer = ScopeEnforcer::new(config.clone()).expect("enforcer failed");
    let client =
        ScopedHttpClient::new(storage.clone(), program_id.clone(), 50).expect("client failed");

    // Populate endpoints in storage
    let ep_api = EndpointEntry {
        program_id: program_id.clone(),
        url: format!("http://127.0.0.1:{}/api/v1/user", port),
        host: "127.0.0.1".to_string(),
        path: "/api/v1/user".to_string(),
        method: "GET".to_string(),
        discovered_via: "seed".to_string(),
        status_code: Some(200),
        response_size: Some(15),
        content_type: Some("application/json".to_string()),
    };
    let _ep_api_id = storage
        .upsert_endpoint(&ep_api)
        .expect("upsert ep_api failed");

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
    let ep_font_id = storage
        .upsert_endpoint(&ep_font)
        .expect("upsert ep_font failed");

    let ep_ai = EndpointEntry {
        program_id: program_id.clone(),
        url: format!("http://127.0.0.1:{}/v1/models", port),
        host: "127.0.0.1".to_string(),
        path: "/v1/models".to_string(),
        method: "GET".to_string(),
        discovered_via: "js_route".to_string(),
        status_code: Some(200),
        response_size: Some(16),
        content_type: Some("application/json".to_string()),
    };
    storage
        .upsert_endpoint(&ep_ai)
        .expect("upsert ep_ai failed");

    let ep_spec = EndpointEntry {
        program_id: program_id.clone(),
        url: format!("http://127.0.0.1:{}/openapi.json", port),
        host: "127.0.0.1".to_string(),
        path: "/openapi.json".to_string(),
        method: "GET".to_string(),
        discovered_via: "openapi_spec".to_string(),
        status_code: Some(200),
        response_size: Some(100),
        content_type: Some("application/json".to_string()),
    };
    storage
        .upsert_endpoint(&ep_spec)
        .expect("upsert ep_spec failed");

    let ep_dashboard = EndpointEntry {
        program_id: program_id.clone(),
        url: format!("http://127.0.0.1:{}/dashboard", port),
        host: "127.0.0.1".to_string(),
        path: "/dashboard".to_string(),
        method: "GET".to_string(),
        discovered_via: "seed".to_string(),
        status_code: Some(200),
        response_size: Some(13),
        content_type: Some("text/html; charset=utf-8".to_string()),
    };
    storage
        .upsert_endpoint(&ep_dashboard)
        .expect("upsert ep_dashboard failed");

    // Execute verification runner
    let runner = SafeVerificationRunner::new(&enforcer, &client, &storage, program_id.clone());
    let summary = runner.run().await.expect("runner execution failed");

    assert_eq!(summary.total_audited, 5);
    assert!(summary.findings_count >= 5);
    // Credentialed CORS reflection produces a HIGH severity finding
    assert!(summary.high_count >= 1);
    // Unauthenticated AI endpoint produces a HIGH severity finding
    assert!(summary.high_count >= 2);

    let findings = storage
        .get_findings_for_program(&program_id)
        .expect("get findings failed");

    // Static asset exemption check: Font asset must NOT generate CORS findings
    assert!(!findings
        .iter()
        .any(|f| f.endpoint_id.as_deref() == Some(&ep_font_id)
            && f.finding_type == "cors_misconfiguration"));

    // Exposed API spec check
    assert!(findings
        .iter()
        .any(|f| f.finding_type == "exposed_api_spec"));

    // Information disclosure check
    assert!(findings
        .iter()
        .any(|f| (f.finding_type == "header_info_disclosure"
            || f.finding_type == "information_disclosure")
            && f.title.contains("X-Powered-By")));
    assert!(findings
        .iter()
        .any(|f| (f.finding_type == "header_info_disclosure"
            || f.finding_type == "information_disclosure")
            && f.title.contains("Server")));

    // Missing security headers check
    assert!(findings
        .iter()
        .any(|f| f.finding_type == "missing_security_headers"
            && f.title.contains("Content-Security-Policy")));

    // Re-run verification: Idempotent persistence must update existing records rather than multiplying
    let summary_second = runner.run().await.expect("second runner execution failed");
    assert_eq!(summary.findings_count, summary_second.findings_count);

    // Generate Markdown report
    let program = storage
        .get_program_by_id(&program_id)
        .expect("get program failed");
    let endpoints = storage
        .get_endpoints_for_program(&program_id)
        .expect("get endpoints failed");

    let report_md = ReportGenerator::generate_markdown(&program, &config, &endpoints, &findings);

    assert!(report_md.contains("# Security Assessment Report: verification-lab-app"));
    assert!(report_md.contains("## Severity Breakdown"));
    assert!(report_md.contains("| **HIGH** |"));
    assert!(report_md
        .contains("CORS Misconfiguration: Arbitrary Origin Reflection with Credentials Allowed"));
    assert!(report_md.contains("Unauthenticated AI / Model Context Protocol (MCP) Interface"));
    assert!(report_md.contains("#### Remediation Guidance"));
}
