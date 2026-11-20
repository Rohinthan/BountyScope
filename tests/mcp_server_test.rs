use bountyscope::mcp::BountyScopeMcpServer;
use bountyscope::scope::{ScopeConfig, ScopeEnforcer};
use bountyscope::storage::{EndpointEntry, FindingEntry, StorageEngine};
use rmcp::ServiceExt;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
async fn test_end_to_end_mcp_session_over_duplex_stream() {
    // 1. Initialize test scope configuration and database in memory
    let config = ScopeConfig {
        program_name: "mcp-duplex-test-app".to_string(),
        platform: "hackerone".to_string(),
        allowed_domains: vec!["example.com".to_string(), "api.example.com".to_string()],
        excluded_domains: vec!["auth.example.com".to_string()],
        excluded_paths: vec!["/logout".to_string()],
        rate_limit_rps: 10,
        safe_mode: true,
        allow_raw_ip_targets: false,
        max_depth: None,
        user_agent: None,
        researcher_handle: Some("security-researcher".to_string()),
        policy_url: Some("https://example.com/policy".to_string()),
        excluded_checks: vec!["missing_security_headers".to_string()],
    };

    let storage = StorageEngine::open_in_memory().expect("storage open failed");
    let program_id = storage
        .upsert_program_scope(&config)
        .expect("upsert program failed");

    let ep = EndpointEntry {
        program_id: program_id.clone(),
        url: "https://example.com/api/v1/profile".to_string(),
        host: "example.com".to_string(),
        path: "/api/v1/profile".to_string(),
        method: "GET".to_string(),
        discovered_via: "seed".to_string(),
        status_code: Some(200),
        response_size: Some(128),
        content_type: Some("application/json".to_string()),
    };
    let ep_id = storage
        .upsert_endpoint(&ep)
        .expect("upsert endpoint failed");

    let finding = FindingEntry {
        program_id: program_id.clone(),
        endpoint_id: Some(ep_id),
        finding_type: "cors_misconfiguration".to_string(),
        severity: "HIGH".to_string(),
        title: "CORS credentials reflection".to_string(),
        description: "Dynamic reflection of untrusted origin with credentials".to_string(),
        evidence: r#"{"origin": "https://untrusted.example.invalid"}"#.to_string(),
        remediation: Some("Do not reflect untrusted origins".to_string()),
    };
    storage
        .upsert_finding(&finding)
        .expect("upsert finding failed");

    let enforcer = ScopeEnforcer::new(config).expect("enforcer creation failed");
    let server = BountyScopeMcpServer::new(enforcer, storage.clone());

    // 2. Establish in-memory duplex transport
    let (server_stream, client_stream) = tokio::io::duplex(65536);

    let server_task = tokio::spawn(async move {
        let running = server.serve(server_stream).await.expect("serve failed");
        let _ = running.waiting().await;
    });

    let (client_read, mut client_write) = tokio::io::split(client_stream);
    let mut client_lines = BufReader::new(client_read).lines();

    // 3. Send JSON-RPC initialize request
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "clientInfo": {
                "name": "test-mcp-client",
                "version": "1.0.0"
            }
        }
    });
    client_write
        .write_all(format!("{}\n", init_req).as_bytes())
        .await
        .expect("write initialize failed");
    client_write.flush().await.expect("flush failed");

    let init_resp_line = client_lines
        .next_line()
        .await
        .expect("read line failed")
        .expect("missing initialize response");
    let init_resp: serde_json::Value =
        serde_json::from_str(&init_resp_line).expect("parse json failed");

    assert_eq!(init_resp["jsonrpc"], "2.0");
    assert_eq!(init_resp["id"], 1);
    assert!(init_resp["result"]["capabilities"]["tools"].is_object());
    assert_eq!(init_resp["result"]["serverInfo"]["name"], "bountyscope");
    assert_eq!(
        init_resp["result"]["serverInfo"]["version"],
        env!("CARGO_PKG_VERSION")
    );

    // 4. Send notifications/initialized
    let initialized_notif = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    client_write
        .write_all(format!("{}\n", initialized_notif).as_bytes())
        .await
        .expect("write initialized failed");
    client_write.flush().await.expect("flush failed");

    // 5. Query tools/list
    let list_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    client_write
        .write_all(format!("{}\n", list_req).as_bytes())
        .await
        .expect("write tools/list failed");
    client_write.flush().await.expect("flush failed");

    let list_resp_line = client_lines
        .next_line()
        .await
        .expect("read line failed")
        .expect("missing tools/list response");
    let list_resp: serde_json::Value =
        serde_json::from_str(&list_resp_line).expect("parse json failed");

    assert_eq!(list_resp["id"], 2);
    let tools = list_resp["result"]["tools"]
        .as_array()
        .expect("tools array");
    let tool_names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("name"))
        .collect();

    assert!(tool_names.contains(&"check_target_scope"));
    assert!(tool_names.contains(&"list_mapped_endpoints"));
    assert!(tool_names.contains(&"list_security_findings"));
    assert!(tool_names.contains(&"generate_assessment_report"));
    assert!(tool_names.contains(&"validate_scope"));

    // 6. Call tool: check_target_scope (in-scope)
    let call_scope_in = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "check_target_scope",
            "arguments": {
                "url": "https://example.com/api/v1/profile"
            }
        }
    });
    client_write
        .write_all(format!("{}\n", call_scope_in).as_bytes())
        .await
        .expect("write call 3 failed");
    client_write.flush().await.expect("flush failed");

    let resp3_line = client_lines
        .next_line()
        .await
        .expect("read line failed")
        .expect("missing resp3");
    let resp3: serde_json::Value = serde_json::from_str(&resp3_line).expect("parse json failed");
    assert_eq!(resp3["id"], 3);
    assert_eq!(resp3["result"]["structuredContent"]["allowed"], true);
    assert_eq!(
        resp3["result"]["structuredContent"]["normalized_url"],
        "https://example.com/api/v1/profile"
    );

    // 7. Call tool: check_target_scope (excluded domain)
    let call_scope_out = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "check_target_scope",
            "arguments": {
                "url": "https://auth.example.com/login"
            }
        }
    });
    client_write
        .write_all(format!("{}\n", call_scope_out).as_bytes())
        .await
        .expect("write call 4 failed");
    client_write.flush().await.expect("flush failed");

    let resp4_line = client_lines
        .next_line()
        .await
        .expect("read line failed")
        .expect("missing resp4");
    let resp4: serde_json::Value = serde_json::from_str(&resp4_line).expect("parse json failed");
    assert_eq!(resp4["id"], 4);
    assert_eq!(resp4["result"]["structuredContent"]["allowed"], false);
    assert!(resp4["result"]["structuredContent"]["reason"].is_string());

    // 8. Call tool: list_mapped_endpoints
    let call_endpoints = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "list_mapped_endpoints",
            "arguments": {
                "limit": 10
            }
        }
    });
    client_write
        .write_all(format!("{}\n", call_endpoints).as_bytes())
        .await
        .expect("write call 5 failed");
    client_write.flush().await.expect("flush failed");

    let resp5_line = client_lines
        .next_line()
        .await
        .expect("read line failed")
        .expect("missing resp5");
    let resp5: serde_json::Value = serde_json::from_str(&resp5_line).expect("parse json failed");
    assert_eq!(resp5["id"], 5);
    assert_eq!(resp5["result"]["structuredContent"]["count"], 1);
    assert_eq!(
        resp5["result"]["structuredContent"]["endpoints"][0]["path"],
        "/api/v1/profile"
    );

    // 9. Call tool: list_security_findings (HIGH severity)
    let call_findings = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "list_security_findings",
            "arguments": {
                "severity": "HIGH"
            }
        }
    });
    client_write
        .write_all(format!("{}\n", call_findings).as_bytes())
        .await
        .expect("write call 6 failed");
    client_write.flush().await.expect("flush failed");

    let resp6_line = client_lines
        .next_line()
        .await
        .expect("read line failed")
        .expect("missing resp6");
    let resp6: serde_json::Value = serde_json::from_str(&resp6_line).expect("parse json failed");
    assert_eq!(resp6["id"], 6);
    assert_eq!(resp6["result"]["structuredContent"]["count"], 1);
    assert_eq!(
        resp6["result"]["structuredContent"]["findings"][0]["severity"],
        "HIGH"
    );
    assert_eq!(
        resp6["result"]["structuredContent"]["findings"][0]["finding_type"],
        "cors_misconfiguration"
    );

    // 10. Call tool: generate_assessment_report
    let call_report = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "generate_assessment_report",
            "arguments": {}
        }
    });
    client_write
        .write_all(format!("{}\n", call_report).as_bytes())
        .await
        .expect("write call 7 failed");
    client_write.flush().await.expect("flush failed");

    let resp7_line = client_lines
        .next_line()
        .await
        .expect("read line failed")
        .expect("missing resp7");
    let resp7: serde_json::Value = serde_json::from_str(&resp7_line).expect("parse json failed");
    assert_eq!(resp7["id"], 7);
    let report_text = resp7["result"]["structuredContent"]["report"]
        .as_str()
        .expect("report text");
    assert!(report_text.contains("# Security Assessment Report: mcp-duplex-test-app"));
    assert!(report_text.contains("https://example.com/api/v1/profile"));
    assert!(report_text.contains("CORS credentials reflection"));

    // 11. Record snapshots and call tool: diff_latest_scans
    let run1 = storage
        .record_scan_snapshot(&program_id)
        .expect("record run 1 failed");

    // Add new endpoint
    let ep2 = EndpointEntry {
        program_id: program_id.clone(),
        url: "https://example.com/api/v2/tokens".to_string(),
        host: "example.com".to_string(),
        path: "/api/v2/tokens".to_string(),
        method: "POST".to_string(),
        discovered_via: "spec".to_string(),
        status_code: Some(201),
        response_size: Some(64),
        content_type: Some("application/json".to_string()),
    };
    storage.upsert_endpoint(&ep2).expect("upsert ep2 failed");
    let run2 = storage
        .record_scan_snapshot(&program_id)
        .expect("record run 2 failed");

    let call_diff = json!({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {
            "name": "diff_latest_scans",
            "arguments": {
                "from_run_id": run1,
                "to_run_id": run2
            }
        }
    });
    client_write
        .write_all(format!("{}\n", call_diff).as_bytes())
        .await
        .expect("write call 8 failed");
    client_write.flush().await.expect("flush failed");

    let resp8_line = client_lines
        .next_line()
        .await
        .expect("read line failed")
        .expect("missing resp8");
    let resp8: serde_json::Value = serde_json::from_str(&resp8_line).expect("parse json failed");
    assert_eq!(resp8["id"], 8);
    let diff_content = &resp8["result"]["structuredContent"];
    assert_eq!(diff_content["program_name"], "mcp-duplex-test-app");
    assert_eq!(
        diff_content["new_endpoints"][0],
        "https://example.com/api/v2/tokens"
    );
    let diff_md = diff_content["markdown_report"].as_str().expect("diff md");
    assert!(diff_md.contains("# Scan Regression & Attack Surface Diff: mcp-duplex-test-app"));
    assert!(diff_md.contains("https://example.com/api/v2/tokens"));

    // 12. Clean shutdown: Drop client write half to signal EOF
    drop(client_write);
    drop(client_lines);

    let _ = server_task.await;
}
