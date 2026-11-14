use bountyscope::http::ScopedHttpClient;
use bountyscope::scope::{ScopeConfig, ScopeEnforcer};
use bountyscope::storage::StorageEngine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_offline_loopback_probe_and_audit_logging() {
    // 1. Bind ephemeral loopback listener
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind loopback listener");
    let local_addr = listener.local_addr().expect("failed to get local addr");
    let port = local_addr.port();

    // 2. Spawn a mock HTTP handler serving a sample JSON response
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"status\":\"live\"}";
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });

    // 3. Initialize storage and scope configuration
    let storage = StorageEngine::open_in_memory().expect("failed to open storage");
    let config = ScopeConfig {
        program_name: "offline-loopback-test".to_string(),
        platform: "local".to_string(),
        allowed_domains: vec!["127.0.0.1".to_string()],
        excluded_domains: vec![],
        excluded_paths: vec!["/admin".to_string()],
        rate_limit_rps: 5,
        safe_mode: true,
    };

    let program_id = storage
        .upsert_program_scope(&config)
        .expect("upsert failed");
    let enforcer = ScopeEnforcer::new(config).expect("enforcer failed");

    let client = ScopedHttpClient::new(storage.clone(), program_id.clone(), 5)
        .expect("client creation failed");

    // 4. Validate URL through enforcer to obtain compile-time safe VerifiedScopeUrl
    let target_str = format!("http://127.0.0.1:{}/api/status", port);
    let verified_url = enforcer
        .validate_url(&target_str)
        .expect("validation failed");

    // 5. Dispatch safe GET probe
    let response = client.get(&verified_url).await.expect("probe failed");

    assert_eq!(response.status_code, 200);
    assert_eq!(response.content_type(), Some("application/json"));
    assert_eq!(
        response.body_as_str().expect("utf8 conversion failed"),
        "{\"status\":\"live\"}"
    );

    // 6. Verify audit log entry in storage
    let audit_logs = storage
        .get_audit_logs(&program_id)
        .expect("get_audit_logs failed");
    assert_eq!(audit_logs.len(), 1);
    assert_eq!(audit_logs[0].target_url, target_str);
    assert_eq!(audit_logs[0].http_method, "GET");
    assert_eq!(audit_logs[0].status_code, Some(200));
}

#[tokio::test]
async fn test_redirect_safety_without_automatic_following() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind listener");
    let port = listener.local_addr().expect("local addr failed").port();

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let response = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://unauthorized-domain.com/login\r\nContent-Length: 0\r\n\r\n";
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });

    let storage = StorageEngine::open_in_memory().expect("failed to open storage");
    let config = ScopeConfig {
        program_name: "redirect-safety-test".to_string(),
        platform: "local".to_string(),
        allowed_domains: vec!["127.0.0.1".to_string()],
        excluded_domains: vec![],
        excluded_paths: vec![],
        rate_limit_rps: 5,
        safe_mode: true,
    };

    let program_id = storage
        .upsert_program_scope(&config)
        .expect("upsert failed");
    let enforcer = ScopeEnforcer::new(config).expect("enforcer failed");

    let client = ScopedHttpClient::new(storage, program_id, 5).expect("client creation failed");
    let target_str = format!("http://127.0.0.1:{}/redirect-me", port);
    let verified_url = enforcer
        .validate_url(&target_str)
        .expect("validation failed");

    let response = client
        .get(&verified_url)
        .await
        .expect("request dispatch failed");

    // Scoped client must NOT follow redirect automatically
    assert_eq!(response.status_code, 301);
    assert_eq!(
        response.redirect_location,
        Some("https://unauthorized-domain.com/login".to_string())
    );
}

#[tokio::test]
async fn test_rate_limiter_inter_request_spacing() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind listener");
    let port = listener.local_addr().expect("local addr failed").port();

    tokio::spawn(async move {
        for _ in 0..3 {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nPONG";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        }
    });

    let storage = StorageEngine::open_in_memory().expect("failed to open storage");
    let config = ScopeConfig {
        program_name: "rate-limit-test".to_string(),
        platform: "local".to_string(),
        allowed_domains: vec!["127.0.0.1".to_string()],
        excluded_domains: vec![],
        excluded_paths: vec![],
        rate_limit_rps: 1, // 1000ms spacing
        safe_mode: true,
    };

    let program_id = storage
        .upsert_program_scope(&config)
        .expect("upsert failed");
    let enforcer = ScopeEnforcer::new(config).expect("enforcer failed");

    let client = ScopedHttpClient::new(storage, program_id, 1).expect("client creation failed");
    let target_str = format!("http://127.0.0.1:{}/ping", port);
    let verified_url = enforcer
        .validate_url(&target_str)
        .expect("validation failed");

    let (res1, res2) = tokio::join!(client.get(&verified_url), client.get(&verified_url));
    let r1 = res1.expect("r1 failed");
    let r2 = res2.expect("r2 failed");

    assert_eq!(r1.status_code, 200);
    assert_eq!(r2.status_code, 200);
    assert!(r1.rate_limited || r2.rate_limited);
}
