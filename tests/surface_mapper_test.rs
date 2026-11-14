use bountyscope::http::ScopedHttpClient;
use bountyscope::mapper::SurfaceMapper;
use bountyscope::scope::{ScopeConfig, ScopeEnforcer};
use bountyscope::storage::StorageEngine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_offline_surface_mapper_end_to_end() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
    let addr = listener.local_addr().expect("local_addr failed");
    let port = addr.port();

    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                let response = if req.contains("GET / ") {
                    let html = r#"<!DOCTYPE html>
<html>
<head>
    <script src="/assets/main.js"></script>
    <script src="https://cdn.thirdparty.com/lib.js"></script>
</head>
<body>
    <a href="/products">Products</a>
    <a href="/logout">Logout</a>
    <a href="https://external.example.com/blog">External Blog</a>
    <script>
        const authRoute = "/api/v1/auth";
    </script>
</body>
</html>"#;
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                        html.len(),
                        html
                    )
                } else if req.contains("GET /assets/main.js ") {
                    let js = r#"
                    const inventoryUrl = "/api/v2/inventory";
                    const gqlEndpoint = "/graphql";
                    "#;
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: {}\r\n\r\n{}",
                        js.len(),
                        js
                    )
                } else if req.contains("GET /robots.txt ") {
                    let robots = "User-agent: *\nDisallow: /docs\nDisallow: /logout\n";
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                        robots.len(),
                        robots
                    )
                } else if req.contains("GET /openapi.json ") {
                    let spec =
                        r#"{"openapi": "3.0.0", "info": {"title": "App API", "version": "1.0"}}"#;
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        spec.len(),
                        spec
                    )
                } else if req.contains("GET /swagger.json ") {
                    // Soft-404: Returns HTTP 200 with HTML error page
                    let html_404 = "<!DOCTYPE html><html><body>Document Not Found</body></html>";
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                        html_404.len(),
                        html_404
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
                };

                let _ = socket.write_all(response.as_bytes()).await;
            }
        }
    });

    let storage = StorageEngine::open_in_memory().expect("failed to open storage");
    let config = ScopeConfig {
        program_name: "surface-mapper-lab".to_string(),
        platform: "local".to_string(),
        allowed_domains: vec!["127.0.0.1".to_string()],
        excluded_domains: vec!["cdn.thirdparty.com".to_string()],
        excluded_paths: vec!["/logout".to_string()],
        rate_limit_rps: 50,
        safe_mode: true,
    };

    let program_id = storage
        .upsert_program_scope(&config)
        .expect("upsert failed");
    let enforcer = ScopeEnforcer::new(config).expect("enforcer failed");
    let client =
        ScopedHttpClient::new(storage.clone(), program_id.clone(), 50).expect("client failed");

    let seed_str = format!("http://127.0.0.1:{}/", port);
    let seed_url = enforcer
        .validate_url(&seed_str)
        .expect("seed validation failed");

    let mapper = SurfaceMapper::new(&enforcer, &client, &storage, program_id.clone())
        .expect("mapper creation failed");

    let result = mapper.map(&seed_url).await.expect("map failed");

    // Verify out-of-scope targets were safely filtered and counted:
    // - /logout (HTML link and robots.txt)
    // - https://cdn.thirdparty.com/lib.js (script tag)
    // - https://external.example.com/blog (HTML link)
    assert!(result.out_of_scope_discarded >= 3);

    // Verify expected in-scope endpoints:
    let endpoints = storage
        .get_endpoints_for_program(&program_id)
        .expect("query endpoints failed");

    let urls: Vec<&str> = endpoints.iter().map(|e| e.url.as_str()).collect();
    assert!(urls.contains(&seed_str.as_str()));
    assert!(urls.iter().any(|u| u.ends_with("/products")));
    assert!(urls.iter().any(|u| u.ends_with("/assets/main.js")));
    assert!(urls.iter().any(|u| u.ends_with("/api/v1/auth")));
    assert!(urls.iter().any(|u| u.ends_with("/api/v2/inventory")));
    assert!(urls.iter().any(|u| u.ends_with("/graphql")));
    assert!(urls.iter().any(|u| u.ends_with("/robots.txt")));
    assert!(urls.iter().any(|u| u.ends_with("/docs")));
    assert!(urls.iter().any(|u| u.ends_with("/openapi.json")));

    // Verify soft-404 /swagger.json was rejected and not persisted as openapi_spec
    assert!(!urls.iter().any(|u| u.ends_with("/swagger.json")));

    // Re-run mapping against the same target: duplicate rows must not be created
    let result_second = mapper.map(&seed_url).await.expect("second map failed");
    let endpoints_second = storage
        .get_endpoints_for_program(&program_id)
        .expect("query endpoints failed");
    assert_eq!(endpoints.len(), endpoints_second.len());
    assert_eq!(result.in_scope_count, result_second.in_scope_count);
}
