use crate::error::{MapperError, ScopeError};
use crate::http::ScopedHttpClient;
use crate::scope::{ScopeEnforcer, VerifiedScopeUrl};
use crate::storage::{EndpointEntry, StorageEngine};
use regex::Regex;
use scraper::{Html, Selector};
use std::collections::{BTreeMap, HashSet};

/// Represents an individual endpoint discovered during surface mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredEndpoint {
    pub url: String,
    pub host: String,
    pub path: String,
    pub discovered_via: String,
    pub status_code: Option<u16>,
    pub response_size: Option<usize>,
    pub content_type: Option<String>,
}

/// Aggregated result of a surface mapping assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceMapResult {
    pub seed_url: String,
    pub total_discovered: usize,
    pub in_scope_count: usize,
    pub out_of_scope_discarded: usize,
    pub endpoints: Vec<DiscoveredEndpoint>,
}

/// Passive vulnerability surface mapper.
///
/// Discovers endpoints through passive observation and standard asset inspection:
/// - HTML hyperlinks (`<a href>`)
/// - External and inline JavaScript bundles (`<script src>` and inline scripts)
/// - Relative API route patterns in client code (`/api/...`, `/v1/...`, `/graphql`)
/// - Directives in technical asset files (`/robots.txt`)
/// - Standard OpenAPI/Swagger specifications with soft-404 false-positive filtering
pub struct SurfaceMapper<'a> {
    enforcer: &'a ScopeEnforcer,
    http_client: &'a ScopedHttpClient,
    storage: &'a StorageEngine,
    program_id: String,
    route_regex: Regex,
}

impl<'a> SurfaceMapper<'a> {
    /// Creates a new `SurfaceMapper` bound to scope enforcer, HTTP probe client, and storage engine.
    pub fn new(
        enforcer: &'a ScopeEnforcer,
        http_client: &'a ScopedHttpClient,
        storage: &'a StorageEngine,
        program_id: String,
    ) -> Result<Self, MapperError> {
        let route_regex =
            Regex::new(r#"["'`](/(?:api|v[0-9]+|graphql)[a-zA-Z0-9_\-/\.\?=&%#]*)["'`]"#)?;

        Ok(Self {
            enforcer,
            http_client,
            storage,
            program_id,
            route_regex,
        })
    }

    /// Performs passive surface mapping starting from a seed URL within authorized scope.
    pub async fn map(&self, seed: &VerifiedScopeUrl) -> Result<SurfaceMapResult, MapperError> {
        let mut discovered_map: BTreeMap<String, DiscoveredEndpoint> = BTreeMap::new();
        let mut out_of_scope_discarded: usize = 0;

        // Fetch seed target URL
        let seed_resp = self.http_client.get(seed).await?;
        let seed_host = seed.as_url().host_str().unwrap_or("").to_string();
        let seed_path = seed.as_url().path().to_string();
        let seed_content_type = seed_resp.content_type().map(|s| s.to_string());
        let seed_size = Some(seed_resp.body.len());
        let seed_status = Some(seed_resp.status_code);

        let seed_entry = EndpointEntry {
            program_id: self.program_id.clone(),
            url: seed.as_str().to_string(),
            host: seed_host.clone(),
            path: seed_path.clone(),
            method: "GET".to_string(),
            discovered_via: "seed".to_string(),
            status_code: seed_status,
            response_size: seed_size,
            content_type: seed_content_type.clone(),
        };
        self.storage.upsert_endpoint(&seed_entry)?;

        discovered_map.insert(
            seed.as_str().to_string(),
            DiscoveredEndpoint {
                url: seed.as_str().to_string(),
                host: seed_host,
                path: seed_path,
                discovered_via: "seed".to_string(),
                status_code: seed_status,
                response_size: seed_size,
                content_type: seed_content_type,
            },
        );

        // Check if seed response contains HTML content
        let is_html = seed_resp
            .content_type()
            .map(|ct| ct.to_ascii_lowercase().contains("text/html"))
            .unwrap_or(false)
            || seed_resp
                .body_as_str()
                .map(|b| {
                    let lower = b.trim_start().to_ascii_lowercase();
                    lower.starts_with("<!doctype") || lower.starts_with("<html")
                })
                .unwrap_or(false);

        if is_html {
            if let Ok(body_str) = seed_resp.body_as_str() {
                self.extract_html_surface(
                    seed,
                    body_str,
                    &mut discovered_map,
                    &mut out_of_scope_discarded,
                )
                .await?;
            }
        }

        // Probe technical asset files (/robots.txt)
        self.discover_robots_txt(seed, &mut discovered_map, &mut out_of_scope_discarded)
            .await?;

        // Probe API documentation specifications (/openapi.json, /swagger.json, /v3/api-docs)
        self.discover_openapi_specs(seed, &mut discovered_map, &mut out_of_scope_discarded)
            .await?;

        // Persist all discovered endpoints into storage
        for endpoint in discovered_map.values() {
            let entry = EndpointEntry {
                program_id: self.program_id.clone(),
                url: endpoint.url.clone(),
                host: endpoint.host.clone(),
                path: endpoint.path.clone(),
                method: "GET".to_string(),
                discovered_via: endpoint.discovered_via.clone(),
                status_code: endpoint.status_code,
                response_size: endpoint.response_size,
                content_type: endpoint.content_type.clone(),
            };
            self.storage.upsert_endpoint(&entry)?;
        }

        let in_scope_count = discovered_map.len();
        let total_discovered = in_scope_count + out_of_scope_discarded;
        let endpoints: Vec<DiscoveredEndpoint> = discovered_map.into_values().collect();

        Ok(SurfaceMapResult {
            seed_url: seed.as_str().to_string(),
            total_discovered,
            in_scope_count,
            out_of_scope_discarded,
            endpoints,
        })
    }

    /// Extracts hyperlinks, external scripts, and inline JavaScript routes from HTML text.
    async fn extract_html_surface(
        &self,
        seed: &VerifiedScopeUrl,
        html_str: &str,
        discovered_map: &mut BTreeMap<String, DiscoveredEndpoint>,
        out_of_scope_discarded: &mut usize,
    ) -> Result<(), MapperError> {
        let document = Html::parse_document(html_str);

        // Extract HTML <a href> hyperlinks
        let a_selector =
            Selector::parse("a[href]").map_err(|e| MapperError::Selector(format!("{e:?}")))?;

        let mut seen_links = HashSet::new();
        for element in document.select(&a_selector) {
            if let Some(href) = element.value().attr("href") {
                let href_trimmed = href.trim();
                if href_trimmed.is_empty()
                    || href_trimmed.starts_with('#')
                    || href_trimmed.starts_with("javascript:")
                    || href_trimmed.starts_with("mailto:")
                    || href_trimmed.starts_with("tel:")
                {
                    continue;
                }

                let mut candidate = match seed.as_url().join(href_trimmed) {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                candidate.set_fragment(None);

                if candidate.scheme() != "http" && candidate.scheme() != "https" {
                    continue;
                }

                let candidate_str = candidate.as_str().to_string();
                if !seen_links.insert(candidate_str) {
                    continue;
                }

                match self.enforcer.validate_url(candidate.as_str()) {
                    Ok(verified) => {
                        let host = verified.as_url().host_str().unwrap_or("").to_string();
                        let path = verified.as_url().path().to_string();
                        let url_str = verified.as_str().to_string();

                        discovered_map.entry(url_str.clone()).or_insert_with(|| {
                            DiscoveredEndpoint {
                                url: url_str,
                                host,
                                path,
                                discovered_via: "html_link".to_string(),
                                status_code: None,
                                response_size: None,
                                content_type: None,
                            }
                        });
                    }
                    Err(ScopeError::DomainNotAllowed(_))
                    | Err(ScopeError::DomainExcluded(_))
                    | Err(ScopeError::PathExcluded(_)) => {
                        *out_of_scope_discarded += 1;
                    }
                    Err(_) => {}
                }
            }
        }

        // Extract <script src> script tags
        let script_src_selector =
            Selector::parse("script[src]").map_err(|e| MapperError::Selector(format!("{e:?}")))?;

        let mut seen_scripts = HashSet::new();
        let mut scripts_to_fetch = Vec::new();
        for element in document.select(&script_src_selector) {
            if let Some(src) = element.value().attr("src") {
                let src_trimmed = src.trim();
                if src_trimmed.is_empty() {
                    continue;
                }

                let mut candidate = match seed.as_url().join(src_trimmed) {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                candidate.set_fragment(None);

                if candidate.scheme() != "http" && candidate.scheme() != "https" {
                    continue;
                }

                let candidate_str = candidate.as_str().to_string();
                if !seen_scripts.insert(candidate_str) {
                    continue;
                }

                match self.enforcer.validate_url(candidate.as_str()) {
                    Ok(verified) => {
                        scripts_to_fetch.push(verified);
                    }
                    Err(ScopeError::DomainNotAllowed(_))
                    | Err(ScopeError::DomainExcluded(_))
                    | Err(ScopeError::PathExcluded(_)) => {
                        *out_of_scope_discarded += 1;
                    }
                    Err(_) => {}
                }
            }
        }

        // Extract routes from inline <script> tags
        let inline_script_selector = Selector::parse("script:not([src])")
            .map_err(|e| MapperError::Selector(format!("{e:?}")))?;

        for element in document.select(&inline_script_selector) {
            let script_text = element.text().collect::<Vec<_>>().join("");
            self.extract_js_routes(seed, &script_text, discovered_map, out_of_scope_discarded);
        }

        // Fetch each in-scope script and extract routes
        for script_verified in scripts_to_fetch {
            let script_url_str = script_verified.as_str().to_string();
            let host = script_verified
                .as_url()
                .host_str()
                .unwrap_or("")
                .to_string();
            let path = script_verified.as_url().path().to_string();

            match self.http_client.get(&script_verified).await {
                Ok(resp) => {
                    let status = Some(resp.status_code);
                    let size = Some(resp.body.len());
                    let ct = resp.content_type().map(|s| s.to_string());

                    discovered_map.insert(
                        script_url_str,
                        DiscoveredEndpoint {
                            url: script_verified.as_str().to_string(),
                            host,
                            path,
                            discovered_via: "html_script".to_string(),
                            status_code: status,
                            response_size: size,
                            content_type: ct,
                        },
                    );

                    if let Ok(js_content) = resp.body_as_str() {
                        self.extract_js_routes(
                            seed,
                            js_content,
                            discovered_map,
                            out_of_scope_discarded,
                        );
                    }
                }
                Err(_) => {
                    discovered_map
                        .entry(script_url_str)
                        .or_insert_with(|| DiscoveredEndpoint {
                            url: script_verified.as_str().to_string(),
                            host,
                            path,
                            discovered_via: "html_script".to_string(),
                            status_code: None,
                            response_size: None,
                            content_type: None,
                        });
                }
            }
        }

        Ok(())
    }

    /// Mines candidate relative API routes from JavaScript source code.
    fn extract_js_routes(
        &self,
        seed: &VerifiedScopeUrl,
        js_code: &str,
        discovered_map: &mut BTreeMap<String, DiscoveredEndpoint>,
        out_of_scope_discarded: &mut usize,
    ) {
        let mut seen_routes = HashSet::new();
        for cap in self.route_regex.captures_iter(js_code) {
            if let Some(matched_path) = cap.get(1) {
                let path_str = matched_path.as_str();
                let mut candidate = match seed.as_url().join(path_str) {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                candidate.set_fragment(None);

                let candidate_str = candidate.as_str().to_string();
                if !seen_routes.insert(candidate_str) {
                    continue;
                }

                match self.enforcer.validate_url(candidate.as_str()) {
                    Ok(verified) => {
                        let host = verified.as_url().host_str().unwrap_or("").to_string();
                        let path = verified.as_url().path().to_string();
                        let url_str = verified.as_str().to_string();

                        discovered_map.entry(url_str.clone()).or_insert_with(|| {
                            DiscoveredEndpoint {
                                url: url_str,
                                host,
                                path,
                                discovered_via: "js_route".to_string(),
                                status_code: None,
                                response_size: None,
                                content_type: None,
                            }
                        });
                    }
                    Err(ScopeError::DomainNotAllowed(_))
                    | Err(ScopeError::DomainExcluded(_))
                    | Err(ScopeError::PathExcluded(_)) => {
                        *out_of_scope_discarded += 1;
                    }
                    Err(_) => {}
                }
            }
        }
    }

    /// Discovers paths listed in /robots.txt.
    async fn discover_robots_txt(
        &self,
        seed: &VerifiedScopeUrl,
        discovered_map: &mut BTreeMap<String, DiscoveredEndpoint>,
        out_of_scope_discarded: &mut usize,
    ) -> Result<(), MapperError> {
        let robots_candidate = match seed.as_url().join("/robots.txt") {
            Ok(u) => u,
            Err(_) => return Ok(()),
        };

        let verified_robots = match self.enforcer.validate_url(robots_candidate.as_str()) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };

        if let Ok(resp) = self.http_client.get(&verified_robots).await {
            if resp.status_code == 200 {
                let host = verified_robots
                    .as_url()
                    .host_str()
                    .unwrap_or("")
                    .to_string();
                let path = verified_robots.as_url().path().to_string();
                let url_str = verified_robots.as_str().to_string();

                discovered_map.insert(
                    url_str,
                    DiscoveredEndpoint {
                        url: verified_robots.as_str().to_string(),
                        host,
                        path,
                        discovered_via: "robots_txt".to_string(),
                        status_code: Some(resp.status_code),
                        response_size: Some(resp.body.len()),
                        content_type: resp.content_type().map(|s| s.to_string()),
                    },
                );

                if let Ok(body_str) = resp.body_as_str() {
                    for line in body_str.lines() {
                        let trimmed = line.trim();
                        let lower = trimmed.to_ascii_lowercase();

                        let candidate_path = if lower.starts_with("disallow:") {
                            trimmed["disallow:".len()..].trim()
                        } else if lower.starts_with("allow:") {
                            trimmed["allow:".len()..].trim()
                        } else {
                            continue;
                        };

                        if candidate_path.is_empty() || !candidate_path.starts_with('/') {
                            continue;
                        }

                        let clean_path = candidate_path.split('*').next().unwrap_or(candidate_path);
                        if clean_path.is_empty() || !clean_path.starts_with('/') {
                            continue;
                        }

                        let mut resolved = match seed.as_url().join(clean_path) {
                            Ok(u) => u,
                            Err(_) => continue,
                        };
                        resolved.set_fragment(None);

                        match self.enforcer.validate_url(resolved.as_str()) {
                            Ok(verified) => {
                                let h = verified.as_url().host_str().unwrap_or("").to_string();
                                let p = verified.as_url().path().to_string();
                                let u = verified.as_str().to_string();

                                discovered_map.entry(u.clone()).or_insert_with(|| {
                                    DiscoveredEndpoint {
                                        url: u,
                                        host: h,
                                        path: p,
                                        discovered_via: "robots_txt".to_string(),
                                        status_code: None,
                                        response_size: None,
                                        content_type: None,
                                    }
                                });
                            }
                            Err(ScopeError::DomainNotAllowed(_))
                            | Err(ScopeError::DomainExcluded(_))
                            | Err(ScopeError::PathExcluded(_)) => {
                                *out_of_scope_discarded += 1;
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Discovers common OpenAPI and Swagger documentation endpoints with soft-404 filtering.
    async fn discover_openapi_specs(
        &self,
        seed: &VerifiedScopeUrl,
        discovered_map: &mut BTreeMap<String, DiscoveredEndpoint>,
        out_of_scope_discarded: &mut usize,
    ) -> Result<(), MapperError> {
        let candidate_paths = ["/openapi.json", "/swagger.json", "/v3/api-docs"];

        for path in candidate_paths {
            let mut candidate_url = match seed.as_url().join(path) {
                Ok(u) => u,
                Err(_) => continue,
            };
            candidate_url.set_fragment(None);

            let verified = match self.enforcer.validate_url(candidate_url.as_str()) {
                Ok(v) => v,
                Err(ScopeError::DomainNotAllowed(_))
                | Err(ScopeError::DomainExcluded(_))
                | Err(ScopeError::PathExcluded(_)) => {
                    *out_of_scope_discarded += 1;
                    continue;
                }
                Err(_) => continue,
            };

            if let Ok(resp) = self.http_client.get(&verified).await {
                if resp.status_code == 200 {
                    // Soft-404 filtering rule: reject responses with HTML Content-Type
                    if let Some(ct) = resp.content_type() {
                        if ct.to_ascii_lowercase().contains("text/html") {
                            continue;
                        }
                    }

                    // Soft-404 filtering rule: reject responses starting with HTML tags
                    if let Ok(body_str) = resp.body_as_str() {
                        let lower = body_str.trim_start().to_ascii_lowercase();
                        if lower.starts_with("<!doctype")
                            || lower.starts_with("<html")
                            || lower.starts_with("<body")
                        {
                            continue;
                        }
                    }

                    // Strict schema verification: payload must parse as JSON containing openapi or swagger keys
                    if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(&resp.body) {
                        if let Some(obj) = json_val.as_object() {
                            if obj.contains_key("openapi") || obj.contains_key("swagger") {
                                let host = verified.as_url().host_str().unwrap_or("").to_string();
                                let path_str = verified.as_url().path().to_string();
                                let url_str = verified.as_str().to_string();

                                discovered_map.insert(
                                    url_str,
                                    DiscoveredEndpoint {
                                        url: verified.as_str().to_string(),
                                        host,
                                        path: path_str,
                                        discovered_via: "openapi_spec".to_string(),
                                        status_code: Some(resp.status_code),
                                        response_size: Some(resp.body.len()),
                                        content_type: resp.content_type().map(|s| s.to_string()),
                                    },
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::ScopeConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn test_scope_config(_port: u16) -> ScopeConfig {
        ScopeConfig {
            program_name: "test-mapper-program".to_string(),
            platform: "local".to_string(),
            allowed_domains: vec!["127.0.0.1".to_string()],
            excluded_domains: vec!["external.example.com".to_string()],
            excluded_paths: vec!["/logout".to_string(), "/api/private/secret".to_string()],
            rate_limit_rps: 50,
            safe_mode: true,
        }
    }

    #[tokio::test]
    async fn test_surface_mapping_and_out_of_scope_filtering() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
        let addr = listener.local_addr().expect("local_addr failed");
        let port = addr.port();

        // Spawn mock server handling seed HTML, script, robots.txt, and openapi.json
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
    <script src="/static/app.js"></script>
    <script src="https://external.example.com/cdn/bundle.js"></script>
</head>
<body>
    <a href="/dashboard">Dashboard</a>
    <a href="/dashboard#overview">Dashboard Overview</a>
    <a href="/dashboard#settings">Dashboard Settings</a>
    <a href="/logout">Logout</a>
    <a href="https://external.example.com/portal">External Portal</a>
    <script>
        const route = "/api/v1/users";
        const ignored = "/api/private/secret";
    </script>
</body>
</html>"#;
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                            html.len(),
                            html
                        )
                    } else if req.contains("GET /static/app.js ") {
                        let js = r#"
                        function fetchStats() {
                            return fetch('/api/v2/metrics');
                        }
                        const gql = '/graphql';
                        "#;
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: {}\r\n\r\n{}",
                            js.len(),
                            js
                        )
                    } else if req.contains("GET /robots.txt ") {
                        let robots = "User-agent: *\nDisallow: /admin\nDisallow: /logout\n";
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                            robots.len(),
                            robots
                        )
                    } else if req.contains("GET /openapi.json ") {
                        let spec = r#"{"openapi": "3.0.0", "info": {"title": "Test API", "version": "1.0"}}"#;
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            spec.len(),
                            spec
                        )
                    } else if req.contains("GET /swagger.json ") {
                        // Soft-404: Returns 200 OK with HTML content
                        let soft_404 = "<html><body>Not Found</body></html>";
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                            soft_404.len(),
                            soft_404
                        )
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

        let seed_url_str = format!("http://127.0.0.1:{}/", port);
        let seed = enforcer
            .validate_url(&seed_url_str)
            .expect("seed validation failed");

        let mapper = SurfaceMapper::new(&enforcer, &client, &storage, program_id.clone())
            .expect("mapper creation failed");

        let result = mapper.map(&seed).await.expect("map failed");

        // Discarded out-of-scope targets:
        // - /logout (from HTML <a href>)
        // - https://external.example.com/portal (from HTML <a href>)
        // - https://external.example.com/cdn/bundle.js (from HTML <script src>)
        // - /api/private/secret (from inline <script>)
        // - /logout (from robots.txt Disallow)
        assert!(result.out_of_scope_discarded >= 4);

        // In-scope discovered targets:
        // - Seed: http://127.0.0.1:<port>/
        // - HTML link: http://127.0.0.1:<port>/dashboard
        // - Script: http://127.0.0.1:<port>/static/app.js
        // - Inline JS route: http://127.0.0.1:<port>/api/v1/users
        // - External JS route: http://127.0.0.1:<port>/api/v2/metrics
        // - External JS route: http://127.0.0.1:<port>/graphql
        // - Robots.txt: http://127.0.0.1:<port>/robots.txt
        // - Robots.txt Disallow: http://127.0.0.1:<port>/admin
        // - OpenAPI spec: http://127.0.0.1:<port>/openapi.json
        // (Soft-404 /swagger.json rejected)
        let urls: Vec<&str> = result.endpoints.iter().map(|e| e.url.as_str()).collect();
        assert!(urls.contains(&seed_url_str.as_str()));
        assert!(urls.iter().any(|u| u.ends_with("/dashboard")));
        assert!(urls.iter().any(|u| u.ends_with("/static/app.js")));
        assert!(urls.iter().any(|u| u.ends_with("/api/v1/users")));
        assert!(urls.iter().any(|u| u.ends_with("/api/v2/metrics")));
        assert!(urls.iter().any(|u| u.ends_with("/graphql")));
        assert!(urls.iter().any(|u| u.ends_with("/robots.txt")));
        assert!(urls.iter().any(|u| u.ends_with("/admin")));
        assert!(urls.iter().any(|u| u.ends_with("/openapi.json")));
        assert!(!urls.iter().any(|u| u.ends_with("/swagger.json")));

        // Verify SQLite storage persistence
        let stored_endpoints = storage
            .get_endpoints_for_program(&program_id)
            .expect("query endpoints failed");
        assert_eq!(stored_endpoints.len(), result.in_scope_count);
    }
}
