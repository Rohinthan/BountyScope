use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use tempfile::tempdir;

struct MockServer {
    port: u16,
    running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockServer {
    fn start<F>(handler: F) -> Self
    where
        F: Fn(&str) -> Option<&'static str> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener failed");
        let port = listener.local_addr().expect("local addr failed").port();
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        let handle = thread::spawn(move || {
            while running_clone.load(Ordering::Relaxed) {
                if let Ok((mut socket, _)) = listener.accept() {
                    let mut buf = [0u8; 4096];
                    let n = socket.read(&mut buf).unwrap_or(0);
                    if n > 0 {
                        let req = String::from_utf8_lossy(&buf[..n]);
                        if let Some(resp) = handler(&req) {
                            let _ = socket.write_all(resp.as_bytes());
                            let _ = socket.flush();
                        }
                    }
                }
            }
        });

        Self {
            port,
            running,
            handle: Some(handle),
        }
    }

    fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        let _ = TcpStream::connect(format!("127.0.0.1:{}", self.port));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[test]
fn test_unified_scan_workflow_and_defaults() {
    let server = MockServer::start(|req| {
        let resp = if req.contains("GET / ") {
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 95\r\n\r\n<html><body><a href=\"/dashboard\">Dashboard</a><script src=\"/static/app.js\"></script></body></html>"
        } else if req.contains("GET /static/app.js ") {
            "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: 35\r\n\r\nconst route = \"/api/v1/telemetry\";"
        } else if req.contains("GET /robots.txt ") {
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 26\r\n\r\nUser-agent: *\nDisallow: /admin\n"
        } else if req.contains("GET /openapi.json ") {
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 70\r\n\r\n{\"openapi\":\"3.0.0\",\"info\":{\"title\":\"Test API\",\"version\":\"1.0.0\"},\"paths\":{}}"
        } else if req.contains("GET /dashboard ") {
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 22\r\n\r\n<h1>Dashboard Area</h1>"
        } else if req.contains("GET /api/v1/telemetry ") {
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"status\":\"live\"}"
        } else if req.contains("GET /admin ") {
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 16\r\n\r\n<h1>Admin UI</h1>"
        } else {
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
        };
        Some(resp)
    });
    let port = server.port();

    let temp = tempdir().expect("tempdir failed");
    let config_path = temp.path().join("scope.yaml");
    let config_yaml = format!(
        r#"program_name: "cli-unified-test"
platform: "local"
allowed_domains:
  - "127.0.0.1"
excluded_domains: []
excluded_paths:
  - "/excluded-path"
rate_limit_rps: 50
safe_mode: true
researcher_handle: "cli-tester"
policy_url: "http://127.0.0.1:{}/policy"
excluded_checks: []
"#,
        port
    );
    std::fs::write(&config_path, config_yaml).expect("write scope.yaml failed");

    let bin_path = env!("CARGO_BIN_EXE_bountyscope");
    let seed_url = format!("http://127.0.0.1:{}/", port);

    // 1. Run unified scan relying on default database and default report output
    let output = Command::new(bin_path)
        .arg("scan")
        .arg("--url")
        .arg(&seed_url)
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("bountyscope scan execution failed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "bountyscope scan failed: stderr: {}",
        stderr
    );
    assert!(stdout.contains("Target scope initialized for program 'cli-unified-test'"));
    assert!(stdout.contains("Starting passive surface mapping"));
    assert!(stdout.contains("Surface mapping complete:"));
    assert!(stdout.contains("Starting non-destructive security verification"));
    assert!(stdout.contains("Audit completed:"));
    assert!(stdout.contains("Assessment report generated successfully:"));
    assert!(stdout.contains("Scan snapshot #1 recorded for regression monitoring."));

    // Verify default database and default Markdown report exist
    let default_db = PathBuf::from("data/cli_unified_test.db");
    let default_report = PathBuf::from("data/cli_unified_test_report.md");
    let default_diff = PathBuf::from("data/cli_unified_test_diff.md");

    assert!(
        default_db.exists(),
        "Default database file {:?} should exist",
        default_db
    );
    assert!(
        default_report.exists(),
        "Default report file {:?} should exist",
        default_report
    );

    let report_content =
        std::fs::read_to_string(&default_report).expect("read default report failed");
    assert!(report_content.contains("# Security Assessment Report: cli-unified-test"));
    assert!(report_content.contains("cli-tester"));

    // 2. Diff with only 1 snapshot must fail cleanly
    let diff_out1 = Command::new(bin_path)
        .arg("diff")
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("bountyscope diff execution failed");
    assert!(
        !diff_out1.status.success(),
        "diff should fail when fewer than 2 snapshots exist"
    );

    // 3. Run second scan to record snapshot #2
    let scan2_out = Command::new(bin_path)
        .arg("scan")
        .arg("--url")
        .arg(&seed_url)
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("bountyscope scan 2 failed");
    assert!(scan2_out.status.success());
    let scan2_stdout = String::from_utf8_lossy(&scan2_out.stdout);
    assert!(scan2_stdout.contains("Scan snapshot #2 recorded for regression monitoring."));

    // 4. Run diff with --stdout
    let diff_stdout_out = Command::new(bin_path)
        .arg("diff")
        .arg("--config")
        .arg(&config_path)
        .arg("--stdout")
        .output()
        .expect("bountyscope diff --stdout execution failed");
    assert!(diff_stdout_out.status.success());
    let diff_stdout_str = String::from_utf8_lossy(&diff_stdout_out.stdout);
    assert!(diff_stdout_str.contains("# Scan Regression & Attack Surface Diff: cli-unified-test"));
    assert!(diff_stdout_str.contains("Baseline Scan:"));

    // 5. Run diff generating default diff file
    let diff_file_out = Command::new(bin_path)
        .arg("diff")
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("bountyscope diff execution failed");
    assert!(diff_file_out.status.success());
    assert!(
        default_diff.exists(),
        "Default diff file {:?} should exist",
        default_diff
    );

    // Cleanup generated default files
    let _ = std::fs::remove_file(&default_db);
    let _ = std::fs::remove_file(&default_report);
    let _ = std::fs::remove_file(&default_diff);
}

#[test]
fn test_env_var_fallback_and_custom_paths() {
    let server = MockServer::start(|_req| {
        Some("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"status\":\"live\"}")
    });
    let port = server.port();

    let temp = tempdir().expect("tempdir failed");
    let config_path = temp.path().join("custom_scope.yaml");
    let config_yaml = r#"program_name: "custom-env-test"
platform: "local"
allowed_domains:
  - "127.0.0.1"
excluded_domains: []
excluded_paths: []
rate_limit_rps: 50
safe_mode: true
"#;
    std::fs::write(&config_path, config_yaml).expect("write scope failed");

    let custom_db = temp.path().join("custom_dir").join("audit.db");
    let custom_report = temp.path().join("custom_dir").join("assessment.md");

    let bin_path = env!("CARGO_BIN_EXE_bountyscope");
    let seed_url = format!("http://127.0.0.1:{}/", port);

    // Run without --config flag, relying on BOUNTYSCOPE_CONFIG env var
    let output = Command::new(bin_path)
        .env("BOUNTYSCOPE_CONFIG", &config_path)
        .arg("scan")
        .arg("--url")
        .arg(&seed_url)
        .arg("--db")
        .arg(&custom_db)
        .arg("--output")
        .arg(&custom_report)
        .output()
        .expect("execution failed");

    assert!(
        output.status.success(),
        "Command failed with stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        custom_db.exists(),
        "Custom database {:?} should be created",
        custom_db
    );
    assert!(
        custom_report.exists(),
        "Custom report {:?} should be created",
        custom_report
    );

    let report_text = std::fs::read_to_string(&custom_report).expect("read report failed");
    assert!(report_text.contains("# Security Assessment Report: custom-env-test"));
}

#[test]
fn test_unauthorized_seed_url_fails_closed() {
    let temp = tempdir().expect("tempdir failed");
    let config_path = temp.path().join("scope.yaml");
    let config_yaml = r#"program_name: "strict-scope-test"
platform: "local"
allowed_domains:
  - "127.0.0.1"
excluded_domains: []
excluded_paths: []
rate_limit_rps: 50
safe_mode: true
"#;
    std::fs::write(&config_path, config_yaml).expect("write scope failed");

    let bin_path = env!("CARGO_BIN_EXE_bountyscope");

    // Attempt scan against an out-of-scope domain
    let output = Command::new(bin_path)
        .arg("scan")
        .arg("--url")
        .arg("https://unauthorized.target.invalid/")
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("execution failed");

    assert!(
        !output.status.success(),
        "Out-of-scope URL must fail closed immediately"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not within authorized scope") || stderr.contains("DisallowedDomain"),
        "stderr should describe scope rejection: {}",
        stderr
    );
}

#[test]
fn test_multi_format_reporting_json_and_sarif() {
    let server = MockServer::start(|req| {
        let resp = if req.contains("GET / ") {
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 48\r\n\r\n<html><body><a href=\"/api/test\">Test</a></body></html>"
        } else if req.contains("GET /api/test ") {
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"status\":\"live\"}"
        } else {
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
        };
        Some(resp)
    });
    let port = server.port();

    let temp = tempdir().expect("tempdir failed");
    let config_path = temp.path().join("scope.yaml");
    let config_yaml = r#"program_name: "cli-multiformat-test"
platform: "local"
allowed_domains:
  - "127.0.0.1"
excluded_domains: []
excluded_paths: []
rate_limit_rps: 50
safe_mode: true
researcher_handle: "format-tester"
"#;
    std::fs::write(&config_path, config_yaml).expect("write scope.yaml failed");

    let bin_path = env!("CARGO_BIN_EXE_bountyscope");
    let seed_url = format!("http://127.0.0.1:{}/", port);
    let db_path = temp.path().join("test.db");

    // 1. Initial scan
    let scan_out = Command::new(bin_path)
        .arg("scan")
        .arg("--url")
        .arg(&seed_url)
        .arg("--config")
        .arg(&config_path)
        .arg("--db")
        .arg(&db_path)
        .output()
        .expect("bountyscope scan failed");
    assert!(scan_out.status.success());

    // 2. Report --format json --stdout
    let json_rep_out = Command::new(bin_path)
        .arg("report")
        .arg("--config")
        .arg(&config_path)
        .arg("--db")
        .arg(&db_path)
        .arg("--format")
        .arg("json")
        .arg("--stdout")
        .output()
        .expect("bountyscope report --format json failed");

    assert!(json_rep_out.status.success());
    let json_stdout = String::from_utf8_lossy(&json_rep_out.stdout);
    let json_val: serde_json::Value =
        serde_json::from_str(&json_stdout).expect("valid JSON stdout expected");

    assert_eq!(json_val["schema_version"], "0.15.3");
    assert_eq!(json_val["tool"]["name"], "BountyScope");
    assert_eq!(json_val["tool"]["version"], "0.15.3");
    assert_eq!(json_val["program"]["name"], "cli-multiformat-test");
    assert_eq!(json_val["program"]["researcher_handle"], "format-tester");
    assert!(!json_val["endpoints"]
        .as_array()
        .expect("endpoints")
        .is_empty());

    // 3. Report --format sarif --stdout
    let sarif_rep_out = Command::new(bin_path)
        .arg("report")
        .arg("--config")
        .arg(&config_path)
        .arg("--db")
        .arg(&db_path)
        .arg("--format")
        .arg("sarif")
        .arg("--stdout")
        .output()
        .expect("bountyscope report --format sarif failed");

    assert!(sarif_rep_out.status.success());
    let sarif_stdout = String::from_utf8_lossy(&sarif_rep_out.stdout);
    let sarif_val: serde_json::Value =
        serde_json::from_str(&sarif_stdout).expect("valid SARIF stdout expected");

    assert_eq!(sarif_val["version"], "2.1.0");
    assert_eq!(
        sarif_val["$schema"],
        "https://json.schemastore.org/sarif-2.1.0.json"
    );
    assert_eq!(
        sarif_val["runs"][0]["tool"]["driver"]["name"],
        "BountyScope"
    );
    assert_eq!(sarif_val["runs"][0]["tool"]["driver"]["version"], "0.15.3");
    assert!(sarif_val["runs"][0]["tool"]["driver"]["rules"].is_array());
    assert!(sarif_val["runs"][0]["results"].is_array());

    // 4. Record second scan to allow diff testing
    let scan2_out = Command::new(bin_path)
        .arg("scan")
        .arg("--url")
        .arg(&seed_url)
        .arg("--config")
        .arg(&config_path)
        .arg("--db")
        .arg(&db_path)
        .output()
        .expect("bountyscope scan 2 failed");
    assert!(scan2_out.status.success());

    // 5. Diff --format json --stdout
    let diff_json_out = Command::new(bin_path)
        .arg("diff")
        .arg("--config")
        .arg(&config_path)
        .arg("--db")
        .arg(&db_path)
        .arg("--format")
        .arg("json")
        .arg("--stdout")
        .output()
        .expect("bountyscope diff --format json failed");

    assert!(diff_json_out.status.success());
    let diff_stdout = String::from_utf8_lossy(&diff_json_out.stdout);
    let diff_val: serde_json::Value =
        serde_json::from_str(&diff_stdout).expect("valid JSON diff expected");

    assert_eq!(diff_val["schema_version"], "0.15.3");
    assert_eq!(diff_val["tool"]["name"], "BountyScope");
    assert_eq!(diff_val["tool"]["version"], "0.15.3");
    assert_eq!(diff_val["program_name"], "cli-multiformat-test");
    assert!(diff_val["metrics"].is_object());

    // 6. Scan with --format sarif writing to derived file
    let sarif_scan_out = Command::new(bin_path)
        .arg("scan")
        .arg("--url")
        .arg(&seed_url)
        .arg("--config")
        .arg(&config_path)
        .arg("--db")
        .arg(&db_path)
        .arg("--format")
        .arg("sarif")
        .output()
        .expect("bountyscope scan --format sarif failed");

    assert!(sarif_scan_out.status.success());
    let default_sarif_file = PathBuf::from("data/cli_multiformat_test_report.sarif");
    assert!(
        default_sarif_file.exists(),
        "Derived SARIF file {:?} should exist",
        default_sarif_file
    );
    let sarif_file_text =
        std::fs::read_to_string(&default_sarif_file).expect("read sarif file failed");
    let sarif_file_val: serde_json::Value =
        serde_json::from_str(&sarif_file_text).expect("valid SARIF from file");
    assert_eq!(sarif_file_val["version"], "2.1.0");

    let _ = std::fs::remove_file(&default_sarif_file);
}
