use bountyscope::error::ScopeError;
use bountyscope::scope::{ScopeConfig, ScopeEnforcer};
use std::path::PathBuf;

#[test]
fn test_scope_example_yaml_loads_and_enforces_boundaries() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let example_path = manifest_dir.join("configs/scope.example.yaml");

    let config = ScopeConfig::from_file(&example_path)
        .unwrap_or_else(|err| panic!("configs/scope.example.yaml must load cleanly: {err}"));

    assert_eq!(config.program_name, "example-security-program");
    assert_eq!(config.platform, "hackerone");
    assert_eq!(config.rate_limit_rps, 2);
    assert!(config.safe_mode);
    assert_eq!(
        config.researcher_handle.as_deref(),
        Some("security-researcher")
    );
    assert_eq!(
        config.policy_url.as_deref(),
        Some("https://hackerone.com/example-security-program/policy")
    );
    assert_eq!(config.excluded_checks, vec!["missing_security_headers"]);

    let enforcer = ScopeEnforcer::new(config)
        .unwrap_or_else(|err| panic!("ScopeEnforcer failed initialization: {err}"));

    // In-scope verification
    assert!(enforcer.validate_url("https://example.com/").is_ok());
    assert!(enforcer
        .validate_url("https://api.example.com/v1/health")
        .is_ok());
    assert!(enforcer
        .validate_url("https://dashboard.example.com/settings")
        .is_ok());
    assert!(enforcer
        .validate_url("http://127.0.0.1:8080/openapi.json")
        .is_ok());

    // In-scope with trailing dot
    assert!(enforcer
        .validate_url("https://api.example.com./v1/health")
        .is_ok());

    // Out-of-scope verification: excluded domain
    let auth_res = enforcer.validate_url("https://auth.example.com/oauth/token");
    assert!(matches!(auth_res, Err(ScopeError::DomainExcluded(_))));

    let pay_res = enforcer.validate_url("https://payment.example.com/checkout");
    assert!(matches!(pay_res, Err(ScopeError::DomainExcluded(_))));

    // Out-of-scope verification: excluded path
    let logout_res = enforcer.validate_url("https://example.com/logout");
    assert!(matches!(logout_res, Err(ScopeError::PathExcluded(_))));

    let purge_res = enforcer.validate_url("https://example.com/admin/purge");
    assert!(matches!(purge_res, Err(ScopeError::PathExcluded(_))));

    // Out-of-scope: path traversal targeting excluded path
    let traversal_res = enforcer.validate_url("https://example.com/public/../logout");
    assert!(matches!(traversal_res, Err(ScopeError::PathExcluded(_))));

    let encoded_res = enforcer.validate_url("https://example.com/%2e%2e/logout");
    assert!(matches!(encoded_res, Err(ScopeError::PathExcluded(_))));

    // Out-of-scope verification: unlisted external domain
    let external_res = enforcer.validate_url("https://evil.corp/payload");
    assert!(matches!(external_res, Err(ScopeError::DomainNotAllowed(_))));
}

#[test]
fn test_malformed_scope_configs_return_structured_errors() {
    // Malformed YAML syntax
    let bad_yaml = "program_name: [unclosed list";
    let parse_err = ScopeConfig::from_yaml_str(bad_yaml);
    assert!(matches!(parse_err, Err(ScopeError::Yaml(_))));

    // Unknown fields rejected by deny_unknown_fields
    let unknown_yaml = r#"
program_name: "test-corp"
platform: "hackerone"
allowed_domains: ["example.com"]
unknown_field: 123
"#;
    let unknown_err = ScopeConfig::from_yaml_str(unknown_yaml);
    assert!(matches!(unknown_err, Err(ScopeError::Yaml(_))));

    // Missing required field / empty program_name
    let empty_name_yaml = r#"
program_name: "  "
platform: "bugcrowd"
allowed_domains: ["example.com"]
"#;
    let name_err = ScopeConfig::from_yaml_str(empty_name_yaml);
    assert!(matches!(name_err, Err(ScopeError::InvalidConfiguration(_))));

    // Empty allowed_domains list
    let no_domains_yaml = r#"
program_name: "test-corp"
platform: "intigriti"
allowed_domains: []
"#;
    let domains_err = ScopeConfig::from_yaml_str(no_domains_yaml);
    assert!(matches!(
        domains_err,
        Err(ScopeError::InvalidConfiguration(_))
    ));

    // Zero rate limit
    let zero_rate_yaml = r#"
program_name: "test-corp"
platform: "hackerone"
allowed_domains: ["example.com"]
rate_limit_rps: 0
"#;
    let rate_err = ScopeConfig::from_yaml_str(zero_rate_yaml);
    assert!(matches!(rate_err, Err(ScopeError::InvalidRateLimit(0))));

    // Excessive rate limit (> 100)
    let excessive_rate_yaml = r#"
program_name: "test-corp"
platform: "hackerone"
allowed_domains: ["example.com"]
rate_limit_rps: 500
"#;
    let rate_err2 = ScopeConfig::from_yaml_str(excessive_rate_yaml);
    assert!(matches!(rate_err2, Err(ScopeError::InvalidRateLimit(500))));

    // safe_mode = false must be rejected
    let unsafe_mode_yaml = r#"
program_name: "test-corp"
platform: "hackerone"
allowed_domains: ["example.com"]
safe_mode: false
"#;
    let unsafe_err = ScopeConfig::from_yaml_str(unsafe_mode_yaml);
    assert!(matches!(
        unsafe_err,
        Err(ScopeError::InvalidConfiguration(_))
    ));
}

#[test]
fn test_adversarial_scope_edge_cases_fail_closed() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let example_path = manifest_dir.join("configs/scope.example.yaml");

    let config = ScopeConfig::from_file(&example_path)
        .unwrap_or_else(|err| panic!("configs/scope.example.yaml must load cleanly: {err}"));
    let enforcer = ScopeEnforcer::new(config)
        .unwrap_or_else(|err| panic!("ScopeEnforcer failed initialization: {err}"));

    // 1. Credentialed authority confusion:
    // Host must resolve to evil.com, not allowed.example.com, and must fail-closed as DomainNotAllowed
    let auth_conf_1 = enforcer.validate_url("https://allowed.example.com@evil.com/");
    assert!(matches!(auth_conf_1, Err(ScopeError::DomainNotAllowed(d)) if d == "evil.com"));

    let auth_conf_2 = enforcer.validate_url("https://user:pass@evil.com/");
    assert!(matches!(auth_conf_2, Err(ScopeError::DomainNotAllowed(d)) if d == "evil.com"));

    // 2. Subdomain suffix / prefix tricks:
    // Suffix trick: allowed.example.com.evil.com
    let suffix_trick = enforcer.validate_url("https://allowed.example.com.evil.com/");
    assert!(
        matches!(suffix_trick, Err(ScopeError::DomainNotAllowed(d)) if d == "allowed.example.com.evil.com")
    );

    // Prefix trick: myexample.com (when example.com and *.example.com are allowed)
    let prefix_trick = enforcer.validate_url("https://myexample.com/");
    assert!(matches!(prefix_trick, Err(ScopeError::DomainNotAllowed(d)) if d == "myexample.com"));

    // 3. Double-encoded and mixed path traversal targeting excluded paths (/logout):
    let double_encoded = enforcer.validate_url("https://example.com/%252e%252e/logout");
    assert!(matches!(double_encoded, Err(ScopeError::PathExcluded(p)) if p == "/logout"));

    let mixed_traversal = enforcer.validate_url("https://example.com/a/b/../../logout");
    assert!(matches!(mixed_traversal, Err(ScopeError::PathExcluded(p)) if p == "/logout"));

    // 4. Private, link-local, and loopback IP rejection when not in allowed_domains:
    // (Note: 127.0.0.1 is in scope in example.yaml, but link-local 169.254.169.254, 10.0.0.1, and [::1] are not)
    let aws_meta = enforcer.validate_url("http://169.254.169.254/latest/meta-data/");
    assert!(matches!(aws_meta, Err(ScopeError::DomainNotAllowed(d)) if d == "169.254.169.254"));

    let rfc1918 = enforcer.validate_url("http://10.0.0.1/");
    assert!(matches!(rfc1918, Err(ScopeError::DomainNotAllowed(d)) if d == "10.0.0.1"));

    let ipv6_loopback = enforcer.validate_url("http://[::1]/");
    assert!(matches!(
        ipv6_loopback,
        Err(ScopeError::DomainNotAllowed(_))
    ));
}
