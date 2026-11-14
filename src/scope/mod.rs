use crate::error::ScopeError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;
use std::path::Path;
use url::Url;

const DEFAULT_RATE_LIMIT_RPS: u32 = 2;
const MAX_RATE_LIMIT_RPS: u32 = 100;

fn default_rate_limit() -> u32 {
    DEFAULT_RATE_LIMIT_RPS
}

fn default_safe_mode() -> bool {
    true
}

/// Target scope configuration defining allowed boundaries and execution constraints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScopeConfig {
    pub program_name: String,
    pub platform: String,
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub excluded_domains: Vec<String>,
    #[serde(default)]
    pub excluded_paths: Vec<String>,
    #[serde(default = "default_rate_limit")]
    pub rate_limit_rps: u32,
    #[serde(default = "default_safe_mode")]
    pub safe_mode: bool,
    #[serde(default)]
    pub researcher_handle: Option<String>,
    #[serde(default)]
    pub policy_url: Option<String>,
    #[serde(default)]
    pub excluded_checks: Vec<String>,
}

impl Default for ScopeConfig {
    fn default() -> Self {
        Self {
            program_name: String::new(),
            platform: String::new(),
            allowed_domains: Vec::new(),
            excluded_domains: Vec::new(),
            excluded_paths: Vec::new(),
            rate_limit_rps: default_rate_limit(),
            safe_mode: default_safe_mode(),
            researcher_handle: None,
            policy_url: None,
            excluded_checks: Vec::new(),
        }
    }
}

impl ScopeConfig {
    /// Validates internal consistency of the scope configuration.
    pub fn validate(&self) -> Result<(), ScopeError> {
        if self.program_name.trim().is_empty() {
            return Err(ScopeError::InvalidConfiguration(
                "program_name cannot be empty".to_string(),
            ));
        }

        if self.platform.trim().is_empty() {
            return Err(ScopeError::InvalidConfiguration(
                "platform cannot be empty".to_string(),
            ));
        }

        if self.allowed_domains.is_empty() {
            return Err(ScopeError::InvalidConfiguration(
                "allowed_domains must contain at least one domain rule".to_string(),
            ));
        }

        for domain in &self.allowed_domains {
            if domain.trim().is_empty() {
                return Err(ScopeError::InvalidConfiguration(
                    "allowed_domains contains an empty domain entry".to_string(),
                ));
            }
        }

        if self.rate_limit_rps == 0 || self.rate_limit_rps > MAX_RATE_LIMIT_RPS {
            return Err(ScopeError::InvalidRateLimit(self.rate_limit_rps));
        }

        if !self.safe_mode {
            return Err(ScopeError::InvalidConfiguration(
                "safe_mode must be set to true: destructive modes are prohibited by policy"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Loads and validates a scope configuration from a YAML file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ScopeError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml_str(&content)
    }

    /// Parses and validates a scope configuration from a YAML string.
    pub fn from_yaml_str(yaml_str: &str) -> Result<Self, ScopeError> {
        let config: ScopeConfig = serde_yaml::from_str(yaml_str)?;
        config.validate()?;
        Ok(config)
    }
}

/// An opaque, validated URL token guaranteed to conform to target scope rules.
///
/// This type can only be instantiated through `ScopeEnforcer::validate_url()`,
/// providing a compile-time safety lock for downstream network request dispatchers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VerifiedScopeUrl {
    inner: Url,
}

impl VerifiedScopeUrl {
    /// Internal constructor only accessible within the scope module.
    fn new(url: Url) -> Self {
        Self { inner: url }
    }

    /// Returns the complete URL as a string slice.
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    /// Returns a reference to the parsed `url::Url`.
    pub fn as_url(&self) -> &Url {
        &self.inner
    }

    /// Returns the target host string.
    pub fn host_str(&self) -> Option<&str> {
        self.inner.host_str()
    }

    /// Returns the URL path.
    pub fn path(&self) -> &str {
        self.inner.path()
    }
}

impl fmt::Display for VerifiedScopeUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl Deref for VerifiedScopeUrl {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Boundary enforcement engine that evaluates candidate URLs against configured scope rules.
#[derive(Debug, Clone)]
pub struct ScopeEnforcer {
    config: ScopeConfig,
}

impl ScopeEnforcer {
    /// Creates a new `ScopeEnforcer` from a validated `ScopeConfig`.
    pub fn new(config: ScopeConfig) -> Result<Self, ScopeError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Reference to the underlying scope configuration.
    pub fn config(&self) -> &ScopeConfig {
        &self.config
    }

    /// Validates a raw URL against the scope definition.
    ///
    /// Returns `Ok(VerifiedScopeUrl)` if the target domain and path comply with all rules.
    pub fn validate_url(&self, raw_url: &str) -> Result<VerifiedScopeUrl, ScopeError> {
        let parsed = Url::parse(raw_url)?;

        // Enforce valid network transport schemes
        match parsed.scheme() {
            "http" | "https" => {}
            other => {
                return Err(ScopeError::InvalidUrl(format!(
                    "unsupported scheme '{other}': only http and https are permitted"
                )))
            }
        }

        let host = match parsed.host_str() {
            Some(h) if !h.is_empty() => h.to_ascii_lowercase(),
            _ => {
                return Err(ScopeError::InvalidUrl(
                    "target URL must contain a valid host component".to_string(),
                ))
            }
        };

        // Check explicit exclusions first (exclusion takes precedence over inclusion)
        for pattern in &self.config.excluded_domains {
            if matches_domain_pattern(pattern, &host) {
                return Err(ScopeError::DomainExcluded(host));
            }
        }

        // Verify target host against allowed domain rules
        let allowed = self
            .config
            .allowed_domains
            .iter()
            .any(|pattern| matches_domain_pattern(pattern, &host));

        if !allowed {
            return Err(ScopeError::DomainNotAllowed(host));
        }

        // Check path exclusions with lexical normalization
        let normalized = normalize_path(parsed.path());
        for excluded_path in &self.config.excluded_paths {
            let norm_excluded = normalize_path(excluded_path);
            if matches_path_pattern(&norm_excluded, &normalized) {
                return Err(ScopeError::PathExcluded(normalized));
            }
        }

        Ok(VerifiedScopeUrl::new(parsed))
    }

    /// Checks if a candidate domain is within scope without parsing a complete URL.
    pub fn is_domain_allowed(&self, host: &str) -> bool {
        let host_lower = host.to_ascii_lowercase();

        for pattern in &self.config.excluded_domains {
            if matches_domain_pattern(pattern, &host_lower) {
                return false;
            }
        }

        self.config
            .allowed_domains
            .iter()
            .any(|pattern| matches_domain_pattern(pattern, &host_lower))
    }

    /// Checks if a candidate path matches any excluded path rule.
    pub fn is_path_excluded(&self, path: &str) -> bool {
        let norm_path = normalize_path(path);
        self.config.excluded_paths.iter().any(|excluded| {
            let norm_excluded = normalize_path(excluded);
            matches_path_pattern(&norm_excluded, &norm_path)
        })
    }
}

/// Evaluates whether a host matches a domain rule (exact match or wildcard `*.domain.tld`).
/// Normalizes trailing dots on both pattern and host.
fn matches_domain_pattern(pattern: &str, host: &str) -> bool {
    let pattern_clean = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let host_clean = host.trim().trim_end_matches('.').to_ascii_lowercase();

    if pattern_clean == host_clean {
        return true;
    }

    if let Some(suffix) = pattern_clean.strip_prefix("*.") {
        // Must match exact domain or subdomains
        if host_clean == suffix {
            return true;
        }

        let dot_suffix = format!(".{suffix}");
        if host_clean.ends_with(&dot_suffix) && host_clean.len() > dot_suffix.len() {
            return true;
        }
    }

    false
}

/// Evaluates whether a path is excluded based on prefix or exact segment matching.
fn matches_path_pattern(pattern: &str, path: &str) -> bool {
    let pat = pattern.trim();
    if pat.is_empty() {
        return false;
    }

    if path == pat {
        return true;
    }

    let prefix_with_slash = if pat.ends_with('/') {
        pat.to_string()
    } else {
        format!("{pat}/")
    };

    path.starts_with(&prefix_with_slash)
}

/// Lexically normalizes a URL path by decoding percent-encoded characters,
/// collapsing multiple slashes, and resolving `.` and `..` traversal segments.
pub fn normalize_path(raw_path: &str) -> String {
    let decoded = percent_encoding::percent_decode_str(raw_path).decode_utf8_lossy();

    let mut segments: Vec<&str> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => {
                segments.push(s);
            }
        }
    }

    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> ScopeConfig {
        ScopeConfig {
            program_name: "test-program".to_string(),
            platform: "hackerone".to_string(),
            allowed_domains: vec![
                "example.com".to_string(),
                "*.example.com".to_string(),
                "127.0.0.1".to_string(),
            ],
            excluded_domains: vec!["auth.example.com".to_string()],
            excluded_paths: vec![
                "/logout".to_string(),
                "/delete-account".to_string(),
                "/admin".to_string(),
            ],
            rate_limit_rps: 2,
            safe_mode: true,
            researcher_handle: None,
            policy_url: None,
            excluded_checks: vec![],
        }
    }

    #[test]
    fn test_valid_scope_url_construction() {
        let config = create_test_config();
        let enforcer = ScopeEnforcer::new(config).expect("failed to create enforcer");

        let verified = enforcer
            .validate_url("https://example.com/api/v1/users")
            .expect("expected valid url");
        assert_eq!(verified.as_str(), "https://example.com/api/v1/users");
        assert_eq!(verified.host_str(), Some("example.com"));
        assert_eq!(verified.path(), "/api/v1/users");
    }

    #[test]
    fn test_subdomain_wildcard_matching() {
        let config = create_test_config();
        let enforcer = ScopeEnforcer::new(config).expect("failed to create enforcer");

        assert!(enforcer
            .validate_url("https://api.example.com/status")
            .is_ok());
        assert!(enforcer
            .validate_url("https://sub.api.example.com/health")
            .is_ok());

        // Malicious domain boundary traversal attempts
        assert!(matches!(
            enforcer.validate_url("https://evilexample.com/attack"),
            Err(ScopeError::DomainNotAllowed(_))
        ));
        assert!(matches!(
            enforcer.validate_url("https://attacker-example.com/"),
            Err(ScopeError::DomainNotAllowed(_))
        ));
    }

    #[test]
    fn test_trailing_dot_domain_normalization() {
        let config = create_test_config();
        let enforcer = ScopeEnforcer::new(config).expect("failed to create enforcer");

        // FQDN with trailing dot should match allowed domain
        assert!(enforcer
            .validate_url("https://api.example.com./status")
            .is_ok());

        // Trailing-dot on excluded domain should be properly caught and excluded
        assert!(matches!(
            enforcer.validate_url("https://auth.example.com./login"),
            Err(ScopeError::DomainExcluded(_))
        ));
    }

    #[test]
    fn test_loopback_ip_matching() {
        let config = create_test_config();
        let enforcer = ScopeEnforcer::new(config).expect("failed to create enforcer");

        assert!(enforcer
            .validate_url("http://127.0.0.1:8080/openapi.json")
            .is_ok());
        assert!(matches!(
            enforcer.validate_url("http://192.168.1.1/admin"),
            Err(ScopeError::DomainNotAllowed(_))
        ));
    }

    #[test]
    fn test_excluded_domain_precedence() {
        let config = create_test_config();
        let enforcer = ScopeEnforcer::new(config).expect("failed to create enforcer");

        // auth.example.com is covered by *.example.com, but explicitly excluded
        let result = enforcer.validate_url("https://auth.example.com/login");
        assert!(matches!(result, Err(ScopeError::DomainExcluded(_))));
    }

    #[test]
    fn test_excluded_path_matching() {
        let config = create_test_config();
        let enforcer = ScopeEnforcer::new(config).expect("failed to create enforcer");

        assert!(matches!(
            enforcer.validate_url("https://example.com/logout"),
            Err(ScopeError::PathExcluded(_))
        ));
        assert!(matches!(
            enforcer.validate_url("https://example.com/logout/confirm"),
            Err(ScopeError::PathExcluded(_))
        ));
        assert!(matches!(
            enforcer.validate_url("https://example.com/delete-account"),
            Err(ScopeError::PathExcluded(_))
        ));

        // Allowed path sharing prefix substring but distinct segment
        assert!(enforcer
            .validate_url("https://example.com/logout-audit")
            .is_ok());
    }

    #[test]
    fn test_path_normalization_and_traversal_rejection() {
        let config = create_test_config();
        let enforcer = ScopeEnforcer::new(config).expect("failed to create enforcer");

        // Consecutive slashes
        assert!(matches!(
            enforcer.validate_url("https://example.com//logout"),
            Err(ScopeError::PathExcluded(_))
        ));

        // Path traversal with dot-dot
        assert!(matches!(
            enforcer.validate_url("https://example.com/public/../logout"),
            Err(ScopeError::PathExcluded(_))
        ));

        // Traversal targeting excluded /admin
        assert!(matches!(
            enforcer.validate_url("https://example.com/public/../admin"),
            Err(ScopeError::PathExcluded(_))
        ));

        // Percent-encoded dots
        assert!(matches!(
            enforcer.validate_url("https://example.com/%2e%2e/logout"),
            Err(ScopeError::PathExcluded(_))
        ));
        assert!(matches!(
            enforcer.validate_url("https://example.com/public/%2e%2e/admin/users"),
            Err(ScopeError::PathExcluded(_))
        ));

        // Verify standalone helper
        assert_eq!(normalize_path("//logout"), "/logout");
        assert_eq!(normalize_path("/public/../logout"), "/logout");
        assert_eq!(normalize_path("/%2e%2e/logout"), "/logout");
        assert_eq!(normalize_path("/a/b/../../c"), "/c");
        assert_eq!(normalize_path("/"), "/");
    }

    #[test]
    fn test_invalid_scheme_rejection() {
        let config = create_test_config();
        let enforcer = ScopeEnforcer::new(config).expect("failed to create enforcer");

        assert!(matches!(
            enforcer.validate_url("ftp://example.com/data"),
            Err(ScopeError::InvalidUrl(_))
        ));
        assert!(matches!(
            enforcer.validate_url("javascript:alert(1)"),
            Err(ScopeError::InvalidUrl(_))
        ));
    }

    #[test]
    fn test_config_validation_rules() {
        let mut config = create_test_config();
        config.program_name = "  ".to_string();
        assert!(matches!(
            config.validate(),
            Err(ScopeError::InvalidConfiguration(_))
        ));

        let mut config = create_test_config();
        config.allowed_domains = vec![];
        assert!(matches!(
            config.validate(),
            Err(ScopeError::InvalidConfiguration(_))
        ));

        let mut config = create_test_config();
        config.rate_limit_rps = 0;
        assert!(matches!(
            config.validate(),
            Err(ScopeError::InvalidRateLimit(0))
        ));

        let mut config = create_test_config();
        config.rate_limit_rps = 101;
        assert!(matches!(
            config.validate(),
            Err(ScopeError::InvalidRateLimit(101))
        ));

        // safe_mode must be true
        let mut config = create_test_config();
        config.safe_mode = false;
        assert!(matches!(
            config.validate(),
            Err(ScopeError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn test_unknown_yaml_fields_rejected() {
        let unknown_field_yaml = r#"
program_name: "test-corp"
platform: "hackerone"
allowed_domains: ["example.com"]
unknown_setting: true
"#;
        let err = ScopeConfig::from_yaml_str(unknown_field_yaml);
        assert!(matches!(err, Err(ScopeError::Yaml(_))));
    }
}
