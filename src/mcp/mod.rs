use std::collections::HashMap;

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Implementation, ServerCapabilities, ServerConfig, Tool},
    tool, tool_handler, tool_router, ServerHandler,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::McpError;
use crate::fingerprint::DetectedTechnology;
use crate::report::ReportGenerator;
use crate::scope::{ScopeConfig, ScopeEnforcer};
use crate::storage::StorageEngine;

/// Parameter schema for the `validate_scope` tool.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ValidateScopeRequest {
    /// Optional YAML configuration string to validate. If omitted, the server's active configuration is evaluated.
    #[serde(default)]
    pub config_yaml: Option<String>,
    /// Whether to enforce strict safety guardrails. Defaults to true if omitted.
    #[serde(default)]
    pub strict: Option<bool>,
}

/// Structured response schema for the `validate_scope` tool.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ValidateScopeResponse {
    /// Whether the configuration passed validation rules.
    pub valid: bool,
    /// Whether strict safety guardrails were evaluated.
    pub strict: bool,
    /// Program name if configuration parsed successfully.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_name: Option<String>,
    /// List of validation errors (empty if valid).
    pub errors: Vec<String>,
    /// List of validation warnings.
    pub warnings: Vec<String>,
}

/// Parameter schema for the `check_target_scope` tool.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct CheckTargetScopeRequest {
    /// Target URL string to evaluate against authorized scope boundaries.
    pub url: String,
}

/// Structured response schema for the `check_target_scope` tool.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct CheckTargetScopeResponse {
    /// Whether the target URL is authorized within scope.
    pub allowed: bool,
    /// Normalized URL string if validation succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized_url: Option<String>,
    /// Failure reason description if validation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Parameter schema for the `list_mapped_endpoints` tool.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ListMappedEndpointsRequest {
    /// Maximum number of endpoint records to return (defaults to all if omitted).
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Endpoint record summary returned by the `list_mapped_endpoints` tool.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct EndpointSummary {
    pub url: String,
    pub host: String,
    pub path: String,
    pub status_code: Option<u16>,
    pub discovered_via: String,
}

/// Parameter schema for the `list_security_findings` tool.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ListSecurityFindingsRequest {
    /// Optional severity filter (e.g. CRITICAL, HIGH, MEDIUM, LOW, INFO).
    #[serde(default)]
    pub severity: Option<String>,
}

/// Security finding summary returned by the `list_security_findings` tool.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct FindingSummary {
    pub id: String,
    pub finding_type: String,
    pub severity: String,
    pub title: String,
    pub target_url: String,
    pub evidence: String,
    pub remediation: Option<String>,
}

/// Parameter schema for the `generate_assessment_report` tool.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct GenerateAssessmentReportRequest {}

/// Parameter schema for the `diff_latest_scans` tool.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct DiffLatestScansRequest {
    /// Baseline scan run ID (defaults to previous scan run).
    #[serde(default)]
    pub from_run_id: Option<i64>,
    /// Target scan run ID (defaults to latest scan run).
    #[serde(default)]
    pub to_run_id: Option<i64>,
}

/// Parameter schema for the `list_detected_technologies` tool.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ListDetectedTechnologiesRequest {
    /// Optional category filter (e.g. WafCdn, WebServer, Framework, Cms, HostingPlatform).
    #[serde(default)]
    pub category: Option<String>,
}

/// Parameter schema for the `list_discovered_subdomains` tool.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ListDiscoveredSubdomainsRequest {
    /// Optional discovery source filter (e.g. ct_log, js_subdomain, sitemap_xml).
    #[serde(default)]
    pub source: Option<String>,
}

/// Subdomain summary returned by the `list_discovered_subdomains` tool.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct SubdomainSummary {
    pub hostname: String,
    pub source: String,
    pub url: String,
}

/// Native Model Context Protocol (MCP) server for BountyScope.
///
/// Exposes read-only and scope-verification tools over JSON-RPC 2.0 to authorized MCP clients:
/// - `check_target_scope`: Validates target URLs against active scope rules.
/// - `list_mapped_endpoints`: Lists stored surface endpoints for the active program.
/// - `list_security_findings`: Retrieves security verification findings with severity filtering.
/// - `generate_assessment_report`: Renders the complete Markdown assessment report.
/// - `diff_latest_scans`: Computes regressions and attack surface differences between historical scan runs.
/// - `validate_scope`: Validates scope configuration syntax and safety constraints.
/// - `list_detected_technologies`: Queries passively detected technologies, frameworks, and WAF/CDN infrastructure.
/// - `list_discovered_subdomains`: Queries discovered in-scope subdomains for the active program.
#[derive(Clone)]
pub struct BountyScopeMcpServer {
    enforcer: ScopeEnforcer,
    storage: StorageEngine,
    tool_router: ToolRouter<Self>,
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for BountyScopeMcpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("bountyscope", "0.16.4"))
            .with_instructions(
                "BountyScope Model Context Protocol server exposing scope validation, mapped endpoints, security findings, assessment reports, and historical regression diffs.",
            )
    }
}

#[tool_router(router = tool_router)]
impl BountyScopeMcpServer {
    /// Creates a new `BountyScopeMcpServer` bound to a loaded `ScopeEnforcer` and `StorageEngine`.
    pub fn new(enforcer: ScopeEnforcer, storage: StorageEngine) -> Self {
        Self {
            enforcer,
            storage,
            tool_router: Self::tool_router(),
        }
    }

    /// Evaluates whether a target URL is within authorized scope boundaries and returns canonicalization details.
    #[tool(
        name = "check_target_scope",
        description = "Evaluates whether a target URL is within authorized scope boundaries and returns canonicalization details.",
        annotations(
            title = "Check Target Scope",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn check_target_scope(
        &self,
        Parameters(params): Parameters<CheckTargetScopeRequest>,
    ) -> CallToolResult {
        let resp = self.evaluate_scope(&params.url);
        match serde_json::to_value(&resp) {
            Ok(val) => CallToolResult::structured(val),
            Err(e) => CallToolResult::structured_error(serde_json::json!({
                "error": "SerializationError",
                "message": e.to_string(),
            })),
        }
    }

    /// Queries stored surface endpoints for the active program from the database.
    #[tool(
        name = "list_mapped_endpoints",
        description = "Queries stored surface endpoints for the active program from the database.",
        annotations(
            title = "List Mapped Endpoints",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn list_mapped_endpoints(
        &self,
        Parameters(params): Parameters<ListMappedEndpointsRequest>,
    ) -> CallToolResult {
        match self.query_endpoints(params.limit) {
            Ok(endpoints) => {
                let count = endpoints.len();
                CallToolResult::structured(serde_json::json!({
                    "endpoints": endpoints,
                    "count": count,
                }))
            }
            Err(err) => CallToolResult::structured_error(serde_json::json!({
                "error": "DatabaseQueryError",
                "message": err.to_string(),
            })),
        }
    }

    /// Queries security verification findings from storage, optionally filtered by severity level.
    #[tool(
        name = "list_security_findings",
        description = "Queries security verification findings from storage, optionally filtered by severity level.",
        annotations(
            title = "List Security Findings",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn list_security_findings(
        &self,
        Parameters(params): Parameters<ListSecurityFindingsRequest>,
    ) -> CallToolResult {
        match self.query_findings(params.severity.as_deref()) {
            Ok(findings) => {
                let count = findings.len();
                CallToolResult::structured(serde_json::json!({
                    "findings": findings,
                    "count": count,
                }))
            }
            Err(err) => CallToolResult::structured_error(serde_json::json!({
                "error": "DatabaseQueryError",
                "message": err.to_string(),
            })),
        }
    }

    /// Generates the complete Markdown assessment report summarizing mapped endpoints and security verification findings.
    #[tool(
        name = "generate_assessment_report",
        description = "Generates the complete Markdown assessment report summarizing mapped endpoints and security verification findings.",
        annotations(
            title = "Generate Assessment Report",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn generate_assessment_report(
        &self,
        _params: Parameters<GenerateAssessmentReportRequest>,
    ) -> CallToolResult {
        match self.render_report() {
            Ok(report_md) => CallToolResult::structured(serde_json::json!({
                "report": report_md,
            })),
            Err(err) => CallToolResult::structured_error(serde_json::json!({
                "error": "ReportGenerationError",
                "message": err.to_string(),
            })),
        }
    }

    /// Computes regressions and attack surface differences between historical scan runs.
    #[tool(
        name = "diff_latest_scans",
        description = "Computes regressions and attack surface differences between historical scan runs.",
        annotations(
            title = "Diff Latest Scans",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn diff_latest_scans(
        &self,
        Parameters(params): Parameters<DiffLatestScansRequest>,
    ) -> CallToolResult {
        let program_name = &self.enforcer.config().program_name;
        let program = match self.storage.get_program_by_name(program_name) {
            Ok(p) => p,
            Err(e) => {
                return CallToolResult::structured_error(serde_json::json!({
                    "error": "ProgramNotFound",
                    "message": e.to_string(),
                }));
            }
        };

        let diff_res = match (params.from_run_id, params.to_run_id) {
            (Some(from), Some(to)) => self
                .storage
                .compute_diff_between_runs(&program.id, from, to),
            (Some(from), None) => match self.storage.get_scan_runs(&program.id) {
                Ok(runs) => match runs.first() {
                    Some(latest) => {
                        self.storage
                            .compute_diff_between_runs(&program.id, from, latest.id)
                    }
                    None => Err(crate::error::StorageError::NotFound(
                        "No historical scan runs found".to_string(),
                    )),
                },
                Err(e) => Err(e),
            },
            (None, Some(to)) => match self.storage.get_scan_runs(&program.id) {
                Ok(runs) => match runs.iter().position(|r| r.id == to) {
                    Some(idx) => match runs.get(idx + 1) {
                        Some(prev) => {
                            self.storage
                                .compute_diff_between_runs(&program.id, prev.id, to)
                        }
                        None => Err(crate::error::StorageError::NotFound(format!(
                            "No baseline run found prior to run #{to}"
                        ))),
                    },
                    None => Err(crate::error::StorageError::NotFound(format!(
                        "Scan run #{to} not found"
                    ))),
                },
                Err(e) => Err(e),
            },
            (None, None) => self.storage.compute_latest_diff(&program.id),
        };

        match diff_res {
            Ok(diff) => {
                let markdown_report = ReportGenerator::generate_diff_markdown(&diff);
                CallToolResult::structured(serde_json::json!({
                    "program_name": diff.program_name,
                    "baseline_run": diff.baseline_run,
                    "current_run": diff.current_run,
                    "new_endpoints": diff.new_endpoints,
                    "removed_endpoints": diff.removed_endpoints,
                    "status_changes": diff.status_changes,
                    "new_findings": diff.new_findings,
                    "resolved_findings": diff.resolved_findings,
                    "new_technologies": diff.new_technologies,
                    "removed_technologies": diff.removed_technologies,
                    "new_subdomains": diff.new_subdomains,
                    "removed_subdomains": diff.removed_subdomains,
                    "markdown_report": markdown_report,
                }))
            }
            Err(err) => CallToolResult::structured_error(serde_json::json!({
                "error": "DiffCalculationError",
                "message": err.to_string(),
            })),
        }
    }

    /// Validates scope configuration syntax and safety constraints with optional strict operator guardrails.
    #[tool(
        name = "validate_scope",
        description = "Validates scope configuration syntax and safety constraints with optional strict operator guardrails.",
        annotations(
            title = "Validate Scope",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn validate_scope(
        &self,
        Parameters(params): Parameters<ValidateScopeRequest>,
    ) -> CallToolResult {
        let is_strict = params.strict.unwrap_or(true);
        let resp = self.evaluate_config_scope(params.config_yaml.as_deref(), is_strict);
        match serde_json::to_value(&resp) {
            Ok(val) => CallToolResult::structured(val),
            Err(e) => CallToolResult::structured_error(serde_json::json!({
                "error": "SerializationError",
                "message": e.to_string(),
            })),
        }
    }

    /// Queries passively detected technologies, frameworks, and WAF/CDN infrastructure from storage, optionally filtered by category.
    #[tool(
        name = "list_detected_technologies",
        description = "Queries passively detected technologies, frameworks, and WAF/CDN infrastructure from storage, optionally filtered by category.",
        annotations(
            title = "List Detected Technologies",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn list_detected_technologies(
        &self,
        Parameters(params): Parameters<ListDetectedTechnologiesRequest>,
    ) -> CallToolResult {
        match self.query_technologies(params.category.as_deref()) {
            Ok(technologies) => {
                let count = technologies.len();
                CallToolResult::structured(serde_json::json!({
                    "technologies": technologies,
                    "count": count,
                }))
            }
            Err(err) => CallToolResult::structured_error(serde_json::json!({
                "error": "DatabaseQueryError",
                "message": err.to_string(),
            })),
        }
    }

    /// Queries discovered in-scope subdomains for the active program from storage, optionally filtered by discovery source.
    #[tool(
        name = "list_discovered_subdomains",
        description = "Queries discovered in-scope subdomains for the active program from storage, optionally filtered by discovery source.",
        annotations(
            title = "List Discovered Subdomains",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn list_discovered_subdomains(
        &self,
        Parameters(params): Parameters<ListDiscoveredSubdomainsRequest>,
    ) -> CallToolResult {
        match self.query_subdomains(params.source.as_deref()) {
            Ok(subdomains) => {
                let count = subdomains.len();
                CallToolResult::structured(serde_json::json!({
                    "subdomains": subdomains,
                    "count": count,
                }))
            }
            Err(err) => CallToolResult::structured_error(serde_json::json!({
                "error": "DatabaseQueryError",
                "message": err.to_string(),
            })),
        }
    }
}

impl BountyScopeMcpServer {
    /// Returns the list of registered tools and their annotations.
    pub fn list_tools(&self) -> Vec<Tool> {
        self.tool_router.list_all()
    }

    /// Returns a reference to the underlying `ScopeEnforcer`.
    pub fn enforcer(&self) -> &ScopeEnforcer {
        &self.enforcer
    }

    /// Returns a reference to the underlying `StorageEngine`.
    pub fn storage(&self) -> &StorageEngine {
        &self.storage
    }

    /// Evaluates a target URL against the active scope configuration.
    pub fn evaluate_scope(&self, url: &str) -> CheckTargetScopeResponse {
        match self.enforcer.validate_url(url) {
            Ok(verified) => CheckTargetScopeResponse {
                allowed: true,
                normalized_url: Some(verified.as_str().to_string()),
                reason: None,
            },
            Err(err) => CheckTargetScopeResponse {
                allowed: false,
                normalized_url: None,
                reason: Some(err.to_string()),
            },
        }
    }

    /// Validates a scope configuration either from raw YAML or against the active server configuration.
    pub fn evaluate_config_scope(
        &self,
        config_yaml: Option<&str>,
        strict: bool,
    ) -> ValidateScopeResponse {
        let config = match config_yaml {
            Some(raw) => match ScopeConfig::from_yaml_str(raw) {
                Ok(c) => c,
                Err(e) => {
                    return ValidateScopeResponse {
                        valid: false,
                        strict,
                        program_name: None,
                        errors: vec![format!("Failed to parse YAML scope configuration: {e}")],
                        warnings: Vec::new(),
                    }
                }
            },
            None => self.enforcer.config().clone(),
        };

        let report = config.lint_strict();
        let valid = if strict {
            report.is_valid()
        } else {
            config.validate().is_ok()
        };

        let errors = if strict { report.errors } else { Vec::new() };

        ValidateScopeResponse {
            valid,
            strict,
            program_name: Some(config.program_name),
            errors,
            warnings: report.warnings,
        }
    }

    /// Queries stored endpoints for the configured program.
    pub fn query_endpoints(&self, limit: Option<usize>) -> Result<Vec<EndpointSummary>, McpError> {
        let program_name = &self.enforcer.config().program_name;
        let program = self
            .storage
            .get_program_by_name(program_name)
            .map_err(McpError::Storage)?;

        let endpoints = self
            .storage
            .get_endpoints_for_program(&program.id)
            .map_err(McpError::Storage)?;

        let mut summaries: Vec<EndpointSummary> = endpoints
            .into_iter()
            .map(|e| EndpointSummary {
                url: e.url,
                host: e.host,
                path: e.path,
                status_code: e.status_code,
                discovered_via: e.discovered_via,
            })
            .collect();

        if let Some(lim) = limit {
            summaries.truncate(lim);
        }

        Ok(summaries)
    }

    /// Queries stored security findings for the configured program, optionally filtered by severity.
    pub fn query_findings(
        &self,
        severity_filter: Option<&str>,
    ) -> Result<Vec<FindingSummary>, McpError> {
        let program_name = &self.enforcer.config().program_name;
        let program = self
            .storage
            .get_program_by_name(program_name)
            .map_err(McpError::Storage)?;

        let endpoints = self
            .storage
            .get_endpoints_for_program(&program.id)
            .map_err(McpError::Storage)?;

        let endpoint_map: HashMap<String, String> =
            endpoints.into_iter().map(|e| (e.id, e.url)).collect();

        let mut findings = self
            .storage
            .get_findings_for_program(&program.id)
            .map_err(McpError::Storage)?;

        if let Some(filter) = severity_filter {
            findings.retain(|f| f.severity.eq_ignore_ascii_case(filter));
        }

        let summaries: Vec<FindingSummary> = findings
            .into_iter()
            .map(|f| {
                let target_url = f
                    .endpoint_id
                    .as_ref()
                    .and_then(|id| endpoint_map.get(id))
                    .cloned()
                    .unwrap_or_else(|| "Program-level".to_string());

                FindingSummary {
                    id: f.id,
                    finding_type: f.finding_type,
                    severity: f.severity,
                    title: f.title,
                    target_url,
                    evidence: f.evidence,
                    remediation: f.remediation,
                }
            })
            .collect();

        Ok(summaries)
    }

    /// Queries stored detected technologies for the configured program, optionally filtered by category.
    pub fn query_technologies(
        &self,
        category_filter: Option<&str>,
    ) -> Result<Vec<DetectedTechnology>, McpError> {
        let program_name = &self.enforcer.config().program_name;
        let program = self
            .storage
            .get_program_by_name(program_name)
            .map_err(McpError::Storage)?;

        let mut technologies = self
            .storage
            .get_detected_technologies_for_program(&program.id)
            .map_err(McpError::Storage)?;

        if let Some(filter) = category_filter {
            technologies.retain(|t| {
                t.category.to_string().eq_ignore_ascii_case(filter)
                    || match t.category {
                        crate::fingerprint::TechCategory::WafCdn => {
                            filter.eq_ignore_ascii_case("waf")
                                || filter.eq_ignore_ascii_case("cdn")
                                || filter.eq_ignore_ascii_case("waf_cdn")
                                || filter.eq_ignore_ascii_case("waf/cdn")
                        }
                        crate::fingerprint::TechCategory::WebServer => {
                            filter.eq_ignore_ascii_case("server")
                                || filter.eq_ignore_ascii_case("web_server")
                        }
                        crate::fingerprint::TechCategory::Framework => {
                            filter.eq_ignore_ascii_case("framework")
                        }
                        crate::fingerprint::TechCategory::Cms => filter.eq_ignore_ascii_case("cms"),
                        crate::fingerprint::TechCategory::HostingPlatform => {
                            filter.eq_ignore_ascii_case("hosting")
                                || filter.eq_ignore_ascii_case("hosting_platform")
                        }
                    }
            });
        }

        Ok(technologies)
    }

    /// Queries stored discovered subdomains for the configured program, optionally filtered by discovery source.
    pub fn query_subdomains(
        &self,
        source_filter: Option<&str>,
    ) -> Result<Vec<SubdomainSummary>, McpError> {
        let program_name = &self.enforcer.config().program_name;
        let program = self
            .storage
            .get_program_by_name(program_name)
            .map_err(McpError::Storage)?;

        let mut subdomains = self
            .storage
            .get_subdomains_for_program(&program.id)
            .map_err(McpError::Storage)?;

        if let Some(src) = source_filter {
            subdomains.retain(|s| s.source.eq_ignore_ascii_case(src));
        }

        let summaries: Vec<SubdomainSummary> = subdomains
            .into_iter()
            .map(|s| SubdomainSummary {
                hostname: s.hostname,
                source: s.source,
                url: s.url,
            })
            .collect();

        Ok(summaries)
    }

    /// Renders the complete Markdown report for the active program.
    pub fn render_report(&self) -> Result<String, McpError> {
        let program_name = &self.enforcer.config().program_name;
        let program = self
            .storage
            .get_program_by_name(program_name)
            .map_err(McpError::Storage)?;

        let endpoints = self
            .storage
            .get_endpoints_for_program(&program.id)
            .map_err(McpError::Storage)?;

        let findings = self
            .storage
            .get_findings_for_program(&program.id)
            .map_err(McpError::Storage)?;

        let technologies = self
            .storage
            .get_detected_technologies_for_program(&program.id)
            .map_err(McpError::Storage)?;

        let subdomains = self
            .storage
            .get_subdomains_for_program(&program.id)
            .map_err(McpError::Storage)?;

        let report_md = ReportGenerator::generate_markdown(
            &program,
            self.enforcer.config(),
            &endpoints,
            &findings,
            &technologies,
            &subdomains,
        );

        Ok(report_md)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::ScopeConfig;
    use crate::storage::{EndpointEntry, FindingEntry};

    fn test_scope_config() -> ScopeConfig {
        ScopeConfig {
            program_name: "mcp-test-app".to_string(),
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
        }
    }

    #[test]
    fn test_check_target_scope_evaluation() {
        let config = test_scope_config();
        let enforcer = ScopeEnforcer::new(config.clone()).expect("enforcer creation failed");
        let storage = StorageEngine::open_in_memory().expect("storage creation failed");
        let _ = storage
            .upsert_program_scope(&config)
            .expect("upsert failed");
        let server = BountyScopeMcpServer::new(enforcer, storage.clone());

        // In-scope evaluation
        let in_scope = server.evaluate_scope("https://example.com/api/v1/users");
        assert!(in_scope.allowed);
        assert_eq!(
            in_scope.normalized_url.as_deref(),
            Some("https://example.com/api/v1/users")
        );
        assert!(in_scope.reason.is_none());

        // Excluded domain evaluation
        let excluded_domain = server.evaluate_scope("https://auth.example.com/login");
        assert!(!excluded_domain.allowed);
        assert!(excluded_domain.normalized_url.is_none());
        assert!(excluded_domain.reason.is_some());

        // Excluded path evaluation
        let excluded_path = server.evaluate_scope("https://example.com/logout");
        assert!(!excluded_path.allowed);
        assert!(excluded_path.normalized_url.is_none());
        assert!(excluded_path.reason.is_some());

        // Out-of-scope external domain
        let out_of_scope = server.evaluate_scope("https://untrusted-target.invalid/");
        assert!(!out_of_scope.allowed);
    }

    #[test]
    fn test_list_mapped_endpoints_queries_and_limits() {
        let config = test_scope_config();
        let enforcer = ScopeEnforcer::new(config.clone()).expect("enforcer creation failed");
        let storage = StorageEngine::open_in_memory().expect("storage creation failed");
        let program_id = storage
            .upsert_program_scope(&config)
            .expect("upsert failed");

        for i in 1..=5 {
            let ep = EndpointEntry {
                program_id: program_id.clone(),
                url: format!("https://example.com/api/v{i}"),
                host: "example.com".to_string(),
                path: format!("/api/v{i}"),
                method: "GET".to_string(),
                discovered_via: "seed".to_string(),
                status_code: Some(200),
                response_size: Some(100),
                content_type: Some("application/json".to_string()),
            };
            storage.upsert_endpoint(&ep).expect("upsert ep failed");
        }

        let server = BountyScopeMcpServer::new(enforcer, storage.clone());

        let all = server.query_endpoints(None).expect("query all failed");
        assert_eq!(all.len(), 5);

        let limited = server
            .query_endpoints(Some(2))
            .expect("query limited failed");
        assert_eq!(limited.len(), 2);
        assert_eq!(limited[0].path, "/api/v1");
        assert_eq!(limited[1].path, "/api/v2");
    }

    #[test]
    fn test_list_security_findings_with_severity_filtering() {
        let config = test_scope_config();
        let enforcer = ScopeEnforcer::new(config.clone()).expect("enforcer creation failed");
        let storage = StorageEngine::open_in_memory().expect("storage creation failed");
        let program_id = storage
            .upsert_program_scope(&config)
            .expect("upsert failed");

        let ep = EndpointEntry {
            program_id: program_id.clone(),
            url: "https://example.com/api/data".to_string(),
            host: "example.com".to_string(),
            path: "/api/data".to_string(),
            method: "GET".to_string(),
            discovered_via: "seed".to_string(),
            status_code: Some(200),
            response_size: Some(100),
            content_type: Some("application/json".to_string()),
        };
        let ep_id = storage.upsert_endpoint(&ep).expect("upsert ep failed");

        let f_high = FindingEntry {
            program_id: program_id.clone(),
            endpoint_id: Some(ep_id.clone()),
            finding_type: "cors_misconfiguration".to_string(),
            severity: "HIGH".to_string(),
            title: "CORS arbitrary reflection with credentials".to_string(),
            description: "High severity finding".to_string(),
            evidence: "{}".to_string(),
            remediation: Some("Fix CORS".to_string()),
        };
        storage.upsert_finding(&f_high).expect("upsert f1 failed");

        let f_low = FindingEntry {
            program_id: program_id.clone(),
            endpoint_id: Some(ep_id),
            finding_type: "weak_csp".to_string(),
            severity: "LOW".to_string(),
            title: "Permissive CSP directives".to_string(),
            description: "Low severity finding".to_string(),
            evidence: "{}".to_string(),
            remediation: Some("Fix CSP".to_string()),
        };
        storage.upsert_finding(&f_low).expect("upsert f2 failed");

        let server = BountyScopeMcpServer::new(enforcer, storage.clone());

        let all_findings = server.query_findings(None).expect("query all failed");
        assert_eq!(all_findings.len(), 2);

        let high_findings = server
            .query_findings(Some("HIGH"))
            .expect("query high failed");
        assert_eq!(high_findings.len(), 1);
        assert_eq!(high_findings[0].severity, "HIGH");
        assert_eq!(high_findings[0].target_url, "https://example.com/api/data");

        let medium_findings = server
            .query_findings(Some("MEDIUM"))
            .expect("query medium failed");
        assert_eq!(medium_findings.len(), 0);
    }

    #[test]
    fn test_generate_assessment_report_via_server() {
        let config = test_scope_config();
        let enforcer = ScopeEnforcer::new(config.clone()).expect("enforcer creation failed");
        let storage = StorageEngine::open_in_memory().expect("storage creation failed");
        let program_id = storage
            .upsert_program_scope(&config)
            .expect("upsert failed");

        let ep = EndpointEntry {
            program_id: program_id.clone(),
            url: "https://example.com/health".to_string(),
            host: "example.com".to_string(),
            path: "/health".to_string(),
            method: "GET".to_string(),
            discovered_via: "seed".to_string(),
            status_code: Some(200),
            response_size: Some(15),
            content_type: Some("application/json".to_string()),
        };
        storage.upsert_endpoint(&ep).expect("upsert ep failed");

        let server = BountyScopeMcpServer::new(enforcer, storage.clone());
        let report = server.render_report().expect("render report failed");

        assert!(report.contains("# Security Assessment Report: mcp-test-app"));
        assert!(report.contains("security-researcher"));
        assert!(report.contains("https://example.com/policy"));
        assert!(report.contains("https://example.com/health"));
    }

    #[tokio::test]
    async fn test_tool_endpoint_handlers_return_call_tool_results() {
        let config = test_scope_config();
        let enforcer = ScopeEnforcer::new(config.clone()).expect("enforcer creation failed");
        let storage = StorageEngine::open_in_memory().expect("storage creation failed");
        let program_id = storage
            .upsert_program_scope(&config)
            .expect("upsert failed");

        let ep = EndpointEntry {
            program_id: program_id.clone(),
            url: "https://example.com/api/v1/health".to_string(),
            host: "example.com".to_string(),
            path: "/api/v1/health".to_string(),
            method: "GET".to_string(),
            discovered_via: "seed".to_string(),
            status_code: Some(200),
            response_size: Some(15),
            content_type: Some("application/json".to_string()),
        };
        storage.upsert_endpoint(&ep).expect("upsert ep failed");

        let server = BountyScopeMcpServer::new(enforcer, storage.clone());

        // 1. check_target_scope
        let res1 = server
            .check_target_scope(Parameters(CheckTargetScopeRequest {
                url: "https://example.com/api/v1/health".to_string(),
            }))
            .await;
        assert_eq!(res1.is_error, Some(false));
        let val1 = res1.structured_content.expect("structured content");
        assert_eq!(val1["allowed"], true);

        // 2. list_mapped_endpoints
        let res2 = server
            .list_mapped_endpoints(Parameters(ListMappedEndpointsRequest { limit: Some(10) }))
            .await;
        assert_eq!(res2.is_error, Some(false));
        let val2 = res2.structured_content.expect("structured content");
        assert_eq!(val2["count"], 1);

        // 3. list_security_findings
        let res3 = server
            .list_security_findings(Parameters(ListSecurityFindingsRequest { severity: None }))
            .await;
        assert_eq!(res3.is_error, Some(false));
        let val3 = res3.structured_content.expect("structured content");
        assert_eq!(val3["count"], 0);

        // 4. generate_assessment_report
        let res4 = server
            .generate_assessment_report(Parameters(GenerateAssessmentReportRequest {}))
            .await;
        assert_eq!(res4.is_error, Some(false));
        let val4 = res4.structured_content.expect("structured content");
        assert!(val4["report"]
            .as_str()
            .expect("report str")
            .contains("mcp-test-app"));

        // 5. list_detected_technologies
        let res_tech0 = server
            .list_detected_technologies(Parameters(ListDetectedTechnologiesRequest::default()))
            .await;
        assert_eq!(res_tech0.is_error, Some(false));
        let val_tech0 = res_tech0.structured_content.expect("structured content");
        assert_eq!(val_tech0["count"], 0);

        let tech = DetectedTechnology {
            name: "Cloudflare".to_string(),
            category: crate::fingerprint::TechCategory::WafCdn,
            version: None,
            evidence: "cf-ray: test".to_string(),
            endpoint: "https://example.com/api/v1/health".to_string(),
        };
        storage
            .upsert_detected_technology(&program_id, &tech)
            .expect("upsert tech failed");

        let res_tech1 = server
            .list_detected_technologies(Parameters(ListDetectedTechnologiesRequest {
                category: Some("WafCdn".to_string()),
            }))
            .await;
        assert_eq!(res_tech1.is_error, Some(false));
        let val_tech1 = res_tech1.structured_content.expect("structured content");
        assert_eq!(val_tech1["count"], 1);
        assert_eq!(val_tech1["technologies"][0]["name"], "Cloudflare");

        // 6. list_discovered_subdomains
        let res_sub0 = server
            .list_discovered_subdomains(Parameters(ListDiscoveredSubdomainsRequest::default()))
            .await;
        assert_eq!(res_sub0.is_error, Some(false));
        let val_sub0 = res_sub0.structured_content.expect("structured content");
        assert_eq!(val_sub0["count"], 1);
        assert_eq!(val_sub0["subdomains"][0]["hostname"], "example.com");

        // 7. diff_latest_scans (fewer than 2 runs returns structured error)
        let res5_err = server
            .diff_latest_scans(Parameters(DiffLatestScansRequest::default()))
            .await;
        assert_eq!(res5_err.is_error, Some(true));

        // Record Run 1
        let run1 = storage.record_scan_snapshot(&program_id).expect("run 1");

        // Add second endpoint and record Run 2
        let ep2 = EndpointEntry {
            program_id: program_id.clone(),
            url: "https://example.com/api/v2/items".to_string(),
            host: "example.com".to_string(),
            path: "/api/v2/items".to_string(),
            method: "GET".to_string(),
            discovered_via: "spec".to_string(),
            status_code: Some(200),
            response_size: Some(40),
            content_type: Some("application/json".to_string()),
        };
        storage.upsert_endpoint(&ep2).expect("upsert ep2 failed");
        let run2 = storage.record_scan_snapshot(&program_id).expect("run 2");

        let res5 = server
            .diff_latest_scans(Parameters(DiffLatestScansRequest {
                from_run_id: Some(run1),
                to_run_id: Some(run2),
            }))
            .await;
        assert_eq!(res5.is_error, Some(false));
        let val5 = res5.structured_content.expect("structured content");
        assert_eq!(val5["new_endpoints"][0], "https://example.com/api/v2/items");
        assert!(val5["markdown_report"]
            .as_str()
            .expect("md report")
            .contains("New Endpoints Discovered (1)"));
    }

    #[tokio::test]
    async fn test_validate_scope_mcp_tool() {
        let config = test_scope_config();
        let enforcer = ScopeEnforcer::new(config).expect("enforcer creation failed");
        let storage = StorageEngine::open_in_memory().expect("storage creation failed");
        let server = BountyScopeMcpServer::new(enforcer, storage);

        // 1. Validate active configuration with strict mode
        let res1 = server
            .validate_scope(Parameters(ValidateScopeRequest {
                config_yaml: None,
                strict: Some(true),
            }))
            .await;
        assert_eq!(res1.is_error, Some(false));
        let val1 = res1.structured_content.expect("structured content");
        assert_eq!(val1["program_name"], "mcp-test-app");
        assert_eq!(val1["strict"], true);

        // 2. Validate custom YAML containing prohibited catch-all wildcard
        let bad_yaml = r#"
program_name: "wildcard-target"
platform: "hackerone"
allowed_domains: ["*"]
rate_limit_rps: 2
safe_mode: true
"#;
        let res2 = server
            .validate_scope(Parameters(ValidateScopeRequest {
                config_yaml: Some(bad_yaml.to_string()),
                strict: Some(true),
            }))
            .await;
        assert_eq!(res2.is_error, Some(false));
        let val2 = res2.structured_content.expect("structured content");
        assert_eq!(val2["valid"], false);
        assert!(!val2["errors"].as_array().expect("errors").is_empty());

        // 3. Same YAML with strict: false should pass standard validation
        let res3 = server
            .validate_scope(Parameters(ValidateScopeRequest {
                config_yaml: Some(bad_yaml.to_string()),
                strict: Some(false),
            }))
            .await;
        assert_eq!(res3.is_error, Some(false));
        let val3 = res3.structured_content.expect("structured content");
        assert_eq!(val3["valid"], true);
    }

    #[test]
    fn test_list_tools_explicit_mcp_tool_annotations() {
        let config = test_scope_config();
        let enforcer = ScopeEnforcer::new(config).expect("enforcer creation failed");
        let storage = StorageEngine::open_in_memory().expect("storage creation failed");
        let server = BountyScopeMcpServer::new(enforcer, storage);

        let tools = server.list_tools();
        assert!(
            tools.len() >= 5,
            "Expected at least 5 registered MCP tools, found {}",
            tools.len()
        );

        let serialized_json = serde_json::to_value(&tools).expect("serialization to JSON failed");
        let tool_array = serialized_json.as_array().expect("tools array in JSON");

        let expected_tools = [
            "check_target_scope",
            "list_mapped_endpoints",
            "list_security_findings",
            "generate_assessment_report",
            "diff_latest_scans",
            "validate_scope",
            "list_detected_technologies",
            "list_discovered_subdomains",
        ];

        for tool_name in &expected_tools {
            let tool_obj = tool_array
                .iter()
                .find(|t| t["name"].as_str() == Some(tool_name))
                .unwrap_or_else(|| {
                    panic!("Expected tool '{}' not found in serialized list", tool_name)
                });

            let annotations = &tool_obj["annotations"];
            assert!(
                annotations.is_object(),
                "Tool '{}' missing annotations object in JSON: {:?}",
                tool_name,
                tool_obj
            );

            assert_eq!(
                annotations["readOnlyHint"].as_bool(),
                Some(true),
                "Tool '{}' readOnlyHint must be true",
                tool_name
            );
            assert_eq!(
                annotations["destructiveHint"].as_bool(),
                Some(false),
                "Tool '{}' destructiveHint must be false",
                tool_name
            );
            assert_eq!(
                annotations["idempotentHint"].as_bool(),
                Some(true),
                "Tool '{}' idempotentHint must be true",
                tool_name
            );
            assert_eq!(
                annotations["openWorldHint"].as_bool(),
                Some(false),
                "Tool '{}' openWorldHint must be false",
                tool_name
            );
        }

        for tool in tool_array {
            let name = tool["name"].as_str().unwrap_or("unknown");
            let ann = &tool["annotations"];
            assert!(
                ann["readOnlyHint"].is_boolean(),
                "Tool '{}' readOnlyHint is not a boolean",
                name
            );
            assert!(
                ann["destructiveHint"].is_boolean(),
                "Tool '{}' destructiveHint is not a boolean",
                name
            );
            assert!(
                ann["idempotentHint"].is_boolean(),
                "Tool '{}' idempotentHint is not a boolean",
                name
            );
            assert!(
                ann["openWorldHint"].is_boolean(),
                "Tool '{}' openWorldHint is not a boolean",
                name
            );
        }
    }
}
