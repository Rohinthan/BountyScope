use crate::error::ReportError;
use crate::scope::ScopeConfig;
use crate::storage::{
    DiffFindingItem, EndpointRecord, EndpointStatusChange, FindingRecord, ProgramRecord, ScanDiff,
    ScanRunRecord,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Supported assessment report output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    /// Formatted GitHub-flavored Markdown
    #[default]
    Md,
    /// Structured JSON schema for CI/CD pipelines and scripting
    Json,
    /// OASIS Static Analysis Results Interchange Format (SARIF v2.1.0)
    Sarif,
}

impl ReportFormat {
    /// Returns the standard file extension for this format.
    pub fn extension(&self) -> &'static str {
        match self {
            ReportFormat::Md => "md",
            ReportFormat::Json => "json",
            ReportFormat::Sarif => "sarif",
        }
    }
}

impl std::fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportFormat::Md => write!(f, "md"),
            ReportFormat::Json => write!(f, "json"),
            ReportFormat::Sarif => write!(f, "sarif"),
        }
    }
}

/// Strongly typed structured JSON assessment report schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonReport {
    pub schema_version: String,
    pub tool: JsonToolMetadata,
    pub program: JsonProgramMetadata,
    pub summary: JsonReportSummary,
    pub endpoints: Vec<JsonEndpointItem>,
    pub findings: Vec<JsonFindingItem>,
}

/// Metadata identifying the executing tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonToolMetadata {
    pub name: String,
    pub version: String,
}

/// Program and scope policy configuration metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonProgramMetadata {
    pub name: String,
    pub platform: String,
    pub policy_url: Option<String>,
    pub researcher_handle: Option<String>,
    pub safe_mode: bool,
    pub rate_limit_rps: u32,
}

/// High-level report metrics and severity breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonReportSummary {
    pub endpoints_count: usize,
    pub findings_count: usize,
    pub severity_breakdown: JsonSeverityBreakdown,
}

/// Aggregated severity counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSeverityBreakdown {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

/// Mapped surface endpoint in JSON report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonEndpointItem {
    pub id: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub method: String,
    pub discovered_via: String,
    pub status_code: Option<u16>,
    pub response_size: Option<usize>,
    pub content_type: Option<String>,
}

/// Security finding in JSON report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonFindingItem {
    pub id: String,
    pub finding_type: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub target_url: String,
    pub evidence: serde_json::Value,
    pub remediation: Option<String>,
    pub verified_at: String,
}

/// Strongly typed JSON representation of a scan regression diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonDiffReport {
    pub schema_version: String,
    pub tool: JsonToolMetadata,
    pub program_name: String,
    pub baseline_run: ScanRunRecord,
    pub current_run: ScanRunRecord,
    pub metrics: JsonDiffMetrics,
    pub new_endpoints: Vec<String>,
    pub removed_endpoints: Vec<String>,
    pub status_changes: Vec<EndpointStatusChange>,
    pub new_findings: Vec<DiffFindingItem>,
    pub resolved_findings: Vec<DiffFindingItem>,
}

/// Quantitative delta metrics between two scan runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonDiffMetrics {
    pub total_endpoints_delta: i64,
    pub total_findings_delta: i64,
    pub new_endpoints_count: usize,
    pub removed_endpoints_count: usize,
    pub status_changes_count: usize,
    pub new_findings_count: usize,
    pub resolved_findings_count: usize,
}

/// OASIS SARIF v2.1.0 document schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

/// Execution run in SARIF v2.1.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

/// Tool container in SARIF v2.1.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

/// Component driver in SARIF v2.1.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

/// Rule definition in SARIF v2.1.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription", skip_serializing_if = "Option::is_none")]
    pub full_description: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<SarifHelp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifRuleProperties>,
}

/// Help and remediation guidance in SARIF v2.1.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifHelp {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
}

/// Rule properties conforming to GitHub Code Scanning standards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRuleProperties {
    #[serde(rename = "problem.severity", skip_serializing_if = "Option::is_none")]
    pub problem_severity: Option<String>,
    #[serde(rename = "security-severity", skip_serializing_if = "Option::is_none")]
    pub security_severity: Option<String>,
}

/// Verification result item in SARIF v2.1.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

/// Message text container in SARIF v2.1.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

/// Physical location container in SARIF v2.1.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

/// Artifact location reference in SARIF v2.1.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
}

/// Artifact location URI in SARIF v2.1.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

fn resolve_target_url<'a>(endpoint_id: Option<&str>, endpoints: &'a [EndpointRecord]) -> &'a str {
    if let Some(ep_id) = endpoint_id {
        endpoints
            .iter()
            .find(|e| e.id == ep_id)
            .map(|e| e.url.as_str())
            .unwrap_or("Program-level")
    } else {
        "Program-level"
    }
}

/// Generates structured reports from security verification findings.
pub struct ReportGenerator;

impl ReportGenerator {
    /// Renders a full Markdown assessment report for a program.
    pub fn generate_markdown(
        program: &ProgramRecord,
        config: &ScopeConfig,
        endpoints: &[EndpointRecord],
        findings: &[FindingRecord],
    ) -> String {
        let mut doc = String::new();

        // 1. Title and Program Summary
        doc.push_str(&format!(
            "# Security Assessment Report: {}\n\n",
            program.name
        ));
        doc.push_str("## Executive Summary\n\n");
        doc.push_str(&format!("- **Program Name:** {}\n", program.name));
        doc.push_str(&format!("- **Platform / Source:** {}\n", program.platform));
        if let Some(policy_url) = &program.policy_url {
            doc.push_str(&format!("- **Policy / Safe Harbor:** {}\n", policy_url));
        }
        if let Some(handle) = &config.researcher_handle {
            doc.push_str(&format!("- **Researcher Attribution:** `{}`\n", handle));
        }
        doc.push_str(&format!(
            "- **Total Endpoints Audited:** {}\n",
            endpoints.len()
        ));
        doc.push_str(&format!(
            "- **Total Security Findings:** {}\n",
            findings.len()
        ));
        doc.push_str(&format!(
            "- **Report Generated At:** {}\n\n",
            program.updated_at
        ));

        // 2. Scope Rules and Constraints
        doc.push_str("## Scope Policy & Rules of Engagement\n\n");
        doc.push_str(&format!("- **Safe Mode Enforced:** {}\n", config.safe_mode));
        doc.push_str(&format!(
            "- **Rate Limit Ceiling:** {} req/sec\n",
            config.rate_limit_rps
        ));
        if let Some(handle) = &config.researcher_handle {
            doc.push_str(&format!(
                "- **Researcher Attribution Header (`X-Bug-Bounty`):** `{}`\n",
                handle
            ));
        }
        if let Some(policy_url) = &config.policy_url {
            doc.push_str(&format!("- **Governing Policy URL:** {}\n", policy_url));
        }

        doc.push_str("\n### Allowed Target Domains\n");
        if config.allowed_domains.is_empty() {
            doc.push_str("_None defined_\n");
        } else {
            for domain in &config.allowed_domains {
                doc.push_str(&format!("- `{domain}`\n"));
            }
        }

        doc.push_str("\n### Excluded Domains\n");
        if config.excluded_domains.is_empty() {
            doc.push_str("_None defined_\n");
        } else {
            for domain in &config.excluded_domains {
                doc.push_str(&format!("- `{domain}`\n"));
            }
        }

        doc.push_str("\n### Excluded URI Paths\n");
        if config.excluded_paths.is_empty() {
            doc.push_str("_None defined_\n");
        } else {
            for path in &config.excluded_paths {
                doc.push_str(&format!("- `{path}`\n"));
            }
        }

        doc.push_str("\n### Excluded Checks (Rules of Engagement)\n");
        if config.excluded_checks.is_empty() {
            doc.push_str("_None defined_\n");
        } else {
            for check in &config.excluded_checks {
                doc.push_str(&format!("- `{check}`\n"));
            }
        }

        // 3. Severity Breakdown Table
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut info_count = 0;

        for f in findings {
            match f.severity.as_str() {
                "CRITICAL" => critical_count += 1,
                "HIGH" => high_count += 1,
                "MEDIUM" => medium_count += 1,
                "LOW" => low_count += 1,
                "INFO" => info_count += 1,
                _ => {}
            }
        }

        doc.push_str("\n## Severity Breakdown\n\n");
        doc.push_str("| Severity Level | Count |\n");
        doc.push_str("| --- | ---: |\n");
        doc.push_str(&format!("| **CRITICAL** | {critical_count} |\n"));
        doc.push_str(&format!("| **HIGH** | {high_count} |\n"));
        doc.push_str(&format!("| **MEDIUM** | {medium_count} |\n"));
        doc.push_str(&format!("| **LOW** | {low_count} |\n"));
        doc.push_str(&format!("| **INFO** | {info_count} |\n"));
        doc.push_str(&format!(
            "| **Total Findings** | **{}** |\n\n",
            findings.len()
        ));

        // 4. Mapped Surface Endpoints
        doc.push_str("## Mapped Surface Endpoints\n\n");
        if endpoints.is_empty() {
            doc.push_str("_No surface endpoints mapped._\n\n");
        } else {
            doc.push_str("| URL | Discovered Via | HTTP Status | Response Size |\n");
            doc.push_str("| --- | --- | ---: | ---: |\n");
            for ep in endpoints {
                let status_str = ep
                    .status_code
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "-".to_string());
                let size_str = ep
                    .response_size
                    .map(|sz| format!("{sz} bytes"))
                    .unwrap_or_else(|| "-".to_string());
                doc.push_str(&format!(
                    "| `{}` | `{}` | {} | {} |\n",
                    ep.url, ep.discovered_via, status_str, size_str
                ));
            }
            doc.push('\n');
        }

        // 5. Detailed Findings Sections
        doc.push_str("## Detailed Security Findings\n\n");
        if findings.is_empty() {
            doc.push_str("_No policy violations or configuration weaknesses were identified._\n");
        } else {
            for (idx, finding) in findings.iter().enumerate() {
                // Find matching endpoint URL if available
                let target_url = endpoints
                    .iter()
                    .find(|e| Some(&e.id) == finding.endpoint_id.as_ref())
                    .map(|e| e.url.as_str())
                    .unwrap_or("Program-level");

                doc.push_str(&format!(
                    "### {}. [{}] {}\n\n",
                    idx + 1,
                    finding.severity,
                    finding.title
                ));
                doc.push_str(&format!("- **Target URL:** `{target_url}`\n"));
                doc.push_str(&format!("- **Finding Type:** `{}`\n", finding.finding_type));
                doc.push_str(&format!("- **Verified At:** {}\n\n", finding.verified_at));

                doc.push_str("#### Description\n\n");
                doc.push_str(&format!("{}\n\n", finding.description));

                doc.push_str("#### Observed Evidence\n\n");
                // Pretty-print JSON evidence if valid
                if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&finding.evidence) {
                    if let Ok(pretty) = serde_json::to_string_pretty(&json_val) {
                        doc.push_str(&format!("```json\n{}\n```\n\n", pretty));
                    } else {
                        doc.push_str(&format!("```json\n{}\n```\n\n", finding.evidence));
                    }
                } else {
                    doc.push_str(&format!("```text\n{}\n```\n\n", finding.evidence));
                }

                if let Some(remediation) = &finding.remediation {
                    doc.push_str("#### Remediation Guidance\n\n");
                    doc.push_str(&format!("{}\n\n", remediation));
                }

                doc.push_str("---\n\n");
            }
        }

        doc
    }

    /// Writes report markdown content to a destination filesystem path.
    pub fn write_to_file<P: AsRef<Path>>(report_content: &str, path: P) -> Result<(), ReportError> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(path, report_content)?;
        Ok(())
    }

    /// Renders a Markdown regression and attack surface diff report.
    pub fn generate_diff_markdown(diff: &ScanDiff) -> String {
        let mut doc = String::new();

        // 1. Header and Executive Delta Summary
        doc.push_str(&format!(
            "# Scan Regression & Attack Surface Diff: {}\n\n",
            diff.program_name
        ));
        doc.push_str("## Executive Delta Summary\n\n");
        doc.push_str(&format!("- **Program Name:** {}\n", diff.program_name));
        doc.push_str(&format!(
            "- **Baseline Scan:** Run #{} (`{}`)\n",
            diff.baseline_run.id, diff.baseline_run.created_at
        ));
        doc.push_str(&format!(
            "- **Current Scan:** Run #{} (`{}`)\n\n",
            diff.current_run.id, diff.current_run.created_at
        ));

        let ep_delta =
            diff.current_run.endpoints_count as i64 - diff.baseline_run.endpoints_count as i64;
        let ep_delta_str = if ep_delta > 0 {
            format!("+{ep_delta}")
        } else {
            ep_delta.to_string()
        };

        let f_delta =
            diff.current_run.findings_count as i64 - diff.baseline_run.findings_count as i64;
        let f_delta_str = if f_delta > 0 {
            format!("+{f_delta}")
        } else {
            f_delta.to_string()
        };

        doc.push_str("| Metric | Baseline | Current | Delta |\n");
        doc.push_str("| :--- | :--- | :--- | :---: |\n");
        doc.push_str(&format!(
            "| **Total Endpoints** | {} | {} | {} |\n",
            diff.baseline_run.endpoints_count, diff.current_run.endpoints_count, ep_delta_str
        ));
        doc.push_str(&format!(
            "| **Total Findings** | {} | {} | {} |\n",
            diff.baseline_run.findings_count, diff.current_run.findings_count, f_delta_str
        ));
        doc.push_str(&format!(
            "| **New Endpoints** | - | - | +{} |\n",
            diff.new_endpoints.len()
        ));
        doc.push_str(&format!(
            "| **Removed Endpoints** | - | - | -{} |\n",
            diff.removed_endpoints.len()
        ));
        doc.push_str(&format!(
            "| **Status Transitions** | - | - | {} |\n",
            diff.status_changes.len()
        ));
        doc.push_str(&format!(
            "| **New Findings (Regressions)** | - | - | +{} |\n",
            diff.new_findings.len()
        ));
        doc.push_str(&format!(
            "| **Resolved Findings** | - | - | -{} |\n\n",
            diff.resolved_findings.len()
        ));

        // 2. New Endpoints
        doc.push_str(&format!(
            "## New Endpoints Discovered ({})\n\n",
            diff.new_endpoints.len()
        ));
        if diff.new_endpoints.is_empty() {
            doc.push_str("_No new surface endpoints discovered._\n\n");
        } else {
            for ep in &diff.new_endpoints {
                doc.push_str(&format!("- `{ep}`\n"));
            }
            doc.push('\n');
        }

        // 3. HTTP Status Transitions
        doc.push_str(&format!(
            "## HTTP Status Transitions ({})\n\n",
            diff.status_changes.len()
        ));
        if diff.status_changes.is_empty() {
            doc.push_str("_No endpoint HTTP status code transitions observed._\n\n");
        } else {
            doc.push_str("| Endpoint URL | Baseline Status | Current Status |\n");
            doc.push_str("| :--- | :---: | :---: |\n");
            for change in &diff.status_changes {
                doc.push_str(&format!(
                    "| `{}` | `{}` | `{}` |\n",
                    change.url, change.baseline_status, change.current_status
                ));
            }
            doc.push('\n');
        }

        // 4. New Findings (Regressions)
        doc.push_str(&format!(
            "## New Security Findings / Regressions ({})\n\n",
            diff.new_findings.len()
        ));
        if diff.new_findings.is_empty() {
            doc.push_str("_No new security findings or regressions identified._\n\n");
        } else {
            doc.push_str("| Severity | Finding Type | Target URL | Title |\n");
            doc.push_str("| :--- | :--- | :--- | :--- |\n");
            for f in &diff.new_findings {
                doc.push_str(&format!(
                    "| **{}** | `{}` | `{}` | {} |\n",
                    f.severity, f.finding_type, f.target_url, f.title
                ));
            }
            doc.push('\n');
        }

        // 5. Resolved Findings
        doc.push_str(&format!(
            "## Resolved Security Findings ({})\n\n",
            diff.resolved_findings.len()
        ));
        if diff.resolved_findings.is_empty() {
            doc.push_str("_No previously reported security findings were resolved._\n\n");
        } else {
            doc.push_str("| Baseline Severity | Finding Type | Target URL | Title |\n");
            doc.push_str("| :--- | :--- | :--- | :--- |\n");
            for f in &diff.resolved_findings {
                doc.push_str(&format!(
                    "| **{}** | `{}` | `{}` | {} |\n",
                    f.severity, f.finding_type, f.target_url, f.title
                ));
            }
            doc.push('\n');
        }

        // 6. Removed Endpoints
        doc.push_str(&format!(
            "## Removed Surface Endpoints ({})\n\n",
            diff.removed_endpoints.len()
        ));
        if diff.removed_endpoints.is_empty() {
            doc.push_str("_No surface endpoints were removed._\n\n");
        } else {
            for ep in &diff.removed_endpoints {
                doc.push_str(&format!("- `{ep}`\n"));
            }
            doc.push('\n');
        }

        doc
    }

    /// Renders a structured JSON assessment report.
    pub fn render_json_report(
        program: &ProgramRecord,
        config: &ScopeConfig,
        endpoints: &[EndpointRecord],
        findings: &[FindingRecord],
    ) -> Result<String, ReportError> {
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut info_count = 0;

        for f in findings {
            match f.severity.as_str() {
                "CRITICAL" => critical_count += 1,
                "HIGH" => high_count += 1,
                "MEDIUM" => medium_count += 1,
                "LOW" => low_count += 1,
                "INFO" => info_count += 1,
                _ => {}
            }
        }

        let json_endpoints: Vec<JsonEndpointItem> = endpoints
            .iter()
            .map(|ep| JsonEndpointItem {
                id: ep.id.clone(),
                url: ep.url.clone(),
                host: ep.host.clone(),
                path: ep.path.clone(),
                method: ep.method.clone(),
                discovered_via: ep.discovered_via.clone(),
                status_code: ep.status_code,
                response_size: ep.response_size,
                content_type: ep.content_type.clone(),
            })
            .collect();

        let json_findings: Vec<JsonFindingItem> = findings
            .iter()
            .map(|f| {
                let target_url =
                    resolve_target_url(f.endpoint_id.as_deref(), endpoints).to_string();
                let evidence = serde_json::from_str::<serde_json::Value>(&f.evidence)
                    .unwrap_or_else(|_| serde_json::Value::String(f.evidence.clone()));

                JsonFindingItem {
                    id: f.id.clone(),
                    finding_type: f.finding_type.clone(),
                    severity: f.severity.clone(),
                    title: f.title.clone(),
                    description: f.description.clone(),
                    target_url,
                    evidence,
                    remediation: f.remediation.clone(),
                    verified_at: f.verified_at.clone(),
                }
            })
            .collect();

        let report = JsonReport {
            schema_version: "0.16.0".to_string(),
            tool: JsonToolMetadata {
                name: "BountyScope".to_string(),
                version: "0.16.0".to_string(),
            },
            program: JsonProgramMetadata {
                name: program.name.clone(),
                platform: program.platform.clone(),
                policy_url: program.policy_url.clone(),
                researcher_handle: config.researcher_handle.clone(),
                safe_mode: config.safe_mode,
                rate_limit_rps: config.rate_limit_rps,
            },
            summary: JsonReportSummary {
                endpoints_count: endpoints.len(),
                findings_count: findings.len(),
                severity_breakdown: JsonSeverityBreakdown {
                    critical: critical_count,
                    high: high_count,
                    medium: medium_count,
                    low: low_count,
                    info: info_count,
                },
            },
            endpoints: json_endpoints,
            findings: json_findings,
        };

        serde_json::to_string_pretty(&report).map_err(ReportError::from)
    }

    /// Renders an OASIS SARIF v2.1.0 JSON report suitable for GitHub Code Scanning.
    pub fn render_sarif_report(
        _program: &ProgramRecord,
        _config: &ScopeConfig,
        endpoints: &[EndpointRecord],
        findings: &[FindingRecord],
    ) -> Result<String, ReportError> {
        let mut rules_map: BTreeMap<String, SarifRule> = BTreeMap::new();
        let mut results: Vec<SarifResult> = Vec::with_capacity(findings.len());

        for finding in findings {
            // Deduplicated rule entry
            rules_map
                .entry(finding.finding_type.clone())
                .or_insert_with(|| {
                    let (problem_severity, security_severity) = match finding.severity.as_str() {
                        "CRITICAL" => ("error", "9.0"),
                        "HIGH" => ("error", "7.0"),
                        "MEDIUM" => ("warning", "5.0"),
                        "LOW" => ("recommendation", "3.0"),
                        "INFO" => ("recommendation", "1.0"),
                        _ => ("recommendation", "1.0"),
                    };

                    SarifRule {
                        id: finding.finding_type.clone(),
                        name: finding.finding_type.clone(),
                        short_description: SarifMessage {
                            text: finding.title.clone(),
                        },
                        full_description: Some(SarifMessage {
                            text: finding.description.clone(),
                        }),
                        help: finding.remediation.as_ref().map(|rem| SarifHelp {
                            text: rem.clone(),
                            markdown: Some(rem.clone()),
                        }),
                        properties: Some(SarifRuleProperties {
                            problem_severity: Some(problem_severity.to_string()),
                            security_severity: Some(security_severity.to_string()),
                        }),
                    }
                });

            let level = match finding.severity.as_str() {
                "CRITICAL" | "HIGH" => "error",
                "MEDIUM" => "warning",
                "LOW" | "INFO" => "note",
                _ => "note",
            };

            let target_url =
                resolve_target_url(finding.endpoint_id.as_deref(), endpoints).to_string();

            results.push(SarifResult {
                rule_id: finding.finding_type.clone(),
                level: level.to_string(),
                message: SarifMessage {
                    text: format!("{}: {}", finding.title, finding.description),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation { uri: target_url },
                    },
                }],
            });
        }

        let sarif = SarifReport {
            schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "BountyScope".to_string(),
                        version: "0.16.0".to_string(),
                        information_uri: "https://github.com/Rohinthan/BountyScope".to_string(),
                        rules: rules_map.into_values().collect(),
                    },
                },
                results,
            }],
        };

        serde_json::to_string_pretty(&sarif).map_err(ReportError::from)
    }

    /// Renders a structured JSON scan diff report.
    pub fn render_json_diff(diff: &ScanDiff) -> Result<String, ReportError> {
        let ep_delta =
            diff.current_run.endpoints_count as i64 - diff.baseline_run.endpoints_count as i64;
        let f_delta =
            diff.current_run.findings_count as i64 - diff.baseline_run.findings_count as i64;

        let diff_report = JsonDiffReport {
            schema_version: "0.16.0".to_string(),
            tool: JsonToolMetadata {
                name: "BountyScope".to_string(),
                version: "0.16.0".to_string(),
            },
            program_name: diff.program_name.clone(),
            baseline_run: diff.baseline_run.clone(),
            current_run: diff.current_run.clone(),
            metrics: JsonDiffMetrics {
                total_endpoints_delta: ep_delta,
                total_findings_delta: f_delta,
                new_endpoints_count: diff.new_endpoints.len(),
                removed_endpoints_count: diff.removed_endpoints.len(),
                status_changes_count: diff.status_changes.len(),
                new_findings_count: diff.new_findings.len(),
                resolved_findings_count: diff.resolved_findings.len(),
            },
            new_endpoints: diff.new_endpoints.clone(),
            removed_endpoints: diff.removed_endpoints.clone(),
            status_changes: diff.status_changes.clone(),
            new_findings: diff.new_findings.clone(),
            resolved_findings: diff.resolved_findings.clone(),
        };

        serde_json::to_string_pretty(&diff_report).map_err(ReportError::from)
    }

    /// Renders an assessment report in the specified format (md, json, or sarif).
    pub fn render_report(
        format: ReportFormat,
        program: &ProgramRecord,
        config: &ScopeConfig,
        endpoints: &[EndpointRecord],
        findings: &[FindingRecord],
    ) -> Result<String, ReportError> {
        match format {
            ReportFormat::Md => Ok(Self::generate_markdown(
                program, config, endpoints, findings,
            )),
            ReportFormat::Json => Self::render_json_report(program, config, endpoints, findings),
            ReportFormat::Sarif => Self::render_sarif_report(program, config, endpoints, findings),
        }
    }

    /// Renders a regression and attack surface diff in the specified format (md or json).
    pub fn render_diff(format: ReportFormat, diff: &ScanDiff) -> Result<String, ReportError> {
        match format {
            ReportFormat::Md => Ok(Self::generate_diff_markdown(diff)),
            ReportFormat::Json => Self::render_json_diff(diff),
            ReportFormat::Sarif => Err(ReportError::UnsupportedFormat(
                "SARIF format is not supported for diff reports. Use 'md' or 'json'.".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_markdown_report_formatting() {
        let program = ProgramRecord {
            id: "prog-1".to_string(),
            name: "report-test-app".to_string(),
            platform: "local".to_string(),
            policy_url: Some("https://hackerone.com/example-program/policy".to_string()),
            created_at: "2026-11-14 10:00:00".to_string(),
            updated_at: "2026-11-14 10:05:00".to_string(),
        };

        let config = ScopeConfig {
            program_name: "report-test-app".to_string(),
            platform: "local".to_string(),
            allowed_domains: vec!["127.0.0.1".to_string()],
            excluded_domains: vec!["logout.example.com".to_string()],
            excluded_paths: vec!["/logout".to_string()],
            rate_limit_rps: 10,
            safe_mode: true,
            researcher_handle: Some("security-researcher".to_string()),
            policy_url: Some("https://hackerone.com/example-program/policy".to_string()),
            excluded_checks: vec!["missing_security_headers".to_string()],
        };

        let endpoints = vec![EndpointRecord {
            id: "ep-1".to_string(),
            program_id: "prog-1".to_string(),
            url: "http://127.0.0.1:8080/api/v1/auth".to_string(),
            host: "127.0.0.1".to_string(),
            path: "/api/v1/auth".to_string(),
            method: "GET".to_string(),
            discovered_via: "seed".to_string(),
            status_code: Some(200),
            response_size: Some(128),
            content_type: Some("application/json".to_string()),
            created_at: "2026-11-14 10:01:00".to_string(),
            last_verified_at: Some("2026-11-14 10:02:00".to_string()),
        }];

        let findings = vec![FindingRecord {
            id: "find-1".to_string(),
            program_id: "prog-1".to_string(),
            endpoint_id: Some("ep-1".to_string()),
            finding_type: "cors_misconfiguration".to_string(),
            severity: "HIGH".to_string(),
            title: "CORS with credentials".to_string(),
            description: "Origin reflected dynamically".to_string(),
            evidence: r#"{"tested_origin": "https://untrusted.example.invalid", "credentials_allowed": true}"#.to_string(),
            remediation: Some("Do not reflect arbitrary origin".to_string()),
            verified_at: "2026-11-14 10:03:00".to_string(),
        }];

        let md = ReportGenerator::generate_markdown(&program, &config, &endpoints, &findings);

        assert!(md.contains("# Security Assessment Report: report-test-app"));
        assert!(md.contains("**HIGH** | 1"));
        assert!(md.contains("[HIGH] CORS with credentials"));
        assert!(md.contains("`http://127.0.0.1:8080/api/v1/auth`"));
        assert!(md.contains("Do not reflect arbitrary origin"));
        assert!(md.contains("https://hackerone.com/example-program/policy"));
        assert!(md.contains("security-researcher"));
        assert!(md.contains("missing_security_headers"));
    }

    #[test]
    fn test_diff_markdown_report_formatting() {
        use crate::storage::{DiffFindingItem, EndpointStatusChange, ScanRunRecord};

        let diff = ScanDiff {
            program_id: "prog-1".to_string(),
            program_name: "diff-test-app".to_string(),
            baseline_run: ScanRunRecord {
                id: 1,
                program_id: "prog-1".to_string(),
                created_at: "2026-11-15 10:00:00".to_string(),
                endpoints_count: 5,
                findings_count: 2,
            },
            current_run: ScanRunRecord {
                id: 2,
                program_id: "prog-1".to_string(),
                created_at: "2026-11-15 11:00:00".to_string(),
                endpoints_count: 6,
                findings_count: 2,
            },
            new_endpoints: vec!["https://example.com/api/v2/new".to_string()],
            removed_endpoints: vec!["https://example.com/api/v1/old".to_string()],
            status_changes: vec![EndpointStatusChange {
                url: "https://example.com/api/v1/login".to_string(),
                baseline_status: "403".to_string(),
                current_status: "200".to_string(),
            }],
            new_findings: vec![DiffFindingItem {
                item_key: "cors_misconfiguration::https://example.com/api/v2/new".to_string(),
                finding_type: "cors_misconfiguration".to_string(),
                target_url: "https://example.com/api/v2/new".to_string(),
                severity: "HIGH".to_string(),
                title: "CORS reflection on v2 API".to_string(),
            }],
            resolved_findings: vec![DiffFindingItem {
                item_key: "information_disclosure::https://example.com/api/v1/old".to_string(),
                finding_type: "information_disclosure".to_string(),
                target_url: "https://example.com/api/v1/old".to_string(),
                severity: "LOW".to_string(),
                title: "Server header disclosure".to_string(),
            }],
        };

        let md = ReportGenerator::generate_diff_markdown(&diff);

        assert!(md.contains("# Scan Regression & Attack Surface Diff: diff-test-app"));
        assert!(md.contains("Run #1 (`2026-11-15 10:00:00`)"));
        assert!(md.contains("Run #2 (`2026-11-15 11:00:00`)"));
        assert!(md.contains("**Total Endpoints** | 5 | 6 | +1"));
        assert!(md.contains("`https://example.com/api/v2/new`"));
        assert!(md.contains("`https://example.com/api/v1/old`"));
        assert!(md.contains("`https://example.com/api/v1/login`"));
        assert!(md.contains("`403` | `200`"));
        assert!(md.contains("CORS reflection on v2 API"));
        assert!(md.contains("Server header disclosure"));
    }

    #[test]
    fn test_json_report_and_diff_serialization() {
        let program = ProgramRecord {
            id: "prog-1".to_string(),
            name: "json-test-app".to_string(),
            platform: "hackerone".to_string(),
            policy_url: Some("https://hackerone.com/json-app".to_string()),
            created_at: "2026-11-15 10:00:00".to_string(),
            updated_at: "2026-11-15 10:05:00".to_string(),
        };

        let config = ScopeConfig {
            program_name: "json-test-app".to_string(),
            platform: "hackerone".to_string(),
            allowed_domains: vec!["127.0.0.1".to_string()],
            excluded_domains: vec![],
            excluded_paths: vec!["/logout".to_string()],
            rate_limit_rps: 5,
            safe_mode: true,
            researcher_handle: Some("bug-hunter".to_string()),
            policy_url: Some("https://hackerone.com/json-app".to_string()),
            excluded_checks: vec![],
        };

        let endpoints = vec![EndpointRecord {
            id: "ep-1".to_string(),
            program_id: "prog-1".to_string(),
            url: "http://127.0.0.1:8080/api/v1/users".to_string(),
            host: "127.0.0.1".to_string(),
            path: "/api/v1/users".to_string(),
            method: "GET".to_string(),
            discovered_via: "js_route".to_string(),
            status_code: Some(200),
            response_size: Some(256),
            content_type: Some("application/json".to_string()),
            created_at: "2026-11-15 10:01:00".to_string(),
            last_verified_at: Some("2026-11-15 10:02:00".to_string()),
        }];

        let findings = vec![FindingRecord {
            id: "find-1".to_string(),
            program_id: "prog-1".to_string(),
            endpoint_id: Some("ep-1".to_string()),
            finding_type: "unauthenticated_ai_endpoint".to_string(),
            severity: "HIGH".to_string(),
            title: "Unauthenticated AI interface".to_string(),
            description: "No authentication challenge".to_string(),
            evidence: r#"{"status": 200, "auth_header": null}"#.to_string(),
            remediation: Some("Require API key".to_string()),
            verified_at: "2026-11-15 10:03:00".to_string(),
        }];

        // Test JSON report rendering
        let json_str =
            ReportGenerator::render_json_report(&program, &config, &endpoints, &findings)
                .expect("render json report failed");

        let val: serde_json::Value = serde_json::from_str(&json_str).expect("valid JSON expected");

        assert_eq!(val["schema_version"], "0.16.0");
        assert_eq!(val["tool"]["name"], "BountyScope");
        assert_eq!(val["tool"]["version"], "0.16.0");
        assert_eq!(val["program"]["name"], "json-test-app");
        assert_eq!(val["program"]["researcher_handle"], "bug-hunter");
        assert_eq!(val["summary"]["endpoints_count"], 1);
        assert_eq!(val["summary"]["findings_count"], 1);
        assert_eq!(val["summary"]["severity_breakdown"]["high"], 1);
        assert_eq!(
            val["endpoints"][0]["url"],
            "http://127.0.0.1:8080/api/v1/users"
        );
        assert_eq!(
            val["findings"][0]["finding_type"],
            "unauthenticated_ai_endpoint"
        );
        assert_eq!(val["findings"][0]["severity"], "HIGH");
        assert_eq!(val["findings"][0]["evidence"]["status"], 200);

        // Test unified render_report with ReportFormat::Json
        let unified_json = ReportGenerator::render_report(
            ReportFormat::Json,
            &program,
            &config,
            &endpoints,
            &findings,
        )
        .expect("render_report json failed");
        assert_eq!(unified_json, json_str);

        // Test JSON diff rendering
        use crate::storage::{DiffFindingItem, EndpointStatusChange, ScanRunRecord};
        let diff = ScanDiff {
            program_id: "prog-1".to_string(),
            program_name: "json-test-app".to_string(),
            baseline_run: ScanRunRecord {
                id: 1,
                program_id: "prog-1".to_string(),
                created_at: "2026-11-15 10:00:00".to_string(),
                endpoints_count: 5,
                findings_count: 1,
            },
            current_run: ScanRunRecord {
                id: 2,
                program_id: "prog-1".to_string(),
                created_at: "2026-11-15 11:00:00".to_string(),
                endpoints_count: 6,
                findings_count: 2,
            },
            new_endpoints: vec!["http://127.0.0.1:8080/api/v2/new".to_string()],
            removed_endpoints: vec![],
            status_changes: vec![EndpointStatusChange {
                url: "http://127.0.0.1:8080/api/v1/users".to_string(),
                baseline_status: "401".to_string(),
                current_status: "200".to_string(),
            }],
            new_findings: vec![DiffFindingItem {
                item_key: "cors::test".to_string(),
                finding_type: "cors_misconfiguration".to_string(),
                target_url: "http://127.0.0.1:8080/api/v2/new".to_string(),
                severity: "HIGH".to_string(),
                title: "CORS on new API".to_string(),
            }],
            resolved_findings: vec![],
        };

        let diff_json_str =
            ReportGenerator::render_json_diff(&diff).expect("render json diff failed");

        let diff_val: serde_json::Value =
            serde_json::from_str(&diff_json_str).expect("valid JSON diff expected");

        assert_eq!(diff_val["schema_version"], "0.16.0");
        assert_eq!(diff_val["program_name"], "json-test-app");
        assert_eq!(diff_val["metrics"]["total_endpoints_delta"], 1);
        assert_eq!(diff_val["metrics"]["new_findings_count"], 1);
        assert_eq!(
            diff_val["new_endpoints"][0],
            "http://127.0.0.1:8080/api/v2/new"
        );

        // Test unified render_diff with ReportFormat::Json
        let unified_diff_json = ReportGenerator::render_diff(ReportFormat::Json, &diff)
            .expect("render_diff json failed");
        assert_eq!(unified_diff_json, diff_json_str);
    }

    #[test]
    fn test_sarif_v2_1_0_schema_and_severity_mapping() {
        let program = ProgramRecord {
            id: "prog-1".to_string(),
            name: "sarif-test-app".to_string(),
            platform: "local".to_string(),
            policy_url: None,
            created_at: "2026-11-15 10:00:00".to_string(),
            updated_at: "2026-11-15 10:05:00".to_string(),
        };

        let config = ScopeConfig {
            program_name: "sarif-test-app".to_string(),
            platform: "local".to_string(),
            allowed_domains: vec!["127.0.0.1".to_string()],
            excluded_domains: vec![],
            excluded_paths: vec![],
            rate_limit_rps: 10,
            safe_mode: true,
            researcher_handle: None,
            policy_url: None,
            excluded_checks: vec![],
        };

        let endpoints = vec![
            EndpointRecord {
                id: "ep-1".to_string(),
                program_id: "prog-1".to_string(),
                url: "http://127.0.0.1:8080/admin".to_string(),
                host: "127.0.0.1".to_string(),
                path: "/admin".to_string(),
                method: "GET".to_string(),
                discovered_via: "seed".to_string(),
                status_code: Some(200),
                response_size: Some(100),
                content_type: Some("text/html".to_string()),
                created_at: "2026-11-15 10:00:00".to_string(),
                last_verified_at: None,
            },
            EndpointRecord {
                id: "ep-2".to_string(),
                program_id: "prog-1".to_string(),
                url: "http://127.0.0.1:8080/api".to_string(),
                host: "127.0.0.1".to_string(),
                path: "/api".to_string(),
                method: "GET".to_string(),
                discovered_via: "seed".to_string(),
                status_code: Some(200),
                response_size: Some(100),
                content_type: Some("application/json".to_string()),
                created_at: "2026-11-15 10:00:00".to_string(),
                last_verified_at: None,
            },
        ];

        let findings = vec![
            FindingRecord {
                id: "f-crit".to_string(),
                program_id: "prog-1".to_string(),
                endpoint_id: Some("ep-1".to_string()),
                finding_type: "unauthenticated_admin".to_string(),
                severity: "CRITICAL".to_string(),
                title: "Unauthenticated Admin Console".to_string(),
                description: "Admin panel accessible without auth".to_string(),
                evidence: "{}".to_string(),
                remediation: Some("Add authentication barrier".to_string()),
                verified_at: "2026-11-15 10:00:00".to_string(),
            },
            FindingRecord {
                id: "f-high".to_string(),
                program_id: "prog-1".to_string(),
                endpoint_id: Some("ep-2".to_string()),
                finding_type: "cors_misconfiguration".to_string(),
                severity: "HIGH".to_string(),
                title: "CORS Arbitrary Origin Reflection".to_string(),
                description: "Reflects origin with credentials".to_string(),
                evidence: "{}".to_string(),
                remediation: Some("Do not reflect origin with credentials".to_string()),
                verified_at: "2026-11-15 10:00:00".to_string(),
            },
            FindingRecord {
                id: "f-med".to_string(),
                program_id: "prog-1".to_string(),
                endpoint_id: Some("ep-2".to_string()),
                finding_type: "cors_misconfiguration".to_string(), // duplicate finding_type for rule deduplication check
                severity: "MEDIUM".to_string(),
                title: "CORS Wildcard Reflection".to_string(),
                description: "Reflects origin without credentials".to_string(),
                evidence: "{}".to_string(),
                remediation: Some("Restrict allowed origins".to_string()),
                verified_at: "2026-11-15 10:00:00".to_string(),
            },
            FindingRecord {
                id: "f-low".to_string(),
                program_id: "prog-1".to_string(),
                endpoint_id: Some("ep-1".to_string()),
                finding_type: "missing_security_headers".to_string(),
                severity: "LOW".to_string(),
                title: "Missing CSP".to_string(),
                description: "No Content-Security-Policy header".to_string(),
                evidence: "{}".to_string(),
                remediation: Some("Configure CSP".to_string()),
                verified_at: "2026-11-15 10:00:00".to_string(),
            },
            FindingRecord {
                id: "f-info".to_string(),
                program_id: "prog-1".to_string(),
                endpoint_id: Some("ep-2".to_string()),
                finding_type: "header_info_disclosure".to_string(),
                severity: "INFO".to_string(),
                title: "Server Banner Disclosure".to_string(),
                description: "Server header leaks version".to_string(),
                evidence: "{}".to_string(),
                remediation: Some("Suppress Server header".to_string()),
                verified_at: "2026-11-15 10:00:00".to_string(),
            },
        ];

        let sarif_str =
            ReportGenerator::render_sarif_report(&program, &config, &endpoints, &findings)
                .expect("render sarif report failed");

        let val: serde_json::Value =
            serde_json::from_str(&sarif_str).expect("valid SARIF JSON expected");

        assert_eq!(val["version"], "2.1.0");
        assert_eq!(
            val["$schema"],
            "https://json.schemastore.org/sarif-2.1.0.json"
        );

        let driver = &val["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "BountyScope");
        assert_eq!(driver["version"], "0.16.0");
        assert_eq!(
            driver["informationUri"],
            "https://github.com/Rohinthan/BountyScope"
        );

        // Rules must be deduplicated: 5 findings, but only 4 unique finding_types
        let rules = driver["rules"].as_array().expect("rules array");
        assert_eq!(rules.len(), 4);
        let rule_ids: Vec<&str> = rules.iter().filter_map(|r| r["id"].as_str()).collect();
        assert!(rule_ids.contains(&"unauthenticated_admin"));
        assert!(rule_ids.contains(&"cors_misconfiguration"));
        assert!(rule_ids.contains(&"missing_security_headers"));
        assert!(rule_ids.contains(&"header_info_disclosure"));

        // Verify severity levels and location URIs
        let results = val["runs"][0]["results"].as_array().expect("results array");
        assert_eq!(results.len(), 5);

        // CRITICAL -> "error"
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[0]["ruleId"], "unauthenticated_admin");
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "http://127.0.0.1:8080/admin"
        );

        // HIGH -> "error"
        assert_eq!(results[1]["level"], "error");
        assert_eq!(results[1]["ruleId"], "cors_misconfiguration");
        assert_eq!(
            results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "http://127.0.0.1:8080/api"
        );

        // MEDIUM -> "warning"
        assert_eq!(results[2]["level"], "warning");
        assert_eq!(results[2]["ruleId"], "cors_misconfiguration");

        // LOW -> "note"
        assert_eq!(results[3]["level"], "note");
        assert_eq!(results[3]["ruleId"], "missing_security_headers");

        // INFO -> "note"
        assert_eq!(results[4]["level"], "note");
        assert_eq!(results[4]["ruleId"], "header_info_disclosure");
    }
}
