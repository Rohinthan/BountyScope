use crate::error::ReportError;
use crate::scope::ScopeConfig;
use crate::storage::{EndpointRecord, FindingRecord, ProgramRecord, ScanDiff};
use std::fs;
use std::path::Path;

/// Generates structured Markdown reports from security verification findings.
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
}
