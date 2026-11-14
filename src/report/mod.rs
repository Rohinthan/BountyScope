use crate::error::ReportError;
use crate::scope::ScopeConfig;
use crate::storage::{EndpointRecord, FindingRecord, ProgramRecord};
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
    }
}
