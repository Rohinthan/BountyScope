use std::collections::{HashMap, HashSet};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::storage::FindingEntry;

/// Categories of detected secrets and sensitive tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretType {
    AwsAccessKey,
    GoogleApiKey,
    GithubToken,
    StripeKey,
    WebhookUrl,
    PrivateKeyPem,
    BearerJwt,
    InternalHost,
}

/// Represents a detected secret before conversion to a persistent finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedSecret {
    pub secret_type: SecretType,
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub masked_value: String,
    pub description: String,
    pub remediation: String,
    pub match_offset: usize,
}

/// Redacts sensitive secret strings preserving at most 4 prefix characters and 4 suffix characters.
///
/// For strings of 8 characters or fewer, the first min(4, len) characters are preserved followed by '****'.
/// The unredacted secret is guaranteed to never be stored or emitted in findings.
pub fn redact_secret(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    if chars.len() <= 8 {
        let prefix: String = chars.iter().take(4.min(chars.len())).collect();
        format!("{prefix}****")
    } else {
        let prefix: String = chars.iter().take(4).collect();
        let suffix: String = chars
            .iter()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("{prefix}****{suffix}")
    }
}

/// Passive secret and sensitive credential scanner with zero extra network requests.
pub struct SecretScanner {
    aws_regex: Regex,
    google_regex: Regex,
    github_pat_regex: Regex,
    stripe_regex: Regex,
    slack_webhook_regex: Regex,
    discord_webhook_regex: Regex,
    private_key_regex: Regex,
    jwt_regex: Regex,
    internal_host_regex: Regex,
    internal_ip_regex: Regex,
}

impl SecretScanner {
    /// Compiles all secret scanning regexes.
    pub fn new() -> Result<Self, regex::Error> {
        let aws_regex = Regex::new(r"\b(AKIA[0-9A-Z]{16})\b")?;
        let google_regex = Regex::new(r"\b(AIza[0-9A-Za-z_\-]{35})\b")?;
        let github_pat_regex =
            Regex::new(r"\b(ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,})\b")?;
        let stripe_regex = Regex::new(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b")?;
        let slack_webhook_regex = Regex::new(
            r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+",
        )?;
        let discord_webhook_regex =
            Regex::new(r"https://(?:discord|discordapp)\.com/api/webhooks/\d+/[0-9A-Za-z_\-]+")?;
        let private_key_regex =
            Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")?;
        let jwt_regex = Regex::new(
            r#"(?i)(?:bearer\s+|["'])(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"#,
        )?;
        let internal_host_regex = Regex::new(
            r#"https?://([a-zA-Z0-9_\-\.]+\.(?:internal|corp|local|staging|test)(?::\d+)?(?:/[^\s"'<>]*)?)"#,
        )?;
        let internal_ip_regex = Regex::new(
            r#"https?://((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/[^\s"'<>]*)?)"#,
        )?;

        Ok(Self {
            aws_regex,
            google_regex,
            github_pat_regex,
            stripe_regex,
            slack_webhook_regex,
            discord_webhook_regex,
            private_key_regex,
            jwt_regex,
            internal_host_regex,
            internal_ip_regex,
        })
    }

    /// Evaluates candidate text and returns all detected secrets.
    pub fn find_secrets(&self, text: &str) -> Vec<DetectedSecret> {
        let mut results = Vec::new();

        // 1. AWS Access Key ID
        for mat in self.aws_regex.find_iter(text) {
            let raw = mat.as_str();
            if Self::is_aws_placeholder(raw) {
                continue;
            }
            results.push(DetectedSecret {
                secret_type: SecretType::AwsAccessKey,
                rule_id: "exposed_aws_access_key".to_string(),
                title: "Exposed AWS Access Key ID".to_string(),
                severity: "HIGH".to_string(),
                masked_value: redact_secret(raw),
                description: "A hardcoded AWS Access Key ID was detected in client-accessible resources."
                    .to_string(),
                remediation: "Rotate the exposed AWS access key immediately and revoke the compromised credentials. Store secrets server-side or in AWS Secrets Manager."
                    .to_string(),
                match_offset: mat.start(),
            });
        }

        // 2. Google Cloud / Firebase API Key
        for mat in self.google_regex.find_iter(text) {
            let raw = mat.as_str();
            if Self::is_credential_placeholder(raw) {
                continue;
            }
            results.push(DetectedSecret {
                secret_type: SecretType::GoogleApiKey,
                rule_id: "exposed_google_api_key".to_string(),
                title: "Exposed Google Cloud / Firebase API Key".to_string(),
                severity: "HIGH".to_string(),
                masked_value: redact_secret(raw),
                description: "A Google Cloud or Firebase API key was detected in client-side code."
                    .to_string(),
                remediation: "Restrict API key permissions in Google Cloud Console by HTTP referrer, IP address, or specific API services. Move sensitive credentials server-side."
                    .to_string(),
                match_offset: mat.start(),
            });
        }

        // 3. GitHub Personal Access / Fine-Grained Token
        for mat in self.github_pat_regex.find_iter(text) {
            let raw = mat.as_str();
            if Self::is_credential_placeholder(raw) {
                continue;
            }
            results.push(DetectedSecret {
                secret_type: SecretType::GithubToken,
                rule_id: "exposed_github_token".to_string(),
                title: "Exposed GitHub Personal Access Token".to_string(),
                severity: "HIGH".to_string(),
                masked_value: redact_secret(raw),
                description: "A hardcoded GitHub personal access token was detected in client-side scripts."
                    .to_string(),
                remediation: "Revoke the compromised GitHub personal access token immediately via GitHub Settings. Use GitHub Actions secrets or environment variables."
                    .to_string(),
                match_offset: mat.start(),
            });
        }

        // 4. Stripe Live Secret / Restricted Key
        for mat in self.stripe_regex.find_iter(text) {
            let raw = mat.as_str();
            if Self::is_credential_placeholder(raw) {
                continue;
            }
            results.push(DetectedSecret {
                secret_type: SecretType::StripeKey,
                rule_id: "exposed_stripe_key".to_string(),
                title: "Exposed Stripe Live Secret Key".to_string(),
                severity: "HIGH".to_string(),
                masked_value: redact_secret(raw),
                description: "A live Stripe secret or restricted API key was detected in client-side assets."
                    .to_string(),
                remediation: "Roll the Stripe API key immediately from the Stripe Dashboard. Never expose secret keys in client-side code; use Stripe Publishable Keys (pk_live_...) client-side only."
                    .to_string(),
                match_offset: mat.start(),
            });
        }

        // 5. Slack Webhook URLs
        for mat in self.slack_webhook_regex.find_iter(text) {
            let raw = mat.as_str();
            if Self::is_credential_placeholder(raw) {
                continue;
            }
            results.push(DetectedSecret {
                secret_type: SecretType::WebhookUrl,
                rule_id: "exposed_webhook_url".to_string(),
                title: "Exposed Communication Webhook URL".to_string(),
                severity: "HIGH".to_string(),
                masked_value: redact_secret(raw),
                description: "An incoming webhook URL for Slack was detected in client-side code, allowing unauthorized message posting."
                    .to_string(),
                remediation: "Revoke and delete the exposed webhook URL. Route alert notifications through an authenticated server-side backend."
                    .to_string(),
                match_offset: mat.start(),
            });
        }

        // 6. Discord Webhook URLs
        for mat in self.discord_webhook_regex.find_iter(text) {
            let raw = mat.as_str();
            if Self::is_credential_placeholder(raw) {
                continue;
            }
            results.push(DetectedSecret {
                secret_type: SecretType::WebhookUrl,
                rule_id: "exposed_webhook_url".to_string(),
                title: "Exposed Communication Webhook URL".to_string(),
                severity: "HIGH".to_string(),
                masked_value: redact_secret(raw),
                description: "An incoming webhook URL for Discord was detected in client-side code, allowing unauthorized message posting."
                    .to_string(),
                remediation: "Revoke and delete the exposed webhook URL. Route alert notifications through an authenticated server-side backend."
                    .to_string(),
                match_offset: mat.start(),
            });
        }

        // 7. Private Key PEM Header
        for mat in self.private_key_regex.find_iter(text) {
            let raw = mat.as_str();
            results.push(DetectedSecret {
                secret_type: SecretType::PrivateKeyPem,
                rule_id: "exposed_private_key".to_string(),
                title: "Exposed Private Cryptographic Key".to_string(),
                severity: "HIGH".to_string(),
                masked_value: redact_secret(raw),
                description: "A private cryptographic key PEM header was detected in client-accessible resources."
                    .to_string(),
                remediation: "Revoke and regenerate the compromised cryptographic key pair immediately. Ensure private keys are never committed to repositories or served publicly."
                    .to_string(),
                match_offset: mat.start(),
            });
        }

        // 8. Hardcoded Bearer / JWT Assignment Literal
        for cap in self.jwt_regex.captures_iter(text) {
            if let Some(mat) = cap.get(1) {
                let raw = mat.as_str();
                if Self::is_credential_placeholder(raw) {
                    continue;
                }
                results.push(DetectedSecret {
                    secret_type: SecretType::BearerJwt,
                    rule_id: "exposed_bearer_jwt".to_string(),
                    title: "Hardcoded Bearer / JWT Token Literal".to_string(),
                    severity: "HIGH".to_string(),
                    masked_value: redact_secret(raw),
                    description: "A hardcoded JSON Web Token (JWT) or Bearer authorization credential was detected in client-side resources."
                        .to_string(),
                    remediation: "Remove hardcoded session tokens or API credentials. Implement dynamic OAuth2 or session token issuance."
                        .to_string(),
                    match_offset: mat.start(),
                });
            }
        }

        // 9. Internal / RFC1918 / Staging Infrastructure Hostnames
        for cap in self.internal_host_regex.captures_iter(text) {
            if let Some(mat) = cap.get(1) {
                let raw = mat.as_str();
                if Self::is_internal_host_placeholder(raw) {
                    continue;
                }
                results.push(DetectedSecret {
                    secret_type: SecretType::InternalHost,
                    rule_id: "exposed_internal_host".to_string(),
                    title: "Exposed Internal Infrastructure Hostname or IP".to_string(),
                    severity: "MEDIUM".to_string(),
                    masked_value: redact_secret(raw),
                    description: "An internal, staging, or private RFC1918 infrastructure address was detected in client-side assets."
                        .to_string(),
                    remediation: "Sanitize build artifacts to remove internal staging hostnames and private IP addresses before deploying to production."
                        .to_string(),
                    match_offset: mat.start(),
                });
            }
        }

        // 10. RFC1918 Private IP URLs
        for cap in self.internal_ip_regex.captures_iter(text) {
            if let Some(mat) = cap.get(1) {
                let raw = mat.as_str();
                results.push(DetectedSecret {
                    secret_type: SecretType::InternalHost,
                    rule_id: "exposed_internal_host".to_string(),
                    title: "Exposed Internal Infrastructure Hostname or IP".to_string(),
                    severity: "MEDIUM".to_string(),
                    masked_value: redact_secret(raw),
                    description: "An internal, staging, or private RFC1918 infrastructure address was detected in client-side assets."
                        .to_string(),
                    remediation: "Sanitize build artifacts to remove internal staging hostnames and private IP addresses before deploying to production."
                        .to_string(),
                    match_offset: mat.start(),
                });
            }
        }

        results
    }

    /// Evaluates text, suppresses duplicates and excessive occurrences per rule, and generates FindingEntry records.
    pub fn scan_text(
        &self,
        program_id: &str,
        endpoint_id: Option<&str>,
        endpoint_url: &str,
        text: &str,
    ) -> Vec<FindingEntry> {
        let detected = self.find_secrets(text);
        let mut findings = Vec::new();
        let mut seen_keys = HashSet::new();
        let mut rule_counts = HashMap::new();

        for secret in detected {
            // Cap at 5 findings per rule per endpoint
            let count = rule_counts.entry(secret.rule_id.clone()).or_insert(0);
            if *count >= 5 {
                continue;
            }

            // Dedup by (rule_id, masked_value)
            let dedup_key = (secret.rule_id.clone(), secret.masked_value.clone());
            if !seen_keys.insert(dedup_key) {
                continue;
            }

            *count += 1;

            let evidence = serde_json::json!({
                "url": endpoint_url,
                "rule_id": secret.rule_id,
                "secret_type": format!("{:?}", secret.secret_type),
                "masked_secret": secret.masked_value,
                "match_offset": secret.match_offset,
            })
            .to_string();

            let description = format!(
                "{} (Redacted match: '{}')",
                secret.description, secret.masked_value
            );

            findings.push(FindingEntry {
                program_id: program_id.to_string(),
                endpoint_id: endpoint_id.map(|s| s.to_string()),
                finding_type: secret.rule_id,
                severity: secret.severity,
                title: secret.title,
                description,
                evidence,
                remediation: Some(secret.remediation),
            });
        }

        findings
    }

    fn is_aws_placeholder(raw: &str) -> bool {
        raw == "AKIAIOSFODNN7EXAMPLE"
            || raw.contains("EXAMPLE")
            || raw.contains("DUMMY")
            || raw.contains("0000000000")
    }

    fn is_credential_placeholder(raw: &str) -> bool {
        let lower = raw.to_ascii_lowercase();
        lower.contains("example")
            || lower.contains("dummy")
            || lower.contains("sample")
            || lower.contains("your_")
            || lower.contains("your-")
            || lower.contains("yourkey")
            || lower.contains("changeme")
            || lower.contains("0000000000")
            || lower.contains("xxxxxx")
    }

    fn is_internal_host_placeholder(raw: &str) -> bool {
        let lower = raw.to_ascii_lowercase();
        lower.starts_with("example.")
            || lower.starts_with("schema.org")
            || lower.starts_with("www.w3.org")
            || lower == "localhost"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_secret_boundaries() {
        assert_eq!(redact_secret(""), "****");
        assert_eq!(redact_secret("1234"), "1234****");
        assert_eq!(redact_secret("12345678"), "1234****");
        assert_eq!(redact_secret("123456789"), "1234****6789");
        assert_eq!(redact_secret("AKIA1234567890ABCDEF"), "AKIA****CDEF");
    }

    #[test]
    fn test_detect_aws_access_key() {
        let scanner = SecretScanner::new().expect("scanner init failed");
        let text = "const awsKey = 'AKIAIOSFODNN7ABCD123';";
        let secrets = scanner.find_secrets(text);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].rule_id, "exposed_aws_access_key");
        assert_eq!(secrets[0].severity, "HIGH");
        assert_eq!(secrets[0].masked_value, "AKIA****D123");
    }

    #[test]
    fn test_filter_aws_example_placeholder() {
        let scanner = SecretScanner::new().expect("scanner init failed");
        let text = "const awsKey = 'AKIAIOSFODNN7EXAMPLE';";
        let secrets = scanner.find_secrets(text);
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_detect_google_api_key() {
        let scanner = SecretScanner::new().expect("scanner init failed");
        let text = "apiKey: 'AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q',";
        let secrets = scanner.find_secrets(text);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].rule_id, "exposed_google_api_key");
        assert_eq!(secrets[0].severity, "HIGH");
        assert_eq!(secrets[0].masked_value, "AIza****5P6Q");
    }

    #[test]
    fn test_filter_google_api_key_placeholder() {
        let scanner = SecretScanner::new().expect("scanner init failed");
        let text = "apiKey: 'AIzaSyDummyExampleKey00000000000000000',";
        let secrets = scanner.find_secrets(text);
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_detect_github_tokens() {
        let scanner = SecretScanner::new().expect("scanner init failed");
        let text = "const pat = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';";
        let secrets = scanner.find_secrets(text);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].rule_id, "exposed_github_token");
        assert_eq!(secrets[0].masked_value, "ghp_****7890");

        let text2 = "const fgPat = 'github_pat_11A2B3C4D_abcdef1234567890abcdef123456';";
        let secrets2 = scanner.find_secrets(text2);
        assert_eq!(secrets2.len(), 1);
        assert_eq!(secrets2[0].rule_id, "exposed_github_token");
        assert_eq!(secrets2[0].masked_value, "gith****3456");
    }

    #[test]
    fn test_detect_stripe_live_secret_key() {
        let scanner = SecretScanner::new().expect("scanner init failed");
        let stripe_sk = format!(
            "{}_{}_{}",
            "sk", "live", "51AbCdEfGhIjKlMnOpQrStUvWxYz012345"
        );
        let text = format!("stripeSecret = '{stripe_sk}';");
        let secrets = scanner.find_secrets(&text);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].rule_id, "exposed_stripe_key");
        assert_eq!(secrets[0].masked_value, "sk_l****2345");

        // Ensure publishable key and test secret keys are NOT flagged
        let pk = format!("{}_{}_{}", "pk", "live", "123456789012345678901234");
        let sk_test = format!("{}_{}_{}", "sk", "test", "123456789012345678901234");
        let text_safe = format!("{pk}; {sk_test};");
        let secrets_safe = scanner.find_secrets(&text_safe);
        assert!(secrets_safe.is_empty());
    }

    #[test]
    fn test_detect_webhooks() {
        let scanner = SecretScanner::new().expect("scanner init failed");
        let slack = format!(
            "const hook = 'https://hooks.{}/services/{}/{}/{}';",
            "slack.com", "T12345678", "B87654321", "AbCdEfGhIjKlMnOpQrStUvWx"
        );
        let discord = format!(
            "const hook = 'https://{}/api/webhooks/{}/{}';",
            "discord.com", "123456789012345678", "AbCdEfGhIjKlMnOpQrStUvWx-123456"
        );

        let slack_res = scanner.find_secrets(&slack);
        assert_eq!(slack_res.len(), 1);
        assert_eq!(slack_res[0].rule_id, "exposed_webhook_url");
        assert_eq!(slack_res[0].masked_value, "http****UvWx");

        let discord_res = scanner.find_secrets(&discord);
        assert_eq!(discord_res.len(), 1);
        assert_eq!(discord_res[0].rule_id, "exposed_webhook_url");
        assert_eq!(discord_res[0].masked_value, "http****3456");
    }

    #[test]
    fn test_detect_private_key_pem() {
        let scanner = SecretScanner::new().expect("scanner init failed");
        let text =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----";
        let secrets = scanner.find_secrets(text);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].rule_id, "exposed_private_key");
        assert_eq!(secrets[0].masked_value, "----****----");
    }

    #[test]
    fn test_detect_jwt_bearer() {
        let scanner = SecretScanner::new().expect("scanner init failed");
        let text = "headers.Authorization = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';";
        let secrets = scanner.find_secrets(text);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].rule_id, "exposed_bearer_jwt");
        assert_eq!(secrets[0].masked_value, "eyJh****sw5c");
    }

    #[test]
    fn test_detect_internal_hosts_and_ips() {
        let scanner = SecretScanner::new().expect("scanner init failed");
        let text = "const internalApi = 'https://auth-service.corp.internal/api/v1'; const staging = 'http://api.backend.staging:8080/metrics'; const rfc1918 = 'http://192.168.1.50/admin';";
        let secrets = scanner.find_secrets(text);
        assert_eq!(secrets.len(), 3);
        for s in &secrets {
            assert_eq!(s.rule_id, "exposed_internal_host");
            assert_eq!(s.severity, "MEDIUM");
        }
    }

    #[test]
    fn test_strict_redaction_guarantee_in_findings() {
        let scanner = SecretScanner::new().expect("scanner init failed");
        let raw_key = "AKIA1122334455667788";
        let text = format!("const key = '{raw_key}';");

        let findings = scanner.scan_text(
            "prog_test",
            Some("ep_1"),
            "https://api.target.com/app.js",
            &text,
        );
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];

        // The raw key must NEVER appear anywhere in finding title, description, or evidence
        assert!(!finding.title.contains(raw_key));
        assert!(!finding.description.contains(raw_key));
        assert!(!finding.evidence.contains(raw_key));
        assert!(finding.evidence.contains("AKIA****7788"));
        assert!(finding.description.contains("AKIA****7788"));
    }

    #[test]
    fn test_deduplication_and_capping() {
        let scanner = SecretScanner::new().expect("scanner init failed");
        // Repeat the same key 10 times
        let mut text = String::new();
        for _ in 0..10 {
            text.push_str("const k = 'AKIA1122334455667788';\n");
        }
        let findings =
            scanner.scan_text("prog_test", None, "https://api.target.com/bundle.js", &text);
        // Should be deduplicated to 1 finding because the masked secret is identical
        assert_eq!(findings.len(), 1);

        // Multiple distinct keys capped at 5
        let mut text2 = String::new();
        for i in 0..10 {
            text2.push_str(&format!("const k{i} = 'AKIA112233445566778{i}';\n"));
        }
        let findings2 = scanner.scan_text(
            "prog_test",
            None,
            "https://api.target.com/bundle.js",
            &text2,
        );
        assert_eq!(findings2.len(), 5);
    }
}
