# Changelog

All notable changes to BountyScope will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.16.4] - 2026-11-20

### Added
- **Passive JavaScript & Source Map Secret / Token Pattern Detection (`src/secrets/`):**
  - Implemented `SecretScanner` performing deterministic, zero-network-I/O pattern scanning across response bodies already retrieved during `SurfaceMapper` (inline scripts, external `.js` scripts, `.js.map` source maps) and `SafeVerificationRunner` audits.
  - Detects high-confidence secrets across 8 distinct categories:
    - `exposed_aws_access_key` (HIGH): AWS Access Key ID (`AKIA[0-9A-Z]{16}`) with AWS documentation placeholder filtering (`AKIAIOSFODNN7EXAMPLE`).
    - `exposed_google_api_key` (HIGH): Google Cloud & Firebase API Keys (`AIza[0-9A-Za-z_\-]{35}`).
    - `exposed_github_token` (HIGH): GitHub Personal Access and Fine-Grained Tokens (`ghp_[0-9A-Za-z]{36}`, `github_pat_[0-9A-Za-z_]{22,}`).
    - `exposed_stripe_key` (HIGH): Stripe Live Secret and Restricted Keys (`(sk|rk)_live_[0-9a-zA-Z]{24,}`), ignoring publishable keys (`pk_live_`) and test keys (`sk_test_`).
    - `exposed_webhook_url` (HIGH): Slack and Discord Incoming Webhook URLs.
    - `exposed_private_key` (HIGH): Private Cryptographic Key PEM headers (`-----BEGIN ... PRIVATE KEY-----`).
    - `exposed_bearer_jwt` (HIGH): Hardcoded JSON Web Token (JWT) or Bearer authorization credentials (`eyJ...`).
    - `exposed_internal_host` (MEDIUM): Internal staging infrastructure hostnames (`.internal`, `.corp`, `.local`, `.staging`, `.test`) and RFC 1918 private IP addresses (`10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`).
  - **Strict Evidence Redaction Guarantee:** Created `redact_secret()` masking secrets to at most 4 prefix and 4 suffix characters (e.g., `AKIA****7788`). The raw, unmasked secret string is guaranteed to never be stored in SQLite `findings` evidence/description, printed to stdout/stderr, or exported in Markdown, JSON, or SARIF reports.
  - **False-Positive Suppression & Finding Capping:** Automatically suppresses documentation placeholders (`EXAMPLE`, `DUMMY`, `YOUR_KEY`, `00000000`) and deduplicates matches by `(rule_id, masked_secret)` with a per-rule ceiling of 5 findings per endpoint.
  - **Config-Driven Exclusions:** Seamless integration with `excluded_checks`, honoring category rules (`secrets`, `exposed_secrets`) or specific rule names (`exposed_aws_access_key`).
- **Database & Storage Engine Enhancements (`src/storage/`):**
  - Added `StorageEngine::get_endpoint_by_url(program_id, url)` for direct endpoint resolution.

## [0.16.3] - 2026-11-20

### Added
- **Scope-Locked Passive Subdomain Discovery via Certificate Transparency (`src/ct/`):**
  - Implemented `CtLogDiscoverer` querying public Certificate Transparency logs (`https://crt.sh/?q=%.<domain>&output=json`) for eligible registered base domains in `ScopeConfig::allowed_domains`.
  - Parses multiline SAN `name_value` entries and `common_name`, normalizes hostnames (lowercase, strips wildcard `*.` prefixes).
  - Enforces strict boundary verification: runs every candidate subdomain through `ScopeEnforcer::validate_url()`, immediately discarding out-of-scope or explicitly excluded subdomains at zero network cost.
  - Resilient network handling: gracefully catches rate limits (`429`), server unavailability (`503`), network timeouts, and JSON parse errors with polite `[WARN]` diagnostics without crashing or aborting scans.
  - Automatically filters base domains, skipping IP addresses, loopback hosts, public suffix / TLD-only entries, and wildcard fragments.
- **CLI Subcommand & Scan Pipeline Integration:**
  - Added standalone `bountyscope ct --config <path> [--json] [--db <path>]` command for dedicated subdomain discovery.
  - Added `--enable-ct` / `--ct-logs` flag to `bountyscope scan` and `bountyscope map` (defaulting to `false`).
  - Automatically seeds discovered subdomains into `SurfaceMapper` endpoint queue with `discovered_via = "ct_log"`.
- **Snapshot Persistence & Regression Monitoring (`bountyscope diff`):**
  - Recorded subdomain snapshot items (`item_type = 'subdomain'`, `source = "ct_log"`) in `scan_snapshot_items`.
  - Added `new_subdomains` and `removed_subdomains` tracking to `compute_diff_between_runs` and `ScanDiff`.
  - Rendered subdomain changes in console output, Markdown reports (`## Subdomains & Hostname Changes`), and structured JSON diff reports (`new_subdomains`, `removed_subdomains`, and quantitative delta metrics).
- **Multi-Format Assessment Reporting:**
  - Added `## Discovered Subdomains` table in Markdown assessment reports.
  - Added `subdomains` array in structured JSON reports (`ReportFormat::Json`).
- **Model Context Protocol (MCP) `list_discovered_subdomains` Tool:**
  - Added `list_discovered_subdomains` tool to `BountyScopeMcpServer` with optional `source` filtering.
  - Configured explicit `ToolAnnotations`: `read_only_hint: true`, `destructive_hint: false`, `idempotent_hint: true`, and `open_world_hint: false`.
  - Updated `diff_latest_scans` MCP tool output to include `new_subdomains` and `removed_subdomains`.

## [0.16.2] - 2026-11-20

### Added
- **Passive Tech-Stack & WAF/CDN Fingerprinting Engine (`src/fingerprint/`):**
  - Zero-network-I/O passive analysis of already-retrieved HTTP response metadata (`status`, `headers`, `Set-Cookie` names, and HTML body/meta tags) collected during surface mapping.
  - Classifies detected technologies into 5 structured categories (`TechCategory`):
    - `WafCdn`: Cloudflare (`cf-ray`, `cf-cache-status`), AWS CloudFront (`x-amz-cf-id`, `x-amz-cf-pop`), Akamai, Fastly, Incapsula / Imperva.
    - `WebServer`: Nginx, Apache HTTP Server, Microsoft-IIS, Caddy, OpenResty, LiteSpeed, Traefik, Envoy.
    - `Framework`: Express, Next.js, Django, Ruby on Rails, ASP.NET, Laravel, Spring Boot, Vue.js, React, Angular.
    - `Cms`: WordPress (`wp-content`, generator tags), Drupal, Joomla.
    - `HostingPlatform`: Vercel, Netlify, Fly.io, Heroku, GitHub Pages.
  - Strict privacy & credential guardrail: raw session cookie values are never extracted or logged into evidence; only cookie names (`Set-Cookie: <name>`) and header banners are preserved.
- **SQLite Storage & Migration (`PRAGMA user_version = 3`):**
  - Added `detected_technologies` table with `UNIQUE(program_id, name, category)` constraint and idempotent migrations from `user_version = 2` to `3`.
  - Added `upsert_detected_technology` and `get_detected_technologies_for_program` to `StorageEngine`.
  - Stored technology snapshot items (`item_type = 'technology'`) in `scan_snapshot_items` during `record_scan_snapshot`.
  - Integrated technology regression and differential analysis in `compute_diff_between_runs` (`new_technologies` and `removed_technologies`).
- **Reporting & Surface Mapping Integration:**
  - Added `## Detected Technology Stack` table in Markdown assessment reports.
  - Added `## Technologies & Infrastructure Changes` in Markdown diff reports.
  - Added `detected_technologies` array in structured JSON reports (`ReportFormat::Json`).
  - Added `new_technologies` and `removed_technologies` arrays in structured JSON diff reports.
  - Extended CLI commands `bountyscope scan`, `bountyscope map`, `bountyscope report`, and `bountyscope diff` to surface detected technologies.
- **Model Context Protocol (MCP) `list_detected_technologies` Tool:**
  - Added `list_detected_technologies` tool to `BountyScopeMcpServer` supporting optional category filtering.
  - Registered with explicit `ToolAnnotations`: `read_only_hint: true`, `destructive_hint: false`, `idempotent_hint: true`, and `open_world_hint: false`.
  - Updated `diff_latest_scans` MCP output to include `new_technologies` and `removed_technologies`.

## [0.16.1] - 2026-11-20

### Added
- **Strict Scope Configuration Linter (`validate-scope --strict`):**
  - Added `--strict` and `--json` flags to `bountyscope validate-scope`.
  - Introduced `ScopeLintReport` structured diagnostic container with `errors` and `warnings` vectors.
  - Implemented `ScopeConfig::lint_strict()` and `ScopeEnforcer::lint_strict()` to enforce safety guardrails prior to executing network interactions.
  - Hard errors enforced under `--strict`:
    - Catch-all and top-level domain wildcard rejection (`*`, `*.com`, `*.in`, and single-label TLD entries).
    - Raw IPv4/IPv6 and CIDR target rejection unless `allow_raw_ip_targets: true` is explicitly opted into.
    - Safe mode execution pacing guardrails (`1 <= rate_limit_rps <= 10` and `max_depth <= 5`).
    - Contradictory scope rule detection (identical entries in both `allowed_domains` and `excluded_domains`).
  - Diagnostic warnings emitted:
    - Missing recommended state-changing / sensitive GET path exclusions (`/logout`, `/signout`, `/unsubscribe`, `/delete`).
    - Multi-label wildcard notice (`*.example.com`) when `excluded_domains` is empty.
    - Missing program identifier or contact attribution (`researcher_handle` or `user_agent`) when targeting external domains.
- **Model Context Protocol (MCP) `validate_scope` Tool & Explicit `ToolAnnotations`:**
  - Added native `validate_scope` tool to `BountyScopeMcpServer` accepting optional `strict: Option<bool>` (defaulting to `true`) and optional raw YAML configuration string.
  - Exposes structured validation diagnostics directly to AI agents and automated triage clients over JSON-RPC 2.0.
  - Configured explicit `ToolAnnotations` hints across all registered MCP tools (`read_only_hint: true`, `destructive_hint: false`, `idempotent_hint: true`, `open_world_hint: false`), ensuring transparent capability signaling for AI orchestrators.
