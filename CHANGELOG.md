# Changelog

All notable changes to BountyScope will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **Model Context Protocol (MCP) `validate_scope` Tool:**
  - Added native `validate_scope` tool to `BountyScopeMcpServer` accepting optional `strict: Option<bool>` (defaulting to `true`) and optional raw YAML configuration string.
  - Exposes structured validation diagnostics directly to AI agents and automated triage clients over JSON-RPC 2.0.
