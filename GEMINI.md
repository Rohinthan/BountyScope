# BountyScope Agent Instructions & Skills Index

This document establishes the active operational guidelines, safety boundaries, and skill integrations for automated agents working on the BountyScope codebase.

---

## 1. Governance & Rules

All agent actions must strictly adhere to:
- **[RULES.md](file:///home/stringray/BountyScope/RULES.md)**: Engineering constraints, versioning rules (`v0.14.0+`), compile-time scope locking, zero runtime panics, zero `unsafe` blocks, and mandatory Valgrind leak verification before commits.

---

## 2. Integrated Agent Skills

The primary capabilities and workflows for this repository are defined by the skills located in [`.agents/skills/`](file:///home/stringray/BountyScope/.agents/skills):

### 1. [Agentic Bug Hunter](file:///home/stringray/BountyScope/.agents/skills/agentic-bug-hunter/SKILL.md)
- **Scope First:** Never test or dispatch requests to unauthorized domains, third parties, or excluded paths.
- **Impact-First & Non-Destructive:** Focus on demonstrable security boundaries; avoid DoS, brute-force loops, or destructive state manipulation.
- **Cluster Hunting:** Apply systematic A-to-B chaining (e.g., CORS reflection auditing, specification exposure analysis).

### 2. [Rust Engineer](file:///home/stringray/BountyScope/.agents/skills/rust-engineer/SKILL.md)
- **Compile-Time Safety:** Enforce domain boundaries via unforgeable types (e.g., `VerifiedScopeUrl`).
- **Idiomatic Rust:** Strict ownership and lifetime management, `thiserror` for structured error definitions, and `anyhow` for CLI context.
- **Zero Runtime Panics:** Prohibit `.unwrap()`, `.expect()`, `panic!()`, `todo!()`, or `unimplemented!()` in runtime paths.
- **Zero Unsafe Code:** No `unsafe` blocks permitted.
- **Linting & Quality:** Must pass `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings` with zero warnings.

### 3. [Security Reviewer](file:///home/stringray/BountyScope/.agents/skills/security-reviewer/SKILL.md)
- **Static Analysis & Dependency Audits:** Regular SAST, secrets scanning, and vulnerability reviews.
- **Accurate Severity Classification:** Use standardized CVSS 3.1 criteria; distinguish true vulnerabilities from benign soft 404s or static CDN assets.
- **Actionable Remediation:** Provide exact file locations and concrete mitigation steps for every finding.

### 4. [MCP Developer](file:///home/stringray/BountyScope/.agents/skills/mcp-developer/SKILL.md)
- **Protocol Compliance:** Adhere to Model Context Protocol (MCP) standards using JSON-RPC 2.0.
- **Strict Schema Enforcement:** Validate all tool parameters and resource URIs against strict schemas.
- **Transport & Access Control:** Maintain transport isolation and contextual rate-limiting on all exposed tool boundaries.
