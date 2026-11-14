# BountyScope Engineering & Safety Rules

## 1. Versioning & Tone
- **Initial Version:** Start the project at version `0.14.0` (`v0.14.0`).
- **Objective Engineering Language:** Never claim the tool is "best", "better", "superior", or "revolutionary" in documentation, comments, or commit messages. Describe concrete technical guarantees and safety constraints factually.

## 2. Clean Naming & Documentation Separation
- **No Phase Labels in Public Artifacts:** Never mention "Phase 1", "Phase A", "Step 1", or draft stages inside `Doc/`, `README.md`, source code comments, or Git commit messages. Write all public documentation as a cohesive, production system.
- **Domain-Driven Identifiers Only:** Never name functions, structs, modules, variables, or tests after build stages (for example, `phase1_fn()` or `temp_step()` are forbidden). Use clear domain names such as `validate_target_scope()` or `inspect_cors_policy()`.
- **Public Technical Docs (`Doc/`):** All architecture, security design, vulnerability methodology, and local lab guides must live inside `Doc/` in clear, human-readable Markdown.
- **Private Execution Logs (`TestDoc/`):** All implementation plans, build logs, test outputs, Valgrind reports, and self-review checklists for each work session must be written inside `TestDoc/`.
- **Git Ignore Enforcement:** `TestDoc/`, `target/`, `.env`, and local SQLite databases (`data/*.db`) must remain listed in `.gitignore` so private execution logs and build artifacts are never pushed to GitHub.
- **Living `README.md`:** Update `README.md` after every completed milestone to reflect current features, CLI commands, and setup instructions—without referencing internal build phases or test runs.

## 3. Rust & Security Implementation Standards
- **Compile-Time Scope Lock:** Outbound HTTP clients must only accept a validated `VerifiedScopeUrl` type constructed by the scope enforcer. Raw `String` or unvalidated `Url` HTTP requests are forbidden.
- **Zero Panics in Runtime Paths:** Do not use `.unwrap()`, `.expect()`, `panic!()`, `todo!()`, or `unimplemented!()` in library or binary runtime code. Propagate all errors cleanly with `thiserror` and `anyhow`.
- **Zero Unsafe Code:** Do not write `unsafe` blocks.
- **Strict Linting & Formatting:** Every change must pass `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings` with zero warnings.
- **Rate Limiting & Safe Mode:** Default outbound concurrency/rate limit must not exceed 2 requests per second unless explicitly configured in `scope.yaml`. Destructive payloads, DoS vectors, and brute-force loops are strictly forbidden.
- **No Hardcoded Secrets:** Never commit API keys, GitHub tokens, or credentials.

## 4. Mandatory Verification & Git Backup Workflow
- **Unit + Context Integration Tests:** Every module must include unit tests and end-to-end context integration tests (covering both valid in-scope inputs and negative out-of-scope rejection cases).
- **Mandatory Valgrind Memory Leak Verification:** Before every Git commit, compile debug binaries (`cargo test --no-run` and `cargo build`) and run both the CLI binary and test executables under Valgrind:
  `valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --error-exitcode=1 <binary>`
  A commit is blocked if Valgrind reports any `definitely lost`, `indirectly lost`, or invalid memory read/write errors.
- **Git Backup Commit:** After clippy, formatting, unit/context tests, Valgrind checks, `Doc/`, `README.md`, and `TestDoc/` logs are all verified, run `git add` and create a clean, descriptive `git commit` as a milestone backup.
