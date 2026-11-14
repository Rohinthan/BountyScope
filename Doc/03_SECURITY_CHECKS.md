# Security Checks and Verification Engine

## Supported Security Checks

BountyScope executes non-destructive security checks against in-scope targets to identify configuration oversights, unauthorized exposures, and interface weaknesses.

### 1. JavaScript Endpoint and Route Discovery
- **Mechanism:** Fetches inline and referenced external JavaScript assets located on authorized web pages. Uses regular expression and lexical token extraction to locate relative URI paths (`/api/v[0-9]/...`), API route parameters, and hidden staging/debug endpoints.
- **Scope Verification:** Every candidate route extracted from scripts is canonicalized against the base origin and passed through the `ScopeEnforcer`. Any route resolving to third-party CDNs, external cloud providers, or excluded domains is tagged as out-of-scope and discarded.
- **Safety Boundary:** Passive GET requests on publicly referenced script files only; does not fuzz parameters or submit automated form payloads.

### 2. Exposed API Specifications (OpenAPI, Swagger, Postman Collections)
- **Mechanism:** Inspects common discovery paths for exposed machine-readable API specifications:
  - `/openapi.json`, `/openapi.yaml`
  - `/swagger.json`, `/swagger/v1/swagger.json`, `/api-docs`
  - `/v2/api-docs`, `/v3/api-docs`
- **Verification:** Evaluates whether returned payloads represent valid JSON/YAML schema definitions containing endpoint listings, authentication schemas, or deprecated operational handlers.
- **Safety Boundary:** Single non-intrusive probe per candidate path. Probes immediately cease if rate-limiting or anti-automation headers (`Retry-After`, `429 Too Many Requests`) are received.

### 3. Cross-Origin Resource Sharing (CORS) Policy Auditing
- **Mechanism:** Dispatches non-credentialed and credentialed CORS preflight and standard requests with test origins to verify server-side `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` headers:
  - Arbitrary unassociated origin (`https://attacker.com`)
  - Null origin (`null`)
  - Prefix/suffix domain mutations (`https://example.com.attacker.com` or `https://notexample.com`)
  - Trusted subdomain reflections (`https://subdomain.example.com`)
- **Severity Classification:**
  - **Critical/High:** `Access-Control-Allow-Origin: *` or dynamically reflected arbitrary origin paired with `Access-Control-Allow-Credentials: true`.
  - **Medium:** Dynamic reflection of `null` origin with credentials allowed.
  - **Low/Info:** Permissive wildcard access (`*`) on non-sensitive public endpoints without credential allowances.

### 4. HTTP Security Header Auditing
- **Mechanism:** Inspects HTTP response headers on baseline and discovered endpoints to assess compliance with defense-in-depth transport and browser isolation policies.
- **Evaluated Headers:**
  - `Content-Security-Policy` (CSP): Validates presence (`missing_security_headers`), evaluates directives for unsafe-inline/unsafe-eval (`weak_csp`), and checks for missing default-src.
  - `Strict-Transport-Security` (HSTS): Checks max-age values (minimum 1 year / 31536000 seconds recommended) and `includeSubDomains` flags (`missing_security_headers`).
  - `X-Content-Type-Options`: Verifies explicit enforcement of `nosniff` (`missing_security_headers`).
  - `X-Frame-Options`: Audits for `DENY` or `SAMEORIGIN` to mitigate clickjacking risks where CSP `frame-ancestors` is absent (`missing_security_headers`).
  - `Server` and `X-Powered-By`: Identifies software banners disclosing versions and framework fingerprints (`header_info_disclosure`).
  - `Cross-Origin-Opener-Policy` (COOP) & `Cross-Origin-Embedder-Policy` (COEP): Audits cross-origin process isolation settings.

### 5. Authorized AI Tool-Boundary and MCP Checks
- **Mechanism:** Assesses exposed AI agent interaction endpoints, Model Context Protocol (MCP) server endpoints, and LLM gateway APIs:
  - Audits authentication barriers on exposed MCP endpoints (`/sse`, `/messages`, `/tools/list`, `/mcp`, `/v1/models`).
  - Registers `unauthenticated_ai_endpoint` findings when AI gateway endpoints respond with HTTP 200 without requiring authentication or presenting an authorization challenge.
  - Tests boundary enforcement on prompt endpoints to detect exposed system instructions or unauthenticated administrative tool invocation.
- **Safety Boundary:** Probes evaluate transport security, HTTP authentication headers, and read-only schema introspection (`tools/list`). Never sends destructive tool invocations or autonomous execution loops.

---

## Standard Finding Types

BountyScope standardizes finding categories across audits:
- `missing_security_headers`: Omission of fundamental defense-in-depth HTTP response headers (CSP, HSTS, XCTO, XFO).
- `weak_csp`: Content-Security-Policy containing `'unsafe-inline'` or `'unsafe-eval'`.
- `cors_misconfiguration`: Arbitrary origin reflection or `null` origin reflection with credentials allowed.
- `exposed_api_spec`: Publicly accessible OpenAPI, Swagger, or Postman specification documents.
- `header_info_disclosure`: Backend framework disclosure (`X-Powered-By`) or verbose version disclosure (`Server`).
- `unauthenticated_ai_endpoint`: Exposed AI model gateway or Model Context Protocol endpoint lacking authentication.

---

## False-Positive Filtering Rules

To maintain high data quality and avoid noise, BountyScope applies deterministic filtering rules before registering security findings:

1. **Content-Type Validation:** Discovered API specifications and endpoints must match their expected MIME type (e.g., `application/json`, `application/yaml`). HTML error pages returning HTTP 200 (soft 404s) are detected by examining DOM signatures and schema parsing errors, preventing false specification flags.
2. **Wildcard DNS Resolution Detection:** Before initiating subdomain surface mapping, BountyScope queries a randomized, non-existent subdomain (e.g., `test-nx-random-uuid.example.com`). If resolved, wildcard DNS is registered, and non-canonical subdomains are suppressed unless explicitly validated by HTTP status or TLS SNI responses.
3. **Static CDN and Asset Disqualification:** CORS reflections on static font assets (`.woff`, `.woff2`, `.ttf`), image files, and public stylesheet bundles are classified as informational or ignored, as open cross-origin sharing is standard operational behavior for non-sensitive static assets.
4. **Header Deprecation Deduplication:** Where `Content-Security-Policy` with `frame-ancestors` is properly configured, absence of legacy `X-Frame-Options` is filtered or lowered to informational status in compliance with modern browser specifications.
5. **Rate-Limit Backoff Verification:** Responses bearing status codes 429, 503, or cloud provider challenge pages (e.g., Cloudflare, Akamai, CloudFront) are isolated from vulnerability analysis to prevent treating rate-limiting challenge pages as application responses.
6. **Program Policy Exclusions (`excluded_checks`):** Checks matching configured exclusion rules in `scope.yaml` (such as `missing_security_headers`, `header_info_disclosure`, or `weak_csp`) are suppressed prior to persistence and excluded from assessment metrics.

---

## Verification Execution & Reporting Workflow

The safe verification process operates directly against mapped endpoints persisted in SQLite:

1. **Policy Audit (`bountyscope audit`):**
   - Loads persisted endpoints for the target program.
   - Dispatches read-only, rate-limited probes for security header configurations, CORS policy responses, exposed specifications, and AI/MCP endpoint posture.
   - Idempotently persists structured finding records into the `findings` table.

2. **Report Generation (`bountyscope report`):**
   - Formats program metadata, boundary configurations, severity counts, and detailed findings with JSON evidence and remediation instructions into a structured Markdown document.
