# Local Testing Lab Guide

## Overview

The local testing lab provides a self-contained, offline target environment for developing and verifying BountyScope inspection capabilities without issuing network requests across external internet infrastructure.

The environment utilizes Docker Compose to orchestrate two dedicated services:
1. **OWASP Juice Shop (`127.0.0.1:3000`):** An intentionally vulnerable web application featuring realistic client-side JavaScript bundles, complex REST APIs, and multiple security configuration scenarios.
2. **Mock API Service (`127.0.0.1:8080`):** A lightweight mock endpoint server exposing OpenAPI/Swagger specifications, customized robots.txt files, and configurable response headers.

## Network Isolation Invariant

Both services bind exclusively to the IPv4 loopback interface (`127.0.0.1`). Under no circumstances are port bindings published to `0.0.0.0` or external network adapters, preventing unintended external access during local testing sessions.

## Prerequisites

- Docker Engine (version 20.10+ or 29.0+)
- Docker Compose v2 (e.g., `docker compose`)

## Starting the Lab

To start the lab environment in detached mode:

```bash
cd lab
docker compose up -d
```

Verify that both containers are running and bound strictly to `127.0.0.1`:

```bash
docker compose ps
```

Expected output:
```text
NAME                        IMAGE                         COMMAND                  SERVICE      CREATED          STATUS          PORTS
bountyscope-lab-juiceshop   bkimminich/juice-shop:latest  "docker-entrypoint.s…"   juice-shop   10 seconds ago   Up 9 seconds    127.0.0.1:3000->3000/tcp
bountyscope-lab-mockapi     python:3.11-alpine            "python3 -m http.ser…"   mock-api     10 seconds ago   Up 9 seconds    127.0.0.1:8080->8080/tcp
```

## Verifying Lab Connectivity

Test HTTP response retrieval from the loopback interface:

```bash
# Verify Juice Shop
curl -I http://127.0.0.1:3000/

# Verify Mock API OpenAPI specification
curl -s http://127.0.0.1:8080/openapi.json | head -n 10
```

## Configuring Scope for Local Lab Testing

To target the local lab in BountyScope, create or reference a configuration file with loopback permissions (e.g., `configs/scope.local.yaml`):

```yaml
program_name: "local-lab-verification"
platform: "local"

allowed_domains:
  - "127.0.0.1"
  - "localhost"

excluded_domains: []
excluded_paths:
  - "/api/v1/reset"

rate_limit_rps: 5
safe_mode: true
```

Validate the scope configuration with the BountyScope CLI:

```bash
bountyscope validate-scope --config configs/scope.local.yaml
```

## Running Assessments Against the Local Lab

### Unified Single-Command Assessment

Execute surface mapping, passive policy verification, and Markdown report generation in a single unified command:

```bash
bountyscope scan --config configs/scope.local.yaml --url http://127.0.0.1:8080/
```

By default, this automatically creates:
- SQLite assessment database at `data/local_lab_verification.db`
- Formatted Markdown report at `data/local_lab_verification_report.md`

You can also leverage the `BOUNTYSCOPE_CONFIG` environment variable:

```bash
export BOUNTYSCOPE_CONFIG=configs/scope.local.yaml
bountyscope scan --url http://127.0.0.1:8080/
```

### Granular Subcommand Pipeline

Alternatively, execute assessment stages individually:

```bash
# 1. Probe a specific endpoint
bountyscope probe --config configs/scope.local.yaml --url http://127.0.0.1:8080/openapi.json

# 2. Passively map endpoints starting from the seed URL
bountyscope map --config configs/scope.local.yaml --url http://127.0.0.1:8080/

# 3. Audit all discovered endpoints for security configuration issues
bountyscope audit --config configs/scope.local.yaml

# 4. Generate the Markdown assessment report
bountyscope report --config configs/scope.local.yaml
```

Note: When `--db` is omitted, BountyScope defaults to `data/<sanitized_program_name>.db` and creates parent directories automatically.

## Stopping and Cleaning Up the Lab

When testing is complete, tear down the containers:

```bash
cd lab
docker compose down
```

To remove container images and associated volumes:

```bash
docker compose down --rmi local -v
```
