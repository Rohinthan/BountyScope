use crate::error::StorageError;
use crate::fingerprint::{DetectedTechnology, TechCategory};
use crate::scope::ScopeConfig;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Represents an outbound HTTP interaction record for the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLogEntry {
    pub program_id: String,
    pub target_url: String,
    pub http_method: String,
    pub status_code: Option<u16>,
    pub duration_ms: u64,
    pub rate_limited: bool,
}

/// Represents a persisted audit log record retrieved from storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLogRecord {
    pub id: i64,
    pub program_id: String,
    pub target_url: String,
    pub http_method: String,
    pub status_code: Option<u16>,
    pub duration_ms: u64,
    pub rate_limited: bool,
    pub timestamp: String,
}

/// Represents an endpoint entry to be persisted or updated in storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointEntry {
    pub program_id: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub method: String,
    pub discovered_via: String,
    pub status_code: Option<u16>,
    pub response_size: Option<usize>,
    pub content_type: Option<String>,
}

/// Represents a persisted endpoint record retrieved from storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRecord {
    pub id: String,
    pub program_id: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub method: String,
    pub discovered_via: String,
    pub status_code: Option<u16>,
    pub response_size: Option<usize>,
    pub content_type: Option<String>,
    pub created_at: String,
    pub last_verified_at: Option<String>,
}

/// Represents a target program record retrieved from storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramRecord {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub policy_url: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Represents a security finding entry to be recorded or updated in storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingEntry {
    pub program_id: String,
    pub endpoint_id: Option<String>,
    pub finding_type: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub remediation: Option<String>,
}

/// Represents a persisted security finding record retrieved from storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRecord {
    pub id: String,
    pub program_id: String,
    pub endpoint_id: Option<String>,
    pub finding_type: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub remediation: Option<String>,
    pub verified_at: String,
}

/// Represents a historical scan execution record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRunRecord {
    pub id: i64,
    pub program_id: String,
    pub created_at: String,
    pub endpoints_count: usize,
    pub findings_count: usize,
}

/// Represents an individual item in a scan snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSnapshotItemRecord {
    pub id: i64,
    pub scan_run_id: i64,
    pub item_type: String,
    pub item_key: String,
    pub status_or_severity: String,
    pub summary: String,
}

/// Represents a detected HTTP status code transition between two scan snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointStatusChange {
    pub url: String,
    pub baseline_status: String,
    pub current_status: String,
}

/// Represents a security finding regression or resolution between scans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffFindingItem {
    pub item_key: String,
    pub finding_type: String,
    pub target_url: String,
    pub severity: String,
    pub title: String,
}

/// Represents a technology addition or removal in a regression diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffTechItem {
    pub name: String,
    pub category: String,
    pub version: Option<String>,
    pub evidence: String,
}

/// Represents a subdomain addition or removal in a regression diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffSubdomainItem {
    pub hostname: String,
    pub source: String,
    pub url: String,
}

/// Represents a discovered subdomain record stored in SQLite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredSubdomainRecord {
    pub hostname: String,
    pub source: String,
    pub url: String,
}

/// Consolidated differential analysis between two historical scan snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanDiff {
    pub program_id: String,
    pub program_name: String,
    pub baseline_run: ScanRunRecord,
    pub current_run: ScanRunRecord,
    pub new_endpoints: Vec<String>,
    pub removed_endpoints: Vec<String>,
    pub status_changes: Vec<EndpointStatusChange>,
    pub new_findings: Vec<DiffFindingItem>,
    pub resolved_findings: Vec<DiffFindingItem>,
    pub new_technologies: Vec<DiffTechItem>,
    pub removed_technologies: Vec<DiffTechItem>,
    pub new_subdomains: Vec<DiffSubdomainItem>,
    pub removed_subdomains: Vec<DiffSubdomainItem>,
}

/// Thread-safe SQLite storage engine managing assessment data and audit trails.
#[derive(Clone)]
pub struct StorageEngine {
    conn: Arc<Mutex<Connection>>,
}

impl StorageEngine {
    /// Opens or creates an SQLite database at the specified filesystem path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    StorageError::Initialization(format!(
                        "failed to create database directory: {e}"
                    ))
                })?;
            }
        }

        let conn = Connection::open(path)?;
        Self::initialize_connection(conn)
    }

    /// Creates an in-memory SQLite database instance (primarily for testing and ephemeral sessions).
    pub fn open_in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        Self::initialize_connection(conn)
    }

    /// Configures essential pragmas and creates the schema.
    fn initialize_connection(conn: Connection) -> Result<Self, StorageError> {
        // Enforce write-ahead logging for concurrent reads and foreign key integrity
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let schema = r#"
        CREATE TABLE IF NOT EXISTS programs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            platform TEXT NOT NULL,
            policy_url TEXT,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scope_rules (
            id TEXT PRIMARY KEY,
            program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
            rule_type TEXT NOT NULL CHECK (rule_type IN ('allow_domain', 'exclude_domain', 'exclude_path')),
            pattern TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS endpoints (
            id TEXT PRIMARY KEY,
            program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
            url TEXT NOT NULL UNIQUE,
            host TEXT NOT NULL,
            path TEXT NOT NULL,
            method TEXT NOT NULL DEFAULT 'GET',
            discovered_via TEXT NOT NULL,
            status_code INTEGER,
            response_size INTEGER,
            content_type TEXT,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_verified_at TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
            endpoint_id TEXT REFERENCES endpoints(id) ON DELETE SET NULL,
            finding_type TEXT NOT NULL,
            severity TEXT NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT NOT NULL,
            remediation TEXT,
            verified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
            target_url TEXT NOT NULL,
            http_method TEXT NOT NULL,
            status_code INTEGER,
            duration_ms INTEGER NOT NULL,
            rate_limited BOOLEAN NOT NULL DEFAULT 0,
            timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            endpoints_count INTEGER NOT NULL,
            findings_count INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_snapshot_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
            item_type TEXT NOT NULL,
            item_key TEXT NOT NULL,
            status_or_severity TEXT NOT NULL,
            summary TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_endpoints_host ON endpoints(host);
        CREATE INDEX IF NOT EXISTS idx_findings_program ON findings(program_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_scan_runs_program ON scan_runs(program_id);
        CREATE INDEX IF NOT EXISTS idx_scan_snapshot_items_run ON scan_snapshot_items(scan_run_id);
        "#;

        conn.execute_batch(schema)?;

        // Deterministic schema versioning and migration via PRAGMA user_version
        Self::apply_migrations(&conn)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Evaluates schema version via `PRAGMA user_version` and applies pending migrations deterministically.
    fn apply_migrations(conn: &Connection) -> Result<(), StorageError> {
        let user_version: i32 = conn.query_row("PRAGMA user_version;", [], |row| row.get(0))?;

        if user_version < 1 {
            // Inspect existing columns in programs table
            let mut stmt = conn.prepare("PRAGMA table_info(programs);")?;
            let mut rows = stmt.query([])?;
            let mut has_programs_table = false;
            let mut has_policy_url = false;

            while let Some(row) = rows.next()? {
                has_programs_table = true;
                let col_name: String = row.get(1)?;
                if col_name.eq_ignore_ascii_case("policy_url") {
                    has_policy_url = true;
                }
            }

            if has_programs_table && !has_policy_url {
                conn.execute("ALTER TABLE programs ADD COLUMN policy_url TEXT;", [])?;
            }

            conn.pragma_update(None, "user_version", 1)?;
        }

        if user_version < 2 {
            let migration_v2 = r#"
            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                endpoints_count INTEGER NOT NULL,
                findings_count INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_snapshot_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
                item_type TEXT NOT NULL,
                item_key TEXT NOT NULL,
                status_or_severity TEXT NOT NULL,
                summary TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_scan_runs_program ON scan_runs(program_id);
            CREATE INDEX IF NOT EXISTS idx_scan_snapshot_items_run ON scan_snapshot_items(scan_run_id);
            "#;
            conn.execute_batch(migration_v2)?;
            conn.pragma_update(None, "user_version", 2)?;
        }

        if user_version < 3 {
            let migration_v3 = r#"
            CREATE TABLE IF NOT EXISTS detected_technologies (
                id TEXT PRIMARY KEY,
                program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                version TEXT,
                evidence TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                discovered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(program_id, name, category)
            );

            CREATE INDEX IF NOT EXISTS idx_detected_technologies_program ON detected_technologies(program_id);
            "#;
            conn.execute_batch(migration_v3)?;
            conn.pragma_update(None, "user_version", 3)?;
        }

        Ok(())
    }

    /// Returns the current schema version from `PRAGMA user_version`.
    pub fn schema_version(&self) -> Result<i32, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockFailure)?;
        let version: i32 = conn.query_row("PRAGMA user_version;", [], |row| row.get(0))?;
        Ok(version)
    }

    /// Upserts a target program definition and updates its associated scope boundary rules.
    /// Returns the program ID.
    pub fn upsert_program_scope(&self, config: &ScopeConfig) -> Result<String, StorageError> {
        let mut conn = self.conn.lock().map_err(|_| StorageError::LockFailure)?;

        let tx = conn.transaction()?;

        // Look up existing program ID by unique name or generate a new UUID
        let existing_id: Option<String> = tx
            .query_row(
                "SELECT id FROM programs WHERE name = ?1",
                params![&config.program_name],
                |row| row.get(0),
            )
            .ok();

        let program_id = match existing_id {
            Some(id) => {
                tx.execute(
                    "UPDATE programs SET platform = ?1, policy_url = ?2, updated_at = CURRENT_TIMESTAMP WHERE id = ?3",
                    params![&config.platform, &config.policy_url, &id],
                )?;
                tx.execute(
                    "DELETE FROM scope_rules WHERE program_id = ?1",
                    params![&id],
                )?;
                id
            }
            None => {
                let id = Uuid::new_v4().to_string();
                tx.execute(
                    "INSERT INTO programs (id, name, platform, policy_url) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        &id,
                        &config.program_name,
                        &config.platform,
                        &config.policy_url
                    ],
                )?;
                id
            }
        };

        // Insert allowed domain rules
        for domain in &config.allowed_domains {
            let rule_id = Uuid::new_v4().to_string();
            tx.execute(
                "INSERT INTO scope_rules (id, program_id, rule_type, pattern) VALUES (?1, ?2, 'allow_domain', ?3)",
                params![&rule_id, &program_id, domain],
            )?;
        }

        // Insert excluded domain rules
        for domain in &config.excluded_domains {
            let rule_id = Uuid::new_v4().to_string();
            tx.execute(
                "INSERT INTO scope_rules (id, program_id, rule_type, pattern) VALUES (?1, ?2, 'exclude_domain', ?3)",
                params![&rule_id, &program_id, domain],
            )?;
        }

        // Insert excluded path rules
        for path in &config.excluded_paths {
            let rule_id = Uuid::new_v4().to_string();
            tx.execute(
                "INSERT INTO scope_rules (id, program_id, rule_type, pattern) VALUES (?1, ?2, 'exclude_path', ?3)",
                params![&rule_id, &program_id, path],
            )?;
        }

        tx.commit()?;
        Ok(program_id)
    }

    /// Retrieves all allowed domain patterns associated with a program.
    pub fn get_allowed_domains(&self, program_id: &str) -> Result<Vec<String>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockFailure)?;
        let mut stmt = conn.prepare(
            "SELECT pattern FROM scope_rules WHERE program_id = ?1 AND rule_type = 'allow_domain';",
        )?;
        let rows = stmt.query_map(params![program_id], |row| row.get(0))?;
        let mut domains = Vec::new();
        for r in rows {
            domains.push(r?);
        }
        Ok(domains)
    }

    /// Records an outbound HTTP interaction into the audit log.
    pub fn record_audit_log(&self, entry: &AuditLogEntry) -> Result<i64, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockFailure)?;

        conn.execute(
            r#"
            INSERT INTO audit_logs (program_id, target_url, http_method, status_code, duration_ms, rate_limited)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                &entry.program_id,
                &entry.target_url,
                &entry.http_method,
                entry.status_code.map(|s| s as i32),
                entry.duration_ms as i64,
                entry.rate_limited,
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    /// Queries audit log records associated with a program ID.
    pub fn get_audit_logs(&self, program_id: &str) -> Result<Vec<AuditLogRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockFailure)?;

        let mut stmt = conn.prepare(
            r#"
            SELECT id, program_id, target_url, http_method, status_code, duration_ms, rate_limited, timestamp
            FROM audit_logs
            WHERE program_id = ?1
            ORDER BY id ASC
            "#,
        )?;

        let rows = stmt.query_map(params![program_id], |row| {
            let status: Option<i32> = row.get(4)?;
            Ok(AuditLogRecord {
                id: row.get(0)?,
                program_id: row.get(1)?,
                target_url: row.get(2)?,
                http_method: row.get(3)?,
                status_code: status.map(|s| s as u16),
                duration_ms: row.get::<_, i64>(5)? as u64,
                rate_limited: row.get(6)?,
                timestamp: row.get(7)?,
            })
        })?;

        let mut records = Vec::new();
        for r in rows {
            records.push(r?);
        }

        Ok(records)
    }

    /// Upserts an endpoint entry into storage.
    ///
    /// If an endpoint with the same URL already exists, its status code, response size,
    /// content type, and last_verified_at timestamp are refreshed.
    /// Returns the endpoint ID.
    pub fn upsert_endpoint(&self, entry: &EndpointEntry) -> Result<String, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockFailure)?;
        let id = Uuid::new_v4().to_string();

        let endpoint_id: String = conn.query_row(
            r#"
            INSERT INTO endpoints (
                id, program_id, url, host, path, method, discovered_via,
                status_code, response_size, content_type, last_verified_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, CURRENT_TIMESTAMP)
            ON CONFLICT(url) DO UPDATE SET
                status_code = excluded.status_code,
                response_size = excluded.response_size,
                content_type = excluded.content_type,
                last_verified_at = CURRENT_TIMESTAMP
            RETURNING id
            "#,
            params![
                &id,
                &entry.program_id,
                &entry.url,
                &entry.host,
                &entry.path,
                &entry.method,
                &entry.discovered_via,
                entry.status_code.map(|s| s as i32),
                entry.response_size.map(|s| s as i64),
                &entry.content_type,
            ],
            |row| row.get(0),
        )?;

        Ok(endpoint_id)
    }

    /// Queries all discovered endpoints for a given program ID.
    pub fn get_endpoints_for_program(
        &self,
        program_id: &str,
    ) -> Result<Vec<EndpointRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockFailure)?;

        let mut stmt = conn.prepare(
            r#"
            SELECT id, program_id, url, host, path, method, discovered_via,
                   status_code, response_size, content_type, created_at, last_verified_at
            FROM endpoints
            WHERE program_id = ?1
            ORDER BY created_at ASC
            "#,
        )?;

        let rows = stmt.query_map(params![program_id], |row| {
            let status: Option<i32> = row.get(7)?;
            let size: Option<i64> = row.get(8)?;
            Ok(EndpointRecord {
                id: row.get(0)?,
                program_id: row.get(1)?,
                url: row.get(2)?,
                host: row.get(3)?,
                path: row.get(4)?,
                method: row.get(5)?,
                discovered_via: row.get(6)?,
                status_code: status.map(|s| s as u16),
                response_size: size.map(|s| s as usize),
                content_type: row.get(9)?,
                created_at: row.get(10)?,
                last_verified_at: row.get(11)?,
            })
        })?;

        let mut endpoints = Vec::new();
        for r in rows {
            endpoints.push(r?);
        }

        Ok(endpoints)
    }

    /// Queries an endpoint record by program ID and URL.
    pub fn get_endpoint_by_url(
        &self,
        program_id: &str,
        url: &str,
    ) -> Result<Option<EndpointRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockFailure)?;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, program_id, url, host, path, method, discovered_via,
                   status_code, response_size, content_type, created_at, last_verified_at
            FROM endpoints
            WHERE program_id = ?1 AND url = ?2
            LIMIT 1
            "#,
        )?;
        let mut rows = stmt.query_map(params![program_id, url], |row| {
            let status: Option<i32> = row.get(7)?;
            let size: Option<i64> = row.get(8)?;
            Ok(EndpointRecord {
                id: row.get(0)?,
                program_id: row.get(1)?,
                url: row.get(2)?,
                host: row.get(3)?,
                path: row.get(4)?,
                method: row.get(5)?,
                discovered_via: row.get(6)?,
                status_code: status.map(|s| s as u16),
                response_size: size.map(|s| s as usize),
                content_type: row.get(9)?,
                created_at: row.get(10)?,
                last_verified_at: row.get(11)?,
            })
        })?;

        if let Some(first) = rows.next() {
            Ok(Some(first?))
        } else {
            Ok(None)
        }
    }

    /// Retrieves a target program record by its unique ID.
    pub fn get_program_by_id(&self, program_id: &str) -> Result<ProgramRecord, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockFailure)?;
        conn.query_row(
            "SELECT id, name, platform, policy_url, created_at, updated_at FROM programs WHERE id = ?1",
            params![program_id],
            |row| {
                Ok(ProgramRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    platform: row.get(2)?,
                    policy_url: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            },
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                StorageError::NotFound(format!("program with id '{program_id}' not found"))
            }
            other => StorageError::Database(other),
        })
    }

    /// Retrieves a target program record by its unique name.
    pub fn get_program_by_name(&self, program_name: &str) -> Result<ProgramRecord, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockFailure)?;
        conn.query_row(
            "SELECT id, name, platform, policy_url, created_at, updated_at FROM programs WHERE name = ?1",
            params![program_name],
            |row| {
                Ok(ProgramRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    platform: row.get(2)?,
                    policy_url: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            },
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                StorageError::NotFound(format!("program with name '{program_name}' not found"))
            }
            other => StorageError::Database(other),
        })
    }

    /// Upserts a security finding record idempotently.
    ///
    /// If a finding for the same `(program_id, endpoint_id, finding_type, title)` already exists,
    /// its `severity`, `title`, `description`, `evidence`, `remediation`, and `verified_at`
    /// timestamp are updated instead of creating a duplicate row.
    pub fn upsert_finding(&self, entry: &FindingEntry) -> Result<String, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockFailure)?;

        let existing_id: Option<String> = match &entry.endpoint_id {
            Some(ep_id) => conn
                .query_row(
                    "SELECT id FROM findings WHERE program_id = ?1 AND endpoint_id = ?2 AND finding_type = ?3 AND title = ?4",
                    params![&entry.program_id, ep_id, &entry.finding_type, &entry.title],
                    |row| row.get(0),
                )
                .ok(),
            None => conn
                .query_row(
                    "SELECT id FROM findings WHERE program_id = ?1 AND endpoint_id IS NULL AND finding_type = ?2 AND title = ?3",
                    params![&entry.program_id, &entry.finding_type, &entry.title],
                    |row| row.get(0),
                )
                .ok(),
        };

        match existing_id {
            Some(id) => {
                conn.execute(
                    r#"
                    UPDATE findings
                    SET severity = ?1, title = ?2, description = ?3, evidence = ?4, remediation = ?5, verified_at = CURRENT_TIMESTAMP
                    WHERE id = ?6
                    "#,
                    params![
                        &entry.severity,
                        &entry.title,
                        &entry.description,
                        &entry.evidence,
                        &entry.remediation,
                        &id,
                    ],
                )?;
                Ok(id)
            }
            None => {
                let id = Uuid::new_v4().to_string();
                conn.execute(
                    r#"
                    INSERT INTO findings (
                        id, program_id, endpoint_id, finding_type, severity, title, description, evidence, remediation, verified_at
                    )
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, CURRENT_TIMESTAMP)
                    "#,
                    params![
                        &id,
                        &entry.program_id,
                        &entry.endpoint_id,
                        &entry.finding_type,
                        &entry.severity,
                        &entry.title,
                        &entry.description,
                        &entry.evidence,
                        &entry.remediation,
                    ],
                )?;
                Ok(id)
            }
        }
    }

    /// Queries all findings for a given program, ordered by severity:
    /// CRITICAL, HIGH, MEDIUM, LOW, INFO.
    pub fn get_findings_for_program(
        &self,
        program_id: &str,
    ) -> Result<Vec<FindingRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockFailure)?;

        let mut stmt = conn.prepare(
            r#"
            SELECT id, program_id, endpoint_id, finding_type, severity, title, description, evidence, remediation, verified_at
            FROM findings
            WHERE program_id = ?1
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    WHEN 'INFO' THEN 5
                    ELSE 6
                END ASC,
                title ASC
            "#,
        )?;

        let rows = stmt.query_map(params![program_id], |row| {
            Ok(FindingRecord {
                id: row.get(0)?,
                program_id: row.get(1)?,
                endpoint_id: row.get(2)?,
                finding_type: row.get(3)?,
                severity: row.get(4)?,
                title: row.get(5)?,
                description: row.get(6)?,
                evidence: row.get(7)?,
                remediation: row.get(8)?,
                verified_at: row.get(9)?,
            })
        })?;

        let mut findings = Vec::new();
        for r in rows {
            findings.push(r?);
        }

        Ok(findings)
    }

    /// Upserts a passively detected technology for a program.
    /// Deduplicates on `(program_id, name, category)`, updating version and latest evidence if observed.
    pub fn upsert_detected_technology(
        &self,
        program_id: &str,
        tech: &DetectedTechnology,
    ) -> Result<String, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockFailure)?;

        let existing: Option<(String, Option<String>)> = conn
            .query_row(
                "SELECT id, version FROM detected_technologies WHERE program_id = ?1 AND name = ?2 AND category = ?3",
                params![program_id, &tech.name, tech.category.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();

        match existing {
            Some((id, existing_version)) => {
                let version = tech.version.clone().or(existing_version);
                conn.execute(
                    r#"
                    UPDATE detected_technologies
                    SET version = ?1, evidence = ?2, endpoint = ?3, discovered_at = CURRENT_TIMESTAMP
                    WHERE id = ?4
                    "#,
                    params![&version, &tech.evidence, &tech.endpoint, &id],
                )?;
                Ok(id)
            }
            None => {
                let id = Uuid::new_v4().to_string();
                conn.execute(
                    r#"
                    INSERT INTO detected_technologies (
                        id, program_id, name, category, version, evidence, endpoint, discovered_at
                    )
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, CURRENT_TIMESTAMP)
                    "#,
                    params![
                        &id,
                        program_id,
                        &tech.name,
                        tech.category.as_str(),
                        &tech.version,
                        &tech.evidence,
                        &tech.endpoint,
                    ],
                )?;
                Ok(id)
            }
        }
    }

    /// Queries all passively detected technologies for a given program, ordered by category and name.
    pub fn get_detected_technologies_for_program(
        &self,
        program_id: &str,
    ) -> Result<Vec<DetectedTechnology>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockFailure)?;
        let mut stmt = conn.prepare(
            r#"
            SELECT name, category, version, evidence, endpoint
            FROM detected_technologies
            WHERE program_id = ?1
            ORDER BY category ASC, name ASC
            "#,
        )?;
        let rows = stmt.query_map(params![program_id], |row| {
            let cat_str: String = row.get(1)?;
            let category = TechCategory::from_str(&cat_str).unwrap_or(TechCategory::Framework);
            Ok(DetectedTechnology {
                name: row.get(0)?,
                category,
                version: row.get(2)?,
                evidence: row.get(3)?,
                endpoint: row.get(4)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Queries all discovered unique subdomains for a program, ordered by hostname.
    pub fn get_subdomains_for_program(
        &self,
        program_id: &str,
    ) -> Result<Vec<DiscoveredSubdomainRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockFailure)?;
        let mut stmt = conn.prepare(
            r#"
            SELECT host, discovered_via, MIN(url)
            FROM endpoints
            WHERE program_id = ?1
            GROUP BY host
            ORDER BY host ASC
            "#,
        )?;
        let rows = stmt.query_map(params![program_id], |row| {
            Ok(DiscoveredSubdomainRecord {
                hostname: row.get(0)?,
                source: row.get(1)?,
                url: row.get(2)?,
            })
        })?;

        let mut subs = Vec::new();
        for r in rows {
            subs.push(r?);
        }
        Ok(subs)
    }

    /// Captures a complete snapshot of all mapped endpoints and findings for the given program.
    /// Returns the assigned scan run ID.
    pub fn record_scan_snapshot(&self, program_id: &str) -> Result<i64, StorageError> {
        let mut conn = self.conn.lock().map_err(|_| StorageError::LockFailure)?;
        let tx = conn.transaction()?;

        // 1. Fetch current endpoints
        let endpoints: Vec<(String, String, Option<u16>, String)> = {
            let mut ep_stmt = tx.prepare(
                r#"
                SELECT url, method, status_code, discovered_via
                FROM endpoints
                WHERE program_id = ?1
                ORDER BY url ASC
                "#,
            )?;
            let ep_rows = ep_stmt.query_map(params![program_id], |row| {
                let status: Option<i32> = row.get(2)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    status.map(|s| s as u16),
                    row.get::<_, String>(3)?,
                ))
            })?;

            let mut vec = Vec::new();
            for r in ep_rows {
                vec.push(r?);
            }
            vec
        };
        let endpoints_count = endpoints.len();

        // 2. Fetch current findings with joined target URL
        let findings: Vec<(String, String, String, String)> = {
            let mut f_stmt = tx.prepare(
                r#"
                SELECT f.finding_type, f.severity, f.title, COALESCE(e.url, 'program')
                FROM findings f
                LEFT JOIN endpoints e ON f.endpoint_id = e.id
                WHERE f.program_id = ?1
                ORDER BY f.id ASC
                "#,
            )?;
            let f_rows = f_stmt.query_map(params![program_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;

            let mut vec = Vec::new();
            for r in f_rows {
                vec.push(r?);
            }
            vec
        };
        let findings_count = findings.len();

        // 3. Fetch detected technologies
        let technologies: Vec<(String, String, Option<String>, String, String)> = {
            let mut t_stmt = tx.prepare(
                r#"
                SELECT name, category, version, evidence, endpoint
                FROM detected_technologies
                WHERE program_id = ?1
                ORDER BY category ASC, name ASC
                "#,
            )?;
            let t_rows = t_stmt.query_map(params![program_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?;
            let mut vec = Vec::new();
            for r in t_rows {
                vec.push(r?);
            }
            vec
        };

        // 4. Create scan_runs record
        tx.execute(
            r#"
            INSERT INTO scan_runs (program_id, endpoints_count, findings_count)
            VALUES (?1, ?2, ?3)
            "#,
            params![program_id, endpoints_count as i64, findings_count as i64],
        )?;
        let scan_run_id = tx.last_insert_rowid();

        // 5. Insert endpoint snapshot items
        {
            let mut item_stmt = tx.prepare(
                r#"
                INSERT INTO scan_snapshot_items (scan_run_id, item_type, item_key, status_or_severity, summary)
                VALUES (?1, 'endpoint', ?2, ?3, ?4)
                "#,
            )?;
            for (url, method, status_code, discovered_via) in &endpoints {
                let status_str = match status_code {
                    Some(code) => code.to_string(),
                    None => "unprobed".to_string(),
                };
                let summary = format!("{method} {url} ({discovered_via})");
                item_stmt.execute(params![scan_run_id, url, status_str, summary])?;
            }
        }

        // 6. Insert finding snapshot items
        {
            let mut item_stmt = tx.prepare(
                r#"
                INSERT INTO scan_snapshot_items (scan_run_id, item_type, item_key, status_or_severity, summary)
                VALUES (?1, 'finding', ?2, ?3, ?4)
                "#,
            )?;
            for (finding_type, severity, title, target_url) in &findings {
                let item_key = format!("{finding_type}::{target_url}");
                item_stmt.execute(params![scan_run_id, item_key, severity, title])?;
            }
        }

        // 7. Insert technology snapshot items
        {
            let mut item_stmt = tx.prepare(
                r#"
                INSERT INTO scan_snapshot_items (scan_run_id, item_type, item_key, status_or_severity, summary)
                VALUES (?1, 'technology', ?2, ?3, ?4)
                "#,
            )?;
            for (name, category, version, evidence, _endpoint) in &technologies {
                let item_key = format!("{category}::{name}");
                let summary = format!("{}|{}", version.as_deref().unwrap_or(""), evidence);
                item_stmt.execute(params![scan_run_id, item_key, category, summary])?;
            }
        }

        // 8. Insert subdomain snapshot items
        {
            let mut sub_stmt = tx.prepare(
                r#"
                SELECT host, discovered_via, MIN(url)
                FROM endpoints
                WHERE program_id = ?1
                GROUP BY host
                "#,
            )?;
            let sub_rows = sub_stmt.query_map(params![program_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            let mut item_stmt = tx.prepare(
                r#"
                INSERT INTO scan_snapshot_items (scan_run_id, item_type, item_key, status_or_severity, summary)
                VALUES (?1, 'subdomain', ?2, ?3, ?4)
                "#,
            )?;
            for r in sub_rows {
                let (host, discovered_via, min_url) = r?;
                item_stmt.execute(params![scan_run_id, host, discovered_via, min_url])?;
            }
        }

        tx.commit()?;
        Ok(scan_run_id)
    }

    /// Retrieves all historical scan run records for a program, ordered newest to oldest.
    pub fn get_scan_runs(&self, program_id: &str) -> Result<Vec<ScanRunRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockFailure)?;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, program_id, created_at, endpoints_count, findings_count
            FROM scan_runs
            WHERE program_id = ?1
            ORDER BY id DESC
            "#,
        )?;
        let rows = stmt.query_map(params![program_id], |row| {
            let ep_cnt: i64 = row.get(3)?;
            let f_cnt: i64 = row.get(4)?;
            Ok(ScanRunRecord {
                id: row.get(0)?,
                program_id: row.get(1)?,
                created_at: row.get(2)?,
                endpoints_count: ep_cnt as usize,
                findings_count: f_cnt as usize,
            })
        })?;

        let mut runs = Vec::new();
        for r in rows {
            runs.push(r?);
        }
        Ok(runs)
    }

    /// Computes differential analysis between two specific historical scan runs.
    pub fn compute_diff_between_runs(
        &self,
        program_id: &str,
        baseline_run_id: i64,
        current_run_id: i64,
    ) -> Result<ScanDiff, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockFailure)?;

        // Verify program exists
        let program_name: String = conn
            .query_row(
                "SELECT name FROM programs WHERE id = ?1",
                params![program_id],
                |row| row.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    StorageError::NotFound(format!("Program '{program_id}' not found"))
                }
                other => StorageError::Database(other),
            })?;

        // Retrieve baseline run
        let baseline_run: ScanRunRecord = conn
            .query_row(
                "SELECT id, program_id, created_at, endpoints_count, findings_count FROM scan_runs WHERE id = ?1 AND program_id = ?2",
                params![baseline_run_id, program_id],
                |row| {
                    let ep_cnt: i64 = row.get(3)?;
                    let f_cnt: i64 = row.get(4)?;
                    Ok(ScanRunRecord {
                        id: row.get(0)?,
                        program_id: row.get(1)?,
                        created_at: row.get(2)?,
                        endpoints_count: ep_cnt as usize,
                        findings_count: f_cnt as usize,
                    })
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    StorageError::NotFound(format!("Baseline scan run ID {baseline_run_id} not found"))
                }
                other => StorageError::Database(other),
            })?;

        // Retrieve current run
        let current_run: ScanRunRecord = conn
            .query_row(
                "SELECT id, program_id, created_at, endpoints_count, findings_count FROM scan_runs WHERE id = ?1 AND program_id = ?2",
                params![current_run_id, program_id],
                |row| {
                    let ep_cnt: i64 = row.get(3)?;
                    let f_cnt: i64 = row.get(4)?;
                    Ok(ScanRunRecord {
                        id: row.get(0)?,
                        program_id: row.get(1)?,
                        created_at: row.get(2)?,
                        endpoints_count: ep_cnt as usize,
                        findings_count: f_cnt as usize,
                    })
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    StorageError::NotFound(format!("Current scan run ID {current_run_id} not found"))
                }
                other => StorageError::Database(other),
            })?;

        // Query baseline items
        let mut baseline_stmt = conn.prepare(
            "SELECT id, scan_run_id, item_type, item_key, status_or_severity, summary FROM scan_snapshot_items WHERE scan_run_id = ?1",
        )?;
        let baseline_rows = baseline_stmt.query_map(params![baseline_run_id], |row| {
            Ok(ScanSnapshotItemRecord {
                id: row.get(0)?,
                scan_run_id: row.get(1)?,
                item_type: row.get(2)?,
                item_key: row.get(3)?,
                status_or_severity: row.get(4)?,
                summary: row.get(5)?,
            })
        })?;

        let mut baseline_endpoints: HashMap<String, ScanSnapshotItemRecord> = HashMap::new();
        let mut baseline_findings: HashMap<String, ScanSnapshotItemRecord> = HashMap::new();
        let mut baseline_technologies: HashMap<String, ScanSnapshotItemRecord> = HashMap::new();
        let mut baseline_subdomains: HashMap<String, ScanSnapshotItemRecord> = HashMap::new();
        for r in baseline_rows {
            let item = r?;
            if item.item_type == "endpoint" {
                baseline_endpoints.insert(item.item_key.clone(), item);
            } else if item.item_type == "finding" {
                baseline_findings.insert(item.item_key.clone(), item);
            } else if item.item_type == "technology" {
                baseline_technologies.insert(item.item_key.clone(), item);
            } else if item.item_type == "subdomain" {
                baseline_subdomains.insert(item.item_key.clone(), item);
            }
        }

        // Query current items
        let mut current_stmt = conn.prepare(
            "SELECT id, scan_run_id, item_type, item_key, status_or_severity, summary FROM scan_snapshot_items WHERE scan_run_id = ?1",
        )?;
        let current_rows = current_stmt.query_map(params![current_run_id], |row| {
            Ok(ScanSnapshotItemRecord {
                id: row.get(0)?,
                scan_run_id: row.get(1)?,
                item_type: row.get(2)?,
                item_key: row.get(3)?,
                status_or_severity: row.get(4)?,
                summary: row.get(5)?,
            })
        })?;

        let mut current_endpoints: HashMap<String, ScanSnapshotItemRecord> = HashMap::new();
        let mut current_findings: HashMap<String, ScanSnapshotItemRecord> = HashMap::new();
        let mut current_technologies: HashMap<String, ScanSnapshotItemRecord> = HashMap::new();
        let mut current_subdomains: HashMap<String, ScanSnapshotItemRecord> = HashMap::new();
        for r in current_rows {
            let item = r?;
            if item.item_type == "endpoint" {
                current_endpoints.insert(item.item_key.clone(), item);
            } else if item.item_type == "finding" {
                current_findings.insert(item.item_key.clone(), item);
            } else if item.item_type == "technology" {
                current_technologies.insert(item.item_key.clone(), item);
            } else if item.item_type == "subdomain" {
                current_subdomains.insert(item.item_key.clone(), item);
            }
        }

        // Endpoint deltas
        let mut new_endpoints: Vec<String> = current_endpoints
            .keys()
            .filter(|k| !baseline_endpoints.contains_key(*k))
            .cloned()
            .collect();
        new_endpoints.sort();

        let mut removed_endpoints: Vec<String> = baseline_endpoints
            .keys()
            .filter(|k| !current_endpoints.contains_key(*k))
            .cloned()
            .collect();
        removed_endpoints.sort();

        let mut status_changes = Vec::new();
        for (url, cur_item) in &current_endpoints {
            if let Some(base_item) = baseline_endpoints.get(url) {
                if base_item.status_or_severity != cur_item.status_or_severity {
                    status_changes.push(EndpointStatusChange {
                        url: url.clone(),
                        baseline_status: base_item.status_or_severity.clone(),
                        current_status: cur_item.status_or_severity.clone(),
                    });
                }
            }
        }
        status_changes.sort_by(|a, b| a.url.cmp(&b.url));

        // Finding deltas
        let mut new_findings = Vec::new();
        for (key, cur_item) in &current_findings {
            if !baseline_findings.contains_key(key) {
                let (f_type, target_url) = cur_item
                    .item_key
                    .split_once("::")
                    .unwrap_or((&cur_item.item_key, "program"));
                new_findings.push(DiffFindingItem {
                    item_key: cur_item.item_key.clone(),
                    finding_type: f_type.to_string(),
                    target_url: target_url.to_string(),
                    severity: cur_item.status_or_severity.clone(),
                    title: cur_item.summary.clone(),
                });
            }
        }
        Self::sort_diff_findings(&mut new_findings);

        let mut resolved_findings = Vec::new();
        for (key, base_item) in &baseline_findings {
            if !current_findings.contains_key(key) {
                let (f_type, target_url) = base_item
                    .item_key
                    .split_once("::")
                    .unwrap_or((&base_item.item_key, "program"));
                resolved_findings.push(DiffFindingItem {
                    item_key: base_item.item_key.clone(),
                    finding_type: f_type.to_string(),
                    target_url: target_url.to_string(),
                    severity: base_item.status_or_severity.clone(),
                    title: base_item.summary.clone(),
                });
            }
        }
        Self::sort_diff_findings(&mut resolved_findings);

        // Technology deltas
        let mut new_technologies = Vec::new();
        for (key, cur_item) in &current_technologies {
            if !baseline_technologies.contains_key(key) {
                let (category, name) = cur_item
                    .item_key
                    .split_once("::")
                    .unwrap_or((&cur_item.status_or_severity, &cur_item.item_key));
                let (version_str, evidence) = cur_item
                    .summary
                    .split_once('|')
                    .unwrap_or(("", &cur_item.summary));
                let version = if version_str.is_empty() {
                    None
                } else {
                    Some(version_str.to_string())
                };
                new_technologies.push(DiffTechItem {
                    name: name.to_string(),
                    category: category.to_string(),
                    version,
                    evidence: evidence.to_string(),
                });
            }
        }
        new_technologies.sort_by(|a, b| {
            a.category
                .cmp(&b.category)
                .then_with(|| a.name.cmp(&b.name))
        });

        let mut removed_technologies = Vec::new();
        for (key, base_item) in &baseline_technologies {
            if !current_technologies.contains_key(key) {
                let (category, name) = base_item
                    .item_key
                    .split_once("::")
                    .unwrap_or((&base_item.status_or_severity, &base_item.item_key));
                let (version_str, evidence) = base_item
                    .summary
                    .split_once('|')
                    .unwrap_or(("", &base_item.summary));
                let version = if version_str.is_empty() {
                    None
                } else {
                    Some(version_str.to_string())
                };
                removed_technologies.push(DiffTechItem {
                    name: name.to_string(),
                    category: category.to_string(),
                    version,
                    evidence: evidence.to_string(),
                });
            }
        }
        removed_technologies.sort_by(|a, b| {
            a.category
                .cmp(&b.category)
                .then_with(|| a.name.cmp(&b.name))
        });

        // Subdomain deltas
        let mut new_subdomains = Vec::new();
        for (key, cur_item) in &current_subdomains {
            if !baseline_subdomains.contains_key(key) {
                new_subdomains.push(DiffSubdomainItem {
                    hostname: cur_item.item_key.clone(),
                    source: cur_item.status_or_severity.clone(),
                    url: cur_item.summary.clone(),
                });
            }
        }
        new_subdomains.sort_by(|a, b| a.hostname.cmp(&b.hostname));

        let mut removed_subdomains = Vec::new();
        for (key, base_item) in &baseline_subdomains {
            if !current_subdomains.contains_key(key) {
                removed_subdomains.push(DiffSubdomainItem {
                    hostname: base_item.item_key.clone(),
                    source: base_item.status_or_severity.clone(),
                    url: base_item.summary.clone(),
                });
            }
        }
        removed_subdomains.sort_by(|a, b| a.hostname.cmp(&b.hostname));

        Ok(ScanDiff {
            program_id: program_id.to_string(),
            program_name,
            baseline_run,
            current_run,
            new_endpoints,
            removed_endpoints,
            status_changes,
            new_findings,
            resolved_findings,
            new_technologies,
            removed_technologies,
            new_subdomains,
            removed_subdomains,
        })
    }

    fn sort_diff_findings(findings: &mut [DiffFindingItem]) {
        fn severity_weight(sev: &str) -> u8 {
            match sev {
                "CRITICAL" => 1,
                "HIGH" => 2,
                "MEDIUM" => 3,
                "LOW" => 4,
                "INFO" => 5,
                _ => 6,
            }
        }
        findings.sort_by(|a, b| {
            severity_weight(&a.severity)
                .cmp(&severity_weight(&b.severity))
                .then_with(|| a.title.cmp(&b.title))
                .then_with(|| a.item_key.cmp(&b.item_key))
        });
    }

    /// Computes differential analysis comparing the two most recent historical scan runs.
    pub fn compute_latest_diff(&self, program_id: &str) -> Result<ScanDiff, StorageError> {
        let runs = self.get_scan_runs(program_id)?;
        if runs.len() < 2 {
            return Err(StorageError::NotFound(
                "At least two historical scan runs are required to compute a diff. Run 'bountyscope scan' or 'bountyscope audit' again to generate a second snapshot.".to_string(),
            ));
        }

        let current = &runs[0];
        let baseline = &runs[1];
        self.compute_diff_between_runs(program_id, baseline.id, current.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> ScopeConfig {
        ScopeConfig {
            program_name: "test-storage-program".to_string(),
            platform: "hackerone".to_string(),
            allowed_domains: vec!["example.com".to_string(), "*.example.com".to_string()],
            excluded_domains: vec!["auth.example.com".to_string()],
            excluded_paths: vec!["/logout".to_string()],
            rate_limit_rps: 2,
            safe_mode: true,
            allow_raw_ip_targets: false,
            max_depth: None,
            user_agent: None,
            researcher_handle: None,
            policy_url: Some("https://hackerone.com/test-storage-program".to_string()),
            excluded_checks: vec![],
        }
    }

    #[test]
    fn test_storage_initialization_and_pragmas() {
        let storage = StorageEngine::open_in_memory().expect("failed to open in-memory storage");
        let conn = storage.conn.lock().expect("lock failed");

        // Verify foreign_keys pragma is enabled
        let fk_enabled: i32 = conn
            .query_row("PRAGMA foreign_keys;", [], |row| row.get(0))
            .expect("failed to read pragma");
        assert_eq!(fk_enabled, 1);
    }

    #[test]
    fn test_upsert_program_scope_and_rule_population() {
        let storage = StorageEngine::open_in_memory().expect("failed to open storage");
        let config = sample_config();

        let program_id = storage
            .upsert_program_scope(&config)
            .expect("upsert failed");
        assert!(!program_id.is_empty());

        // Update config with changed rules
        let mut updated = config.clone();
        updated.allowed_domains.push("api.example.com".to_string());
        let updated_id = storage
            .upsert_program_scope(&updated)
            .expect("second upsert failed");
        assert_eq!(program_id, updated_id);

        let conn = storage.conn.lock().expect("lock failed");
        let rule_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM scope_rules WHERE program_id = ?1",
                params![&program_id],
                |row| row.get(0),
            )
            .expect("count failed");
        // 3 allowed domains + 1 excluded domain + 1 excluded path = 5 rules
        assert_eq!(rule_count, 5);
        drop(conn);

        let prog = storage
            .get_program_by_id(&program_id)
            .expect("get_program_by_id failed");
        assert_eq!(
            prog.policy_url.as_deref(),
            Some("https://hackerone.com/test-storage-program")
        );
        let prog_by_name = storage
            .get_program_by_name(&config.program_name)
            .expect("get_program_by_name failed");
        assert_eq!(
            prog_by_name.policy_url.as_deref(),
            Some("https://hackerone.com/test-storage-program")
        );
    }

    #[test]
    fn test_foreign_key_enforcement() {
        let storage = StorageEngine::open_in_memory().expect("failed to open storage");

        // Inserting an audit log with an invalid foreign key must fail
        let invalid_entry = AuditLogEntry {
            program_id: "non-existent-uuid".to_string(),
            target_url: "https://example.com/".to_string(),
            http_method: "GET".to_string(),
            status_code: Some(200),
            duration_ms: 45,
            rate_limited: false,
        };

        let result = storage.record_audit_log(&invalid_entry);
        assert!(result.is_err());
    }

    #[test]
    fn test_audit_log_recording_and_retrieval() {
        let storage = StorageEngine::open_in_memory().expect("failed to open storage");
        let config = sample_config();
        let program_id = storage
            .upsert_program_scope(&config)
            .expect("upsert failed");

        let entry = AuditLogEntry {
            program_id: program_id.clone(),
            target_url: "https://example.com/api/v1/health".to_string(),
            http_method: "GET".to_string(),
            status_code: Some(200),
            duration_ms: 120,
            rate_limited: false,
        };

        let log_id = storage.record_audit_log(&entry).expect("log failed");
        assert!(log_id > 0);

        let logs = storage.get_audit_logs(&program_id).expect("query failed");
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].target_url, "https://example.com/api/v1/health");
        assert_eq!(logs[0].status_code, Some(200));
        assert_eq!(logs[0].duration_ms, 120);
        assert!(!logs[0].rate_limited);
    }

    #[test]
    fn test_endpoint_upsert_and_conflict_update() {
        let storage = StorageEngine::open_in_memory().expect("failed to open storage");
        let config = sample_config();
        let program_id = storage
            .upsert_program_scope(&config)
            .expect("upsert failed");

        let entry = EndpointEntry {
            program_id: program_id.clone(),
            url: "https://example.com/api/v1/users".to_string(),
            host: "example.com".to_string(),
            path: "/api/v1/users".to_string(),
            method: "GET".to_string(),
            discovered_via: "html_link".to_string(),
            status_code: Some(200),
            response_size: Some(1024),
            content_type: Some("application/json".to_string()),
        };

        let ep_id1 = storage
            .upsert_endpoint(&entry)
            .expect("upsert endpoint failed");
        assert!(!ep_id1.is_empty());

        let endpoints = storage
            .get_endpoints_for_program(&program_id)
            .expect("query endpoints failed");
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].url, "https://example.com/api/v1/users");
        assert_eq!(endpoints[0].status_code, Some(200));
        assert_eq!(endpoints[0].response_size, Some(1024));

        // Re-upsert same URL with updated status code and response size
        let mut updated_entry = entry.clone();
        updated_entry.status_code = Some(403);
        updated_entry.response_size = Some(512);
        updated_entry.discovered_via = "re-scan".to_string();

        let ep_id2 = storage
            .upsert_endpoint(&updated_entry)
            .expect("second upsert endpoint failed");
        assert_eq!(ep_id1, ep_id2);

        let endpoints_updated = storage
            .get_endpoints_for_program(&program_id)
            .expect("query endpoints failed");
        assert_eq!(endpoints_updated.len(), 1);
        assert_eq!(endpoints_updated[0].status_code, Some(403));
        assert_eq!(endpoints_updated[0].response_size, Some(512));
    }

    #[test]
    fn test_finding_upsert_idempotency_and_severity_ordering() {
        let storage = StorageEngine::open_in_memory().expect("failed to open storage");
        let config = sample_config();
        let program_id = storage
            .upsert_program_scope(&config)
            .expect("upsert failed");

        let prog = storage
            .get_program_by_id(&program_id)
            .expect("get program failed");
        assert_eq!(prog.name, config.program_name);

        let ep_entry = EndpointEntry {
            program_id: program_id.clone(),
            url: "https://example.com/api/v1/auth".to_string(),
            host: "example.com".to_string(),
            path: "/api/v1/auth".to_string(),
            method: "GET".to_string(),
            discovered_via: "seed".to_string(),
            status_code: Some(200),
            response_size: Some(256),
            content_type: Some("application/json".to_string()),
        };
        let ep_id = storage
            .upsert_endpoint(&ep_entry)
            .expect("upsert ep failed");

        // Insert finding 1 (LOW)
        let f1 = FindingEntry {
            program_id: program_id.clone(),
            endpoint_id: Some(ep_id.clone()),
            finding_type: "missing_security_headers".to_string(),
            severity: "LOW".to_string(),
            title: "Missing CSP".to_string(),
            description: "No CSP header".to_string(),
            evidence: "{}".to_string(),
            remediation: Some("Add CSP".to_string()),
        };
        let f1_id = storage.upsert_finding(&f1).expect("upsert f1 failed");

        // Insert finding 2 (HIGH)
        let f2 = FindingEntry {
            program_id: program_id.clone(),
            endpoint_id: Some(ep_id.clone()),
            finding_type: "cors_misconfiguration".to_string(),
            severity: "HIGH".to_string(),
            title: "CORS with credentials".to_string(),
            description: "Origin reflected".to_string(),
            evidence: "{}".to_string(),
            remediation: Some("Fix CORS".to_string()),
        };
        let f2_id = storage.upsert_finding(&f2).expect("upsert f2 failed");
        assert_ne!(f1_id, f2_id);

        // Re-upsert finding 1 with updated description
        let mut f1_updated = f1.clone();
        f1_updated.description = "Updated CSP description".to_string();
        let f1_re_id = storage
            .upsert_finding(&f1_updated)
            .expect("re-upsert f1 failed");
        assert_eq!(f1_id, f1_re_id);

        let findings = storage
            .get_findings_for_program(&program_id)
            .expect("query findings failed");
        assert_eq!(findings.len(), 2);
        // Severity ordering: HIGH must come before LOW
        assert_eq!(findings[0].severity, "HIGH");
        assert_eq!(findings[0].finding_type, "cors_misconfiguration");
        assert_eq!(findings[1].severity, "LOW");
        assert_eq!(findings[1].description, "Updated CSP description");
    }

    #[test]
    fn test_fresh_db_initializes_schema_version_3() {
        let storage = StorageEngine::open_in_memory().expect("open_in_memory failed");
        assert_eq!(storage.schema_version().expect("schema_version failed"), 3);
    }

    #[test]
    fn test_legacy_db_without_policy_url_migrates_cleanly() {
        let dir = tempfile::tempdir().expect("tempdir failed");
        let db_path = dir.path().join("legacy.db");

        // Create legacy schema without policy_url and insert existing row
        {
            let conn = Connection::open(&db_path).expect("open legacy conn failed");
            conn.execute(
                "CREATE TABLE programs (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    platform TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );",
                [],
            )
            .expect("create legacy table failed");

            conn.execute(
                "INSERT INTO programs (id, name, platform) VALUES ('p1', 'legacy-app', 'hackerone');",
                [],
            )
            .expect("insert legacy row failed");
        }

        // Open with StorageEngine and verify automatic migration to v3
        let storage = StorageEngine::open(&db_path).expect("open StorageEngine failed");
        assert_eq!(storage.schema_version().expect("schema_version failed"), 3);

        let prog = storage
            .get_program_by_id("p1")
            .expect("get_program_by_id failed");
        assert_eq!(prog.name, "legacy-app");
        assert_eq!(prog.platform, "hackerone");
        assert_eq!(prog.policy_url, None);

        // Verify policy_url can be updated
        let mut config = sample_config();
        config.program_name = "legacy-app".to_string();
        config.policy_url = Some("https://example.com/policy".to_string());
        storage
            .upsert_program_scope(&config)
            .expect("upsert_program_scope failed");

        let updated_prog = storage
            .get_program_by_id("p1")
            .expect("get updated program failed");
        assert_eq!(
            updated_prog.policy_url,
            Some("https://example.com/policy".to_string())
        );
    }

    #[test]
    fn test_reopening_migrated_db_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir failed");
        let db_path = dir.path().join("reopen.db");

        {
            let storage = StorageEngine::open(&db_path).expect("first open failed");
            assert_eq!(storage.schema_version().expect("schema_version failed"), 3);
            let config = sample_config();
            storage
                .upsert_program_scope(&config)
                .expect("upsert failed");
        }

        {
            let storage = StorageEngine::open(&db_path).expect("second open failed");
            assert_eq!(storage.schema_version().expect("schema_version failed"), 3);
            let config = sample_config();
            let prog_id = storage
                .upsert_program_scope(&config)
                .expect("second upsert failed");
            let prog = storage
                .get_program_by_id(&prog_id)
                .expect("get program failed");
            assert_eq!(prog.name, config.program_name);
        }
    }

    #[test]
    fn test_schema_migrates_from_v1_to_v2_cleanly() {
        let dir = tempfile::tempdir().expect("tempdir failed");
        let db_path = dir.path().join("v1_to_v2.db");

        // Create a v1 schema database
        {
            let conn = Connection::open(&db_path).expect("open connection failed");
            conn.execute_batch(
                r#"
                CREATE TABLE programs (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    platform TEXT NOT NULL,
                    policy_url TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE endpoints (
                    id TEXT PRIMARY KEY,
                    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
                    url TEXT NOT NULL UNIQUE,
                    host TEXT NOT NULL,
                    path TEXT NOT NULL,
                    method TEXT NOT NULL DEFAULT 'GET',
                    discovered_via TEXT NOT NULL,
                    status_code INTEGER,
                    response_size INTEGER,
                    content_type TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_verified_at TIMESTAMP
                );

                PRAGMA user_version = 1;
                "#,
            )
            .expect("init v1 db failed");

            conn.execute(
                "INSERT INTO programs (id, name, platform, policy_url) VALUES ('p1', 'mig-prog', 'hackerone', 'https://example.com');",
                [],
            )
            .expect("insert program failed");

            conn.execute(
                "INSERT INTO endpoints (id, program_id, url, host, path, method, discovered_via, status_code) VALUES ('e1', 'p1', 'https://example.com/api', 'example.com', '/api', 'GET', 'seed', 200);",
                [],
            )
            .expect("insert endpoint failed");
        }

        // Open with StorageEngine and verify automatic migration to v3
        let storage = StorageEngine::open(&db_path).expect("open StorageEngine failed");
        assert_eq!(storage.schema_version().expect("schema_version failed"), 3);

        // Verify existing data is preserved
        let prog = storage
            .get_program_by_id("p1")
            .expect("get_program_by_id failed");
        assert_eq!(prog.name, "mig-prog");
        let endpoints = storage
            .get_endpoints_for_program("p1")
            .expect("get_endpoints failed");
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].url, "https://example.com/api");

        // Verify detected_technologies table was created and can be queried
        let techs = storage
            .get_detected_technologies_for_program("p1")
            .expect("get_detected_technologies failed");
        assert_eq!(techs.len(), 0);

        // Verify scan snapshots can now be recorded on the migrated database
        let run_id = storage
            .record_scan_snapshot("p1")
            .expect("record_scan_snapshot failed");
        assert_eq!(run_id, 1);
        let runs = storage.get_scan_runs("p1").expect("get_scan_runs failed");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].endpoints_count, 1);
        assert_eq!(runs[0].findings_count, 0);
    }

    #[test]
    fn test_scan_snapshot_and_diff_detects_new_endpoints_status_shifts_and_regressions() {
        let storage = StorageEngine::open_in_memory().expect("open_in_memory failed");
        let config = sample_config();
        let program_id = storage
            .upsert_program_scope(&config)
            .expect("upsert_program_scope failed");

        // Baseline: Add endpoint 1 (HTTP 403) and endpoint 2 (HTTP 200)
        let ep1 = EndpointEntry {
            program_id: program_id.clone(),
            url: "https://example.com/api/v1/auth".to_string(),
            host: "example.com".to_string(),
            path: "/api/v1/auth".to_string(),
            method: "GET".to_string(),
            discovered_via: "seed".to_string(),
            status_code: Some(403),
            response_size: Some(100),
            content_type: Some("application/json".to_string()),
        };
        let ep1_id = storage.upsert_endpoint(&ep1).expect("upsert ep1 failed");

        let ep2 = EndpointEntry {
            program_id: program_id.clone(),
            url: "https://example.com/api/v1/legacy".to_string(),
            host: "example.com".to_string(),
            path: "/api/v1/legacy".to_string(),
            method: "GET".to_string(),
            discovered_via: "seed".to_string(),
            status_code: Some(200),
            response_size: Some(500),
            content_type: Some("application/json".to_string()),
        };
        let ep2_id = storage.upsert_endpoint(&ep2).expect("upsert ep2 failed");

        // Add finding 1 (HIGH) on ep1 and finding 2 (LOW) on ep2
        let f1 = FindingEntry {
            program_id: program_id.clone(),
            endpoint_id: Some(ep1_id),
            finding_type: "cors_misconfiguration".to_string(),
            severity: "HIGH".to_string(),
            title: "CORS origin reflection".to_string(),
            description: "Reflected origin".to_string(),
            evidence: "{}".to_string(),
            remediation: None,
        };
        storage.upsert_finding(&f1).expect("upsert f1 failed");

        let f2 = FindingEntry {
            program_id: program_id.clone(),
            endpoint_id: Some(ep2_id),
            finding_type: "information_disclosure".to_string(),
            severity: "LOW".to_string(),
            title: "Server header disclosure".to_string(),
            description: "Server header leaked".to_string(),
            evidence: "{}".to_string(),
            remediation: None,
        };
        storage.upsert_finding(&f2).expect("upsert f2 failed");

        let tech1 = crate::fingerprint::DetectedTechnology {
            name: "Nginx".to_string(),
            category: crate::fingerprint::TechCategory::WebServer,
            version: Some("1.18.0".to_string()),
            evidence: "Server: nginx/1.18.0".to_string(),
            endpoint: "https://example.com/api/v1/auth".to_string(),
        };
        storage
            .upsert_detected_technology(&program_id, &tech1)
            .expect("upsert tech1 failed");

        // Record Baseline Snapshot (Run 1)
        let run1_id = storage
            .record_scan_snapshot(&program_id)
            .expect("record run1 failed");
        assert_eq!(run1_id, 1);

        // Diff with only one run must return NotFound error
        let diff_err = storage.compute_latest_diff(&program_id);
        assert!(diff_err.is_err());

        // Alter state for Current Run:
        // 1. Status shift on ep1: 403 -> 200
        let mut ep1_updated = ep1.clone();
        ep1_updated.status_code = Some(200);
        storage
            .upsert_endpoint(&ep1_updated)
            .expect("update ep1 failed");

        // 2. Add new endpoint (ep3)
        let ep3 = EndpointEntry {
            program_id: program_id.clone(),
            url: "https://example.com/api/v1/new_ep".to_string(),
            host: "example.com".to_string(),
            path: "/api/v1/new_ep".to_string(),
            method: "POST".to_string(),
            discovered_via: "crawler".to_string(),
            status_code: Some(201),
            response_size: Some(250),
            content_type: Some("application/json".to_string()),
        };
        let ep3_id = storage.upsert_endpoint(&ep3).expect("upsert ep3 failed");

        // 3. Remove ep2 and resolve f2
        {
            let conn = storage.conn.lock().expect("lock failed");
            conn.execute(
                "DELETE FROM findings WHERE title = 'Server header disclosure'",
                [],
            )
            .expect("delete f2 failed");
            conn.execute(
                "DELETE FROM endpoints WHERE url = 'https://example.com/api/v1/legacy'",
                [],
            )
            .expect("delete ep2 failed");
        }

        // 4. Add new finding (f3 regression) on ep3
        let f3 = FindingEntry {
            program_id: program_id.clone(),
            endpoint_id: Some(ep3_id),
            finding_type: "open_redirect".to_string(),
            severity: "MEDIUM".to_string(),
            title: "Unvalidated parameter redirect".to_string(),
            description: "Redirects to external domain".to_string(),
            evidence: "{}".to_string(),
            remediation: None,
        };
        storage.upsert_finding(&f3).expect("upsert f3 failed");

        // 5. Add new CT discovered subdomain
        let ct_ep = EndpointEntry {
            program_id: program_id.clone(),
            url: "https://api.example.com/".to_string(),
            host: "api.example.com".to_string(),
            path: "/".to_string(),
            method: "GET".to_string(),
            discovered_via: "ct_log".to_string(),
            status_code: None,
            response_size: None,
            content_type: None,
        };
        storage
            .upsert_endpoint(&ct_ep)
            .expect("upsert ct_ep failed");

        // 6. Shift technology: remove Nginx, add Cloudflare
        {
            let conn = storage.conn.lock().expect("lock failed");
            conn.execute("DELETE FROM detected_technologies WHERE name = 'Nginx'", [])
                .expect("delete tech1 failed");
        }
        let tech2 = crate::fingerprint::DetectedTechnology {
            name: "Cloudflare".to_string(),
            category: crate::fingerprint::TechCategory::WafCdn,
            version: None,
            evidence: "cf-ray: test".to_string(),
            endpoint: "https://example.com/api/v1/new_ep".to_string(),
        };
        storage
            .upsert_detected_technology(&program_id, &tech2)
            .expect("upsert tech2 failed");

        // Record Current Snapshot (Run 2)
        let run2_id = storage
            .record_scan_snapshot(&program_id)
            .expect("record run2 failed");
        assert_eq!(run2_id, 2);

        // Compute diff
        let diff = storage
            .compute_latest_diff(&program_id)
            .expect("compute_latest_diff failed");

        assert_eq!(diff.program_id, program_id);
        assert_eq!(diff.baseline_run.id, 1);
        assert_eq!(diff.current_run.id, 2);

        // Verify deltas
        assert_eq!(
            diff.new_endpoints,
            vec![
                "https://api.example.com/".to_string(),
                "https://example.com/api/v1/new_ep".to_string(),
            ]
        );
        assert_eq!(
            diff.removed_endpoints,
            vec!["https://example.com/api/v1/legacy".to_string()]
        );

        assert_eq!(diff.status_changes.len(), 1);
        assert_eq!(
            diff.status_changes[0].url,
            "https://example.com/api/v1/auth"
        );
        assert_eq!(diff.status_changes[0].baseline_status, "403");
        assert_eq!(diff.status_changes[0].current_status, "200");

        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.new_findings[0].finding_type, "open_redirect");
        assert_eq!(diff.new_findings[0].severity, "MEDIUM");

        assert_eq!(diff.resolved_findings.len(), 1);
        assert_eq!(
            diff.resolved_findings[0].finding_type,
            "information_disclosure"
        );
        assert_eq!(diff.resolved_findings[0].severity, "LOW");

        assert_eq!(diff.new_technologies.len(), 1);
        assert_eq!(diff.new_technologies[0].name, "Cloudflare");
        assert_eq!(diff.new_technologies[0].category, "WafCdn");

        assert_eq!(diff.removed_technologies.len(), 1);
        assert_eq!(diff.removed_technologies[0].name, "Nginx");
        assert_eq!(diff.removed_technologies[0].category, "WebServer");

        assert_eq!(diff.new_subdomains.len(), 1);
        assert_eq!(diff.new_subdomains[0].hostname, "api.example.com");
        assert_eq!(diff.new_subdomains[0].source, "ct_log");
        assert_eq!(diff.new_subdomains[0].url, "https://api.example.com/");
        assert_eq!(diff.removed_subdomains.len(), 0);

        let subs = storage
            .get_subdomains_for_program(&program_id)
            .expect("get_subdomains failed");
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0].hostname, "api.example.com");
        assert_eq!(subs[0].source, "ct_log");
        assert_eq!(subs[1].hostname, "example.com");
    }
}
