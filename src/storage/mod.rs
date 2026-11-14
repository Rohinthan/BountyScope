use crate::error::StorageError;
use crate::scope::ScopeConfig;
use rusqlite::{params, Connection};
use std::path::Path;
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

        CREATE INDEX IF NOT EXISTS idx_endpoints_host ON endpoints(host);
        CREATE INDEX IF NOT EXISTS idx_findings_program ON findings(program_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
        "#;

        conn.execute_batch(schema)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
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
                    "UPDATE programs SET platform = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = ?2",
                    params![&config.platform, &id],
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
                    "INSERT INTO programs (id, name, platform) VALUES (?1, ?2, ?3)",
                    params![&id, &config.program_name, &config.platform],
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

    /// Retrieves a target program record by its unique ID.
    pub fn get_program_by_id(&self, program_id: &str) -> Result<ProgramRecord, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockFailure)?;
        conn.query_row(
            "SELECT id, name, platform, created_at, updated_at FROM programs WHERE id = ?1",
            params![program_id],
            |row| {
                Ok(ProgramRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    platform: row.get(2)?,
                    created_at: row.get(3)?,
                    updated_at: row.get(4)?,
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
            "SELECT id, name, platform, created_at, updated_at FROM programs WHERE name = ?1",
            params![program_name],
            |row| {
                Ok(ProgramRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    platform: row.get(2)?,
                    created_at: row.get(3)?,
                    updated_at: row.get(4)?,
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
}
