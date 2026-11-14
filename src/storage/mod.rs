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
}
