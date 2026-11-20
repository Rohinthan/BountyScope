use thiserror::Error;

/// Structured domain errors for scope configuration, parsing, and boundary enforcement.
#[derive(Debug, Error)]
pub enum ScopeError {
    #[error("I/O error while reading configuration: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to parse YAML configuration: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("Failed to parse URL: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("Invalid scope configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Invalid URL format: {0}")]
    InvalidUrl(String),

    #[error("Domain is not within allowed target scope: {0}")]
    DomainNotAllowed(String),

    #[error("Domain is explicitly excluded from scope: {0}")]
    DomainExcluded(String),

    #[error("URL path is explicitly excluded from inspection: {0}")]
    PathExcluded(String),

    #[error("Invalid rate limit '{0}': rate limit must be between 1 and 100 requests per second")]
    InvalidRateLimit(u32),
}

/// Structured errors for SQLite storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Storage initialization error: {0}")]
    Initialization(String),

    #[error("Entity not found: {0}")]
    NotFound(String),

    #[error("Internal storage lock failure")]
    LockFailure,
}

/// Structured errors for HTTP probing and network interaction.
#[derive(Debug, Error)]
pub enum HttpError {
    #[error("HTTP client initialization error: {0}")]
    Initialization(String),

    #[error("Network dispatch error: {0}")]
    Network(String),

    #[error("Response body exceeded maximum allowed size of {0} bytes (limit: {1} bytes)")]
    PayloadTooLarge(usize, usize),

    #[error("Rate limit or service unavailable (HTTP {0}): retries exhausted")]
    RateLimitExhausted(u16),

    #[error("Storage error during HTTP operation: {0}")]
    Storage(#[from] StorageError),

    #[error("Scope error during HTTP operation: {0}")]
    Scope(#[from] ScopeError),
}

/// Structured errors for passive surface mapping operations.
#[derive(Debug, Error)]
pub enum MapperError {
    #[error("Scope error during surface mapping: {0}")]
    Scope(#[from] ScopeError),

    #[error("HTTP error during surface mapping: {0}")]
    Http(#[from] HttpError),

    #[error("Storage error during surface mapping: {0}")]
    Storage(#[from] StorageError),

    #[error("URL parsing error during surface mapping: {0}")]
    Url(#[from] url::ParseError),

    #[error("JSON parsing error during surface mapping: {0}")]
    Json(#[from] serde_json::Error),

    #[error("HTML/CSS selector parsing error: {0}")]
    Selector(String),

    #[error("Regex compilation error: {0}")]
    Regex(#[from] regex::Error),

    #[error("Certificate Transparency discovery error: {0}")]
    Ct(#[from] CtError),
}

/// Structured errors for verification runner operations.
#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("Scope error during verification: {0}")]
    Scope(#[from] ScopeError),

    #[error("HTTP error during verification: {0}")]
    Http(#[from] HttpError),

    #[error("Storage error during verification: {0}")]
    Storage(#[from] StorageError),

    #[error("URL parsing error during verification: {0}")]
    Url(#[from] url::ParseError),

    #[error("JSON serialization error during verification: {0}")]
    Json(#[from] serde_json::Error),
}

/// Structured errors for report generation operations.
#[derive(Debug, Error)]
pub enum ReportError {
    #[error("I/O error during report generation: {0}")]
    Io(#[from] std::io::Error),

    #[error("Storage error during report generation: {0}")]
    Storage(#[from] StorageError),

    #[error("Program not found: {0}")]
    ProgramNotFound(String),

    #[error("JSON serialization error during report generation: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Unsupported report format: {0}")]
    UnsupportedFormat(String),
}

/// Structured errors for Model Context Protocol (MCP) server operations.
#[derive(Debug, Error)]
pub enum McpError {
    #[error("Scope error during MCP operation: {0}")]
    Scope(#[from] ScopeError),

    #[error("Storage error during MCP operation: {0}")]
    Storage(#[from] StorageError),

    #[error("Report generation error during MCP operation: {0}")]
    Report(#[from] ReportError),

    #[error("MCP protocol or transport error: {0}")]
    Protocol(String),
}

/// Structured errors for Certificate Transparency discovery operations.
#[derive(Debug, Error)]
pub enum CtError {
    #[error("Network error during CT log discovery: {0}")]
    Network(String),

    #[error("Rate limited by CT log provider (HTTP {0})")]
    RateLimited(u16),

    #[error("CT log service unavailable (HTTP {0})")]
    ServiceUnavailable(u16),

    #[error("JSON parsing error from CT log response: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Scope error during CT discovery: {0}")]
    Scope(#[from] ScopeError),
}
