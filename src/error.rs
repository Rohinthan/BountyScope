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
