pub mod ct;
pub mod error;
pub mod fingerprint;
pub mod http;
pub mod mapper;
pub mod mcp;
pub mod report;
pub mod scope;
pub mod secrets;
pub mod storage;
pub mod verifier;

pub use ct::{CtLogDiscoverer, DiscoveredSubdomain};
pub use error::{
    CtError, HttpError, MapperError, McpError, ReportError, ScopeError, StorageError, VerifierError,
};
pub use fingerprint::{DetectedTechnology, PassiveFingerprinter, TechCategory};
pub use http::{HttpProbeResponse, ScopedHttpClient, MAX_RESPONSE_BODY_BYTES};
pub use mapper::{DiscoveredEndpoint, SurfaceMapResult, SurfaceMapper};
pub use mcp::{BountyScopeMcpServer, ValidateScopeRequest, ValidateScopeResponse};
pub use report::{ReportFormat, ReportGenerator};
pub use scope::{normalize_path, ScopeConfig, ScopeEnforcer, ScopeLintReport, VerifiedScopeUrl};
pub use secrets::{redact_secret, DetectedSecret, SecretScanner, SecretType};
pub use storage::{
    AuditLogEntry, AuditLogRecord, DiffFindingItem, DiffSubdomainItem, DiffTechItem,
    DiscoveredSubdomainRecord, EndpointEntry, EndpointRecord, EndpointStatusChange, FindingEntry,
    FindingRecord, ProgramRecord, ScanDiff, ScanRunRecord, ScanSnapshotItemRecord, StorageEngine,
};
pub use verifier::{SafeVerificationRunner, VerificationSummary};
