use anyhow::{Context, Result};
use bountyscope::http::ScopedHttpClient;
use bountyscope::mapper::SurfaceMapper;
use bountyscope::mcp::BountyScopeMcpServer;
use bountyscope::report::ReportGenerator;
use bountyscope::scope::{ScopeConfig, ScopeEnforcer};
use bountyscope::storage::StorageEngine;
use bountyscope::verifier::SafeVerificationRunner;
use clap::{Parser, Subcommand};
use rmcp::ServiceExt;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "bountyscope")]
#[command(version = "0.14.1")]
#[command(
    about = "Automated vulnerability surface mapping and passive policy verification engine",
    long_about = "BountyScope is an automated vulnerability surface mapping and passive policy verification engine designed for authorized security assessments and bug bounty programs."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate target scope boundaries and configuration syntax
    ValidateScope {
        /// Path to scope configuration YAML file
        #[arg(
            short,
            long,
            env = "BOUNTYSCOPE_CONFIG",
            default_value = "configs/scope.example.yaml"
        )]
        config: PathBuf,
    },

    /// Execute unified end-to-end passive scan: mapping, verification, and report generation
    Scan {
        /// Target seed URL to initiate mapping and verification
        #[arg(short, long)]
        url: String,

        /// Path to scope configuration YAML file
        #[arg(
            short,
            long,
            env = "BOUNTYSCOPE_CONFIG",
            default_value = "configs/scope.example.yaml"
        )]
        config: PathBuf,

        /// Path to local SQLite database file (defaults to data/<program_name>.db)
        #[arg(short, long)]
        db: Option<PathBuf>,

        /// Output file path for Markdown report (defaults to data/<program_name>_report.md)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Safely probe an in-scope URL, enforcing rate limits and recording audit logs
    Probe {
        /// Path to scope configuration YAML file
        #[arg(
            short,
            long,
            env = "BOUNTYSCOPE_CONFIG",
            default_value = "configs/scope.example.yaml"
        )]
        config: PathBuf,

        /// Target URL to probe
        #[arg(short, long)]
        url: String,

        /// Path to local SQLite database file (defaults to data/<program_name>.db)
        #[arg(short, long)]
        db: Option<PathBuf>,
    },

    /// Passively map the attack surface starting from an in-scope seed URL
    Map {
        /// Path to scope configuration YAML file
        #[arg(
            short,
            long,
            env = "BOUNTYSCOPE_CONFIG",
            default_value = "configs/scope.example.yaml"
        )]
        config: PathBuf,

        /// Seed URL to initiate passive surface mapping
        #[arg(short, long)]
        url: String,

        /// Path to local SQLite database file (defaults to data/<program_name>.db)
        #[arg(short, long)]
        db: Option<PathBuf>,
    },

    /// Run non-destructive verification audits across mapped endpoints
    Audit {
        /// Path to scope configuration YAML file
        #[arg(
            short,
            long,
            env = "BOUNTYSCOPE_CONFIG",
            default_value = "configs/scope.example.yaml"
        )]
        config: PathBuf,

        /// Path to local SQLite database file (defaults to data/<program_name>.db)
        #[arg(short, long)]
        db: Option<PathBuf>,
    },

    /// Generate an assessment Markdown report from stored audit findings
    Report {
        /// Path to scope configuration YAML file
        #[arg(
            short,
            long,
            env = "BOUNTYSCOPE_CONFIG",
            default_value = "configs/scope.example.yaml"
        )]
        config: PathBuf,

        /// Path to local SQLite database file (defaults to data/<program_name>.db)
        #[arg(short, long)]
        db: Option<PathBuf>,

        /// Output file path for Markdown report (defaults to data/<program_name>_report.md unless --stdout is set)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Print report directly to standard output
        #[arg(long, default_value_t = false)]
        stdout: bool,
    },

    /// Serve native Model Context Protocol (MCP) server over stdio
    Mcp {
        /// Path to scope configuration YAML file
        #[arg(
            short,
            long,
            env = "BOUNTYSCOPE_CONFIG",
            default_value = "configs/scope.example.yaml"
        )]
        config: PathBuf,

        /// Path to local SQLite database file (defaults to data/<program_name>.db)
        #[arg(short, long)]
        db: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::ValidateScope { config }) => execute_validate_scope(&config),
        Some(Commands::Scan {
            url,
            config,
            db,
            output,
        }) => execute_scan(&config, &url, &db, &output).await,
        Some(Commands::Probe { config, url, db }) => execute_probe(&config, &url, &db).await,
        Some(Commands::Map { config, url, db }) => execute_map(&config, &url, &db).await,
        Some(Commands::Audit { config, db }) => execute_audit(&config, &db).await,
        Some(Commands::Report {
            config,
            db,
            output,
            stdout,
        }) => execute_report(&config, &db, &output, stdout),
        Some(Commands::Mcp { config, db }) => execute_mcp(&config, &db).await,
        None => {
            println!("BountyScope v0.14.1 - Vulnerability Surface Mapping Engine");
            println!("Run 'bountyscope --help' for available commands.");
            Ok(())
        }
    }
}

fn sanitize_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if sanitized.is_empty() {
        "bountyscope".to_string()
    } else {
        sanitized
    }
}

fn resolve_db_path(db_arg: &Option<PathBuf>, program_name: &str) -> Result<PathBuf> {
    let db_path = match db_arg {
        Some(p) => p.clone(),
        None => {
            let sanitized = sanitize_name(program_name);
            PathBuf::from(format!("data/{sanitized}.db"))
        }
    };
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create database directory {:?}", parent))?;
        }
    }
    Ok(db_path)
}

fn resolve_report_output_path(
    output_arg: &Option<PathBuf>,
    program_name: &str,
    stdout: bool,
) -> Result<Option<PathBuf>> {
    if stdout {
        return Ok(None);
    }
    let path = match output_arg {
        Some(p) => p.clone(),
        None => {
            let sanitized = sanitize_name(program_name);
            PathBuf::from(format!("data/{sanitized}_report.md"))
        }
    };
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create report directory {:?}", parent))?;
        }
    }
    Ok(Some(path))
}

fn execute_validate_scope(config_path: &PathBuf) -> Result<()> {
    let config = ScopeConfig::from_file(config_path)
        .with_context(|| format!("Failed to load scope configuration from {:?}", config_path))?;

    let enforcer = ScopeEnforcer::new(config.clone())
        .with_context(|| "Scope configuration failed validation rules")?;

    let conf = enforcer.config();
    println!(
        "Scope configuration valid: {} (platform: {}, allowed_domains: {}, excluded_domains: {}, excluded_paths: {}, rate_limit_rps: {}, safe_mode: {})",
        conf.program_name,
        conf.platform,
        conf.allowed_domains.len(),
        conf.excluded_domains.len(),
        conf.excluded_paths.len(),
        conf.rate_limit_rps,
        conf.safe_mode
    );

    Ok(())
}

async fn execute_scan(
    config_path: &PathBuf,
    url_str: &str,
    db_arg: &Option<PathBuf>,
    output_arg: &Option<PathBuf>,
) -> Result<()> {
    let config = ScopeConfig::from_file(config_path)
        .with_context(|| format!("Failed to load scope configuration from {:?}", config_path))?;

    let enforcer = ScopeEnforcer::new(config.clone())
        .with_context(|| "Scope configuration failed validation rules")?;

    let verified_seed = enforcer
        .validate_url(url_str)
        .with_context(|| format!("Seed URL '{url_str}' is not within authorized scope"))?;

    let db_path = resolve_db_path(db_arg, &config.program_name)?;
    let storage = StorageEngine::open(&db_path)
        .with_context(|| format!("Failed to initialize database at {:?}", db_path))?;

    let program_id = storage
        .upsert_program_scope(&config)
        .with_context(|| "Failed to upsert target scope in database")?;

    let client = ScopedHttpClient::new(storage.clone(), program_id.clone(), config.rate_limit_rps)
        .with_context(|| "Failed to initialize scoped HTTP client")?
        .with_researcher_handle(config.researcher_handle.clone());

    println!(
        "Target scope initialized for program '{}'",
        config.program_name
    );
    println!("Database: {:?}", db_path);

    println!(
        "Starting passive surface mapping from {}...",
        verified_seed.as_str()
    );
    let mapper = SurfaceMapper::new(&enforcer, &client, &storage, program_id.clone())
        .with_context(|| "Failed to initialize surface mapper")?;

    let map_result = mapper.map(&verified_seed).await.with_context(|| {
        format!(
            "Surface mapping failed for seed '{}'",
            verified_seed.as_str()
        )
    })?;

    println!(
        "Surface mapping complete: {} endpoints discovered ({} in-scope, {} out-of-scope discarded)",
        map_result.total_discovered, map_result.in_scope_count, map_result.out_of_scope_discarded
    );

    println!("Starting non-destructive security verification...");
    let runner = SafeVerificationRunner::new(&enforcer, &client, &storage, program_id.clone());
    let audit_summary = runner
        .run()
        .await
        .with_context(|| "Verification runner failed during audit execution")?;

    println!(
        "Audit completed: {} endpoints audited, {} total findings",
        audit_summary.total_audited, audit_summary.findings_count
    );
    println!("  CRITICAL: {}", audit_summary.critical_count);
    println!("  HIGH:     {}", audit_summary.high_count);
    println!("  MEDIUM:   {}", audit_summary.medium_count);
    println!("  LOW:      {}", audit_summary.low_count);
    println!("  INFO:     {}", audit_summary.info_count);

    let program = storage
        .get_program_by_name(&config.program_name)
        .with_context(|| format!("Program '{}' not found in database.", config.program_name))?;

    let endpoints = storage
        .get_endpoints_for_program(&program.id)
        .with_context(|| "Failed to query endpoints from database")?;

    let findings = storage
        .get_findings_for_program(&program.id)
        .with_context(|| "Failed to query findings from database")?;

    let report_content =
        ReportGenerator::generate_markdown(&program, &config, &endpoints, &findings);

    let out_path = resolve_report_output_path(output_arg, &config.program_name, false)?
        .context("Report output path resolution failed")?;

    ReportGenerator::write_to_file(&report_content, &out_path)
        .with_context(|| format!("Failed to write report to {:?}", out_path))?;

    println!("Assessment report generated successfully: {:?}", out_path);

    Ok(())
}

async fn execute_probe(
    config_path: &PathBuf,
    url_str: &str,
    db_arg: &Option<PathBuf>,
) -> Result<()> {
    let config = ScopeConfig::from_file(config_path)
        .with_context(|| format!("Failed to load scope configuration from {:?}", config_path))?;

    let enforcer = ScopeEnforcer::new(config.clone())
        .with_context(|| "Scope configuration failed validation rules")?;

    let verified_url = enforcer
        .validate_url(url_str)
        .with_context(|| format!("Target URL '{url_str}' is not within authorized scope"))?;

    let db_path = resolve_db_path(db_arg, &config.program_name)?;
    let storage = StorageEngine::open(&db_path)
        .with_context(|| format!("Failed to initialize database at {:?}", db_path))?;

    let program_id = storage
        .upsert_program_scope(&config)
        .with_context(|| "Failed to upsert target scope in database")?;

    let client = ScopedHttpClient::new(storage, program_id, config.rate_limit_rps)
        .with_context(|| "Failed to initialize scoped HTTP client")?
        .with_researcher_handle(config.researcher_handle.clone());

    let response = client
        .get(&verified_url)
        .await
        .with_context(|| format!("HTTP probe dispatch failed for '{}'", verified_url.as_str()))?;

    let content_type = response.content_type().unwrap_or("unknown");
    let redirect_info = match &response.redirect_location {
        Some(loc) => format!(" [Redirect -> {loc}]"),
        None => String::new(),
    };

    println!(
        "Probe successful: {} -> HTTP {} ({}, {} bytes, {} ms{})",
        verified_url.as_str(),
        response.status_code,
        content_type,
        response.body.len(),
        response.duration_ms,
        redirect_info
    );

    Ok(())
}

async fn execute_map(config_path: &PathBuf, url_str: &str, db_arg: &Option<PathBuf>) -> Result<()> {
    let config = ScopeConfig::from_file(config_path)
        .with_context(|| format!("Failed to load scope configuration from {:?}", config_path))?;

    let enforcer = ScopeEnforcer::new(config.clone())
        .with_context(|| "Scope configuration failed validation rules")?;

    let verified_seed = enforcer
        .validate_url(url_str)
        .with_context(|| format!("Seed URL '{url_str}' is not within authorized scope"))?;

    let db_path = resolve_db_path(db_arg, &config.program_name)?;
    let storage = StorageEngine::open(&db_path)
        .with_context(|| format!("Failed to initialize database at {:?}", db_path))?;

    let program_id = storage
        .upsert_program_scope(&config)
        .with_context(|| "Failed to upsert target scope in database")?;

    let client = ScopedHttpClient::new(storage.clone(), program_id.clone(), config.rate_limit_rps)
        .with_context(|| "Failed to initialize scoped HTTP client")?
        .with_researcher_handle(config.researcher_handle.clone());

    let mapper = SurfaceMapper::new(&enforcer, &client, &storage, program_id)
        .with_context(|| "Failed to initialize surface mapper")?;

    let result = mapper.map(&verified_seed).await.with_context(|| {
        format!(
            "Surface mapping failed for seed '{}'",
            verified_seed.as_str()
        )
    })?;

    println!(
        "Surface mapping complete for {}: {} endpoints discovered ({} in-scope, {} out-of-scope discarded)",
        result.seed_url,
        result.total_discovered,
        result.in_scope_count,
        result.out_of_scope_discarded
    );

    for endpoint in &result.endpoints {
        let status_desc = match endpoint.status_code {
            Some(code) => format!("HTTP {code}"),
            None => "unprobed".to_string(),
        };
        println!(
            "  [{}] {} ({})",
            endpoint.discovered_via, endpoint.url, status_desc
        );
    }

    Ok(())
}

async fn execute_audit(config_path: &PathBuf, db_arg: &Option<PathBuf>) -> Result<()> {
    let config = ScopeConfig::from_file(config_path)
        .with_context(|| format!("Failed to load scope configuration from {:?}", config_path))?;

    let enforcer = ScopeEnforcer::new(config.clone())
        .with_context(|| "Scope configuration failed validation rules")?;

    let db_path = resolve_db_path(db_arg, &config.program_name)?;
    let storage = StorageEngine::open(&db_path)
        .with_context(|| format!("Failed to initialize database at {:?}", db_path))?;

    let program = storage
        .get_program_by_name(&config.program_name)
        .with_context(|| {
            format!(
                "Program '{}' not found in database. Run 'bountyscope map' first.",
                config.program_name
            )
        })?;

    let client = ScopedHttpClient::new(storage.clone(), program.id.clone(), config.rate_limit_rps)
        .with_context(|| "Failed to initialize scoped HTTP client")?
        .with_researcher_handle(config.researcher_handle.clone());

    let runner = SafeVerificationRunner::new(&enforcer, &client, &storage, program.id.clone());
    let summary = runner
        .run()
        .await
        .with_context(|| "Verification runner failed during audit execution")?;

    println!(
        "Audit completed for program '{}': {} endpoints audited, {} total findings",
        program.name, summary.total_audited, summary.findings_count
    );
    println!("  CRITICAL: {}", summary.critical_count);
    println!("  HIGH:     {}", summary.high_count);
    println!("  MEDIUM:   {}", summary.medium_count);
    println!("  LOW:      {}", summary.low_count);
    println!("  INFO:     {}", summary.info_count);

    Ok(())
}

fn execute_report(
    config_path: &PathBuf,
    db_arg: &Option<PathBuf>,
    output_arg: &Option<PathBuf>,
    stdout: bool,
) -> Result<()> {
    let config = ScopeConfig::from_file(config_path)
        .with_context(|| format!("Failed to load scope configuration from {:?}", config_path))?;

    let db_path = resolve_db_path(db_arg, &config.program_name)?;
    let storage = StorageEngine::open(&db_path)
        .with_context(|| format!("Failed to initialize database at {:?}", db_path))?;

    let program = storage
        .get_program_by_name(&config.program_name)
        .with_context(|| format!("Program '{}' not found in database.", config.program_name))?;

    let endpoints = storage
        .get_endpoints_for_program(&program.id)
        .with_context(|| "Failed to query endpoints from database")?;

    let findings = storage
        .get_findings_for_program(&program.id)
        .with_context(|| "Failed to query findings from database")?;

    let report_content =
        ReportGenerator::generate_markdown(&program, &config, &endpoints, &findings);

    match resolve_report_output_path(output_arg, &config.program_name, stdout)? {
        Some(out_path) => {
            ReportGenerator::write_to_file(&report_content, &out_path)
                .with_context(|| format!("Failed to write report to {:?}", out_path))?;
            println!("Report generated successfully: {:?}", out_path);
        }
        None => {
            println!("{report_content}");
        }
    }

    Ok(())
}

async fn execute_mcp(config_path: &PathBuf, db_arg: &Option<PathBuf>) -> Result<()> {
    let config = ScopeConfig::from_file(config_path)
        .with_context(|| format!("Failed to load scope configuration from {:?}", config_path))?;

    let enforcer = ScopeEnforcer::new(config.clone())
        .with_context(|| "Scope configuration failed validation rules")?;

    let db_path = resolve_db_path(db_arg, &config.program_name)?;
    let storage = StorageEngine::open(&db_path)
        .with_context(|| format!("Failed to initialize database at {:?}", db_path))?;

    let _ = storage
        .upsert_program_scope(&config)
        .with_context(|| "Failed to upsert target scope in database")?;

    eprintln!(
        "BountyScope MCP server initialized for program '{}' (database: {:?})",
        config.program_name, db_path
    );
    eprintln!("Serving Model Context Protocol over stdio transport...");

    let server = BountyScopeMcpServer::new(enforcer, storage);
    let running = server
        .serve(rmcp::transport::io::stdio())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to initialize MCP server: {e}"))?;

    let _ = running
        .waiting()
        .await
        .map_err(|e| anyhow::anyhow!("MCP server runtime error: {e}"))?;

    eprintln!("BountyScope MCP server stopped cleanly.");
    Ok(())
}
