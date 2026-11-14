use anyhow::{Context, Result};
use bountyscope::http::ScopedHttpClient;
use bountyscope::mapper::SurfaceMapper;
use bountyscope::report::ReportGenerator;
use bountyscope::scope::{ScopeConfig, ScopeEnforcer};
use bountyscope::storage::StorageEngine;
use bountyscope::verifier::SafeVerificationRunner;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "bountyscope")]
#[command(version = "0.14.0")]
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
        #[arg(short, long, default_value = "configs/scope.example.yaml")]
        config: PathBuf,
    },

    /// Safely probe an in-scope URL, enforcing rate limits and recording audit logs
    Probe {
        /// Path to scope configuration YAML file
        #[arg(short, long, default_value = "configs/scope.example.yaml")]
        config: PathBuf,

        /// Target URL to probe
        #[arg(short, long)]
        url: String,

        /// Path to local SQLite database file
        #[arg(short, long, default_value = "data/bountyscope.db")]
        db: PathBuf,
    },

    /// Passively map the attack surface starting from an in-scope seed URL
    Map {
        /// Path to scope configuration YAML file
        #[arg(short, long, default_value = "configs/scope.example.yaml")]
        config: PathBuf,

        /// Seed URL to initiate passive surface mapping
        #[arg(short, long)]
        url: String,

        /// Path to local SQLite database file
        #[arg(short, long, default_value = "data/bountyscope.db")]
        db: PathBuf,
    },

    /// Run non-destructive verification audits across mapped endpoints
    Audit {
        /// Path to scope configuration YAML file
        #[arg(short, long, default_value = "configs/scope.example.yaml")]
        config: PathBuf,

        /// Path to local SQLite database file
        #[arg(short, long, default_value = "data/bountyscope.db")]
        db: PathBuf,
    },

    /// Generate an assessment Markdown report from stored audit findings
    Report {
        /// Path to scope configuration YAML file
        #[arg(short, long, default_value = "configs/scope.example.yaml")]
        config: PathBuf,

        /// Path to local SQLite database file
        #[arg(short, long, default_value = "data/bountyscope.db")]
        db: PathBuf,

        /// Optional output file path for Markdown report (prints to stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::ValidateScope { config }) => execute_validate_scope(&config),
        Some(Commands::Probe { config, url, db }) => execute_probe(&config, &url, &db).await,
        Some(Commands::Map { config, url, db }) => execute_map(&config, &url, &db).await,
        Some(Commands::Audit { config, db }) => execute_audit(&config, &db).await,
        Some(Commands::Report { config, db, output }) => execute_report(&config, &db, &output),
        None => {
            println!("BountyScope v0.14.0 - Vulnerability Surface Mapping Engine");
            println!("Run 'bountyscope --help' for available commands.");
            Ok(())
        }
    }
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

async fn execute_probe(config_path: &PathBuf, url_str: &str, db_path: &PathBuf) -> Result<()> {
    let config = ScopeConfig::from_file(config_path)
        .with_context(|| format!("Failed to load scope configuration from {:?}", config_path))?;

    let enforcer = ScopeEnforcer::new(config.clone())
        .with_context(|| "Scope configuration failed validation rules")?;

    let verified_url = enforcer
        .validate_url(url_str)
        .with_context(|| format!("Target URL '{url_str}' is not within authorized scope"))?;

    let storage = StorageEngine::open(db_path)
        .with_context(|| format!("Failed to initialize database at {:?}", db_path))?;

    let program_id = storage
        .upsert_program_scope(&config)
        .with_context(|| "Failed to upsert target scope in database")?;

    let client = ScopedHttpClient::new(storage, program_id, config.rate_limit_rps)
        .with_context(|| "Failed to initialize scoped HTTP client")?;

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

async fn execute_map(config_path: &PathBuf, url_str: &str, db_path: &PathBuf) -> Result<()> {
    let config = ScopeConfig::from_file(config_path)
        .with_context(|| format!("Failed to load scope configuration from {:?}", config_path))?;

    let enforcer = ScopeEnforcer::new(config.clone())
        .with_context(|| "Scope configuration failed validation rules")?;

    let verified_seed = enforcer
        .validate_url(url_str)
        .with_context(|| format!("Seed URL '{url_str}' is not within authorized scope"))?;

    let storage = StorageEngine::open(db_path)
        .with_context(|| format!("Failed to initialize database at {:?}", db_path))?;

    let program_id = storage
        .upsert_program_scope(&config)
        .with_context(|| "Failed to upsert target scope in database")?;

    let client = ScopedHttpClient::new(storage.clone(), program_id.clone(), config.rate_limit_rps)
        .with_context(|| "Failed to initialize scoped HTTP client")?;

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

async fn execute_audit(config_path: &PathBuf, db_path: &PathBuf) -> Result<()> {
    let config = ScopeConfig::from_file(config_path)
        .with_context(|| format!("Failed to load scope configuration from {:?}", config_path))?;

    let enforcer = ScopeEnforcer::new(config.clone())
        .with_context(|| "Scope configuration failed validation rules")?;

    let storage = StorageEngine::open(db_path)
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
        .with_context(|| "Failed to initialize scoped HTTP client")?;

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
    db_path: &PathBuf,
    output: &Option<PathBuf>,
) -> Result<()> {
    let config = ScopeConfig::from_file(config_path)
        .with_context(|| format!("Failed to load scope configuration from {:?}", config_path))?;

    let storage = StorageEngine::open(db_path)
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

    match output {
        Some(out_path) => {
            ReportGenerator::write_to_file(&report_content, out_path)
                .with_context(|| format!("Failed to write report to {:?}", out_path))?;
            println!("Report generated successfully: {:?}", out_path);
        }
        None => {
            println!("{report_content}");
        }
    }

    Ok(())
}
