use anyhow::{Context, Result};
use bountyscope::http::ScopedHttpClient;
use bountyscope::scope::{ScopeConfig, ScopeEnforcer};
use bountyscope::storage::StorageEngine;
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
