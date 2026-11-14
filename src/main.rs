use anyhow::{Context, Result};
use bountyscope::scope::{ScopeConfig, ScopeEnforcer};
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
