//! Kestrel CLI
//!
//! Command-line interface for the Kestrel detection engine.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "kestrel")]
#[command(about = "Kestrel - Next-generation endpoint behavior detection engine", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the detection engine
    Run {
        /// Rules directory
        #[arg(short, long, default_value = "./rules")]
        rules: PathBuf,

        /// Log level
        #[arg(short, long, default_value = "info")]
        log_level: String,
    },

    /// Validate rules without running detection
    Validate {
        /// Rules directory
        #[arg(short, long, default_value = "./rules")]
        rules: PathBuf,
    },

    /// List loaded rules
    List {
        /// Rules directory
        #[arg(short, long, default_value = "./rules")]
        rules: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { rules, log_level } => {
            setup_logging(&log_level)?;
            run_engine(rules).await?;
        }
        Commands::Validate { rules } => {
            setup_logging("info")?;
            validate_rules(rules).await?;
        }
        Commands::List { rules } => {
            setup_logging("info")?;
            list_rules(rules).await?;
        }
    }

    Ok(())
}

fn setup_logging(level: &str) -> Result<()> {
    let level = level.parse::<Level>().unwrap_or(Level::INFO);

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| anyhow::anyhow!("Failed to set tracing subscriber: {}", e))?;

    Ok(())
}

async fn run_engine(rules_dir: PathBuf) -> Result<()> {
    info!("Starting Kestrel detection engine");
    info!(rules_dir = %rules_dir.display(), "Loading rules from");

    let config = kestrel_engine::EngineConfig {
        rules_dir,
        ..Default::default()
    };

    let engine = kestrel_engine::DetectionEngine::new(config).await?;

    let stats = engine.stats().await;
    info!(rule_count = stats.rule_count, "Engine started");

    // TODO: Implement event processing loop
    info!("Engine running. Press Ctrl+C to stop.");

    tokio::signal::ctrl_c().await?;
    info!("Shutting down engine");

    Ok(())
}

async fn validate_rules(rules_dir: PathBuf) -> Result<()> {
    info!("Validating rules in {}", rules_dir.display());

    let rule_config = kestrel_rules::RuleManagerConfig {
        rules_dir,
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let rule_manager = kestrel_rules::RuleManager::new(rule_config);
    let stats = rule_manager.load_all().await?;

    info!(
        loaded = stats.loaded,
        failed = stats.failed,
        "Validation complete"
    );

    if stats.failed > 0 {
        anyhow::bail!("Failed to load {} rules", stats.failed);
    }

    Ok(())
}

async fn list_rules(rules_dir: PathBuf) -> Result<()> {
    let rule_config = kestrel_rules::RuleManagerConfig {
        rules_dir,
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let rule_manager = kestrel_rules::RuleManager::new(rule_config);
    rule_manager.load_all().await?;

    let rule_ids = rule_manager.list_rules().await;
    info!(count = rule_ids.len(), "Loaded rules:");

    for id in rule_ids {
        if let Some(rule) = rule_manager.get_rule(&id).await {
            println!(
                "- {} ({}) - {}",
                rule.metadata.id, rule.metadata.name, rule.metadata.severity
            );
        }
    }

    Ok(())
}
