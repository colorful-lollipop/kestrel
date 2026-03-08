//! Kestrel CLI
//!
//! Command-line interface for the Kestrel detection engine.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
use tracing::{Level, info};
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

        /// Optional eBPF object file path
        #[arg(long)]
        ebpf_object: Option<PathBuf>,

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

    /// Replay a captured event log through the detection engine
    Replay {
        /// Rules directory
        #[arg(short, long, default_value = "./rules")]
        rules: PathBuf,

        /// Replay log path
        #[arg(long)]
        log: PathBuf,

        /// Replay speed multiplier (0 = as fast as possible)
        #[arg(long, default_value = "0")]
        speed: f64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            rules,
            ebpf_object,
            log_level,
        } => {
            setup_logging(&log_level)?;
            run_engine(rules, ebpf_object).await?;
        },
        Commands::Validate { rules } => {
            setup_logging("info")?;
            validate_rules(rules).await?;
        },
        Commands::List { rules } => {
            setup_logging("info")?;
            list_rules(rules).await?;
        },
        Commands::Replay { rules, log, speed } => {
            setup_logging("info")?;
            replay_log(rules, log, speed).await?;
        },
    }

    Ok(())
}

fn setup_logging(level: &str) -> Result<()> {
    let level = level.parse::<Level>().unwrap_or(Level::INFO);

    let subscriber = FmtSubscriber::builder().with_max_level(level).finish();

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| anyhow::anyhow!("Failed to set tracing subscriber: {}", e))?;

    Ok(())
}

async fn run_engine(rules_dir: PathBuf, ebpf_object: Option<PathBuf>) -> Result<()> {
    info!("Starting Kestrel detection engine");
    info!(rules_dir = %rules_dir.display(), "Loading rules from");

    let config = kestrel_engine::EngineConfig {
        rules_dir,
        ..Default::default()
    };

    let mut engine = kestrel_engine::DetectionEngine::new(config).await?;

    let stats = engine.stats().await;
    info!(
        rule_count = stats.rule_count,
        compiled_single_event_rules = stats.single_event_rule_count,
        "Engine started"
    );

    info!("Starting event processing loop...");
    engine.start().await?;

    let mut collector = if let Some(object_path) = ebpf_object {
        info!(path = %object_path.display(), "Loading eBPF collector object");
        let publisher = engine.publisher();
        let (collector_tx, mut collector_rx) = mpsc::channel(1024);
        tokio::spawn(async move {
            while let Some(event) = collector_rx.recv().await {
                if let Err(error) = publisher.publish(event).await {
                    tracing::error!(error = %error, "Failed to publish collector event into engine");
                }
            }
        });

        let ebpf = aya::Ebpf::load_file(&object_path)
            .with_context(|| format!("Failed to load eBPF object {}", object_path.display()))?;
        let mut collector = kestrel_ebpf::EbpfCollector::new(collector_tx, ebpf);
        let supported = kestrel_ebpf::EbpfCollector::supported_live_event_types();
        info!(?supported, "Current live eBPF collector event support");
        collector.update_interests(supported);
        collector.start().await.with_context(|| {
            format!("Failed to start eBPF collector from {}", object_path.display())
        })?;
        info!("eBPF collector started");
        Some(collector)
    } else {
        None
    };

    info!(
        "Engine running and waiting for events from a collector or publisher. Press Ctrl+C to stop."
    );

    let mut stats_interval = interval(Duration::from_secs(10));

    tokio::spawn(async move {
        loop {
            stats_interval.tick().await;
            tracing::info!("Engine running - waiting for events");
        }
    });

    tokio::signal::ctrl_c().await?;
    info!("Shutting down engine");

    if let Some(ref mut collector) = collector {
        collector.stop().await;
    }

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

    info!(loaded = stats.loaded, failed = stats.failed, "Validation complete");

    if stats.failed > 0 {
        anyhow::bail!("Failed to load {} rules", stats.failed);
    }

    Ok(())
}

async fn replay_log(rules_dir: PathBuf, log_path: PathBuf, speed: f64) -> Result<()> {
    info!(rules_dir = %rules_dir.display(), log_path = %log_path.display(), speed, "Starting replay");

    let config = kestrel_engine::EngineConfig {
        rules_dir,
        alert_output: kestrel_core::AlertOutputConfig {
            stdout: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut engine = kestrel_engine::DetectionEngine::new(config).await?;
    let stats = engine
        .replay_log(kestrel_core::ReplayConfig {
            log_path,
            speed_multiplier: speed,
            stop_on_error: true,
            verify_determinism: false,
            verification_runs: 1,
            ..Default::default()
        })
        .await?;

    info!(
        events_processed = stats.events_processed,
        current_ts_mono_ns = stats.current_ts_mono_ns,
        current_ts_wall_ns = stats.current_ts_wall_ns,
        "Replay completed"
    );

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
