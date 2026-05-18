//! Kestrel CLI
//!
//! Command-line interface for the Kestrel detection engine.
//!
//! Platform support:
//! - Linux: Full eBPF collection + replay
//! - macOS/Windows: Replay and mock collection (no eBPF)

#[cfg(feature = "ebpf")]
use anyhow::Context;
use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::sync::Arc;
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

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AlertOutputType {
    /// Output alerts to stdout
    Stdout,
    /// Output alerts to a file
    File,
    /// Drop all alerts (no output)
    Null,
}

/// Alert output configuration for the CLI.
#[derive(Debug, clap::Args)]
pub struct AlertOutputArgs {
    /// Alert output format
    #[arg(long, value_enum, default_value = "stdout")]
    pub alert_output: AlertOutputType,

    /// Alert output file path (when format is file)
    #[arg(long)]
    pub alert_file: Option<PathBuf>,

    /// Pretty-print JSON alerts
    #[arg(long)]
    pub pretty_alerts: bool,

    /// Additional alert sinks (comma-separated: kafka://host:port/topic,es://host:port/index)
    #[arg(long)]
    pub alert_sinks: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the detection engine
    Run {
        /// Rules directory
        #[arg(short, long, default_value = "./rules")]
        rules: PathBuf,

        /// Optional eBPF object file path (Linux only)
        #[arg(long)]
        ebpf_object: Option<PathBuf>,

        /// Collector type: "ebpf" (Linux), "mock", or "replay"
        #[arg(long, default_value = "ebpf")]
        collector: String,

        /// Log level
        #[arg(short, long, default_value = "info")]
        log_level: String,

        /// Alert output configuration
        #[command(flatten)]
        alert_config: AlertOutputArgs,

        /// Watch rules directory for changes and hot-reload
        #[arg(long)]
        watch_rules: bool,
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

        /// Alert output configuration
        #[command(flatten)]
        alert_config: AlertOutputArgs,
    },

    /// Explain why a rule did or didn't match for a given event
    Explain {
        /// Rules directory
        #[arg(short, long, default_value = "./rules")]
        rules: PathBuf,

        /// Rule ID to explain
        #[arg(short, long)]
        rule_id: String,

        /// Event type ID
        #[arg(long)]
        event_type: u16,

        /// Entity key
        #[arg(long, default_value = "42")]
        entity_key: u128,

        /// Monotonic timestamp
        #[arg(long, default_value = "1000")]
        timestamp: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            rules,
            ebpf_object,
            collector,
            log_level,
            alert_config,
            watch_rules,
        } => {
            setup_logging(&log_level)?;
            run_engine(rules, ebpf_object, &collector, &alert_config, watch_rules).await?;
        },
        Commands::Validate { rules } => {
            setup_logging("info")?;
            validate_rules(rules).await?;
        },
        Commands::List { rules } => {
            setup_logging("info")?;
            list_rules(rules).await?;
        },
        Commands::Replay {
            rules,
            log,
            speed,
            alert_config,
        } => {
            setup_logging("info")?;
            replay_log(rules, log, speed, &alert_config).await?;
        },
        Commands::Explain {
            rules,
            rule_id,
            event_type,
            entity_key,
            timestamp,
        } => {
            setup_logging("info")?;
            explain_rules(rules, rule_id, event_type, entity_key, timestamp).await?;
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

/// Build an [`AlertRouter`] from CLI alert output arguments.
fn create_alert_router(config: &AlertOutputArgs) -> anyhow::Result<kestrel_core::AlertRouter> {
    let mut router = kestrel_core::AlertRouter::new();

    match config.alert_output {
        AlertOutputType::Stdout => {
            router
                .add_sink("stdout", Arc::new(kestrel_core::StdoutSink::new(config.pretty_alerts)));
        },
        AlertOutputType::File => {
            let path = config
                .alert_file
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("--alert-file required when --alert-output=file"))?;
            router.add_sink("file", Arc::new(kestrel_core::FileSink::new(path)?));
        },
        AlertOutputType::Null => {
            // No sinks = alerts are dropped
        },
    }

    Ok(router)
}

async fn run_engine(
    rules_dir: PathBuf,
    ebpf_object: Option<PathBuf>,
    collector_type: &str,
    alert_args: &AlertOutputArgs,
    watch_rules: bool,
) -> Result<()> {
    info!("Starting Kestrel detection engine");
    info!(rules_dir = %rules_dir.display(), "Loading rules from");

    let alert_router = create_alert_router(alert_args)?;
    let alert_sink: Option<Arc<dyn kestrel_core::AlertSink>> = if alert_router.health().is_empty() {
        None
    } else {
        Some(Arc::new(alert_router))
    };

    // Keep a clone of rules_dir for hot-reload watcher (config takes ownership)
    let rules_dir_for_watcher = rules_dir.clone();

    let config = kestrel_engine::EngineConfig {
        rules_dir,
        alert_sink,
        ..Default::default()
    };

    let mut engine = kestrel_engine::DetectionEngine::new(config).await?;

    let stats = engine.stats().await;
    info!(
        rule_count = stats.rule_count,
        compiled_single_event_rules = stats.single_event_rule_count,
        "Engine started"
    );

    // Set up hot reload if requested
    if watch_rules {
        if rules_dir_for_watcher.exists() {
            let rule_manager = engine.rule_manager().clone();
            match kestrel_rules::hot_reload::RuleHotReloader::new(
                rule_manager,
                &rules_dir_for_watcher,
                500, // 500ms debounce
            ) {
                Ok(mut hot_reloader) => {
                    tokio::spawn(async move {
                        while let Some(event) = hot_reloader.next_event().await {
                            match event {
                                kestrel_rules::hot_reload::HotReloadEvent::RulesReloaded(Ok(
                                    count,
                                )) => {
                                    info!("Hot reload completed: {} rules active", count);
                                },
                                kestrel_rules::hot_reload::HotReloadEvent::RulesReloaded(Err(
                                    e,
                                )) => {
                                    tracing::error!("Hot reload failed: {}", e);
                                },
                                kestrel_rules::hot_reload::HotReloadEvent::ValidationFailed(e) => {
                                    tracing::warn!("Hot reload validation failed: {}", e);
                                },
                                _ => {},
                            }
                        }
                    });
                    info!("Rule hot-reload enabled for {}", rules_dir_for_watcher.display());
                },
                Err(e) => {
                    tracing::warn!("Failed to start rule watcher: {}", e);
                },
            }
        } else {
            tracing::warn!(
                "Cannot watch rules directory: {} does not exist",
                rules_dir_for_watcher.display()
            );
        }
    }

    info!("Starting event processing loop...");
    engine.start().await?;

    // Create collector based on type and platform
    let mut collector: Option<Box<dyn kestrel_core::EventCollector>> =
        create_collector(collector_type, ebpf_object).await?;

    if let Some(ref mut c) = collector {
        info!(collector = c.name(), "Starting event collector");
        let publisher = engine.publisher();
        let (collector_tx, mut collector_rx) = mpsc::channel(1024);

        // Bridge collector events to engine
        tokio::spawn(async move {
            while let Some(event) = collector_rx.recv().await {
                if let Err(error) = publisher.publish(event).await {
                    tracing::error!(error = %error, "Failed to publish collector event into engine");
                }
            }
        });

        c.start(collector_tx).await?;
        info!(collector = c.name(), "Event collector started");
    } else {
        info!("No collector specified, running in engine-only mode");
    }

    info!("Engine running and waiting for events. Press Ctrl+C to stop.");

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
        collector.stop().await?;
    }

    Ok(())
}

/// Create an event collector based on the specified type.
///
/// On non-Linux platforms, eBPF collector is not available.
/// On non-macOS platforms, macOS collector is not available.
async fn create_collector(
    collector_type: &str,
    ebpf_object: Option<PathBuf>,
) -> Result<Option<Box<dyn kestrel_core::EventCollector>>> {
    match collector_type {
        "ebpf" => {
            #[cfg(feature = "ebpf")]
            {
                let object_path = ebpf_object
                    .ok_or_else(|| anyhow::anyhow!("eBPF collector requires --ebpf-object path"))?;

                info!(path = %object_path.display(), "Loading eBPF collector object");
                let ebpf = aya::Ebpf::load_file(&object_path).with_context(|| {
                    format!("Failed to load eBPF object {}", object_path.display())
                })?;

                let (tx, _rx) = mpsc::channel(1024);
                let mut ebpf_collector = kestrel_ebpf::EbpfCollector::new(tx, ebpf);
                let supported = kestrel_ebpf::EbpfCollector::supported_live_event_types();
                info!(?supported, "Current live eBPF collector event support");
                ebpf_collector.update_interests(supported);

                Ok(Some(Box::new(EbpfCollectorAdapter(ebpf_collector))))
            }
            #[cfg(not(feature = "ebpf"))]
            {
                anyhow::bail!(
                    "eBPF collector not available on this platform. \
                     Build with --features ebpf on Linux, or use --collector mock/replay"
                );
            }
        },
        "macos" => {
            #[cfg(feature = "macos")]
            {
                info!("Creating macOS event collector with Endpoint Security");
                let collector = kestrel_collector_macos::MacOSEventCollector::new()
                    .map_err(|e| anyhow::anyhow!("Failed to create macOS collector: {}", e))?;
                Ok(Some(Box::new(collector)))
            }
            #[cfg(not(feature = "macos"))]
            {
                anyhow::bail!(
                    "macOS collector not available on this platform. \
                     Build with --features macos on macOS, or use --collector mock/replay"
                );
            }
        },
        "mock" => {
            let count = 100; // Default mock event count
            info!(count, "Creating mock event collector");
            Ok(Some(Box::new(kestrel_core::MockEventCollector::generate_test_events(count))))
        },
        "replay" => {
            let path = ebpf_object.ok_or_else(|| {
                anyhow::anyhow!("Replay collector requires --ebpf-object as log path")
            })?;
            info!(path = %path.display(), "Creating replay event collector");
            Ok(Some(Box::new(kestrel_core::ReplayEventCollector::new(path))))
        },
        _ => anyhow::bail!(
            "Unknown collector type: '{}'. Use 'ebpf', 'macos', 'mock', or 'replay'",
            collector_type
        ),
    }
}

/// Adapter to make EbpfCollector implement EventCollector trait.
#[cfg(feature = "ebpf")]
struct EbpfCollectorAdapter(kestrel_ebpf::EbpfCollector);

#[cfg(feature = "ebpf")]
#[async_trait::async_trait]
impl kestrel_core::EventCollector for EbpfCollectorAdapter {
    async fn start(
        &mut self,
        _event_tx: mpsc::Sender<kestrel_event::Event>,
    ) -> std::result::Result<(), kestrel_core::PlatformError> {
        self.0
            .start()
            .await
            .map_err(|e| kestrel_core::PlatformError::InitializationError(e.to_string()))
    }

    async fn stop(&mut self) -> std::result::Result<(), kestrel_core::PlatformError> {
        self.0.stop().await;
        Ok(())
    }

    fn name(&self) -> &str {
        "ebpf"
    }

    fn platform_info(&self) -> Option<&kestrel_core::PlatformInfo> {
        None
    }
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

async fn replay_log(
    rules_dir: PathBuf,
    log_path: PathBuf,
    speed: f64,
    alert_args: &AlertOutputArgs,
) -> Result<()> {
    info!(rules_dir = %rules_dir.display(), log_path = %log_path.display(), speed, "Starting replay");

    let alert_router = create_alert_router(alert_args)?;
    let alert_sink: Option<Arc<dyn kestrel_core::AlertSink>> = if alert_router.health().is_empty() {
        None
    } else {
        Some(Arc::new(alert_router))
    };

    let config = kestrel_engine::EngineConfig {
        rules_dir,
        alert_sink,
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

async fn explain_rules(
    rules_dir: PathBuf,
    rule_id: String,
    event_type: u16,
    entity_key: u128,
    timestamp: u64,
) -> Result<()> {
    info!(%rule_id, event_type, entity_key, timestamp, "Explaining rule evaluation");

    // Create an in-memory trace collector
    let trace_config = kestrel_observability::TraceConfig {
        enabled: true,
        traced_rules: vec![rule_id.clone()],
        ..Default::default()
    };
    let trace_collector = Arc::new(kestrel_observability::InMemoryTraceCollector::new(trace_config));
    let trace_collector_dyn: Arc<dyn kestrel_observability::TraceCollector> = trace_collector.clone();

    let config = kestrel_engine::EngineConfig {
        rules_dir,
        trace_collector: Some(trace_collector_dyn),
        ..Default::default()
    };

    let engine = kestrel_engine::DetectionEngine::new(config).await?;

    // Create a test event
    let event = kestrel_event::Event::builder()
        .event_type(event_type)
        .entity_key(entity_key)
        .ts_mono(timestamp)
        .ts_wall(timestamp)
        .build()?;

    // Evaluate the event
    let alerts = engine.eval_event(&event).await?;

    // Get traces and explain
    let traces = trace_collector.get_traces_for_rule(&rule_id);

    if traces.is_empty() {
        println!("No trace found for rule '{}' on this event.", rule_id);
        println!("The rule may not have been evaluated (check if the event type matches).");
    } else {
        for trace in traces {
            let explanation = kestrel_observability::Explain::explain(&trace);
            println!("{}", explanation);
        }
    }

    println!("\nAlerts generated: {}", alerts.len());
    for alert in alerts {
        println!("- Rule: {}, Severity: {:?}", alert.rule_id, alert.severity);
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
