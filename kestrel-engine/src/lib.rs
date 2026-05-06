//! Kestrel Detection Engine
//!
//! This is the core detection engine that coordinates event processing,
// //! rule evaluation, alert generation, and enforcement actions.

use futures::stream::{FuturesUnordered, StreamExt};
use kestrel_core::eventbus::{DefaultPartitioner, Partitioner};
use kestrel_core::{
    ActionDecision, ActionExecutor, ActionPolicy, ActionTarget, ActionType, Alert, AlertHandle,
    AlertOutput, AlertOutputConfig, EventBus, EventBusConfig, EventBusHandle, EventEvidence,
    NoOpExecutor, ReplayConfig, ReplaySource, ReplayStats, Severity, TimeManager,
};
use kestrel_event::Event;
use kestrel_nfa::{CompiledSequence, NfaEngine, NfaEngineConfig, PredicateEvaluator};
use kestrel_rules::{Rule, RuleDefinition, RuleManager, Severity as RuleSeverity};
use kestrel_schema::{
    EventTypeDef, RuleCapabilities, RuleManifest as SchemaRuleManifest,
    RuleMetadata as SchemaRuleMetadata, SchemaRegistry, register_builtin_linux_schema,
};
use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use thiserror::Error;
use tokio::sync::{Mutex, mpsc};
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

#[cfg(feature = "wasm")]
use kestrel_eql::{EqlCompiler, IrRule, IrRuleType, codegen_wasm::WasmCodeGenerator};
#[cfg(feature = "wasm")]
use kestrel_runtime_wasm::{WasmConfig, WasmEngine};

// Runtime abstraction layer
pub mod runtime;
pub use runtime::{
    EvalResult, Runtime, RuntimeCapabilities, RuntimeError, RuntimeManager, RuntimeResult,
    RuntimeType,
};

#[cfg(feature = "lua")]
pub use runtime::LuaRuntimeAdapter;
#[cfg(feature = "wasm")]
pub use runtime::WasmRuntimeAdapter;

/// Engine operation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EngineMode {
    /// Inline enforcement mode - real-time blocking with strict budget
    Inline,

    /// Online detection mode - full sequence evaluation, alert-only
    Detect,

    /// Offline replay mode - no enforcement, deterministic results
    Offline,
}

/// Detection engine configuration
#[derive(Clone)]
pub struct EngineConfig {
    /// Event bus configuration
    pub event_bus: EventBusConfig,

    /// Alert output configuration
    pub alert_output: AlertOutputConfig,

    /// Rule manager configuration
    pub rules_dir: std::path::PathBuf,

    /// Engine operation mode
    pub mode: EngineMode,

    /// Action executor for enforcement (optional, uses NoOpExecutor if None)
    pub action_executor: Option<Arc<dyn ActionExecutor>>,

    /// Wasm runtime configuration (optional)
    #[cfg(feature = "wasm")]
    pub wasm_config: Option<WasmConfig>,

    /// NFA engine configuration
    pub nfa_config: Option<NfaEngineConfig>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            event_bus: EventBusConfig::default(),
            alert_output: AlertOutputConfig::default(),
            rules_dir: std::path::PathBuf::from("./rules"),
            mode: EngineMode::Detect,
            action_executor: None,
            #[cfg(feature = "wasm")]
            wasm_config: None,
            nfa_config: Some(NfaEngineConfig::default()),
        }
    }
}

/// Single-event rule with compiled predicate
#[derive(Debug, Clone)]
pub struct SingleEventRule {
    pub rule_id: String,
    pub rule_name: String,
    pub event_type: u16,
    pub severity: Severity,
    pub description: Option<String>,
    pub predicate: CompiledPredicate,
    /// Whether this rule can be enforced (inline mode only)
    pub blockable: bool,
    /// Action to take when rule matches (None = alert only)
    pub action_type: Option<ActionType>,
}

struct EvalContext<'a> {
    nfa_engine: &'a Arc<Mutex<Option<NfaEngine>>>,
    single_event_rules: &'a [SingleEventRule],
    #[cfg(feature = "wasm")]
    wasm_engine: Option<&'a Arc<WasmEngine>>,
    mode: EngineMode,
    action_executor: &'a Arc<dyn ActionExecutor>,
    schema: &'a SchemaRegistry,
    alerts_generated: &'a std::sync::atomic::AtomicU64,
    actions_generated: &'a std::sync::atomic::AtomicU64,
    errors_count: &'a std::sync::atomic::AtomicU64,
}

#[derive(Debug, Clone)]
pub enum CompiledPredicate {
    #[cfg(feature = "wasm")]
    Wasm {
        module_id: String,
        predicate_index: u32,
        required_fields: Vec<u32>,
    },
    #[cfg(feature = "lua")]
    Lua {
        script: String,
        required_fields: Vec<u32>,
    },
    AlwaysMatch,
}

/// Convert RuleSeverity to Severity
fn rule_severity_to_severity(severity: RuleSeverity) -> Severity {
    match severity {
        RuleSeverity::Informational => Severity::Informational,
        RuleSeverity::Low => Severity::Low,
        RuleSeverity::Medium => Severity::Medium,
        RuleSeverity::High => Severity::High,
        RuleSeverity::Critical => Severity::Critical,
    }
}

/// Determine action target from event
fn determine_action_target(event: &Event, schema: &SchemaRegistry) -> ActionTarget {
    let pid = schema
        .get_field_id("process.pid")
        .and_then(|field_id| event.get_field(field_id))
        .and_then(|value| value.as_u64())
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or((event.entity_key & 0xFFFF_FFFF) as u32);

    let executable = schema
        .get_field_id("process.executable")
        .and_then(|field_id| event.get_field(field_id))
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let file_path = schema
        .get_field_id("file.path")
        .and_then(|field_id| event.get_field(field_id))
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let network_destination = schema
        .get_field_id("network.destination")
        .and_then(|field_id| event.get_field(field_id))
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let network_port = schema
        .get_field_id("network.dest_port")
        .and_then(|field_id| event.get_field(field_id))
        .and_then(|value| value.as_u64());

    match event.event_type_id {
        3..=5 => ActionTarget::FileOp {
            pid,
            path: file_path.unwrap_or_else(|| format!("entity_{}", event.entity_key)),
        },
        6..=7 => {
            let addr = match (network_destination, network_port) {
                (Some(destination), Some(port)) => format!("{}:{}", destination, port),
                (Some(destination), None) => destination,
                (None, Some(port)) => format!("unknown:{}", port),
                (None, None) => format!("entity_{}", event.entity_key),
            };
            ActionTarget::NetworkOp { pid, addr }
        },
        _ => ActionTarget::ProcessExec {
            pid,
            executable: executable.unwrap_or_else(|| format!("entity_{}", event.entity_key)),
        },
    }
}

/// Detection engine
pub struct DetectionEngine {
    event_bus: EventBus,
    _alert_output: AlertOutput,
    alert_handle: AlertHandle,
    event_batch_rx: Mutex<Option<mpsc::Receiver<Vec<Event>>>>,
    processing_started: AtomicBool,
    rule_manager: Arc<RuleManager>,
    schema: Arc<SchemaRegistry>,

    /// Engine operation mode
    mode: EngineMode,

    /// Action executor for enforcement
    action_executor: Arc<dyn ActionExecutor>,

    #[cfg(feature = "wasm")]
    wasm_engine: Option<Arc<WasmEngine>>,

    #[cfg(feature = "wasm")]
    eql_compiler: std::sync::Mutex<Option<EqlCompiler>>,

    partition_count: usize,
    partitioner: Arc<dyn Partitioner>,

    /// NFA engines for sequence detection, one per event-bus partition
    nfa_engines: Vec<Arc<Mutex<Option<NfaEngine>>>>,

    /// Compiled single-event rules
    single_event_rules: Arc<tokio::sync::RwLock<Vec<SingleEventRule>>>,

    /// Alert counter (atomic for thread safety)
    alerts_generated: Arc<std::sync::atomic::AtomicU64>,

    /// Action counter (atomic for thread safety)
    actions_generated: Arc<std::sync::atomic::AtomicU64>,

    /// Error counter for tracking engine errors (atomic for thread safety)
    errors_count: Arc<std::sync::atomic::AtomicU64>,
}

impl DetectionEngine {
    /// Create a new detection engine
    pub async fn new(config: EngineConfig) -> Result<Self, EngineError> {
        info!("Initializing Kestrel detection engine");

        // Initialize schema registry
        let schema = Arc::new(SchemaRegistry::new());
        register_builtin_linux_schema(schema.as_ref())
            .map_err(|e| EngineError::SchemaError(e.to_string()))?;
        info!("Schema registry initialized");

        let (event_sink_tx, event_sink_rx) = mpsc::channel(config.event_bus.channel_size.max(1));
        let event_bus = EventBus::new_with_sink(config.event_bus.clone(), event_sink_tx);
        info!("Event bus initialized with engine sink");

        let alert_output = AlertOutput::new(config.alert_output);
        let alert_handle = alert_output.handle();
        info!("Alert output initialized");

        // Initialize rule manager
        let rule_config = kestrel_rules::RuleManagerConfig {
            rules_dir: config.rules_dir.clone(),
            watch_enabled: false,
            max_concurrent_loads: 4,
        };

        let rule_manager = Arc::new(RuleManager::new(rule_config));

        // Load initial rules
        let stats = rule_manager.load_all().await?;
        info!(loaded = stats.loaded, failed = stats.failed, "Rules loaded");

        // Initialize EQL compiler if Wasm is enabled
        #[cfg(feature = "wasm")]
        let eql_compiler = std::sync::Mutex::new(if config.wasm_config.is_some() {
            Some(EqlCompiler::new(schema.clone()))
        } else {
            None
        });

        // Initialize Wasm engine if configured
        #[cfg(feature = "wasm")]
        let wasm_engine = if let Some(wasm_config) = config.wasm_config {
            let engine = WasmEngine::new(wasm_config, schema.clone())
                .map_err(|e| EngineError::WasmRuntimeError(e.to_string()))?;
            info!("Wasm runtime initialized");
            Some(Arc::new(engine))
        } else {
            info!("Wasm runtime disabled");
            None
        };

        let partition_count = config.event_bus.partitions.max(1);
        let partitioner: Arc<dyn Partitioner> =
            Arc::new(DefaultPartitioner::new(config.event_bus.partition_strategy));

        // Initialize NFA engines with Wasm runtime as predicate evaluator
        let nfa_engines = if let Some(nfa_config) = config.nfa_config {
            #[cfg(feature = "wasm")]
            let predicate_evaluator = wasm_engine
                .clone()
                .map(|engine| engine as Arc<dyn PredicateEvaluator>);

            #[cfg(not(feature = "wasm"))]
            let predicate_evaluator: Option<Arc<dyn PredicateEvaluator>> = None;

            if let Some(evaluator) = predicate_evaluator {
                let engines = (0..partition_count)
                    .map(|_| {
                        Arc::new(Mutex::new(Some(NfaEngine::new(
                            nfa_config.clone(),
                            evaluator.clone(),
                        ))))
                    })
                    .collect::<Vec<_>>();
                info!(partitions = partition_count, "Partitioned NFA engines initialized");
                engines
            } else {
                warn!("NFA engine disabled (no predicate evaluator)");
                (0..partition_count)
                    .map(|_| Arc::new(Mutex::new(None)))
                    .collect::<Vec<_>>()
            }
        } else {
            (0..partition_count)
                .map(|_| Arc::new(Mutex::new(None)))
                .collect::<Vec<_>>()
        };

        let single_event_rules = Arc::new(tokio::sync::RwLock::new(Vec::new()));

        // Initialize action executor
        let action_executor = config
            .action_executor
            .unwrap_or_else(|| Arc::new(NoOpExecutor) as Arc<dyn ActionExecutor>);

        // Log the engine mode
        info!(mode = ?config.mode, "Detection engine mode");

        let engine = Self {
            event_bus,
            _alert_output: alert_output,
            alert_handle,
            event_batch_rx: Mutex::new(Some(event_sink_rx)),
            processing_started: AtomicBool::new(false),
            rule_manager,
            schema,
            mode: config.mode,
            action_executor,
            #[cfg(feature = "wasm")]
            wasm_engine,
            #[cfg(feature = "wasm")]
            eql_compiler,
            partition_count,
            partitioner,
            nfa_engines,
            single_event_rules,
            alerts_generated: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            actions_generated: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            errors_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        };

        engine.compile_rules().await?;

        Ok(engine)
    }

    /// Get the rule manager
    pub fn rule_manager(&self) -> &Arc<RuleManager> {
        &self.rule_manager
    }

    /// Publish an event into the engine pipeline.
    pub async fn publish_event(&self, event: Event) -> Result<(), EngineError> {
        self.event_bus
            .handle()
            .publish(event)
            .await
            .map_err(|e| EngineError::EventBusError(e.to_string()))
    }

    /// Cloneable publisher handle for external collectors.
    pub fn publisher(&self) -> EventBusHandle {
        self.event_bus.handle()
    }

    pub async fn replay_log(&mut self, config: ReplayConfig) -> Result<ReplayStats, EngineError> {
        if !self.processing_started.load(Ordering::SeqCst) {
            self.start().await?;
        }

        let mut replay = ReplaySource::new(config, self.schema.clone(), TimeManager::mock());
        replay.start(&self.event_bus).await?;
        Ok(replay.stats())
    }

    async fn emit_alerts(
        alert_handle: &AlertHandle,
        alerts: Vec<Alert>,
        errors_count: &std::sync::atomic::AtomicU64,
    ) {
        for alert in alerts {
            if let Err(error) = alert_handle.emit(alert).await {
                error!(error = %error, "Failed to emit alert");
                errors_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    fn ensure_event_types_registered(&self, eql: &str) -> Result<(), EngineError> {
        #[cfg(feature = "wasm")]
        {
            let compiler_guard = self
                .eql_compiler
                .lock()
                .map_err(|e| EngineError::WasmRuntimeError(format!("Mutex lock error: {}", e)))?;

            let compiler = compiler_guard.as_ref().ok_or_else(|| {
                EngineError::WasmRuntimeError("EQL compiler not initialized".to_string())
            })?;

            let query = compiler
                .parse(eql)
                .map_err(|e| EngineError::WasmRuntimeError(format!("EQL parse error: {}", e)))?;

            register_builtin_linux_schema(self.schema.as_ref())
                .map_err(|e| EngineError::SchemaError(e.to_string()))?;

            for event_type in query.event_types() {
                if self.schema.get_event_type_id(&event_type).is_none() {
                    self.schema
                        .register_event_type(EventTypeDef {
                            name: event_type.clone(),
                            description: Some(format!("Auto-registered from rule {}", event_type)),
                            parent: None,
                        })
                        .map_err(|e| {
                            EngineError::WasmRuntimeError(format!(
                                "Schema registration error: {}",
                                e
                            ))
                        })?;
                }
            }
        }

        #[cfg(not(feature = "wasm"))]
        {
            let _ = eql;
        }

        Ok(())
    }

    #[cfg(feature = "wasm")]
    fn predicate_indices(ir: &IrRule) -> HashMap<String, u32> {
        ir.predicates
            .keys()
            .enumerate()
            .map(|(index, predicate_id)| (predicate_id.clone(), index as u32))
            .collect()
    }

    #[cfg(feature = "wasm")]
    fn schema_manifest_for_rule(rule: &Rule) -> SchemaRuleManifest {
        let metadata = SchemaRuleMetadata {
            rule_id: rule.metadata.id.clone(),
            rule_name: rule.metadata.name.clone(),
            rule_version: rule.metadata.version.clone(),
            author: rule.metadata.author.clone(),
            description: rule.metadata.description.clone(),
            tags: rule.metadata.tags.clone(),
            severity: rule.metadata.severity.to_string(),
            schema_version: "1.0".to_string(),
        };

        SchemaRuleManifest {
            format_version: "1.0".to_string(),
            metadata,
            capabilities: RuleCapabilities::default(),
        }
    }

    /// Compile and register a rule.
    #[cfg(feature = "wasm")]
    pub async fn compile_single_event_rule(&self, rule: &Rule) -> Result<(), EngineError> {
        let definition = match &rule.definition {
            RuleDefinition::Eql(eql) => eql.clone(),
            RuleDefinition::Wasm(_) => {
                warn!(rule_id = %rule.metadata.id, "Skipping precompiled Wasm rule in engine compiler");
                return Ok(());
            },
            RuleDefinition::Lua(_) => {
                warn!(rule_id = %rule.metadata.id, "Skipping Lua rule in current engine compiler path");
                return Ok(());
            },
        };

        self.ensure_event_types_registered(&definition)?;

        let wasm_engine = self.wasm_engine.as_ref().ok_or_else(|| {
            EngineError::WasmRuntimeError("Wasm engine not initialized".to_string())
        })?;

        let ir = {
            let mut compiler_guard = self
                .eql_compiler
                .lock()
                .map_err(|e| EngineError::WasmRuntimeError(format!("Mutex lock error: {}", e)))?;
            let compiler = compiler_guard.as_mut().ok_or_else(|| {
                EngineError::WasmRuntimeError("EQL compiler not initialized".to_string())
            })?;

            compiler.compile_to_ir(&definition).map_err(|e| {
                EngineError::WasmRuntimeError(format!("EQL compilation error: {}", e))
            })?
        };
        let predicate_indices = Self::predicate_indices(&ir);

        let mut wasm_generator = WasmCodeGenerator::new();
        let wat = wasm_generator
            .generate(&ir)
            .map_err(|e| EngineError::WasmRuntimeError(format!("Wasm codegen error: {}", e)))?;
        let wasm_bytes = wat::parse_str(&wat)
            .map_err(|e| EngineError::WasmRuntimeError(format!("WAT parsing error: {}", e)))?;

        wasm_engine
            .load_module(Self::schema_manifest_for_rule(rule), wasm_bytes.clone())
            .await
            .map_err(|e| EngineError::WasmRuntimeError(e.to_string()))?;

        match &ir.rule_type {
            IrRuleType::Event { event_type } => {
                let event_type_id = self.schema.get_event_type_id(event_type).ok_or_else(|| {
                    EngineError::WasmRuntimeError(format!(
                        "Event type '{}' not registered in schema",
                        event_type
                    ))
                })?;

                let predicate = ir.predicates.get("main").ok_or_else(|| {
                    EngineError::WasmRuntimeError("No main predicate found".to_string())
                })?;

                let predicate_index = *predicate_indices.get("main").ok_or_else(|| {
                    EngineError::WasmRuntimeError("Main predicate index not found".to_string())
                })?;

                let single_rule = SingleEventRule {
                    rule_id: rule.metadata.id.clone(),
                    rule_name: rule.metadata.name.clone(),
                    event_type: event_type_id,
                    severity: rule_severity_to_severity(rule.metadata.severity),
                    description: rule.metadata.description.clone(),
                    predicate: CompiledPredicate::Wasm {
                        module_id: rule.metadata.id.clone(),
                        predicate_index,
                        required_fields: predicate.required_fields.clone(),
                    },
                    blockable: false,
                    action_type: None,
                };

                let mut rules = self.single_event_rules.write().await;
                rules.push(single_rule);
                info!(rule_id = %rule.metadata.id, "Compiled single-event rule");
            },
            IrRuleType::Sequence { .. } => {
                let compiled_sequence =
                    self.compile_sequence_rule(rule, &ir, &predicate_indices)?;
                self.load_sequence(compiled_sequence).await?;
                info!(rule_id = %rule.metadata.id, "Compiled sequence rule");
            },
        }

        Ok(())
    }

    #[cfg(not(feature = "wasm"))]
    pub async fn compile_single_event_rule(&self, _rule: &Rule) -> Result<(), EngineError> {
        Ok(())
    }

    #[cfg(feature = "wasm")]
    fn compile_sequence_rule(
        &self,
        rule: &Rule,
        ir: &IrRule,
        predicate_indices: &HashMap<String, u32>,
    ) -> Result<CompiledSequence, EngineError> {
        let sequence = ir.sequence.as_ref().ok_or_else(|| {
            EngineError::NfaError(format!(
                "Missing sequence metadata for rule {}",
                rule.metadata.id
            ))
        })?;

        let steps = sequence
            .steps
            .iter()
            .map(|step| {
                let event_type_id = self
                    .schema
                    .get_event_type_id(&step.event_type_name)
                    .ok_or_else(|| {
                        EngineError::NfaError(format!(
                            "Event type '{}' is not registered for rule {}",
                            step.event_type_name, rule.metadata.id
                        ))
                    })?;
                let predicate_index =
                    predicate_indices.get(&step.predicate_id).ok_or_else(|| {
                        EngineError::NfaError(format!(
                            "Predicate '{}' is not indexed for rule {}",
                            step.predicate_id, rule.metadata.id
                        ))
                    })?;

                Ok::<kestrel_nfa::SeqStep, EngineError>(kestrel_nfa::SeqStep::new(
                    step.index as u16,
                    format!("{}:{}", rule.metadata.id, predicate_index),
                    event_type_id,
                ))
            })
            .collect::<Result<Vec<_>, EngineError>>()?;

        let until_step = sequence
            .until
            .as_ref()
            .map(|predicate_id| {
                let predicate = ir.predicates.get(predicate_id).ok_or_else(|| {
                    EngineError::NfaError(format!(
                        "Until predicate '{}' not found for rule {}",
                        predicate_id, rule.metadata.id
                    ))
                })?;
                let predicate_index = predicate_indices.get(predicate_id).ok_or_else(|| {
                    EngineError::NfaError(format!(
                        "Until predicate '{}' missing index for rule {}",
                        predicate_id, rule.metadata.id
                    ))
                })?;
                let event_type_id = self
                    .schema
                    .get_event_type_id(&predicate.event_type)
                    .ok_or_else(|| {
                        EngineError::NfaError(format!(
                            "Until event type '{}' not registered for rule {}",
                            predicate.event_type, rule.metadata.id
                        ))
                    })?;

                Ok::<kestrel_nfa::SeqStep, EngineError>(kestrel_nfa::SeqStep::new(
                    steps.len() as u16,
                    format!("{}:{}", rule.metadata.id, predicate_index),
                    event_type_id,
                ))
            })
            .transpose()?;

        let nfa_sequence = kestrel_nfa::NfaSequence::with_captures(
            rule.metadata.id.clone(),
            sequence.by_field_id,
            steps,
            sequence.maxspan_ms,
            until_step,
            ir.captures.clone(),
        );

        Ok(CompiledSequence {
            id: rule.metadata.id.clone(),
            sequence: nfa_sequence,
            rule_id: rule.metadata.id.clone(),
            rule_name: rule.metadata.name.clone(),
        })
    }

    /// Compile all loaded rules into single-event and sequence rules
    pub async fn compile_rules(&self) -> Result<(), EngineError> {
        info!("Compiling rules");

        {
            let mut rules = self.single_event_rules.write().await;
            rules.clear();
        }

        let rule_ids = self.rule_manager.list_rules().await;

        for rule_id in rule_ids {
            if let Some(rule) = self.rule_manager.get_rule(&rule_id).await {
                if let Err(error) = self.compile_single_event_rule(&rule).await {
                    error!(rule_id = %rule.metadata.id, error = %error, "Failed to compile rule");
                    self.errors_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }

        let count = self.single_event_rules.read().await.len();
        info!(count, "Single-event rules compiled");

        Ok(())
    }

    /// Get engine statistics
    pub async fn stats(&self) -> EngineStats {
        let rule_count = self.rule_manager.rule_count().await;
        let alerts_generated = self
            .alerts_generated
            .load(std::sync::atomic::Ordering::Relaxed);
        let actions_generated = self
            .actions_generated
            .load(std::sync::atomic::Ordering::Relaxed);
        let errors_count = self.errors_count.load(std::sync::atomic::Ordering::Relaxed);
        let single_event_rule_count = self.single_event_rules.read().await.len();

        EngineStats {
            rule_count,
            single_event_rule_count,
            alerts_generated,
            actions_generated,
            errors_count,
        }
    }

    /// Start the detection engine's event processing loop
    /// This method subscribes to the event bus and processes events in the background.
    /// Returns immediately after starting the event loop.
    pub async fn start(&mut self) -> Result<(), EngineError> {
        info!("Starting detection engine event loop");

        if self.processing_started.swap(true, Ordering::SeqCst) {
            warn!("Detection engine event loop already started");
            return Ok(());
        }

        let mut receiver = self.event_batch_rx.lock().await.take().ok_or_else(|| {
            EngineError::EventBusError("Event batch receiver not available".to_string())
        })?;

        let single_event_rules = self.single_event_rules.clone();
        let nfa_engines = self.nfa_engines.clone();
        let alert_handle = self.alert_handle.clone();
        let action_executor = self.action_executor.clone();
        let alerts_generated = self.alerts_generated.clone();
        let actions_generated = self.actions_generated.clone();
        let errors_count = self.errors_count.clone();
        let schema = self.schema.clone();
        let mode = self.mode;
        let partitioner = self.partitioner.clone();
        let partition_count = self.partition_count;
        #[cfg(feature = "wasm")]
        let wasm_engine = self.wasm_engine.clone();

        tokio::spawn(async move {
            info!("Event processing loop started");
            while let Some(batch) = receiver.recv().await {
                if batch.is_empty() {
                    continue;
                }

                let partition_id = partitioner.partition(&batch[0], partition_count);
                let single_event_rules_snapshot = { single_event_rules.read().await.clone() };
                let eval_context = EvalContext {
                    nfa_engine: &nfa_engines[partition_id],
                    single_event_rules: &single_event_rules_snapshot,
                    #[cfg(feature = "wasm")]
                    wasm_engine: wasm_engine.as_ref(),
                    mode,
                    action_executor: &action_executor,
                    schema: schema.as_ref(),
                    alerts_generated: alerts_generated.as_ref(),
                    actions_generated: actions_generated.as_ref(),
                    errors_count: errors_count.as_ref(),
                };

                for event in batch {
                    let result =
                        DetectionEngine::eval_event_with_rules(&event, &eval_context).await;

                    match result {
                        Ok(alerts) => {
                            if !alerts.is_empty() {
                                let alert_handle = alert_handle.clone();
                                let errors_count = errors_count.clone();
                                tokio::spawn(async move {
                                    DetectionEngine::emit_alerts(
                                        &alert_handle,
                                        alerts,
                                        errors_count.as_ref(),
                                    )
                                    .await;
                                });
                            }
                        },
                        Err(error) => {
                            error!(error = %error, "Failed to evaluate event batch item");
                            errors_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        },
                    }
                }
            }
        });

        let event_handle = self.event_bus.handle();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let stats = event_handle.metrics();
                tracing::debug!(
                    events_received = stats.events_received,
                    events_processed = stats.events_processed,
                    "Event bus stats"
                );
            }
        });

        Ok(())
    }

    /// Evaluate an event against all loaded rules
    #[tracing::instrument(skip(self, event), fields(event_id = %event.ts_mono_ns, event_type_id = event.event_type_id))]
    pub async fn eval_event(&self, event: &Event) -> Result<Vec<Alert>, EngineError> {
        let single_event_rules_snapshot = { self.single_event_rules.read().await.clone() };
        let partition_id = self.partition_for_event(event);
        let context = EvalContext {
            nfa_engine: &self.nfa_engines[partition_id],
            single_event_rules: &single_event_rules_snapshot,
            #[cfg(feature = "wasm")]
            wasm_engine: self.wasm_engine.as_ref(),
            mode: self.mode,
            action_executor: &self.action_executor,
            schema: self.schema.as_ref(),
            alerts_generated: self.alerts_generated.as_ref(),
            actions_generated: self.actions_generated.as_ref(),
            errors_count: self.errors_count.as_ref(),
        };

        DetectionEngine::eval_event_with_rules(event, &context).await
    }

    async fn eval_event_with_rules(
        event: &Event,
        context: &EvalContext<'_>,
    ) -> Result<Vec<Alert>, EngineError> {
        debug!(
            event_type_id = event.event_type_id,
            entity_key = event.entity_key,
            "Evaluating event"
        );

        let mut alerts = Vec::new();

        {
            let mut guard = context.nfa_engine.lock().await;
            if let Some(nfa_engine) = guard.as_mut() {
                match nfa_engine.process_event(event).await {
                    Ok(sequence_alerts) => {
                        for seq_alert in sequence_alerts {
                            let events: Vec<EventEvidence> = seq_alert
                                .events
                                .iter()
                                .map(|e| EventEvidence {
                                    event_type_id: e.event_type_id,
                                    timestamp_ns: e.ts_mono_ns,
                                    fields: vec![],
                                })
                                .collect();

                            let alert_context = serde_json::json!({
                                "sequence_id": seq_alert.sequence_id,
                                "entity_key": seq_alert.entity_key,
                                "captures": seq_alert.captures,
                            });

                            alerts.push(Alert {
                                id: format!("{}-{}", seq_alert.rule_id, seq_alert.timestamp_ns),
                                rule_id: seq_alert.rule_id.clone(),
                                rule_name: seq_alert.rule_name.clone(),
                                severity: Severity::High,
                                title: format!("Sequence matched: {}", seq_alert.sequence_id),
                                description: Some(format!(
                                    "Entity {} completed sequence {}",
                                    seq_alert.entity_key, seq_alert.sequence_id
                                )),
                                timestamp_ns: seq_alert.timestamp_ns,
                                events,
                                context: alert_context,
                            });

                            context
                                .alerts_generated
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    },
                    Err(error) => {
                        error!(error = %error, "NFA engine error");
                        context
                            .errors_count
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    },
                }
            }
        }

        #[cfg(feature = "wasm")]
        {
            let wasm_engine = context.wasm_engine.cloned();
            let mut evaluations = FuturesUnordered::new();

            for single_rule in context.single_event_rules.iter() {
                if single_rule.event_type != event.event_type_id {
                    continue;
                }

                let rule = single_rule.clone();
                let wasm_engine = wasm_engine.clone();
                evaluations.push(async move {
                    let matched = match &rule.predicate {
                        CompiledPredicate::Wasm {
                            module_id,
                            predicate_index,
                            ..
                        } => {
                            let wasm_engine = wasm_engine.ok_or_else(|| {
                                EngineError::WasmRuntimeError(
                                    "Wasm engine not initialized for Wasm predicate".to_string(),
                                )
                            })?;
                            DetectionEngine::eval_wasm_predicate(
                                wasm_engine.as_ref(),
                                module_id,
                                *predicate_index,
                                event,
                            )
                            .await?
                        },
                        CompiledPredicate::AlwaysMatch => true,
                        CompiledPredicate::Lua { .. } => false,
                    };

                    Ok::<(SingleEventRule, bool), EngineError>((rule, matched))
                });
            }

            while let Some(result) = evaluations.next().await {
                let (single_rule, matched) = result?;
                if !matched {
                    continue;
                }

                alerts.push(Alert {
                    id: format!("{}-{}", single_rule.rule_id, event.ts_mono_ns),
                    rule_id: single_rule.rule_id.clone(),
                    rule_name: single_rule.rule_name.clone(),
                    severity: single_rule.severity,
                    title: format!("Single-event rule matched: {}", single_rule.rule_name),
                    description: single_rule.description.clone(),
                    timestamp_ns: event.ts_mono_ns,
                    events: vec![EventEvidence {
                        event_type_id: event.event_type_id,
                        timestamp_ns: event.ts_mono_ns,
                        fields: vec![],
                    }],
                    context: serde_json::json!({"rule_type": "single_event"}),
                });
                context
                    .alerts_generated
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                if context.mode == EngineMode::Inline && single_rule.blockable {
                    if let Some(action_type) = single_rule.action_type {
                        let decision = ActionDecision::new(
                            single_rule.rule_id.clone(),
                            action_type,
                            ActionPolicy::Inline,
                            determine_action_target(event, context.schema),
                            format!("Rule matched: {}", single_rule.rule_name),
                            vec![],
                        );

                        match context.action_executor.execute(&decision) {
                            Ok(result) if result.success => {
                                context
                                    .actions_generated
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            },
                            Ok(result) => {
                                debug!(
                                    action_id = %decision.id,
                                    action = ?action_type,
                                    error = %result.error.as_deref().unwrap_or(""),
                                    "Action not executed (executor decision)"
                                );
                            },
                            Err(error) => {
                                error!(
                                    action_id = %decision.id,
                                    action = ?action_type,
                                    error = %error,
                                    "Action execution failed"
                                );
                            },
                        }
                    }
                }
            }
        }

        Ok(alerts)
    }

    #[cfg(feature = "wasm")]
    async fn eval_wasm_predicate(
        wasm_engine: &WasmEngine,
        module_id: &str,
        predicate_index: u32,
        event: &Event,
    ) -> Result<bool, EngineError> {
        wasm_engine
            .eval_loaded_predicate(module_id, predicate_index, event)
            .await
            .map_err(|e| EngineError::WasmRuntimeError(e.to_string()))
    }

    /// Load a compiled sequence into the NFA engine
    pub async fn load_sequence(&self, sequence: CompiledSequence) -> Result<(), EngineError> {
        for (partition_id, nfa_engine) in self.nfa_engines.iter().enumerate() {
            let mut guard = nfa_engine.lock().await;
            if let Some(engine) = guard.as_mut() {
                engine.load_sequence(sequence.clone()).map_err(|e| {
                    EngineError::NfaError(format!(
                        "partition {partition_id} load_sequence failed: {e}"
                    ))
                })?;
            }
        }

        Ok(())
    }

    /// Unload a compiled sequence from every partitioned NFA engine.
    pub async fn unload_sequence(&self, sequence_id: &str) -> Result<(), EngineError> {
        for (partition_id, nfa_engine) in self.nfa_engines.iter().enumerate() {
            let mut guard = nfa_engine.lock().await;
            if let Some(engine) = guard.as_mut() {
                engine.unload_sequence(sequence_id).map_err(|e| {
                    EngineError::NfaError(format!(
                        "partition {partition_id} unload_sequence failed: {e}"
                    ))
                })?;
            }
        }
        Ok(())
    }

    fn partition_for_event(&self, event: &Event) -> usize {
        self.partitioner.partition(event, self.partition_count)
    }
}

/// Engine statistics
#[derive(Debug, Clone)]
pub struct EngineStats {
    pub rule_count: usize,
    pub single_event_rule_count: usize,
    pub alerts_generated: u64,
    pub actions_generated: u64,
    pub errors_count: u64,
}

/// Engine errors
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("Rule manager error: {0}")]
    RuleManagerError(#[from] kestrel_rules::RuleManagerError),

    #[error("Event bus error: {0}")]
    EventBusError(String),

    #[error("Alert output error: {0}")]
    AlertOutputError(String),

    #[error("Wasm runtime error: {0}")]
    WasmRuntimeError(String),

    #[error("NFA error: {0}")]
    NfaError(String),

    #[error("Schema error: {0}")]
    SchemaError(String),

    #[error("Replay error: {0}")]
    ReplayError(#[from] kestrel_core::ReplayError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_event::Event;
    use kestrel_nfa::{CompiledSequence, NfaResult, NfaSequence, SeqStep};
    use tokio::time::Duration;

    struct TestMockEvaluator {
        result: bool,
    }

    #[async_trait::async_trait]
    impl PredicateEvaluator for TestMockEvaluator {
        async fn evaluate(&self, _predicate_id: &str, _event: &Event) -> NfaResult<bool> {
            Ok(self.result)
        }

        fn get_required_fields(&self, _predicate_id: &str) -> NfaResult<Vec<u32>> {
            Ok(Vec::new())
        }

        fn has_predicate(&self, _predicate_id: &str) -> bool {
            true
        }
    }

    fn create_test_sequence(sequence_id: &str) -> CompiledSequence {
        CompiledSequence {
            id: sequence_id.to_string(),
            sequence: NfaSequence::new(
                sequence_id.to_string(),
                100,
                vec![
                    SeqStep::new(0, "pred1".to_string(), 1),
                    SeqStep::new(1, "pred2".to_string(), 2),
                ],
                Some(5_000),
                None,
            ),
            rule_id: format!("rule-{sequence_id}"),
            rule_name: format!("Rule {sequence_id}"),
        }
    }

    #[tokio::test]
    async fn test_engine_create() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();

        let config = EngineConfig {
            rules_dir,
            ..Default::default()
        };

        let engine = DetectionEngine::new(config).await;
        assert!(engine.is_ok());

        let engine = engine.unwrap();
        let stats = engine.stats().await;
        assert_eq!(stats.rule_count, 0);
    }

    #[tokio::test]
    async fn test_partitioned_nfa_count_matches_event_bus_partitions() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();

        let config = EngineConfig {
            rules_dir,
            event_bus: EventBusConfig {
                partitions: 4,
                ..Default::default()
            },
            #[cfg(feature = "wasm")]
            wasm_config: Some(WasmConfig::default()),
            ..Default::default()
        };

        let engine = DetectionEngine::new(config).await.unwrap();
        assert_eq!(engine.nfa_engines.len(), 4);
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_partitioned_nfa_load_sequence_all_partitions() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();

        let config = EngineConfig {
            rules_dir,
            event_bus: EventBusConfig {
                partitions: 4,
                ..Default::default()
            },
            #[cfg(feature = "wasm")]
            wasm_config: Some(WasmConfig::default()),
            ..Default::default()
        };

        let engine = DetectionEngine::new(config).await.unwrap();
        engine
            .load_sequence(create_test_sequence("partition-seq"))
            .await
            .unwrap();

        for partition_engine in &engine.nfa_engines {
            let mut guard = partition_engine.lock().await;
            let nfa = guard.as_mut().expect("partition NFA should exist");
            assert!(
                nfa.unload_sequence("partition-seq").unwrap(),
                "sequence should be loaded in every partition"
            );
        }
    }

    #[tokio::test]
    async fn test_eval_event_sequence_match_async_nfa() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();

        let config = EngineConfig {
            rules_dir,
            event_bus: EventBusConfig {
                partitions: 4,
                ..Default::default()
            },
            #[cfg(feature = "wasm")]
            wasm_config: None,
            ..Default::default()
        };

        let engine = DetectionEngine::new(config).await.unwrap();

        for partition_engine in &engine.nfa_engines {
            let mut guard = partition_engine.lock().await;
            *guard = Some(NfaEngine::new(NfaEngineConfig::default(), Arc::new(TestMockEvaluator { result: true })));
        }

        engine
            .load_sequence(create_test_sequence("async-seq"))
            .await
            .unwrap();

        let first_event = Event::builder()
            .event_type(1)
            .ts_mono(1_000)
            .ts_wall(1_000)
            .entity_key(42)
            .build()
            .unwrap();
        let second_event = Event::builder()
            .event_type(2)
            .ts_mono(2_000)
            .ts_wall(2_000)
            .entity_key(42)
            .build()
            .unwrap();

        let first_alerts = engine.eval_event(&first_event).await.unwrap();
        assert!(first_alerts.is_empty());

        let second_alerts = engine.eval_event(&second_event).await.unwrap();
        assert_eq!(second_alerts.len(), 1);
        assert_eq!(second_alerts[0].rule_id, "async-seq");
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_partitioned_nfa_unload_sequence_all_partitions() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();

        let config = EngineConfig {
            rules_dir,
            event_bus: EventBusConfig {
                partitions: 4,
                ..Default::default()
            },
            #[cfg(feature = "wasm")]
            wasm_config: Some(WasmConfig::default()),
            ..Default::default()
        };

        let engine = DetectionEngine::new(config).await.unwrap();
        engine
            .load_sequence(create_test_sequence("unload-seq"))
            .await
            .unwrap();
        engine.unload_sequence("unload-seq").await.unwrap();

        for partition_engine in &engine.nfa_engines {
            let mut guard = partition_engine.lock().await;
            let nfa = guard.as_mut().expect("partition NFA should exist");
            assert!(
                !nfa.unload_sequence("unload-seq").unwrap(),
                "sequence should be removed from every partition"
            );
        }
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_single_event_rule_always_match() {
        let rule = SingleEventRule {
            rule_id: "test-always-match".to_string(),
            rule_name: "Test Always Match".to_string(),
            event_type: 1,
            severity: Severity::Medium,
            description: Some("A test rule that always matches".to_string()),
            predicate: CompiledPredicate::AlwaysMatch,
            blockable: false,
            action_type: None,
        };

        assert_eq!(rule.rule_id, "test-always-match");
        assert_eq!(rule.event_type, 1);
    }

    #[test]
    fn test_determine_action_target_prefers_process_fields() {
        let schema = Arc::new(SchemaRegistry::new());
        register_builtin_linux_schema(schema.as_ref()).unwrap();

        let pid_field = schema.get_field_id("process.pid").unwrap();
        let exec_field = schema.get_field_id("process.executable").unwrap();
        let event = Event::builder()
            .event_type(1)
            .ts_mono(1)
            .ts_wall(1)
            .entity_key(999)
            .field(pid_field, kestrel_schema::TypedValue::U64(4242))
            .field(exec_field, kestrel_schema::TypedValue::String("/usr/bin/bash".to_string()))
            .build()
            .unwrap();

        let target = determine_action_target(&event, schema.as_ref());
        assert_eq!(
            target,
            ActionTarget::ProcessExec {
                pid: 4242,
                executable: "/usr/bin/bash".to_string(),
            }
        );
    }

    #[test]
    fn test_determine_action_target_uses_file_target_for_file_events() {
        let schema = Arc::new(SchemaRegistry::new());
        register_builtin_linux_schema(schema.as_ref()).unwrap();

        let pid_field = schema.get_field_id("process.pid").unwrap();
        let path_field = schema.get_field_id("file.path").unwrap();
        let event = Event::builder()
            .event_type(3)
            .ts_mono(1)
            .ts_wall(1)
            .entity_key(999)
            .field(pid_field, kestrel_schema::TypedValue::U64(4242))
            .field(path_field, kestrel_schema::TypedValue::String("/etc/passwd".to_string()))
            .build()
            .unwrap();

        let target = determine_action_target(&event, schema.as_ref());
        assert_eq!(
            target,
            ActionTarget::FileOp {
                pid: 4242,
                path: "/etc/passwd".to_string(),
            }
        );
    }

    #[test]
    fn test_determine_action_target_uses_network_target_for_network_events() {
        let schema = Arc::new(SchemaRegistry::new());
        register_builtin_linux_schema(schema.as_ref()).unwrap();

        let pid_field = schema.get_field_id("process.pid").unwrap();
        let destination_field = schema.get_field_id("network.destination").unwrap();
        let port_field = schema.get_field_id("network.dest_port").unwrap();
        let event = Event::builder()
            .event_type(6)
            .ts_mono(1)
            .ts_wall(1)
            .entity_key(999)
            .field(pid_field, kestrel_schema::TypedValue::U64(4242))
            .field(
                destination_field,
                kestrel_schema::TypedValue::String("192.168.1.10".to_string()),
            )
            .field(port_field, kestrel_schema::TypedValue::U64(443))
            .build()
            .unwrap();

        let target = determine_action_target(&event, schema.as_ref());
        assert_eq!(
            target,
            ActionTarget::NetworkOp {
                pid: 4242,
                addr: "192.168.1.10:443".to_string(),
            }
        );
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_stats_includes_single_event_rules() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();

        let config = EngineConfig {
            rules_dir,
            ..Default::default()
        };

        let engine = DetectionEngine::new(config).await.unwrap();
        let stats = engine.stats().await;

        assert_eq!(stats.rule_count, 0);
        assert_eq!(stats.single_event_rule_count, 0);
        assert_eq!(stats.alerts_generated, 0);
        assert_eq!(stats.actions_generated, 0);
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_start_processes_published_events() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();

        let config = EngineConfig {
            rules_dir,
            event_bus: EventBusConfig {
                batch_size: 1,
                batch_timeout_ms: 10,
                ..Default::default()
            },
            alert_output: AlertOutputConfig {
                stdout: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let mut engine = DetectionEngine::new(config).await.unwrap();
        {
            let mut rules = engine.single_event_rules.write().await;
            rules.push(SingleEventRule {
                rule_id: "background-rule".to_string(),
                rule_name: "Background Rule".to_string(),
                event_type: 1,
                severity: Severity::Medium,
                description: None,
                predicate: CompiledPredicate::AlwaysMatch,
                blockable: false,
                action_type: None,
            });
        }

        engine.start().await.unwrap();
        engine
            .publish_event(
                Event::builder()
                    .event_type(1)
                    .ts_mono(1000)
                    .ts_wall(1000)
                    .entity_key(42)
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let stats = engine.stats().await;
            if stats.alerts_generated == 1 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for background alert"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_replay_log_processes_events() {
        use kestrel_core::BinaryLog;

        let temp_dir = tempfile::tempdir().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();
        let log_path = temp_dir.path().join("replay.kest");

        let config = EngineConfig {
            rules_dir,
            event_bus: EventBusConfig {
                batch_size: 1,
                batch_timeout_ms: 10,
                ..Default::default()
            },
            alert_output: AlertOutputConfig {
                stdout: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let mut engine = DetectionEngine::new(config).await.unwrap();
        {
            let mut rules = engine.single_event_rules.write().await;
            rules.push(SingleEventRule {
                rule_id: "replay-rule".to_string(),
                rule_name: "Replay Rule".to_string(),
                event_type: 1,
                severity: Severity::Medium,
                description: None,
                predicate: CompiledPredicate::AlwaysMatch,
                blockable: false,
                action_type: None,
            });
        }

        let event = Event::builder()
            .event_type(1)
            .ts_mono(1000)
            .ts_wall(1000)
            .entity_key(42)
            .build()
            .unwrap();
        BinaryLog::new(engine.schema.clone())
            .write_events(log_path.clone(), &[event], "test-hash".to_string())
            .unwrap();

        let stats = engine
            .replay_log(ReplayConfig {
                log_path,
                speed_multiplier: 0.0,
                stop_on_error: true,
                verify_determinism: false,
                verification_runs: 1,
                ..Default::default()
            })
            .await
            .unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let engine_stats = engine.stats().await;
            if engine_stats.alerts_generated == 1 {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting for replay alert");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        assert_eq!(stats.events_processed, 1);
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_single_event_rule_eval_always_match() {
        use kestrel_event::Event;

        let temp_dir = tempfile::tempdir().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();

        #[cfg(feature = "wasm")]
        let config = EngineConfig {
            rules_dir,
            wasm_config: Some(kestrel_runtime_wasm::WasmConfig::default()),
            ..Default::default()
        };

        #[cfg(not(feature = "wasm"))]
        let config = EngineConfig {
            rules_dir,
            ..Default::default()
        };

        let engine = DetectionEngine::new(config).await.unwrap();

        let rule = SingleEventRule {
            rule_id: "test-always-match-rule".to_string(),
            rule_name: "Test Always Match Rule".to_string(),
            event_type: 1,
            severity: Severity::Medium,
            description: Some("A test rule that always matches".to_string()),
            predicate: CompiledPredicate::AlwaysMatch,
            blockable: false,
            action_type: None,
        };

        {
            let mut rules = engine.single_event_rules.write().await;
            rules.push(rule);
        }

        let event = Event::builder()
            .event_type(1)
            .ts_mono(1234567890)
            .ts_wall(1234567890)
            .entity_key(42)
            .build()
            .unwrap();

        let alerts = engine.eval_event(&event).await.unwrap();

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "test-always-match-rule");
        assert_eq!(alerts[0].severity, Severity::Medium);
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_single_event_rule_no_match_different_event_type() {
        use kestrel_event::Event;

        let temp_dir = tempfile::tempdir().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();

        #[cfg(feature = "wasm")]
        let config = EngineConfig {
            rules_dir,
            wasm_config: Some(kestrel_runtime_wasm::WasmConfig::default()),
            ..Default::default()
        };

        #[cfg(not(feature = "wasm"))]
        let config = EngineConfig {
            rules_dir,
            ..Default::default()
        };

        let engine = DetectionEngine::new(config).await.unwrap();

        let rule = SingleEventRule {
            rule_id: "test-type-match-rule".to_string(),
            rule_name: "Test Type Match Rule".to_string(),
            event_type: 99,
            severity: Severity::High,
            description: Some("A test rule for event type 99".to_string()),
            predicate: CompiledPredicate::AlwaysMatch,
            blockable: false,
            action_type: None,
        };

        {
            let mut rules = engine.single_event_rules.write().await;
            rules.push(rule);
        }

        let event = Event::builder()
            .event_type(1)
            .ts_mono(1234567890)
            .ts_wall(1234567890)
            .entity_key(42)
            .build()
            .unwrap();

        let alerts = engine.eval_event(&event).await.unwrap();

        assert_eq!(alerts.len(), 0);
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_eval_event_multiple_single_event_rules() {
        use kestrel_event::Event;

        let temp_dir = tempfile::tempdir().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();

        #[cfg(feature = "wasm")]
        let config = EngineConfig {
            rules_dir,
            wasm_config: Some(kestrel_runtime_wasm::WasmConfig::default()),
            ..Default::default()
        };

        #[cfg(not(feature = "wasm"))]
        let config = EngineConfig {
            rules_dir,
            ..Default::default()
        };

        let engine = DetectionEngine::new(config).await.unwrap();

        let rule1 = SingleEventRule {
            rule_id: "test-rule-1".to_string(),
            rule_name: "Test Rule 1".to_string(),
            event_type: 1,
            severity: Severity::Low,
            description: Some("First test rule".to_string()),
            predicate: CompiledPredicate::AlwaysMatch,
            blockable: false,
            action_type: None,
        };

        let rule2 = SingleEventRule {
            rule_id: "test-rule-2".to_string(),
            rule_name: "Test Rule 2".to_string(),
            event_type: 1,
            severity: Severity::High,
            description: Some("Second test rule".to_string()),
            predicate: CompiledPredicate::AlwaysMatch,
            blockable: false,
            action_type: None,
        };

        let rule3 = SingleEventRule {
            rule_id: "test-rule-3".to_string(),
            rule_name: "Test Rule 3".to_string(),
            event_type: 2,
            severity: Severity::Critical,
            description: Some("Third test rule (different event type)".to_string()),
            predicate: CompiledPredicate::AlwaysMatch,
            blockable: false,
            action_type: None,
        };

        {
            let mut rules = engine.single_event_rules.write().await;
            rules.push(rule1);
            rules.push(rule2);
            rules.push(rule3);
        }

        let event = Event::builder()
            .event_type(1)
            .ts_mono(1234567890)
            .ts_wall(1234567890)
            .entity_key(42)
            .build()
            .unwrap();

        let alerts = engine.eval_event(&event).await.unwrap();

        assert_eq!(alerts.len(), 2);
        let rule_ids: Vec<&str> = alerts.iter().map(|a| a.rule_id.as_str()).collect();
        assert!(rule_ids.contains(&"test-rule-1"));
        assert!(rule_ids.contains(&"test-rule-2"));
        assert!(!rule_ids.contains(&"test-rule-3"));
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_inline_mode_with_blockable_rule() {
        use kestrel_core::{ActionType, NoOpExecutor};
        use kestrel_event::Event;

        let temp_dir = tempfile::tempdir().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();

        #[cfg(feature = "wasm")]
        let config = EngineConfig {
            rules_dir,
            wasm_config: Some(kestrel_runtime_wasm::WasmConfig::default()),
            mode: EngineMode::Inline,
            action_executor: Some(Arc::new(NoOpExecutor) as Arc<dyn ActionExecutor>),
            ..Default::default()
        };

        #[cfg(not(feature = "wasm"))]
        let config = EngineConfig {
            rules_dir,
            mode: EngineMode::Inline,
            action_executor: Some(Arc::new(NoOpExecutor::default()) as Arc<dyn ActionExecutor>),
            ..Default::default()
        };

        let engine = DetectionEngine::new(config).await.unwrap();

        // Create a blockable rule with Block action
        let rule = SingleEventRule {
            rule_id: "test-blockable-rule".to_string(),
            rule_name: "Test Blockable Rule".to_string(),
            event_type: 1,
            severity: Severity::High,
            description: Some("A test rule that should trigger enforcement".to_string()),
            predicate: CompiledPredicate::AlwaysMatch,
            blockable: true,
            action_type: Some(ActionType::Block),
        };

        {
            let mut rules = engine.single_event_rules.write().await;
            rules.push(rule);
        }

        let event = Event::builder()
            .event_type(1)
            .ts_mono(1234567890)
            .ts_wall(1234567890)
            .entity_key(42)
            .build()
            .unwrap();

        // Process event
        let alerts = engine.eval_event(&event).await.unwrap();

        // Verify alert was generated
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "test-blockable-rule");

        // Verify action was executed in Inline mode
        let stats = engine.stats().await;
        assert_eq!(stats.actions_generated, 1);
        assert_eq!(stats.alerts_generated, 1);
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_detect_mode_no_enforcement() {
        use kestrel_core::{ActionType, NoOpExecutor};
        use kestrel_event::Event;

        let temp_dir = tempfile::tempdir().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();

        #[cfg(feature = "wasm")]
        let config = EngineConfig {
            rules_dir,
            wasm_config: Some(kestrel_runtime_wasm::WasmConfig::default()),
            mode: EngineMode::Detect, // Detect mode (default)
            action_executor: Some(Arc::new(NoOpExecutor) as Arc<dyn ActionExecutor>),
            ..Default::default()
        };

        #[cfg(not(feature = "wasm"))]
        let config = EngineConfig {
            rules_dir,
            mode: EngineMode::Detect, // Detect mode (default)
            action_executor: Some(Arc::new(NoOpExecutor::default()) as Arc<dyn ActionExecutor>),
            ..Default::default()
        };

        let engine = DetectionEngine::new(config).await.unwrap();

        // Create a blockable rule with Block action
        let rule = SingleEventRule {
            rule_id: "test-no-enforce-rule".to_string(),
            rule_name: "Test No Enforcement Rule".to_string(),
            event_type: 1,
            severity: Severity::High,
            description: Some("A blockable rule in Detect mode".to_string()),
            predicate: CompiledPredicate::AlwaysMatch,
            blockable: true,
            action_type: Some(ActionType::Block),
        };

        {
            let mut rules = engine.single_event_rules.write().await;
            rules.push(rule);
        }

        let event = Event::builder()
            .event_type(1)
            .ts_mono(1234567890)
            .ts_wall(1234567890)
            .entity_key(42)
            .build()
            .unwrap();

        // Process event
        let alerts = engine.eval_event(&event).await.unwrap();

        // Verify alert was generated
        assert_eq!(alerts.len(), 1);

        // Verify NO action was executed in Detect mode (alert-only)
        let stats = engine.stats().await;
        assert_eq!(stats.actions_generated, 0); // No actions in Detect mode
        assert_eq!(stats.alerts_generated, 1);
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_non_blockable_rule_no_enforcement() {
        use kestrel_core::{ActionType, NoOpExecutor};
        use kestrel_event::Event;

        let temp_dir = tempfile::tempdir().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();

        #[cfg(feature = "wasm")]
        let config = EngineConfig {
            rules_dir,
            wasm_config: Some(kestrel_runtime_wasm::WasmConfig::default()),
            mode: EngineMode::Inline, // Inline mode
            action_executor: Some(Arc::new(NoOpExecutor) as Arc<dyn ActionExecutor>),
            ..Default::default()
        };

        #[cfg(not(feature = "wasm"))]
        let config = EngineConfig {
            rules_dir,
            mode: EngineMode::Inline, // Inline mode
            action_executor: Some(Arc::new(NoOpExecutor::default()) as Arc<dyn ActionExecutor>),
            ..Default::default()
        };

        let engine = DetectionEngine::new(config).await.unwrap();

        // Create a non-blockable rule (blockable=false)
        let rule = SingleEventRule {
            rule_id: "test-non-blockable".to_string(),
            rule_name: "Test Non-Blockable Rule".to_string(),
            event_type: 1,
            severity: Severity::Medium,
            description: Some("A non-blockable rule".to_string()),
            predicate: CompiledPredicate::AlwaysMatch,
            blockable: false,                     // Not blockable
            action_type: Some(ActionType::Block), // Has action but not blockable
        };

        {
            let mut rules = engine.single_event_rules.write().await;
            rules.push(rule);
        }

        let event = Event::builder()
            .event_type(1)
            .ts_mono(1234567890)
            .ts_wall(1234567890)
            .entity_key(42)
            .build()
            .unwrap();

        // Process event
        let alerts = engine.eval_event(&event).await.unwrap();

        // Verify alert was generated
        assert_eq!(alerts.len(), 1);

        // Verify NO action was executed (rule not blockable)
        let stats = engine.stats().await;
        assert_eq!(stats.actions_generated, 0);
        assert_eq!(stats.alerts_generated, 1);
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_action_type_kill() {
        use kestrel_core::{ActionType, NoOpExecutor};
        use kestrel_event::Event;

        let temp_dir = tempfile::tempdir().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();

        #[cfg(feature = "wasm")]
        let config = EngineConfig {
            rules_dir,
            wasm_config: Some(kestrel_runtime_wasm::WasmConfig::default()),
            mode: EngineMode::Inline,
            action_executor: Some(Arc::new(NoOpExecutor) as Arc<dyn ActionExecutor>),
            ..Default::default()
        };

        #[cfg(not(feature = "wasm"))]
        let config = EngineConfig {
            rules_dir,
            mode: EngineMode::Inline,
            action_executor: Some(Arc::new(NoOpExecutor::default()) as Arc<dyn ActionExecutor>),
            ..Default::default()
        };

        let engine = DetectionEngine::new(config).await.unwrap();

        // Create a blockable rule with Kill action
        let rule = SingleEventRule {
            rule_id: "test-kill-rule".to_string(),
            rule_name: "Test Kill Rule".to_string(),
            event_type: 1,
            severity: Severity::Critical,
            description: Some("A kill rule for critical threats".to_string()),
            predicate: CompiledPredicate::AlwaysMatch,
            blockable: true,
            action_type: Some(ActionType::Kill),
        };

        {
            let mut rules = engine.single_event_rules.write().await;
            rules.push(rule);
        }

        let event = Event::builder()
            .event_type(1)
            .ts_mono(1234567890)
            .ts_wall(1234567890)
            .entity_key(42)
            .build()
            .unwrap();

        // Process event
        let alerts = engine.eval_event(&event).await.unwrap();

        // Verify alert was generated
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::Critical);

        // Verify Kill action was executed
        let stats = engine.stats().await;
        assert_eq!(stats.actions_generated, 1);
    }
}
