//! Kestrel Detection Engine
//!
//! This is the core detection engine that coordinates event processing,
// //! rule evaluation, alert generation, and enforcement actions.

use futures::stream::{FuturesUnordered, StreamExt};
use kestrel_core::eventbus::{DefaultPartitioner, Partitioner, PublishError};
use kestrel_core::{
    ActionDecision, ActionExecutor, ActionPolicy, ActionTarget, ActionType, Alert, AlertHandle,
    AlertOutput, AlertOutputConfig, AlertSink, EventBus, EventBusConfig, EventBusHandle,
    NoOpExecutor, ReplayConfig, ReplaySource, ReplayStats, Severity, TimeManager,
};
use kestrel_event::Event;
use kestrel_nfa::{CompiledSequence, NfaEngine, NfaEngineConfig, PredicateEvaluator};
use kestrel_observability::{NoopTraceCollector, TraceCollector};
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
use tokio::sync::{Mutex, Semaphore, mpsc};
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

// Performance optimization crates
use arc_swap::ArcSwap;

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

pub mod processor;
pub use processor::{
    CompositeProcessor, EventProcessor, NfaEventProcessor, ProcessResult, ProcessingContext,
    ProcessorError, SingleEventProcessor, alert_from_sequence_match, alert_from_single_event,
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

    /// Alert output configuration (legacy, used when `alert_sink` is `None`)
    pub alert_output: AlertOutputConfig,

    /// Optional pluggable alert sink. When provided, takes precedence over `alert_output`.
    pub alert_sink: Option<Arc<dyn AlertSink>>,

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

    /// Optional trace collector for rule evaluation tracing
    pub trace_collector: Option<Arc<dyn TraceCollector>>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            event_bus: EventBusConfig::default(),
            alert_output: AlertOutputConfig::default(),
            alert_sink: None,
            rules_dir: std::path::PathBuf::from("./rules"),
            mode: EngineMode::Detect,
            action_executor: None,
            #[cfg(feature = "wasm")]
            wasm_config: None,
            nfa_config: Some(NfaEngineConfig::default()),
            trace_collector: None,
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
    trace_collector: &'a Arc<dyn TraceCollector>,
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

/// Output of compiling a single rule
#[derive(Debug, Clone)]
pub enum CompileOutput {
    SingleEvent(SingleEventRule),
    Sequence(CompiledSequence),
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
        .map(|field_id| event.get_field_as_u32(field_id, (event.entity_key & 0xFFFF_FFFF) as u32))
        .unwrap_or((event.entity_key & 0xFFFF_FFFF) as u32);

    let executable = schema
        .get_field_id("process.executable")
        .map(|field_id| event.get_field_as_string(field_id, ""))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let file_path = schema
        .get_field_id("file.path")
        .map(|field_id| event.get_field_as_string(field_id, ""))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let network_destination = schema
        .get_field_id("network.destination")
        .map(|field_id| event.get_field_as_string(field_id, ""))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
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
    _alert_output: Option<AlertOutput>,
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
    eql_compiler: tokio::sync::Mutex<Option<EqlCompiler>>,

    partition_count: usize,
    partitioner: Arc<dyn Partitioner>,

    /// NFA engines for sequence detection, one per event-bus partition
    nfa_engines: Vec<Arc<Mutex<Option<NfaEngine>>>>,

    /// Compiled single-event rules
    /// Using ArcSwap for lock-free reads (rules change rarely, read on every event)
    single_event_rules: Arc<ArcSwap<Vec<SingleEventRule>>>,

    /// Alert counter (atomic for thread safety)
    alerts_generated: Arc<std::sync::atomic::AtomicU64>,

    /// Action counter (atomic for thread safety)
    actions_generated: Arc<std::sync::atomic::AtomicU64>,

    /// Error counter for tracking engine errors (atomic for thread safety)
    errors_count: Arc<std::sync::atomic::AtomicU64>,

    /// Trace collector for rule evaluation tracing
    trace_collector: Arc<dyn TraceCollector>,
}

impl DetectionEngine {
    /// Create a new detection engine
    pub async fn new(config: EngineConfig) -> Result<Self, EngineError> {
        info!("Initializing Kestrel detection engine");

        // Initialize schema registry
        let schema = Arc::new(SchemaRegistry::new());
        register_builtin_linux_schema(schema.as_ref())?;
        info!("Schema registry initialized");

        let (event_sink_tx, event_sink_rx) = mpsc::channel(config.event_bus.channel_size.max(1));
        let event_bus = EventBus::new_with_sink(config.event_bus.clone(), event_sink_tx);
        info!("Event bus initialized with engine sink");

        let (alert_handle, alert_output) = if let Some(sink) = config.alert_sink {
            info!("Alert sink initialized (pluggable)");
            (AlertHandle::from_sink(sink), None)
        } else {
            let alert_output = AlertOutput::new(config.alert_output);
            let handle = alert_output.handle();
            info!("Alert output initialized (legacy)");
            (handle, Some(alert_output))
        };

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
        let eql_compiler = tokio::sync::Mutex::new(if config.wasm_config.is_some() {
            Some(EqlCompiler::new(schema.clone()))
        } else {
            None
        });

        // Initialize Wasm engine if configured
        #[cfg(feature = "wasm")]
        let wasm_engine = if let Some(wasm_config) = config.wasm_config {
            let engine = WasmEngine::new(wasm_config, schema.clone())?;
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

        let single_event_rules = Arc::new(ArcSwap::new(Arc::new(Vec::new())));

        // Initialize trace collector
        let trace_collector: Arc<dyn TraceCollector> = config
            .trace_collector
            .unwrap_or_else(|| Arc::new(NoopTraceCollector::new()));

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
            trace_collector,
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
        self.event_bus.handle().publish(event).await?;
        Ok(())
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

    async fn ensure_event_types_registered(&self, eql: &str) -> Result<(), EngineError> {
        #[cfg(feature = "wasm")]
        {
            let compiler_guard = self.eql_compiler.lock().await;

            let compiler = compiler_guard
                .as_ref()
                .ok_or_else(|| EngineError::Generic("EQL compiler not initialized".to_string()))?;

            let query = compiler
                .parse(eql)
                .map_err(|e| EngineError::Generic(format!("EQL parse error: {}", e)))?;

            register_builtin_linux_schema(self.schema.as_ref())?;

            for event_type in query.event_types() {
                if self.schema.get_event_type_id(&event_type).is_none() {
                    self.schema.register_event_type(EventTypeDef {
                        name: event_type.clone(),
                        description: Some(format!("Auto-registered from rule {}", event_type)),
                        parent: None,
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

    /// Compile a single rule without mutating shared engine state.
    #[cfg(feature = "wasm")]
    pub async fn compile_single_event_rule(
        &self,
        rule: &Rule,
    ) -> Result<Option<CompileOutput>, EngineError> {
        let definition = match &rule.definition {
            RuleDefinition::Eql(eql) => eql.clone(),
            RuleDefinition::Wasm(_) => {
                warn!(rule_id = %rule.metadata.id, "Skipping precompiled Wasm rule in engine compiler");
                return Ok(None);
            },
            RuleDefinition::Lua(_) => {
                warn!(rule_id = %rule.metadata.id, "Skipping Lua rule in current engine compiler path");
                return Ok(None);
            },
        };

        self.ensure_event_types_registered(&definition).await?;

        let wasm_engine = self
            .wasm_engine
            .as_ref()
            .ok_or_else(|| EngineError::Generic("Wasm engine not initialized".to_string()))?;

        let ir = {
            let mut compiler_guard = self.eql_compiler.lock().await;
            let compiler = compiler_guard
                .as_mut()
                .ok_or_else(|| EngineError::Generic("EQL compiler not initialized".to_string()))?;

            compiler
                .compile_to_ir(&definition)
                .map_err(|e| EngineError::Generic(format!("EQL compilation error: {}", e)))?
        };
        let predicate_indices = Self::predicate_indices(&ir);

        // Build predicate_fields map from IR
        let mut predicate_fields = ahash::AHashMap::new();
        for (pred_id, pred) in &ir.predicates {
            if let Some(&idx) = predicate_indices.get(pred_id) {
                predicate_fields.insert(idx, pred.required_fields.clone());
            }
        }

        let mut wasm_generator = WasmCodeGenerator::new();
        let wat = wasm_generator
            .generate(&ir)
            .map_err(|e| EngineError::Generic(format!("Wasm codegen error: {}", e)))?;
        let wasm_bytes = wat::parse_str(&wat)
            .map_err(|e| EngineError::Generic(format!("WAT parsing error: {}", e)))?;

        wasm_engine
            .load_module(Self::schema_manifest_for_rule(rule), wasm_bytes.clone(), predicate_fields)
            .await?;

        match &ir.rule_type {
            IrRuleType::Event { event_type } => {
                let event_type_id = self.schema.get_event_type_id(event_type).ok_or_else(|| {
                    EngineError::Generic(format!(
                        "Event type '{}' not registered in schema",
                        event_type
                    ))
                })?;

                let predicate = ir
                    .predicates
                    .get("main")
                    .ok_or_else(|| EngineError::Generic("No main predicate found".to_string()))?;

                let predicate_index = *predicate_indices.get("main").ok_or_else(|| {
                    EngineError::Generic("Main predicate index not found".to_string())
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

                info!(rule_id = %rule.metadata.id, "Compiled single-event rule");
                Ok(Some(CompileOutput::SingleEvent(single_rule)))
            },
            IrRuleType::Sequence { .. } => {
                let compiled_sequence =
                    self.compile_sequence_rule(rule, &ir, &predicate_indices)?;
                info!(rule_id = %rule.metadata.id, "Compiled sequence rule");
                Ok(Some(CompileOutput::Sequence(compiled_sequence)))
            },
        }
    }

    #[cfg(not(feature = "wasm"))]
    pub async fn compile_single_event_rule(
        &self,
        _rule: &Rule,
    ) -> Result<Option<CompileOutput>, EngineError> {
        Ok(None)
    }

    #[cfg(feature = "wasm")]
    fn compile_sequence_rule(
        &self,
        rule: &Rule,
        ir: &IrRule,
        predicate_indices: &HashMap<String, u32>,
    ) -> Result<CompiledSequence, EngineError> {
        let sequence = ir.sequence.as_ref().ok_or_else(|| {
            EngineError::Generic(format!("Missing sequence metadata for rule {}", rule.metadata.id))
        })?;

        let steps = sequence
            .steps
            .iter()
            .map(|step| {
                let event_type_id = self
                    .schema
                    .get_event_type_id(&step.event_type_name)
                    .ok_or_else(|| {
                        EngineError::Generic(format!(
                            "Event type '{}' is not registered for rule {}",
                            step.event_type_name, rule.metadata.id
                        ))
                    })?;
                let predicate_index =
                    predicate_indices.get(&step.predicate_id).ok_or_else(|| {
                        EngineError::Generic(format!(
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
                    EngineError::Generic(format!(
                        "Until predicate '{}' not found for rule {}",
                        predicate_id, rule.metadata.id
                    ))
                })?;
                let predicate_index = predicate_indices.get(predicate_id).ok_or_else(|| {
                    EngineError::Generic(format!(
                        "Until predicate '{}' missing index for rule {}",
                        predicate_id, rule.metadata.id
                    ))
                })?;
                let event_type_id = self
                    .schema
                    .get_event_type_id(&predicate.event_type)
                    .ok_or_else(|| {
                        EngineError::Generic(format!(
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

        self.single_event_rules.store(Arc::new(Vec::new()));

        let rule_ids = self.rule_manager.list_rules().await;

        // Compile rules concurrently with limited parallelism
        let compiled: Vec<_> = futures::stream::iter(rule_ids)
            .map(|rule_id| async move {
                match self.rule_manager.get_rule(&rule_id).await {
                    Some(rule) => match self.compile_single_event_rule(&rule).await {
                        Ok(output) => output,
                        Err(error) => {
                            error!(rule_id = %rule.metadata.id, %error, "Failed to compile rule");
                            self.errors_count.fetch_add(1, Ordering::Relaxed);
                            None
                        },
                    },
                    None => {
                        error!(%rule_id, "Rule not found");
                        self.errors_count.fetch_add(1, Ordering::Relaxed);
                        None
                    },
                }
            })
            .buffer_unordered(8)
            .collect()
            .await;

        // Apply compiled results sequentially to avoid races
        let mut single_rules = Vec::new();
        for output in compiled {
            match output {
                Some(CompileOutput::SingleEvent(rule)) => {
                    single_rules.push(rule);
                },
                Some(CompileOutput::Sequence(seq)) => {
                    if let Err(e) = self.load_sequence(seq).await {
                        error!(error = %e, "Failed to load sequence");
                        self.errors_count.fetch_add(1, Ordering::Relaxed);
                    }
                },
                None => {},
            }
        }

        self.single_event_rules.store(Arc::new(single_rules));

        let count = self.single_event_rules.load().len();
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
        let single_event_rule_count = self.single_event_rules.load().len();

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
            EngineError::Generic("Event batch receiver not available".to_string())
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
                let trace_collector = self.trace_collector.clone();
                #[cfg(feature = "wasm")]
                let wasm_engine = self.wasm_engine.clone();

                tokio::spawn(async move {
                    info!("Event processing loop started");
                    while let Some(batch) = receiver.recv().await {
                        if batch.is_empty() {
                            continue;
                        }

                        let partition_id = partitioner.partition(&batch[0], partition_count);
                        let rules_guard = single_event_rules.load();
                        let eval_context = EvalContext {
                            nfa_engine: &nfa_engines[partition_id],
                            single_event_rules: &*rules_guard,
                            #[cfg(feature = "wasm")]
                            wasm_engine: wasm_engine.as_ref(),
                            mode,
                            action_executor: &action_executor,
                            schema: schema.as_ref(),
                            alerts_generated: alerts_generated.as_ref(),
                            actions_generated: actions_generated.as_ref(),
                            errors_count: errors_count.as_ref(),
                            trace_collector: &trace_collector,
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
        let rules_guard = self.single_event_rules.load();
        let partition_id = self.partition_for_event(event);
        let context = EvalContext {
            nfa_engine: &self.nfa_engines[partition_id],
            single_event_rules: &*rules_guard,
            #[cfg(feature = "wasm")]
            wasm_engine: self.wasm_engine.as_ref(),
            mode: self.mode,
            action_executor: &self.action_executor,
            schema: self.schema.as_ref(),
            alerts_generated: self.alerts_generated.as_ref(),
            actions_generated: self.actions_generated.as_ref(),
            errors_count: self.errors_count.as_ref(),
            trace_collector: &self.trace_collector,
        };

        DetectionEngine::eval_event_with_rules(event, &context).await
    }

    async fn eval_event_with_rules(
        event: &Event,
        context: &EvalContext<'_>,
    ) -> Result<Vec<Alert>, EngineError> {
        use kestrel_observability::TraceStep;
        use std::time::Instant;

        debug!(
            event_type_id = event.event_type_id,
            entity_key = event.entity_key,
            "Evaluating event"
        );

        let mut alerts = Vec::new();
        let event_arc = Arc::new(event.clone());
        let eval_start = Instant::now();

        // Start NFA trace
        let nfa_trace_id = context.trace_collector.start_trace("nfa", event);
        let mut nfa_steps = Vec::new();

        {
            let mut guard = context.nfa_engine.lock().await;
            if let Some(nfa_engine) = guard.as_mut() {
                match nfa_engine.process_event(&*event_arc).await {
                    Ok(sequence_alerts) => {
                        for seq_alert in sequence_alerts {
                            alerts.push(alert_from_sequence_match(&seq_alert));
                            context
                                .alerts_generated
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            if nfa_trace_id != 0 {
                                nfa_steps.push(TraceStep::SequenceComplete {
                                    sequence_id: seq_alert.rule_id.clone(),
                                    matched_events: seq_alert.events.iter().map(|e| e.event_id).collect(),
                                });
                            }
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

        // Record NFA trace if tracing is active
        if nfa_trace_id != 0 {
            let trace = kestrel_observability::RuleTrace {
                trace_id: nfa_trace_id,
                rule_id: "nfa".to_string(),
                event_id: event.event_id,
                timestamp_ns: event.ts_mono_ns,
                duration: eval_start.elapsed(),
                matched: !alerts.is_empty(),
                steps: nfa_steps,
                error: None,
            };
            context.trace_collector.record_trace(trace);
        }

        #[cfg(feature = "wasm")]
        {
            let wasm_engine = context.wasm_engine.cloned();
            let semaphore = Arc::new(Semaphore::new(16));
            let mut evaluations = FuturesUnordered::new();

            for single_rule in context.single_event_rules.iter() {
                if single_rule.event_type != event.event_type_id {
                    continue;
                }

                let permit = semaphore
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|e| EngineError::Generic(format!("semaphore error: {e}")))?;
                let rule = single_rule.clone();
                let wasm_engine = wasm_engine.clone();
                evaluations.push(async move {
                    let _permit = permit;
                    let matched = match &rule.predicate {
                        CompiledPredicate::Wasm {
                            module_id,
                            predicate_index,
                            ..
                        } => {
                            let wasm_engine = wasm_engine.ok_or_else(|| {
                                EngineError::Generic(
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
                        #[cfg(feature = "lua")]
                        CompiledPredicate::Lua { .. } => false,
                    };

                    Ok::<(SingleEventRule, bool), EngineError>((rule, matched))
                });
            }

            while let Some(result) = evaluations.next().await {
                let (single_rule, matched) = result?;

                // Record trace for this rule evaluation
                if context.trace_collector.is_rule_traced(&single_rule.rule_id) {
                    let trace_id = context.trace_collector.start_trace(&single_rule.rule_id, event);
                    if trace_id != 0 {
                        let pred_explanation = if matched {
                            format!("Predicate matched for event type {}", event.event_type_id)
                        } else {
                            format!("Predicate did not match for event type {}", event.event_type_id)
                        };

                        let trace = kestrel_observability::RuleTrace {
                            trace_id,
                            rule_id: single_rule.rule_id.clone(),
                            event_id: event.event_id,
                            timestamp_ns: event.ts_mono_ns,
                            duration: Instant::now().duration_since(eval_start),
                            matched,
                            steps: vec![kestrel_observability::TraceStep::Predicate {
                                predicate_id: format!("{}", single_rule.event_type),
                                result: matched,
                                explanation: pred_explanation,
                                field_values: Vec::new(),
                            }],
                            error: None,
                        };
                        context.trace_collector.record_trace(trace);
                    }
                }

                if !matched {
                    continue;
                }

                alerts.push(alert_from_single_event(
                    &single_rule.rule_id,
                    &single_rule.rule_name,
                    event,
                    single_rule.severity,
                ));
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
        Ok(wasm_engine
            .eval_loaded_predicate(module_id, predicate_index, event)
            .await?)
    }

    async fn with_nfa_engines<F>(&self, mut f: F) -> Result<(), EngineError>
    where
        F: FnMut(usize, &mut NfaEngine) -> Result<(), kestrel_nfa::NfaError>,
    {
        for (partition_id, nfa_engine) in self.nfa_engines.iter().enumerate() {
            let mut guard = nfa_engine.lock().await;
            if let Some(engine) = guard.as_mut() {
                f(partition_id, engine)?;
            }
        }
        Ok(())
    }

    /// Load a compiled sequence into the NFA engine
    pub async fn load_sequence(&self, sequence: CompiledSequence) -> Result<(), EngineError> {
        self.with_nfa_engines(|_partition_id, engine| engine.load_sequence(sequence.clone()))
            .await
    }

    /// Unload a compiled sequence from every partitioned NFA engine.
    pub async fn unload_sequence(&self, sequence_id: &str) -> Result<(), EngineError> {
        self.with_nfa_engines(|_partition_id, engine| {
            engine.unload_sequence(sequence_id).map(|_| ())
        })
        .await
    }

    fn partition_for_event(&self, event: &Event) -> usize {
        self.partitioner.partition(event, self.partition_count)
    }

    #[cfg(test)]
    pub fn push_test_rule(&self, rule: SingleEventRule) {
        let mut rules = (**self.single_event_rules.load()).clone();
        rules.push(rule);
        self.single_event_rules.store(Arc::new(rules));
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
    #[error("Event bus error")]
    EventBusError(#[from] PublishError),

    #[cfg(feature = "wasm")]
    #[error("Wasm runtime error")]
    WasmRuntimeError(#[from] kestrel_runtime_wasm::WasmRuntimeError),

    #[cfg(feature = "lua")]
    #[error("Lua runtime error")]
    LuaRuntimeError(#[from] kestrel_runtime_lua::LuaRuntimeError),

    #[error("NFA error")]
    NfaError(#[from] kestrel_nfa::NfaError),

    #[error("Rule manager error")]
    RuleManagerError(#[from] kestrel_rules::RuleManagerError),

    #[error("Schema error")]
    SchemaError(#[from] kestrel_schema::SchemaError),

    #[error("Platform error")]
    PlatformError(#[from] kestrel_core::PlatformError),

    #[error("Replay error")]
    ReplayError(#[from] kestrel_core::ReplayError),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("IO error")]
    IoError(#[from] std::io::Error),

    #[error("Generic error: {0}")]
    Generic(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_event::Event;
    use kestrel_event::test_helpers::test_event;
    use kestrel_nfa::{CompiledSequence, NfaSequence, SeqStep};

    struct TestMockEvaluator {
        result: bool,
    }

    #[async_trait::async_trait]
    impl PredicateEvaluator for TestMockEvaluator {
        async fn evaluate(
            &self,
            _predicate_id: &str,
            _event: &Event,
        ) -> kestrel_event::PredicateResult<bool> {
            Ok(self.result)
        }

        fn get_required_fields(
            &self,
            _predicate_id: &str,
        ) -> kestrel_event::PredicateResult<Vec<u32>> {
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
            *guard = Some(NfaEngine::new(
                NfaEngineConfig::default(),
                Arc::new(TestMockEvaluator { result: true }),
            ));
        }

        engine
            .load_sequence(create_test_sequence("async-seq"))
            .await
            .unwrap();

        let first_event = test_event(1, 42, 1_000);
        let second_event = test_event(2, 42, 2_000);

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
            .field(exec_field, kestrel_schema::TypedValue::String("/usr/bin/bash".into()))
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
            .field(path_field, kestrel_schema::TypedValue::String("/etc/passwd".into()))
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
            .field(destination_field, kestrel_schema::TypedValue::String("192.168.1.10".into()))
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
        engine.push_test_rule(SingleEventRule {
            rule_id: "background-rule".to_string(),
            rule_name: "Background Rule".to_string(),
            event_type: 1,
            severity: Severity::Medium,
            description: None,
            predicate: CompiledPredicate::AlwaysMatch,
            blockable: false,
            action_type: None,
        });

        engine.start().await.unwrap();
        engine.publish_event(test_event(1, 42, 1000)).await.unwrap();

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
        engine.push_test_rule(SingleEventRule {
            rule_id: "replay-rule".to_string(),
            rule_name: "Replay Rule".to_string(),
            event_type: 1,
            severity: Severity::Medium,
            description: None,
            predicate: CompiledPredicate::AlwaysMatch,
            blockable: false,
            action_type: None,
        });

        let event = test_event(1, 42, 1000);

        engine.start().await.unwrap();
        engine.publish_event(event).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let engine_stats = engine.stats().await;
            if engine_stats.alerts_generated == 1 {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting for replay alert");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_single_event_rule_eval_always_match() {
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

        engine.push_test_rule(rule);

        let event = test_event(1, 42, 1234567890);

        let alerts = engine.eval_event(&event).await.unwrap();

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "test-always-match-rule");
        assert_eq!(alerts[0].severity, Severity::Medium);
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_single_event_rule_no_match_different_event_type() {
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

        engine.push_test_rule(rule);

        let event = test_event(1, 42, 1234567890);

        let alerts = engine.eval_event(&event).await.unwrap();

        assert_eq!(alerts.len(), 0);
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_eval_event_multiple_single_event_rules() {
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

        engine.push_test_rule(rule1);
        engine.push_test_rule(rule2);
        engine.push_test_rule(rule3);

        let event = test_event(1, 42, 1234567890);

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

        engine.push_test_rule(rule);

        let event = test_event(1, 42, 1234567890);

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

        engine.push_test_rule(rule);

        let event = test_event(1, 42, 1234567890);

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

        engine.push_test_rule(rule);

        let event = test_event(1, 42, 1234567890);

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

        engine.push_test_rule(rule);

        let event = test_event(1, 42, 1234567890);

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
