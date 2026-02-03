//! Kestrel Detection Engine
//!
//! This is the core detection engine that coordinates event processing,
// //! rule evaluation, alert generation, and enforcement actions.

use kestrel_core::{
    ActionDecision, ActionExecutor, ActionPolicy, ActionTarget,
    ActionType, Alert, AlertOutput, AlertOutputConfig, EventBus, EventBusConfig, EventEvidence,
    NoOpExecutor, Severity,
};
use kestrel_event::Event;
use kestrel_nfa::{CompiledSequence, NfaEngine, NfaEngineConfig, PredicateEvaluator};
use kestrel_rules::{Rule, RuleDefinition, RuleManager, Severity as RuleSeverity};
use kestrel_schema::SchemaRegistry;
use std::sync::Arc;
use thiserror::Error;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

#[cfg(feature = "wasm")]
use kestrel_eql::{EqlCompiler, IrRuleType};
#[cfg(feature = "wasm")]
use kestrel_runtime_wasm::{WasmConfig, WasmEngine};

// Runtime abstraction layer
pub mod runtime;
pub use runtime::{
    EvalResult, Runtime, RuntimeCapabilities, RuntimeError, RuntimeManager, RuntimeResult,
    RuntimeType,
};

#[cfg(feature = "wasm")]
pub use runtime::WasmRuntimeAdapter;
#[cfg(feature = "lua")]
pub use runtime::LuaRuntimeAdapter;

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

#[derive(Debug, Clone)]
pub enum CompiledPredicate {
    #[cfg(feature = "wasm")]
    Wasm {
        wasm_bytes: Vec<u8>,
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
fn determine_action_target(event: &Event) -> ActionTarget {
    // For now, use a simple default target based on entity key
    // In a full implementation, this would extract PID and executable from event fields
    let pid = (event.entity_key & 0xFFFFFFFF) as u32;
    let executable = format!("entity_{}", event.entity_key);

    // Default to process execution target
    ActionTarget::ProcessExec { pid, executable }
}

/// Detection engine
pub struct DetectionEngine {
    event_bus: EventBus,
    _alert_output: AlertOutput,
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

    /// NFA engine for sequence detection
    nfa_engine: Option<NfaEngine>,

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
        info!("Schema registry initialized");

        // Initialize event bus
        let event_bus = EventBus::new(config.event_bus.clone());
        info!("Event bus initialized");

        // Initialize alert output
        let alert_output = AlertOutput::new(config.alert_output);
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

        #[cfg(not(feature = "wasm"))]
        let eql_compiler = std::sync::Mutex::new(None);

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

        #[cfg(not(feature = "wasm"))]
        let wasm_engine = None;

        // Initialize NFA engine with Wasm runtime as predicate evaluator
        let nfa_engine = if let Some(nfa_config) = config.nfa_config {
            #[cfg(feature = "wasm")]
            let predicate_evaluator = wasm_engine
                .clone()
                .map(|engine| engine as Arc<dyn PredicateEvaluator>);

            #[cfg(not(feature = "wasm"))]
            let predicate_evaluator = None;

            if let Some(evaluator) = predicate_evaluator {
                let engine = NfaEngine::new(nfa_config, evaluator);
                info!("NFA engine initialized");
                Some(engine)
            } else {
                warn!("NFA engine disabled (no predicate evaluator)");
                None
            }
        } else {
            None
        };

        let single_event_rules = Arc::new(tokio::sync::RwLock::new(Vec::new()));

        // Initialize action executor
        let action_executor = config
            .action_executor
            .unwrap_or_else(|| Arc::new(NoOpExecutor::default()) as Arc<dyn ActionExecutor>);

        // Log the engine mode
        info!(mode = ?config.mode, "Detection engine mode");

        Ok(Self {
            event_bus,
            _alert_output: alert_output,
            rule_manager,
            schema,
            mode: config.mode,
            action_executor,
            #[cfg(feature = "wasm")]
            wasm_engine,
            #[cfg(feature = "wasm")]
            eql_compiler,
            nfa_engine,
            single_event_rules,
            alerts_generated: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            actions_generated: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            errors_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    /// Get the rule manager
    pub fn rule_manager(&self) -> &Arc<RuleManager> {
        &self.rule_manager
    }

    /// Compile and register a single-event rule
    #[cfg(feature = "wasm")]
    pub async fn compile_single_event_rule(&self, rule: &Rule) -> Result<(), EngineError> {
        let mut compiler_guard = self
            .eql_compiler
            .lock()
            .map_err(|e| EngineError::WasmRuntimeError(format!("Mutex lock error: {}", e)))?;

        let compiler = match &mut *compiler_guard {
            Some(c) => c,
            None => {
                return Err(EngineError::WasmRuntimeError(
                    "EQL compiler not initialized".to_string(),
                ))
            }
        };

        let _wasm_engine = match &self.wasm_engine {
            Some(e) => e,
            None => {
                return Err(EngineError::WasmRuntimeError(
                    "Wasm engine not initialized".to_string(),
                ))
            }
        };

        let definition = match &rule.definition {
            RuleDefinition::Eql(eql) => eql.clone(),
            RuleDefinition::Wasm(_) => return Ok(()),
            RuleDefinition::Lua(_) => return Ok(()),
        };

        let ir = compiler
            .compile_to_ir(&definition)
            .map_err(|e| EngineError::WasmRuntimeError(format!("EQL compilation error: {}", e)))?;

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

                let required_fields: Vec<u32> = predicate.required_fields.clone();

                let wasm_bytes = compiler.compile_to_wasm(&definition).map_err(|e| {
                    EngineError::WasmRuntimeError(format!("Wasm compilation error: {}", e))
                })?;

                let wasm_bytes = wat::parse_str(&wasm_bytes).map_err(|e| {
                    EngineError::WasmRuntimeError(format!("WAT parsing error: {}", e))
                })?;

                let single_rule = SingleEventRule {
                    rule_id: rule.metadata.id.clone(),
                    rule_name: rule.metadata.name.clone(),
                    event_type: event_type_id,
                    severity: rule_severity_to_severity(rule.metadata.severity),
                    description: rule.metadata.description.clone(),
                    predicate: CompiledPredicate::Wasm {
                        wasm_bytes,
                        required_fields,
                    },
                    blockable: false,  // Default to non-blockable for now
                    action_type: None, // Default to alert-only for now
                };

                let mut rules = self.single_event_rules.write().await;
                rules.push(single_rule);
                info!(rule_id = %rule.metadata.id, "Compiled single-event rule");
            }
            IrRuleType::Sequence { .. } => {
                info!(rule_id = %rule.metadata.id, "Skipping sequence rule (handled by NFA engine)");
            }
        }

        Ok(())
    }

    #[cfg(not(feature = "wasm"))]
    pub async fn compile_single_event_rule(&self, _rule: &Rule) -> Result<(), EngineError> {
        Ok(())
    }

    /// Compile all loaded rules into single-event and sequence rules
    pub async fn compile_rules(&self) -> Result<(), EngineError> {
        info!("Compiling rules");

        let rule_ids = self.rule_manager.list_rules().await;

        for rule_id in rule_ids {
            if let Some(rule) = self.rule_manager.get_rule(&rule_id).await {
                self.compile_single_event_rule(&rule).await?;
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
        let errors_count = self
            .errors_count
            .load(std::sync::atomic::Ordering::Relaxed);
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

        let _alerts_generated = self.alerts_generated.clone();

        let event_handle = self.event_bus.handle();

        tokio::spawn(async move {
            info!("Event processing loop started");
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
    pub async fn eval_event(&mut self, event: &Event) -> Result<Vec<Alert>, EngineError> {
        debug!(
            event_type_id = event.event_type_id,
            entity_key = event.entity_key,
            "Evaluating event"
        );

        let mut alerts = Vec::new();

        // Evaluate against NFA engine (sequence rules)
        if let Some(ref mut nfa_engine) = self.nfa_engine {
            match nfa_engine.process_event(event) {
                Ok(sequence_alerts) => {
                    for seq_alert in sequence_alerts {
                        // Convert events to EventEvidence
                        let events: Vec<EventEvidence> = seq_alert
                            .events
                            .iter()
                            .map(|e| EventEvidence {
                                event_type_id: e.event_type_id,
                                timestamp_ns: e.ts_mono_ns,
                                fields: vec![],
                            })
                            .collect();

                        // Create context from captures
                        let context = serde_json::json!({
                            "sequence_id": seq_alert.sequence_id,
                            "entity_key": seq_alert.entity_key,
                            "captures": seq_alert.captures,
                        });

                        // Generate unique alert ID
                        let alert_id = format!("{}-{}", seq_alert.rule_id, seq_alert.timestamp_ns);

                        let alert = Alert {
                            id: alert_id,
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
                            context,
                        };
                        alerts.push(alert);

                        // Increment alert counter
                        self.alerts_generated
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    error!(error = %e, "NFA engine error");
                    self.errors_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }

        // Evaluate single-event rules
        #[cfg(feature = "wasm")]
        {
            let rules = self.single_event_rules.read().await;
            let wasm_engine = match &self.wasm_engine {
                Some(e) => e,
                None => return Ok(alerts),
            };

            for single_rule in rules.iter() {
                // Check if event type matches
                if single_rule.event_type != event.event_type_id {
                    continue;
                }

                // Evaluate predicate
                let matched = match &single_rule.predicate {
                    CompiledPredicate::Wasm {
                        wasm_bytes,
                        required_fields: _,
                    } => {
                        self.eval_wasm_predicate(wasm_engine, wasm_bytes, event)
                            .await?
                    }
                    CompiledPredicate::AlwaysMatch => true,
                    #[cfg(feature = "wasm")]
                    CompiledPredicate::Lua { .. } => false,
                    #[cfg(not(feature = "wasm"))]
                    CompiledPredicate::Lua { .. } => false,
                };

                if matched {
                    let alert_id = format!("{}-{}", single_rule.rule_id, event.ts_mono_ns);

                    let alert = Alert {
                        id: alert_id.clone(),
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
                        context: serde_json::json!({
                            "rule_type": "single_event",
                        }),
                    };
                    alerts.push(alert);

                    self.alerts_generated
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    // In Inline mode, execute action if rule is blockable
                    if self.mode == EngineMode::Inline && single_rule.blockable {
                        if let Some(action_type) = single_rule.action_type {
                            let decision = ActionDecision::new(
                                single_rule.rule_id.clone(),
                                action_type,
                                ActionPolicy::Inline,
                                determine_action_target(event),
                                format!("Rule matched: {}", single_rule.rule_name),
                                vec![],
                            );

                            match self.action_executor.execute(&decision) {
                                Ok(result) if result.success => {
                                    self.actions_generated
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    debug!(
                                        action_id = %decision.id,
                                        action = ?action_type,
                                        "Action executed successfully"
                                    );
                                }
                                Ok(result) => {
                                    debug!(
                                        action_id = %decision.id,
                                        action = ?action_type,
                                        error = %result.error.as_deref().unwrap_or(""),
                                        "Action not executed (executor decision)"
                                    );
                                }
                                Err(e) => {
                                    error!(
                                        action_id = %decision.id,
                                        action = ?action_type,
                                        error = %e,
                                        "Action execution failed"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(alerts)
    }

    #[cfg(feature = "wasm")]
    async fn eval_wasm_predicate(
        &self,
        wasm_engine: &WasmEngine,
        wasm_bytes: &[u8],
        event: &Event,
    ) -> Result<bool, EngineError> {
        wasm_engine
            .eval_adhoc_predicate(wasm_bytes, event)
            .await
            .map_err(|e| EngineError::WasmRuntimeError(e.to_string()))
    }

    /// Load a compiled sequence into the NFA engine
    pub fn load_sequence(&mut self, sequence: CompiledSequence) -> Result<(), EngineError> {
        if let Some(ref mut nfa_engine) = self.nfa_engine {
            nfa_engine
                .load_sequence(sequence)
                .map_err(|e| EngineError::NfaError(e.to_string()))?;
        }
        Ok(())
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_event::Event;
    use tokio::time::Duration;

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

    #[tokio::test]
    async fn test_single_event_rule_eval_always_match() {
        use kestrel_event::Event;
        use tokio::time::Duration;

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

        let mut engine = DetectionEngine::new(config).await.unwrap();

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

    #[tokio::test]
    async fn test_single_event_rule_no_match_different_event_type() {
        use kestrel_event::Event;
        use tokio::time::Duration;

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

        let mut engine = DetectionEngine::new(config).await.unwrap();

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

    #[tokio::test]
    async fn test_eval_event_multiple_single_event_rules() {
        use kestrel_event::Event;
        use tokio::time::Duration;

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

        let mut engine = DetectionEngine::new(config).await.unwrap();

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

    #[tokio::test]
    async fn test_inline_mode_with_blockable_rule() {
        use kestrel_core::{ActionType, NoOpExecutor};
        use kestrel_event::Event;
        use tokio::time::Duration;

        let temp_dir = tempfile::tempdir().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();

        #[cfg(feature = "wasm")]
        let config = EngineConfig {
            rules_dir,
            wasm_config: Some(kestrel_runtime_wasm::WasmConfig::default()),
            mode: EngineMode::Inline,
            action_executor: Some(Arc::new(NoOpExecutor::default()) as Arc<dyn ActionExecutor>),
            ..Default::default()
        };

        #[cfg(not(feature = "wasm"))]
        let config = EngineConfig {
            rules_dir,
            mode: EngineMode::Inline,
            action_executor: Some(Arc::new(NoOpExecutor::default()) as Arc<dyn ActionExecutor>),
            ..Default::default()
        };

        let mut engine = DetectionEngine::new(config).await.unwrap();

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

    #[tokio::test]
    async fn test_detect_mode_no_enforcement() {
        use kestrel_core::{ActionType, NoOpExecutor};
        use kestrel_event::Event;
        use tokio::time::Duration;

        let temp_dir = tempfile::tempdir().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();

        #[cfg(feature = "wasm")]
        let config = EngineConfig {
            rules_dir,
            wasm_config: Some(kestrel_runtime_wasm::WasmConfig::default()),
            mode: EngineMode::Detect, // Detect mode (default)
            action_executor: Some(Arc::new(NoOpExecutor::default()) as Arc<dyn ActionExecutor>),
            ..Default::default()
        };

        #[cfg(not(feature = "wasm"))]
        let config = EngineConfig {
            rules_dir,
            mode: EngineMode::Detect, // Detect mode (default)
            action_executor: Some(Arc::new(NoOpExecutor::default()) as Arc<dyn ActionExecutor>),
            ..Default::default()
        };

        let mut engine = DetectionEngine::new(config).await.unwrap();

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

    #[tokio::test]
    async fn test_non_blockable_rule_no_enforcement() {
        use kestrel_core::{ActionType, NoOpExecutor};
        use kestrel_event::Event;
        use tokio::time::Duration;

        let temp_dir = tempfile::tempdir().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();

        #[cfg(feature = "wasm")]
        let config = EngineConfig {
            rules_dir,
            wasm_config: Some(kestrel_runtime_wasm::WasmConfig::default()),
            mode: EngineMode::Inline, // Inline mode
            action_executor: Some(Arc::new(NoOpExecutor::default()) as Arc<dyn ActionExecutor>),
            ..Default::default()
        };

        #[cfg(not(feature = "wasm"))]
        let config = EngineConfig {
            rules_dir,
            mode: EngineMode::Inline, // Inline mode
            action_executor: Some(Arc::new(NoOpExecutor::default()) as Arc<dyn ActionExecutor>),
            ..Default::default()
        };

        let mut engine = DetectionEngine::new(config).await.unwrap();

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

    #[tokio::test]
    async fn test_action_type_kill() {
        use kestrel_core::{ActionType, NoOpExecutor};
        use kestrel_event::Event;
        use tokio::time::Duration;

        let temp_dir = tempfile::tempdir().unwrap();
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();

        #[cfg(feature = "wasm")]
        let config = EngineConfig {
            rules_dir,
            wasm_config: Some(kestrel_runtime_wasm::WasmConfig::default()),
            mode: EngineMode::Inline,
            action_executor: Some(Arc::new(NoOpExecutor::default()) as Arc<dyn ActionExecutor>),
            ..Default::default()
        };

        #[cfg(not(feature = "wasm"))]
        let config = EngineConfig {
            rules_dir,
            mode: EngineMode::Inline,
            action_executor: Some(Arc::new(NoOpExecutor::default()) as Arc<dyn ActionExecutor>),
            ..Default::default()
        };

        let mut engine = DetectionEngine::new(config).await.unwrap();

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
