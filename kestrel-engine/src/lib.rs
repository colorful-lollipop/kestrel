//! Kestrel Detection Engine
//!
//! This is the core detection engine that coordinates event processing,
//! rule evaluation, and alert generation.

use kestrel_core::{
    Alert, AlertOutput, AlertOutputConfig, EventBus, EventBusConfig, EventEvidence, Severity,
};
use kestrel_event::Event;
use kestrel_nfa::{CompiledSequence, NfaEngine, NfaEngineConfig, PredicateEvaluator};
use kestrel_rules::RuleManager;
use kestrel_schema::SchemaRegistry;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info, warn};

#[cfg(feature = "wasm")]
use kestrel_runtime_wasm::{WasmConfig, WasmEngine};

/// Detection engine configuration
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Event bus configuration
    pub event_bus: EventBusConfig,

    /// Alert output configuration
    pub alert_output: AlertOutputConfig,

    /// Rule manager configuration
    pub rules_dir: std::path::PathBuf,

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
            #[cfg(feature = "wasm")]
            wasm_config: None,
            nfa_config: Some(NfaEngineConfig::default()),
        }
    }
}

/// Detection engine
pub struct DetectionEngine {
    _event_bus: EventBus,
    _alert_output: AlertOutput,
    rule_manager: Arc<RuleManager>,
    schema: Arc<SchemaRegistry>,

    #[cfg(feature = "wasm")]
    wasm_engine: Option<Arc<WasmEngine>>,

    /// NFA engine for sequence detection
    nfa_engine: Option<NfaEngine>,

    /// Alert counter (atomic for thread safety)
    alerts_generated: Arc<std::sync::atomic::AtomicU64>,
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
            rules_dir: config.rules_dir,
            watch_enabled: false, // TODO: implement hot-reload
            max_concurrent_loads: 4,
        };

        let rule_manager = Arc::new(RuleManager::new(rule_config));

        // Load initial rules
        let stats = rule_manager.load_all().await?;
        info!(loaded = stats.loaded, failed = stats.failed, "Rules loaded");

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

        Ok(Self {
            _event_bus: event_bus,
            _alert_output: alert_output,
            rule_manager,
            schema,

            #[cfg(feature = "wasm")]
            wasm_engine,

            nfa_engine,
            alerts_generated: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    /// Get the rule manager
    pub fn rule_manager(&self) -> &Arc<RuleManager> {
        &self.rule_manager
    }

    /// Get engine statistics
    pub async fn stats(&self) -> EngineStats {
        let rule_count = self.rule_manager.rule_count().await;
        let alerts_generated = self
            .alerts_generated
            .load(std::sync::atomic::Ordering::Relaxed);

        EngineStats {
            rule_count,
            alerts_generated,
        }
    }

    /// Evaluate an event against all loaded rules
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
                            severity: Severity::High, // TODO: Get from rule
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
                }
            }
        }

        // TODO: Evaluate single-event rules
        // This would involve:
        // 1. Getting all single-event rules from RuleManager
        // 2. Evaluating predicates against the event
        // 3. Generating alerts for matches

        Ok(alerts)
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
    pub alerts_generated: u64,
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
}
