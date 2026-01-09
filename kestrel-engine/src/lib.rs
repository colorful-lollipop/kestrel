//! Kestrel Detection Engine
//!
//! This is the core detection engine that coordinates event processing,
//! rule evaluation, and alert generation.

use kestrel_core::{Alert, AlertOutput, AlertOutputConfig, EventBus, EventBusConfig};
use kestrel_event::Event;
use kestrel_rules::RuleManager;
use kestrel_schema::SchemaRegistry;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

#[cfg(feature = "wasm")]
use kestrel_runtime_wasm::{WasmEngine, WasmConfig, RuleManifest, EvalResult};

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
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            event_bus: EventBusConfig::default(),
            alert_output: AlertOutputConfig::default(),
            rules_dir: std::path::PathBuf::from("./rules"),
            #[cfg(feature = "wasm")]
            wasm_config: None,
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
        info!(
            loaded = stats.loaded,
            failed = stats.failed,
            "Rules loaded"
        );

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

        Ok(Self {
            _event_bus: event_bus,
            _alert_output: alert_output,
            rule_manager,
            schema,

            #[cfg(feature = "wasm")]
            wasm_engine,
        })
    }

    /// Get the rule manager
    pub fn rule_manager(&self) -> &Arc<RuleManager> {
        &self.rule_manager
    }

    /// Get engine statistics
    pub async fn stats(&self) -> EngineStats {
        let rule_count = self.rule_manager.rule_count().await;

        EngineStats {
            rule_count,
            alerts_generated: 0, // TODO: implement alert counting
        }
    }

    /// Evaluate an event against all loaded rules
    pub async fn eval_event(&self, event: &Event) -> Result<Vec<Alert>, EngineError> {
        debug!("Evaluating event");
        let mut alerts = Vec::new();

        // For now, return empty alerts
        // Full evaluation will be implemented in Phase 3 with EQL compiler
        Ok(alerts)
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
