use async_trait::async_trait;
use kestrel_core::{Alert, AlertSink, AlertSinkError, Backpressure, EmitStatus, SinkHealth};
use kestrel_event::Event;
use kestrel_observability::{RuleTrace, TraceCollector, TraceId, TraceStep};
use kestrel_rules::Rule;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use thiserror::Error;

/// In-memory alert sink that collects all emitted alerts.
pub struct InMemoryAlertSink {
    alerts: Mutex<Vec<Alert>>,
}

impl InMemoryAlertSink {
    pub fn new() -> Self {
        Self {
            alerts: Mutex::new(Vec::new()),
        }
    }

    /// Retrieve all captured alerts.
    pub fn alerts(&self) -> Vec<Alert> {
        self.alerts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Clear all captured alerts.
    pub fn clear(&self) {
        self.alerts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

impl Default for InMemoryAlertSink {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertSink for InMemoryAlertSink {
    fn emit(&self, alert: &Alert) -> Result<(EmitStatus, Backpressure), AlertSinkError> {
        self.alerts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(alert.clone());
        Ok((EmitStatus::Acknowledged, Backpressure::Normal))
    }

    fn health(&self) -> SinkHealth {
        SinkHealth {
            healthy: true,
            ..SinkHealth::default()
        }
    }
}

/// In-memory trace collector that records all rule evaluation traces.
pub struct InMemoryTraceCollector {
    traces: Mutex<Vec<RuleTrace>>,
    next_id: AtomicU64,
}

impl InMemoryTraceCollector {
    pub fn new() -> Self {
        Self {
            traces: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Retrieve all captured traces.
    pub fn traces(&self) -> Vec<RuleTrace> {
        self.traces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl Default for InMemoryTraceCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceCollector for InMemoryTraceCollector {
    fn record_trace(&self, trace: RuleTrace) {
        self.traces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(trace);
    }

    fn record_step(&self, _trace_id: TraceId, _step: TraceStep) {}

    fn start_trace(&self, _rule_id: &str, _event: &Event) -> TraceId {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn flush(&self) {}

    fn is_rule_traced(&self, _rule_id: &str) -> bool {
        true
    }
}

/// Configuration for sandbox execution.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Maximum number of events to process from a fixture.
    pub max_events: usize,
    /// Maximum memory usage in megabytes (soft limit, documented).
    pub max_memory_mb: usize,
    /// Timeout for the entire sandbox run in milliseconds.
    pub timeout_ms: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_events: 10_000,
            max_memory_mb: 512,
            timeout_ms: 30_000,
        }
    }
}

/// Result of running a fixture through the sandbox.
#[derive(Debug, Clone)]
pub struct SandboxResult {
    /// Number of events that were successfully evaluated.
    pub events_processed: usize,
    /// All alerts generated during evaluation.
    pub alerts_generated: Vec<Alert>,
    /// All traces collected during evaluation.
    pub traces: Vec<RuleTrace>,
    /// Total wall-clock duration of the run.
    pub duration: Duration,
    /// Any non-fatal errors encountered during evaluation.
    pub errors: Vec<String>,
}

/// Errors that can occur during sandbox execution.
#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Engine error: {0}")]
    Engine(String),
    #[error("Fixture error: {0}")]
    Fixture(#[from] crate::fixture::FixtureError),
    #[error("Timeout after {0}ms")]
    Timeout(u64),
}

/// Trait for running fixtures in a sandboxed environment.
#[async_trait]
pub trait FixtureRunner {
    /// Run a rule against a fixture file.
    async fn run_fixture(
        &self,
        rule: &Rule,
        fixture_path: &std::path::Path,
    ) -> Result<SandboxResult, SandboxError>;
}

/// Sandboxed detection engine for testing rules against fixtures.
///
/// The sandbox creates an isolated [`DetectionEngine`] in offline mode,
/// injects in-memory alert and trace collectors, and evaluates events
/// without any side effects.
pub struct SandboxEngine {
    config: SandboxConfig,
}

impl SandboxEngine {
    /// Create a new sandbox engine with the given configuration.
    pub fn new(config: SandboxConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl FixtureRunner for SandboxEngine {
    async fn run_fixture(
        &self,
        rule: &Rule,
        fixture_path: &std::path::Path,
    ) -> Result<SandboxResult, SandboxError> {
        let fixture = crate::FixtureLoader::load(fixture_path)?;

        let temp_dir = tempfile::tempdir()?;
        crate::write_rule_package(temp_dir.path(), rule).map_err(SandboxError::Io)?;

        let alert_sink = Arc::new(InMemoryAlertSink::new());
        let trace_collector = Arc::new(InMemoryTraceCollector::new());

        let engine_config = kestrel_engine::EngineConfig {
            rules_dir: temp_dir.path().to_path_buf(),
            mode: kestrel_engine::EngineMode::Offline,
            alert_sink: Some(alert_sink.clone()),
            trace_collector: Some(trace_collector.clone()),
            ..Default::default()
        };

        let engine = tokio::time::timeout(
            Duration::from_millis(self.config.timeout_ms),
            kestrel_engine::DetectionEngine::new(engine_config),
        )
        .await
        .map_err(|_| SandboxError::Timeout(self.config.timeout_ms))?
        .map_err(|e| SandboxError::Engine(e.to_string()))?;

        let start = Instant::now();
        let mut events_processed = 0;
        let mut errors = Vec::new();

        for event in fixture.events.iter().take(self.config.max_events) {
            match tokio::time::timeout(
                Duration::from_millis(self.config.timeout_ms),
                engine.eval_event(event),
            )
            .await
            {
                Ok(Ok(_alerts)) => {
                    events_processed += 1;
                },
                Ok(Err(e)) => {
                    errors.push(format!("Event evaluation error: {}", e));
                },
                Err(_) => {
                    errors.push(format!(
                        "Event evaluation timed out after {}ms",
                        self.config.timeout_ms
                    ));
                },
            }
        }

        let duration = start.elapsed();

        Ok(SandboxResult {
            events_processed,
            alerts_generated: alert_sink.alerts(),
            traces: trace_collector.traces(),
            duration,
            errors,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_event::Event;
    use kestrel_rules::{Rule, RuleDefinition, RuleMetadata, Severity};

    fn test_rule() -> Rule {
        Rule {
            metadata: RuleMetadata {
                id: "sandbox-001".to_string(),
                name: "Sandbox Test Rule".to_string(),
                description: None,
                version: "1.0.0".to_string(),
                author: None,
                tags: vec![],
                severity: Severity::Low,
            },
            definition: RuleDefinition::Eql("process where true".to_string()),
        }
    }

    #[tokio::test]
    async fn test_run_fixture_json() {
        let temp_dir = tempfile::tempdir().unwrap();
        let fixture_path = temp_dir.path().join("test.json");

        let fixture = crate::Fixture {
            name: "Test Fixture".to_string(),
            description: None,
            events: vec![
                Event::builder()
                    .event_type(1)
                    .ts_mono(1000)
                    .ts_wall(1000)
                    .entity_key(42)
                    .build()
                    .unwrap(),
            ],
            expected: crate::ExpectedOutcome::ShouldMatch,
        };

        std::fs::write(&fixture_path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();

        let engine = SandboxEngine::new(SandboxConfig::default());
        let result = engine.run_fixture(&test_rule(), &fixture_path).await;

        assert!(result.is_ok(), "Sandbox run failed: {:?}", result.err());
        let result = result.unwrap();
        assert_eq!(result.events_processed, 1);
        assert!(result.errors.is_empty(), "Errors: {:?}", result.errors);
    }

    #[tokio::test]
    async fn test_run_fixture_yaml() {
        let temp_dir = tempfile::tempdir().unwrap();
        let fixture_path = temp_dir.path().join("test.yaml");

        let fixture = crate::Fixture {
            name: "Test Fixture".to_string(),
            description: None,
            events: vec![
                Event::builder()
                    .event_type(1)
                    .ts_mono(2000)
                    .ts_wall(2000)
                    .entity_key(99)
                    .build()
                    .unwrap(),
            ],
            expected: crate::ExpectedOutcome::ShouldAlert,
        };

        std::fs::write(&fixture_path, serde_yaml::to_string(&fixture).unwrap()).unwrap();

        let engine = SandboxEngine::new(SandboxConfig::default());
        let result = engine.run_fixture(&test_rule(), &fixture_path).await;

        assert!(result.is_ok(), "Sandbox run failed: {:?}", result.err());
        let result = result.unwrap();
        assert_eq!(result.events_processed, 1);
    }

    #[tokio::test]
    async fn test_run_fixture_with_fields() {
        let temp_dir = tempfile::tempdir().unwrap();
        let fixture_path = temp_dir.path().join("test.json");

        // Manually construct JSON with lowercase TypedValue keys to work around
        // the upstream serialize/deserialize case mismatch in kestrel-schema.
        let raw_json = r#"{
            "name": "Field Fixture",
            "description": "Event with fields",
            "events": [
                {
                    "event_id": 0,
                    "event_type_id": 1,
                    "ts_mono_ns": 3000,
                    "ts_wall_ns": 3000,
                    "entity_key": 7,
                    "fields": [[1, {"string": "/usr/bin/ssh"}], [2, {"u64": 1234}]],
                    "source_id": null
                }
            ],
            "expected": "should_match"
        }"#;

        std::fs::write(&fixture_path, raw_json).unwrap();

        let engine = SandboxEngine::new(SandboxConfig::default());
        let result = engine.run_fixture(&test_rule(), &fixture_path).await;

        assert!(result.is_ok(), "Sandbox run failed: {:?}", result.err());
        let result = result.unwrap();
        assert_eq!(result.events_processed, 1);
    }

    #[test]
    fn test_in_memory_alert_sink() {
        let sink = InMemoryAlertSink::new();
        let alert = Alert {
            id: "alert-1".to_string(),
            rule_id: "rule-1".to_string(),
            rule_name: "Test".to_string(),
            severity: kestrel_schema::Severity::High,
            timestamp_ns: 1000,
            title: "Test Alert".to_string(),
            description: None,
            events: vec![],
            context: serde_json::json!({}),
        };

        sink.emit(&alert).unwrap();
        let alerts = sink.alerts();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].id, "alert-1");

        sink.clear();
        assert!(sink.alerts().is_empty());
    }

    #[test]
    fn test_in_memory_trace_collector() {
        let collector = InMemoryTraceCollector::new();
        let event = Event::builder()
            .event_type(1)
            .ts_mono(0)
            .ts_wall(0)
            .entity_key(0)
            .build()
            .unwrap();

        let trace = RuleTrace {
            trace_id: collector.start_trace("rule-1", &event),
            rule_id: "rule-1".to_string(),
            event_id: 1,
            timestamp_ns: 1000,
            duration: Duration::from_millis(1),
            matched: true,
            steps: vec![],
            error: None,
        };

        collector.record_trace(trace.clone());
        let traces = collector.traces();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].rule_id, "rule-1");
    }
}
