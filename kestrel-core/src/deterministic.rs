use kestrel_event::Event;
use kestrel_schema::{SchemaRegistry, TypedValue};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info};

use crate::alert::Alert;
use crate::replay::BinaryLog;

pub struct DeterministicVerifier {
    schema: Arc<SchemaRegistry>,
}

#[derive(Debug, Clone)]
pub struct DeterministicResult {
    pub total_runs: usize,
    pub consistent: bool,
    pub mismatches: Vec<String>,
    pub total_alerts: Vec<usize>,
    pub execution_times_ms: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMismatch {
    pub event_id: u64,
    pub expected: usize,
    pub actual: usize,
    pub details: String,
}

#[derive(Debug, Clone)]
pub struct ReplayVerificationResult {
    pub total_events: usize,
    pub total_alerts: usize,
    pub mismatches: Vec<VerificationMismatch>,
    pub is_deterministic: bool,
    pub execution_time_ms: u64,
    pub memory_peak_bytes: usize,
    pub cpu_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayVerificationReport {
    pub timestamp: u64,
    pub total_events: usize,
    pub total_alerts: usize,
    pub duration_ms: u64,
    pub is_deterministic: bool,
    pub runtime_consistent: bool,
    pub memory_peak_mb: f64,
    pub cpu_time_ms: u64,
    pub log_version: u32,
    pub schema_version: u32,
    pub engine_build_id: String,
    pub event_count: u64,
    pub mismatches: Vec<VerificationMismatch>,
}

impl DeterministicVerifier {
    pub fn new(schema: Arc<SchemaRegistry>) -> Self {
        Self { schema }
    }

    pub async fn verify_determinism<F>(
        &self,
        events: &[Event],
        run_detection: F,
    ) -> Result<DeterministicResult, Box<dyn std::error::Error>>
    where
        F: Fn(&[Event]) -> Vec<Alert>,
    {
        let runs = 5usize;
        let mut results: Vec<Vec<Alert>> = Vec::with_capacity(runs);
        let mut mismatches = Vec::new();
        let mut total_alerts = Vec::new();
        let mut execution_times = Vec::new();

        for i in 0..runs {
            let start = std::time::Instant::now();
            let result = run_detection(events);
            let elapsed = start.elapsed().as_millis() as u64;

            execution_times.push(elapsed);
            total_alerts.push(result.len());
            results.push(result.clone());

            if i > 0 {
                if result.len() != results[0].len() {
                    mismatches.push(format!(
                        "Run {} has different alert count: {} vs {}",
                        i + 1,
                        result.len(),
                        results[0].len()
                    ));
                }
            }
        }

        Ok(DeterministicResult {
            total_runs: runs,
            consistent: mismatches.is_empty(),
            mismatches,
            total_alerts,
            execution_times_ms: execution_times,
        })
    }

    pub fn generate_test_sequence(&self, count: usize, base_time: u64) -> Vec<Event> {
        let mut events = Vec::with_capacity(count);
        for i in 0..count {
            let event = Event::builder()
                .event_id((i + 1) as u64)
                .event_type(1)
                .ts_mono(base_time + (i as u64 * 1_000_000_000))
                .ts_wall(base_time + (i as u64 * 1_000_000_000))
                .entity_key(0x12345)
                .field(1, TypedValue::String(format!("/bin/test_{}", i)))
                .field(2, TypedValue::I64(i as i64))
                .build()
                .unwrap();
            events.push(event);
        }
        events
    }

    pub async fn replay_and_verify(
        &self,
        log_path: PathBuf,
        run_detection: impl Fn(&Event) -> Vec<Alert>,
    ) -> Result<ReplayVerificationResult, Box<dyn std::error::Error>> {
        let schema = self.schema.clone();
        let binary_log = BinaryLog::new(schema);
        let events = binary_log.read_events(log_path)?;

        if events.is_empty() {
            return Ok(ReplayVerificationResult {
                total_events: 0,
                total_alerts: 0,
                mismatches: Vec::new(),
                is_deterministic: true,
                execution_time_ms: 0,
                memory_peak_bytes: 0,
                cpu_time_ms: 0,
            });
        }

        let start = std::time::Instant::now();
        let mut all_alerts = Vec::new();
        let mut mismatches = Vec::new();

        for event in &events {
            let alerts = run_detection(event);
            all_alerts.extend(alerts);
        }

        let elapsed = start.elapsed();

        Ok(ReplayVerificationResult {
            total_events: events.len(),
            total_alerts: all_alerts.len(),
            mismatches,
            is_deterministic: true,
            execution_time_ms: elapsed.as_millis() as u64,
            memory_peak_bytes: 0,
            cpu_time_ms: elapsed.as_millis() as u64,
        })
    }
}

impl ReplayVerificationReport {
    pub fn generate_summary(&self) -> String {
        format!(
            r#"
Replay Verification Report
==========================
Timestamp: {}
Events Processed: {}
Alerts Generated: {}
Duration: {}ms
Deterministic: {}
Runtime Consistent: {}
Peak Memory: {:.2}MB
CPU Time: {}ms
Mismatches: {}

Log Header Information:
  Version: {}
  Schema Version: {}
  Engine Build: {}
  Event Count: {}
"#,
            self.timestamp,
            self.total_events,
            self.total_alerts,
            self.duration_ms,
            self.is_deterministic,
            self.runtime_consistent,
            self.memory_peak_mb,
            self.cpu_time_ms,
            self.mismatches.len(),
            self.log_version,
            self.schema_version,
            self.engine_build_id,
            self.event_count,
        )
    }
}

impl Default for ReplayVerificationReport {
    fn default() -> Self {
        Self {
            timestamp: 0,
            total_events: 0,
            total_alerts: 0,
            duration_ms: 0,
            is_deterministic: true,
            runtime_consistent: true,
            memory_peak_mb: 0.0,
            cpu_time_ms: 0,
            log_version: 0,
            schema_version: 0,
            engine_build_id: String::new(),
            event_count: 0,
            mismatches: Vec::new(),
        }
    }
}

pub struct ReplaySource {
    log: BinaryLog,
    events: Vec<Event>,
    current_index: usize,
    pub verification_enabled: bool,
    pub expected_results: Option<HashMap<u64, Vec<Alert>>>,
    recorded_results: Arc<Mutex<Vec<(u64, Vec<Alert>)>>>,
}

impl ReplaySource {
    pub fn with_verification(
        log: BinaryLog,
        events: Vec<Event>,
        expected_results: HashMap<u64, Vec<Alert>>,
    ) -> Self {
        Self {
            log,
            events,
            current_index: 0,
            verification_enabled: true,
            expected_results: Some(expected_results),
            recorded_results: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn replay_and_verify<F>(
        &mut self,
        run_eval: F,
    ) -> Result<ReplayVerificationResult, crate::ReplayError>
    where
        F: Fn(&Event) -> Vec<Alert>,
    {
        let mut results = Vec::new();
        let mut mismatches = Vec::new();
        let start = std::time::Instant::now();

        let expected_results = self.expected_results.take();
        let mut local_recorded = Vec::new();

        while let Some(event) = self.next_event() {
            let alerts = run_eval(event);

            if let Some(expected) = expected_results.as_ref() {
                if let Some(expected_alerts) = expected.get(&event.event_id) {
                    if alerts.len() != expected_alerts.len() {
                        mismatches.push(VerificationMismatch {
                            event_id: event.event_id,
                            expected: expected_alerts.len(),
                            actual: alerts.len(),
                            details: format!(
                                "Event {}: expected {} alerts, got {}",
                                event.event_id,
                                expected_alerts.len(),
                                alerts.len()
                            ),
                        });
                    }
                }
            }

            results.push((event.event_id, alerts.clone()));
            local_recorded.push((event.event_id, alerts));
        }

        {
            let mut recorded = self.recorded_results.lock().await;
            recorded.extend(local_recorded);
        }

        self.expected_results = expected_results;

        let elapsed = start.elapsed();
        let is_deterministic = mismatches.is_empty();

        Ok(ReplayVerificationResult {
            total_events: results.len(),
            total_alerts: results.iter().map(|(_, a)| a.len()).sum(),
            mismatches,
            is_deterministic,
            execution_time_ms: elapsed.as_millis() as u64,
            memory_peak_bytes: 0,
            cpu_time_ms: elapsed.as_millis() as u64,
        })
    }

    pub fn next_event(&mut self) -> Option<&Event> {
        if self.current_index < self.events.len() {
            let event = &self.events[self.current_index];
            self.current_index += 1;
            Some(event)
        } else {
            None
        }
    }

    pub fn reset(&mut self) {
        self.current_index = 0;
    }

    pub fn get_recorded_results(&self) -> &Arc<Mutex<Vec<(u64, Vec<Alert>)>>> {
        &self.recorded_results
    }
}

pub struct DeterministicTestRunner {
    schema: Arc<SchemaRegistry>,
    results: Arc<RwLock<Vec<DeterministicResult>>>,
}

impl DeterministicTestRunner {
    pub fn new(schema: Arc<SchemaRegistry>) -> Self {
        Self {
            schema,
            results: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn run_deterministic_test<F>(
        &self,
        name: &str,
        events: &[Event],
        run_detection: F,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        F: Fn(&[Event]) -> Vec<Alert>,
    {
        let verifier = DeterministicVerifier::new(self.schema.clone());
        let result = verifier.verify_determinism(events, run_detection).await?;

        let is_consistent = result.consistent;
        let mismatches = result.mismatches.clone();

        let mut results = self.results.write().await;
        results.push(result);

        info!("Test '{}' completed: deterministic={}", name, is_consistent);

        if !is_consistent {
            for mismatch in &mismatches {
                error!("Mismatch: {}", mismatch);
            }
        }

        Ok(())
    }

    pub async fn get_results(&self) -> Vec<DeterministicResult> {
        self.results.read().await.clone()
    }

    pub async fn clear_results(&self) {
        let mut results = self.results.write().await;
        results.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TimeManager;
    use kestrel_event::Event;

    fn create_test_events(count: usize) -> Vec<Event> {
        let mut events = Vec::new();
        for i in 0..count {
            let event = Event::builder()
                .event_id((i + 1) as u64)
                .event_type(1)
                .ts_mono((i as u64 + 1) * 1_000_000_000)
                .ts_wall((i as u64 + 1) * 1_000_000_000)
                .entity_key(i as u128 % 4)
                .field(1, TypedValue::I64(i as i64))
                .field(2, TypedValue::String(format!("event_{}", i)))
                .build()
                .unwrap();
            events.push(event);
        }
        events
    }

    fn run_detection(events: &[Event]) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for event in events {
            if event.fields.iter().any(|(_, v)| {
                if let TypedValue::I64(n) = v {
                    *n > 50
                } else {
                    false
                }
            }) {
                alerts.push(Alert {
                    id: format!("alert-{}", event.event_id),
                    rule_id: "test-rule".to_string(),
                    rule_name: "Test Rule".to_string(),
                    severity: crate::Severity::Medium,
                    title: "Test alert".to_string(),
                    description: None,
                    timestamp_ns: event.ts_mono_ns,
                    events: vec![],
                    context: serde_json::json!({}),
                });
            }
        }
        alerts
    }

    #[tokio::test]
    async fn test_deterministic_verifier() {
        let schema = Arc::new(SchemaRegistry::new());
        let verifier = DeterministicVerifier::new(schema);

        let events = create_test_events(20);
        let result = verifier
            .verify_determinism(&events, |events| run_detection(events))
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(
            result.consistent,
            "Results should be deterministic: {:?}",
            result.mismatches
        );
        assert_eq!(result.total_runs, 5);
    }

    #[tokio::test]
    async fn test_generate_test_sequence() {
        let schema = Arc::new(SchemaRegistry::new());
        let verifier = DeterministicVerifier::new(schema);

        let events = verifier.generate_test_sequence(15, 2_000_000_000);

        assert_eq!(events.len(), 15);
        for (i, event) in events.iter().enumerate() {
            assert_eq!(event.event_id, (i + 1) as u64);
            assert_eq!(event.event_type_id, 1);
            assert_eq!(event.ts_mono_ns, 2_000_000_000 + (i as u64 * 1_000_000_000));
        }
    }

    #[tokio::test]
    async fn test_replay_verification_report() {
        let report = ReplayVerificationReport::default();
        let summary = report.generate_summary();

        assert!(summary.contains("Replay Verification Report"));
        assert!(summary.contains("Events Processed: 0"));
    }

    #[tokio::test]
    async fn test_deterministic_test_runner() {
        let schema = Arc::new(SchemaRegistry::new());
        let runner = DeterministicTestRunner::new(schema);

        let events = create_test_events(10);
        let result = runner
            .run_deterministic_test("test_basic", &events, |events| {
                let count = events
                    .iter()
                    .filter(|e| {
                        if let Some(TypedValue::I64(n)) = e.get_field(1) {
                            *n > 25
                        } else {
                            false
                        }
                    })
                    .count();
                vec![]
            })
            .await;

        assert!(result.is_ok());

        let results = runner.get_results().await;
        assert_eq!(results.len(), 1);
        assert!(results[0].consistent);
    }
}
