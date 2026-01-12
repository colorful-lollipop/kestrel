use kestrel_core::{DeterministicTestRunner, DeterministicVerifier, ReplayVerificationReport};
use kestrel_event::Event;
use kestrel_schema::{SchemaRegistry, TypedValue};
use std::sync::Arc;

fn create_test_schema() -> Arc<SchemaRegistry> {
    Arc::new(SchemaRegistry::new())
}

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

fn empty_alerts(_events: &[Event]) -> Vec<kestrel_core::Alert> {
    vec![]
}

#[tokio::test]
async fn test_deterministic_verifier_basic() {
    let schema = create_test_schema();
    let verifier = DeterministicVerifier::new(schema);

    let events = create_test_events(30);
    let result = verifier.verify_determinism(&events, empty_alerts).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert!(result.consistent);
    assert_eq!(result.total_runs, 5);
}

#[tokio::test]
async fn test_deterministic_verifier_empty_events() {
    let schema = create_test_schema();
    let verifier = DeterministicVerifier::new(schema);

    let events: Vec<Event> = vec![];
    let result = verifier.verify_determinism(&events, empty_alerts).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert!(result.consistent);
    assert_eq!(result.total_runs, 5);
}

#[tokio::test]
async fn test_generate_test_sequence() {
    let schema = create_test_schema();
    let verifier = DeterministicVerifier::new(schema);

    let events = verifier.generate_test_sequence(15, 2_000_000_000);

    assert_eq!(events.len(), 15);

    for (i, event) in events.iter().enumerate() {
        assert_eq!(event.event_id, (i + 1) as u64);
        assert_eq!(event.event_type_id, 1);
    }
}

#[tokio::test]
async fn test_deterministic_test_runner() {
    let schema = create_test_schema();
    let runner = DeterministicTestRunner::new(schema);

    let events = create_test_events(25);
    let result = runner
        .run_deterministic_test("test_runner_basic", &events, empty_alerts)
        .await;

    assert!(result.is_ok());

    let results = runner.get_results().await;
    assert_eq!(results.len(), 1);
    assert!(results[0].consistent);
}

#[tokio::test]
async fn test_deterministic_test_runner_multiple_tests() {
    let schema = create_test_schema();
    let runner = DeterministicTestRunner::new(schema);

    let events1 = create_test_events(10);
    let events2 = create_test_events(20);

    let result1 = runner
        .run_deterministic_test("test_small", &events1, empty_alerts)
        .await;

    let result2 = runner
        .run_deterministic_test("test_large", &events2, empty_alerts)
        .await;

    assert!(result1.is_ok());
    assert!(result2.is_ok());

    let results = runner.get_results().await;
    assert_eq!(results.len(), 2);
}

#[tokio::test]
async fn test_deterministic_test_runner_clear() {
    let schema = create_test_schema();
    let runner = DeterministicTestRunner::new(schema);

    let events = create_test_events(10);
    let _ = runner
        .run_deterministic_test("test", &events, empty_alerts)
        .await;

    assert_eq!(runner.get_results().await.len(), 1);

    runner.clear_results().await;

    assert_eq!(runner.get_results().await.len(), 0);
}

#[tokio::test]
async fn test_replay_verification_report_summary() {
    let report = ReplayVerificationReport {
        timestamp: 0,
        total_events: 100,
        total_alerts: 15,
        duration_ms: 500,
        is_deterministic: true,
        runtime_consistent: true,
        memory_peak_mb: 12.5,
        cpu_time_ms: 450,
        log_version: 1,
        schema_version: 1,
        engine_build_id: "test".to_string(),
        event_count: 100,
        mismatches: Vec::new(),
    };

    let summary = report.generate_summary();

    assert!(summary.contains("Replay Verification Report"));
    assert!(summary.contains("Events Processed: 100"));
}

#[tokio::test]
async fn test_replay_verification_report_with_mismatches() {
    let mismatches = vec![kestrel_core::VerificationMismatch {
        event_id: 42,
        expected: 1,
        actual: 0,
        details: "Expected 1 alert, got 0".to_string(),
    }];

    let report = ReplayVerificationReport {
        timestamp: 0,
        total_events: 100,
        total_alerts: 16,
        duration_ms: 500,
        is_deterministic: false,
        runtime_consistent: true,
        memory_peak_mb: 12.5,
        cpu_time_ms: 450,
        log_version: 1,
        schema_version: 1,
        engine_build_id: "test".to_string(),
        event_count: 100,
        mismatches,
    };

    let summary = report.generate_summary();

    assert!(summary.contains("Deterministic: false"));
    assert!(summary.contains("Mismatches: 1"));
}

#[tokio::test]
async fn test_replay_verification_result() {
    let result = kestrel_core::ReplayVerificationResult {
        total_events: 50,
        total_alerts: 8,
        mismatches: Vec::new(),
        is_deterministic: true,
        execution_time_ms: 250,
        memory_peak_bytes: 1024 * 1024,
        cpu_time_ms: 200,
    };

    assert!(result.is_deterministic);
    assert_eq!(result.total_events, 50);
    assert_eq!(result.total_alerts, 8);
}

#[tokio::test]
async fn test_verification_mismatch() {
    let mismatch = kestrel_core::VerificationMismatch {
        event_id: 42,
        expected: 1,
        actual: 0,
        details: "Event 42 expected 1 alert, got 0".to_string(),
    };

    assert_eq!(mismatch.event_id, 42);
    assert_eq!(mismatch.expected, 1);
    assert_eq!(mismatch.actual, 0);
}

#[tokio::test]
async fn test_deterministic_timing_consistency() {
    let schema = create_test_schema();
    let verifier = DeterministicVerifier::new(schema);

    let events = create_test_events(50);
    let result = verifier
        .verify_determinism(&events, empty_alerts)
        .await
        .unwrap();

    assert!(result.consistent);
}

#[tokio::test]
async fn test_deterministic_alert_count_stability() {
    let schema = create_test_schema();
    let verifier = DeterministicVerifier::new(schema);

    let events: Vec<Event> = (0..100)
        .map(|i| {
            Event::builder()
                .event_id((i + 1) as u64)
                .event_type(1)
                .ts_mono((i as u64 + 1) * 1_000_000_000)
                .ts_wall((i as u64 + 1) * 1_000_000_000)
                .entity_key(i as u128 % 10)
                .field(1, TypedValue::I64((i % 100) as i64))
                .build()
                .unwrap()
        })
        .collect();

    let result = verifier
        .verify_determinism(&events, empty_alerts)
        .await
        .unwrap();

    assert!(result.consistent);
}

#[tokio::test]
async fn test_replay_config_defaults() {
    let config = kestrel_core::ReplayConfig::default();

    assert_eq!(config.speed_multiplier, 1.0);
    assert!(!config.stop_on_error);
    assert!(!config.verify_determinism);
    assert!(config.expected_results_path.is_none());
    assert!(!config.record_for_verification);
    assert!(config.seed.is_none());
    assert_eq!(config.verification_runs, 3);
}
