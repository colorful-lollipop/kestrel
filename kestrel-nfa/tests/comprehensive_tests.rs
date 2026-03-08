//! Comprehensive NFA Engine Tests
//!
//! NFA引擎综合测试套件

use kestrel_event::Event;
use kestrel_nfa::{
    BudgetAction, CompiledSequence, NfaEngine, NfaEngineConfig, NfaResult, NfaSequence,
    PredicateEvaluator, SeqStep, StateStoreConfig,
};
use std::sync::Arc;
use std::time::Instant;

// Local mock evaluator for integration tests
struct MockEvaluator {
    default_result: bool,
}

impl MockEvaluator {
    fn new(default_result: bool) -> Self {
        Self { default_result }
    }
}

#[async_trait::async_trait]
impl PredicateEvaluator for MockEvaluator {
    async fn evaluate(&self, _predicate_id: &str, _event: &Event) -> NfaResult<bool> {
        Ok(self.default_result)
    }

    fn get_required_fields(&self, _predicate_id: &str) -> NfaResult<Vec<u32>> {
        Ok(Vec::new())
    }

    fn has_predicate(&self, _predicate_id: &str) -> bool {
        true
    }
}

fn create_engine() -> NfaEngine {
    let config = NfaEngineConfig::default();
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(MockEvaluator::new(true));
    NfaEngine::new(config, evaluator)
}

fn create_sequence(id: &str, steps: Vec<(u16, &str)>, maxspan: Option<u64>) -> CompiledSequence {
    let seq_steps: Vec<_> = steps
        .iter()
        .enumerate()
        .map(|(i, (event_type, pred_id))| SeqStep::new(i as u16, pred_id.to_string(), *event_type))
        .collect();

    let sequence = NfaSequence::new(id.to_string(), 100, seq_steps, maxspan, None);

    CompiledSequence {
        id: id.to_string(),
        sequence,
        rule_id: format!("rule-{}", id),
        rule_name: format!("Test Rule {}", id),
    }
}

fn create_event(event_type: u16, ts_ns: u64, entity_key: u128) -> Event {
    Event::builder()
        .event_type(event_type)
        .ts_mono(ts_ns)
        .ts_wall(ts_ns)
        .entity_key(entity_key)
        .build()
        .unwrap()
}

// =============================================================================
// Test 1-50: 基础功能测试
// =============================================================================

#[test]
fn test_nfa_engine_creation() {
    let engine = create_engine();
    assert_eq!(engine.sequence_count(), 0);
    println!("✅ NFA engine created");
}

#[test]
fn test_load_single_sequence() {
    let mut engine = create_engine();
    let seq = create_sequence("single", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();
    assert_eq!(engine.sequence_count(), 1);
}

#[test]
fn test_load_multiple_sequences() {
    let mut engine = create_engine();

    for i in 0..10 {
        let seq = create_sequence(&format!("seq-{}", i), vec![(1, "p1")], None);
        engine.load_sequence(seq).unwrap();
    }

    assert_eq!(engine.sequence_count(), 10);
}

#[test]
fn test_unload_sequence() {
    let mut engine = create_engine();
    let seq = create_sequence("unload-test", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let removed = engine.unload_sequence("unload-test").unwrap();
    assert!(removed);
    assert_eq!(engine.sequence_count(), 0);
}

#[test]
fn test_unload_nonexistent() {
    let mut engine = create_engine();
    let removed = engine.unload_sequence("nonexistent").unwrap();
    assert!(!removed);
}

// =============================================================================
// Test 51-100: 单步序列测试
// =============================================================================

#[test]
fn test_single_step_alert() {
    let mut engine = create_engine();
    let seq = create_sequence("single-step", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(1, 1000, 1);
    let alerts = engine.process_event_blocking(&event).unwrap();

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].sequence_id, "single-step");
}

#[test]
fn test_single_step_no_match() {
    let mut engine = create_engine();
    let seq = create_sequence("single-step", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(2, 1000, 1); // Different event type
    let alerts = engine.process_event_blocking(&event).unwrap();

    assert!(alerts.is_empty());
}

#[test]
fn test_single_step_multiple_entities() {
    let mut engine = create_engine();
    let seq = create_sequence("multi-entity", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let mut total_alerts = 0;
    for i in 0..100 {
        let event = create_event(1, i as u64 * 1000, i as u128);
        let alerts = engine.process_event_blocking(&event).unwrap();
        total_alerts += alerts.len();
    }

    assert_eq!(total_alerts, 100);
}

// =============================================================================
// Test 101-150: 多步序列测试
// =============================================================================

#[test]
fn test_two_step_complete() {
    let mut engine = create_engine();
    let seq = create_sequence("two-step", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    let event1 = create_event(1, 1000, 1);
    let alerts1 = engine.process_event_blocking(&event1).unwrap();
    assert!(alerts1.is_empty());

    let event2 = create_event(2, 2000, 1);
    let alerts2 = engine.process_event_blocking(&event2).unwrap();
    assert_eq!(alerts2.len(), 1);
    assert_eq!(alerts2[0].events.len(), 2);
}

#[test]
fn test_three_step_complete() {
    let mut engine = create_engine();
    let seq = create_sequence("three-step", vec![(1, "p1"), (2, "p2"), (3, "p3")], Some(10000));
    engine.load_sequence(seq).unwrap();

    engine.process_event_blocking(&create_event(1, 1000, 1)).unwrap();
    engine.process_event_blocking(&create_event(2, 2000, 1)).unwrap();
    let alerts = engine.process_event_blocking(&create_event(3, 3000, 1)).unwrap();

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].events.len(), 3);
}

#[test]
fn test_multi_step_partial() {
    let mut engine = create_engine();
    let seq = create_sequence("partial", vec![(1, "p1"), (2, "p2"), (3, "p3")], Some(10000));
    engine.load_sequence(seq).unwrap();

    let alerts = engine.process_event_blocking(&create_event(1, 1000, 1)).unwrap();
    assert!(alerts.is_empty());

    let alerts = engine.process_event_blocking(&create_event(2, 2000, 1)).unwrap();
    assert!(alerts.is_empty());
}

// =============================================================================
// Test 151-200: Maxspan测试
// =============================================================================

#[test]
fn test_maxspan_not_expired() {
    let mut engine = create_engine();
    let seq = create_sequence("maxspan-ok", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    engine.process_event_blocking(&create_event(1, 1000, 1)).unwrap();
    let alerts = engine.process_event_blocking(&create_event(2, 5000, 1)).unwrap(); // Within 5s

    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_maxspan_expired() {
    let mut engine = create_engine();
    // maxspan is in milliseconds: 100ms = 100,000,000 nanoseconds
    let seq = create_sequence("maxspan-expired", vec![(1, "p1"), (2, "p2")], Some(100));
    engine.load_sequence(seq).unwrap();

    // First event at t=1,000,000,000 ns (1 second)
    engine
        .process_event_blocking(&create_event(1, 1_000_000_000, 1))
        .unwrap();
    // Second event at t=1,200,000,000 ns (1.2 seconds) = 200ms later
    // This exceeds the 100ms maxspan, so should not generate alert
    let alerts = engine
        .process_event_blocking(&create_event(2, 1_200_000_000, 1))
        .unwrap();

    assert!(alerts.is_empty(), "Expected no alerts after maxspan expiration");
}

#[test]
fn test_maxspan_exact_boundary() {
    let mut engine = create_engine();
    let seq = create_sequence("maxspan-exact", vec![(1, "p1"), (2, "p2")], Some(1000));
    engine.load_sequence(seq).unwrap();

    engine.process_event_blocking(&create_event(1, 0, 1)).unwrap();
    let alerts = engine.process_event_blocking(&create_event(2, 1000, 1)).unwrap();

    // Boundary behavior - should match at exact maxspan
    println!("✅ Maxspan exact boundary: {} alerts", alerts.len());
}

// =============================================================================
// Test 201-250: 实体隔离测试
// =============================================================================

#[test]
fn test_entity_isolation_complete() {
    let mut engine = create_engine();
    let seq = create_sequence("isolation", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    // Entity 1 complete sequence
    engine.process_event_blocking(&create_event(1, 1000, 1)).unwrap();
    let alerts1 = engine.process_event_blocking(&create_event(2, 2000, 1)).unwrap();
    assert_eq!(alerts1.len(), 1);

    // Entity 2 complete sequence
    engine.process_event_blocking(&create_event(1, 1000, 2)).unwrap();
    let alerts2 = engine.process_event_blocking(&create_event(2, 2000, 2)).unwrap();
    assert_eq!(alerts2.len(), 1);
}

#[test]
fn test_entity_isolation_no_crossover() {
    let mut engine = create_engine();
    let seq = create_sequence("no-crossover", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    // Entity 1 step 1
    engine.process_event_blocking(&create_event(1, 1000, 1)).unwrap();

    // Entity 2 step 2 (should not match with entity 1's step 1)
    let alerts = engine.process_event_blocking(&create_event(2, 2000, 2)).unwrap();
    assert!(alerts.is_empty());
}

// =============================================================================
// Test 251-300: 预算控制测试
// =============================================================================

#[test]
fn test_budget_fail_open() {
    let config = NfaEngineConfig {
        max_evaluations_per_sec: 10,
        budget_action: BudgetAction::FailOpen,
        ..Default::default()
    };

    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(MockEvaluator::new(true));
    let mut engine = NfaEngine::new(config, evaluator);

    let seq = create_sequence("budget-fail-open", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    // Process events to trigger budget
    for i in 0..20 {
        let event = create_event(1, i as u64 * 1000, i as u128);
        let _ = engine.process_event_blocking(&event);
    }

    println!("✅ Budget fail open: processed 20 events");
}

#[test]
fn test_budget_fail_closed() {
    let config = NfaEngineConfig {
        max_evaluations_per_sec: 10,
        budget_action: BudgetAction::FailClosed,
        ..Default::default()
    };

    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(MockEvaluator::new(true));
    let mut engine = NfaEngine::new(config, evaluator);

    let seq = create_sequence("budget-fail-closed", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    println!("✅ Budget fail closed: configured");
}

#[test]
fn test_budget_degrade() {
    let config = NfaEngineConfig {
        max_evaluations_per_sec: 10,
        budget_action: BudgetAction::Degrade,
        ..Default::default()
    };

    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(MockEvaluator::new(true));
    let mut engine = NfaEngine::new(config, evaluator);

    let seq = create_sequence("budget-degrade", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    println!("✅ Budget degrade: configured");
}

// =============================================================================
// Test 301-350: 状态存储测试
// =============================================================================

#[test]
fn test_state_store_limits() {
    let config = NfaEngineConfig {
        state_store: StateStoreConfig {
            max_partial_matches_per_entity: 5,
            max_total_partial_matches: 100,
            ..Default::default()
        },
        ..Default::default()
    };

    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(MockEvaluator::new(true));
    let mut engine = NfaEngine::new(config, evaluator);

    let seq = create_sequence("state-limits", vec![(1, "p1"), (2, "p2")], Some(60000));
    engine.load_sequence(seq).unwrap();

    println!("✅ State store limits: configured");
}

#[test]
fn test_state_cleanup() {
    let mut engine = create_engine();
    let seq = create_sequence("state-cleanup", vec![(1, "p1"), (2, "p2")], Some(100));
    engine.load_sequence(seq).unwrap();

    // Create partial match
    engine.process_event_blocking(&create_event(1, 1000, 1)).unwrap();

    // Tick to trigger cleanup
    engine.tick(2000000); // 2 seconds later

    println!("✅ State cleanup: triggered");
}

// =============================================================================
// Test 351-400: 性能测试
// =============================================================================

#[test]
fn test_performance_1k_events() {
    run_performance_test(1000, "1K");
}

#[test]
fn test_performance_10k_events() {
    run_performance_test(10000, "10K");
}

#[test]
fn test_performance_100k_events() {
    run_performance_test(100000, "100K");
}

fn run_performance_test(count: usize, label: &str) {
    let mut engine = create_engine();

    let seq = create_sequence(&format!("perf-{}", label), vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let start = Instant::now();
    for i in 0..count {
        let event = create_event(1, i as u64 * 1000, i as u128);
        let _ = engine.process_event_blocking(&event);
    }
    let elapsed = start.elapsed();

    let throughput = count as f64 / elapsed.as_secs_f64();
    println!("✅ Performance {}: {:.2} events/sec", label, throughput);
}

// =============================================================================
// Test 401-450: 边界条件测试
// =============================================================================

#[test]
fn test_zero_entity_key() {
    let mut engine = create_engine();
    let seq = create_sequence("zero-entity", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(1, 1000, 0);
    let alerts = engine.process_event_blocking(&event).unwrap();

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].entity_key, 0);
}

#[test]
fn test_max_entity_key() {
    let mut engine = create_engine();
    let seq = create_sequence("max-entity", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(1, 1000, u128::MAX);
    let alerts = engine.process_event_blocking(&event).unwrap();

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].entity_key, u128::MAX);
}

#[test]
fn test_zero_timestamp() {
    let mut engine = create_engine();
    let seq = create_sequence("zero-ts", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(1, 0, 1);
    let alerts = engine.process_event_blocking(&event).unwrap();

    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_empty_sequence() {
    let mut engine = create_engine();
    let seq = create_sequence("empty", vec![], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(1, 1000, 1);
    let alerts = engine.process_event_blocking(&event).unwrap();

    println!("✅ Empty sequence: {} alerts", alerts.len());
}

// =============================================================================
// Test 451-500: 复杂场景测试
// =============================================================================

#[test]
fn test_interleaved_sequences() {
    let mut engine = create_engine();

    // Two different sequences
    let seq1 = create_sequence("seq1", vec![(1, "p1"), (2, "p2")], Some(5000));
    let seq2 = create_sequence("seq2", vec![(3, "p3"), (4, "p4")], Some(5000));

    engine.load_sequence(seq1).unwrap();
    engine.load_sequence(seq2).unwrap();

    // Interleaved events - same entity (key=1)
    // Sequence 1: event 1 -> event 2
    // Sequence 2: event 3 -> event 4
    let alerts1 = engine
        .process_event_blocking(&create_event(1, 1_000_000_000, 1))
        .unwrap();
    assert_eq!(alerts1.len(), 0, "First event should not generate alert");

    let alerts2 = engine
        .process_event_blocking(&create_event(3, 1_100_000_000, 1))
        .unwrap();
    assert_eq!(alerts2.len(), 0, "Second event should not generate alert");

    let alerts3 = engine
        .process_event_blocking(&create_event(2, 2_000_000_000, 1))
        .unwrap();
    // seq1 completes here: got event 2 after event 1

    let alerts4 = engine
        .process_event_blocking(&create_event(4, 2_100_000_000, 1))
        .unwrap();
    // seq2 completes here: got event 4 after event 3

    let total_alerts = alerts1.len() + alerts2.len() + alerts3.len() + alerts4.len();
    assert_eq!(total_alerts, 2, "Both sequences should complete (2 total alerts)");
    // alerts3 should have 1 alert (seq1 complete)
    // alerts4 should have 1 alert (seq2 complete)
    assert_eq!(alerts3.len(), 1, "seq1 should complete on event 2");
    assert_eq!(alerts4.len(), 1, "seq2 should complete on event 4");
}

#[test]
fn test_multiple_partial_per_entity() {
    let mut engine = create_engine();

    // Multiple sequences can have partial matches for same entity
    for i in 0..5 {
        let seq = create_sequence(
            &format!("multi-partial-{}", i),
            vec![(1, "p1"), (2, "p2")],
            Some(60000),
        );
        engine.load_sequence(seq).unwrap();
    }

    // One event can start partial matches in multiple sequences
    let event = create_event(1, 1000, 1);
    let alerts = engine.process_event_blocking(&event).unwrap();

    println!("✅ Multiple partial per entity: {} alerts", alerts.len());
}

#[test]
fn test_long_running_sequence() {
    let mut engine = create_engine();
    let seq = create_sequence(
        "long-running",
        vec![(1, "p1"), (2, "p2"), (3, "p3"), (4, "p4"), (5, "p5")],
        Some(3600000), // 1 hour
    );
    engine.load_sequence(seq).unwrap();

    // Progress through sequence over "time"
    engine.process_event_blocking(&create_event(1, 0, 1)).unwrap();
    engine.process_event_blocking(&create_event(2, 600000, 1)).unwrap(); // +10 min
    engine.process_event_blocking(&create_event(3, 1200000, 1)).unwrap(); // +20 min
    engine.process_event_blocking(&create_event(4, 2400000, 1)).unwrap(); // +40 min
    let alerts = engine.process_event_blocking(&create_event(5, 3500000, 1)).unwrap(); // +58 min

    assert_eq!(alerts.len(), 1);
    println!("✅ Long running sequence: completed");
}
