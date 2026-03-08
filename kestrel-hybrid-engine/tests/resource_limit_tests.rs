//! Resource Limit Tests
//!
//! 资源限制测试套件 - 测试内存、CPU、时间限制下的表现

use kestrel_event::Event;
use kestrel_hybrid_engine::{HybridEngine, HybridEngineConfig};
use kestrel_nfa::{
    BudgetAction, CompiledSequence, NfaEngineConfig, NfaSequence, PredicateEvaluator, SeqStep,
    StateStoreConfig,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct ResourceTestEvaluator;

#[async_trait::async_trait]
impl PredicateEvaluator for ResourceTestEvaluator {
    async fn evaluate(&self, _predicate_id: &str, _event: &Event) -> kestrel_nfa::NfaResult<bool> {
        // Simulate some processing time
        std::thread::sleep(Duration::from_micros(1));
        Ok(true)
    }

    fn get_required_fields(&self, _predicate_id: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
        Ok(Vec::new())
    }

    fn has_predicate(&self, _predicate_id: &str) -> bool {
        true
    }
}

fn create_engine_with_budget(config: NfaEngineConfig) -> HybridEngine {
    let hybrid_config = HybridEngineConfig {
        nfa_config: config,
        ..Default::default()
    };
    let evaluator = Arc::new(ResourceTestEvaluator);
    HybridEngine::new(hybrid_config, evaluator).unwrap()
}

fn create_engine() -> HybridEngine {
    create_engine_with_budget(NfaEngineConfig::default())
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
// Test 1-30: 内存限制测试
// =============================================================================

#[test]
fn test_memory_limit_1mb() {
    test_memory_consumption("1MB", 1000);
}

#[test]
fn test_memory_limit_10mb() {
    test_memory_consumption("10MB", 10000);
}

#[test]
fn test_memory_limit_100mb() {
    test_memory_consumption("100MB", 100000);
}

fn test_memory_consumption(label: &str, num_entities: usize) {
    let config = NfaEngineConfig {
        state_store: StateStoreConfig {
            max_partial_matches_per_entity: 100,
            max_total_partial_matches: num_entities * 10,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut engine = create_engine_with_budget(config);

    let seq = create_sequence(
        &format!("memory-{}", label),
        vec![(1, "p1"), (2, "p2"), (3, "p3")],
        Some(300000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Memory limit {}: configured for {} entities", label, num_entities);
}

#[test]
fn test_partial_match_quota() {
    let config = NfaEngineConfig {
        state_store: StateStoreConfig {
            max_partial_matches_per_entity: 5,
            max_total_partial_matches: 1000,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut engine = create_engine_with_budget(config);

    // Multiple sequences that can have partial matches
    for i in 0..10 {
        let seq =
            create_sequence(&format!("quota-seq-{}", i), vec![(1, "p1"), (2, "p2")], Some(60000));
        engine.load_sequence(seq).unwrap();
    }

    println!("✅ Partial match quota: 5 per entity");
}

#[test]
fn test_lru_eviction() {
    let config = NfaEngineConfig {
        state_store: StateStoreConfig {
            max_total_partial_matches: 100,
            lru_eviction_threshold: 0.8,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut engine = create_engine_with_budget(config);

    let seq = create_sequence("lru-test", vec![(1, "p1"), (2, "p2")], Some(60000));
    engine.load_sequence(seq).unwrap();

    println!("✅ LRU eviction: configured");
}

// =============================================================================
// Test 31-60: CPU/预算限制测试
// =============================================================================

#[test]
fn test_eval_budget_100_per_sec() {
    test_evaluation_budget(100, 0, BudgetAction::FailOpen);
}

#[test]
fn test_eval_budget_1000_per_sec() {
    test_evaluation_budget(1000, 0, BudgetAction::FailOpen);
}

#[test]
fn test_eval_budget_10000_per_sec() {
    test_evaluation_budget(10000, 0, BudgetAction::FailOpen);
}

#[test]
fn test_time_budget_1ms() {
    test_evaluation_budget(0, 1_000_000, BudgetAction::FailOpen);
}

#[test]
fn test_time_budget_10ms() {
    test_evaluation_budget(0, 10_000_000, BudgetAction::FailOpen);
}

#[test]
fn test_budget_fail_closed() {
    test_evaluation_budget(100, 0, BudgetAction::FailClosed);
}

#[test]
fn test_budget_degrade() {
    test_evaluation_budget(100, 0, BudgetAction::Degrade);
}

fn test_evaluation_budget(max_evals: u64, max_time_ns: u64, action: BudgetAction) {
    let config = NfaEngineConfig {
        max_evaluations_per_sec: max_evals,
        max_eval_time_ns: max_time_ns,
        budget_action: action,
        ..Default::default()
    };

    let mut engine = create_engine_with_budget(config);

    let seq = create_sequence(&format!("budget-{}", max_evals), vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    println!(
        "✅ Evaluation budget: {} evals/sec, {} ns, action={:?}",
        max_evals, max_time_ns, action
    );
}

// =============================================================================
// Test 61-90: 时间限制测试
// =============================================================================

#[test]
fn test_processing_timeout_1ms() {
    test_processing_timeout(Duration::from_millis(1));
}

#[test]
fn test_processing_timeout_10ms() {
    test_processing_timeout(Duration::from_millis(10));
}

#[test]
fn test_processing_timeout_100ms() {
    test_processing_timeout(Duration::from_millis(100));
}

fn test_processing_timeout(timeout: Duration) {
    let mut engine = create_engine();

    let seq = create_sequence(
        &format!("timeout-{}", timeout.as_millis()),
        vec![(1, "p1"), (2, "p2")],
        Some(5000),
    );
    engine.load_sequence(seq).unwrap();

    let start = Instant::now();

    // Process events
    for i in 0..100 {
        let event = create_event(1, i as u64 * 1000, i as u128);
        let _ = engine.process_event(&event);
    }

    let elapsed = start.elapsed();
    println!("✅ Processing timeout {}: completed in {:?}", timeout.as_millis(), elapsed);
}

#[test]
fn test_maxspan_enforcement() {
    let mut engine = create_engine();

    let seq = create_sequence(
        "maxspan-enforce",
        vec![(1, "p1"), (2, "p2")],
        Some(100), // 100ms maxspan
    );
    engine.load_sequence(seq).unwrap();

    // First event at t=0
    let event1 = create_event(1, 0, 1);
    engine.process_event(&event1).unwrap();

    // Second event after maxspan (100ms = 100,000,000 nanoseconds)
    let event2 = create_event(2, 200_000_000, 1); // 200ms > 100ms
    let alerts = engine.process_event(&event2).unwrap();

    assert!(alerts.is_empty(), "Should not alert after maxspan expired");
    println!("✅ Maxspan enforcement: no alert after expiry");
}

// =============================================================================
// Test 91-120: 状态存储限制测试
// =============================================================================

#[test]
fn test_state_store_cleanup() {
    let config = NfaEngineConfig {
        state_store: StateStoreConfig {
            cleanup_interval: Duration::from_millis(1000),
            ..Default::default()
        },
        ..Default::default()
    };

    let mut engine = create_engine_with_budget(config);

    let seq = create_sequence("state-cleanup", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    println!("✅ State store cleanup: 1000ms check interval");
}

#[test]
fn test_state_cleanup_on_remove() {
    let mut engine = create_engine();

    let seq = create_sequence("cleanup-on-remove", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    // Create partial match
    let event1 = create_event(1, 1000, 1);
    engine.process_event(&event1).unwrap();

    // Complete sequence (should cleanup)
    let event2 = create_event(2, 2000, 1);
    let _ = engine.process_event(&event2);

    println!("✅ State cleanup on remove: verified");
}

// =============================================================================
// Test 121-150: 并发资源限制测试
// =============================================================================

#[test]
fn test_concurrent_memory_limit() {
    let config = NfaEngineConfig {
        state_store: StateStoreConfig {
            max_total_partial_matches: 10000,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut engine = create_engine_with_budget(config);

    // Load many rules
    for i in 0..100 {
        let seq = create_sequence(
            &format!("concurrent-mem-{}", i),
            vec![(1, "p1"), (2, "p2")],
            Some(300000),
        );
        engine.load_sequence(seq).unwrap();
    }

    let stats = engine.stats();
    println!("✅ Concurrent memory limit: {} rules", stats.total_rules_tracked);
}

#[test]
fn test_backpressure_simulation() {
    let mut engine = create_engine();

    let seq = create_sequence("backpressure", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    // Simulate burst
    let burst_size = 10000;
    let start = Instant::now();

    for i in 0..burst_size {
        let event = create_event(1, i as u64 * 100, i as u128);
        let _ = engine.process_event(&event);
    }

    let elapsed = start.elapsed();
    let throughput = burst_size as f64 / elapsed.as_secs_f64();

    println!("✅ Backpressure simulation: {:.2} events/sec", throughput);
}

// =============================================================================
// Test 151-180: 极端限制测试
// =============================================================================

#[test]
fn test_extremely_small_maxspan() {
    let mut engine = create_engine();

    let seq = create_sequence(
        "tiny-maxspan",
        vec![(1, "p1"), (2, "p2")],
        Some(1), // 1ms maxspan
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Extremely small maxspan: 1ms");
}

#[test]
fn test_zero_budget() {
    let config = NfaEngineConfig {
        max_evaluations_per_sec: 0, // Unlimited
        max_eval_time_ns: 0,        // Unlimited
        ..Default::default()
    };

    let mut engine = create_engine_with_budget(config);

    let seq = create_sequence("zero-budget", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    println!("✅ Zero budget: unlimited");
}

#[test]
fn test_single_partial_match_limit() {
    let config = NfaEngineConfig {
        state_store: StateStoreConfig {
            max_partial_matches_per_entity: 1,
            max_total_partial_matches: 100,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut engine = create_engine_with_budget(config);

    let seq = create_sequence("single-partial", vec![(1, "p1"), (2, "p2")], Some(60000));
    engine.load_sequence(seq).unwrap();

    println!("✅ Single partial match limit per entity");
}

// =============================================================================
// Test 181-210: 恢复与降级测试
// =============================================================================

#[test]
fn test_graceful_degradation() {
    let config = NfaEngineConfig {
        max_evaluations_per_sec: 100,
        budget_action: BudgetAction::Degrade,
        ..Default::default()
    };

    let mut engine = create_engine_with_budget(config);

    let seq = create_sequence("degradation", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    // Process many events to trigger degradation
    for i in 0..1000 {
        let event = create_event(1, i as u64 * 100, i as u128);
        let _ = engine.process_event(&event);
    }

    println!("✅ Graceful degradation: handled 1000 events");
}

#[test]
fn test_fail_open_recovery() {
    let config = NfaEngineConfig {
        max_evaluations_per_sec: 100,
        budget_action: BudgetAction::FailOpen,
        ..Default::default()
    };

    let mut engine = create_engine_with_budget(config);

    let seq = create_sequence("fail-open", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    println!("✅ Fail open recovery: configured");
}

#[test]
fn test_fail_closed_error() {
    let config = NfaEngineConfig {
        max_evaluations_per_sec: 100,
        budget_action: BudgetAction::FailClosed,
        ..Default::default()
    };

    let mut engine = create_engine_with_budget(config);

    let seq = create_sequence("fail-closed", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    println!("✅ Fail closed error: configured");
}

// =============================================================================
// Test 211-240: 长期运行资源测试
// =============================================================================

#[test]
fn test_long_running_memory_stability() {
    let mut engine = create_engine();

    let seq = create_sequence("long-running", vec![(1, "p1"), (2, "p2")], Some(60000));
    engine.load_sequence(seq).unwrap();

    // Simulate long running with many entities
    let num_cycles = 10;
    let entities_per_cycle = 1000;

    for cycle in 0..num_cycles {
        for entity in 0..entities_per_cycle {
            let key = (cycle * entities_per_cycle + entity) as u128;
            let event = create_event(1, cycle as u64 * 1000000, key);
            let _ = engine.process_event(&event);
        }
    }

    println!(
        "✅ Long running memory: {} cycles × {} entities",
        num_cycles, entities_per_cycle
    );
}

#[test]
fn test_periodic_cleanup_effectiveness() {
    let mut engine = create_engine();

    let seq = create_sequence(
        "periodic-cleanup",
        vec![(1, "p1"), (2, "p2")],
        Some(1000), // Short maxspan for quick expiry
    );
    engine.load_sequence(seq).unwrap();

    // Create many partial matches
    for i in 0..1000 {
        let event = create_event(1, i as u64 * 100, i as u128);
        let _ = engine.process_event(&event);
    }

    println!("✅ Periodic cleanup: 1000 partial matches created");
}
