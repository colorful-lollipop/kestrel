//! Performance and Memory Tests for NFA Module
//!
//! NFA模块的性能测试和内存测试

#![allow(dead_code)]

use kestrel_event::Event;
use kestrel_nfa::*;
use std::sync::Arc;
use std::time::Instant;

// =============================================================================
// Test Helpers
// =============================================================================

struct TestEvaluator {
    results: std::collections::HashMap<String, bool>,
}

impl TestEvaluator {
    fn new() -> Self {
        Self {
            results: std::collections::HashMap::new(),
        }
    }

    fn with_result(mut self, id: &str, result: bool) -> Self {
        self.results.insert(id.to_string(), result);
        self
    }
}

#[async_trait::async_trait]
impl PredicateEvaluator for TestEvaluator {
    async fn evaluate(&self, predicate_id: &str, _event: &Event) -> NfaResult<bool> {
        Ok(self.results.get(predicate_id).copied().unwrap_or(true))
    }

    fn get_required_fields(&self, _predicate_id: &str) -> NfaResult<Vec<u32>> {
        Ok(Vec::new())
    }

    fn has_predicate(&self, predicate_id: &str) -> bool {
        self.results.contains_key(predicate_id) || predicate_id.starts_with("p")
    }
}

fn create_engine() -> NfaEngine {
    let config = NfaEngineConfig::default();
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestEvaluator::new());
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
// Throughput Performance Tests
// =============================================================================

#[test]
fn test_nfa_throughput_basic() {
    let mut engine = create_engine();

    let seq = create_sequence("throughput", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let event_counts = vec![1000, 10000, 50000];

    for count in event_counts {
        let start = Instant::now();

        for i in 0..count {
            let event = create_event(1, i as u64 * 1000, i as u128);
            let _ = engine.process_event_blocking(&event);
        }

        let elapsed = start.elapsed();
        let throughput = count as f64 / elapsed.as_secs_f64();

        println!("✅ NFA throughput ({} events): {:.0} events/sec", count, throughput);

        assert!(throughput > 1000.0, "Throughput too low: {:.0}", throughput);
    }
}

#[test]
fn test_nfa_throughput_multi_step() {
    let mut engine = create_engine();

    let seq = create_sequence("multi-step", vec![(1, "p1"), (2, "p2"), (3, "p3")], Some(60000));
    engine.load_sequence(seq).unwrap();

    let event_count = 10000;
    let start = Instant::now();

    for i in 0..event_count {
        let event = create_event((i % 3 + 1) as u16, i as u64 * 1000, (i % 100) as u128);
        let _ = engine.process_event_blocking(&event);
    }

    let elapsed = start.elapsed();
    let throughput = event_count as f64 / elapsed.as_secs_f64();

    println!("✅ NFA multi-step throughput: {:.0} events/sec", throughput);
}

// =============================================================================
// Scaling Tests
// =============================================================================

#[test]
fn test_nfa_rule_scaling() {
    let rule_counts = vec![1, 10, 50, 100];
    let event_count = 5000;

    for rule_count in rule_counts {
        let mut engine = create_engine();

        // Load rules
        for i in 0..rule_count {
            let seq = create_sequence(&format!("scale-rule-{}", i), vec![(1, "p1")], None);
            engine.load_sequence(seq).unwrap();
        }

        // Process events
        let start = Instant::now();
        for i in 0..event_count {
            let event = create_event(1, i as u64 * 1000, (i % 50) as u128);
            let _ = engine.process_event_blocking(&event);
        }
        let elapsed = start.elapsed();

        let throughput = event_count as f64 / elapsed.as_secs_f64();
        println!("✅ NFA scaling ({} rules): {:.0} events/sec", rule_count, throughput);
    }
}

#[test]
fn test_nfa_entity_scaling() {
    let entity_counts = vec![10, 100, 1000, 5000];
    let events_per_entity = 10;

    for entity_count in entity_counts {
        let mut engine = create_engine();

        let seq = create_sequence(
            &format!("entity-scale-{}", entity_count),
            vec![(1, "p1"), (2, "p2")],
            Some(300000),
        );
        engine.load_sequence(seq).unwrap();

        let start = Instant::now();

        // Create events for many entities
        for entity_id in 0..entity_count {
            for step in 0..events_per_entity {
                let event = create_event(
                    (step + 1) as u16,
                    (entity_id * events_per_entity + step + 1) as u64 * 1_000_000,
                    entity_id as u128,
                );
                let _ = engine.process_event_blocking(&event);
            }
        }

        let elapsed = start.elapsed();
        let total_events = entity_count * events_per_entity;
        let throughput = total_events as f64 / elapsed.as_secs_f64();

        println!(
            "✅ NFA entity scaling ({} entities): {:.0} events/sec",
            entity_count, throughput
        );
    }
}

// =============================================================================
// Memory Usage Tests
// =============================================================================

#[test]
fn test_nfa_memory_with_partial_matches() {
    use std::mem::size_of;

    let partial_match_size = size_of::<PartialMatch>();
    println!("✅ PartialMatch size: {} bytes", partial_match_size);

    let entity_counts = vec![100, 500, 1000];

    for entity_count in entity_counts {
        let mut engine = create_engine();

        let seq = create_sequence(
            &format!("memory-test-{}", entity_count),
            vec![(1, "p1"), (2, "p2")],
            Some(60000),
        );
        engine.load_sequence(seq).unwrap();

        // Create partial matches (only first event for each entity)
        for entity_id in 0..entity_count {
            let event = create_event(1, 1_000_000, entity_id as u128);
            let _ = engine.process_event_blocking(&event);
        }

        let estimated_memory = entity_count * partial_match_size;
        println!("   {} partial matches: ~{} KB estimated", entity_count, estimated_memory / 1024);
    }
}

// =============================================================================
// Latency Tests
// =============================================================================

#[test]
fn test_nfa_latency_distribution() {
    let mut engine = create_engine();

    let seq = create_sequence("latency", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let iterations = 50000;
    let mut latencies: Vec<u64> = Vec::with_capacity(iterations);

    // Warmup
    for _ in 0..1000 {
        let event = create_event(1, 1_000_000, 1);
        let _ = engine.process_event_blocking(&event);
    }

    // Measure
    for i in 0..iterations {
        let start = Instant::now();
        let event = create_event(1, i as u64 * 1000, (i % 100) as u128);
        let _ = engine.process_event_blocking(&event);
        let elapsed = start.elapsed().as_nanos() as u64;
        latencies.push(elapsed);
    }

    latencies.sort();

    let p50 = latencies[iterations / 2];
    let p90 = latencies[iterations * 9 / 10];
    let p99 = latencies[iterations * 99 / 100];

    println!("✅ NFA latency distribution:");
    println!("   P50: {} ns", p50);
    println!("   P90: {} ns", p90);
    println!("   P99: {} ns", p99);
}

// =============================================================================
// Budget Tests
// =============================================================================

#[test]
fn test_nfa_evaluation_budget() {
    let config = NfaEngineConfig {
        max_evaluations_per_sec: 10_000,
        max_eval_time_ns: 1_000_000, // 1ms
        budget_action: BudgetAction::FailOpen,
        ..Default::default()
    };

    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestEvaluator::new());
    let mut engine = NfaEngine::new(config, evaluator);

    let seq = create_sequence("budget-test", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let start = Instant::now();

    for i in 0..5000 {
        let event = create_event(1, i as u64 * 1000, i as u128);
        let _ = engine.process_event_blocking(&event);
    }

    let elapsed = start.elapsed();

    println!("✅ NFA with budget: 5000 events in {:?}", elapsed);
}

// =============================================================================
// State Store Performance
// =============================================================================

#[test]
fn test_state_store_performance() {
    let config = StateStoreConfig {
        max_partial_matches_per_entity: 100,
        max_total_partial_matches: 10_000,
        ..Default::default()
    };

    let nfa_config = NfaEngineConfig {
        state_store: config,
        ..Default::default()
    };

    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestEvaluator::new());
    let mut engine = NfaEngine::new(nfa_config, evaluator);

    // Load multiple sequences
    for i in 0..10 {
        let seq =
            create_sequence(&format!("state-seq-{}", i), vec![(1, "p1"), (2, "p2")], Some(60000));
        engine.load_sequence(seq).unwrap();
    }

    let start = Instant::now();

    // Create many partial matches
    for entity_id in 0..1000 {
        let event = create_event(1, 1_000_000, entity_id as u128);
        let _ = engine.process_event_blocking(&event);
    }

    let elapsed = start.elapsed();

    println!("✅ State store performance: 1000 partial matches in {:?}", elapsed);
}

// =============================================================================
// Complex Sequence Tests
// =============================================================================

#[test]
fn test_nfa_long_sequence_performance() {
    let step_counts = vec![5, 10, 20, 50];

    for step_count in step_counts {
        let mut engine = create_engine();

        let steps: Vec<_> = (0..step_count).map(|i| (i as u16 + 1, "p")).collect();

        let seq = create_sequence(&format!("long-seq-{}", step_count), steps, Some(60000));
        engine.load_sequence(seq).unwrap();

        let start = Instant::now();

        // Complete one sequence
        for i in 0..step_count {
            let event = create_event((i + 1) as u16, (i + 1) as u64 * 1_000_000, 1);
            let _ = engine.process_event_blocking(&event);
        }

        let elapsed = start.elapsed();

        println!("✅ NFA long sequence ({} steps): completed in {:?}", step_count, elapsed);
    }
}

// =============================================================================
// Concurrent Processing Tests
// =============================================================================

#[test]
fn test_nfa_concurrent_sequences() {
    let mut engine = create_engine();

    // Load multiple sequences
    for i in 0..5 {
        let seq = create_sequence(
            &format!("concurrent-seq-{}", i),
            vec![(1, "p1"), (2, "p2")],
            Some(30000),
        );
        engine.load_sequence(seq).unwrap();
    }

    let entity_count = 100;
    let start = Instant::now();

    // Process events for multiple entities
    for entity_id in 0..entity_count {
        let event1 = create_event(1, 1_000_000, entity_id as u128);
        let _ = engine.process_event_blocking(&event1);

        let event2 = create_event(2, 2_000_000, entity_id as u128);
        let _ = engine.process_event_blocking(&event2);
    }

    let elapsed = start.elapsed();
    let throughput = (entity_count * 2) as f64 / elapsed.as_secs_f64();

    println!("✅ NFA concurrent sequences: {:.0} events/sec", throughput);
}

// =============================================================================
// Maxspan Boundary Tests
// =============================================================================

#[test]
fn test_maxspan_boundary_performance() {
    let mut engine = create_engine();

    let seq = create_sequence("maxspan-perf", vec![(1, "p1"), (2, "p2")], Some(1000));
    engine.load_sequence(seq).unwrap();

    let start = Instant::now();

    // Events exactly at boundary
    for i in 0..1000 {
        let base_ts = i as u64 * 1_000_000_000;
        let event1 = create_event(1, base_ts, i as u128);
        let _ = engine.process_event_blocking(&event1);

        let event2 = create_event(2, base_ts + 1_000_000_000, i as u128); // Exactly at 1000ms boundary
        let _ = engine.process_event_blocking(&event2);
    }

    let elapsed = start.elapsed();

    println!("✅ Maxspan boundary performance: 2000 events in {:?}", elapsed);
}
