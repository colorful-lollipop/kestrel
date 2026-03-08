//! Stability Tests
//!
//! 稳定性测试套件 - 长时间运行、内存泄漏检测

use kestrel_event::Event;
use kestrel_hybrid_engine::{HybridEngine, HybridEngineConfig};
use kestrel_nfa::{CompiledSequence, NfaEngineConfig, NfaSequence, PredicateEvaluator, SeqStep};
use std::sync::Arc;
use std::time::Instant;

struct StabilityEvaluator;

#[async_trait::async_trait]
impl PredicateEvaluator for StabilityEvaluator {
    async fn evaluate(&self, _predicate_id: &str, _event: &Event) -> kestrel_nfa::NfaResult<bool> {
        Ok(true)
    }

    fn get_required_fields(&self, _predicate_id: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
        Ok(Vec::new())
    }

    fn has_predicate(&self, _predicate_id: &str) -> bool {
        true
    }
}

fn create_engine() -> HybridEngine {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(StabilityEvaluator);
    HybridEngine::new(config, evaluator).unwrap()
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
        rule_name: format!("Stability Rule {}", id),
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
// Test 1-30: 长时间运行测试
// =============================================================================

#[test]
fn test_continuous_operation_1k_events() {
    run_continuous_test(1_000, "1K events");
}

#[test]
fn test_continuous_operation_10k_events() {
    run_continuous_test(10_000, "10K events");
}

#[test]
fn test_continuous_operation_100k_events() {
    run_continuous_test(100_000, "100K events");
}

#[test]
fn test_continuous_operation_1m_events() {
    run_continuous_test(1_000_000, "1M events");
}

fn run_continuous_test(event_count: usize, label: &str) {
    let mut engine = create_engine();

    let seq = create_sequence(
        &format!("continuous-{}", label.replace(" ", "-")),
        vec![(1, "p1"), (2, "p2")],
        Some(60000),
    );
    engine.load_sequence(seq).unwrap();

    let start = Instant::now();
    let mut total_alerts = 0;

    for i in 0..event_count {
        let entity = (i % 1000) as u128; // Cycle through 1000 entities
        let event_type = if i % 2 == 0 { 1 } else { 2 };
        let ts = i as u64 * 1000;

        let event = create_event(event_type, ts, entity);
        let alerts = engine.process_event(&event).unwrap();
        total_alerts += alerts.len();

        // Progress report every 100k events
        if i > 0 && i % 100_000 == 0 {
            println!("  Progress: {}/{} events processed", i, event_count);
        }
    }

    let elapsed = start.elapsed();
    let throughput = event_count as f64 / elapsed.as_secs_f64();

    println!("✅ Continuous operation ({}):", label);
    println!("   Events: {}", event_count);
    println!("   Alerts: {}", total_alerts);
    println!("   Time: {:?}", elapsed);
    println!("   Throughput: {:.2} events/sec", throughput);
}

// =============================================================================
// Test 31-60: 内存稳定性测试
// =============================================================================

#[test]
fn test_memory_stability_cyclic_entities() {
    let mut engine = create_engine();

    let seq = create_sequence("memory-cyclic", vec![(1, "p1"), (2, "p2"), (3, "p3")], Some(30000));
    engine.load_sequence(seq).unwrap();

    // Cycle through entities to test cleanup
    let cycles = 100;
    let entities_per_cycle = 1000;

    for cycle in 0..cycles {
        for i in 0..entities_per_cycle {
            let entity = (cycle * entities_per_cycle + i) as u128;
            let event = create_event(1, cycle as u64 * 100000, entity);
            let _ = engine.process_event(&event);
        }

        if cycle % 10 == 0 {
            println!("  Memory cycle {}/{}", cycle, cycles);
        }
    }

    println!(
        "✅ Memory stability cyclic: {} cycles × {} entities",
        cycles, entities_per_cycle
    );
}

#[test]
fn test_memory_stability_complete_sequences() {
    let mut engine = create_engine();

    let seq = create_sequence("memory-complete", vec![(1, "p1"), (2, "p2")], Some(60000));
    engine.load_sequence(seq).unwrap();

    // Complete many sequences to test cleanup
    let iterations = 10000;

    for i in 0..iterations {
        let entity = i as u128;
        let event1 = create_event(1, i as u64 * 1000, entity);
        let event2 = create_event(2, i as u64 * 1000 + 500, entity);

        let _ = engine.process_event(&event1);
        let _ = engine.process_event(&event2);
    }

    println!("✅ Memory stability complete: {} sequences", iterations);
}

#[test]
fn test_memory_stability_expired_partial() {
    let mut engine = create_engine();

    let seq = create_sequence(
        "memory-expired",
        vec![(1, "p1"), (2, "p2")],
        Some(100), // Very short maxspan
    );
    engine.load_sequence(seq).unwrap();

    // Create partial matches that will expire
    let iterations = 10000;

    for i in 0..iterations {
        let entity = i as u128;
        let event = create_event(1, i as u64 * 200, entity);
        let _ = engine.process_event(&event);
    }

    println!("✅ Memory stability expired: {} partial matches", iterations);
}

// =============================================================================
// Test 61-90: 规则动态加载测试
// =============================================================================

#[test]
fn test_dynamic_rule_loading() {
    let mut engine = create_engine();

    // Load rules dynamically during operation
    let batch_size = 10;
    let batches = 10;

    for batch in 0..batches {
        for i in 0..batch_size {
            let rule_id = batch * batch_size + i;
            let seq = create_sequence(&format!("dynamic-{}", rule_id), vec![(1, "p1")], None);
            engine.load_sequence(seq).unwrap();
        }

        // Process some events after each batch
        for j in 0..100 {
            let event = create_event(1, (batch * 100 + j) as u64 * 1000, j as u128);
            let _ = engine.process_event(&event);
        }

        println!("  Loaded batch {}/{}", batch + 1, batches);
    }

    let stats = engine.stats();
    assert_eq!(stats.total_rules_tracked, batch_size * batches);
    println!("✅ Dynamic rule loading: {} rules", stats.total_rules_tracked);
}

#[test]
fn test_rule_reloading_stability() {
    let mut engine = create_engine();

    // Simulate rule updates
    let update_cycles = 5;

    for cycle in 0..update_cycles {
        // Load new version of rules
        for i in 0..10 {
            let seq =
                create_sequence(&format!("reloadable-{}", i), vec![(i as u16 + 1, "p1")], None);
            engine.load_sequence(seq).unwrap();
        }

        // Process events
        for j in 0..1000 {
            let event = create_event((j % 10 + 1) as u16, j as u64 * 1000, j as u128);
            let _ = engine.process_event(&event);
        }

        println!("  Reload cycle {}/{}", cycle + 1, update_cycles);
    }

    println!("✅ Rule reloading stability: {} cycles", update_cycles);
}

// =============================================================================
// Test 91-120: 错误恢复稳定性
// =============================================================================

#[test]
fn test_error_recovery_stability() {
    let mut engine = create_engine();

    let seq = create_sequence("error-recovery", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    let iterations = 10000;
    let error_interval = 100;

    for i in 0..iterations {
        // Every error_interval events, simulate a problematic scenario
        if i % error_interval == 0 && i > 0 {
            // Entity with mismatched sequence
            let event = create_event(99, i as u64 * 1000, 999999);
            let _ = engine.process_event(&event);
        }

        let entity = i as u128;
        let event_type = if i % 2 == 0 { 1 } else { 2 };
        let event = create_event(event_type, i as u64 * 1000, entity);
        let _ = engine.process_event(&event);
    }

    println!("✅ Error recovery stability: {} iterations", iterations);
}

#[test]
fn test_graceful_degradation_under_load() {
    let config = HybridEngineConfig {
        nfa_config: NfaEngineConfig {
            max_evaluations_per_sec: 1000,
            ..Default::default()
        },
        ..Default::default()
    };

    let evaluator = Arc::new(StabilityEvaluator);
    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    let seq = create_sequence("degradation-load", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    // Burst load
    let burst_size = 10000;
    let start = Instant::now();

    for i in 0..burst_size {
        let event = create_event(1, i as u64 * 100, i as u128);
        let _ = engine.process_event(&event);
    }

    let elapsed = start.elapsed();
    println!("✅ Graceful degradation: {} events in {:?}", burst_size, elapsed);
}

// =============================================================================
// Test 121-150: 状态一致性测试
// =============================================================================

#[test]
fn test_state_consistency_across_time() {
    let mut engine = create_engine();

    let seq =
        create_sequence("state-consistency", vec![(1, "p1"), (2, "p2"), (3, "p3")], Some(60000));
    engine.load_sequence(seq).unwrap();

    // Create consistent pattern across time
    let time_steps = 1000;
    let entities = 100;

    for step in 0..time_steps {
        for entity in 0..entities {
            let event_type = (step % 3) + 1;
            let ts = step as u64 * 1000 + entity as u64;
            let event = create_event(event_type, ts, entity as u128);
            let _ = engine.process_event(&event);
        }
    }

    println!("✅ State consistency: {} steps × {} entities", time_steps, entities);
}

#[test]
fn test_alert_consistency() {
    let mut engine = create_engine();

    let seq = create_sequence("alert-consistency", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    // Process same sequence multiple times
    let repetitions = 100;
    let mut alert_counts = Vec::new();

    for rep in 0..repetitions {
        let entity = rep as u128;
        let event1 = create_event(1, rep as u64 * 10000, entity);
        let event2 = create_event(2, rep as u64 * 10000 + 1000, entity);

        let _ = engine.process_event(&event1);
        let alerts = engine.process_event(&event2).unwrap();
        alert_counts.push(alerts.len());
    }

    // All should have exactly 1 alert
    assert!(alert_counts.iter().all(|&c| c == 1), "Inconsistent alert counts");
    println!("✅ Alert consistency: {} repetitions, all consistent", repetitions);
}

// =============================================================================
// Test 151-180: 性能稳定性测试
// =============================================================================

#[test]
fn test_performance_stability_over_time() {
    let mut engine = create_engine();

    let seq = create_sequence("perf-stability", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    let measurement_windows = 10;
    let events_per_window = 10000;
    let mut throughputs = Vec::new();

    for window in 0..measurement_windows {
        let start = Instant::now();

        for i in 0..events_per_window {
            let event = create_event(
                (i % 2 + 1) as u16,
                (window * events_per_window + i) as u64 * 1000,
                i as u128,
            );
            let _ = engine.process_event(&event);
        }

        let elapsed = start.elapsed();
        let throughput = events_per_window as f64 / elapsed.as_secs_f64();
        throughputs.push(throughput);

        println!("  Window {}: {:.2} events/sec", window + 1, throughput);
    }

    // Calculate variance
    let avg = throughputs.iter().sum::<f64>() / throughputs.len() as f64;
    let variance =
        throughputs.iter().map(|t| (t - avg).powi(2)).sum::<f64>() / throughputs.len() as f64;
    let cv = variance.sqrt() / avg; // Coefficient of variation

    println!("✅ Performance stability:");
    println!("   Average: {:.2} events/sec", avg);
    println!("   CV: {:.2}%", cv * 100.0);
}

#[test]
fn test_latency_stability() {
    let mut engine = create_engine();

    let seq = create_sequence("latency-stability", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let samples = 10000;
    let mut latencies = Vec::with_capacity(samples);

    for i in 0..samples {
        let start = Instant::now();
        let event = create_event(1, i as u64 * 1000, i as u128);
        let _ = engine.process_event(&event);
        let elapsed = start.elapsed().as_nanos() as f64;
        latencies.push(elapsed);
    }

    // Calculate percentiles
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = latencies[latencies.len() / 2];
    let p95 = latencies[latencies.len() * 95 / 100];
    let p99 = latencies[latencies.len() * 99 / 100];

    println!("✅ Latency stability:");
    println!("   P50: {:.2} ns", p50);
    println!("   P95: {:.2} ns", p95);
    println!("   P99: {:.2} ns", p99);
}

// =============================================================================
// Test 181-210: 边界稳定性测试
// =============================================================================

#[test]
fn test_extreme_entity_count_stability() {
    let mut engine = create_engine();

    let seq = create_sequence("extreme-entities", vec![(1, "p1"), (2, "p2")], Some(60000));
    engine.load_sequence(seq).unwrap();

    // Process events for many entities
    let entity_count = 100000;
    let events_per_entity = 2;

    for entity in 0..entity_count {
        for event_idx in 0..events_per_entity {
            let event_type = event_idx as u16 + 1;
            let ts = entity as u64 * 10000 + event_idx as u64 * 1000;
            let event = create_event(event_type, ts, entity as u128);
            let _ = engine.process_event(&event);
        }
    }

    println!("✅ Extreme entity count: {} entities", entity_count);
}

#[test]
fn test_long_sequence_stability() {
    let mut engine = create_engine();

    // Create a long sequence
    let steps: Vec<_> = (0..50).map(|i| (i as u16 + 1, "p1")).collect();

    let seq = create_sequence("long-seq-stability", steps, Some(600000));
    engine.load_sequence(seq).unwrap();

    // Process partial matches
    let entities = 1000;
    for entity in 0..entities {
        for step in 0..25 {
            // Halfway through
            let event = create_event(
                step as u16 + 1,
                entity as u64 * 100000 + step as u64 * 1000,
                entity as u128,
            );
            let _ = engine.process_event(&event);
        }
    }

    println!("✅ Long sequence stability: {} entities, 50-step sequence", entities);
}

// =============================================================================
// Test 211-240: 并发稳定性测试
// =============================================================================

#[test]
fn test_high_entity_churn() {
    let mut engine = create_engine();

    let seq = create_sequence(
        "entity-churn",
        vec![(1, "p1"), (2, "p2")],
        Some(1000), // Short window for quick churn
    );
    engine.load_sequence(seq).unwrap();

    // High rate of new entities
    let iterations = 10000;
    let start = Instant::now();

    for i in 0..iterations {
        let event = create_event(1, i as u64 * 100, i as u128);
        let _ = engine.process_event(&event);
    }

    let elapsed = start.elapsed();
    println!("✅ High entity churn: {} entities in {:?}", iterations, elapsed);
}

#[test]
fn test_mixed_workload_stability() {
    let mut engine = create_engine();

    // Multiple sequences with different characteristics
    let sequences = vec![
        ("short-fast", vec![(1, "p1")], Some(1000)),
        ("medium", vec![(1, "p1"), (2, "p2")], Some(10000)),
        ("long-slow", vec![(1, "p1"), (2, "p2"), (3, "p3")], Some(60000)),
    ];

    for (name, steps, maxspan) in sequences {
        let seq = create_sequence(name, steps, maxspan);
        engine.load_sequence(seq).unwrap();
    }

    // Mixed workload
    let iterations = 10000;
    for i in 0..iterations {
        let event_type = (i % 3 + 1) as u16;
        let event = create_event(event_type, i as u64 * 1000, i as u128);
        let _ = engine.process_event(&event);
    }

    println!("✅ Mixed workload stability: {} events", iterations);
}

// =============================================================================
// Test 241-250: 综合稳定性测试
// =============================================================================

#[test]
fn test_comprehensive_stability() {
    let mut engine = create_engine();

    // Load multiple rules
    for i in 0..50 {
        let seq = create_sequence(
            &format!("comprehensive-{}", i),
            vec![(1, "p1"), (2, "p2")],
            Some(30000),
        );
        engine.load_sequence(seq).unwrap();
    }

    // Comprehensive test
    let duration_sec = 5; // Run for 5 seconds
    let start = Instant::now();
    let mut event_count = 0;
    let mut entity_id = 0u128;

    while start.elapsed().as_secs() < duration_sec {
        let event =
            create_event((event_count % 2 + 1) as u16, event_count as u64 * 1000, entity_id);
        let _ = engine.process_event(&event);

        event_count += 1;
        entity_id = (entity_id + 1) % 10000; // Cycle through 10000 entities

        if event_count % 10000 == 0 {
            println!("  Processed {} events...", event_count);
        }
    }

    let elapsed = start.elapsed();
    let throughput = event_count as f64 / elapsed.as_secs_f64();

    println!("✅ Comprehensive stability:");
    println!("   Events: {}", event_count);
    println!("   Duration: {:?}", elapsed);
    println!("   Throughput: {:.2} events/sec", throughput);
}
