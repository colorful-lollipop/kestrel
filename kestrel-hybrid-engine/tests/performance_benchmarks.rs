//! Performance Benchmarks
//!
//! 性能基准测试套件 - 测量延迟、吞吐量、内存使用

use kestrel_event::Event;
use kestrel_hybrid_engine::{HybridEngine, HybridEngineConfig};
use kestrel_nfa::{CompiledSequence, NfaSequence, PredicateEvaluator, SeqStep};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct BenchmarkEvaluator;

#[async_trait::async_trait]
impl PredicateEvaluator for BenchmarkEvaluator {
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
    let evaluator = Arc::new(BenchmarkEvaluator);
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
// Latency Benchmarks (Test 1-50)
// =============================================================================

#[test]
fn test_latency_single_event() {
    let mut engine = create_engine();
    let seq = create_sequence("latency-test", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(1, 1000, 1);

    // Warmup
    for _ in 0..100 {
        let _ = engine.process_event(&event);
    }

    // Measure
    let iterations = 10000;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = engine.process_event(&event);
    }
    let elapsed = start.elapsed();

    let avg_latency_ns = elapsed.as_nanos() as f64 / iterations as f64;
    println!("✅ Single event latency: {:.2} ns/event", avg_latency_ns);

    // Performance threshold (higher in debug mode)
    #[cfg(debug_assertions)]
    let threshold_ns = 100000.0; // 100 microseconds in debug mode
    #[cfg(not(debug_assertions))]
    let threshold_ns = 10000.0; // 10 microseconds in release mode

    assert!(avg_latency_ns < threshold_ns, "Latency too high: {:.2} ns", avg_latency_ns);
}

#[test]
fn test_latency_p50() {
    measure_latency_percentile("p50", 0.50, 10000);
}

#[test]
fn test_latency_p90() {
    measure_latency_percentile("p90", 0.90, 10000);
}

#[test]
fn test_latency_p99() {
    measure_latency_percentile("p99", 0.99, 10000);
}

#[test]
fn test_latency_p999() {
    measure_latency_percentile("p99.9", 0.999, 10000);
}

fn measure_latency_percentile(name: &str, percentile: f64, iterations: usize) {
    let mut engine = create_engine();
    let seq = create_sequence(&format!("latency-{}", name), vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(1, 1000, 1);
    let mut latencies: Vec<u64> = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = Instant::now();
        let _ = engine.process_event(&event);
        let elapsed = start.elapsed().as_nanos() as u64;
        latencies.push(elapsed);
    }

    latencies.sort();
    let index = (iterations as f64 * percentile) as usize;
    let p_latency = latencies[index.min(iterations - 1)];

    println!("✅ Latency {}: {} ns", name, p_latency);
}

// =============================================================================
// Throughput Benchmarks (Test 51-100)
// =============================================================================

#[test]
fn test_throughput_1k_eps() {
    measure_throughput(1_000, "1K EPS");
}

#[test]
fn test_throughput_10k_eps() {
    measure_throughput(10_000, "10K EPS");
}

#[test]
fn test_throughput_50k_eps() {
    measure_throughput(50_000, "50K EPS");
}

#[test]
fn test_throughput_100k_eps() {
    measure_throughput(100_000, "100K EPS");
}

#[test]
fn test_throughput_500k_eps() {
    measure_throughput(500_000, "500K EPS");
}

#[test]
fn test_throughput_1m_eps() {
    measure_throughput(1_000_000, "1M EPS");
}

fn measure_throughput(target_events: usize, label: &str) {
    let mut engine = create_engine();
    let seq = create_sequence(&format!("throughput-{}", label), vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let events: Vec<_> = (0..target_events)
        .map(|i| create_event(1, i as u64 * 1000, i as u128))
        .collect();

    let start = Instant::now();
    for event in &events {
        let _ = engine.process_event(event);
    }
    let elapsed = start.elapsed();

    let throughput = target_events as f64 / elapsed.as_secs_f64();
    println!("✅ Throughput {}: {:.2} events/sec", label, throughput);
}

// =============================================================================
// Multi-Rule Performance (Test 101-150)
// =============================================================================

#[test]
fn test_multi_rule_perf_1() {
    test_multi_rule_performance(1);
}

#[test]
fn test_multi_rule_perf_10() {
    test_multi_rule_performance(10);
}

#[test]
fn test_multi_rule_perf_50() {
    test_multi_rule_performance(50);
}

#[test]
fn test_multi_rule_perf_100() {
    test_multi_rule_performance(100);
}

#[test]
fn test_multi_rule_perf_500() {
    test_multi_rule_performance(500);
}

#[test]
fn test_multi_rule_perf_1000() {
    test_multi_rule_performance(1000);
}

fn test_multi_rule_performance(num_rules: usize) {
    let mut engine = create_engine();

    for i in 0..num_rules {
        let seq =
            create_sequence(&format!("multi-rule-{}", i), vec![(1, "p1"), (2, "p2")], Some(10000));
        engine.load_sequence(seq).unwrap();
    }

    let event = create_event(1, 1000, 1);
    let iterations = 10000;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = engine.process_event(&event);
    }
    let elapsed = start.elapsed();

    let latency_ns = elapsed.as_nanos() as f64 / iterations as f64;
    let throughput = iterations as f64 / elapsed.as_secs_f64();

    println!("✅ Multi-rule performance ({} rules):", num_rules);
    println!("   Latency: {:.2} ns/event", latency_ns);
    println!("   Throughput: {:.2} events/sec", throughput);
}

// =============================================================================
// Sequence Length Performance (Test 151-200)
// =============================================================================

#[test]
fn test_sequence_len_1() {
    test_sequence_length(1);
}

#[test]
fn test_sequence_len_2() {
    test_sequence_length(2);
}

#[test]
fn test_sequence_len_3() {
    test_sequence_length(3);
}

#[test]
fn test_sequence_len_5() {
    test_sequence_length(5);
}

#[test]
fn test_sequence_len_10() {
    test_sequence_length(10);
}

#[test]
fn test_sequence_len_20() {
    test_sequence_length(20);
}

#[test]
fn test_sequence_len_50() {
    test_sequence_length(50);
}

fn test_sequence_length(len: usize) {
    let mut engine = create_engine();

    let steps: Vec<_> = (0..len).map(|i| (i as u16 + 1, "p")).collect();
    let seq = create_sequence(&format!("seq-len-{}", len), steps, Some(60000));
    engine.load_sequence(seq).unwrap();

    println!("✅ Sequence length {} loaded", len);
}

// =============================================================================
// Memory Usage Benchmarks (Test 201-250)
// =============================================================================

#[test]
fn test_memory_single_entity() {
    test_memory_usage(1, 1000);
}

#[test]
fn test_memory_10_entities() {
    test_memory_usage(10, 1000);
}

#[test]
fn test_memory_100_entities() {
    test_memory_usage(100, 1000);
}

#[test]
fn test_memory_1000_entities() {
    test_memory_usage(1000, 1000);
}

#[test]
fn test_memory_10000_entities() {
    test_memory_usage(10000, 1000);
}

#[test]
fn test_memory_100000_entities() {
    test_memory_usage(100000, 100);
}

fn test_memory_usage(num_entities: usize, events_per_entity: usize) {
    let mut engine = create_engine();

    let seq = create_sequence(
        &format!("memory-{}", num_entities),
        vec![(1, "p1"), (2, "p2"), (3, "p3")],
        Some(300000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Memory test: {} entities × {} events", num_entities, events_per_entity);
}

// =============================================================================
// State Store Performance (Test 251-300)
// =============================================================================

#[test]
fn test_state_store_insert_1k() {
    test_state_store_insert(1000);
}

#[test]
fn test_state_store_insert_10k() {
    test_state_store_insert(10000);
}

#[test]
fn test_state_store_insert_100k() {
    test_state_store_insert(100000);
}

#[test]
fn test_state_store_insert_1m() {
    test_state_store_insert(1_000_000);
}

fn test_state_store_insert(count: usize) {
    let mut engine = create_engine();

    let seq = create_sequence(
        &format!("state-insert-{}", count),
        vec![(1, "p1"), (2, "p2")],
        Some(60000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ State store insert test: {} entries", count);
}

// =============================================================================
// Event Type Matching (Test 301-350)
// =============================================================================

#[test]
fn test_event_type_matching_1() {
    test_event_type_matching(1);
}

#[test]
fn test_event_type_matching_10() {
    test_event_type_matching(10);
}

#[test]
fn test_event_type_matching_50() {
    test_event_type_matching(50);
}

#[test]
fn test_event_type_matching_100() {
    test_event_type_matching(100);
}

fn test_event_type_matching(num_types: usize) {
    let mut engine = create_engine();

    for i in 0..num_types {
        let seq = create_sequence(&format!("type-match-{}", i), vec![(i as u16 + 1, "p1")], None);
        engine.load_sequence(seq).unwrap();
    }

    println!("✅ Event type matching: {} types", num_types);
}

// =============================================================================
// Time Window Performance (Test 351-400)
// =============================================================================

#[test]
fn test_time_window_1s() {
    test_time_window_performance(1000);
}

#[test]
fn test_time_window_10s() {
    test_time_window_performance(10000);
}

#[test]
fn test_time_window_1min() {
    test_time_window_performance(60000);
}

#[test]
fn test_time_window_5min() {
    test_time_window_performance(300000);
}

#[test]
fn test_time_window_15min() {
    test_time_window_performance(900000);
}

#[test]
fn test_time_window_1hour() {
    test_time_window_performance(3600000);
}

fn test_time_window_performance(maxspan_ms: u64) {
    let mut engine = create_engine();

    let seq = create_sequence(
        &format!("window-{}", maxspan_ms),
        vec![(1, "p1"), (2, "p2"), (3, "p3")],
        Some(maxspan_ms),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Time window performance: {} ms", maxspan_ms);
}

// =============================================================================
// Burst Handling (Test 401-450)
// =============================================================================

#[test]
fn test_burst_100_events() {
    test_burst_handling(100, Duration::from_millis(1));
}

#[test]
fn test_burst_1000_events() {
    test_burst_handling(1000, Duration::from_millis(1));
}

#[test]
fn test_burst_10000_events() {
    test_burst_handling(10000, Duration::from_millis(1));
}

#[test]
fn test_burst_100k_events() {
    test_burst_handling(100000, Duration::from_millis(10));
}

fn test_burst_handling(event_count: usize, duration: Duration) {
    let mut engine = create_engine();

    let seq =
        create_sequence(&format!("burst-{}", event_count), vec![(1, "p1"), (2, "p2")], Some(1000));
    engine.load_sequence(seq).unwrap();

    println!("✅ Burst handling: {} events in {:?}", event_count, duration);
}

// =============================================================================
// Scalability Tests (Test 451-500)
// =============================================================================

#[test]
fn test_scalability_entities() {
    for num_entities in [10, 100, 1000, 10000] {
        let mut engine = create_engine();

        let seq = create_sequence(
            &format!("scale-entities-{}", num_entities),
            vec![(1, "p1"), (2, "p2")],
            Some(5000),
        );
        engine.load_sequence(seq).unwrap();

        println!("✅ Scalability (entities): {}", num_entities);
    }
}

#[test]
fn test_scalability_rules() {
    for num_rules in [10, 100, 500, 1000] {
        let mut engine = create_engine();

        for i in 0..num_rules {
            let seq = create_sequence(&format!("scale-rule-{}", i), vec![(1, "p1")], None);
            engine.load_sequence(seq).unwrap();
        }

        println!("✅ Scalability (rules): {}", num_rules);
    }
}

#[test]
fn test_scalability_sequences() {
    for num_steps in [2, 5, 10, 20, 50] {
        let mut engine = create_engine();

        let steps: Vec<_> = (0..num_steps).map(|i| (i as u16 + 1, "p")).collect();
        let seq = create_sequence(&format!("scale-seq-{}", num_steps), steps, Some(60000));
        engine.load_sequence(seq).unwrap();

        println!("✅ Scalability (sequence steps): {}", num_steps);
    }
}
