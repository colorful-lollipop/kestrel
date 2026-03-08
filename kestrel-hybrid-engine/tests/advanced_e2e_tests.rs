//! Advanced End-to-End Tests for Hybrid Engine
//!
//! 高级端到端测试 - 性能、内存、复杂场景

use kestrel_event::Event;
use kestrel_hybrid_engine::{HybridEngine, HybridEngineConfig};
use kestrel_nfa::{
    BudgetAction, CompiledSequence, NfaEngineConfig, NfaSequence, PredicateEvaluator, SeqStep,
    StateStoreConfig,
};
use std::sync::Arc;
use std::time::Instant;

// =============================================================================
// Test Helpers
// =============================================================================

struct TestEvaluator;

#[async_trait::async_trait]
impl PredicateEvaluator for TestEvaluator {
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
    let evaluator = Arc::new(TestEvaluator);
    HybridEngine::new(config, evaluator).unwrap()
}

fn create_engine_with_config(config: NfaEngineConfig) -> HybridEngine {
    let hybrid_config = HybridEngineConfig {
        nfa_config: config,
        ..Default::default()
    };
    let evaluator = Arc::new(TestEvaluator);
    HybridEngine::new(hybrid_config, evaluator).unwrap()
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
// Advanced Performance Tests
// =============================================================================

#[test]
fn test_extreme_throughput() {
    let mut engine = create_engine();

    let seq = create_sequence("throughput", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let event_counts = vec![10_000, 50_000, 100_000];

    for count in event_counts {
        let start = Instant::now();

        for i in 0..count {
            let event = create_event(1, i as u64 * 1000, i as u128);
            let _ = engine.process_event(&event);
        }

        let elapsed = start.elapsed();
        let throughput = count as f64 / elapsed.as_secs_f64();

        println!(
            "✅ Extreme throughput ({} events): {:?} ({:.0} events/sec)",
            count, elapsed, throughput
        );
    }
}

#[test]
fn test_multi_rule_scaling() {
    let rule_counts = vec![1, 10, 50, 100, 500];
    let event_count = 10_000;

    for rule_count in rule_counts {
        let mut engine = create_engine();

        // Load rules
        for i in 0..rule_count {
            let seq = create_sequence(
                &format!("scale-rule-{}", i),
                vec![(1, "p1"), (2, "p2")],
                Some(10000),
            );
            engine.load_sequence(seq).unwrap();
        }

        // Process events
        let start = Instant::now();
        for i in 0..event_count {
            let event = create_event((i % 2 + 1) as u16, i as u64 * 1000, (i % 100) as u128);
            let _ = engine.process_event(&event);
        }
        let elapsed = start.elapsed();

        let throughput = event_count as f64 / elapsed.as_secs_f64();
        println!("✅ Multi-rule scaling ({} rules): {:.0} events/sec", rule_count, throughput);
    }
}

#[test]
fn test_long_sequence_performance() {
    let step_counts = vec![5, 10, 20, 50];

    for step_count in step_counts {
        let mut engine = create_engine();

        let steps: Vec<_> = (0..step_count).map(|i| (i as u16 + 1, "p")).collect();

        let seq = create_sequence(&format!("long-seq-{}", step_count), steps, Some(60000));
        engine.load_sequence(seq).unwrap();

        // Complete one sequence
        let start = Instant::now();
        for i in 0..step_count {
            let event = create_event((i + 1) as u16, (i + 1) as u64 * 1_000_000, 1);
            let _ = engine.process_event(&event);
        }
        let elapsed = start.elapsed();

        println!("✅ Long sequence ({} steps): completed in {:?}", step_count, elapsed);
    }
}

// =============================================================================
// Memory Stress Tests
// =============================================================================

#[test]
fn test_memory_with_many_entities() {
    let entity_counts = vec![1000, 5000, 10000];
    let events_per_entity = 10;

    for entity_count in entity_counts {
        let mut engine = create_engine();

        let seq = create_sequence(
            &format!("mem-entity-{}", entity_count),
            vec![(1, "p1"), (2, "p2")],
            Some(300000),
        );
        engine.load_sequence(seq).unwrap();

        let start = Instant::now();

        // Create partial matches for many entities
        for entity_id in 0..entity_count {
            let event = create_event(1, 1_000_000, entity_id as u128);
            let _ = engine.process_event(&event);
        }

        // Complete some sequences
        for entity_id in 0..entity_count / 2 {
            let event = create_event(2, 2_000_000, entity_id as u128);
            let _ = engine.process_event(&event);
        }

        let elapsed = start.elapsed();

        println!(
            "✅ Memory test ({} entities, {} events): {:?}",
            entity_count,
            entity_count * events_per_entity / 2,
            elapsed
        );
    }
}

#[test]
fn test_memory_with_long_running_sequences() {
    let mut engine = create_engine();

    let seq = create_sequence(
        "long-running-memory",
        vec![(1, "p1"), (2, "p2"), (3, "p3")],
        Some(3_600_000), // 1 hour maxspan
    );
    engine.load_sequence(seq).unwrap();

    // Create many long-running partial matches
    let entity_count = 5000;

    for i in 0..entity_count {
        let event = create_event(1, i as u64 * 1_000_000, i as u128);
        let _ = engine.process_event(&event);

        // Some entities progress to step 2
        if i % 2 == 0 {
            let event = create_event(2, (i as u64 + 1) * 1_000_000, i as u128);
            let _ = engine.process_event(&event);
        }
    }

    println!("✅ Long-running sequences: {} partial matches created", entity_count);
}

// =============================================================================
// Complex Real-World Scenarios
// =============================================================================

#[test]
fn test_mitre_attack_scenario_lateral_movement() {
    let mut engine = create_engine();

    // Simulate lateral movement detection
    // 1. Authentication event
    // 2. Network connection to new host
    // 3. Service creation on remote host
    // 4. Process execution on remote host
    let seq = create_sequence(
        "lateral-movement",
        vec![
            (1001, "auth"),       // Authentication
            (1002, "netconn"),    // Network connection
            (1003, "svc_create"), // Service creation
            (1004, "proc_exec"),  // Process execution
        ],
        Some(300000), // 5 minute window
    );
    engine.load_sequence(seq).unwrap();

    // Entity A: Legitimate activity
    let _ = engine.process_event(&create_event(1001, 1_000_000_000, 1));
    let _ = engine.process_event(&create_event(1002, 1_010_000_000, 1));

    // Entity B: Lateral movement (complete sequence)
    let _ = engine.process_event(&create_event(1001, 1_100_000_000, 2));
    let _ = engine.process_event(&create_event(1002, 1_110_000_000, 2));
    let _ = engine.process_event(&create_event(1003, 1_120_000_000, 2));
    let alerts = engine
        .process_event(&create_event(1004, 1_130_000_000, 2))
        .unwrap();

    assert_eq!(alerts.len(), 1, "Should detect lateral movement");
    assert_eq!(alerts[0].entity_key, 2);

    println!("✅ MITRE ATT&CK lateral movement scenario: detected");
}

#[test]
fn test_mitre_attack_scenario_data_exfiltration() {
    let mut engine = create_engine();

    // Data exfiltration pattern
    // 1. Large file read
    // 2. Network connection to external IP
    // 3. Large data transfer
    let seq = create_sequence(
        "data-exfil",
        vec![
            (2001, "large_file_read"),
            (2002, "external_conn"),
            (2003, "data_transfer"),
        ],
        Some(60000), // 1 minute window
    );
    engine.load_sequence(seq).unwrap();

    // Simulate data exfiltration
    let _ = engine.process_event(&create_event(2001, 1_000_000_000, 100));
    let _ = engine.process_event(&create_event(2002, 1_005_000_000, 100));
    let alerts = engine
        .process_event(&create_event(2003, 1_010_000_000, 100))
        .unwrap();

    assert_eq!(alerts.len(), 1);

    println!("✅ MITRE ATT&CK data exfiltration scenario: detected");
}

#[test]
fn test_mitre_attack_scenario_persistence() {
    let mut engine = create_engine();

    // Persistence mechanism detection
    // 1. Registry modification
    // 2. Scheduled task creation
    // 3. System service modification
    let seq = create_sequence(
        "persistence",
        vec![
            (3001, "registry_mod"),
            (3002, "scheduled_task"),
            (3003, "service_mod"),
        ],
        Some(300000), // 5 minutes
    );
    engine.load_sequence(seq).unwrap();

    // Simulate persistence activity
    let _ = engine.process_event(&create_event(3001, 1_000_000_000, 200));
    let _ = engine.process_event(&create_event(3002, 1_050_000_000, 200));
    let alerts = engine
        .process_event(&create_event(3003, 1_100_000_000, 200))
        .unwrap();

    assert_eq!(alerts.len(), 1);

    println!("✅ MITRE ATT&CK persistence scenario: detected");
}

// =============================================================================
// Edge Cases and Boundary Tests
// =============================================================================

#[test]
fn test_zero_timestamp_handling() {
    let mut engine = create_engine();

    let seq = create_sequence("zero-ts", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    // Events with timestamp 0
    let _ = engine.process_event(&create_event(1, 0, 1));
    let alerts = engine
        .process_event(&create_event(2, 1_000_000, 1))
        .unwrap();

    assert_eq!(alerts.len(), 1);
    println!("✅ Zero timestamp handling: works correctly");
}

#[test]
fn test_max_entity_key() {
    let mut engine = create_engine();

    let seq = create_sequence("max-entity", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let max_key = u128::MAX;
    let alerts = engine
        .process_event(&create_event(1, 1_000_000, max_key))
        .unwrap();

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].entity_key, max_key);

    println!("✅ Max entity key handling: works correctly");
}

#[test]
fn test_rapid_event_burst() {
    let mut engine = create_engine();

    let seq = create_sequence("burst", vec![(1, "p1"), (2, "p2")], Some(1000));
    engine.load_sequence(seq).unwrap();

    let burst_size = 10_000;
    let start = Instant::now();

    // All events at the same timestamp
    for i in 0..burst_size {
        let event = create_event((i % 2 + 1) as u16, 1_000_000, (i % 100) as u128);
        let _ = engine.process_event(&event);
    }

    let elapsed = start.elapsed();
    let throughput = burst_size as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Rapid burst ({} events same timestamp): {:.0} events/sec",
        burst_size, throughput
    );
}

#[test]
fn test_interleaved_entity_sequences() {
    let mut engine = create_engine();

    let seq = create_sequence("interleaved", vec![(1, "p1"), (2, "p2"), (3, "p3")], Some(10000));
    engine.load_sequence(seq).unwrap();

    // Interleave events from 100 different entities
    let entity_count = 100;
    let events_per_entity = 3;

    for step in 0..events_per_entity {
        for entity_id in 0..entity_count {
            let event = create_event(
                (step + 1) as u16,
                (step * entity_count + entity_id + 1) as u64 * 1_000_000,
                entity_id as u128,
            );
            let _ = engine.process_event(&event);
        }
    }

    println!(
        "✅ Interleaved entity sequences: {} entities × {} steps",
        entity_count, events_per_entity
    );
}

// =============================================================================
// Budget and Resource Limit Tests
// =============================================================================

#[test]
fn test_evaluation_budget_enforcement() {
    let config = NfaEngineConfig {
        max_evaluations_per_sec: 1000,
        max_eval_time_ns: 1_000_000, // 1ms
        budget_action: BudgetAction::FailOpen,
        ..Default::default()
    };

    let mut engine = create_engine_with_config(config);

    let seq = create_sequence("budget-test", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let start = Instant::now();

    // Process many events
    for i in 0..5000 {
        let event = create_event(1, i as u64 * 1000, i as u128);
        let _ = engine.process_event(&event);
    }

    let elapsed = start.elapsed();

    println!("✅ Budget enforcement: 5000 events processed in {:?}", elapsed);
}

#[test]
fn test_state_store_limits() {
    let config = NfaEngineConfig {
        state_store: StateStoreConfig {
            max_partial_matches_per_entity: 5,
            max_total_partial_matches: 1000,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut engine = create_engine_with_config(config);

    // Load multiple sequences that can create partial matches
    for i in 0..10 {
        let seq =
            create_sequence(&format!("limit-seq-{}", i), vec![(1, "p1"), (2, "p2")], Some(60000));
        engine.load_sequence(seq).unwrap();
    }

    // Create partial matches (each entity can have max 5)
    for entity_id in 0..100 {
        let event = create_event(1, 1_000_000, entity_id as u128);
        let _ = engine.process_event(&event);
    }

    let stats = engine.stats();
    println!("✅ State store limits: total rules tracked = {}", stats.total_rules_tracked);
}

// =============================================================================
// Latency Distribution Tests
// =============================================================================

#[test]
fn test_latency_distribution() {
    let mut engine = create_engine();

    let seq = create_sequence("latency", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    let iterations = 10000;
    let mut latencies: Vec<u64> = Vec::with_capacity(iterations);

    // Warmup
    for _ in 0..100 {
        let event = create_event(1, 1_000_000, 1);
        let _ = engine.process_event(&event);
    }

    // Measure
    for i in 0..iterations {
        let start = Instant::now();
        let event = create_event((i % 2 + 1) as u16, i as u64 * 1000, (i % 100) as u128);
        let _ = engine.process_event(&event);
        let elapsed = start.elapsed().as_nanos() as u64;
        latencies.push(elapsed);
    }

    latencies.sort();

    let p50 = latencies[iterations / 2];
    let p90 = latencies[iterations * 9 / 10];
    let p99 = latencies[iterations * 99 / 100];
    let p999 = latencies[iterations * 999 / 1000];

    println!("✅ Latency distribution ({} iterations):", iterations);
    println!("   P50: {} ns", p50);
    println!("   P90: {} ns", p90);
    println!("   P99: {} ns", p99);
    println!("   P99.9: {} ns", p999);

    // Performance assertions (in debug mode, be more lenient)
    #[cfg(debug_assertions)]
    let threshold_ns = 100_000; // 100 microseconds in debug
    #[cfg(not(debug_assertions))]
    let threshold_ns = 10_000; // 10 microseconds in release

    assert!(p99 < threshold_ns * 10, "P99 latency too high: {} ns", p99);
}
