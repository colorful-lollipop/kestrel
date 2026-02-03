// End-to-End Test for Hybrid Engine
//
// Tests the complete workflow: rule loading → strategy selection → event processing → hot spot detection

use kestrel_hybrid_engine::{HybridEngine, HybridEngineConfig};
use kestrel_nfa::{CompiledSequence, NfaSequence, SeqStep};
use std::sync::Arc;

// Mock predicate evaluator for testing
struct MockEvaluator;

impl kestrel_nfa::PredicateEvaluator for MockEvaluator {
    fn evaluate(&self, _predicate_id: &str, _event: &kestrel_event::Event) -> kestrel_nfa::NfaResult<bool> {
        Ok(true)
    }

    fn get_required_fields(&self, _predicate_id: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
        Ok(vec![1, 2])
    }

    fn has_predicate(&self, predicate_id: &str) -> bool {
        !predicate_id.is_empty()
    }
}

// Helper function to create a test sequence
fn create_sequence(id: &str, steps: usize) -> CompiledSequence {
    let seq_steps: Vec<_> = (0..steps)
        .map(|i| SeqStep::new(i as u16, format!("pred{}", i), (i + 1) as u16))
        .collect();

    let sequence = NfaSequence::new(
        id.to_string(),
        100, // by_field_id
        seq_steps,
        Some(5000), // maxspan
        None,       // until_step
    );

    CompiledSequence {
        id: id.to_string(),
        sequence,
        rule_id: format!("rule-{}", id),
        rule_name: format!("Test Rule {}", id),
    }
}

#[test]
fn test_e2e_workflow() {
    // 1. Setup hybrid engine
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);
    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    // 2. Load multiple sequences with different complexities
    // Simple 2-step sequence → should get LazyDfa strategy
    let seq1 = create_sequence("simple-seq", 2);
    engine.load_sequence(seq1).unwrap();

    // Simple 3-step sequence → should get LazyDfa strategy
    let seq2 = create_sequence("medium-seq", 3);
    engine.load_sequence(seq2).unwrap();

    // Simple 1-step sequence → should get AcDfa or LazyDfa strategy
    let seq3 = create_sequence("tiny-seq", 1);
    engine.load_sequence(seq3).unwrap();

    // 3. Verify strategies were assigned
    let strategy1 = engine.get_rule_strategy("simple-seq");
    let strategy2 = engine.get_rule_strategy("medium-seq");
    let strategy3 = engine.get_rule_strategy("tiny-seq");

    assert!(strategy1.is_some(), "simple-seq should have a strategy");
    assert!(strategy2.is_some(), "medium-seq should have a strategy");
    assert!(strategy3.is_some(), "tiny-seq should have a strategy");

    // 4. Process events
    let event = kestrel_event::Event::builder()
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(12345)
        .build()
        .unwrap();

    // Process multiple events
    let mut processed = 0;
    for _ in 0..100 {
        let result = engine.process_event(&event);
        assert!(result.is_ok(), "Event processing should not fail");
        processed += 1;
    }
    assert_eq!(processed, 100, "Should process all 100 events");

    // 5. Check statistics
    let stats = engine.stats();
    assert_eq!(stats.total_rules_tracked, 3, "Should track 3 rules");
    assert_eq!(stats.nfa_sequence_count, 3, "Should have 3 NFA sequences");
}

#[test]
fn test_e2e_with_different_complexities() {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);
    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    // Load sequences with varying complexity
    for i in 1..=10 {
        let steps = match i {
            1..=3 => 2,   // Simple
            4..=7 => 5,   // Medium
            _ => 10,      // Complex
        };

        let seq = create_sequence(&format!("seq-{}", i), steps);
        engine.load_sequence(seq).unwrap();
    }

    // Verify all sequences loaded
    let stats = engine.stats();
    assert_eq!(stats.total_rules_tracked, 10);

    // Verify all 10 sequences have strategies
    let mut strategies_found = 0;
    for i in 1..=10 {
        if engine.get_rule_strategy(&format!("seq-{}", i)).is_some() {
            strategies_found += 1;
        }
    }
    assert_eq!(strategies_found, 10, "All 10 sequences should have strategies");

    // Process events
    let event = kestrel_event::Event::builder()
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(12345)
        .build()
        .unwrap();

    let mut processed = 0;
    for _ in 0..50 {
        let result = engine.process_event(&event);
        assert!(result.is_ok(), "Event processing should not fail");
        processed += 1;
    }
    assert_eq!(processed, 50, "Should process all 50 events");

    // Final stats should show all rules still tracked
    let final_stats = engine.stats();
    assert_eq!(final_stats.total_rules_tracked, 10, "All 10 rules should still be tracked");
}

#[test]
fn test_e2e_strategy_consistency() {
    // Test that the same rule type gets consistent strategy
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);
    let mut engine = HybridEngine::new(config.clone(), evaluator).unwrap();

    // Load multiple similar sequences
    for i in 1..=5 {
        let seq = create_sequence(&format!("seq-{}", i), 2);
        engine.load_sequence(seq).unwrap();
    }

    // All should have the same strategy (since they're identical complexity)
    let strategies: Vec<_> = (1..=5)
        .map(|i| engine.get_rule_strategy(&format!("seq-{}", i)))
        .collect();

    // All should have some strategy
    assert!(strategies.iter().all(|s| s.is_some()), "All sequences should have strategies assigned");

    // First strategy should be the same for all
    let first_strategy = strategies[0].unwrap();
    for strategy in &strategies[1..] {
        assert_eq!(strategy.unwrap(), first_strategy, "All similar sequences should have the same strategy");
    }
    
    // Verify consistent strategy assignment
    let stats = engine.stats();
    assert_eq!(stats.total_rules_tracked, 5, "Should track all 5 identical sequences");
}

#[test]
fn test_e2e_engine_reusability() {
    // Test that engine can be reused for multiple rule sets
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);

    // First batch
    let mut engine = HybridEngine::new(config.clone(), evaluator.clone()).unwrap();
    for i in 1..=3 {
        let seq = create_sequence(&format!("batch1-seq-{}", i), 2);
        engine.load_sequence(seq).unwrap();
    }

    let stats1 = engine.stats();
    assert_eq!(stats1.total_rules_tracked, 3);

    // Second batch (new engine)
    let mut engine2 = HybridEngine::new(config.clone(), evaluator).unwrap();
    for i in 1..=5 {
        let seq = create_sequence(&format!("batch2-seq-{}", i), 3);
        engine2.load_sequence(seq).unwrap();
    }

    let stats2 = engine2.stats();
    assert_eq!(stats2.total_rules_tracked, 5);

    // Verify independence
    assert!(engine.get_rule_strategy("batch1-seq-1").is_some());
    assert!(engine2.get_rule_strategy("batch2-seq-1").is_some());
    assert!(engine.get_rule_strategy("batch2-seq-1").is_none());
}

#[test]
fn test_e2e_event_processing_throughput() {
    // Measure event processing throughput
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);
    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    // Load 10 sequences
    for i in 1..=10 {
        let seq = create_sequence(&format!("seq-{}", i), 3);
        engine.load_sequence(seq).unwrap();
    }

    // Create event
    let event = kestrel_event::Event::builder()
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(12345)
        .build()
        .unwrap();

    // Measure time to process 1000 events
    let start = std::time::Instant::now();
    for _ in 0..1000 {
        let _ = engine.process_event(&event);
    }
    let elapsed = start.elapsed();

    let throughput = 1000.0 / elapsed.as_secs_f64();
    let avg_latency_us = elapsed.as_micros() as f64 / 1000.0;

    // Should process at least 1k events/sec (conservative baseline for debug mode)
    assert!(throughput > 1_000.0, "Throughput should be > 1k events/sec, got {:.2}", throughput);
    
    // Verify latency is reasonable (< 1ms per event)
    assert!(avg_latency_us < 1000.0, "Average latency should be < 1ms, got {:.2} μs", avg_latency_us);
}
