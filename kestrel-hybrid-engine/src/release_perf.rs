// Release mode comprehensive performance test
//
// Run with: cargo test --release -p kestrel-hybrid-engine release_perf -- --ignored

#[cfg(test)]
mod release_perf_tests {
    use crate::{HybridEngine, HybridEngineConfig};
    use kestrel_nfa::{CompiledSequence, NfaEngine, NfaEngineConfig, NfaSequence, SeqStep};
    use std::sync::Arc;
    use std::time::Instant;

    // Mock predicate evaluator
    struct MockEvaluator;

    impl kestrel_nfa::PredicateEvaluator for MockEvaluator {
        fn evaluate(&self, _p: &str, _e: &kestrel_event::Event) -> kestrel_nfa::NfaResult<bool> {
            Ok(true)
        }
        fn get_required_fields(&self, _p: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
            Ok(vec![1, 2])
        }
        fn has_predicate(&self, p: &str) -> bool {
            !p.is_empty()
        }
    }

    #[test]
    #[ignore]
    fn release_perf() {
        println!("\n=== Release Mode Performance Test ===\n");

        // Test 1: Sequence loading throughput
        let config = HybridEngineConfig::default();
        let evaluator = Arc::new(MockEvaluator);
        let mut engine = HybridEngine::new(config, evaluator).unwrap();

        let start = Instant::now();
        for i in 1..=100 {
            let steps = vec![SeqStep::new(0, format!("pred{}", i), 1)];
            let seq = NfaSequence::new(format!("seq-{}", i), 100, steps, Some(5000), None);
            let compiled = CompiledSequence {
                id: format!("seq-{}", i),
                sequence: seq,
                rule_id: format!("rule-{}", i),
                rule_name: format!("Rule {}", i),
            };
            engine.load_sequence(compiled).unwrap();
        }
        let load_time = start.elapsed();
        println!("Loaded 100 sequences in {:?}", load_time);
        println!("Average: {:.2} µs/sequence", load_time.as_micros() as f64 / 100.0);

        // Test 2: Event processing throughput
        let event = kestrel_event::Event::builder()
            .event_type(1)
            .ts_mono(1000)
            .ts_wall(1000)
            .entity_key(12345)
            .build()
            .unwrap();

        // Warmup
        for _ in 0..10000 {
            let _ = engine.process_event(&event);
        }

        let iterations = 100_000;
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = engine.process_event(&event);
        }
        let process_time = start.elapsed();
        let ns_per_event = process_time.as_nanos() / iterations;

        println!("\nEvent Processing:");
        println!("  Total: {:?} for {} events", process_time, iterations);
        println!("  Per event: {} ns", ns_per_event);
        println!("  Throughput: {:.2} K events/sec", (iterations as f64 / process_time.as_secs_f64()) / 1000.0);

        // Test 3: Statistics
        let stats = engine.stats();
        println!("\nEngine Statistics:");
        println!("  Total rules tracked: {}", stats.total_rules_tracked);
        println!("  NFA sequences: {}", stats.nfa_sequence_count);

        // Performance assertions (release mode targets)
        assert!(ns_per_event < 200000, "Event processing should be fast, got {} ns", ns_per_event);
        println!("\n✅ Release mode performance verified!");
    }
}
