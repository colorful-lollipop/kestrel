// Quick Performance Comparison: AC-DFA vs NFA
//
// Simple benchmark to compare AC-DFA and NFA performance in release mode

use kestrel_ac_dfa::{AcMatcher, MatchPattern, AcDfaConfig};
use kestrel_nfa::{CompiledSequence, NfaEngine, NfaEngineConfig, NfaSequence, SeqStep};
use std::sync::Arc;
use std::time::Instant;

use kestrel_nfa::test_helpers::MockEvaluator;

fn main() {
    println!("=== AC-DFA vs NFA Performance Comparison (Release Mode) ===\n");

    // 1. Test AC-DFA performance
    println!("Testing AC-DFA...");
    let patterns: Vec<_> = (0..100)
        .map(|i| {
            MatchPattern::equals(
                format!("string_{}", i),
                1,
                format!("rule-{}", i),
            ).unwrap()
        })
        .collect();

    let config = AcDfaConfig::default();
    let ac_matcher = AcMatcher::new(patterns, config).unwrap();

    // Warmup
    for _ in 0..10000 {
        let _ = ac_matcher.matches_field(1, "string_42");
    }

    // Benchmark AC-DFA
    let iterations = 1_000_000;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = ac_matcher.matches_field(1, "string_42");
    }
    let ac_duration = start.elapsed();
    let ac_ns_per_op = ac_duration.as_nanos() / iterations;

    println!("  AC-DFA:");
    println!("    Total time: {:?}", ac_duration);
    println!("    Per operation: {} ns", ac_ns_per_op);
    println!("    Throughput: {:.2} M ops/sec", 1000.0 / ac_duration.as_secs_f64() / 1000.0);
    println!();

    // 2. Test NFA performance
    println!("Testing NFA...");
    let steps = vec![SeqStep::new(0, "pred1".to_string(), 1)];
    let sequence = NfaSequence::new("test-seq".to_string(), 100, steps, Some(5000), None);
    let compiled = CompiledSequence {
        id: "test-seq".to_string(),
        sequence,
        rule_id: "rule-1".to_string(),
        rule_name: "Test Rule".to_string(),
    };

    let config = NfaEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator::default());
    let mut nfa_engine = NfaEngine::new(config, evaluator);
    nfa_engine.load_sequence(compiled).unwrap();

    let event = kestrel_event::Event::builder()
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(12345)
        .build()
        .unwrap();

    // Warmup
    for _ in 0..10000 {
        let _ = nfa_engine.process_event_blocking(&event);
    }

    // Benchmark NFA
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = nfa_engine.process_event_blocking(&event);
    }
    let nfa_duration = start.elapsed();
    let nfa_ns_per_op = nfa_duration.as_nanos() / iterations;

    println!("  NFA:");
    println!("    Total time: {:?}", nfa_duration);
    println!("    Per operation: {} {} ns", nfa_ns_per_op, if cfg!(debug_assertions) { "(debug)" } else { "(release)" });
    println!("    Throughput: {:.2} M ops/sec", 1000.0 / nfa_duration.as_secs_f64() / 1000.0);
    println!();

    // 3. Calculate speedup
    let speedup = nfa_ns_per_op as f64 / ac_ns_per_op as f64;
    println!("=== Results ===");
    println!("AC-DFA: {} ns/op", ac_ns_per_op);
    println!("NFA:    {} ns/op", nfa_ns_per_op);
    println!("Speedup: {:.2}x", speedup);

    if speedup >= 10.0 {
        println!("\n🎉 Excellent! Speedup >= 10x target achieved!");
    } else if speedup >= 5.0 {
        println!("\n✅ Good! Speedup >= 5x target achieved!");
    } else {
        println!("\n⚠️  Speedup below 5x target");
    }
}
