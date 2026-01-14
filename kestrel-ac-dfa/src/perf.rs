// Quick release mode performance comparison
//
// Run with: cargo test --release -p kestrel-ac-dfa ac_dfa_perf -- --ignored

#[cfg(test)]
mod perf_tests {
    use crate::{AcMatcher, MatchPattern, AcDfaConfig};
    use std::time::Instant;

    #[test]
    #[ignore] // Run with: cargo test --release ac_dfa_perf -- --ignored
    fn ac_dfa_perf() {
        let patterns: Vec<_> = (0..100)
            .map(|i| MatchPattern::equals(format!("pattern_{}", i), 1, format!("rule_{}", i)).unwrap())
            .collect();

        let config = AcDfaConfig::default();
        let matcher = AcMatcher::new(patterns, config).unwrap();

        // Warmup
        for _ in 0..10000 {
            let _ = matcher.matches_field(1, "pattern_42");
        }

        // Benchmark
        let iterations = 1_000_000;
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = matcher.matches_field(1, "pattern_42");
        }
        let duration = start.elapsed();
        let ns_per_op = duration.as_nanos() / iterations;

        println!("\n=== Release Mode AC-DFA Performance ===");
        println!("Iterations: {}", iterations);
        println!("Total time: {:?}", duration);
        println!("Per operation: {} ns", ns_per_op);
        println!("Throughput: {:.2} M ops/sec", (iterations as f64 / duration.as_secs_f64()) / 1_000_000.0);

        // Assertion for minimum performance
        assert!(ns_per_op < 200, "AC-DFA should be fast in release mode, got {} ns/op", ns_per_op);
    }
}
