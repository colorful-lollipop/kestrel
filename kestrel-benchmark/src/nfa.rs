use std::sync::Arc;
use std::time::Duration;

use kestrel_event::Event;
use kestrel_nfa::{CompiledSequence, NfaEngine, NfaEngineConfig, PredicateEvaluator, SeqStep};
use kestrel_schema::{SchemaRegistry, TypedValue};

use super::{
    calculate_percentiles, format_duration,
};

struct NoOpPredicateEvaluator;

impl PredicateEvaluator for NoOpPredicateEvaluator {
    fn evaluate(&self, _predicate_id: &str, _event: &Event) -> kestrel_nfa::NfaResult<bool> {
        Ok(true)
    }

    fn get_required_fields(&self, _predicate_id: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
        Ok(vec![])
    }

    fn has_predicate(&self, _predicate_id: &str) -> bool {
        true
    }
}

pub fn run_nfa_benchmarks() {
    println!("\n=== NFA Engine Benchmark ===\n");

    let config = NfaEngineConfig::default();

    let _schema = Arc::new(SchemaRegistry::new());
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(NoOpPredicateEvaluator);
    let mut nfa_engine = NfaEngine::new(config, evaluator);

    let sequence = CompiledSequence {
        id: "curl_dns_write".to_string(),
        sequence: kestrel_nfa::NfaSequence::with_captures(
            "curl_dns_write".to_string(),
            0,
            vec![
                SeqStep::new(0, "exe_predicate".to_string(), 1),
                SeqStep::new(1, "dns_predicate".to_string(), 2),
                SeqStep::new(2, "file_predicate".to_string(), 3),
            ],
            Some(10000),
            None,
            Vec::new(),
        ),
        rule_id: "curl_dns_write_rule".to_string(),
        rule_name: "Curl DNS Write Detection".to_string(),
    };

    nfa_engine.load_sequence(sequence);

    let entity_key = 0xabcdef123456789u128;

    let events: Vec<Event> = (0..3000)
        .map(|i| {
            let step = i % 3;
            let ts = 1_000_000_000u64 + (i as u64 * 1000);

            match step {
                0 => Event::builder()
                    .event_id(i as u64)
                    .event_type(1)
                    .ts_mono(ts)
                    .ts_wall(ts)
                    .entity_key(entity_key)
                    .field(1, TypedValue::String("/usr/bin/curl".into()))
                    .build()
                    .unwrap(),
                1 => Event::builder()
                    .event_id(i as u64)
                    .event_type(2)
                    .ts_mono(ts)
                    .ts_wall(ts)
                    .entity_key(entity_key)
                    .field(2, TypedValue::String("malicious.domain.com".into()))
                    .build()
                    .unwrap(),
                _ => Event::builder()
                    .event_id(i as u64)
                    .event_type(3)
                    .ts_mono(ts)
                    .ts_wall(ts)
                    .entity_key(entity_key)
                    .field(3, TypedValue::String("/tmp/payload".into()))
                    .build()
                    .unwrap(),
            }
        })
        .collect();

    let mut latencies = Vec::with_capacity(2000);

    for event in &events {
        let start = std::time::Instant::now();
        let _ = nfa_engine.process_event(event);
        latencies.push(start.elapsed());
    }

    let (p50, p90, p99) = calculate_percentiles(&mut latencies);

    println!("    P50: {}", format_duration(p50));
    println!("    P90: {}", format_duration(p90));
    println!("    P99: {}", format_duration(p99));

    let sum: Duration = latencies.iter().sum();
    let avg = sum / latencies.len() as u32;
    println!("    Avg: {}", format_duration(avg));
}

pub fn run() {
    run_nfa_benchmarks();
}
