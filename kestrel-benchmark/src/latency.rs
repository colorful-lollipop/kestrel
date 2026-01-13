use std::time::Duration;

use kestrel_core::{AlertOutputConfig, EventBusConfig};
use kestrel_engine::{DetectionEngine, EngineConfig};

use super::{calculate_percentiles, create_single_test_event, format_duration};

const LATENCY_SAMPLE_COUNT: usize = 10000;
const WARMUP_COUNT: usize = 1000;

pub fn run_latency_benchmarks() {
    println!("\n=== Latency Benchmark Results ===\n");

    let runtime = tokio::runtime::Runtime::new().unwrap();

    let config = EngineConfig::default();

    let mut engine = runtime.block_on(async { DetectionEngine::new(config).await.unwrap() });

    let event = create_single_test_event();

    println!("  Warming up ({} iterations)...", WARMUP_COUNT);
    for _ in 0..WARMUP_COUNT {
        runtime.block_on(async {
            let _ = engine.eval_event(&event).await;
        });
    }

    println!(
        "  Measuring latency distribution ({} samples)...\n",
        LATENCY_SAMPLE_COUNT
    );

    let mut latencies = Vec::with_capacity(LATENCY_SAMPLE_COUNT);

    for _ in 0..LATENCY_SAMPLE_COUNT {
        let start = std::time::Instant::now();
        runtime.block_on(async {
            let _ = engine.eval_event(&event).await;
        });
        latencies.push(start.elapsed());
    }

    let (p50, p90, p99) = calculate_percentiles(&mut latencies);

    println!("  Latency Distribution:");
    println!("    P50: {}", format_duration(p50));
    println!("    P90: {}", format_duration(p90));
    println!("    P99: {}", format_duration(p99));
    println!(
        "    Max: {}",
        format_duration(*latencies.iter().max().unwrap())
    );

    let sum: Duration = latencies.iter().sum();
    let avg = sum / latencies.len() as u32;
    println!("    Avg: {}", format_duration(avg));

    println!("\n  Target: P99 < 1µs");
}

pub fn run_nfa_latency_benchmarks() {
    use kestrel_event::Event;
    use kestrel_nfa::{CompiledSequence, NfaEngine, NfaEngineConfig, PredicateEvaluator, SeqStep};
    use kestrel_schema::{SchemaRegistry, TypedValue};
    use std::sync::Arc;

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

    println!("\n=== NFA Sequence Latency Benchmark ===\n");

    let runtime = tokio::runtime::Runtime::new().unwrap();

    let config = NfaEngineConfig::default();

    let schema = Arc::new(SchemaRegistry::new());
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(NoOpPredicateEvaluator);
    let mut nfa_engine = NfaEngine::new(config, evaluator);

    let sequence = CompiledSequence {
        id: "test_sequence".to_string(),
        sequence: kestrel_nfa::NfaSequence::with_captures(
            "test_sequence".to_string(),
            0,
            vec![
                SeqStep::new(0, "step1".to_string(), 1),
                SeqStep::new(1, "step2".to_string(), 2),
                SeqStep::new(2, "step3".to_string(), 3),
            ],
            Some(10000),
            None,
            Vec::new(),
        ),
        rule_id: "test_rule".to_string(),
        rule_name: "Test Rule".to_string(),
    };

    nfa_engine.load_sequence(sequence);

    let entity_key = 0x123456789abcdefu128;

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
                    .field(1, TypedValue::String("/bin/curl".into()))
                    .build()
                    .unwrap(),
                1 => Event::builder()
                    .event_id(i as u64)
                    .event_type(2)
                    .ts_mono(ts)
                    .ts_wall(ts)
                    .entity_key(entity_key)
                    .field(2, TypedValue::String("evil.com".into()))
                    .build()
                    .unwrap(),
                _ => Event::builder()
                    .event_id(i as u64)
                    .event_type(3)
                    .ts_mono(ts)
                    .ts_wall(ts)
                    .entity_key(entity_key)
                    .field(3, TypedValue::String("/etc/passwd".into()))
                    .build()
                    .unwrap(),
            }
        })
        .collect();

    println!("  Warming up...");
    for event in &events[..100] {
        let _ = nfa_engine.process_event(event);
    }

    let mut latencies = Vec::with_capacity(2000);

    println!("  Measuring NFA processing latency (2000 events)...");
    for event in &events[100..1200] {
        let start = std::time::Instant::now();
        let _ = nfa_engine.process_event(event);
        latencies.push(start.elapsed());
    }

    let (p50, p90, p99) = calculate_percentiles(&mut latencies.clone());

    println!("\n  NFA Processing Latency:");
    println!("    P50: {}", format_duration(p50));
    println!("    P90: {}", format_duration(p90));
    println!("    P99: {}", format_duration(p99));

    let sum: Duration = latencies.iter().sum();
    let avg = sum / latencies.len() as u32;
    println!("    Avg: {}", format_duration(avg));

    println!("\n  Target: P99 < 10µs");
}

pub fn run() {
    run_latency_benchmarks();
    run_nfa_latency_benchmarks();
}
