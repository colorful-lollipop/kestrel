// NFA Sequence Benchmarks
//
// Benchmarks for NFA sequence matching with varying complexity.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use kestrel_event::Event;
use kestrel_nfa::{CompiledSequence, NfaEngine, NfaEngineConfig, NfaSequence, SeqStep};
use std::sync::Arc;

use kestrel_nfa::test_helpers::MockEvaluator;

fn create_event(event_type: u16, ts: u64, entity_key: u128) -> Event {
    Event::builder()
        .event_type(event_type)
        .ts_mono(ts)
        .ts_wall(ts)
        .entity_key(entity_key)
        .build()
        .unwrap()
}

fn bench_sequence_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("nfa_sequence");

    // Benchmark: simple 3-step sequence
    group.bench_function("3_step_match", |b| {
        let steps = vec![
            SeqStep::new(0, "pred1".to_string(), 1),
            SeqStep::new(1, "pred2".to_string(), 2),
            SeqStep::new(2, "pred3".to_string(), 3),
        ];
        let sequence = NfaSequence::new("test-seq-3".to_string(), 100, steps, Some(5000), None);
        let compiled = CompiledSequence {
            id: "test-seq-3".to_string(),
            sequence,
            rule_id: "rule-1".to_string(),
            rule_name: "Test Rule 3".to_string(),
        };

        let evaluator = Arc::new(MockEvaluator::new(true));
        let mut engine = NfaEngine::new(NfaEngineConfig::default(), evaluator);
        engine.load_sequence(compiled).unwrap();

        let events: Vec<Event> = (0..3)
            .map(|i| create_event(i as u16 + 1, 1000 + i as u64 * 1000, 42))
            .collect();

        b.iter(|| {
            for event in &events {
                black_box(engine.process_event_blocking(black_box(event)).unwrap());
            }
        });
    });

    // Benchmark: 10-step complex sequence
    group.bench_function("10_step_match", |b| {
        let steps: Vec<_> = (0..10)
            .map(|i| SeqStep::new(i as u16, format!("pred{}", i), i as u16 + 1))
            .collect();
        let sequence = NfaSequence::new("test-seq-10".to_string(), 100, steps, Some(10000), None);
        let compiled = CompiledSequence {
            id: "test-seq-10".to_string(),
            sequence,
            rule_id: "rule-10".to_string(),
            rule_name: "Test Rule 10".to_string(),
        };

        let evaluator = Arc::new(MockEvaluator::new(true));
        let mut engine = NfaEngine::new(NfaEngineConfig::default(), evaluator);
        engine.load_sequence(compiled).unwrap();

        let events: Vec<Event> = (0..10)
            .map(|i| create_event(i as u16 + 1, 1000 + i as u64 * 1000, 42))
            .collect();

        b.iter(|| {
            for event in &events {
                black_box(engine.process_event_blocking(black_box(event)).unwrap());
            }
        });
    });

    // Benchmark: sequence with maxspan (non-matching due to timeout)
    group.bench_function("maxspan_timeout", |b| {
        let steps = vec![
            SeqStep::new(0, "pred1".to_string(), 1),
            SeqStep::new(1, "pred2".to_string(), 2),
        ];
        // maxspan of 1ms - events are 2ms apart, so second event should timeout
        let sequence = NfaSequence::new(
            "test-seq-timeout".to_string(),
            100,
            steps,
            Some(1),
            None,
        );
        let compiled = CompiledSequence {
            id: "test-seq-timeout".to_string(),
            sequence,
            rule_id: "rule-timeout".to_string(),
            rule_name: "Test Timeout".to_string(),
        };

        let evaluator = Arc::new(MockEvaluator::new(true));
        let mut engine = NfaEngine::new(NfaEngineConfig::default(), evaluator);
        engine.load_sequence(compiled).unwrap();

        let first_event = create_event(1, 0, 42);
        let second_event = create_event(2, 2_000_000, 42); // 2ms later, exceeds 1ms maxspan

        b.iter(|| {
            black_box(engine.process_event_blocking(black_box(&first_event)).unwrap());
            black_box(engine.process_event_blocking(black_box(&second_event)).unwrap());
        });
    });

    group.finish();
}

criterion_group!(benches, bench_sequence_matching);
criterion_main!(benches);
