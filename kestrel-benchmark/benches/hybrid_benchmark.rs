// Hybrid Engine Performance Benchmarks
//
// Benchmarks for comparing AC-DFA, Lazy DFA, and NFA performance

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use kestrel_ac_dfa::{AcDfaBuilder, MatchPattern, PatternKind};
use kestrel_eql::ir::{IrLiteral, IrNode, IrPredicate};
use kestrel_lazy_dfa::{HotSpotDetector, LazyDfaConfig};
use kestrel_nfa::{CompiledSequence, NfaEngine, NfaEngineConfig, SeqStep, NfaSequence};
use std::sync::Arc;
use std::time::Duration;

// Mock predicate evaluator for testing
struct MockEvaluator;

impl kestrel_nfa::PredicateEvaluator for MockEvaluator {
    fn evaluate(&self, predicate_id: &str, _event: &kestrel_event::Event) -> kestrel_nfa::NfaResult<bool> {
        // Return true for all predicates
        Ok(true)
    }

    fn get_required_fields(&self, _predicate_id: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
        Ok(vec![])
    }

    fn has_predicate(&self, predicate_id: &str) -> bool {
        !predicate_id.is_empty()
    }
}

/// Benchmark AC-DFA string matching
fn bench_ac_dfa_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("ac_dfa");

    for pattern_count in [10, 100, 1000].iter() {
        // Create patterns
        let patterns: Vec<_> = (0..*pattern_count)
            .map(|i| {
                MatchPattern::equals(
                    format!("pattern_{}", i),
                    1,
                    format!("rule-{}", i),
                ).unwrap()
            })
            .collect();

        let matcher = AcDfaBuilder::new()
            .add_patterns(patterns)
            .build()
            .unwrap();

        let test_text = "pattern_42";

        group.bench_with_input(
            BenchmarkId::new("match", pattern_count),
            &pattern_count,
            |b, _| {
                b.iter(|| {
                    black_box(matcher.matches_field(1, black_box(test_text)))
                });
            },
        );
    }

    group.finish();
}

/// Benchmark NFA sequence matching
fn bench_nfa_sequence_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("nfa_sequence");

    for sequence_length in [2, 5, 10].iter() {
        let steps: Vec<_> = (0..*sequence_length)
            .map(|i| {
                SeqStep::new(
                    i as u16,
                    format!("pred{}", i),
                    (i + 1) as u16,
                )
            })
            .collect();

        let sequence = NfaSequence::new(
            "test-seq".to_string(),
            100,
            steps,
            Some(5000),
            None,
        );

        let compiled = CompiledSequence {
            id: "test-seq".to_string(),
            sequence,
            rule_id: "rule-1".to_string(),
            rule_name: "Test Rule".to_string(),
        };

        let config = NfaEngineConfig::default();
        let evaluator = Arc::new(MockEvaluator);
        let mut engine = NfaEngine::new(config, evaluator);
        engine.load_sequence(compiled).unwrap();

        let event = kestrel_event::Event::builder()
            .event_type(1)
            .ts_mono(1000)
            .ts_wall(1000)
            .entity_key(12345)
            .build()
            .unwrap();

        group.bench_with_input(
            BenchmarkId::new("match", sequence_length),
            &sequence_length,
            |b, _| {
                b.iter(|| {
                    black_box(engine.process_event(black_box(&event)))
                });
            },
        );
    }

    group.finish();
}

/// Benchmark hot spot detection overhead
fn bench_hot_spot_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("hot_spot_detection");

    let config = LazyDfaConfig::default();
    let mut detector = HotSpotDetector::new(config.hot_spot_threshold);

    // Simulate varying loads
    for evals_per_sec in [100, 1000, 10000].iter() {
        group.bench_with_input(
            BenchmarkId::new("overhead", evals_per_sec),
            &evals_per_sec,
            |b, &eps| {
                b.iter(|| {
                    let seq_id = "test-seq";
                    for _ in 0..eps {
                        detector.record_evaluation(seq_id, 100);
                        detector.record_match(seq_id);
                    }
                    black_box(detector.is_hot(seq_id))
                });
            },
        );
    }

    group.finish();
}

/// Benchmark strategy analysis overhead
fn bench_strategy_analysis(c: &mut Criterion) {
    use kestrel_hybrid_engine::RuleComplexityAnalyzer;
    use kestrel_eql::ir::{IrRule, IrRuleType, IrBinaryOp};

    let mut group = c.benchmark_group("strategy_analysis");

    // Simple rule (string literals)
    let simple_rule = {
        let mut rule = IrRule::new(
            "simple-rule".to_string(),
            IrRuleType::Event {
                event_type: "process".to_string(),
            },
        );

        let predicate = IrPredicate {
            id: "main".to_string(),
            event_type: "process".to_string(),
            root: IrNode::BinaryOp {
                op: IrBinaryOp::Eq,
                left: Box::new(IrNode::LoadField { field_id: 1 }),
                right: Box::new(IrNode::Literal {
                    value: IrLiteral::String("bash".to_string()),
                }),
            },
            required_fields: vec![1],
            required_regex: vec![],
            required_globs: vec![],
        };

        rule.add_predicate(predicate);
        rule
    };

    // Complex rule (regex)
    let complex_rule = {
        let mut rule = IrRule::new(
            "complex-rule".to_string(),
            IrRuleType::Event {
                event_type: "process".to_string(),
            },
        );

        let predicate = IrPredicate {
            id: "main".to_string(),
            event_type: "process".to_string(),
            root: IrNode::FunctionCall {
                func: kestrel_eql::ir::IrFunction::Regex,
                args: vec![
                    IrNode::Literal {
                        value: IrLiteral::String(".*\\.exe".to_string()),
                    },
                    IrNode::LoadField { field_id: 1 },
                ],
            },
            required_fields: vec![1],
            required_regex: vec![".*\\.exe".to_string()],
            required_globs: vec![],
        };

        rule.add_predicate(predicate);
        rule
    };

    group.bench_function("simple_rule", |b| {
        b.iter(|| {
            black_box(RuleComplexityAnalyzer::analyze(&simple_rule))
        });
    });

    group.bench_function("complex_rule", |b| {
        b.iter(|| {
            black_box(RuleComplexityAnalyzer::analyze(&complex_rule))
        });
    });

    group.finish();
}

/// Benchmark AC-DFA vs NFA for string matching
fn bench_ac_dfa_vs_nfa(c: &mut Criterion) {
    let mut group = c.benchmark_group("ac_dfa_vs_nfa");

    // Create AC-DFA matcher
    let patterns: Vec<_> = (0..100)
        .map(|i| {
            MatchPattern::equals(
                format!("string_{}", i),
                1,
                "rule-1".to_string(),
            ).unwrap()
        })
        .collect();

    let ac_matcher = AcDfaBuilder::new()
        .add_patterns(patterns)
        .build()
        .unwrap();

    // Create NFA engine
    let steps = vec![
        SeqStep::new(0, "pred1".to_string(), 1),
    ];

    let sequence = NfaSequence::new(
        "test-seq".to_string(),
        100,
        steps,
        Some(5000),
        None,
    );

    let compiled = CompiledSequence {
        id: "test-seq".to_string(),
        sequence,
        rule_id: "rule-1".to_string(),
        rule_name: "Test Rule".to_string(),
    };

    let config = NfaEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);
    let mut engine = NfaEngine::new(config, evaluator);
    engine.load_sequence(compiled).unwrap();

    let event = kestrel_event::Event::builder()
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(12345)
        .build()
        .unwrap();

    group.bench_function("ac_dfa", |b| {
        b.iter(|| {
            black_box(ac_matcher.matches_field(1, "string_42"))
        });
    });

    group.bench_function("nfa", |b| {
        b.iter(|| {
            black_box(engine.process_event(&event))
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_ac_dfa_matching,
    bench_nfa_sequence_matching,
    bench_hot_spot_detection,
    bench_strategy_analysis,
    bench_ac_dfa_vs_nfa
);

criterion_main!(benches);
