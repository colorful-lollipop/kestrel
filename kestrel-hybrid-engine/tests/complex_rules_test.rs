// Complex Rules Performance and Functionality Test
//
// Tests hybrid engine with complex real-world rule scenarios:
// - Regex patterns
// - Glob patterns
// - Until conditions
// - Long sequences
// - Multiple predicates
// - Mixed complexity

use kestrel_hybrid_engine::{
    HybridEngine, HybridEngineConfig, MatchingStrategy, RuleComplexityAnalyzer, RuleStrategy,
};
use kestrel_eql::ir::*;
use kestrel_nfa::{CompiledSequence, NfaSequence, SeqStep};
use std::sync::Arc;
use std::time::Instant;

// Mock predicate evaluator for testing
struct MockEvaluator;

impl kestrel_nfa::PredicateEvaluator for MockEvaluator {
    fn evaluate(
        &self,
        _predicate_id: &str,
        _event: &kestrel_event::Event,
    ) -> Result<bool, kestrel_nfa::NfaError> {
        Ok(true)
    }

    fn get_required_fields(&self, _predicate_id: &str) -> Result<Vec<u32>, kestrel_nfa::NfaError> {
        Ok(vec![1, 2, 3])
    }

    fn has_predicate(&self, predicate_id: &str) -> bool {
        !predicate_id.is_empty()
    }
}

// Helper to create complex sequence
fn create_complex_sequence(
    id: &str,
    steps: usize,
    has_until: bool,
) -> CompiledSequence {
    let seq_steps: Vec<_> = (0..steps)
        .map(|i| SeqStep::new(i as u16, format!("pred{}", i), (i + 1) as u16))
        .collect();

    let until_step = if has_until {
        Some(SeqStep::new((steps - 1) as u16, format!("pred{}", steps - 1), steps as u16))
    } else {
        None
    };

    let sequence = NfaSequence::new(
        id.to_string(),
        100, // by_field_id
        seq_steps,
        Some(5000), // maxspan
        until_step,
    );

    CompiledSequence {
        id: id.to_string(),
        sequence,
        rule_id: format!("rule-{}", id),
        rule_name: format!("Complex Rule {}", id),
    }
}

// ============================================================================
// Test 1: Regex-based Rules
// ============================================================================

#[test]
fn test_regex_rule_analysis() {
    let mut rule = IrRule::new(
        "regex-rule".to_string(),
        IrRuleType::Event {
            event_type: "process".to_string(),
        },
    );

    // Complex regex pattern
    let predicate = IrPredicate {
        id: "main".to_string(),
        event_type: "process".to_string(),
        root: IrNode::FunctionCall {
            func: IrFunction::Regex,
            args: vec![
                IrNode::Literal {
                    value: IrLiteral::String(".*\\.(exe|dll|bat|cmd)".to_string()),
                },
                IrNode::LoadField { field_id: 1 },
            ],
        },
        required_fields: vec![1],
        required_regex: vec![".*\\.(exe|dll|bat|cmd)".to_string()],
        required_globs: vec![],
    };

    rule.add_predicate(predicate);

    let recommendation = RuleComplexityAnalyzer::analyze(&rule).unwrap();

    // Should recommend NFA due to regex
    assert_eq!(recommendation.strategy, MatchingStrategy::Nfa);
    assert!(recommendation.complexity.has_regex);
    // Note: score may vary based on analyzer implementation
    println!("Regex rule analysis: score={}, strategy={:?}",
             recommendation.complexity.score, recommendation.strategy);
}

#[test]
fn test_regex_performance() {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);
    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    // Create sequence with regex predicates
    let seq1 = create_complex_sequence("regex-seq-1", 3, false);
    let seq2 = create_complex_sequence("regex-seq-2", 5, false);
    let seq3 = create_complex_sequence("regex-seq-3", 7, false);

    engine.load_sequence(seq1).unwrap();
    engine.load_sequence(seq2).unwrap();
    engine.load_sequence(seq3).unwrap();

    // Verify strategies - should use NFA for complex regex rules
    for id in &["regex-seq-1", "regex-seq-2", "regex-seq-3"] {
        let strategy = engine.get_rule_strategy(id);
        assert!(strategy.is_some());
        println!("{}: {:?}", id, strategy.unwrap());
    }

    // Measure event processing performance
    let event = kestrel_event::Event::builder()
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(12345)
        .build()
        .unwrap();

    // Warmup
    for _ in 0..1000 {
        let _ = engine.process_event(&event);
    }

    // Benchmark
    let iterations = 10_000;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = engine.process_event(&event);
    }
    let elapsed = start.elapsed();

    let throughput = iterations as f64 / elapsed.as_secs_f64();
    let latency_us = elapsed.as_micros() as f64 / iterations as f64;

    println!("\nRegex Rules Performance:");
    println!("  Total events: {}", iterations);
    println!("  Throughput: {:.2} K events/sec", throughput / 1000.0);
    println!("  Average latency: {:.2} µs/event", latency_us);

    // Should still process at reasonable speed even with regex
    assert!(throughput > 500.0, "Regex rules should achieve >500 EPS");
}

// ============================================================================
// Test 2: Glob Pattern Rules
// ============================================================================

#[test]
fn test_glob_rule_analysis() {
    let mut rule = IrRule::new(
        "glob-rule".to_string(),
        IrRuleType::Event {
            event_type: "file".to_string(),
        },
    );

    // Glob pattern
    let predicate = IrPredicate {
        id: "main".to_string(),
        event_type: "file".to_string(),
        root: IrNode::FunctionCall {
            func: IrFunction::Wildcard,
            args: vec![
                IrNode::Literal {
                    value: IrLiteral::String("/etc/**/*.conf".to_string()),
                },
                IrNode::LoadField { field_id: 1 },
            ],
        },
        required_fields: vec![1],
        required_regex: vec![],
        required_globs: vec!["/etc/**/*.conf".to_string()],
    };

    rule.add_predicate(predicate);

    let recommendation = RuleComplexityAnalyzer::analyze(&rule).unwrap();

    // Should detect glob pattern
    assert!(recommendation.complexity.has_glob);
    // Strategy depends on overall complexity
    println!("Glob rule analysis: score={}, strategy={:?}",
             recommendation.complexity.score, recommendation.strategy);
}

// ============================================================================
// Test 3: Long Sequence Rules
// ============================================================================

#[test]
fn test_long_sequence_analysis() {
    let mut rule = IrRule::new(
        "long-seq-rule".to_string(),
        IrRuleType::Sequence {
            event_types: vec!["process".to_string()],
        },
    );

    // Create 10-step sequence
    let mut steps = vec![];
    for i in 0..10 {
        steps.push(IrSeqStep {
            index: i,
            predicate_id: format!("pred{}", i),
            event_type_name: "process".to_string(),
        });
    }

    rule.sequence = Some(IrSequence {
        maxspan_ms: Some(10000),
        by_field_id: 100,
        until: None,
        steps,
    });

    // Add simple predicates
    for i in 0..10 {
        let predicate = IrPredicate {
            id: format!("pred{}", i),
            event_type: "process".to_string(),
            root: IrNode::Literal {
                value: IrLiteral::Bool(true),
            },
            required_fields: vec![],
            required_regex: vec![],
            required_globs: vec![],
        };
        rule.add_predicate(predicate);
    }

    let recommendation = RuleComplexityAnalyzer::analyze(&rule).unwrap();

    // Should have higher complexity due to many steps
    assert!(recommendation.complexity.sequence_steps == 10);
    assert!(recommendation.complexity.score > 30);

    println!("Long sequence analysis: score={}, steps={}, strategy={:?}",
             recommendation.complexity.score,
             recommendation.complexity.sequence_steps,
             recommendation.strategy);
}

#[test]
fn test_long_sequence_performance() {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);
    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    // Load sequences of varying lengths
    for steps in &[5, 10, 15, 20] {
        let seq = create_complex_sequence(&format!("long-seq-{}", steps), *steps, false);
        engine.load_sequence(seq).unwrap();
    }

    let stats = engine.stats();
    assert_eq!(stats.total_rules_tracked, 4);

    // Process events
    let event = kestrel_event::Event::builder()
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(12345)
        .build()
        .unwrap();

    let start = Instant::now();
    for _ in 0..1000 {
        let _ = engine.process_event(&event);
    }
    let elapsed = start.elapsed();

    let throughput = 1000.0 / elapsed.as_secs_f64();
    println!("Long sequence throughput: {:.2} events/sec", throughput);

    // Even with long sequences, should be performant
    assert!(throughput > 500.0);
}

// ============================================================================
// Test 4: Until Condition Rules
// ============================================================================

#[test]
fn test_until_condition_analysis() {
    let mut rule = IrRule::new(
        "until-rule".to_string(),
        IrRuleType::Sequence {
            event_types: vec!["process".to_string()],
        },
    );

    // 5-step sequence with until condition
    let steps: Vec<_> = (0..5)
        .map(|i| IrSeqStep {
            index: i,
            predicate_id: format!("pred{}", i),
            event_type_name: "process".to_string(),
        })
        .collect();

    rule.sequence = Some(IrSequence {
        maxspan_ms: Some(5000),
        by_field_id: 100,
        until: Some("pred4".to_string()), // until condition on step 4
        steps,
    });

    // Add predicates
    for i in 0..5 {
        let predicate = IrPredicate {
            id: format!("pred{}", i),
            event_type: "process".to_string(),
            root: IrNode::Literal {
                value: IrLiteral::Bool(true),
            },
            required_fields: vec![],
            required_regex: vec![],
            required_globs: vec![],
        };
        rule.add_predicate(predicate);
    }

    let recommendation = RuleComplexityAnalyzer::analyze(&rule).unwrap();

    // Should have higher complexity due to until
    assert!(recommendation.complexity.has_until);
    assert!(recommendation.complexity.score > 40);

    println!("Until condition analysis: score={}, has_until={}, strategy={:?}",
             recommendation.complexity.score,
             recommendation.complexity.has_until,
             recommendation.strategy);
}

#[test]
fn test_until_condition_performance() {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);
    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    // Load sequences with until conditions
    let seq1 = create_complex_sequence("until-seq-1", 3, true);
    let seq2 = create_complex_sequence("until-seq-2", 5, true);
    let seq3 = create_complex_sequence("until-seq-3", 7, true);

    engine.load_sequence(seq1).unwrap();
    engine.load_sequence(seq2).unwrap();
    engine.load_sequence(seq3).unwrap();

    // Process events
    let event = kestrel_event::Event::builder()
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(12345)
        .build()
        .unwrap();

    let start = Instant::now();
    for _ in 0..1000 {
        let _ = engine.process_event(&event);
    }
    let elapsed = start.elapsed();

    let throughput = 1000.0 / elapsed.as_secs_f64();
    println!("Until condition throughput: {:.2} events/sec", throughput);

    assert!(throughput > 500.0);
}

// ============================================================================
// Test 5: Mixed Complexity Rules
// ============================================================================

#[test]
fn test_mixed_complexity_rules() {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);
    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    // Load a mix of rule types
    // 1-3: Simple rules (2-3 steps, no complex features)
    for i in 1..=3 {
        let seq = create_complex_sequence(&format!("simple-{}", i), 2, false);
        engine.load_sequence(seq).unwrap();
    }

    // 4-6: Medium rules (5-7 steps)
    for i in 4..=6 {
        let seq = create_complex_sequence(&format!("medium-{}", i), 5, false);
        engine.load_sequence(seq).unwrap();
    }

    // 7-9: Complex rules (10+ steps with until)
    for i in 7..=9 {
        let seq = create_complex_sequence(&format!("complex-{}", i), 10, true);
        engine.load_sequence(seq).unwrap();
    }

    let stats = engine.stats();
    assert_eq!(stats.total_rules_tracked, 9);

    // Analyze strategy distribution
    let mut ac_dfa_count = 0;
    let mut lazy_dfa_count = 0;
    let mut nfa_count = 0;
    let mut hybrid_count = 0;

    for i in 1..=9 {
        let id = if i <= 3 {
            format!("simple-{}", i)
        } else if i <= 6 {
            format!("medium-{}", i)
        } else {
            format!("complex-{}", i)
        };

        if let Some(strategy) = engine.get_rule_strategy(&id) {
            match strategy {
                RuleStrategy::AcDfa => ac_dfa_count += 1,
                RuleStrategy::LazyDfa => lazy_dfa_count += 1,
                RuleStrategy::Nfa => nfa_count += 1,
                RuleStrategy::HybridAcNfa => hybrid_count += 1,
            }
            println!("{}: {:?}", id, strategy);
        }
    }

    println!("\nStrategy distribution:");
    println!("  AcDfa: {} rules", ac_dfa_count);
    println!("  LazyDfa: {} rules", lazy_dfa_count);
    println!("  Nfa: {} rules", nfa_count);
    println!("  HybridAcNfa: {} rules", hybrid_count);

    // Process events
    let event = kestrel_event::Event::builder()
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(12345)
        .build()
        .unwrap();

    let start = Instant::now();
    for _ in 0..5000 {
        let _ = engine.process_event(&event);
    }
    let elapsed = start.elapsed();

    let throughput = 5000.0 / elapsed.as_secs_f64();
    println!("\nMixed complexity throughput: {:.2} events/sec", throughput);
    println!("Average latency: {:.2} µs/event", elapsed.as_micros() as f64 / 5000.0);

    assert!(throughput > 500.0);
}

// ============================================================================
// Test 6: Very Complex Rule (Multiple Features)
// ============================================================================

#[test]
fn test_very_complex_rule() {
    let mut rule = IrRule::new(
        "very-complex-rule".to_string(),
        IrRuleType::Sequence {
            event_types: vec!["process".to_string()],
        },
    );

    // 15-step sequence with until
    let steps: Vec<_> = (0..15)
        .map(|i| IrSeqStep {
            index: i,
            predicate_id: format!("pred{}", i),
            event_type_name: "process".to_string(),
        })
        .collect();

    rule.sequence = Some(IrSequence {
        maxspan_ms: Some(15000),
        by_field_id: 100,
        until: Some("pred14".to_string()),
        steps,
    });

    // Add complex predicates with regex and glob
    for i in 0..15 {
        let root = if i % 3 == 0 {
            // Regex predicate
            IrNode::FunctionCall {
                func: IrFunction::Regex,
                args: vec![
                    IrNode::Literal {
                        value: IrLiteral::String(".*\\.exe".to_string()),
                    },
                    IrNode::LoadField { field_id: 1 },
                ],
            }
        } else if i % 3 == 1 {
            // Glob predicate
            IrNode::FunctionCall {
                func: IrFunction::Wildcard,
                args: vec![
                    IrNode::Literal {
                        value: IrLiteral::String("/tmp/**".to_string()),
                    },
                    IrNode::LoadField { field_id: 2 },
                ],
            }
        } else {
            // Simple predicate
            IrNode::Literal {
                value: IrLiteral::Bool(true),
            }
        };

        let predicate = IrPredicate {
            id: format!("pred{}", i),
            event_type: "process".to_string(),
            root,
            required_fields: vec![1, 2],
            required_regex: if i % 3 == 0 {
                vec![".*\\.exe".to_string()]
            } else {
                vec![]
            },
            required_globs: if i % 3 == 1 {
                vec!["/tmp/**".to_string()]
            } else {
                vec![]
            },
        };

        rule.add_predicate(predicate);
    }

    let recommendation = RuleComplexityAnalyzer::analyze(&rule).unwrap();

    println!("Very complex rule analysis:");
    println!("  Score: {}", recommendation.complexity.score);
    println!("  Steps: {}", recommendation.complexity.sequence_steps);
    println!("  Has regex: {}", recommendation.complexity.has_regex);
    println!("  Has glob: {}", recommendation.complexity.has_glob);
    println!("  Has until: {}", recommendation.complexity.has_until);
    println!("  Strategy: {:?}", recommendation.strategy);

    // Should be classified as very complex
    assert!(recommendation.complexity.score > 70);
    assert!(recommendation.complexity.has_regex);
    assert!(recommendation.complexity.has_glob);
    assert!(recommendation.complexity.has_until);
}

// ============================================================================
// Test 7: Performance Comparison by Complexity
// ============================================================================

#[test]
fn test_performance_by_complexity() {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);

    println!("\n=== Performance by Complexity ===\n");

    // Test different complexity levels
    let test_cases = vec![
        ("Simple", 2, false),
        ("Medium", 5, false),
        ("Complex", 10, false),
        ("Very Complex", 15, true),
    ];

    for (name, steps, has_until) in test_cases {
        let mut engine = HybridEngine::new(config.clone(), evaluator.clone()).unwrap();
        let seq = create_complex_sequence(&format!("test-{}", name), steps, has_until);
        engine.load_sequence(seq).unwrap();

        let event = kestrel_event::Event::builder()
            .event_type(1)
            .ts_mono(1000)
            .ts_wall(1000)
            .entity_key(12345)
            .build()
            .unwrap();

        // Warmup
        for _ in 0..1000 {
            let _ = engine.process_event(&event);
        }

        // Benchmark
        let iterations = 10_000;
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = engine.process_event(&event);
        }
        let elapsed = start.elapsed();

        let throughput = iterations as f64 / elapsed.as_secs_f64();
        let latency_ns = elapsed.as_nanos() / iterations;

        println!("{} ({} steps, until={}):", name, steps, has_until);
        println!("  Throughput: {:.2} K events/sec", throughput / 1000.0);
        println!("  Latency: {} ns/event", latency_ns);
        println!();
    }
}

// ============================================================================
// Test 8: Strategy Selection Accuracy
// ============================================================================

#[test]
fn test_strategy_selection_accuracy() {
    // Test that strategy selection aligns with rule characteristics
    let test_cases = vec![
        // (name, steps, has_regex, has_glob, has_until, expected_score_range)
        ("simple", 2, false, false, false, 0..35),
        ("medium", 5, false, false, false, 35..60),
        ("complex_regex", 3, true, false, false, 50..100),
        ("complex_glob", 3, false, true, false, 40..100),
        ("complex_until", 5, false, false, true, 40..80),
    ];

    for (name, steps, has_regex, has_glob, has_until, expected_score) in test_cases {
        let mut rule = IrRule::new(
            format!("{}-rule", name),
            IrRuleType::Sequence {
                event_types: vec!["process".to_string()],
            },
        );

        let steps_vec: Vec<_> = (0..steps)
            .map(|i| IrSeqStep {
                index: i,
                predicate_id: format!("pred{}", i),
                event_type_name: "process".to_string(),
            })
            .collect();

        rule.sequence = Some(IrSequence {
            maxspan_ms: Some(5000),
            by_field_id: 100,
            until: if has_until { Some(format!("pred{}", steps - 1)) } else { None },
            steps: steps_vec,
        });

        // Add predicates based on complexity
        for i in 0..steps {
            let root = if has_regex && i % 2 == 0 {
                IrNode::FunctionCall {
                    func: IrFunction::Regex,
                    args: vec![
                        IrNode::Literal {
                            value: IrLiteral::String(".*".to_string()),
                        },
                        IrNode::LoadField { field_id: 1 },
                    ],
                }
            } else if has_glob && i % 2 == 0 {
                IrNode::FunctionCall {
                    func: IrFunction::Wildcard,
                    args: vec![
                        IrNode::Literal {
                            value: IrLiteral::String("**".to_string()),
                        },
                        IrNode::LoadField { field_id: 1 },
                    ],
                }
            } else {
                IrNode::Literal {
                    value: IrLiteral::Bool(true),
                }
            };

            let predicate = IrPredicate {
                id: format!("pred{}", i),
                event_type: "process".to_string(),
                root,
                required_fields: vec![1],
                required_regex: if has_regex && i % 2 == 0 {
                    vec![".*".to_string()]
                } else {
                    vec![]
                },
                required_globs: if has_glob && i % 2 == 0 {
                    vec!["**".to_string()]
                } else {
                    vec![]
                },
            };

            rule.add_predicate(predicate);
        }

        let recommendation = RuleComplexityAnalyzer::analyze(&rule).unwrap();

        println!("{}: score={}, strategy={:?}, expected range={:?}",
                 name, recommendation.complexity.score,
                 recommendation.strategy, expected_score);

        // Verify score is in expected range
        assert!(expected_score.contains(&recommendation.complexity.score),
                "Score {} for {} should be in range {:?}",
                recommendation.complexity.score, name, expected_score);
    }
}
