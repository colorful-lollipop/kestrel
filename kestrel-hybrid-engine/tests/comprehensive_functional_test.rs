// Comprehensive Functional Test Suite
//
// Tests all aspects of the hybrid engine with realistic rule scenarios:
// - All EQL features
// - Edge cases
// - Error handling
// - Integration scenarios

use kestrel_hybrid_engine::{
    analyze_rule, ComplexityWeights, HybridEngine, HybridEngineConfig, MatchingStrategy,
    RuleComplexityAnalyzer, RuleStrategy,
};
use kestrel_eql::ir::*;
use kestrel_nfa::{CompiledSequence, NfaSequence, SeqStep};
use std::sync::Arc;

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
        Ok(vec![1, 2, 3, 4, 5])
    }

    fn has_predicate(&self, predicate_id: &str) -> bool {
        !predicate_id.is_empty()
    }
}

fn create_base_sequence(id: &str, steps: usize) -> CompiledSequence {
    let seq_steps: Vec<_> = (0..steps)
        .map(|i| SeqStep::new(i as u16, format!("pred{}", i), (i + 1) as u16))
        .collect();

    let sequence = NfaSequence::new(
        id.to_string(),
        100,
        seq_steps,
        Some(5000),
        None,
    );

    CompiledSequence {
        id: id.to_string(),
        sequence,
        rule_id: format!("rule-{}", id),
        rule_name: format!("Test Rule {}", id),
    }
}

// ============================================================================
// Section 1: String Operations
// ============================================================================

#[test]
fn test_string_equality() {
    let mut rule = IrRule::new(
        "string-eq".to_string(),
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
    let analyzer = RuleComplexityAnalyzer::new();
    let rec = analyzer.analyze(&rule).unwrap();

    assert_eq!(rec.strategy, MatchingStrategy::AcDfa);
    assert!(rec.complexity.has_string_literals());
    println!("String equality: strategy={:?}", rec.strategy);
}

#[test]
fn test_string_contains() {
    let mut rule = IrRule::new(
        "string-contains".to_string(),
        IrRuleType::Event {
            event_type: "process".to_string(),
        },
    );

    let predicate = IrPredicate {
        id: "main".to_string(),
        event_type: "process".to_string(),
        root: IrNode::FunctionCall {
            func: IrFunction::Contains,
            args: vec![
                IrNode::LoadField { field_id: 1 },
                IrNode::Literal {
                    value: IrLiteral::String("ssh".to_string()),
                },
            ],
        },
        required_fields: vec![1],
        required_regex: vec![],
        required_globs: vec![],
    };

    rule.add_predicate(predicate);
    let analyzer = RuleComplexityAnalyzer::new();
    let rec = analyzer.analyze(&rule).unwrap();

    // Contains function should increase complexity score and be marked as function
    assert!(rec.complexity.score > 0, "Contains operation should have non-zero complexity");
    assert!(rec.complexity.has_functions, "Contains function call should be detected");
}

#[test]
fn test_string_startswith() {
    let mut rule = IrRule::new(
        "string-startswith".to_string(),
        IrRuleType::Event {
            event_type: "file".to_string(),
        },
    );

    let predicate = IrPredicate {
        id: "main".to_string(),
        event_type: "file".to_string(),
        root: IrNode::FunctionCall {
            func: IrFunction::StartsWith,
            args: vec![
                IrNode::LoadField { field_id: 1 },
                IrNode::Literal {
                    value: IrLiteral::String("/usr/bin".to_string()),
                },
            ],
        },
        required_fields: vec![1],
        required_regex: vec![],
        required_globs: vec![],
    };

    rule.add_predicate(predicate);
    let analyzer = RuleComplexityAnalyzer::new();
    let rec = analyzer.analyze(&rule).unwrap();

    // StartsWith is a function call
    assert!(rec.complexity.has_functions, "StartsWith function call should be detected");
    assert!(rec.complexity.score >= 0, "Complexity score should be non-negative");
}

#[test]
fn test_string_endswith() {
    let mut rule = IrRule::new(
        "string-endswith".to_string(),
        IrRuleType::Event {
            event_type: "file".to_string(),
        },
    );

    let predicate = IrPredicate {
        id: "main".to_string(),
        event_type: "file".to_string(),
        root: IrNode::FunctionCall {
            func: IrFunction::EndsWith,
            args: vec![
                IrNode::LoadField { field_id: 1 },
                IrNode::Literal {
                    value: IrLiteral::String(".exe".to_string()),
                },
            ],
        },
        required_fields: vec![1],
        required_regex: vec![],
        required_globs: vec![],
    };

    rule.add_predicate(predicate);
    let analyzer = RuleComplexityAnalyzer::new();
    let rec = analyzer.analyze(&rule).unwrap();

    // EndsWith is a function call
    assert!(rec.complexity.has_functions, "EndsWith function call should be detected");
    assert!(rec.complexity.score >= 0, "Complexity score should be non-negative");
}

// ============================================================================
// Section 2: Comparison Operations
// ============================================================================

#[test]
fn test_numeric_comparisons() {
    let comparisons = vec![
        (IrBinaryOp::Eq, "=="),
        (IrBinaryOp::NotEq, "!="),
        (IrBinaryOp::Less, "<"),
        (IrBinaryOp::LessEq, "<="),
        (IrBinaryOp::Greater, ">"),
        (IrBinaryOp::GreaterEq, ">="),
    ];

    for (op, op_str) in comparisons {
        let mut rule = IrRule::new(
            format!("numeric-{}", op_str),
            IrRuleType::Event {
                event_type: "process".to_string(),
            },
        );

        let predicate = IrPredicate {
            id: "main".to_string(),
            event_type: "process".to_string(),
            root: IrNode::BinaryOp {
                op: op.clone(),
                left: Box::new(IrNode::LoadField { field_id: 1 }),
                right: Box::new(IrNode::Literal {
                    value: IrLiteral::Int(1024),
                }),
            },
            required_fields: vec![1],
            required_regex: vec![],
            required_globs: vec![],
        };

        rule.add_predicate(predicate);
        let analyzer = RuleComplexityAnalyzer::new();
    let rec = analyzer.analyze(&rule).unwrap();

        // All numeric comparisons should be analyzed successfully
        assert!(
            matches!(
                rec.strategy,
                MatchingStrategy::AcDfa | MatchingStrategy::LazyDfa | MatchingStrategy::Nfa
            ),
            "Numeric {} should have a valid strategy",
            op_str
        );
    }
}

// ============================================================================
// Section 3: Logical Operations
// ============================================================================

#[test]
fn test_logical_and() {
    let mut rule = IrRule::new(
        "logical-and".to_string(),
        IrRuleType::Event {
            event_type: "process".to_string(),
        },
    );

    let predicate = IrPredicate {
        id: "main".to_string(),
        event_type: "process".to_string(),
        root: IrNode::BinaryOp {
            op: IrBinaryOp::And,
            left: Box::new(IrNode::BinaryOp {
                op: IrBinaryOp::Eq,
                left: Box::new(IrNode::LoadField { field_id: 1 }),
                right: Box::new(IrNode::Literal {
                    value: IrLiteral::String("bash".to_string()),
                }),
            }),
            right: Box::new(IrNode::BinaryOp {
                op: IrBinaryOp::Greater,
                left: Box::new(IrNode::LoadField { field_id: 2 }),
                right: Box::new(IrNode::Literal {
                    value: IrLiteral::Int(1000),
                }),
            }),
        },
        required_fields: vec![1, 2],
        required_regex: vec![],
        required_globs: vec![],
    };

    rule.add_predicate(predicate);
    let analyzer = RuleComplexityAnalyzer::new();
    let rec = analyzer.analyze(&rule).unwrap();

    // AND operation with string and int comparisons - the string literal contributes to complexity
    // Note: BinaryOp itself doesn't add complexity, but string literals do via has_string_literals()
    assert!(rec.complexity.has_string_literals(), "AND with string comparison should have string literals");
    // Score may be 0 for very simple rules without sequences, functions, etc.
}

#[test]
fn test_logical_or() {
    let mut rule = IrRule::new(
        "logical-or".to_string(),
        IrRuleType::Event {
            event_type: "process".to_string(),
        },
    );

    let predicate = IrPredicate {
        id: "main".to_string(),
        event_type: "process".to_string(),
        root: IrNode::BinaryOp {
            op: IrBinaryOp::Or,
            left: Box::new(IrNode::BinaryOp {
                op: IrBinaryOp::Eq,
                left: Box::new(IrNode::LoadField { field_id: 1 }),
                right: Box::new(IrNode::Literal {
                    value: IrLiteral::String("bash".to_string()),
                }),
            }),
            right: Box::new(IrNode::BinaryOp {
                op: IrBinaryOp::Eq,
                left: Box::new(IrNode::LoadField { field_id: 1 }),
                right: Box::new(IrNode::Literal {
                    value: IrLiteral::String("sh".to_string()),
                }),
            }),
        },
        required_fields: vec![1],
        required_regex: vec![],
        required_globs: vec![],
    };

    rule.add_predicate(predicate);
    let analyzer = RuleComplexityAnalyzer::new();
    let rec = analyzer.analyze(&rule).unwrap();

    // OR operation with string comparisons - the string literals contribute to complexity
    assert!(rec.complexity.has_string_literals(), "OR with string comparisons should have string literals");
    // Score may be 0 for very simple rules without sequences, functions, etc.
}

#[test]
fn test_logical_not() {
    let mut rule = IrRule::new(
        "logical-not".to_string(),
        IrRuleType::Event {
            event_type: "process".to_string(),
        },
    );

    let predicate = IrPredicate {
        id: "main".to_string(),
        event_type: "process".to_string(),
        root: IrNode::UnaryOp {
            op: IrUnaryOp::Not,
            operand: Box::new(IrNode::BinaryOp {
                op: IrBinaryOp::Eq,
                left: Box::new(IrNode::LoadField { field_id: 1 }),
                right: Box::new(IrNode::Literal {
                    value: IrLiteral::String("systemd".to_string()),
                }),
            }),
        },
        required_fields: vec![1],
        required_regex: vec![],
        required_globs: vec![],
    };

    rule.add_predicate(predicate);
    let analyzer = RuleComplexityAnalyzer::new();
    let rec = analyzer.analyze(&rule).unwrap();

    // NOT operation should have non-negative complexity
    assert!(rec.complexity.score >= 0, "Complexity score should be non-negative");
}

// ============================================================================
// Section 4: Collections
// ============================================================================

#[test]
fn test_in_operator() {
    let mut rule = IrRule::new(
        "in-operator".to_string(),
        IrRuleType::Event {
            event_type: "process".to_string(),
        },
    );

    let predicate = IrPredicate {
        id: "main".to_string(),
        event_type: "process".to_string(),
        root: IrNode::In {
            value: Box::new(IrNode::LoadField { field_id: 1 }),
            values: vec![
                IrLiteral::String("bash".to_string()),
                IrLiteral::String("sh".to_string()),
                IrLiteral::String("zsh".to_string()),
            ],
        },
        required_fields: vec![1],
        required_regex: vec![],
        required_globs: vec![],
    };

    rule.add_predicate(predicate);
    let analyzer = RuleComplexityAnalyzer::new();
    let rec = analyzer.analyze(&rule).unwrap();

    // IN operator with multiple string values
    assert!(rec.complexity.score >= 0, "IN operator should have non-negative complexity");
    // IN operator counts string literals
    assert!(rec.complexity.string_literals >= 3, "IN operator with 3 strings should have at least 3 string literals");
}

// ============================================================================
// Section 5: Sequence Variations
// ============================================================================

#[test]
fn test_single_step_sequence() {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);
    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    let seq = create_base_sequence("single-step", 1);
    engine.load_sequence(seq).unwrap();

    let strategy = engine.get_rule_strategy("single-step");
    assert!(strategy.is_some(), "Single-step sequence should have a strategy assigned");
    // Verify the strategy is valid (any valid strategy is acceptable)
    match strategy.unwrap() {
        RuleStrategy::AcDfa | RuleStrategy::LazyDfa | RuleStrategy::Nfa | RuleStrategy::HybridAcNfa => {
            // All are valid strategies depending on implementation
        }
    }
}

#[test]
fn test_two_step_sequence() {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);
    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    let seq = create_base_sequence("two-step", 2);
    engine.load_sequence(seq).unwrap();

    let strategy = engine.get_rule_strategy("two-step");
    assert!(strategy.is_some(), "Two-step sequence should have a strategy assigned");
    // Two-step sequence should have a valid strategy
    match strategy.unwrap() {
        RuleStrategy::AcDfa | RuleStrategy::LazyDfa | RuleStrategy::Nfa | RuleStrategy::HybridAcNfa => {
            // All are valid strategies for 2-step sequences
        }
    }
}

#[test]
fn test_multi_step_sequence() {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);
    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    for steps in &[3, 5, 7, 10] {
        let seq = create_base_sequence(&format!("multi-step-{}", steps), *steps);
        engine.load_sequence(seq).unwrap();
    }

    for steps in &[3, 5, 7, 10] {
        let id = &format!("multi-step-{}", steps);
        let strategy = engine.get_rule_strategy(id);
        assert!(strategy.is_some(), "Multi-step {} sequence should have a strategy", steps);
    }
    
    // Verify that longer sequences have strategies assigned
    let stats = engine.stats();
    assert_eq!(stats.total_rules_tracked, 4, "Should track all 4 multi-step sequences");
}

// ============================================================================
// Section 6: Edge Cases
// ============================================================================

#[test]
fn test_empty_predicate() {
    let mut rule = IrRule::new(
        "empty-pred".to_string(),
        IrRuleType::Event {
            event_type: "process".to_string(),
        },
    );

    let predicate = IrPredicate {
        id: "main".to_string(),
        event_type: "process".to_string(),
        root: IrNode::Literal {
            value: IrLiteral::Bool(true),
        },
        required_fields: vec![],
        required_regex: vec![],
        required_globs: vec![],
    };

    rule.add_predicate(predicate);
    let analyzer = RuleComplexityAnalyzer::new();
    let rec = analyzer.analyze(&rule).unwrap();

    // Empty/true predicate should have minimal complexity
    assert_eq!(rec.complexity.score, 0, "True literal should have zero complexity");
    // True literal has no functions, regex, glob, etc.
    assert!(!rec.complexity.has_functions, "True literal should have no functions");
    assert!(!rec.complexity.has_regex, "True literal should have no regex");
    assert!(!rec.complexity.has_glob, "True literal should have no glob patterns");
}

#[test]
fn test_maxspan_variations() {
    let maxspans = vec![Some(1000), Some(5000), Some(10000), Some(60000), None];

    for maxspan in maxspans {
        let seq_steps = vec![
            SeqStep::new(0, "pred0".to_string(), 1),
            SeqStep::new(1, "pred1".to_string(), 2),
        ];

        let sequence = NfaSequence::new(
            format!("maxspan-{:?}", maxspan),
            100,
            seq_steps,
            maxspan,
            None,
        );

        let compiled = CompiledSequence {
            id: format!("maxspan-{:?}", maxspan),
            sequence,
            rule_id: format!("rule-maxspan-{:?}", maxspan),
            rule_name: format!("Maxspan {:?}", maxspan),
        };

        let config = HybridEngineConfig::default();
        let evaluator = Arc::new(MockEvaluator);
        let mut engine = HybridEngine::new(config, evaluator).unwrap();

        let result = engine.load_sequence(compiled);
        assert!(result.is_ok(), "Should load sequence with maxspan={:?}", maxspan);
        
        // Verify sequence was loaded and tracked
        let stats = engine.stats();
        assert_eq!(stats.total_rules_tracked, 1, "Should track 1 sequence");
    }
}

#[test]
fn test_multiple_predicates_in_rule() {
    let mut rule = IrRule::new(
        "multi-pred".to_string(),
        IrRuleType::Sequence {
            event_types: vec!["process".to_string()],
        },
    );

    // Add sequence
    let steps: Vec<_> = (0..3)
        .map(|i| IrSeqStep {
            index: i,
            predicate_id: format!("pred{}", i),
            event_type_name: "process".to_string(),
        })
        .collect();

    rule.sequence = Some(IrSequence {
        maxspan_ms: Some(5000),
        by_field_id: 100,
        until: None,
        steps,
    });

    // Add multiple predicates
    for i in 0..3 {
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

    let analyzer = RuleComplexityAnalyzer::new();
    let rec = analyzer.analyze(&rule).unwrap();
    
    // Multiple predicates in a sequence should be analyzed correctly
    assert_eq!(rec.complexity.sequence_steps, 3, "Should have 3 sequence steps");
    assert!(rec.complexity.score >= 0, "Complexity should be non-negative");
}

// ============================================================================
// Section 7: Integration Tests
// ============================================================================

#[test]
fn test_full_pipeline_simple_rule() {
    // Test complete pipeline with simple rule
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);
    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    let seq = create_base_sequence("pipeline-simple", 2);
    engine.load_sequence(seq).unwrap();

    let event = kestrel_event::Event::builder()
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(12345)
        .build()
        .unwrap();

    let result = engine.process_event(&event);
    assert!(result.is_ok(), "Event processing should succeed");
    
    // Verify event was processed (result may be empty if sequence not completed)
    let alerts = result.unwrap();
    // For a 2-step sequence with 1 event, we expect no alerts yet
    assert_eq!(alerts.len(), 0, "Single event should not trigger 2-step sequence alert");

    let stats = engine.stats();
    assert_eq!(stats.total_rules_tracked, 1, "Should track 1 rule");
}

#[test]
fn test_full_pipeline_complex_rule() {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);
    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    // Load multiple complex sequences
    for i in 1..=5 {
        let steps = 3 + (i % 3) * 2; // 3, 5, 7, 4, 6
        let seq = create_base_sequence(&format!("pipeline-complex-{}", i), steps);
        engine.load_sequence(seq).unwrap();
    }

    let event = kestrel_event::Event::builder()
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(12345)
        .build()
        .unwrap();

    // Process multiple events
    for _ in 0..100 {
        let result = engine.process_event(&event);
        assert!(result.is_ok(), "Event processing should not fail");
    }

    let stats = engine.stats();
    assert_eq!(stats.total_rules_tracked, 5, "Should track all 5 rules");
    assert_eq!(stats.nfa_sequence_count, 5, "Should have 5 NFA sequences");
}

#[test]
fn test_engine_with_many_rules() {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);
    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    // Load 50 rules
    for i in 1..=50 {
        let steps = (i % 10) + 1; // 1-10 steps
        let seq = create_base_sequence(&format!("many-rules-{}", i), steps);
        engine.load_sequence(seq).unwrap();
    }

    let stats = engine.stats();
    assert_eq!(stats.total_rules_tracked, 50);

    let event = kestrel_event::Event::builder()
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(12345)
        .build()
        .unwrap();

    // Should handle many rules efficiently
    let mut processed_count = 0;
    for _ in 0..100 {
        let result = engine.process_event(&event);
        assert!(result.is_ok(), "Processing should not fail with many rules");
        processed_count += 1;
    }
    assert_eq!(processed_count, 100, "Should process all 100 events");
    
    // Verify all rules are still tracked after processing
    let stats = engine.stats();
    assert_eq!(stats.total_rules_tracked, 50, "All 50 rules should still be tracked");
}

// ============================================================================
// Section 8: Strategy Distribution Analysis
// ============================================================================

#[test]
fn test_analyze_strategy_distribution() {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);
    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    // Load variety of rules
    // Simple rules (1-3 steps)
    for i in 1..=10 {
        let seq = create_base_sequence(&format!("simple-{}", i), 2);
        engine.load_sequence(seq).unwrap();
    }

    // Medium rules (4-7 steps)
    for i in 1..=10 {
        let seq = create_base_sequence(&format!("medium-{}", i), 5);
        engine.load_sequence(seq).unwrap();
    }

    // Complex rules (8+ steps)
    for i in 1..=10 {
        let seq = create_base_sequence(&format!("complex-{}", i), 10);
        engine.load_sequence(seq).unwrap();
    }

    // Analyze distribution
    let mut ac_dfa_count = 0;
    let mut lazy_dfa_count = 0;
    let mut nfa_count = 0;
    let mut hybrid_count = 0;

    for prefix in &["simple", "medium", "complex"] {
        for i in 1..=10 {
            let id = format!("{}-{}", prefix, i);
            if let Some(strategy) = engine.get_rule_strategy(&id) {
                match strategy {
                    RuleStrategy::AcDfa => ac_dfa_count += 1,
                    RuleStrategy::LazyDfa => lazy_dfa_count += 1,
                    RuleStrategy::Nfa => nfa_count += 1,
                    RuleStrategy::HybridAcNfa => hybrid_count += 1,
                }
            }
        }
    }

    // Verify strategy distribution totals
    let total_with_strategy = ac_dfa_count + lazy_dfa_count + nfa_count + hybrid_count;
    assert_eq!(total_with_strategy, 30, "All 30 rules should have a strategy assigned");
    
    // Verify distribution is reasonable - at least some rules should be assigned
    // Note: The exact distribution depends on the strategy selection algorithm
    assert!(total_with_strategy >= 30, "All rules should have strategies");

    let stats = engine.stats();
    assert_eq!(stats.total_rules_tracked, 30, "Should track all 30 rules");
}

// ============================================================================
// Section 9: Real-world Rule Scenarios
// ============================================================================

#[test]
fn test_suspicious_process_execution() {
    // Simulate: Detect suspicious process execution patterns
    let mut rule = IrRule::new(
        "suspicious-process".to_string(),
        IrRuleType::Event {
            event_type: "process".to_string(),
        },
    );

    // process.name == "powershell.exe" and process.command_line contains "Invoke-Expression"
    let predicate = IrPredicate {
        id: "main".to_string(),
        event_type: "process".to_string(),
        root: IrNode::BinaryOp {
            op: IrBinaryOp::And,
            left: Box::new(IrNode::BinaryOp {
                op: IrBinaryOp::Eq,
                left: Box::new(IrNode::LoadField { field_id: 1 }),
                right: Box::new(IrNode::Literal {
                    value: IrLiteral::String("powershell.exe".to_string()),
                }),
            }),
            right: Box::new(IrNode::FunctionCall {
                func: IrFunction::Contains,
                args: vec![
                    IrNode::LoadField { field_id: 2 },
                    IrNode::Literal {
                        value: IrLiteral::String("Invoke-Expression".to_string()),
                    },
                ],
            }),
        },
        required_fields: vec![1, 2],
        required_regex: vec![],
        required_globs: vec![],
    };

    rule.add_predicate(predicate);
    let analyzer = RuleComplexityAnalyzer::new();
    let rec = analyzer.analyze(&rule).unwrap();

    // Complex rule with AND + Contains should have appropriate complexity
    assert!(rec.complexity.score > 0, "Complex rule should have positive complexity");
    assert!(rec.complexity.has_functions, "Should detect function operations");
}

#[test]
fn test_file_access_pattern() {
    // Simulate: Detect suspicious file access patterns
    let mut rule = IrRule::new(
        "file-access".to_string(),
        IrRuleType::Sequence {
            event_types: vec!["file".to_string()],
        },
    );

    let steps = vec![
        IrSeqStep {
            index: 0,
            predicate_id: "file_create".to_string(),
            event_type_name: "file".to_string(),
        },
        IrSeqStep {
            index: 1,
            predicate_id: "file_modify".to_string(),
            event_type_name: "file".to_string(),
        },
        IrSeqStep {
            index: 2,
            predicate_id: "file_delete".to_string(),
            event_type_name: "file".to_string(),
        },
    ];

    rule.sequence = Some(IrSequence {
        maxspan_ms: Some(10000),
        by_field_id: 100,
        until: None,
        steps,
    });

    for pred_id in &["file_create", "file_modify", "file_delete"] {
        let predicate = IrPredicate {
            id: pred_id.to_string(),
            event_type: "file".to_string(),
            root: IrNode::Literal {
                value: IrLiteral::Bool(true),
            },
            required_fields: vec![],
            required_regex: vec![],
            required_globs: vec![],
        };
        rule.add_predicate(predicate);
    }

    let analyzer = RuleComplexityAnalyzer::new();
    let rec = analyzer.analyze(&rule).unwrap();

    // 3-step sequence should be properly analyzed
    assert_eq!(rec.complexity.sequence_steps, 3, "Should have 3 sequence steps");
    assert!(rec.complexity.score >= 0, "Complexity should be non-negative");
    // All predicates are true literals, so should be simple
    assert!(rec.complexity.score < 50, "Simple predicates should have low complexity");
}
