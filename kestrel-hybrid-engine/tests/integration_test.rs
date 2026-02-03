// Integration tests for Hybrid Engine
//
// Tests the complete workflow from rule analysis through
// strategy selection to event processing.

use kestrel_hybrid_engine::{
    analyze_rule, HybridEngine, HybridEngineConfig, MatchingStrategy, RuleComplexityAnalyzer,
    RuleStrategy,
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
        Ok(vec![1, 2])
    }

    fn has_predicate(&self, predicate_id: &str) -> bool {
        !predicate_id.is_empty()
    }
}

// Helper function to create a test sequence
fn create_test_sequence(id: &str, step_count: usize) -> CompiledSequence {
    let steps: Vec<_> = (0..step_count)
        .map(|i| SeqStep::new(i as u16, format!("pred{}", i), (i + 1) as u16))
        .collect();

    let sequence = NfaSequence::new(
        id.to_string(),
        100, // by_field_id
        steps,
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
fn test_rule_complexity_analyzer_simple() {
    let mut rule = IrRule::new(
        "simple-rule".to_string(),
        IrRuleType::Event {
            event_type: "process".to_string(),
        },
    );

    // Simple string literal rule
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

    let recommendation = analyze_rule(&rule).unwrap();

    assert_eq!(recommendation.strategy, MatchingStrategy::AcDfa);
    assert!(recommendation.confidence > 0.8);
    assert!(recommendation.complexity.is_simple());
    assert!(recommendation.complexity.has_string_literals());
}

#[test]
fn test_rule_complexity_analyzer_complex() {
    let mut rule = IrRule::new(
        "complex-rule".to_string(),
        IrRuleType::Event {
            event_type: "file".to_string(),
        },
    );

    // Complex rule with regex
    let predicate = IrPredicate {
        id: "main".to_string(),
        event_type: "file".to_string(),
        root: IrNode::FunctionCall {
            func: IrFunction::Regex,
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

    let recommendation = analyze_rule(&rule).unwrap();

    // Should recommend HybridAcNfa due to regex + string literals
    // (regex function has a string argument, so it's complex but has string literals)
    assert!(matches!(
        recommendation.strategy,
        MatchingStrategy::HybridAcNfa
    ));
    assert!(!recommendation.complexity.is_simple());
    assert!(recommendation.complexity.has_regex);
}

#[test]
fn test_hybrid_engine_load_sequence() {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);

    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    // Load a simple sequence
    let sequence = create_test_sequence("seq-1", 2);
    let result = engine.load_sequence(sequence);

    assert!(result.is_ok());

    // Check that strategy was recorded
    let strategy = engine.get_rule_strategy("seq-1");
    assert!(strategy.is_some());
}

#[test]
fn test_hybrid_engine_multiple_strategies() {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);

    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    // Load multiple sequences
    let seq1 = create_test_sequence("seq-1", 2);
    let seq2 = create_test_sequence("seq-2", 3);
    let seq3 = create_test_sequence("seq-3", 1);

    engine.load_sequence(seq1).unwrap();
    engine.load_sequence(seq2).unwrap();
    engine.load_sequence(seq3).unwrap();

    // Check that all have strategies
    let stats = engine.stats();
    assert_eq!(stats.total_rules_tracked, 3);

    // All should have some strategy assigned
    for id in &["seq-1", "seq-2", "seq-3"] {
        let strategy = engine.get_rule_strategy(id);
        assert!(strategy.is_some(), "Sequence {} should have a strategy", id);

        if let Some(s) = strategy {
            match s {
                RuleStrategy::AcDfa
                | RuleStrategy::LazyDfa
                | RuleStrategy::Nfa
                | RuleStrategy::HybridAcNfa => {
                    println!("Sequence {} has strategy {:?}", id, s);
                }
            }
        }
    }
}

#[test]
fn test_engine_statistics() {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);

    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    // Load some sequences
    engine.load_sequence(create_test_sequence("seq-1", 2)).unwrap();
    engine.load_sequence(create_test_sequence("seq-2", 3)).unwrap();

    // Get statistics
    let stats = engine.stats();

    assert_eq!(stats.total_rules_tracked, 2);
    assert_eq!(stats.nfa_sequence_count, 2); // All sequences loaded into NFA
}

#[test]
fn test_strategy_types() {
    // Verify all strategy types can be created and compared
    let strategies = vec![
        RuleStrategy::AcDfa,
        RuleStrategy::LazyDfa,
        RuleStrategy::Nfa,
        RuleStrategy::HybridAcNfa,
    ];

    for strategy in strategies {
        match strategy {
            RuleStrategy::AcDfa => println!("AC-DFA strategy"),
            RuleStrategy::LazyDfa => println!("Lazy DFA strategy"),
            RuleStrategy::Nfa => println!("NFA strategy"),
            RuleStrategy::HybridAcNfa => println!("Hybrid AC-DFA+NFA strategy"),
        }
    }

    // Test equality
    assert_eq!(RuleStrategy::Nfa, RuleStrategy::Nfa);
    assert_ne!(RuleStrategy::AcDfa, RuleStrategy::Nfa);
}

#[test]
fn test_complexity_scoring() {
    let mut rule = IrRule::new(
        "score-test".to_string(),
        IrRuleType::Event {
            event_type: "process".to_string(),
        },
    );

    // Add a sequence
    rule.sequence = Some(kestrel_eql::ir::IrSequence {
        maxspan_ms: Some(5000),
        by_field_id: 100,
        until: None,
        steps: vec![
            kestrel_eql::ir::IrSeqStep {
                index: 0,
                predicate_id: "main".to_string(),
                event_type_name: "process".to_string(),
            },
            kestrel_eql::ir::IrSeqStep {
                index: 1,
                predicate_id: "main".to_string(),
                event_type_name: "file".to_string(),
            },
        ],
    });

    // Simple predicate with string literal
    let predicate = IrPredicate {
        id: "main".to_string(),
        event_type: "process".to_string(),
        root: IrNode::BinaryOp {
            op: IrBinaryOp::Eq,
            left: Box::new(IrNode::LoadField { field_id: 1 }),
            right: Box::new(IrNode::Literal {
                value: IrLiteral::String("test".to_string()),
            }),
        },
        required_fields: vec![1],
        required_regex: vec![],
        required_globs: vec![],
    };

    rule.add_predicate(predicate);

    let recommendation = analyze_rule(&rule).unwrap();

    // Should be simple with low score
    assert!(recommendation.complexity.score < 50);
    assert!(recommendation.complexity.sequence_steps == 2);
}
