// Rule Complexity Analyzer - Analyzes EQL rules to determine optimal matching strategy
//
// Classifies rules by complexity and recommends whether to use:
// - AC-DFA (for string literal rules)
// - Lazy DFA (for hot, simple sequences)
// - NFA (for complex rules)

use crate::HybridEngineError;
use kestrel_eql::ir::{IrNode, IrPredicate, IrRule, IrFunction};

/// Complexity score for a rule
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RuleComplexity {
    /// Overall complexity score (0-100, higher = more complex)
    pub score: u8,

    /// Number of sequence steps
    pub sequence_steps: usize,

    /// Has regex patterns?
    pub has_regex: bool,

    /// Has glob patterns?
    pub has_glob: bool,

    /// Has function calls?
    pub has_functions: bool,

    /// Has captures?
    pub has_captures: bool,

    /// Has until condition?
    pub has_until: bool,

    /// String literal count
    pub string_literals: usize,
}

impl RuleComplexity {
    pub fn new() -> Self {
        Self {
            score: 0,
            sequence_steps: 0,
            has_regex: false,
            has_glob: false,
            has_functions: false,
            has_captures: false,
            has_until: false,
            string_literals: 0,
        }
    }

    /// Calculate overall complexity score
    pub fn calculate(&mut self) {
        let mut score = 0u8;

        // Sequence steps add complexity
        score += (self.sequence_steps as u8) * 10;

        // Regex is complex
        if self.has_regex {
            score += 30;
        }

        // Glob is moderately complex
        if self.has_glob {
            score += 20;
        }

        // Function calls add complexity
        if self.has_functions {
            score += 15;
        }

        // Captures add complexity
        if self.has_captures {
            score += 10;
        }

        // Until condition is complex
        if self.has_until {
            score += 25;
        }

        // String literals reduce relative complexity (they're simple)
        if self.string_literals > 0 {
            score = score.saturating_sub((self.string_literals as u8) * 2);
        }

        // Clamp to 0-100
        self.score = score.min(100);
    }

    /// Check if this is a simple rule (suitable for DFA)
    pub fn is_simple(&self) -> bool {
        self.score < 40 && !self.has_regex && !self.has_until
    }

    /// Check if this has string literals (suitable for AC-DFA)
    pub fn has_string_literals(&self) -> bool {
        self.string_literals > 0
    }
}

impl Default for RuleComplexity {
    fn default() -> Self {
        Self::new()
    }
}

/// Recommended matching strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchingStrategy {
    /// Use AC-DFA for fast string matching
    AcDfa,

    /// Use lazy DFA for hot sequences
    LazyDfa,

    /// Use NFA (default for complex rules)
    Nfa,

    /// Hybrid: AC-DFA pre-filter + NFA
    HybridAcNfa,
}

/// Strategy recommendation with reasoning
#[derive(Debug, Clone)]
pub struct StrategyRecommendation {
    /// Recommended strategy
    pub strategy: MatchingStrategy,

    /// Complexity score
    pub complexity: RuleComplexity,

    /// Reason for this recommendation
    pub reason: String,

    /// Confidence in this recommendation (0.0 - 1.0)
    pub confidence: f64,
}

/// Rule complexity analyzer
pub struct RuleComplexityAnalyzer;

impl RuleComplexityAnalyzer {
    /// Analyze a rule and recommend a matching strategy
    pub fn analyze(rule: &IrRule) -> Result<StrategyRecommendation, HybridEngineError> {
        let mut complexity = RuleComplexity::new();

        // Analyze sequence
        if let Some(seq) = &rule.sequence {
            complexity.sequence_steps = seq.steps.len();
            complexity.has_until = seq.until.is_some();
        }

        // Analyze predicates
        for predicate in rule.predicates.values() {
            Self::analyze_predicate(predicate, &mut complexity);
        }

        // Analyze captures
        complexity.has_captures = !rule.captures.is_empty();

        // Calculate final score
        complexity.calculate();

        // Generate recommendation
        let recommendation = Self::recommend_strategy(&complexity);

        Ok(recommendation)
    }

    /// Analyze a predicate
    fn analyze_predicate(predicate: &IrPredicate, complexity: &mut RuleComplexity) {
        // Check for regex
        if !predicate.required_regex.is_empty() {
            complexity.has_regex = true;
        }

        // Check for glob
        if !predicate.required_globs.is_empty() {
            complexity.has_glob = true;
        }

        // Analyze the predicate AST
        Self::analyze_node(&predicate.root, complexity);
    }

    /// Analyze an IR node
    fn analyze_node(node: &IrNode, complexity: &mut RuleComplexity) {
        match node {
            // String literals
            IrNode::Literal { value } => {
                if matches!(value, kestrel_eql::ir::IrLiteral::String(_)) {
                    complexity.string_literals += 1;
                }
            }

            // Binary operations
            IrNode::BinaryOp { op: _, left, right } => {
                Self::analyze_node(left, complexity);
                Self::analyze_node(right, complexity);
            }

            // Function calls
            IrNode::FunctionCall { func, .. } => {
                complexity.has_functions = true;
                match func {
                    IrFunction::Regex => complexity.has_regex = true,
                    IrFunction::Wildcard => complexity.has_glob = true,
                    _ => {}
                }
            }

            // In operation (string sets)
            IrNode::In { values, .. } => {
                for value in values {
                    if matches!(value, kestrel_eql::ir::IrLiteral::String(_)) {
                        complexity.string_literals += 1;
                    }
                }
            }

            // Unary operations
            IrNode::UnaryOp { operand, .. } => {
                Self::analyze_node(operand, complexity);
            }

            _ => {}
        }
    }

    /// Recommend a matching strategy based on complexity
    fn recommend_strategy(complexity: &RuleComplexity) -> StrategyRecommendation {
        let (strategy, reason, confidence) = if complexity.has_string_literals() && complexity.is_simple() {
            // Simple rule with string literals -> AC-DFA
            (
                MatchingStrategy::AcDfa,
                format!(
                    "Simple rule ({} literals, complexity {})",
                    complexity.string_literals, complexity.score
                ),
                0.9,
            )
        } else if complexity.is_simple() && complexity.sequence_steps > 0 {
            // Simple sequence -> Lazy DFA (will be hot-spot detected)
            (
                MatchingStrategy::LazyDfa,
                format!(
                    "Simple sequence ({} steps, complexity {})",
                    complexity.sequence_steps, complexity.score
                ),
                0.8,
            )
        } else if complexity.has_string_literals() {
            // String literals but complex -> Hybrid AC-DFA + NFA
            (
                MatchingStrategy::HybridAcNfa,
                format!(
                    "Complex rule with {} string literals (complexity {})",
                    complexity.string_literals, complexity.score
                ),
                0.7,
            )
        } else {
            // Complex rule -> NFA
            (
                MatchingStrategy::Nfa,
                format!(
                    "Complex rule (complexity {}, regex={}, glob={})",
                    complexity.score, complexity.has_regex, complexity.has_glob
                ),
                0.95,
            )
        };

        StrategyRecommendation {
            strategy,
            complexity: complexity.clone(),
            reason,
            confidence,
        }
    }
}

impl Default for RuleComplexityAnalyzer {
    fn default() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_eql::ir::*;

    #[test]
    fn test_complexity_creation() {
        let complexity = RuleComplexity::new();
        assert_eq!(complexity.score, 0);
        assert!(!complexity.has_regex);
        assert!(complexity.is_simple());
    }

    #[test]
    fn test_complexity_calculation() {
        let mut complexity = RuleComplexity::new();
        complexity.sequence_steps = 2;
        complexity.string_literals = 5;
        complexity.calculate();

        // Score should be low due to string literals
        assert!(complexity.score < 40);
        assert!(complexity.is_simple());
        assert!(complexity.has_string_literals());
    }

    #[test]
    fn test_complexity_with_regex() {
        let mut complexity = RuleComplexity::new();
        complexity.sequence_steps = 1;
        complexity.has_regex = true;
        complexity.calculate();

        // Regex should increase complexity significantly
        assert!(complexity.score >= 30);
        assert!(!complexity.is_simple());
    }

    #[test]
    fn test_analyze_simple_rule() {
        let mut rule = IrRule::new(
            "test-rule".to_string(),
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

        let recommendation = RuleComplexityAnalyzer::analyze(&rule).unwrap();

        assert_eq!(recommendation.strategy, MatchingStrategy::AcDfa);
        assert!(recommendation.confidence > 0.8);
    }

    #[test]
    fn test_analyze_complex_rule() {
        let mut rule = IrRule::new(
            "test-rule".to_string(),
            IrRuleType::Event {
                event_type: "process".to_string(),
            },
        );

        let predicate = IrPredicate {
            id: "main".to_string(),
            event_type: "process".to_string(),
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

        let recommendation = RuleComplexityAnalyzer::analyze(&rule).unwrap();

        // Should recommend NFA due to regex
        assert!(matches!(
            recommendation.strategy,
            MatchingStrategy::Nfa
        ));
    }
}
