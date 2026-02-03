// Rule Complexity Analyzer - Analyzes EQL rules to determine optimal matching strategy
//
// Classifies rules by complexity and recommends whether to use:
// - AC-DFA (for string literal rules)
// - Lazy DFA (for hot, simple sequences)
// - NFA (for complex rules)

use crate::{AnalysisError, HybridEngineError};
use kestrel_eql::ir::{IrFunction, IrNode, IrPredicate, IrRule};

/// Configuration for complexity scoring weights
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComplexityWeights {
    /// Weight per sequence step (default: 10)
    pub sequence_step: u8,

    /// Weight for regex patterns (default: 30)
    pub regex: u8,

    /// Weight for glob patterns (default: 20)
    pub glob: u8,

    /// Weight for function calls (default: 15)
    pub function: u8,

    /// Weight for captures (default: 10)
    pub capture: u8,

    /// Weight for until conditions (default: 25)
    pub until: u8,

    /// Reduction per string literal (default: 2)
    pub string_literal_reduction: u8,

    /// Threshold for simple rules (default: 40)
    pub simple_threshold: u8,
}

impl ComplexityWeights {
    /// Create a new weights configuration with default values
    pub const fn new() -> Self {
        Self {
            sequence_step: 10,
            regex: 30,
            glob: 20,
            function: 15,
            capture: 10,
            until: 25,
            string_literal_reduction: 2,
            simple_threshold: 40,
        }
    }

    /// Create a conservative configuration (higher thresholds, prefers NFA)
    pub const fn conservative() -> Self {
        Self {
            sequence_step: 15,
            regex: 40,
            glob: 25,
            function: 20,
            capture: 15,
            until: 35,
            string_literal_reduction: 1,
            simple_threshold: 30,
        }
    }

    /// Create an aggressive configuration (lower thresholds, prefers DFA)
    pub const fn aggressive() -> Self {
        Self {
            sequence_step: 8,
            regex: 25,
            glob: 15,
            function: 10,
            capture: 5,
            until: 20,
            string_literal_reduction: 3,
            simple_threshold: 50,
        }
    }
}

impl Default for ComplexityWeights {
    fn default() -> Self {
        Self::new()
    }
}

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

    /// Calculate overall complexity score with custom weights
    pub fn calculate_with_weights(&mut self, weights: &ComplexityWeights) {
        let mut score: u16 = 0;

        // Sequence steps add complexity
        score += (self.sequence_steps as u16) * (weights.sequence_step as u16);

        // Regex is complex
        if self.has_regex {
            score += weights.regex as u16;
        }

        // Glob is moderately complex
        if self.has_glob {
            score += weights.glob as u16;
        }

        // Function calls add complexity
        if self.has_functions {
            score += weights.function as u16;
        }

        // Captures add complexity
        if self.has_captures {
            score += weights.capture as u16;
        }

        // Until condition is complex
        if self.has_until {
            score += weights.until as u16;
        }

        // String literals reduce relative complexity (they're simple)
        if self.string_literals > 0 {
            let reduction = (self.string_literals as u16) * (weights.string_literal_reduction as u16);
            score = score.saturating_sub(reduction);
        }

        // Clamp to 0-100
        self.score = score.min(100) as u8;
    }

    /// Calculate overall complexity score with default weights
    pub fn calculate(&mut self) {
        self.calculate_with_weights(&ComplexityWeights::default());
    }

    /// Check if this is a simple rule (suitable for DFA) with custom threshold
    pub fn is_simple_with_threshold(&self, threshold: u8) -> bool {
        self.score < threshold && !self.has_regex && !self.has_until
    }

    /// Check if this is a simple rule with default threshold
    pub fn is_simple(&self) -> bool {
        self.is_simple_with_threshold(ComplexityWeights::default().simple_threshold)
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

impl std::fmt::Display for MatchingStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchingStrategy::AcDfa => write!(f, "AC-DFA"),
            MatchingStrategy::LazyDfa => write!(f, "Lazy-DFA"),
            MatchingStrategy::Nfa => write!(f, "NFA"),
            MatchingStrategy::HybridAcNfa => write!(f, "Hybrid-AC-NFA"),
        }
    }
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

impl StrategyRecommendation {
    /// Create a new recommendation
    pub fn new(
        strategy: MatchingStrategy,
        complexity: RuleComplexity,
        reason: impl Into<String>,
        confidence: f64,
    ) -> Self {
        Self {
            strategy,
            complexity,
            reason: reason.into(),
            confidence: confidence.clamp(0.0, 1.0),
        }
    }
}

/// Rule complexity analyzer with configurable weights
#[derive(Debug, Clone)]
pub struct RuleComplexityAnalyzer {
    weights: ComplexityWeights,
}

impl RuleComplexityAnalyzer {
    /// Create a new analyzer with default weights
    pub fn new() -> Self {
        Self {
            weights: ComplexityWeights::default(),
        }
    }

    /// Create a new analyzer with custom weights
    pub fn with_weights(weights: ComplexityWeights) -> Self {
        Self { weights }
    }

    /// Create a conservative analyzer (prefers NFA for safety)
    pub fn conservative() -> Self {
        Self {
            weights: ComplexityWeights::conservative(),
        }
    }

    /// Create an aggressive analyzer (prefers DFA for performance)
    pub fn aggressive() -> Self {
        Self {
            weights: ComplexityWeights::aggressive(),
        }
    }

    /// Get the current weights
    pub fn weights(&self) -> &ComplexityWeights {
        &self.weights
    }

    /// Update the weights
    pub fn set_weights(&mut self, weights: ComplexityWeights) {
        self.weights = weights;
    }

    /// Analyze a rule and recommend a matching strategy
    pub fn analyze(&self, rule: &IrRule) -> Result<StrategyRecommendation, HybridEngineError> {
        let mut complexity = RuleComplexity::new();

        // Analyze sequence
        if let Some(seq) = &rule.sequence {
            complexity.sequence_steps = seq.steps.len();
            complexity.has_until = seq.until.is_some();
        }

        // Analyze predicates
        for predicate in rule.predicates.values() {
            Self::analyze_predicate(predicate, &mut complexity)?;
        }

        // Analyze captures
        complexity.has_captures = !rule.captures.is_empty();

        // Calculate final score
        complexity.calculate_with_weights(&self.weights);

        // Generate recommendation
        let recommendation = self.recommend_strategy(&complexity);

        Ok(recommendation)
    }

    /// Analyze a predicate
    fn analyze_predicate(
        predicate: &IrPredicate,
        complexity: &mut RuleComplexity,
    ) -> Result<(), AnalysisError> {
        // Check for regex
        if !predicate.required_regex.is_empty() {
            complexity.has_regex = true;
        }

        // Check for glob
        if !predicate.required_globs.is_empty() {
            complexity.has_glob = true;
        }

        // Analyze the predicate AST
        Self::analyze_node(&predicate.root, complexity)?;

        Ok(())
    }

    /// Analyze an IR node
    fn analyze_node(node: &IrNode, complexity: &mut RuleComplexity) -> Result<(), AnalysisError> {
        match node {
            // String literals
            IrNode::Literal { value } => {
                if matches!(value, kestrel_eql::ir::IrLiteral::String(_)) {
                    complexity.string_literals += 1;
                }
                Ok(())
            }

            // Binary operations
            IrNode::BinaryOp { left, right, .. } => {
                Self::analyze_node(left, complexity)?;
                Self::analyze_node(right, complexity)
            }

            // Function calls
            IrNode::FunctionCall { func, args } => {
                complexity.has_functions = true;
                match func {
                    IrFunction::Regex => complexity.has_regex = true,
                    IrFunction::Wildcard => complexity.has_glob = true,
                    _ => {}
                }
                // Analyze function arguments
                for arg in args {
                    Self::analyze_node(arg, complexity)?;
                }
                Ok(())
            }

            // In operation (string sets)
            IrNode::In { values, .. } => {
                for value in values {
                    if matches!(value, kestrel_eql::ir::IrLiteral::String(_)) {
                        complexity.string_literals += 1;
                    }
                }
                Ok(())
            }

            // Unary operations
            IrNode::UnaryOp { operand, .. } => Self::analyze_node(operand, complexity),

            // LoadField and other leaf nodes
            _ => Ok(()),
        }
    }

    /// Recommend a matching strategy based on complexity
    fn recommend_strategy(&self, complexity: &RuleComplexity) -> StrategyRecommendation {
        if complexity.has_string_literals() && complexity.is_simple_with_threshold(self.weights.simple_threshold) {
            // Simple rule with string literals -> AC-DFA
            StrategyRecommendation::new(
                MatchingStrategy::AcDfa,
                complexity.clone(),
                format!(
                    "Simple rule ({} literals, complexity {})",
                    complexity.string_literals, complexity.score
                ),
                0.9,
            )
        } else if complexity.is_simple_with_threshold(self.weights.simple_threshold) && complexity.sequence_steps > 0 {
            // Simple sequence -> Lazy DFA (will be hot-spot detected)
            StrategyRecommendation::new(
                MatchingStrategy::LazyDfa,
                complexity.clone(),
                format!(
                    "Simple sequence ({} steps, complexity {})",
                    complexity.sequence_steps, complexity.score
                ),
                0.8,
            )
        } else if complexity.has_string_literals() {
            // String literals but complex -> Hybrid AC-DFA + NFA
            StrategyRecommendation::new(
                MatchingStrategy::HybridAcNfa,
                complexity.clone(),
                format!(
                    "Complex rule with {} string literals (complexity {})",
                    complexity.string_literals, complexity.score
                ),
                0.7,
            )
        } else {
            // Complex rule -> NFA
            StrategyRecommendation::new(
                MatchingStrategy::Nfa,
                complexity.clone(),
                format!(
                    "Complex rule (complexity {}, regex={}, glob={})",
                    complexity.score, complexity.has_regex, complexity.has_glob
                ),
                0.95,
            )
        }
    }
}

impl Default for RuleComplexityAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function for one-off analysis with default weights
pub fn analyze_rule(rule: &IrRule) -> Result<StrategyRecommendation, HybridEngineError> {
    RuleComplexityAnalyzer::new().analyze(rule)
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
    fn test_complexity_with_custom_weights() {
        let mut complexity = RuleComplexity::new();
        complexity.sequence_steps = 2;
        complexity.string_literals = 5;

        // With aggressive weights, should be simpler
        let aggressive = ComplexityWeights::aggressive();
        complexity.calculate_with_weights(&aggressive);
        let aggressive_score = complexity.score;

        // Reset and calculate with conservative weights
        let mut complexity = RuleComplexity::new();
        complexity.sequence_steps = 2;
        complexity.string_literals = 5;

        let conservative = ComplexityWeights::conservative();
        complexity.calculate_with_weights(&conservative);
        let conservative_score = complexity.score;

        // Conservative should give higher score
        assert!(conservative_score >= aggressive_score);
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
    fn test_analyzer_creation() {
        let default_analyzer = RuleComplexityAnalyzer::new();
        assert_eq!(default_analyzer.weights().simple_threshold, 40);

        let conservative = RuleComplexityAnalyzer::conservative();
        assert_eq!(conservative.weights().simple_threshold, 30);

        let aggressive = RuleComplexityAnalyzer::aggressive();
        assert_eq!(aggressive.weights().simple_threshold, 50);
    }

    #[test]
    fn test_analyze_simple_rule() {
        let analyzer = RuleComplexityAnalyzer::new();
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

        let recommendation = analyzer.analyze(&rule).unwrap();

        assert_eq!(recommendation.strategy, MatchingStrategy::AcDfa);
        assert!(recommendation.confidence > 0.8);
    }

    #[test]
    fn test_analyze_complex_rule() {
        let analyzer = RuleComplexityAnalyzer::new();
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

        let recommendation = analyzer.analyze(&rule).unwrap();

        // Should recommend HybridAcNfa due to regex + string literals
        // (regex function has a string argument, so it's complex but has string literals)
        assert!(matches!(
            recommendation.strategy,
            MatchingStrategy::HybridAcNfa
        ));
    }

    #[test]
    fn test_convenience_function() {
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

        // Test convenience function
        let recommendation = analyze_rule(&rule).unwrap();
        assert_eq!(recommendation.strategy, MatchingStrategy::AcDfa);
    }

    #[test]
    fn test_matching_strategy_display() {
        assert_eq!(MatchingStrategy::AcDfa.to_string(), "AC-DFA");
        assert_eq!(MatchingStrategy::LazyDfa.to_string(), "Lazy-DFA");
        assert_eq!(MatchingStrategy::Nfa.to_string(), "NFA");
        assert_eq!(MatchingStrategy::HybridAcNfa.to_string(), "Hybrid-AC-NFA");
    }

    #[test]
    fn test_strategy_recommendation_new() {
        let complexity = RuleComplexity::new();
        let rec = StrategyRecommendation::new(
            MatchingStrategy::AcDfa,
            complexity,
            "Test reason",
            0.85,
        );
        
        assert_eq!(rec.strategy, MatchingStrategy::AcDfa);
        assert_eq!(rec.reason, "Test reason");
        assert!((rec.confidence - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn test_confidence_clamping() {
        let complexity = RuleComplexity::new();
        
        // Test upper bound
        let rec = StrategyRecommendation::new(
            MatchingStrategy::Nfa,
            complexity,
            "test",
            1.5,
        );
        assert!((rec.confidence - 1.0).abs() < f64::EPSILON);

        // Test lower bound
        let rec = StrategyRecommendation::new(
            MatchingStrategy::Nfa,
            complexity,
            "test",
            -0.5,
        );
        assert!((rec.confidence - 0.0).abs() < f64::EPSILON);
    }
}
