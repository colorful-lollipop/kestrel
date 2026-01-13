// Builder and Pattern Extractor for AC-DFA
//
// This module provides functionality to extract string matching patterns
// from EQL IR predicates and build the AC-DFA matcher.

use crate::matcher::AcMatcher;
use crate::pattern::{MatchPattern, PatternKind};
use crate::{AcDfaConfig, AcDfaError, AcDfaResult};
use kestrel_eql::ir::{IrNode, IrPredicate};
use std::collections::HashSet;

/// Extracts string matching patterns from EQL IR predicates
pub struct PatternExtractor {
    /// Maximum number of patterns to extract
    max_patterns: usize,

    /// Maximum pattern length
    max_pattern_length: usize,

    /// Whether to use case-insensitive matching
    /// Note: Currently not used in extraction but reserved for future use
    #[allow(dead_code)]
    case_insensitive: bool,
}

impl PatternExtractor {
    /// Create a new pattern extractor with default configuration
    pub fn new() -> Self {
        Self::with_config(AcDfaConfig::default())
    }

    /// Create a new pattern extractor with custom configuration
    pub fn with_config(config: AcDfaConfig) -> Self {
        Self {
            max_patterns: config.max_patterns,
            max_pattern_length: config.max_pattern_length,
            case_insensitive: config.case_insensitive,
        }
    }

    /// Extract patterns from a single predicate
    pub fn extract_from_predicate(
        &self,
        predicate: &IrPredicate,
        rule_id: &str,
    ) -> AcDfaResult<Vec<MatchPattern>> {
        let mut patterns = Vec::new();
        self.extract_from_node(&predicate.root, predicate, rule_id, &mut patterns)?;

        // Enforce pattern limit
        if self.max_patterns > 0 && patterns.len() > self.max_patterns {
            return Err(AcDfaError::TooManyPatterns {
                count: patterns.len(),
                max: self.max_patterns,
            });
        }

        Ok(patterns)
    }

    /// Extract patterns from a single IR node
    fn extract_from_node(
        &self,
        node: &IrNode,
        predicate: &IrPredicate,
        rule_id: &str,
        patterns: &mut Vec<MatchPattern>,
    ) -> AcDfaResult<()> {
        match node {
            // Binary operations: check for string comparisons
            IrNode::BinaryOp { op, left, right } => {
                // Handle logical operations by recursing into both sides
                if matches!(
                    op,
                    kestrel_eql::ir::IrBinaryOp::And | kestrel_eql::ir::IrBinaryOp::Or
                ) {
                    self.extract_from_node(left, predicate, rule_id, patterns)?;
                    self.extract_from_node(right, predicate, rule_id, patterns)?;
                } else {
                    // Handle comparison operations
                    self.extract_from_binary_op(op, left, right, predicate, rule_id, patterns)?;
                }
            }

            // Function calls: check for contains, startswith, endswith
            IrNode::FunctionCall { func, args } => {
                self.extract_from_function_call(func, args, predicate, rule_id, patterns)?;
            }

            // In operation: check for constant string sets
            IrNode::In { value, values } => {
                self.extract_from_in_op(value, values, predicate, rule_id, patterns)?;
            }

            // Unary operations: recurse into operand
            IrNode::UnaryOp { operand, .. } => {
                self.extract_from_node(operand, predicate, rule_id, patterns)?;
            }

            // Other node types: not relevant for pattern extraction
            _ => {}
        }

        Ok(())
    }

    /// Extract patterns from binary operations (e.g., field == "literal")
    fn extract_from_binary_op(
        &self,
        op: &kestrel_eql::ir::IrBinaryOp,
        left: &IrNode,
        right: &IrNode,
        _predicate: &IrPredicate,
        rule_id: &str,
        patterns: &mut Vec<MatchPattern>,
    ) -> AcDfaResult<()> {
        use kestrel_eql::ir::IrLiteral;

        // Only handle equality/inequality comparisons
        if !matches!(
            op,
            kestrel_eql::ir::IrBinaryOp::Eq | kestrel_eql::ir::IrBinaryOp::NotEq
        ) {
            return Ok(());
        }

        // Try to extract (field, string_literal) pair
        let (field_id, pattern_str) = match (left, right) {
            (IrNode::LoadField { field_id }, IrNode::Literal { value }) => {
                match value {
                    IrLiteral::String(s) => (*field_id, s),
                    _ => return Ok(()),
                }
            }
            (IrNode::Literal { value }, IrNode::LoadField { field_id }) => {
                match value {
                    IrLiteral::String(s) => (*field_id, s),
                    _ => return Ok(()),
                }
            }
            _ => return Ok(()),
        };

        // Validate pattern length
        if self.max_pattern_length > 0 && pattern_str.len() > self.max_pattern_length {
            return Ok(()); // Skip too-long patterns
        }

        // Create the pattern
        let pattern = MatchPattern::new(
            pattern_str.clone(),
            field_id,
            PatternKind::Equals,
            rule_id.to_string(),
        )?;

        patterns.push(pattern);

        Ok(())
    }

    /// Extract patterns from function calls (contains, startswith, endswith)
    fn extract_from_function_call(
        &self,
        func: &kestrel_eql::ir::IrFunction,
        args: &[IrNode],
        _predicate: &IrPredicate,
        rule_id: &str,
        patterns: &mut Vec<MatchPattern>,
    ) -> AcDfaResult<()> {
        use kestrel_eql::ir::IrFunction;

        // Check if this is a string function we care about
        let kind = match func {
            IrFunction::Contains => PatternKind::Contains,
            IrFunction::StartsWith => PatternKind::StartsWith,
            IrFunction::EndsWith => PatternKind::EndsWith,
            _ => return Ok(()),
        };

        // Extract arguments: func(field, "pattern") or func("pattern", field)
        if args.len() < 2 {
            return Ok(());
        }

        let (field_id, pattern_str) = match (&args[0], &args[1]) {
            (IrNode::LoadField { field_id }, IrNode::Literal { value: lit }) => {
                (field_id, lit)
            }
            (IrNode::Literal { value: lit }, IrNode::LoadField { field_id }) => {
                (field_id, lit)
            }
            _ => return Ok(()),
        };

        // Only extract string literals
        let pattern_str = match pattern_str {
            kestrel_eql::ir::IrLiteral::String(s) => s,
            _ => return Ok(()),
        };

        // Validate pattern length
        if self.max_pattern_length > 0 && pattern_str.len() > self.max_pattern_length {
            return Ok(());
        }

        // Create the pattern
        let pattern = MatchPattern::new(
            pattern_str.clone(),
            *field_id,
            kind,
            rule_id.to_string(),
        )?;

        patterns.push(pattern);

        Ok(())
    }

    /// Extract patterns from "in" operations
    fn extract_from_in_op(
        &self,
        value: &IrNode,
        values: &[kestrel_eql::ir::IrLiteral],
        _predicate: &IrPredicate,
        rule_id: &str,
        patterns: &mut Vec<MatchPattern>,
    ) -> AcDfaResult<()> {
        // Get the field being tested
        let field_id = match value {
            IrNode::LoadField { field_id } => field_id,
            _ => return Ok(()),
        };

        // Extract all string literals from the value set
        for lit in values {
            if let kestrel_eql::ir::IrLiteral::String(pattern_str) = lit {
                // Validate pattern length
                if self.max_pattern_length > 0 && pattern_str.len() > self.max_pattern_length {
                    continue;
                }

                // Create the pattern
                let pattern = MatchPattern::new(
                    pattern_str.clone(),
                    *field_id,
                    PatternKind::Equals,
                    rule_id.to_string(),
                )?;

                patterns.push(pattern);
            }
        }

        Ok(())
    }
}

impl Default for PatternExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing an AC-DFA matcher from EQL IR
pub struct AcDfaBuilder {
    config: AcDfaConfig,
    patterns: Vec<MatchPattern>,
    rule_ids: HashSet<String>,
}

impl AcDfaBuilder {
    /// Create a new builder with default configuration
    pub fn new() -> Self {
        Self::with_config(AcDfaConfig::default())
    }

    /// Create a new builder with custom configuration
    pub fn with_config(config: AcDfaConfig) -> Self {
        Self {
            config,
            patterns: Vec::new(),
            rule_ids: HashSet::new(),
        }
    }

    /// Add patterns from a predicate
    pub fn add_predicate(
        mut self,
        predicate: &IrPredicate,
        rule_id: &str,
    ) -> AcDfaResult<Self> {
        // Prevent duplicate rule IDs
        if self.rule_ids.contains(rule_id) {
            return Ok(self);
        }

        let extractor = PatternExtractor::with_config(self.config.clone());
        let mut new_patterns = extractor.extract_from_predicate(predicate, rule_id)?;

        // Enforce pattern limit
        let remaining = if self.config.max_patterns > 0 {
            self.config.max_patterns.saturating_sub(self.patterns.len())
        } else {
            usize::MAX
        };

        if new_patterns.len() > remaining {
            new_patterns.truncate(remaining);
        }

        self.patterns.extend(new_patterns);
        self.rule_ids.insert(rule_id.to_string());

        Ok(self)
    }

    /// Add patterns from multiple predicates
    pub fn add_predicates(
        mut self,
        predicates: &[(String, IrPredicate)],
    ) -> AcDfaResult<Self> {
        for (rule_id, predicate) in predicates {
            self = self.add_predicate(predicate, rule_id)?;
        }

        Ok(self)
    }

    /// Build the AC matcher
    pub fn build(self) -> AcDfaResult<AcMatcher> {
        if self.patterns.is_empty() {
            return Err(AcDfaError::NoPatterns);
        }

        AcMatcher::new(self.patterns, self.config)
    }

    /// Get the number of patterns extracted
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

impl Default for AcDfaBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_eql::ir::{IrNode, IrPredicate, IrFunction};

    #[test]
    fn test_extractor_creation() {
        let extractor = PatternExtractor::new();
        assert_eq!(extractor.max_patterns, 10_000);
    }

    #[test]
    fn test_builder_creation() {
        let builder = AcDfaBuilder::new();
        assert_eq!(builder.pattern_count(), 0);
    }

    #[test]
    fn test_extract_equality() {
        let predicate = IrPredicate {
            id: "pred1".to_string(),
            event_type: "process".to_string(),
            root: IrNode::BinaryOp {
                op: kestrel_eql::ir::IrBinaryOp::Eq,
                left: Box::new(IrNode::LoadField { field_id: 1 }),
                right: Box::new(IrNode::Literal {
                    value: kestrel_eql::ir::IrLiteral::String("bash".to_string()),
                }),
            },
            required_fields: vec![1],
            required_regex: vec![],
            required_globs: vec![],
        };

        let extractor = PatternExtractor::new();
        let patterns = extractor.extract_from_predicate(&predicate, "rule-1").unwrap();

        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].pattern, "bash");
        assert_eq!(patterns[0].kind, PatternKind::Equals);
    }

    #[test]
    fn test_extract_contains() {
        let predicate = IrPredicate {
            id: "pred1".to_string(),
            event_type: "process".to_string(),
            root: IrNode::FunctionCall {
                func: IrFunction::Contains,
                args: vec![
                    IrNode::LoadField { field_id: 1 },
                    IrNode::Literal {
                        value: kestrel_eql::ir::IrLiteral::String("ssh".to_string()),
                    },
                ],
            },
            required_fields: vec![1],
            required_regex: vec![],
            required_globs: vec![],
        };

        let extractor = PatternExtractor::new();
        let patterns = extractor.extract_from_predicate(&predicate, "rule-1").unwrap();

        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].pattern, "ssh");
        assert_eq!(patterns[0].kind, PatternKind::Contains);
    }
}
