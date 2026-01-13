// Pattern types for AC-DFA
//
// Defines the various string matching patterns that can be extracted
// from EQL predicates and compiled into the Aho-Corasick automaton.

use crate::{AcDfaError, AcDfaResult};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A string matching pattern extracted from an EQL predicate
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MatchPattern {
    /// The pattern string to match
    pub pattern: String,

    /// Which field this pattern applies to
    pub field_id: u32,

    /// What kind of match operation to perform
    pub kind: PatternKind,

    /// Which predicate/rule this pattern belongs to
    pub rule_id: String,

    /// Unique identifier for this pattern
    pub pattern_id: String,
}

impl MatchPattern {
    /// Create a new match pattern
    pub fn new(
        pattern: String,
        field_id: u32,
        kind: PatternKind,
        rule_id: String,
    ) -> AcDfaResult<Self> {
        if pattern.is_empty() {
            return Err(AcDfaError::InvalidPattern(
                "Pattern cannot be empty".to_string(),
            ));
        }

        // Generate a unique pattern ID
        let pattern_id = format!("{}:{}:{}", rule_id, field_id, kind);

        Ok(Self {
            pattern,
            field_id,
            kind,
            rule_id,
            pattern_id,
        })
    }

    /// Create a pattern for exact equality matching
    pub fn equals(pattern: String, field_id: u32, rule_id: String) -> AcDfaResult<Self> {
        Self::new(pattern, field_id, PatternKind::Equals, rule_id)
    }

    /// Create a pattern for contains matching
    pub fn contains(pattern: String, field_id: u32, rule_id: String) -> AcDfaResult<Self> {
        Self::new(pattern, field_id, PatternKind::Contains, rule_id)
    }

    /// Create a pattern for prefix matching
    pub fn starts_with(
        pattern: String,
        field_id: u32,
        rule_id: String,
    ) -> AcDfaResult<Self> {
        Self::new(pattern, field_id, PatternKind::StartsWith, rule_id)
    }

    /// Create a pattern for suffix matching
    pub fn ends_with(pattern: String, field_id: u32, rule_id: String) -> AcDfaResult<Self> {
        Self::new(pattern, field_id, PatternKind::EndsWith, rule_id)
    }

    /// Validate this pattern
    pub fn validate(&self, max_length: usize) -> AcDfaResult<()> {
        if self.pattern.len() > max_length {
            return Err(AcDfaError::PatternTooLong {
                length: self.pattern.len(),
                max: max_length,
            });
        }
        Ok(())
    }
}

/// The type of pattern matching to perform
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PatternKind {
    /// Exact equality: `field == "pattern"`
    Equals,

    /// Contains: `field contains "pattern"`
    Contains,

    /// Starts with: `field startswith "pattern"`
    StartsWith,

    /// Ends with: `field endswith "pattern"`
    EndsWith,
}

impl PatternKind {
    /// Get all pattern kinds
    pub fn all() -> &'static [PatternKind] {
        &[
            PatternKind::Equals,
            PatternKind::Contains,
            PatternKind::StartsWith,
            PatternKind::EndsWith,
        ]
    }
}

impl fmt::Display for PatternKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatternKind::Equals => write!(f, "=="),
            PatternKind::Contains => write!(f, "contains"),
            PatternKind::StartsWith => write!(f, "startswith"),
            PatternKind::EndsWith => write!(f, "endswith"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_creation() {
        let pattern = MatchPattern::equals("bash".to_string(), 1, "rule-1".to_string()).unwrap();
        assert_eq!(pattern.pattern, "bash");
        assert_eq!(pattern.field_id, 1);
        assert_eq!(pattern.kind, PatternKind::Equals);
        assert_eq!(pattern.rule_id, "rule-1");
    }

    #[test]
    fn test_pattern_empty() {
        let result = MatchPattern::equals("".to_string(), 1, "rule-1".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_pattern_validation() {
        let pattern = MatchPattern::equals("bash".to_string(), 1, "rule-1".to_string()).unwrap();
        assert!(pattern.validate(10).is_ok());
        assert!(pattern.validate(2).is_err());
    }

    #[test]
    fn test_pattern_kinds() {
        assert_eq!(PatternKind::all().len(), 4);
    }

    #[test]
    fn test_pattern_kind_display() {
        assert_eq!(PatternKind::Equals.to_string(), "==");
        assert_eq!(PatternKind::Contains.to_string(), "contains");
        assert_eq!(PatternKind::StartsWith.to_string(), "startswith");
        assert_eq!(PatternKind::EndsWith.to_string(), "endswith");
    }
}
