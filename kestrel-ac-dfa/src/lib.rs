// Kestrel AC-DFA - Aho-Corasick Multi-Pattern DFA
//!
// This crate provides fast multi-pattern string matching using the
// Aho-Corasick algorithm, optimized for Kestrel's event detection needs.
//
// ## Overview
//
// The AC-DFA acts as a fast pre-filter for the NFA engine, quickly
// eliminating events that don't match any string literals in predicates.
//
// ## Use Cases
//
// - String equality: `process.name == "bash"`
// - String contains: `process.command_line contains "ssh"`
// - String prefix: `process.command_line startswith "/usr/bin"`
// - String suffix: `file.path endswith ".exe"`
//
// ## Architecture
//
// ```text
// ┌─────────────────────────────────────────────────┐
// │           AC Automaton Builder                  │
// │  (extracts string literals from IR predicates)  │
// └──────────────┬──────────────────────────────────┘
//                │
//                v
// ┌─────────────────────────────────────────────────┐
// │         Aho-Corasick DFA                        │
// │  (multi-pattern matching in O(n) time)         │
// └──────────────┬──────────────────────────────────┘
//                │
//                v
// ┌─────────────────────────────────────────────────┐
// │         Matcher Interface                       │
// │  - matches: HashSet<String>                    │
// │  - field_id: u32                               │
// │  - match_type: MatchType                       │
// └─────────────────────────────────────────────────┘
// ```

mod builder;
mod matcher;
mod pattern;

#[cfg(test)]
mod perf;

pub use builder::{AcDfaBuilder, PatternExtractor};
pub use matcher::{AcMatcher, MatchType, StringMatch};
pub use pattern::{MatchPattern, PatternKind};

use thiserror::Error;

/// Errors that can occur in the AC-DFA
#[derive(Debug, Error)]
pub enum AcDfaError {
    #[error("Invalid pattern: {0}")]
    InvalidPattern(String),

    #[error("No patterns provided")]
    NoPatterns,

    #[error("Pattern too long: {length} bytes (max: {max})")]
    PatternTooLong { length: usize, max: usize },

    #[error("Too many patterns: {count} (max: {max})")]
    TooManyPatterns { count: usize, max: usize },
}

/// Result type for AC-DFA operations
pub type AcDfaResult<T> = Result<T, AcDfaError>;

/// Configuration for the AC-DFA
#[derive(Debug, Clone)]
pub struct AcDfaConfig {
    /// Maximum number of patterns (0 = unlimited)
    pub max_patterns: usize,

    /// Maximum pattern length in bytes (0 = unlimited)
    pub max_pattern_length: usize,

    /// Enable case-insensitive matching
    pub case_insensitive: bool,

    /// Enable UTF-8 validation
    pub validate_utf8: bool,
}

impl Default for AcDfaConfig {
    fn default() -> Self {
        Self {
            max_patterns: 10_000,
            max_pattern_length: 4096,
            case_insensitive: false,
            validate_utf8: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = AcDfaConfig::default();
        assert_eq!(config.max_patterns, 10_000);
        assert_eq!(config.max_pattern_length, 4096);
        assert!(!config.case_insensitive);
        assert!(config.validate_utf8);
    }

    #[test]
    fn test_error_display() {
        let err = AcDfaError::InvalidPattern("test".to_string());
        assert!(err.to_string().contains("test"));
    }
}
