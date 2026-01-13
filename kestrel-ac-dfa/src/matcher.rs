// AC Matcher - performs fast multi-pattern string matching
//
// Uses the Aho-Corasick algorithm to match multiple patterns
// against event field values in O(n) time, where n is the text length.

use crate::pattern::{MatchPattern, PatternKind};
use crate::{AcDfaConfig, AcDfaError, AcDfaResult};
use ahash::AHashMap;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, Match as AcMatch};

/// A match found by the AC-DFA
#[derive(Debug, Clone)]
pub struct StringMatch {
    /// The pattern that matched
    pub pattern_id: String,

    /// The field that was matched
    pub field_id: u32,

    /// The kind of match
    pub kind: MatchType,

    /// The start position of the match
    pub start: usize,

    /// The end position of the match
    pub end: usize,
}

/// The type of match that occurred
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchType {
    /// The entire text equals the pattern
    Exact,

    /// The text contains the pattern
    Contains,

    /// The text starts with the pattern
    Prefix,

    /// The text ends with the pattern
    Suffix,
}

/// The AC-DFA matcher
pub struct AcMatcher {
    /// The underlying Aho-Corasick automaton
    automaton: AhoCorasick,

    /// Mapping from pattern ID to match pattern metadata
    patterns: AHashMap<usize, MatchPattern>,

    /// Configuration
    config: AcDfaConfig,
}

impl AcMatcher {
    /// Create a new AC matcher from patterns
    pub fn new(patterns: Vec<MatchPattern>, config: AcDfaConfig) -> AcDfaResult<Self> {
        if patterns.is_empty() {
            return Err(AcDfaError::NoPatterns);
        }

        if config.max_patterns > 0 && patterns.len() > config.max_patterns {
            return Err(AcDfaError::TooManyPatterns {
                count: patterns.len(),
                max: config.max_patterns,
            });
        }

        // Validate all patterns
        for pattern in &patterns {
            pattern.validate(config.max_pattern_length)?;
        }

        // Build the pattern vector for Aho-Corasick
        let ac_patterns: Vec<&str> = patterns.iter().map(|p| p.pattern.as_str()).collect();

        // Build the Aho-Corasick automaton
        let mut builder = AhoCorasickBuilder::new();
        builder
            .match_kind(aho_corasick::MatchKind::Standard); // Standard matching (leftmost-longest)

        if config.case_insensitive {
            builder.ascii_case_insensitive(true);
        }

        let automaton = builder.build(&ac_patterns).map_err(|e| {
            AcDfaError::InvalidPattern(format!("Failed to build automaton: {}", e))
        })?;

        // Build pattern mapping
        let mut pattern_map = AHashMap::default();
        for (idx, pattern) in patterns.into_iter().enumerate() {
            pattern_map.insert(idx, pattern);
        }

        Ok(Self {
            automaton,
            patterns: pattern_map,
            config,
        })
    }

    /// Check if a field value matches any patterns for that field
    pub fn matches_field(&self, field_id: u32, text: &str) -> Vec<StringMatch> {
        let mut matches = Vec::new();

        // Find all AC matches in the text
        for ac_match in self.automaton.find_iter(text) {
            let pattern_id = ac_match.pattern().as_usize();
            let pattern = match self.patterns.get(&pattern_id) {
                Some(p) => p,
                None => continue,
            };

            // Only match if the field ID matches
            if pattern.field_id != field_id {
                continue;
            }

            // Check if the match is valid for the pattern kind
            let match_type = self.validate_match(pattern, text, &ac_match);
            if let Some(kind) = match_type {
                matches.push(StringMatch {
                    pattern_id: pattern.pattern_id.clone(),
                    field_id: pattern.field_id,
                    kind,
                    start: ac_match.start(),
                    end: ac_match.end(),
                });
            }
        }

        matches
    }

    /// Validate that a match is valid for the pattern kind
    fn validate_match(
        &self,
        pattern: &MatchPattern,
        text: &str,
        ac_match: &AcMatch,
    ) -> Option<MatchType> {
        match pattern.kind {
            PatternKind::Equals => {
                // For equality, the match must span the entire text
                if ac_match.start() == 0 && ac_match.end() == text.len() {
                    Some(MatchType::Exact)
                } else {
                    None
                }
            }
            PatternKind::Contains => {
                // Contains is always valid for any match
                Some(MatchType::Contains)
            }
            PatternKind::StartsWith => {
                // For starts with, the match must start at position 0
                if ac_match.start() == 0 {
                    Some(MatchType::Prefix)
                } else {
                    None
                }
            }
            PatternKind::EndsWith => {
                // For ends with, the match must end at the text length
                if ac_match.end() == text.len() {
                    Some(MatchType::Suffix)
                } else {
                    None
                }
            }
        }
    }

    /// Get the number of patterns in this matcher
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Get a reference to the configuration
    pub fn config(&self) -> &AcDfaConfig {
        &self.config
    }

    /// Create a builder for constructing an AcMatcher
    pub fn builder() -> AcMatcherBuilder {
        AcMatcherBuilder::default()
    }
}

/// Builder for constructing an AcMatcher
#[derive(Default)]
pub struct AcMatcherBuilder {
    patterns: Vec<MatchPattern>,
    config: AcDfaConfig,
}

impl AcMatcherBuilder {
    /// Add a pattern to the matcher
    pub fn add_pattern(mut self, pattern: MatchPattern) -> Self {
        self.patterns.push(pattern);
        self
    }

    /// Add multiple patterns
    pub fn add_patterns(mut self, patterns: Vec<MatchPattern>) -> Self {
        self.patterns.extend(patterns);
        self
    }

    /// Set the configuration
    pub fn config(mut self, config: AcDfaConfig) -> Self {
        self.config = config;
        self
    }

    /// Build the matcher
    pub fn build(self) -> AcDfaResult<AcMatcher> {
        AcMatcher::new(self.patterns, self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::MatchPattern;

    #[test]
    fn test_matcher_creation() {
        let patterns = vec![
            MatchPattern::equals("bash".to_string(), 1, "rule-1".to_string()).unwrap(),
        ];

        let matcher = AcMatcher::new(patterns, AcDfaConfig::default()).unwrap();
        assert_eq!(matcher.pattern_count(), 1);
    }

    #[test]
    fn test_matcher_no_patterns() {
        let result = AcMatcher::new(vec![], AcDfaConfig::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_exact_match() {
        let patterns = vec![
            MatchPattern::equals("bash".to_string(), 1, "rule-1".to_string()).unwrap(),
        ];

        let matcher = AcMatcher::new(patterns, AcDfaConfig::default()).unwrap();
        let matches = matcher.matches_field(1, "bash");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, MatchType::Exact);
    }

    #[test]
    fn test_contains_match() {
        let patterns = vec![
            MatchPattern::contains("ssh".to_string(), 1, "rule-1".to_string()).unwrap(),
        ];

        let matcher = AcMatcher::new(patterns, AcDfaConfig::default()).unwrap();
        let matches = matcher.matches_field(1, "/usr/bin/ssh-server");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, MatchType::Contains);
    }

    #[test]
    fn test_prefix_match() {
        let patterns = vec![
            MatchPattern::starts_with("/usr/bin".to_string(), 1, "rule-1".to_string()).unwrap(),
        ];

        let matcher = AcMatcher::new(patterns, AcDfaConfig::default()).unwrap();
        let matches = matcher.matches_field(1, "/usr/bin/bash");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, MatchType::Prefix);
    }

    #[test]
    fn test_suffix_match() {
        let patterns = vec![
            MatchPattern::ends_with(".exe".to_string(), 1, "rule-1".to_string()).unwrap(),
        ];

        let matcher = AcMatcher::new(patterns, AcDfaConfig::default()).unwrap();
        let matches = matcher.matches_field(1, "malware.exe");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].kind, MatchType::Suffix);
    }

    #[test]
    fn test_no_match_wrong_field() {
        let patterns = vec![
            MatchPattern::equals("bash".to_string(), 1, "rule-1".to_string()).unwrap(),
        ];

        let matcher = AcMatcher::new(patterns, AcDfaConfig::default()).unwrap();
        let matches = matcher.matches_field(2, "bash");

        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_builder() {
        let patterns = vec![
            MatchPattern::equals("bash".to_string(), 1, "rule-1".to_string()).unwrap(),
            MatchPattern::contains("ssh".to_string(), 2, "rule-1".to_string()).unwrap(),
        ];

        let matcher = AcMatcher::builder()
            .add_patterns(patterns)
            .build()
            .unwrap();

        assert_eq!(matcher.pattern_count(), 2);
    }
}
