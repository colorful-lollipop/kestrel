// Kestrel Hybrid Engine - NFA+DFA Hybrid Matching Engine
//
// Integrates AC-DFA, lazy DFA, and NFA for optimal performance
// based on rule complexity and hot spot detection.

mod analyzer;
mod engine;

#[cfg(test)]
mod release_perf;

pub use analyzer::{
    analyze_rule, ComplexityWeights, MatchingStrategy, RuleComplexity,
    RuleComplexityAnalyzer, StrategyRecommendation,
};
pub use engine::{HybridEngine, HybridEngineConfig, RuleStrategy};

use thiserror::Error;

/// Errors specific to rule analysis
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AnalysisError {
    /// Invalid predicate structure
    #[error("Invalid predicate structure: {0}")]
    InvalidPredicate(String),

    /// Unsupported operation in predicate
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),

    /// Nested complexity exceeded limits
    #[error("Complexity limit exceeded: {0}")]
    ComplexityLimitExceeded(String),

    /// Invalid regex pattern
    #[error("Invalid regex pattern: {0}")]
    InvalidRegexPattern(String),

    /// Invalid glob pattern
    #[error("Invalid glob pattern: {0}")]
    InvalidGlobPattern(String),
}

/// Errors specific to engine configuration
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConfigurationError {
    /// Invalid weight configuration
    #[error("Invalid weight value: {0}")]
    InvalidWeight(String),

    /// Invalid threshold value
    #[error("Invalid threshold: {0} (must be 0-100)")]
    InvalidThreshold(u8),

    /// Missing required configuration
    #[error("Missing required configuration: {0}")]
    MissingConfiguration(String),

    /// Incompatible settings
    #[error("Incompatible configuration: {0}")]
    IncompatibleSettings(String),
}

/// Errors that can occur in the hybrid engine
#[derive(Debug, Error)]
pub enum HybridEngineError {
    /// Analysis-specific errors
    #[error("Analysis error: {0}")]
    AnalysisError(#[from] AnalysisError),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    ConfigurationError(#[from] ConfigurationError),

    /// Engine execution errors
    #[error("Engine error: {context}: {message}")]
    EngineError { context: String, message: String },

    /// Rule not found
    #[error("Rule not found: {0}")]
    RuleNotFound(String),

    /// Strategy selection error
    #[error("Strategy error for rule '{rule_id}': {message}")]
    StrategyError { rule_id: String, message: String },

    /// Runtime compilation error
    #[error("Compilation error: {0}")]
    CompilationError(String),

    /// Runtime matching error
    #[error("Matching error in {strategy}: {message}")]
    MatchingError { strategy: String, message: String },
}

impl HybridEngineError {
    /// Create a new engine error with context
    pub fn engine_error(context: impl Into<String>, message: impl Into<String>) -> Self {
        Self::EngineError {
            context: context.into(),
            message: message.into(),
        }
    }

    /// Create a new strategy error
    pub fn strategy_error(rule_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::StrategyError {
            rule_id: rule_id.into(),
            message: message.into(),
        }
    }

    /// Create a new matching error
    pub fn matching_error(strategy: impl Into<String>, message: impl Into<String>) -> Self {
        Self::MatchingError {
            strategy: strategy.into(),
            message: message.into(),
        }
    }

    /// Check if this is a configuration error
    pub fn is_configuration_error(&self) -> bool {
        matches!(self, Self::ConfigurationError(_))
    }

    /// Check if this is an analysis error
    pub fn is_analysis_error(&self) -> bool {
        matches!(self, Self::AnalysisError(_))
    }
}

/// Result type for hybrid engine operations
pub type HybridEngineResult<T> = Result<T, HybridEngineError>;

// Implement From conversions for error types
impl From<kestrel_nfa::NfaError> for HybridEngineError {
    fn from(err: kestrel_nfa::NfaError) -> Self {
        Self::engine_error("NFA", err.to_string())
    }
}

impl From<kestrel_ac_dfa::AcDfaError> for HybridEngineError {
    fn from(err: kestrel_ac_dfa::AcDfaError) -> Self {
        Self::engine_error("AC-DFA", err.to_string())
    }
}

impl From<kestrel_lazy_dfa::LazyDfaError> for HybridEngineError {
    fn from(err: kestrel_lazy_dfa::LazyDfaError) -> Self {
        Self::engine_error("Lazy-DFA", err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_error_display() {
        let err = AnalysisError::InvalidPredicate("test pred".to_string());
        assert!(err.to_string().contains("Invalid predicate"));
        assert!(err.to_string().contains("test pred"));
    }

    #[test]
    fn test_configuration_error_display() {
        let err = ConfigurationError::InvalidThreshold(150);
        assert!(err.to_string().contains("Invalid threshold"));
        assert!(err.to_string().contains("150"));
    }

    #[test]
    fn test_hybrid_engine_error_variants() {
        let analysis_err = HybridEngineError::AnalysisError(
            AnalysisError::UnsupportedOperation("test".to_string())
        );
        assert!(analysis_err.is_analysis_error());
        assert!(!analysis_err.is_configuration_error());

        let config_err = HybridEngineError::ConfigurationError(
            ConfigurationError::InvalidWeight("negative".to_string())
        );
        assert!(config_err.is_configuration_error());
        assert!(!config_err.is_analysis_error());
    }

    #[test]
    fn test_error_helpers() {
        let engine_err = HybridEngineError::engine_error("test", "something failed");
        assert!(engine_err.to_string().contains("test"));
        assert!(engine_err.to_string().contains("something failed"));

        let strategy_err = HybridEngineError::strategy_error("rule-1", "no valid strategy");
        assert!(strategy_err.to_string().contains("rule-1"));
        assert!(strategy_err.to_string().contains("no valid strategy"));

        let matching_err = HybridEngineError::matching_error("NFA", "match failed");
        assert!(matching_err.to_string().contains("NFA"));
        assert!(matching_err.to_string().contains("match failed"));
    }

    #[test]
    fn test_analysis_error_from() {
        let analysis_err = AnalysisError::InvalidRegexPattern("[invalid".to_string());
        let hybrid_err: HybridEngineError = analysis_err.into();
        assert!(hybrid_err.to_string().contains("Invalid regex"));
    }

    #[test]
    fn test_configuration_error_from() {
        let config_err = ConfigurationError::MissingConfiguration("weights".to_string());
        let hybrid_err: HybridEngineError = config_err.into();
        assert!(hybrid_err.to_string().contains("Missing required"));
    }
}
