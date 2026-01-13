// Kestrel Hybrid Engine - NFA+DFA Hybrid Matching Engine
//
// Integrates AC-DFA, lazy DFA, and NFA for optimal performance
// based on rule complexity and hot spot detection.

mod analyzer;
mod engine;

pub use analyzer::{
    RuleComplexity, RuleComplexityAnalyzer, StrategyRecommendation,
    MatchingStrategy,
};
pub use engine::{HybridEngine, HybridEngineConfig, RuleStrategy};

use thiserror::Error;

/// Errors that can occur in the hybrid engine
#[derive(Debug, Error)]
pub enum HybridEngineError {
    #[error("Analysis error: {0}")]
    AnalysisError(String),

    #[error("Engine error: {0}")]
    EngineError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Rule not found: {0}")]
    RuleNotFound(String),
}

/// Result type for hybrid engine operations
pub type HybridEngineResult<T> = Result<T, HybridEngineError>;

// Implement From conversions for error types
impl From<kestrel_nfa::NfaError> for HybridEngineError {
    fn from(err: kestrel_nfa::NfaError) -> Self {
        HybridEngineError::EngineError(format!("NFA error: {}", err))
    }
}

impl From<kestrel_ac_dfa::AcDfaError> for HybridEngineError {
    fn from(err: kestrel_ac_dfa::AcDfaError) -> Self {
        HybridEngineError::EngineError(format!("AC-DFA error: {}", err))
    }
}

impl From<kestrel_lazy_dfa::LazyDfaError> for HybridEngineError {
    fn from(err: kestrel_lazy_dfa::LazyDfaError) -> Self {
        HybridEngineError::EngineError(format!("Lazy DFA error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = HybridEngineError::AnalysisError("test".to_string());
        assert!(err.to_string().contains("test"));
    }
}
