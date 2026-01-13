// Kestrel Lazy DFA - Hot Sequence Detection and DFA Caching
//!
// This crate provides lazy DFA construction and caching for frequently
// used (hot) sequence patterns, optimizing performance for high-traffic rules.

mod cache;
mod converter;
mod detector;
mod dfa;

pub use cache::{DfaCache, DfaCacheConfig};
pub use converter::NfaToDfaConverter;
pub use detector::{HotSpot, HotSpotDetector, HotSpotThreshold};
pub use dfa::{DfaState, LazyDfa};

use thiserror::Error;

/// Errors that can occur in the lazy DFA system
#[derive(Debug, Error)]
pub enum LazyDfaError {
    #[error("NFA to DFA conversion failed: {0}")]
    ConversionFailed(String),

    #[error("DFA state limit exceeded: {states} states (max: {max})")]
    StateLimitExceeded { states: usize, max: usize },

    #[error("Memory limit exceeded: {size} bytes (max: {max})")]
    MemoryLimitExceeded { size: usize, max: usize },

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("Sequence not found: {0}")]
    SequenceNotFound(String),
}

/// Result type for lazy DFA operations
pub type LazyDfaResult<T> = Result<T, LazyDfaError>;

/// Configuration for the lazy DFA system
#[derive(Debug, Clone)]
pub struct LazyDfaConfig {
    /// Hot spot detection thresholds
    pub hot_spot_threshold: HotSpotThreshold,

    /// DFA cache configuration
    pub cache_config: DfaCacheConfig,

    /// Maximum DFA states per sequence (0 = unlimited)
    pub max_dfa_states: usize,

    /// Maximum memory for all DFAs combined (0 = unlimited)
    pub max_total_memory: usize,
}

impl Default for LazyDfaConfig {
    fn default() -> Self {
        Self {
            hot_spot_threshold: HotSpotThreshold::default(),
            cache_config: DfaCacheConfig::default(),
            max_dfa_states: 1000,
            max_total_memory: 10 * 1024 * 1024, // 10MB
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = LazyDfaConfig::default();
        assert_eq!(config.max_dfa_states, 1000);
        assert_eq!(config.max_total_memory, 10 * 1024 * 1024);
    }

    #[test]
    fn test_error_display() {
        let err = LazyDfaError::ConversionFailed("test".to_string());
        assert!(err.to_string().contains("test"));
    }
}
