// Kestrel NFA Engine - Host-side sequence matching engine
//
// This crate implements the NFA (Non-deterministic Finite Automaton) engine
// for sequence detection in EQL rules. It handles:
// - Partial match tracking per entity
// - Time windows (maxspan)
// - Termination conditions (until)
// - State management (TTL/LRU/quota)
// - Entity grouping (sequence by)

mod engine;
mod metrics;
mod state;
mod store;

pub use engine::{BudgetAction, NfaEngine, NfaEngineConfig};
pub use metrics::{EvictionReason, NfaMetrics, SequenceMetrics};
pub use state::{NfaSequence, NfaStateId, PartialMatch, SeqStep};
pub use store::{QuotaConfig, StateStore, StateStoreConfig};

use kestrel_event::Event;

use thiserror::Error;

/// Errors that can occur in the NFA engine
#[derive(Debug, Error)]
pub enum NfaError {
    #[error("Invalid sequence configuration: {0}")]
    InvalidSequence(String),

    #[error("State store error: {0}")]
    StateStoreError(String),

    #[error("Quota exceeded for rule {rule_id}: {reason}")]
    QuotaExceeded { rule_id: String, reason: String },

    #[error("Predicate evaluation failed: {0}")]
    PredicateError(String),

    #[error("Schema error: {0}")]
    SchemaError(String),
}

/// Result type for NFA operations
pub type NfaResult<T> = Result<T, NfaError>;

/// Predicate evaluator trait - interface for evaluating predicates on events
///
/// This trait is implemented by Wasm and Lua runtimes to provide
/// predicate evaluation capabilities to the NFA engine.
pub trait PredicateEvaluator: Send + Sync {
    /// Evaluate a predicate against an event
    fn evaluate(&self, predicate_id: &str, event: &Event) -> NfaResult<bool>;

    /// Get the field IDs required by a predicate
    fn get_required_fields(&self, predicate_id: &str) -> NfaResult<Vec<u32>>;

    /// Check if a predicate exists
    fn has_predicate(&self, predicate_id: &str) -> bool;
}

/// Compilation result - contains a compiled sequence ready for loading into the engine
#[derive(Debug, Clone)]
pub struct CompiledSequence {
    /// Unique sequence identifier
    pub id: String,

    /// Sequence definition
    pub sequence: NfaSequence,

    /// Rule metadata
    pub rule_id: String,
    pub rule_name: String,
}

/// Alert generated when a sequence matches
#[derive(Debug, Clone)]
pub struct SequenceAlert {
    /// Rule that generated this alert
    pub rule_id: String,
    pub rule_name: String,

    /// Sequence that matched
    pub sequence_id: String,

    /// Entity that triggered the match
    pub entity_key: u128,

    /// Timestamp of the match
    pub timestamp_ns: u64,

    /// Events that participated in the sequence
    pub events: Vec<Event>,

    /// Captured data from predicates (alias -> value)
    pub captures: Vec<(String, kestrel_schema::TypedValue)>,
}

/// Mock predicate evaluator for testing
/// 
/// This module provides a configurable mock evaluator that can:
/// - Track call counts
/// - Return different results for different predicates
/// - Simulate evaluation failures
#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    
    /// A configurable mock evaluator for testing
    pub struct MockEvaluator {
        /// Total number of evaluate() calls
        call_count: AtomicUsize,
        /// Per-predicate call counts
        predicate_calls: Mutex<HashMap<String, usize>>,
        /// Configured results for specific predicates
        predicate_results: HashMap<String, bool>,
        /// Default result for predicates not in predicate_results
        default_result: bool,
        /// Simulate failure for specific predicates
        failure_predicates: Vec<String>,
        /// Required fields to return for get_required_fields
        required_fields: Vec<u32>,
    }
    
    impl MockEvaluator {
        /// Create a new mock evaluator with default result
        pub fn new(default_result: bool) -> Self {
            Self {
                call_count: AtomicUsize::new(0),
                predicate_calls: Mutex::new(HashMap::new()),
                predicate_results: HashMap::new(),
                default_result,
                failure_predicates: Vec::new(),
                required_fields: vec![1, 2, 3],
            }
        }
        
        /// Set the result for a specific predicate
        pub fn with_result(mut self, predicate_id: impl Into<String>, result: bool) -> Self {
            self.predicate_results.insert(predicate_id.into(), result);
            self
        }
        
        /// Configure a predicate to fail evaluation
        pub fn with_failure(mut self, predicate_id: impl Into<String>) -> Self {
            self.failure_predicates.push(predicate_id.into());
            self
        }
        
        /// Set the required fields to return
        pub fn with_required_fields(mut self, fields: Vec<u32>) -> Self {
            self.required_fields = fields;
            self
        }
        
        /// Get total call count
        pub fn total_calls(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
        
        /// Get call count for a specific predicate
        pub fn predicate_calls(&self, predicate_id: &str) -> usize {
            self.predicate_calls
                .lock()
                .unwrap()
                .get(predicate_id)
                .copied()
                .unwrap_or(0)
        }
        
        /// Check if a specific predicate was ever called
        pub fn was_called(&self, predicate_id: &str) -> bool {
            self.predicate_calls(predicate_id) > 0
        }
        
        /// Reset all call counts
        pub fn reset_counts(&self) {
            self.call_count.store(0, Ordering::SeqCst);
            self.predicate_calls.lock().unwrap().clear();
        }
    }
    
    impl PredicateEvaluator for MockEvaluator {
        fn evaluate(&self, predicate_id: &str, _event: &Event) -> NfaResult<bool> {
            // Update counts
            self.call_count.fetch_add(1, Ordering::SeqCst);
            self.predicate_calls
                .lock()
                .unwrap()
                .entry(predicate_id.to_string())
                .and_modify(|c| *c += 1)
                .or_insert(1);
            
            // Check if this predicate should fail
            if self.failure_predicates.contains(&predicate_id.to_string()) {
                return Err(NfaError::PredicateError(
                    format!("Simulated failure for {}", predicate_id)
                ));
            }
            
            // Return configured result or default
            Ok(self.predicate_results.get(predicate_id)
                .copied()
                .unwrap_or(self.default_result))
        }
        
        fn get_required_fields(&self, _predicate_id: &str) -> NfaResult<Vec<u32>> {
            Ok(self.required_fields.clone())
        }
        
        fn has_predicate(&self, predicate_id: &str) -> bool {
            !predicate_id.is_empty()
        }
    }
    
    impl Default for MockEvaluator {
        fn default() -> Self {
            Self::new(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nfa_error_display() {
        let err = NfaError::InvalidSequence("test".to_string());
        assert!(err.to_string().contains("test"));
    }
    
    #[test]
    fn test_mock_evaluator_default() {
        use test_helpers::MockEvaluator;
        
        let evaluator = MockEvaluator::default();
        let event = Event::builder()
            .event_type(1)
            .ts_mono(1000)
            .ts_wall(1000)
            .entity_key(123)
            .build()
            .unwrap();
        
        assert!(evaluator.evaluate("test", &event).unwrap());
        assert_eq!(evaluator.total_calls(), 1);
        assert!(evaluator.was_called("test"));
    }
    
    #[test]
    fn test_mock_evaluator_with_results() {
        use test_helpers::MockEvaluator;
        
        let evaluator = MockEvaluator::new(true)
            .with_result("pred1", true)
            .with_result("pred2", false);
        
        let event = Event::builder()
            .event_type(1)
            .ts_mono(1000)
            .ts_wall(1000)
            .entity_key(123)
            .build()
            .unwrap();
        
        assert!(evaluator.evaluate("pred1", &event).unwrap());
        assert!(!evaluator.evaluate("pred2", &event).unwrap());
        assert!(evaluator.evaluate("unknown", &event).unwrap()); // default
    }
    
    #[test]
    fn test_mock_evaluator_failure() {
        use test_helpers::MockEvaluator;
        
        let evaluator = MockEvaluator::new(true)
            .with_failure("failing_pred");
        
        let event = Event::builder()
            .event_type(1)
            .ts_mono(1000)
            .ts_wall(1000)
            .entity_key(123)
            .build()
            .unwrap();
        
        assert!(evaluator.evaluate("ok_pred", &event).unwrap());
        assert!(evaluator.evaluate("failing_pred", &event).is_err());
    }
}
