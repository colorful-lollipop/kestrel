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

pub use engine::{NfaEngine, NfaEngineConfig};
pub use metrics::{EvictionReason, NfaMetrics, SequenceMetrics};
pub use state::{NfaSequence, NfaStateId, PartialMatch, SeqStep};
pub use store::{QuotaConfig, StateStore, StateStoreConfig};

use kestrel_eql::ir::{IrRule, IrSeqStep, IrSequence};
use kestrel_event::Event;
use kestrel_schema::SchemaRegistry;
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

    /// Captured data from predicates
    pub captures: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nfa_error_display() {
        let err = NfaError::InvalidSequence("test".to_string());
        assert!(err.to_string().contains("test"));
    }
}
