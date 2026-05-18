use kestrel_event::Event;
use kestrel_schema::{EntityKey, TypedValue};
use std::time::Duration;

/// A unique identifier for a trace session
pub type TraceId = u64;

/// A trace of a single rule evaluation
#[derive(Debug, Clone)]
pub struct RuleTrace {
    /// Trace session ID
    pub trace_id: TraceId,
    /// Rule ID being evaluated
    pub rule_id: String,
    /// Event ID being evaluated
    pub event_id: u64,
    /// Evaluation timestamp
    pub timestamp_ns: u64,
    /// Duration of evaluation
    pub duration: Duration,
    /// Whether the rule matched
    pub matched: bool,
    /// Steps in the evaluation
    pub steps: Vec<TraceStep>,
    /// Optional error
    pub error: Option<String>,
}

/// A single step in rule evaluation tracing
#[derive(Debug, Clone)]
pub enum TraceStep {
    /// Predicate evaluation
    Predicate {
        predicate_id: String,
        result: bool,
        /// Human-readable explanation of the evaluation
        explanation: String,
        /// Actual field values that were checked
        field_values: Vec<(String, Option<TypedValue>)>,
    },
    /// NFA state transition
    NfaTransition {
        from_state: String,
        to_state: String,
        event_type_id: u16,
        entity_key: EntityKey,
    },
    /// Sequence step matched
    SequenceMatch {
        step_index: usize,
        predicate_id: String,
        partial_match_id: String,
    },
    /// Sequence completed
    SequenceComplete {
        sequence_id: String,
        matched_events: Vec<u64>,
    },
    /// Action taken
    Action {
        action_type: String,
        target: String,
        success: bool,
    },
}

/// Trait for collecting traces from the detection engine
///
/// Implementations can write to files, send to remote collectors,
/// or store in memory for debugging.
pub trait TraceCollector: Send + Sync {
    /// Record a complete rule evaluation trace
    fn record_trace(&self, trace: RuleTrace);

    /// Record a single evaluation step (for incremental tracing)
    fn record_step(&self, trace_id: TraceId, step: TraceStep);

    /// Start a new trace session, returns the trace ID
    fn start_trace(&self, rule_id: &str, event: &Event) -> TraceId;

    /// Flush any buffered traces
    fn flush(&self);

    /// Check if tracing is enabled for a given rule
    fn is_rule_traced(&self, rule_id: &str) -> bool;
}

/// Configuration for trace collection
#[derive(Debug, Clone)]
pub struct TraceConfig {
    /// Whether tracing is enabled globally
    pub enabled: bool,
    /// Rules to trace (empty = all rules)
    pub traced_rules: Vec<String>,
    /// Maximum traces to keep in memory
    pub max_in_memory_traces: usize,
    /// Whether to include field values in traces
    pub include_field_values: bool,
    /// Whether to trace NFA state transitions
    pub trace_nfa_transitions: bool,
    /// Whether to trace predicate evaluations
    pub trace_predicates: bool,
    /// Output format
    pub output_format: TraceOutputFormat,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            traced_rules: Vec::new(),
            max_in_memory_traces: 1000,
            include_field_values: true,
            trace_nfa_transitions: true,
            trace_predicates: true,
            output_format: TraceOutputFormat::Json,
        }
    }
}

/// Output format for traces
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceOutputFormat {
    /// JSON format
    Json,
    /// Human-readable text format
    Text,
}

/// Helper to generate trace IDs
pub fn generate_trace_id() -> TraceId {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
