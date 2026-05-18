use crate::collector::*;
use kestrel_event::Event;

/// A no-op trace collector that does nothing.
///
/// This is the default when tracing is disabled, ensuring zero overhead
/// in production when tracing is not needed.
pub struct NoopTraceCollector;

impl NoopTraceCollector {
    /// Create a new no-op trace collector
    pub fn new() -> Self {
        Self
    }
}

impl Default for NoopTraceCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceCollector for NoopTraceCollector {
    fn record_trace(&self, _trace: RuleTrace) {
        // Intentionally empty - no-op
    }

    fn record_step(&self, _trace_id: TraceId, _step: TraceStep) {
        // Intentionally empty - no-op
    }

    fn start_trace(&self, _rule_id: &str, _event: &Event) -> TraceId {
        0
    }

    fn flush(&self) {
        // Intentionally empty - no-op
    }

    fn is_rule_traced(&self, _rule_id: &str) -> bool {
        false
    }
}
