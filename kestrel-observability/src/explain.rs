use crate::collector::*;
use crate::decision::*;
use kestrel_event::Event;
use std::collections::VecDeque;
use std::sync::Mutex;

/// In-memory trace collector that stores traces for debugging and explain mode.
pub struct InMemoryTraceCollector {
    config: TraceConfig,
    traces: Mutex<VecDeque<RuleTrace>>,
}

impl InMemoryTraceCollector {
    /// Create a new in-memory trace collector
    pub fn new(config: TraceConfig) -> Self {
        Self {
            config,
            traces: Mutex::new(VecDeque::with_capacity(100)),
        }
    }

    /// Get all stored traces
    pub fn get_traces(&self) -> Vec<RuleTrace> {
        self.traces.lock().unwrap().iter().cloned().collect()
    }

    /// Get traces for a specific rule
    pub fn get_traces_for_rule(&self, rule_id: &str) -> Vec<RuleTrace> {
        self.traces
            .lock()
            .unwrap()
            .iter()
            .filter(|t| t.rule_id == rule_id)
            .cloned()
            .collect()
    }

    /// Get traces for a specific event
    pub fn get_traces_for_event(&self, event_id: u64) -> Vec<RuleTrace> {
        self.traces
            .lock()
            .unwrap()
            .iter()
            .filter(|t| t.event_id == event_id)
            .cloned()
            .collect()
    }

    /// Clear all stored traces
    pub fn clear(&self) {
        self.traces.lock().unwrap().clear();
    }

    /// Get the last N traces
    pub fn get_last_traces(&self, n: usize) -> Vec<RuleTrace> {
        self.traces
            .lock()
            .unwrap()
            .iter()
            .rev()
            .take(n)
            .cloned()
            .collect()
    }
}

impl TraceCollector for InMemoryTraceCollector {
    fn record_trace(&self, trace: RuleTrace) {
        if !self.config.enabled {
            return;
        }

        let mut traces = self.traces.lock().unwrap();
        if traces.len() >= self.config.max_in_memory_traces {
            traces.pop_front();
        }
        traces.push_back(trace);
    }

    fn record_step(&self, _trace_id: TraceId, _step: TraceStep) {
        // Steps are accumulated in the trace, not stored separately
    }

    fn start_trace(&self, rule_id: &str, _event: &Event) -> TraceId {
        if !self.config.enabled {
            return 0;
        }
        if !self.is_rule_traced(rule_id) {
            return 0;
        }
        generate_trace_id()
    }

    fn flush(&self) {
        // In-memory collector doesn't need flushing
    }

    fn is_rule_traced(&self, rule_id: &str) -> bool {
        if !self.config.enabled {
            return false;
        }
        if self.config.traced_rules.is_empty() {
            return true;
        }
        self.config.traced_rules.contains(&rule_id.to_string())
    }
}

/// Explain mode: reconstruct a human-readable explanation of why a rule did or didn't match.
pub struct Explain;

impl Explain {
    /// Explain why a rule matched or didn't match for a given event.
    ///
    /// Returns a human-readable string with the evaluation breakdown.
    pub fn explain(trace: &RuleTrace) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "Rule '{}' evaluation for event {}\n",
            trace.rule_id, trace.event_id
        ));
        output.push_str(&format!("Result: {}\n", if trace.matched { "MATCHED" } else { "NO MATCH" }));
        output.push_str(&format!("Duration: {:?}\n", trace.duration));
        output.push('\n');

        for (i, step) in trace.steps.iter().enumerate() {
            output.push_str(&format!("Step {}: ", i + 1));
            match step {
                TraceStep::Predicate { predicate_id, result, explanation, field_values } => {
                    output.push_str(&format!("Predicate '{}' -> {}\n", predicate_id, if *result { "true" } else { "false" }));
                    output.push_str(&format!("  Explanation: {}\n", explanation));
                    for (field, value) in field_values {
                        let val_str = match value {
                            Some(v) => format!("{:?}", v),
                            None => "(missing)".to_string(),
                        };
                        output.push_str(&format!("  Field '{}': {}\n", field, val_str));
                    }
                },
                TraceStep::NfaTransition { from_state, to_state, event_type_id, .. } => {
                    output.push_str(&format!(
                        "NFA transition: {} -> {} (event_type={})\n",
                        from_state, to_state, event_type_id
                    ));
                },
                TraceStep::SequenceMatch { step_index, predicate_id, .. } => {
                    output.push_str(&format!(
                        "Sequence step {} matched (predicate '{}')\n",
                        step_index, predicate_id
                    ));
                },
                TraceStep::SequenceComplete { sequence_id, matched_events } => {
                    output.push_str(&format!(
                        "Sequence '{}' completed with events: {:?}\n",
                        sequence_id, matched_events
                    ));
                },
                TraceStep::Action { action_type, target, success } => {
                    output.push_str(&format!(
                        "Action '{}' on '{}' -> {}\n",
                        action_type, target, if *success { "success" } else { "failed" }
                    ));
                },
            }
            output.push('\n');
        }

        if let Some(error) = &trace.error {
            output.push_str(&format!("ERROR: {}\n", error));
        }

        output
    }

    /// Explain a decision log in human-readable format.
    pub fn explain_decision(log: &DecisionLog) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "Decision Log: {}\n",
            log.decision_id
        ));
        output.push_str(&format!(
            "Rule '{}' ({}) for event {}\n",
            log.rule_name, log.rule_id, log.event_id
        ));
        output.push_str(&format!(
            "Result: {}\n",
            if log.matched { "MATCHED" } else { "NO MATCH" }
        ));
        output.push('\n');

        for pred in &log.predicates {
            output.push_str(&format!(
                "Predicate '{}': {}\n",
                pred.predicate_id,
                if pred.matched { "MATCHED" } else { "NO MATCH" }
            ));
            output.push_str(&format!("  {}\n", pred.explanation));
            if let Some(expected) = &pred.expected_value {
                output.push_str(&format!("  Expected: {}\n", expected));
            }
            if let Some(actual) = &pred.actual_value {
                output.push_str(&format!("  Actual: {}\n", actual));
            }
            output.push('\n');
        }

        output
    }
}
