// NFA State structures
//
// This module defines the core data structures for NFA state management:
// - NfaSequence: A compiled sequence rule
// - PartialMatch: Tracks in-progress sequence matches for an entity
// - SeqStep: Individual step in a sequence

use kestrel_event::Event;
use smallvec::{smallvec, SmallVec};
use std::collections::HashMap;

/// Unique identifier for an NFA state (position in sequence)
pub type NfaStateId = u16;

/// A compiled sequence rule ready for NFA execution
#[derive(Debug, Clone)]
pub struct NfaSequence {
    /// Unique sequence identifier
    pub id: String,

    /// Field ID to group by (e.g., process.entity_id)
    pub by_field_id: u32,

    /// Sequence steps
    pub steps: Vec<SeqStep>,

    /// Maximum time window for the sequence (in milliseconds)
    pub maxspan_ms: Option<u64>,

    /// Optional termination condition
    pub until_step: Option<Box<SeqStep>>,

    /// Field captures for alert output
    pub captures: Vec<kestrel_eql::ir::IrCapture>,

    /// PERFORMANCE: Pre-computed index: event_type_id -> [step_indices]
    /// Avoids filtering steps on every event
    pub(crate) event_type_to_steps: HashMap<u16, SmallVec<[usize; 4]>>,
}

impl NfaSequence {
    /// Get relevant step indices for a given event type
    /// Returns empty slice if no steps match this event type
    #[inline]
    pub fn get_relevant_steps(&self, event_type_id: u16) -> &[usize] {
        self.event_type_to_steps
            .get(&event_type_id)
            .map(|v| &v[..])
            .unwrap_or(&[])
    }

    /// Get the maximum state ID in this sequence
    #[inline]
    pub fn max_state(&self) -> NfaStateId {
        self.steps.len() as NfaStateId - 1
    }

    /// Get the first step (if any)
    #[inline]
    pub fn first_step(&self) -> Option<&SeqStep> {
        self.steps.first()
    }

    /// Check if an event type is relevant to this sequence
    #[inline]
    pub fn has_event_type(&self, event_type_id: u16) -> bool {
        self.event_type_to_steps.contains_key(&event_type_id)
            || (self.until_step.is_some()
                && self.until_step.as_ref().map(|s| s.event_type_id) == Some(event_type_id))
    }
}

/// A single step in a sequence
#[derive(Debug, Clone)]
pub struct SeqStep {
    /// State ID (position in sequence, 0-indexed)
    pub state_id: NfaStateId,

    /// Predicate identifier (references predicate in PredicateEvaluator)
    pub predicate_id: String,

    /// Event type ID that this step matches
    pub event_type_id: u16,

    /// Optional condition for this step
    pub condition: Option<String>,
}

impl SeqStep {
    /// Create a new sequence step
    pub fn new(state_id: NfaStateId, predicate_id: String, event_type_id: u16) -> Self {
        Self {
            state_id,
            predicate_id,
            event_type_id,
            condition: None,
        }
    }

    /// Create a new sequence step with a condition
    pub fn with_condition(mut self, condition: String) -> Self {
        self.condition = Some(condition);
        self
    }
}

/// Tracks an in-progress partial match for a specific entity
#[derive(Debug, Clone)]
pub struct PartialMatch {
    /// Sequence this partial match is for
    pub sequence_id: String,

    /// Current state in the sequence (which step we've matched up to)
    pub current_state: NfaStateId,

    /// Entity key for this partial match
    pub entity_key: u128,

    /// Events that have matched so far (indexed by step position)
    /// Using SmallVec for inline optimization - most sequences are short
    pub matched_events: SmallVec<[MatchedEvent; 4]>,

    /// Timestamp when this partial match was created (first event)
    pub started_at: u64,

    /// Timestamp of the last matched event
    pub last_match_ns: u64,

    /// Whether this match has been terminated (by until condition)
    pub terminated: bool,
}

/// Information about a matched event in the sequence
#[derive(Debug, Clone)]
pub struct MatchedEvent {
    /// State ID (step position)
    pub state_id: NfaStateId,

    /// The event that matched
    pub event: Event,

    /// Timestamp of this match
    pub timestamp_ns: u64,
}

impl PartialMatch {
    /// Create a new partial match starting at the first state
    pub fn new(
        sequence_id: String,
        entity_key: u128,
        initial_event: Event,
        initial_state_id: NfaStateId,
    ) -> Self {
        let timestamp_ns = initial_event.ts_mono_ns;
        let matched_event = MatchedEvent {
            state_id: initial_state_id,
            event: initial_event,
            timestamp_ns,
        };

        Self {
            sequence_id,
            current_state: initial_state_id,
            entity_key,
            matched_events: smallvec![matched_event],
            started_at: timestamp_ns,
            last_match_ns: timestamp_ns,
            terminated: false,
        }
    }

    /// Advance this partial match to the next state
    pub fn advance(&mut self, event: Event, next_state_id: NfaStateId) {
        let timestamp_ns = event.ts_mono_ns;
        let matched_event = MatchedEvent {
            state_id: next_state_id,
            event,
            timestamp_ns,
        };

        self.current_state = next_state_id;
        self.matched_events.push(matched_event);
        self.last_match_ns = timestamp_ns;
    }

    /// Check if this partial match has exceeded the maxspan time window
    /// Uses the first event's timestamp (started_at) for accurate maxspan calculation
    pub fn is_expired(&self, now_ns: u64, maxspan_ms: Option<u64>) -> bool {
        if let Some(maxspan) = maxspan_ms {
            let maxspan_ns = maxspan.saturating_mul(1_000_000); // Convert ms to ns
            let elapsed = now_ns.saturating_sub(self.started_at);
            elapsed > maxspan_ns
        } else {
            false
        }
    }

    /// Check if this partial match is complete (has reached the final state)
    pub fn is_complete(&self, total_steps: usize) -> bool {
        // current_state is 0-indexed, so we need +1 to compare with step count
        (self.current_state as usize + 1) >= total_steps
    }

    /// Terminate this partial match (e.g., due to until condition)
    pub fn terminate(&mut self) {
        self.terminated = true;
    }

    /// Get the age of this partial match in nanoseconds
    pub fn age_ns(&self, now_ns: u64) -> u64 {
        now_ns.saturating_sub(self.started_at)
    }

    /// Get the time since the last match in nanoseconds
    pub fn time_since_last_match_ns(&self, now_ns: u64) -> u64 {
        now_ns.saturating_sub(self.last_match_ns)
    }
}

impl NfaSequence {
    /// Create a new NFA sequence
    pub fn new(
        id: String,
        by_field_id: u32,
        steps: Vec<SeqStep>,
        maxspan_ms: Option<u64>,
        until_step: Option<SeqStep>,
    ) -> Self {
        let event_type_to_steps = Self::build_event_type_index(&steps);
        Self {
            id,
            by_field_id,
            steps,
            maxspan_ms,
            until_step: until_step.map(Box::new),
            captures: Vec::new(),
            event_type_to_steps,
        }
    }

    /// Create a new NFA sequence with captures
    pub fn with_captures(
        id: String,
        by_field_id: u32,
        steps: Vec<SeqStep>,
        maxspan_ms: Option<u64>,
        until_step: Option<SeqStep>,
        captures: Vec<kestrel_eql::ir::IrCapture>,
    ) -> Self {
        let event_type_to_steps = Self::build_event_type_index(&steps);
        Self {
            id,
            by_field_id,
            steps,
            maxspan_ms,
            until_step: until_step.map(Box::new),
            captures,
            event_type_to_steps,
        }
    }

    /// Build the event type to steps index for O(1) lookup
    #[inline]
    fn build_event_type_index(steps: &[SeqStep]) -> HashMap<u16, SmallVec<[usize; 4]>> {
        let mut index = HashMap::new();
        for (idx, step) in steps.iter().enumerate() {
            index
                .entry(step.event_type_id)
                .or_insert_with(SmallVec::new)
                .push(idx);
        }
        index
    }

    /// Get the total number of steps in this sequence
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }

    /// Get the next state ID after the current one
    pub fn next_state(&self, current_state: NfaStateId) -> Option<NfaStateId> {
        let next = current_state + 1;
        if (next as usize) < self.steps.len() {
            Some(next)
        } else {
            None
        }
    }

    /// Check if a state ID is valid for this sequence
    pub fn is_valid_state(&self, state_id: NfaStateId) -> bool {
        (state_id as usize) < self.steps.len()
    }

    /// Get a step by state ID
    pub fn get_step(&self, state_id: NfaStateId) -> Option<&SeqStep> {
        self.steps.get(state_id as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_event::Event;

    fn create_test_event(event_type_id: u16, ts_ns: u64) -> Event {
        Event::builder()
            .event_type(event_type_id)
            .ts_mono(ts_ns)
            .ts_wall(ts_ns)
            .entity_key(12345)
            .build()
            .expect("failed to build test event")
    }

    #[test]
    fn test_partial_match_creation() {
        let event = create_test_event(1, 1000);
        let pm = PartialMatch::new("test_seq".to_string(), 12345, event, 0);

        assert_eq!(pm.sequence_id, "test_seq");
        assert_eq!(pm.entity_key, 12345);
        assert_eq!(pm.current_state, 0);
        assert_eq!(pm.matched_events.len(), 1);
        assert_eq!(pm.started_at, 1000);
        assert!(!pm.terminated);
    }

    #[test]
    fn test_partial_match_advance() {
        let event1 = create_test_event(1, 1000);
        let mut pm = PartialMatch::new("test_seq".to_string(), 12345, event1, 0);

        let event2 = create_test_event(2, 2000);
        pm.advance(event2, 1);

        assert_eq!(pm.current_state, 1);
        assert_eq!(pm.matched_events.len(), 2);
        assert_eq!(pm.last_match_ns, 2000);
    }

    #[test]
    fn test_partial_match_is_complete() {
        let event = create_test_event(1, 1000);
        let mut pm = PartialMatch::new("test_seq".to_string(), 12345, event, 0);

        // 3-step sequence
        assert!(!pm.is_complete(3)); // State 0 of 3

        pm.current_state = 1;
        assert!(!pm.is_complete(3)); // State 1 of 3

        pm.current_state = 2;
        assert!(pm.is_complete(3)); // State 2 of 3 (last state)
    }

    #[test]
    fn test_partial_match_expiration() {
        let event = create_test_event(1, 1_000_000_000); // 1 second in ns
        let pm = PartialMatch::new("test_seq".to_string(), 12345, event, 0);

        // maxspan of 5 seconds (5000 ms)
        let maxspan_ms = Some(5000);

        // Not expired at 4 seconds (4,000,000,000 ns)
        assert!(!pm.is_expired(5_000_000_000, maxspan_ms));

        // Expired at 6 seconds (6,000,000,000 ns)
        assert!(pm.is_expired(7_000_000_000, maxspan_ms));

        // No maxspan = never expires
        assert!(!pm.is_expired(1_000_000_000_000, None));
    }

    #[test]
    fn test_partial_match_terminate() {
        let event = create_test_event(1, 1000);
        let mut pm = PartialMatch::new("test_seq".to_string(), 12345, event, 0);

        assert!(!pm.terminated);
        pm.terminate();
        assert!(pm.terminated);
    }

    #[test]
    fn test_nfa_sequence_next_state() {
        let steps = vec![
            SeqStep::new(0, "pred1".to_string(), 1),
            SeqStep::new(1, "pred2".to_string(), 2),
            SeqStep::new(2, "pred3".to_string(), 3),
        ];

        let seq = NfaSequence::new("test".to_string(), 100, steps, Some(5000), None);

        // Can advance from state 0
        assert_eq!(seq.next_state(0), Some(1));

        // Can advance from state 1
        assert_eq!(seq.next_state(1), Some(2));

        // Cannot advance from last state
        assert_eq!(seq.next_state(2), None);
    }

    #[test]
    fn test_seq_step_creation() {
        let step = SeqStep::new(0, "test_pred".to_string(), 42);
        assert_eq!(step.state_id, 0);
        assert_eq!(step.predicate_id, "test_pred");
        assert_eq!(step.event_type_id, 42);
        assert!(step.condition.is_none());

        let step_with_cond = SeqStep::new(0, "test_pred".to_string(), 42)
            .with_condition("some_condition".to_string());
        assert_eq!(step_with_cond.condition, Some("some_condition".to_string()));
    }
}
