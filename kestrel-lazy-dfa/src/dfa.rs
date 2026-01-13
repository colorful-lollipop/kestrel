// Lazy DFA - Deterministic Finite Automaton for hot sequences
//
// Represents a DFA constructed from an NFA for fast matching
// of frequently used sequence patterns.

use crate::LazyDfaError;
use ahash::AHashMap;
use kestrel_nfa::NfaStateId;
use std::collections::HashMap;
use std::fmt;

/// A DFA state
#[derive(Debug, Clone)]
pub struct DfaState {
    /// State ID
    pub id: usize,

    /// NFA states that comprise this DFA state (powerset construction)
    pub nfa_states: Vec<NfaStateId>,

    /// Transitions: (event_type_id) -> next_state_id
    pub transitions: HashMap<u16, usize>,

    /// Is this an accepting state?
    pub is_accepting: bool,
}

impl DfaState {
    pub fn new(id: usize, nfa_states: Vec<NfaStateId>) -> Self {
        Self {
            id,
            nfa_states,
            transitions: HashMap::default(),
            is_accepting: false,
        }
    }

    pub fn add_transition(&mut self, event_type_id: u16, next_state: usize) {
        self.transitions.insert(event_type_id, next_state);
    }

    pub fn get_transition(&self, event_type_id: u16) -> Option<usize> {
        self.transitions.get(&event_type_id).copied()
    }

    pub fn transition_count(&self) -> usize {
        self.transitions.len()
    }
}

/// A lazy DFA for fast sequence matching
#[derive(Clone)]
pub struct LazyDfa {
    /// DFA states
    pub(crate) states: Vec<DfaState>,

    /// Initial state
    initial_state: usize,

    /// Sequence ID this DFA represents
    sequence_id: String,

    /// Number of steps in the sequence
    step_count: usize,

    /// Estimated memory usage in bytes
    memory_usage: usize,
}

impl LazyDfa {
    pub fn new(sequence_id: String, step_count: usize) -> Self {
        // Create initial state (empty set of NFA states)
        let initial = DfaState::new(0, vec![]);

        Self {
            states: vec![initial],
            initial_state: 0,
            sequence_id,
            step_count,
            memory_usage: 0,
        }
    }

    pub fn add_state(&mut self, nfa_states: Vec<NfaStateId>) -> usize {
        let id = self.states.len();
        let state = DfaState::new(id, nfa_states);
        // Calculate memory usage
        let state_memory = std::mem::size_of::<DfaState>()
            + state.nfa_states.len() * std::mem::size_of::<NfaStateId>()
            + state.transitions.len() * (std::mem::size_of::<u16>() + std::mem::size_of::<usize>());
        self.memory_usage += state_memory;
        self.states.push(state);
        id
    }

    pub fn get_state(&self, id: usize) -> Option<&DfaState> {
        self.states.get(id)
    }

    pub fn get_state_mut(&mut self, id: usize) -> Option<&mut DfaState> {
        self.states.get_mut(id)
    }

    pub fn state_count(&self) -> usize {
        self.states.len()
    }

    pub fn sequence_id(&self) -> &str {
        &self.sequence_id
    }

    pub fn step_count(&self) -> usize {
        self.step_count
    }

    pub fn memory_usage(&self) -> usize {
        self.memory_usage
    }

    /// Match an event type against the DFA
    pub fn match_event(&self, mut current_state: usize, event_type_id: u16) -> Option<usize> {
        let state = self.get_state(current_state)?;
        let next_state = state.get_transition(event_type_id)?;
        Some(next_state)
    }

    /// Check if a state is accepting (sequence complete)
    pub fn is_accepting(&self, state_id: usize) -> bool {
        self.get_state(state_id)
            .map(|s| s.is_accepting)
            .unwrap_or(false)
    }

    /// Get the initial state ID
    pub fn initial_state(&self) -> usize {
        self.initial_state
    }
}

impl fmt::Debug for LazyDfa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LazyDfa")
            .field("sequence_id", &self.sequence_id)
            .field("state_count", &self.states.len())
            .field("step_count", &self.step_count)
            .field("memory_usage", &self.memory_usage)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dfa_creation() {
        let dfa = LazyDfa::new("seq-1".to_string(), 3);
        assert_eq!(dfa.sequence_id(), "seq-1");
        assert_eq!(dfa.step_count(), 3);
        assert_eq!(dfa.state_count(), 1);
        assert_eq!(dfa.initial_state(), 0);
    }

    #[test]
    fn test_state_addition() {
        let mut dfa = LazyDfa::new("seq-1".to_string(), 3);
        let state_id = dfa.add_state(vec![0, 1]);

        assert_eq!(state_id, 1);
        assert_eq!(dfa.state_count(), 2);
        assert!(dfa.get_state(state_id).is_some());
    }

    #[test]
    fn test_state_transitions() {
        let mut dfa = LazyDfa::new("seq-1".to_string(), 3);
        let state_id = dfa.add_state(vec![1]);

        // Add a transition
        let state = dfa.get_state_mut(state_id).unwrap();
        state.add_transition(10, 2);

        // Check transition exists
        let state = dfa.get_state(state_id).unwrap();
        assert_eq!(state.get_transition(10), Some(2));
        assert_eq!(state.get_transition(99), None);
        assert_eq!(state.transition_count(), 1);
    }

    #[test]
    fn test_match_event() {
        let mut dfa = LazyDfa::new("seq-1".to_string(), 2);

        // Add states and transitions
        let state1 = dfa.add_state(vec![0]);
        let state2 = dfa.add_state(vec![1]);

        let s0 = dfa.get_state_mut(0).unwrap();
        s0.add_transition(10, state1);

        let s1 = dfa.get_state_mut(state1).unwrap();
        s1.add_transition(20, state2);

        // Match events
        let next = dfa.match_event(0, 10);
        assert_eq!(next, Some(state1));

        let next = dfa.match_event(state1, 20);
        assert_eq!(next, Some(state2));

        // Non-matching event
        let next = dfa.match_event(0, 99);
        assert_eq!(next, None);
    }
}
