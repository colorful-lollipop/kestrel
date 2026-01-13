// NFA to DFA Converter
//
// Converts NFA sequences to DFAs using subset construction (powerset construction).
// Only converts sequences that are simple enough to avoid state explosion.

use crate::dfa::LazyDfa;
use crate::dfa::DfaState;
use crate::{LazyDfaError, LazyDfaResult};
use kestrel_eql::ir::IrRule;
use kestrel_nfa::{CompiledSequence, NfaSequence};
use std::collections::{HashMap, HashSet};

/// NFA to DFA converter
pub struct NfaToDfaConverter {
    /// Maximum number of DFA states to create
    max_states: usize,
}

impl NfaToDfaConverter {
    pub fn new(max_states: usize) -> Self {
        Self { max_states }
    }

    /// Convert a compiled sequence to a DFA
    pub fn convert(&self, compiled: &CompiledSequence) -> LazyDfaResult<LazyDfa> {
        let sequence = &compiled.sequence;

        // Check if sequence is simple enough for DFA conversion
        self.check_sequence_complexity(sequence)?;

        // Build DFA using subset construction
        let mut dfa = LazyDfa::new(compiled.id.clone(), sequence.step_count());

        // Initial state: no NFA states yet
        let mut unmarked_states = vec![vec![0u16]]; // Start with initial NFA state (NfaStateId is u16)
        let mut state_map: HashMap<Vec<u16>, usize> = HashMap::new();
        state_map.insert(vec![0], 0);

        let mut state_id = 0;

        while let Some(nfa_states) = unmarked_states.pop() {
            // Get or create DFA state for this NFA state set
            let dfa_state_id = *state_map.get(&nfa_states).unwrap();

            // Collect all possible transitions from this NFA state set
            let mut transitions: HashMap<u16, Vec<u16>> = HashMap::new();

            for &nfa_state in &nfa_states {
                if let Some(step) = sequence.steps.get(nfa_state as usize) {
                    // Transition on this event type
                    transitions
                        .entry(step.event_type_id)
                        .or_insert_with(Vec::new)
                        .push(nfa_state + 1); // Move to next NFA state
                }
            }

            // Create transitions to new DFA states
            for (event_type, next_nfa_states) in transitions {
                // Deduplicate and sort NFA states
                let mut unique_states: Vec<_> = next_nfa_states.into_iter().collect();
                unique_states.sort();
                unique_states.dedup();

                // Get or create target DFA state
                let target_id = if let Some(&id) = state_map.get(&unique_states) {
                    id
                } else {
                    let new_id = dfa.add_state(unique_states.clone());
                    state_map.insert(unique_states.clone(), new_id);
                    unmarked_states.push(unique_states);
                    new_id
                };

                // Add transition
                if let Some(state) = dfa.get_state_mut(dfa_state_id) {
                    state.add_transition(event_type, target_id);
                }

                // Check if we've exceeded state limit
                if dfa.state_count() > self.max_states {
                    return Err(LazyDfaError::StateLimitExceeded {
                        states: dfa.state_count(),
                        max: self.max_states,
                    });
                }

                state_id = state_id.max(target_id);
            }
        }

        // Mark accepting states (sequences that reach the end)
        let step_count = sequence.step_count() as u16;
        for dfa_state in &mut dfa.states {
            // Check if any NFA state in this DFA state is the final state
            let max_nfa_state = dfa_state.nfa_states.iter().copied().max().unwrap_or(0);
            if max_nfa_state >= step_count.saturating_sub(1) {
                dfa_state.is_accepting = true;
            }
        }

        Ok(dfa)
    }

    /// Check if a sequence is simple enough for DFA conversion
    fn check_sequence_complexity(&self, sequence: &NfaSequence) -> LazyDfaResult<()> {
        // Check for until condition (makes it complex)
        if sequence.until_step.is_some() {
            return Err(LazyDfaError::ConversionFailed(
                "Sequence has 'until' condition, not suitable for DFA".to_string(),
            ));
        }

        // Check sequence length
        if sequence.step_count() > self.max_states / 2 {
            return Err(LazyDfaError::ConversionFailed(format!(
                "Sequence too long: {} steps (max: {})",
                sequence.step_count(),
                self.max_states / 2
            )));
        }

        // Check for captures (may be OK, but adds complexity)
        if !sequence.captures.is_empty() {
            tracing::warn!(
                "Sequence {} has captures, DFA may not preserve semantics",
                sequence.id
            );
        }

        Ok(())
    }

    /// Convert from an IR rule (assuming it has a sequence)
    pub fn convert_from_ir(&self, ir_rule: &IrRule, rule_id: &str) -> LazyDfaResult<LazyDfa> {
        // Create a compiled sequence from IR
        let compiled: CompiledSequence = (ir_rule, rule_id).into();
        self.convert(&compiled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_nfa::SeqStep;

    #[test]
    fn test_converter_creation() {
        let converter = NfaToDfaConverter::new(1000);
        assert_eq!(converter.max_states, 1000);
    }

    #[test]
    fn test_simple_sequence_conversion() {
        let converter = NfaToDfaConverter::new(1000);

        // Create a simple sequence
        let sequence = NfaSequence::new(
            "test-seq".to_string(),
            100, // by_field_id
            vec![
                SeqStep::new(0, "pred1".to_string(), 1),
                SeqStep::new(1, "pred2".to_string(), 2),
            ],
            Some(5000),
            None,
        );

        let compiled = CompiledSequence {
            id: "test-seq".to_string(),
            sequence,
            rule_id: "rule-1".to_string(),
            rule_name: "Test Rule".to_string(),
        };

        let dfa = converter.convert(&compiled).unwrap();
        assert_eq!(dfa.sequence_id(), "test-seq");
        assert_eq!(dfa.step_count(), 2);
        assert!(dfa.state_count() > 0);
    }

    #[test]
    fn test_sequence_with_until_fails() {
        let converter = NfaToDfaConverter::new(1000);

        let until_step = SeqStep::new(99, "until-pred".to_string(), 3);
        let sequence = NfaSequence::new(
            "test-seq".to_string(),
            100,
            vec![SeqStep::new(0, "pred1".to_string(), 1)],
            Some(5000),
            Some(until_step),
        );

        let compiled = CompiledSequence {
            id: "test-seq".to_string(),
            sequence,
            rule_id: "rule-1".to_string(),
            rule_name: "Test Rule".to_string(),
        };

        let result = converter.convert(&compiled);
        assert!(result.is_err());
    }

    #[test]
    fn test_state_limit() {
        let converter = NfaToDfaConverter::new(5); // Very low limit

        // Create a sequence that will exceed the state limit
        let steps: Vec<_> = (0..10)
            .map(|i| SeqStep::new(i, format!("pred{}", i), (i + 1) as u16))
            .collect();

        let sequence = NfaSequence::new(
            "test-seq".to_string(),
            100,
            steps,
            Some(5000),
            None,
        );

        let compiled = CompiledSequence {
            id: "test-seq".to_string(),
            sequence,
            rule_id: "rule-1".to_string(),
            rule_name: "Test Rule".to_string(),
        };

        let result = converter.convert(&compiled);
        // Should fail due to state limit
        assert!(result.is_err() || result.unwrap().state_count() <= 5);
    }
}
