// NFA Engine - Core execution engine for sequence detection
//
// This module implements the main NFA engine that:
// - Loads compiled sequences
// - Processes events through the NFA
// - Tracks partial matches per entity
// - Generates alerts when sequences complete
// - Handles maxspan, until, and by semantics

use crate::metrics::{EvictionReason, NfaMetrics};
use crate::state::{NfaSequence, NfaStateId, PartialMatch, SeqStep};
use crate::store::{StateStore, StateStoreConfig};
use crate::{CompiledSequence, NfaError, NfaResult, PredicateEvaluator, SequenceAlert};
use ahash::AHashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use tracing::{debug, trace, warn};

/// Configuration for the NFA engine
#[derive(Debug, Clone)]
pub struct NfaEngineConfig {
    /// State store configuration
    pub state_store: StateStoreConfig,

    /// Maximum number of sequences to load (0 = unlimited)
    pub max_sequences: usize,
}

impl Default for NfaEngineConfig {
    fn default() -> Self {
        Self {
            state_store: StateStoreConfig::default(),
            max_sequences: 1000,
        }
    }
}

/// NFA Engine - main execution engine for sequence detection
pub struct NfaEngine {
    /// Loaded sequences indexed by sequence ID
    sequences: AHashMap<String, NfaSequence>,

    /// Predicate evaluator for evaluating predicates
    predicate_evaluator: Arc<dyn PredicateEvaluator>,

    /// State store for partial matches
    state_store: StateStore,

    /// Metrics
    metrics: Arc<RwLock<NfaMetrics>>,

    /// Configuration
    config: NfaEngineConfig,
}

impl NfaEngine {
    /// Create a new NFA engine
    pub fn new(config: NfaEngineConfig, predicate_evaluator: Arc<dyn PredicateEvaluator>) -> Self {
        let metrics = Arc::new(RwLock::new(NfaMetrics::new()));
        let state_store = StateStore::new(config.state_store.clone());

        Self {
            sequences: AHashMap::default(),
            predicate_evaluator,
            state_store,
            metrics,
            config,
        }
    }

    /// Load a compiled sequence into the engine
    pub fn load_sequence(&mut self, compiled: CompiledSequence) -> NfaResult<()> {
        debug!(sequence_id = %compiled.id, "Loading sequence");

        // Check if we've exceeded max sequences
        if self.config.max_sequences > 0 && self.sequences.len() >= self.config.max_sequences {
            return Err(NfaError::InvalidSequence(format!(
                "Maximum sequence limit reached: {}",
                self.config.max_sequences
            )));
        }

        // Register metrics for this sequence
        self.metrics.write().register_sequence(compiled.id.clone());

        // Store the sequence
        self.sequences
            .insert(compiled.id.clone(), compiled.sequence);

        Ok(())
    }

    /// Unload a sequence from the engine
    pub fn unload_sequence(&mut self, sequence_id: &str) -> NfaResult<bool> {
        debug!(sequence_id, "Unloading sequence");

        let removed = self.sequences.remove(sequence_id).is_some();

        if removed {
            // Cleanup all partial matches for this sequence
            self.cleanup_sequence(sequence_id);

            // Unregister metrics
            self.metrics.write().unregister_sequence(sequence_id);
        }

        Ok(removed)
    }

    /// Process an event through the NFA engine
    pub fn process_event(&mut self, event: &kestrel_event::Event) -> NfaResult<Vec<SequenceAlert>> {
        let mut alerts = Vec::new();
        let entity_key = event.entity_key;

        trace!(
            event_type_id = event.event_type_id,
            entity_key = entity_key,
            "Processing event"
        );

        // Record event in metrics
        self.metrics.write().record_event();

        // Collect sequence IDs to avoid borrow checker issues
        let sequence_ids: Vec<String> = self.sequences.keys().cloned().collect();

        // Process event through each sequence
        for sequence_id in sequence_ids {
            // Get sequence metrics handle before processing
            let metrics_handle = self
                .metrics
                .read()
                .get_sequence_metrics(&sequence_id)
                .cloned();

            if let Some(seq_metrics) = metrics_handle {
                seq_metrics.record_event();
            }

            // Get the sequence (clone to avoid holding borrow)
            let sequence = self.sequences.get(&sequence_id).cloned();

            if let Some(seq) = sequence {
                // Process event through this sequence
                if let Some(match_alerts) = self.process_sequence_event(&seq, event)? {
                    alerts.extend(match_alerts);
                }
            }
        }

        Ok(alerts)
    }

    /// Process an event through a specific sequence
    fn process_sequence_event(
        &mut self,
        sequence: &NfaSequence,
        event: &kestrel_event::Event,
    ) -> NfaResult<Option<Vec<SequenceAlert>>> {
        let entity_key = event.entity_key;
        let event_type_id = event.event_type_id;

        // Check if this event type is relevant to any step in the sequence
        let relevant_steps: Vec<_> = sequence
            .steps
            .iter()
            .filter(|step| step.event_type_id == event_type_id)
            .collect();

        if relevant_steps.is_empty() {
            return Ok(None);
        }

        let mut alerts = Vec::new();
        let timestamp_ns = event.ts_mono_ns;

        // Check for until condition first
        if let Some(until_step) = &sequence.until_step {
            if self.step_matches(event, until_step, sequence_id(sequence))? {
                // Until condition matched - terminate all partial matches for this entity
                self.terminate_entity_partial_matches(sequence, entity_key)?;
                return Ok(None);
            }
        }

        // Check each relevant step
        for step in &relevant_steps {
            if !self.step_matches(event, step, sequence_id(sequence))? {
                continue;
            }

            // Step matched - check if we can advance any partial matches
            let state_id = step.state_id;

            // If this is the first step (state 0), start a new partial match
            if state_id == 0 {
                self.start_partial_match(sequence, event.clone(), entity_key)?;
            } else {
                // Try to advance existing partial matches
                if let Some(alert) =
                    self.try_advance_partial_matches(sequence, event.clone(), entity_key, state_id)?
                {
                    alerts.push(alert);
                }
            }
        }

        Ok(if alerts.is_empty() {
            None
        } else {
            Some(alerts)
        })
    }

    /// Check if a step matches an event
    fn step_matches(
        &self,
        event: &kestrel_event::Event,
        step: &SeqStep,
        _sequence_id: &str,
    ) -> NfaResult<bool> {
        // Evaluate the predicate
        match self.predicate_evaluator.evaluate(&step.predicate_id, event) {
            Ok(matches) => Ok(matches),
            Err(e) => {
                warn!(
                    predicate_id = %step.predicate_id,
                    error = %e,
                    "Predicate evaluation failed"
                );
                Err(e)
            }
        }
    }

    /// Start a new partial match for a sequence
    fn start_partial_match(
        &mut self,
        sequence: &NfaSequence,
        event: kestrel_event::Event,
        entity_key: u128,
    ) -> NfaResult<()> {
        let partial_match = PartialMatch::new(
            sequence_id(sequence).to_string(),
            entity_key,
            event,
            0, // Start at state 0
        );

        // Store the partial match
        self.state_store.insert(partial_match)?;

        // Update metrics
        let metrics_handle = self
            .metrics
            .read()
            .get_sequence_metrics(sequence_id(sequence))
            .cloned();
        if let Some(seq_metrics) = metrics_handle {
            seq_metrics.partial_match_created();
        }

        trace!(
            sequence_id = %sequence.id,
            entity_key = entity_key,
            "Started new partial match"
        );

        Ok(())
    }

    /// Try to advance existing partial matches
    fn try_advance_partial_matches(
        &mut self,
        sequence: &NfaSequence,
        event: kestrel_event::Event,
        entity_key: u128,
        step_state_id: NfaStateId,
    ) -> NfaResult<Option<SequenceAlert>> {
        // Find partial matches that are at the previous state
        let prev_state = step_state_id.saturating_sub(1);

        // Try to get a partial match at the previous state
        if let Some(mut partial_match) =
            self.state_store
                .get(sequence_id(sequence), entity_key, prev_state)
        {
            // Check if the partial match is expired
            let now_ns = event.ts_mono_ns;
            if partial_match.is_expired(now_ns, sequence.maxspan_ms) {
                // Partial match expired - remove it
                self.state_store
                    .remove(sequence_id(sequence), entity_key, prev_state);

                let metrics_handle = self
                    .metrics
                    .read()
                    .get_sequence_metrics(sequence_id(sequence))
                    .cloned();
                if let Some(seq_metrics) = metrics_handle {
                    seq_metrics.partial_match_removed();
                    seq_metrics.record_eviction(EvictionReason::Expired);
                }

                return Ok(None);
            }

            // Advance the partial match
            partial_match.advance(event.clone(), step_state_id);

            // Check if the sequence is now complete
            if partial_match.is_complete(sequence.step_count()) {
                // Sequence complete! Generate alert
                let alert = self.generate_alert(sequence, partial_match)?;

                // Remove the partial match
                self.state_store
                    .remove(sequence_id(sequence), entity_key, step_state_id);

                let metrics_handle = self
                    .metrics
                    .read()
                    .get_sequence_metrics(sequence_id(sequence))
                    .cloned();
                if let Some(seq_metrics) = metrics_handle {
                    seq_metrics.partial_match_removed();
                    seq_metrics.sequence_completed();
                }

                self.metrics.write().record_alert();

                return Ok(Some(alert));
            } else {
                // Store the advanced partial match at the new state
                self.state_store
                    .remove(sequence_id(sequence), entity_key, prev_state);
                self.state_store.insert(partial_match)?;
            }
        }

        Ok(None)
    }

    /// Terminate all partial matches for an entity (due to until condition)
    fn terminate_entity_partial_matches(
        &mut self,
        sequence: &NfaSequence,
        entity_key: u128,
    ) -> NfaResult<()> {
        // For simplicity, we'll terminate all states for this entity and sequence
        // In a more optimized implementation, we'd track all states per entity
        for state_id in 0..sequence.step_count() as NfaStateId {
            if let Some(mut pm) =
                self.state_store
                    .remove(sequence_id(sequence), entity_key, state_id)
            {
                pm.terminate();

                let metrics_handle = self
                    .metrics
                    .read()
                    .get_sequence_metrics(sequence_id(sequence))
                    .cloned();
                if let Some(seq_metrics) = metrics_handle {
                    seq_metrics.partial_match_removed();
                    seq_metrics.record_eviction(EvictionReason::Terminated);
                }

                trace!(
                    sequence_id = %sequence.id,
                    entity_key = entity_key,
                    state_id = state_id,
                    "Terminated partial match due to until condition"
                );
            }
        }

        Ok(())
    }

    /// Generate an alert from a completed partial match
    fn generate_alert(
        &self,
        sequence: &NfaSequence,
        partial_match: PartialMatch,
    ) -> NfaResult<SequenceAlert> {
        let events: Vec<_> = partial_match
            .matched_events
            .into_iter()
            .map(|me| me.event)
            .collect();

        let captures = Vec::new(); // TODO: Extract captures from predicates

        Ok(SequenceAlert {
            rule_id: sequence.id.clone(),
            rule_name: sequence.id.clone(), // Use ID as name for now
            sequence_id: sequence.id.clone(),
            entity_key: partial_match.entity_key,
            timestamp_ns: partial_match.last_match_ns,
            events,
            captures,
        })
    }

    /// Cleanup all partial matches for a sequence
    fn cleanup_sequence(&mut self, sequence_id: &str) {
        // This would typically involve iterating through all entities and states
        // and removing partial matches for this sequence
        // For now, we'll rely on the periodic cleanup to handle this
    }

    /// Perform periodic maintenance (cleanup expired states, etc.)
    pub fn tick(&mut self, now_ns: u64) {
        let expired = self.state_store.cleanup_expired(now_ns);

        for pm in expired {
            let metrics_handle = self
                .metrics
                .read()
                .get_sequence_metrics(&pm.sequence_id)
                .cloned();
            if let Some(seq_metrics) = metrics_handle {
                seq_metrics.partial_match_removed();

                let reason = if pm.terminated {
                    EvictionReason::Terminated
                } else {
                    EvictionReason::Expired
                };

                seq_metrics.record_eviction(reason);
            }
        }

        // Check if we need to evict LRU entries
        let total = self.state_store.total_matches();
        let max = self.config.state_store.max_total_partial_matches;

        if max > 0 && total as f32 > max as f32 * self.config.state_store.lru_eviction_threshold {
            let to_evict = total
                - (max as f32 * (1.0 - self.config.state_store.lru_eviction_threshold) as f32)
                    as usize;
            let evicted = self.state_store.evict_lru(to_evict);

            for pm in evicted {
                let metrics_handle = self
                    .metrics
                    .read()
                    .get_sequence_metrics(&pm.sequence_id)
                    .cloned();
                if let Some(seq_metrics) = metrics_handle {
                    seq_metrics.partial_match_removed();
                    seq_metrics.record_eviction(EvictionReason::Lru);
                }
            }
        }
    }

    /// Get metrics
    pub fn metrics(&self) -> &Arc<RwLock<NfaMetrics>> {
        &self.metrics
    }

    /// Get the number of loaded sequences
    pub fn sequence_count(&self) -> usize {
        self.sequences.len()
    }
}

/// Helper function to get sequence ID from reference
fn sequence_id(seq: &NfaSequence) -> &str {
    &seq.id
}

/// Compile an IR sequence to an NFA sequence
impl From<(&kestrel_eql::ir::IrRule, &str)> for CompiledSequence {
    fn from((ir_rule, rule_id): (&kestrel_eql::ir::IrRule, &str)) -> Self {
        let sequence = ir_rule
            .sequence
            .as_ref()
            .expect("IR rule must have a sequence");

        let steps = sequence
            .steps
            .iter()
            .enumerate()
            .map(|(idx, step)| SeqStep {
                state_id: idx as NfaStateId,
                predicate_id: step.predicate_id.clone(),
                event_type_id: 0, // TODO: Extract from predicate or add to IR
                condition: None,
            })
            .collect();

        let nfa_sequence = NfaSequence::new(
            ir_rule.rule_id.clone(),
            sequence.by_field_id,
            steps,
            sequence.maxspan_ms,
            sequence.until.as_ref().map(|until| SeqStep {
                state_id: 999, // Until doesn't have a traditional state ID
                predicate_id: until.clone(),
                event_type_id: 0,
                condition: None,
            }),
        );

        Self {
            id: ir_rule.rule_id.clone(),
            sequence: nfa_sequence,
            rule_id: rule_id.to_string(),
            rule_name: ir_rule.rule_id.clone(), // Use rule_id as name for now
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // Mock predicate evaluator for testing
    struct MockPredicateEvaluator {
        predicates: AHashMap<String, bool>,
    }

    impl MockPredicateEvaluator {
        fn new() -> Self {
            Self {
                predicates: AHashMap::default(),
            }
        }

        fn set_result(&mut self, predicate_id: String, result: bool) {
            self.predicates.insert(predicate_id, result);
        }
    }

    impl PredicateEvaluator for MockPredicateEvaluator {
        fn evaluate(&self, predicate_id: &str, _event: &kestrel_event::Event) -> NfaResult<bool> {
            Ok(*self.predicates.get(predicate_id).unwrap_or(&false))
        }

        fn get_required_fields(&self, _predicate_id: &str) -> NfaResult<Vec<u32>> {
            Ok(vec![])
        }

        fn has_predicate(&self, predicate_id: &str) -> bool {
            self.predicates.contains_key(predicate_id)
        }
    }

    #[test]
    fn test_nfa_engine_creation() {
        let config = NfaEngineConfig::default();
        let evaluator = Arc::new(MockPredicateEvaluator::new());
        let engine = NfaEngine::new(config, evaluator);

        assert_eq!(engine.sequence_count(), 0);
    }

    #[test]
    fn test_load_sequence() {
        let config = NfaEngineConfig::default();
        let mut evaluator = MockPredicateEvaluator::new();
        evaluator.set_result("pred1".to_string(), true);

        let mut engine = NfaEngine::new(NfaEngineConfig::default(), Arc::new(evaluator));

        let sequence = NfaSequence::new(
            "test_seq".to_string(),
            100,
            vec![SeqStep::new(0, "pred1".to_string(), 1)],
            Some(5000),
            None,
        );

        let compiled = CompiledSequence {
            id: "test_seq".to_string(),
            sequence,
            rule_id: "rule1".to_string(),
            rule_name: "Test Rule".to_string(),
        };

        assert!(engine.load_sequence(compiled).is_ok());
        assert_eq!(engine.sequence_count(), 1);
    }
}
