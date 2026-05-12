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
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, trace, warn};

/// Configuration for the NFA engine
#[derive(Debug, Clone)]
pub struct NfaEngineConfig {
    /// State store configuration
    pub state_store: StateStoreConfig,

    /// Maximum number of sequences to load (0 = unlimited)
    pub max_sequences: usize,

    /// Per-rule evaluation budget (max evaluations per second per rule)
    /// 0 = unlimited
    pub max_evaluations_per_sec: u64,

    /// Per-rule evaluation time budget (max nanoseconds per evaluation)
    /// 0 = unlimited
    pub max_eval_time_ns: u64,

    /// Budget exceeded action: "fail_open" (skip rule), "fail_closed" (return error), "degrade" (simplify)
    pub budget_action: BudgetAction,

    /// Minimum number of sequences to evaluate in parallel
    /// 0 = always use parallel evaluation (if runtime available)
    /// 1+ = only parallelize when relevant sequences >= threshold
    pub parallel_threshold: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetAction {
    /// Skip rule evaluation when budget exceeded
    FailOpen,
    /// Return error when budget exceeded
    FailClosed,
    /// Degrade: skip expensive predicates (regex) when budget exceeded
    Degrade,
}

impl Default for NfaEngineConfig {
    fn default() -> Self {
        Self {
            state_store: StateStoreConfig::default(),
            max_sequences: 1000,
            max_evaluations_per_sec: 100_000,
            max_eval_time_ns: 1_000_000,
            parallel_threshold: 4,
            budget_action: BudgetAction::FailOpen,
        }
    }
}

/// NFA Engine - main execution engine for sequence detection
pub struct NfaEngine {
    /// Loaded sequences indexed by sequence ID
    /// Using Arc for zero-copy cloning in hot path
    sequences: AHashMap<String, Arc<NfaSequence>>,

    /// Event type index: event_type_id -> sequence IDs that have steps matching this type
    event_type_index: HashMap<u16, Vec<Arc<str>>>,

    /// Predicate evaluator for evaluating predicates
    predicate_evaluator: Arc<dyn PredicateEvaluator>,

    /// State store for partial matches
    state_store: Arc<StateStore>,

    /// Metrics
    metrics: Arc<RwLock<NfaMetrics>>,

    /// Configuration
    config: NfaEngineConfig,

    /// Per-rule budget tracking: sequence_id -> (eval_count, eval_time_ns, window_start_ns)
    budget_tracker: RwLock<AHashMap<String, (u64, u64, u64)>>,
}

impl NfaEngine {
    /// Create a new NFA engine
    pub fn new(config: NfaEngineConfig, predicate_evaluator: Arc<dyn PredicateEvaluator>) -> Self {
        let metrics = Arc::new(RwLock::new(NfaMetrics::new()));
        let state_store = Arc::new(StateStore::new(config.state_store.clone()));

        Self {
            sequences: AHashMap::default(),
            event_type_index: HashMap::default(),
            predicate_evaluator,
            state_store,
            metrics,
            config,
            budget_tracker: RwLock::new(AHashMap::default()),
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

        // Store the sequence (wrapped in Arc for zero-copy cloning)
        self.sequences
            .insert(compiled.id.clone(), Arc::new(compiled.sequence.clone()));

        // Update event type index - use a Set to avoid duplicates for steps with same event_type_id
        let mut event_types: std::collections::HashSet<u16> = std::collections::HashSet::new();
        for step in &compiled.sequence.steps {
            if event_types.insert(step.event_type_id) {
                // Only add if this event_type wasn't already indexed
                self.event_type_index
                    .entry(step.event_type_id)
                    .or_default()
                    .push(Arc::from(compiled.id.as_str()));
            }
        }

        // Also index the until step if present
        if let Some(until_step) = &compiled.sequence.until_step {
            self.event_type_index
                .entry(until_step.event_type_id)
                .or_default()
                .push(Arc::from(compiled.id.as_str()));
        }

        Ok(())
    }

    /// Check and update budget for a sequence
    /// Returns true if budget exceeded (action depends on config)
    fn check_budget(&self, sequence_id: &str, eval_time_ns: u64) -> bool {
        let max_evals = self.config.max_evaluations_per_sec;
        let max_time = self.config.max_eval_time_ns;

        if max_evals == 0 && max_time == 0 {
            return false;
        }

        let now_ns = std::time::Instant::now().elapsed().as_nanos() as u64;
        let window_ns = 1_000_000_000;

        let mut tracker = self.budget_tracker.write();
        let (count, time, window_start) = tracker
            .entry(sequence_id.to_string())
            .or_insert((0, 0, now_ns));

        let start_ns = *window_start;

        if now_ns.saturating_sub(start_ns) > window_ns {
            *count = 0;
            *time = 0;
            *window_start = now_ns;
        }

        let exceeded =
            if (max_evals > 0 && *count >= max_evals) || (max_time > 0 && *time >= max_time) {
                true
            } else {
                *count += 1;
                *time += eval_time_ns;
                false
            };

        if exceeded {
            if let Some(seq_metrics) = self.metrics.read().get_sequence_metrics(sequence_id) {
                seq_metrics.record_budget_violation();
            }
            warn!(
                sequence_id = sequence_id,
                count = count,
                time_ns = time,
                "Budget exceeded for sequence"
            );
        }

        exceeded
    }

    /// Unload a sequence from the engine
    pub fn unload_sequence(&mut self, sequence_id: &str) -> NfaResult<bool> {
        debug!(sequence_id, "Unloading sequence");

        let removed = self.sequences.remove(sequence_id).is_some();

        if removed {
            // Cleanup all partial matches for this sequence
            self.cleanup_sequence(sequence_id);

            // Remove from event type index
            for (_event_type, seq_ids) in self.event_type_index.iter_mut() {
                seq_ids.retain(|id| id.as_ref() != sequence_id);
            }

            // Unregister metrics
            self.metrics.write().unregister_sequence(sequence_id);
        }

        Ok(removed)
    }

    /// Process an event through the NFA engine
    ///
    /// PERFORMANCE OPTIMIZED:
    /// - Uses thread-local buffer to avoid allocations
    /// - Zero-copy sequence references (no clone)
    /// - Lock-free metrics for hot path
    /// Process an event through the NFA engine
    ///
    /// TWO-PHASE EVALUATION:
    /// - Phase 1 (parallel/concurrent): Evaluate predicates across sequences.
    ///   This phase is read-only with respect to engine state.
    /// - Phase 2 (sequential): Apply state transitions, budget checks, and metrics
    ///   updates in deterministic order.
    pub async fn process_event(
        &mut self,
        event: &kestrel_event::Event,
    ) -> NfaResult<Vec<SequenceAlert>> {
        let entity_key = event.entity_key;
        let event_type_id = event.event_type_id;

        trace!(event_type_id = event_type_id, entity_key = entity_key, "Processing event");

        // Record event in metrics - use Relaxed ordering for hot path
        self.metrics.read().record_event_relaxed();

        // Create Arc<Event> once for zero-copy cloning across sequences
        let event_arc = Arc::new(event.clone());

        // Collect relevant sequence IDs to process (avoid borrow issues)
        let relevant_sequence_ids: Vec<Arc<str>> = self
            .event_type_index
            .get(&event_type_id)
            .cloned()
            .unwrap_or_default();

        // Phase 1: Evaluate predicates (parallel if threshold met and tokio runtime available)
        let evaluations = if relevant_sequence_ids.len() >= self.config.parallel_threshold
            && tokio::runtime::Handle::try_current().is_ok()
        {
            // Spawn evaluation tasks for true parallelism across CPU cores
            let mut handles = Vec::with_capacity(relevant_sequence_ids.len());
            for seq_id in relevant_sequence_ids {
                if let Some(seq) = self.sequences.get(seq_id.as_ref()).cloned() {
                    let evaluator = Arc::clone(&self.predicate_evaluator);
                    let event = Arc::clone(&event_arc);
                    let store = Arc::clone(&self.state_store);
                    let handle = tokio::task::spawn(async move {
                        evaluate_sequence_phase1(seq, event, evaluator, store, entity_key).await
                    });
                    handles.push(handle);
                }
            }
            let results = futures::future::join_all(handles).await;
            let mut evaluations = Vec::with_capacity(results.len());
            for r in results {
                // JoinHandle yields Result<NfaResult<SequenceEvaluation>, JoinError>
                evaluations.push(
                    r.map_err(|e| NfaError::PredicateError(e.to_string()))??
                );
            }
            evaluations
        } else {
            // Sequential/concurrent evaluation using join_all (no spawn required)
            let futures: Vec<_> = relevant_sequence_ids
                .iter()
                .filter_map(|seq_id| {
                    let seq = self.sequences.get(seq_id.as_ref()).cloned()?;
                    Some(evaluate_sequence_phase1(
                        seq,
                        Arc::clone(&event_arc),
                        Arc::clone(&self.predicate_evaluator),
                        Arc::clone(&self.state_store),
                        entity_key,
                    ))
                })
                .collect();
            let results = futures::future::join_all(futures).await;
            let mut evaluations = Vec::with_capacity(results.len());
            for r in results {
                evaluations.push(r?);
            }
            evaluations
        };

        // Phase 2: Apply state transitions sequentially for determinism
        let mut alerts = self.apply_evaluations(evaluations, &event_arc).await?;
        alerts.shrink_to_fit();
        Ok(alerts)
    }

    /// Synchronous compatibility wrapper for non-async callers.
    pub fn process_event_blocking(
        &mut self,
        event: &kestrel_event::Event,
    ) -> NfaResult<Vec<SequenceAlert>> {
        futures::executor::block_on(self.process_event(event))
    }

    /// Apply evaluated sequence transitions in deterministic order (Phase 2).
    ///
    /// This method is single-threaded to maintain state consistency.
    /// Transitions are sorted by sequence_id to ensure deterministic ordering.
    async fn apply_evaluations(
        &mut self,
        mut evaluations: Vec<SequenceEvaluation>,
        event: &Arc<kestrel_event::Event>,
    ) -> NfaResult<Vec<SequenceAlert>> {
        // Sort by sequence_id for deterministic ordering
        evaluations.sort_by(|a, b| a.sequence_id.cmp(&b.sequence_id));

        let mut alerts = Vec::with_capacity(evaluations.len());

        for eval in evaluations {
            // Record sequence-level event metric
            if let Some(seq_metrics) = self.metrics.read().get_sequence_metrics_arc(&eval.sequence_id) {
                seq_metrics.record_event_relaxed();
            }

            let mut action = eval.action;

            // Apply budget checks sequentially (matches original behavior)
            for (_predicate_id, eval_time_ns) in &eval.predicate_evals {
                if let Some(seq_metrics) = self.metrics.read().get_sequence_metrics(&eval.sequence_id) {
                    seq_metrics.record_evaluation(*eval_time_ns);
                }

                if self.check_budget(&eval.sequence_id, *eval_time_ns) {
                    match self.config.budget_action {
                        BudgetAction::FailOpen | BudgetAction::Degrade => {
                            trace!(
                                sequence_id = %eval.sequence_id,
                                "Suppressing transition due to budget exceeded"
                            );
                            action = EvaluatedAction::None;
                        },
                        BudgetAction::FailClosed => {
                            warn!(sequence_id = %eval.sequence_id, "Rule budget exceeded (fail-closed)");
                            return Err(NfaError::QuotaExceeded {
                                rule_id: eval.sequence_id.clone(),
                                reason: "Budget exceeded during sequential application".to_string(),
                            });
                        },
                    }
                    break;
                }
            }

            // Apply the state transition
            match action {
                EvaluatedAction::None => {},
                EvaluatedAction::Terminate => {
                    if let Some(seq) = self.sequences.get(&eval.sequence_id).cloned() {
                        self.terminate_entity_partial_matches(&seq, eval.entity_key)?;
                    }
                },
                EvaluatedAction::StartNew => {
                    if let Some(seq) = self.sequences.get(&eval.sequence_id).cloned() {
                        self.start_partial_match(&seq, Arc::clone(event), eval.entity_key)?;

                        // Check if this is a single-step sequence (complete immediately)
                        if seq.step_count() == 1 {
                            if let Some(pm) = self.state_store.get(&eval.sequence_id, eval.entity_key, 0) {
                                let alert = self.generate_alert(&seq, pm)?;
                                alerts.push(alert);
                                self.state_store.remove(&eval.sequence_id, eval.entity_key, 0);
                            }
                        }
                    }
                },
                EvaluatedAction::AdvanceTo(state_id) => {
                    if let Some(seq) = self.sequences.get(&eval.sequence_id).cloned() {
                        if let Some(alert) = self.try_advance_partial_matches(
                            &seq,
                            Arc::clone(event),
                            eval.entity_key,
                            state_id,
                        )? {
                            alerts.push(alert);
                        }
                    }
                },
            }
        }

        Ok(alerts)
    }

    fn start_partial_match(
        &mut self,
        sequence: &NfaSequence,
        event: Arc<kestrel_event::Event>,
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
            .get_sequence_metrics(sequence_id(sequence));
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
        event: Arc<kestrel_event::Event>,
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
            trace!(
                sequence_id = %sequence.id,
                entity_key = entity_key,
                prev_state = prev_state,
                step_state_id = step_state_id,
                current_state = partial_match.current_state,
                "Found partial match to advance"
            );
            // Check if the partial match is expired
            let now_ns = event.ts_mono_ns;
            if partial_match.is_expired(now_ns, sequence.maxspan_ms) {
                // Partial match expired - remove it
                self.state_store
                    .remove(sequence_id(sequence), entity_key, prev_state);

                let metrics_handle = self
                    .metrics
                    .read()
                    .get_sequence_metrics(sequence_id(sequence));
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
                    .get_sequence_metrics(sequence_id(sequence));
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
                    .get_sequence_metrics(sequence_id(sequence));
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

        let captures = self.extract_captures(sequence, &events)?;

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

    /// Extract field captures from matched events based on sequence configuration
    pub fn extract_captures(
        &self,
        sequence: &NfaSequence,
        events: &[Arc<kestrel_event::Event>],
    ) -> NfaResult<Vec<(String, kestrel_schema::TypedValue)>> {
        let mut captures = Vec::new();

        for capture in &sequence.captures {
            let target_event = if let Some(source_step) = &capture.source_step {
                let step_index: usize = source_step.parse().unwrap_or(0);
                if step_index < events.len() {
                    &events[step_index]
                } else {
                    continue;
                }
            } else {
                events.last().unwrap_or(&events[0])
            };

            if let Some(value) = target_event.get_field(capture.field_id) {
                captures.push((capture.alias.clone(), value.clone()));
            } else {
                captures.push((capture.alias.clone(), kestrel_schema::TypedValue::Null));
            }
        }

        Ok(captures)
    }

    /// Cleanup all partial matches for a sequence
    fn cleanup_sequence(&mut self, sequence_id: &str) {
        // Get the SeqId for this sequence (if it exists)
        let seq_id = if let Some(id) = self.state_store.get_seq_id(sequence_id) {
            id
        } else {
            return;
        };

        // Remove all partial matches for this sequence across all shards
        let removed = self.state_store.remove_by_sequence(seq_id);

        debug!(sequence_id, removed, "Cleaned up sequence partial matches");
    }

    /// Perform periodic maintenance (cleanup expired states, etc.)
    pub fn tick(&mut self, now_ns: u64) {
        let maxspan_ms = self.config.state_store.default_maxspan_ms;
        let expired = self.state_store.cleanup_expired(now_ns, maxspan_ms);

        for pm in expired {
            let metrics_handle = self.metrics.read().get_sequence_metrics(&pm.sequence_id);
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
                - (max as f32 * (1.0 - self.config.state_store.lru_eviction_threshold)) as usize;
            let evicted = self.state_store.evict_lru(to_evict);

            for pm in evicted {
                let metrics_handle = self.metrics.read().get_sequence_metrics(&pm.sequence_id);
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

/// Helper function to convert event type name to event type ID
/// Uses a simple hash-based approach for consistent ID generation
fn event_type_name_to_id(name: &str) -> u16 {
    let mut hash = 0u16;
    for byte in name.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(byte as u16);
    }
    if hash == 0 {
        hash = 1; // Ensure non-zero
    }
    hash
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
                event_type_id: event_type_name_to_id(&step.event_type_name),
                condition: None,
            })
            .collect();

        let until_step = sequence.until.as_ref().map(|until| {
            // Find the predicate to get its event type
            let event_type_name = ir_rule
                .predicates
                .get(until)
                .map_or("unknown", |p| &p.event_type);
            SeqStep {
                state_id: 999, // Until doesn't have a traditional state ID
                predicate_id: until.clone(),
                event_type_id: event_type_name_to_id(event_type_name),
                condition: None,
            }
        });

        let nfa_sequence = NfaSequence::with_captures(
            ir_rule.rule_id.clone(),
            sequence.by_field_id,
            steps,
            sequence.maxspan_ms,
            until_step,
            ir_rule.captures.clone(),
        );

        Self {
            id: ir_rule.rule_id.clone(),
            sequence: nfa_sequence,
            rule_id: rule_id.to_string(),
            rule_name: ir_rule.rule_id.clone(), // Use rule_id as name for now
        }
    }
}

// =============================================================================
// Two-Phase Evaluation Types and Functions
// =============================================================================

/// The type of state transition determined during Phase 1 evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvaluatedAction {
    /// No state transition needed.
    None,
    /// Terminate all partial matches for this entity (until condition matched).
    Terminate,
    /// Start a new partial match at state 0.
    StartNew,
    /// Advance an existing partial match to the given state.
    AdvanceTo(NfaStateId),
}

/// Result of Phase 1 evaluation for a single sequence.
#[derive(Debug, Clone)]
struct SequenceEvaluation {
    sequence_id: String,
    entity_key: u128,
    action: EvaluatedAction,
    /// Per-predicate evaluation results: (predicate_id, eval_time_ns)
    predicate_evals: Vec<(String, u64)>,
}

/// Phase 1: Evaluate predicates for a single sequence.
///
/// This function is pure read-only with respect to engine state.
/// It may run in parallel with other sequence evaluations.
async fn evaluate_sequence_phase1(
    sequence: Arc<NfaSequence>,
    event: Arc<kestrel_event::Event>,
    predicate_evaluator: Arc<dyn PredicateEvaluator>,
    state_store: Arc<StateStore>,
    entity_key: u128,
) -> NfaResult<SequenceEvaluation> {
    let event_type_id = event.event_type_id;
    let mut predicate_evals = Vec::with_capacity(2);

    // Check until condition first (same order as original sequential code)
    if let Some(until_step) = &sequence.until_step {
        if until_step.event_type_id == event_type_id {
            let start = std::time::Instant::now();
            let matched = predicate_evaluator
                .evaluate(&until_step.predicate_id, &event)
                .await?;
            predicate_evals.push((
                until_step.predicate_id.clone(),
                start.elapsed().as_nanos() as u64,
            ));

            if matched {
                return Ok(SequenceEvaluation {
                    sequence_id: sequence.id.clone(),
                    entity_key,
                    action: EvaluatedAction::Terminate,
                    predicate_evals,
                });
            }
        }
    }

    // Determine expected state based on existing partial matches (read-only)
    let expected_state = get_expected_state(&state_store, &sequence, entity_key)?;

    // Find step at expected state that passes predicate
    let relevant_step_indices = sequence.get_relevant_steps(event_type_id);
    for &step_idx in relevant_step_indices {
        if let Some(step) = sequence.steps.get(step_idx) {
            if step.state_id == expected_state {
                let start = std::time::Instant::now();
                let matched = predicate_evaluator
                    .evaluate(&step.predicate_id, &event)
                    .await?;
                predicate_evals.push((
                    step.predicate_id.clone(),
                    start.elapsed().as_nanos() as u64,
                ));

                if matched {
                    let action = if step.state_id == 0 {
                        EvaluatedAction::StartNew
                    } else {
                        EvaluatedAction::AdvanceTo(step.state_id)
                    };
                    return Ok(SequenceEvaluation {
                        sequence_id: sequence.id.clone(),
                        entity_key,
                        action,
                        predicate_evals,
                    });
                }
                break; // Only one step at expected state
            }
        }
    }

    Ok(SequenceEvaluation {
        sequence_id: sequence.id.clone(),
        entity_key,
        action: EvaluatedAction::None,
        predicate_evals,
    })
}

/// Get the expected next state for an entity in a sequence.
///
/// Returns 0 if no partial match exists, otherwise returns state_id to advance to.
fn get_expected_state(
    state_store: &StateStore,
    sequence: &NfaSequence,
    entity_key: u128,
) -> NfaResult<NfaStateId> {
    let mut max_state: NfaStateId = 0;
    let mut found = false;
    for step in &sequence.steps {
        let _ = state_store.with_match(
            &sequence.id,
            entity_key,
            step.state_id,
            |pm| {
                if !pm.terminated && pm.current_state >= max_state {
                    max_state = pm.current_state;
                    found = true;
                }
            },
        );
    }
    if found {
        Ok(max_state.saturating_add(1))
    } else {
        Ok(0)
    }
}

mod tests {
    use super::*;

    use std::sync::Arc;

    // Mock predicate evaluator for testing
    struct TestPredicateEvaluator {
        predicates: ahash::AHashMap<String, bool>,
    }

    impl TestPredicateEvaluator {
        fn new() -> Self {
            Self {
                predicates: ahash::AHashMap::default(),
            }
        }

        fn set_result(&mut self, predicate_id: String, result: bool) {
            self.predicates.insert(predicate_id, result);
        }
    }

    #[async_trait::async_trait]
    impl PredicateEvaluator for TestPredicateEvaluator {
        async fn evaluate(&self, predicate_id: &str, _event: &kestrel_event::Event) -> NfaResult<bool> {
            Ok(*self.predicates.get(predicate_id).unwrap_or(&false))
        }

        fn get_required_fields(&self, _predicate_id: &str) -> NfaResult<Vec<u32>> {
            Ok(vec![])
        }

        fn has_predicate(&self, predicate_id: &str) -> bool {
            self.predicates.contains_key(predicate_id)
        }
    }

    struct AsyncTestPredicateEvaluator {
        predicates: ahash::AHashMap<String, bool>,
    }

    #[async_trait::async_trait]
    impl PredicateEvaluator for AsyncTestPredicateEvaluator {
        async fn evaluate(
            &self,
            predicate_id: &str,
            _event: &kestrel_event::Event,
        ) -> NfaResult<bool> {
            Ok(*self.predicates.get(predicate_id).unwrap_or(&false))
        }

        fn get_required_fields(&self, _predicate_id: &str) -> NfaResult<Vec<u32>> {
            Ok(vec![])
        }

        fn has_predicate(&self, predicate_id: &str) -> bool {
            self.predicates.contains_key(predicate_id)
        }
    }

    #[tokio::test]
    async fn test_process_event_with_async_predicate() {
        let mut predicates = ahash::AHashMap::default();
        predicates.insert("pred1".to_string(), true);
        predicates.insert("pred2".to_string(), true);

        let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(AsyncTestPredicateEvaluator { predicates });
        let mut engine = NfaEngine::new(NfaEngineConfig::default(), evaluator);

        let sequence = NfaSequence::new(
            "test_seq".to_string(),
            100,
            vec![
                SeqStep::new(0, "pred1".to_string(), 1),
                SeqStep::new(1, "pred2".to_string(), 2),
            ],
            Some(5_000),
            None,
        );

        let compiled = CompiledSequence {
            id: "test_seq".to_string(),
            sequence,
            rule_id: "rule1".to_string(),
            rule_name: "Test Rule".to_string(),
        };

        assert!(engine.load_sequence(compiled).is_ok());

        let first_event = create_test_event(1, 1_000);
        let second_event = create_test_event(2, 2_000);

        let first_alerts = engine.process_event(&first_event).await.unwrap();
        assert!(first_alerts.is_empty());

        let second_alerts = engine.process_event(&second_event).await.unwrap();
        assert_eq!(second_alerts.len(), 1);
    }

    #[test]
    fn test_nfa_engine_creation() {
        let config = NfaEngineConfig::default();
        let evaluator = Arc::new(TestPredicateEvaluator::new());
        let engine = NfaEngine::new(config, evaluator);

        assert_eq!(engine.sequence_count(), 0);
    }

    #[test]
    fn test_load_sequence() {
        let _config = NfaEngineConfig::default();
        let mut evaluator = TestPredicateEvaluator::new();
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

    #[test]
    fn test_event_type_index() {
        let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestPredicateEvaluator::new());
        let mut engine = NfaEngine::new(NfaEngineConfig::default(), evaluator);

        let sequence = NfaSequence::new(
            "test_seq".to_string(),
            100,
            vec![
                SeqStep::new(0, "pred1".to_string(), 1),
                SeqStep::new(1, "pred2".to_string(), 2),
            ],
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

        // Check that event type index was populated
        assert!(engine.event_type_index.contains_key(&1));
        assert!(engine.event_type_index.contains_key(&2));
    }

    #[test]
    fn test_budget_no_limits() {
        let config = NfaEngineConfig {
            max_evaluations_per_sec: 0,
            max_eval_time_ns: 0,
            budget_action: BudgetAction::FailOpen,
            ..Default::default()
        };
        let mut evaluator = TestPredicateEvaluator::new();
        evaluator.set_result("pred1".to_string(), true);
        let mut engine = NfaEngine::new(config, Arc::new(evaluator));

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

        let event = create_test_event(1, 1000);
        let result = engine.process_event_blocking(&event);
        assert!(result.is_ok());
    }

    #[test]
    fn test_budget_eval_count_limit() {
        let config = NfaEngineConfig {
            max_evaluations_per_sec: 2,
            max_eval_time_ns: 0,
            budget_action: BudgetAction::FailOpen,
            state_store: StateStoreConfig {
                max_partial_matches_per_entity: 1000,
                ..Default::default()
            },
            ..Default::default()
        };
        let evaluator = TestPredicateEvaluator::new();
        let engine = NfaEngine::new(config, Arc::new(evaluator));

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

        let mut engine = engine;
        assert!(engine.load_sequence(compiled).is_ok());

        // Process multiple events - first 2 should succeed, rest should hit budget
        for i in 0..5 {
            let event = create_test_event(1, 1000 + i);
            let _ = engine.process_event_blocking(&event);
        }

        let metrics = engine.metrics.read();
        if let Some(seq_metrics) = metrics.get_sequence_metrics("test_seq") {
            let violations = seq_metrics.get_budget_violations();
            assert!(violations > 0, "Expected budget violations, got: {}", violations);
        }
    }

    #[test]
    fn test_budget_time_limit() {
        let config = NfaEngineConfig {
            max_evaluations_per_sec: 0,
            max_eval_time_ns: 1,
            budget_action: BudgetAction::FailOpen,
            ..Default::default()
        };
        let mut evaluator = TestPredicateEvaluator::new();
        evaluator.set_result("pred1".to_string(), true);
        let mut engine = NfaEngine::new(config, Arc::new(evaluator));

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

        let event = create_test_event(1, 1000);
        let _result = engine.process_event_blocking(&event);
    }

    #[test]
    fn test_budget_fail_open() {
        let config = NfaEngineConfig {
            max_evaluations_per_sec: 1,
            budget_action: BudgetAction::FailOpen,
            ..Default::default()
        };
        let mut evaluator = TestPredicateEvaluator::new();
        evaluator.set_result("pred1".to_string(), true);
        let mut engine = NfaEngine::new(config, Arc::new(evaluator));

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

        let mut alerts_count = 0;
        for i in 0..5 {
            let event = create_test_event(1, 1000 + i);
            let result = engine.process_event_blocking(&event);
            if let Ok(alerts) = result {
                alerts_count += alerts.len();
            }
        }

        let _ = alerts_count;
    }

    #[test]
    fn test_budget_fail_closed() {
        let config = NfaEngineConfig {
            max_evaluations_per_sec: 1,
            budget_action: BudgetAction::FailClosed,
            ..Default::default()
        };
        let mut evaluator = TestPredicateEvaluator::new();
        evaluator.set_result("pred1".to_string(), true);
        let mut engine = NfaEngine::new(config, Arc::new(evaluator));

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

        let event = create_test_event(1, 1000);
        let _result = engine.process_event_blocking(&event);
    }

    #[test]
    fn test_budget_violation_metrics() {
        let config = NfaEngineConfig {
            max_evaluations_per_sec: 3,
            budget_action: BudgetAction::FailOpen,
            state_store: StateStoreConfig {
                max_partial_matches_per_entity: 1000,
                ..Default::default()
            },
            ..Default::default()
        };
        let evaluator = TestPredicateEvaluator::new();
        let mut engine = NfaEngine::new(config, Arc::new(evaluator));

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

        // Process events - predicate returns false so no partial match created
        // but each event still triggers step_matches and budget check
        for i in 0..10 {
            let event = create_test_event(1, 1000 + i);
            let _ = engine.process_event_blocking(&event);
        }

        let summary = engine.metrics.read().get_summary();
        let _ = summary.total_evictions;

        let metrics = engine.metrics.read();
        if let Some(seq_metrics) = metrics.get_sequence_metrics("test_seq") {
            let violations = seq_metrics.get_budget_violations();
            assert!(violations > 0, "Expected budget violations, got: {}", violations);

            let evaluations = seq_metrics.get_evaluations();
            assert!(
                evaluations >= violations,
                "Evaluations {} should be >= violations {}",
                evaluations,
                violations
            );
        }
    }

    // =========================================================================
    // Two-Phase Parallel Evaluation Tests
    // =========================================================================

    #[tokio::test]
    async fn test_parallel_sequential_equivalence_multi_sequence() {
        let mut parallel_evaluator = TestPredicateEvaluator::new();
        parallel_evaluator.set_result("p1".to_string(), true);
        parallel_evaluator.set_result("p2".to_string(), true);
        parallel_evaluator.set_result("p3".to_string(), true);
        parallel_evaluator.set_result("p4".to_string(), true);

        let mut sequential_evaluator = TestPredicateEvaluator::new();
        sequential_evaluator.set_result("p1".to_string(), true);
        sequential_evaluator.set_result("p2".to_string(), true);
        sequential_evaluator.set_result("p3".to_string(), true);
        sequential_evaluator.set_result("p4".to_string(), true);

        let parallel_evaluator: Arc<dyn PredicateEvaluator> = Arc::new(parallel_evaluator);
        let sequential_evaluator: Arc<dyn PredicateEvaluator> = Arc::new(sequential_evaluator);

        let mut parallel_engine = NfaEngine::new(
            NfaEngineConfig {
                parallel_threshold: 0,
                ..Default::default()
            },
            parallel_evaluator,
        );
        let mut sequential_engine = NfaEngine::new(
            NfaEngineConfig {
                parallel_threshold: 9999,
                ..Default::default()
            },
            sequential_evaluator,
        );

        // Load multiple sequences with different event types
        let seqs = vec![
            ("seq_a", vec![(1, "p1"), (2, "p2")]),
            ("seq_b", vec![(1, "p3"), (3, "p4")]),
            ("seq_c", vec![(2, "p1")]),
        ];

        for (id, steps) in seqs {
            let seq_steps: Vec<_> = steps
                .into_iter()
                .enumerate()
                .map(|(i, (et, pred))| SeqStep::new(i as u16, pred.to_string(), et))
                .collect();
            let seq = NfaSequence::new(id.to_string(), 100, seq_steps, Some(10_000), None);
            let compiled = CompiledSequence {
                id: id.to_string(),
                sequence: seq,
                rule_id: format!("rule-{}", id),
                rule_name: id.to_string(),
            };
            parallel_engine.load_sequence(compiled.clone()).unwrap();
            sequential_engine.load_sequence(compiled).unwrap();
        }

        // Feed interleaved events
        let events = vec![
            create_test_event(1, 1_000),
            create_test_event(1, 2_000),
            create_test_event(2, 3_000),
            create_test_event(3, 4_000),
            create_test_event(2, 5_000),
        ];

        let mut parallel_alerts = Vec::new();
        let mut sequential_alerts = Vec::new();

        for event in events {
            parallel_alerts.extend(parallel_engine.process_event(&event).await.unwrap());
            sequential_alerts.extend(sequential_engine.process_event(&event).await.unwrap());
        }

        // Same number of alerts
        assert_eq!(
            parallel_alerts.len(),
            sequential_alerts.len(),
            "Parallel and sequential should produce same number of alerts"
        );

        // Same alert contents (sorted by sequence_id for stability)
        let mut parallel_sorted = parallel_alerts.clone();
        let mut sequential_sorted = sequential_alerts.clone();
        parallel_sorted.sort_by(|a, b| a.sequence_id.cmp(&b.sequence_id));
        sequential_sorted.sort_by(|a, b| a.sequence_id.cmp(&b.sequence_id));

        for (p, s) in parallel_sorted.iter().zip(sequential_sorted.iter()) {
            assert_eq!(p.sequence_id, s.sequence_id);
            assert_eq!(p.entity_key, s.entity_key);
            assert_eq!(p.events.len(), s.events.len());
        }
    }

    #[tokio::test]
    async fn test_parallel_sequential_equivalence_single_entity() {
        let mut evaluator = TestPredicateEvaluator::new();
        evaluator.set_result("p1".to_string(), true);
        evaluator.set_result("p2".to_string(), true);
        evaluator.set_result("p3".to_string(), true);

        let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(evaluator);
        let mut parallel_engine = NfaEngine::new(
            NfaEngineConfig {
                parallel_threshold: 0,
                ..Default::default()
            },
            Arc::clone(&evaluator),
        );
        let mut sequential_engine = NfaEngine::new(
            NfaEngineConfig {
                parallel_threshold: 9999,
                ..Default::default()
            },
            evaluator,
        );

        // One 3-step sequence
        let seq = NfaSequence::new(
            "three_step".to_string(),
            100,
            vec![
                SeqStep::new(0, "p1".to_string(), 1),
                SeqStep::new(1, "p2".to_string(), 2),
                SeqStep::new(2, "p3".to_string(), 3),
            ],
            Some(10_000),
            None,
        );
        let compiled = CompiledSequence {
            id: "three_step".to_string(),
            sequence: seq,
            rule_id: "rule1".to_string(),
            rule_name: "Three Step".to_string(),
        };
        parallel_engine.load_sequence(compiled.clone()).unwrap();
        sequential_engine.load_sequence(compiled).unwrap();

        let events = vec![
            create_test_event(1, 1_000),
            create_test_event(2, 2_000),
            create_test_event(3, 3_000),
        ];

        for event in &events {
            let p = parallel_engine.process_event(event).await.unwrap();
            let s = sequential_engine.process_event(event).await.unwrap();
            assert_eq!(
                p.len(),
                s.len(),
                "Event type {} should produce same alert count",
                event.event_type_id
            );
        }

        // Final alert should be identical
        let p_final = parallel_engine.process_event(&create_test_event(3, 4_000)).await.unwrap();
        let s_final = sequential_engine.process_event(&create_test_event(3, 4_000)).await.unwrap();
        assert_eq!(p_final.len(), s_final.len());
    }

    #[tokio::test]
    async fn test_parallel_determinism_same_event_same_result() {
        let mut evaluator = TestPredicateEvaluator::new();
        evaluator.set_result("p1".to_string(), true);
        evaluator.set_result("p2".to_string(), true);

        let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(evaluator);
        let mut engine = NfaEngine::new(
            NfaEngineConfig {
                parallel_threshold: 0,
                ..Default::default()
            },
            evaluator,
        );

        // Load 10 single-step sequences all matching event type 1
        for i in 0..10 {
            let seq = NfaSequence::new(
                format!("seq_{}", i),
                100,
                vec![SeqStep::new(0, "p1".to_string(), 1)],
                Some(5_000),
                None,
            );
            let compiled = CompiledSequence {
                id: format!("seq_{}", i),
                sequence: seq,
                rule_id: format!("rule{}", i),
                rule_name: format!("Rule {}", i),
            };
            engine.load_sequence(compiled).unwrap();
        }

        // Process events with different entity keys deterministically
        let mut all_counts = Vec::new();
        for i in 0u128..20 {
            let e = kestrel_event::Event::builder()
                .event_type(1)
                .ts_mono(1_000)
                .ts_wall(1_000)
                .entity_key(i.wrapping_add(1))
                .build()
                .unwrap();
            let alerts = engine.process_event(&e).await.unwrap();
            all_counts.push(alerts.len());
        }

        // Every run should produce exactly 10 alerts (one per sequence)
        assert!(
            all_counts.iter().all(|&c| c == 10),
            "All parallel runs should produce 10 alerts"
        );
    }

    fn create_test_event(event_type: u16, timestamp_ns: u64) -> kestrel_event::Event {
        kestrel_event::Event::builder()
            .event_type(event_type)
            .ts_mono(timestamp_ns)
            .ts_wall(timestamp_ns)
            .entity_key(0x12345)
            .build()
            .expect("Failed to build test event")
    }
}
// TEST MARKER
