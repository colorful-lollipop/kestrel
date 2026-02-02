// NFA Engine metrics
//
// This module provides comprehensive metrics collection for the NFA engine,
// including per-sequence metrics and overall engine statistics.

use ahash::AHashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

/// Reason for a partial match eviction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvictionReason {
    /// Expired due to maxspan time window
    Expired,

    /// Terminated by until condition
    Terminated,

    /// Evicted by LRU policy (memory pressure)
    Lru,

    /// Evicted due to quota exceeded
    Quota,

    /// Entity completed sequence (matched all steps)
    Completed,
}

/// Per-sequence metrics
#[derive(Debug, Default)]
pub struct SequenceMetrics {
    /// Total events processed for this sequence
    pub events_processed: AtomicU64,

    /// Total predicate evaluations performed
    pub evaluations: AtomicU64,

    /// Total time spent in predicate evaluation (nanoseconds)
    pub eval_time_ns: AtomicU64,

    /// Total partial matches created
    pub partial_matches_created: AtomicU64,

    /// Current active partial matches
    pub active_partial_matches: AtomicUsize,

    /// Total completed sequences (alerts generated)
    pub completed_sequences: AtomicU64,

    /// Total evictions by reason
    pub evictions: RwLock<AHashMap<EvictionReason, AtomicU64>>,

    /// Peak concurrent partial matches
    pub peak_concurrent_matches: AtomicUsize,

    /// Budget violations count (exceeded eval count or time)
    pub budget_violations: AtomicU64,
}

impl SequenceMetrics {
    pub fn new() -> Self {
        Self {
            events_processed: AtomicU64::new(0),
            evaluations: AtomicU64::new(0),
            eval_time_ns: AtomicU64::new(0),
            partial_matches_created: AtomicU64::new(0),
            active_partial_matches: AtomicUsize::new(0),
            completed_sequences: AtomicU64::new(0),
            evictions: RwLock::new(AHashMap::default()),
            peak_concurrent_matches: AtomicUsize::new(0),
            budget_violations: AtomicU64::new(0),
        }
    }

    pub fn record_event(&self) {
        self.events_processed.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record an event processed - relaxed ordering for hot path
    #[inline]
    pub fn record_event_relaxed(&self) {
        self.events_processed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_evaluation(&self, time_ns: u64) {
        self.evaluations.fetch_add(1, Ordering::Relaxed);
        self.eval_time_ns.fetch_add(time_ns, Ordering::Relaxed);
    }

    pub fn record_budget_violation(&self) {
        self.budget_violations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn partial_match_created(&self) {
        self.partial_matches_created.fetch_add(1, Ordering::Relaxed);
        self.active_partial_matches.fetch_add(1, Ordering::Relaxed);
        self.update_peak();
    }

    pub fn partial_match_removed(&self) {
        self.active_partial_matches.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn sequence_completed(&self) {
        self.completed_sequences.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_eviction(&self, reason: EvictionReason) {
        let mut evictions = self.evictions.write();
        let counter = evictions.entry(reason).or_insert_with(|| AtomicU64::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn update_peak(&self) {
        let current = self.active_partial_matches.load(Ordering::Relaxed);
        loop {
            let peak = self.peak_concurrent_matches.load(Ordering::Relaxed);
            if current <= peak {
                break;
            }
            if self
                .peak_concurrent_matches
                .compare_exchange_weak(peak, current, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }

    pub fn get_active_count(&self) -> usize {
        self.active_partial_matches.load(Ordering::Relaxed)
    }

    pub fn get_events_processed(&self) -> u64 {
        self.events_processed.load(Ordering::Relaxed)
    }

    pub fn get_completions(&self) -> u64 {
        self.completed_sequences.load(Ordering::Relaxed)
    }

    pub fn get_evaluations(&self) -> u64 {
        self.evaluations.load(Ordering::Relaxed)
    }

    pub fn get_eval_time_ns(&self) -> u64 {
        self.eval_time_ns.load(Ordering::Relaxed)
    }

    pub fn get_budget_violations(&self) -> u64 {
        self.budget_violations.load(Ordering::Relaxed)
    }
}

/// Overall NFA engine metrics
#[derive(Debug)]
pub struct NfaMetrics {
    /// Per-sequence metrics indexed by sequence ID
    pub sequences: RwLock<AHashMap<String, Arc<SequenceMetrics>>>,

    /// Total events processed across all sequences
    pub total_events_processed: AtomicU64,

    /// Total alerts generated
    pub total_alerts: AtomicU64,

    /// Current number of loaded sequences
    pub loaded_sequences: AtomicUsize,

    /// Peak number of loaded sequences
    pub peak_loaded_sequences: AtomicUsize,
}

impl NfaMetrics {
    pub fn new() -> Self {
        Self {
            sequences: RwLock::default(),
            total_events_processed: AtomicU64::new(0),
            total_alerts: AtomicU64::new(0),
            loaded_sequences: AtomicUsize::new(0),
            peak_loaded_sequences: AtomicUsize::new(0),
        }
    }

    /// Register a new sequence and return its metrics handle
    pub fn register_sequence(&self, sequence_id: String) -> Arc<SequenceMetrics> {
        let mut sequences = self.sequences.write();
        let metrics = Arc::new(SequenceMetrics::new());
        sequences.insert(sequence_id.clone(), metrics.clone());

        let count = self.loaded_sequences.fetch_add(1, Ordering::Relaxed) + 1;
        loop {
            let peak = self.peak_loaded_sequences.load(Ordering::Relaxed);
            if count <= peak {
                break;
            }
            if self
                .peak_loaded_sequences
                .compare_exchange_weak(peak, count, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }

        metrics
    }

    /// Unregister a sequence
    pub fn unregister_sequence(&self, sequence_id: &str) -> Option<Arc<SequenceMetrics>> {
        self.sequences.write().remove(sequence_id)
    }

    /// Get metrics for a specific sequence
    pub fn get_sequence_metrics(&self, sequence_id: &str) -> Option<Arc<SequenceMetrics>> {
        self.sequences.read().get(sequence_id).cloned()
    }
    
    /// Get metrics for a specific sequence - returns Arc directly
    /// 
    /// PERFORMANCE: Avoids extra clone by returning Arc
    #[inline]
    pub fn get_sequence_metrics_arc(&self, sequence_id: &str) -> Option<Arc<SequenceMetrics>> {
        self.sequences.read().get(sequence_id).map(Arc::clone)
    }

    /// Record an event processed
    pub fn record_event(&self) {
        self.total_events_processed.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record an event processed - relaxed ordering for hot path
    /// 
    /// PERFORMANCE: Uses Relaxed ordering which is fastest on x86_64
    #[inline]
    pub fn record_event_relaxed(&self) {
        self.total_events_processed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an alert generated
    pub fn record_alert(&self) {
        self.total_alerts.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total events processed
    pub fn get_total_events(&self) -> u64 {
        self.total_events_processed.load(Ordering::Relaxed)
    }

    /// Get total alerts
    pub fn get_total_alerts(&self) -> u64 {
        self.total_alerts.load(Ordering::Relaxed)
    }

    /// Get loaded sequence count
    pub fn get_loaded_count(&self) -> usize {
        self.loaded_sequences.load(Ordering::Relaxed)
    }

    /// Get a summary of all metrics
    pub fn get_summary(&self) -> MetricsSummary {
        let mut total_active = 0;
        let mut total_completions = 0;
        let mut total_evictions = 0;

        for metrics in self.sequences.read().values() {
            total_active += metrics.get_active_count();
            total_completions += metrics.get_completions();
            for counter in metrics.evictions.read().values() {
                total_evictions += counter.load(Ordering::Relaxed);
            }
        }

        MetricsSummary {
            total_events: self.get_total_events(),
            total_alerts: self.get_total_alerts(),
            loaded_sequences: self.get_loaded_count(),
            active_partial_matches: total_active,
            total_completions,
            total_evictions,
        }
    }
}

impl Default for NfaMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of engine metrics
#[derive(Debug, Clone)]
pub struct MetricsSummary {
    pub total_events: u64,
    pub total_alerts: u64,
    pub loaded_sequences: usize,
    pub active_partial_matches: usize,
    pub total_completions: u64,
    pub total_evictions: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequence_metrics_creation() {
        let metrics = SequenceMetrics::new();
        assert_eq!(metrics.get_events_processed(), 0);
        assert_eq!(metrics.get_active_count(), 0);
    }

    #[test]
    fn test_sequence_metrics_recording() {
        let metrics = SequenceMetrics::new();

        metrics.record_event();
        assert_eq!(metrics.get_events_processed(), 1);

        metrics.partial_match_created();
        assert_eq!(metrics.get_active_count(), 1);

        metrics.partial_match_removed();
        assert_eq!(metrics.get_active_count(), 0);

        metrics.sequence_completed();
        assert_eq!(metrics.get_completions(), 1);
    }

    #[test]
    fn test_eviction_recording() {
        let metrics = SequenceMetrics::new();

        metrics.record_eviction(EvictionReason::Expired);
        metrics.record_eviction(EvictionReason::Expired);
        metrics.record_eviction(EvictionReason::Terminated);

        let evictions = metrics.evictions.read();
        assert_eq!(
            evictions[&EvictionReason::Expired].load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            evictions[&EvictionReason::Terminated].load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_peak_concurrent_matches() {
        let metrics = SequenceMetrics::new();

        metrics.partial_match_created();
        metrics.partial_match_created();
        assert_eq!(metrics.peak_concurrent_matches.load(Ordering::Relaxed), 2);

        metrics.partial_match_removed();
        assert_eq!(metrics.peak_concurrent_matches.load(Ordering::Relaxed), 2); // Peak stays at 2
    }

    #[test]
    fn test_nfa_metrics_registration() {
        let mut nfa_metrics = NfaMetrics::new();

        let _metrics1 = nfa_metrics.register_sequence("seq1".to_string());
        let _metrics2 = nfa_metrics.register_sequence("seq2".to_string());

        assert_eq!(nfa_metrics.get_loaded_count(), 2);

        // Record events at the NFA level
        nfa_metrics.record_event();
        nfa_metrics.record_event();
        nfa_metrics.record_event();

        assert_eq!(nfa_metrics.get_total_events(), 3);
    }

    #[test]
    fn test_nfa_metrics_summary() {
        let mut nfa_metrics = NfaMetrics::new();

        let seq1 = nfa_metrics.register_sequence("seq1".to_string());
        let seq2 = nfa_metrics.register_sequence("seq2".to_string());

        seq1.partial_match_created();
        seq1.sequence_completed();
        seq1.partial_match_removed(); // Complete sequences are removed
        seq1.record_eviction(EvictionReason::Expired);

        seq2.partial_match_created();
        seq2.partial_match_created();
        seq2.sequence_completed();
        seq2.partial_match_removed(); // Complete sequences are removed

        let summary = nfa_metrics.get_summary();
        assert_eq!(summary.active_partial_matches, 1); // 1 remaining in seq1
        assert_eq!(summary.total_completions, 2);
        assert_eq!(summary.total_evictions, 1);
    }
}
