// Hot Spot Detector - Identifies frequently matched sequences
//
// Tracks sequence matching frequency and success rate to determine
// which sequences should be converted to DFAs for performance.

use crate::LazyDfaError;
use ahash::AHashMap;
use std::time::{Duration, Instant};

/// Hot spot detection thresholds
#[derive(Debug, Clone)]
pub struct HotSpotThreshold {
    /// Minimum matches per minute to be considered "hot"
    pub min_matches_per_minute: u64,

    /// Minimum success rate (0.0 - 1.0)
    pub min_success_rate: f64,

    /// Minimum total matches before considering conversion
    pub min_total_matches: u64,

    /// Time window for evaluating hot spots
    pub evaluation_window: Duration,
}

impl Default for HotSpotThreshold {
    fn default() -> Self {
        Self {
            min_matches_per_minute: 1000,
            min_success_rate: 0.8,
            min_total_matches: 500,
            evaluation_window: Duration::from_secs(60),
        }
    }
}

/// Statistics for a single sequence
#[derive(Debug, Clone)]
pub struct SequenceStats {
    /// Total number of evaluations
    pub evaluations: u64,

    /// Number of successful matches
    pub matches: u64,

    /// Number of partial matches created
    pub partial_matches: u64,

    /// First seen timestamp
    pub first_seen: Instant,

    /// Last seen timestamp
    pub last_seen: Instant,

    /// Total evaluation time (nanoseconds)
    pub total_eval_time_ns: u64,
}

impl SequenceStats {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            evaluations: 0,
            matches: 0,
            partial_matches: 0,
            first_seen: now,
            last_seen: now,
            total_eval_time_ns: 0,
        }
    }

    pub fn record_evaluation(&mut self, eval_time_ns: u64) {
        self.evaluations += 1;
        self.last_seen = Instant::now();
        self.total_eval_time_ns += eval_time_ns;
    }

    pub fn record_match(&mut self) {
        self.matches += 1;
    }

    pub fn record_partial_match(&mut self) {
        self.partial_matches += 1;
    }

    pub fn success_rate(&self) -> f64 {
        if self.evaluations == 0 {
            return 0.0;
        }
        self.matches as f64 / self.evaluations as f64
    }

    pub fn matches_per_minute(&self) -> f64 {
        let duration = self.last_seen.duration_since(self.first_seen);
        let minutes = duration.as_secs_f64() / 60.0;
        if minutes == 0.0 {
            return 0.0;
        }
        self.matches as f64 / minutes
    }

    pub fn avg_eval_time_ns(&self) -> u64 {
        if self.evaluations == 0 {
            return 0;
        }
        self.total_eval_time_ns / self.evaluations
    }
}

impl Default for SequenceStats {
    fn default() -> Self {
        Self::new()
    }
}

/// A detected hot spot
#[derive(Debug, Clone)]
pub struct HotSpot {
    /// Sequence ID
    pub sequence_id: String,

    /// Current statistics
    pub stats: SequenceStats,

    /// Hotness score (higher = hotter)
    pub score: f64,
}

/// Hot spot detector
pub struct HotSpotDetector {
    /// Statistics per sequence
    stats: AHashMap<String, SequenceStats>,

    /// Detection thresholds
    thresholds: HotSpotThreshold,
}

impl HotSpotDetector {
    pub fn new(thresholds: HotSpotThreshold) -> Self {
        Self {
            stats: AHashMap::default(),
            thresholds,
        }
    }

    pub fn with_default_thresholds() -> Self {
        Self::new(HotSpotThreshold::default())
    }

    /// Record an evaluation for a sequence
    pub fn record_evaluation(&mut self, sequence_id: &str, eval_time_ns: u64) {
        let stats = self.stats.entry(sequence_id.to_string()).or_default();
        stats.record_evaluation(eval_time_ns);
    }

    /// Record a match for a sequence
    pub fn record_match(&mut self, sequence_id: &str) {
        if let Some(stats) = self.stats.get_mut(sequence_id) {
            stats.record_match();
        }
    }

    /// Record a partial match for a sequence
    pub fn record_partial_match(&mut self, sequence_id: &str) {
        if let Some(stats) = self.stats.get_mut(sequence_id) {
            stats.record_partial_match();
        }
    }

    /// Get statistics for a sequence
    pub fn get_stats(&self, sequence_id: &str) -> Option<&SequenceStats> {
        self.stats.get(sequence_id)
    }

    /// Check if a sequence is a hot spot
    pub fn is_hot(&self, sequence_id: &str) -> bool {
        let stats = match self.stats.get(sequence_id) {
            Some(s) => s,
            None => return false,
        };

        // Check minimum total matches
        if stats.evaluations < self.thresholds.min_total_matches {
            return false;
        }

        // Check success rate
        if stats.success_rate() < self.thresholds.min_success_rate {
            return false;
        }

        // Check matches per minute
        if stats.matches_per_minute() < self.thresholds.min_matches_per_minute as f64 {
            return false;
        }

        true
    }

    /// Get all hot spots
    pub fn get_hot_spots(&self) -> Vec<HotSpot> {
        self.stats
            .iter()
            .filter(|(id, _)| self.is_hot(id))
            .map(|(id, stats)| {
                let score = self.calculate_hotness_score(stats);
                HotSpot {
                    sequence_id: id.clone(),
                    stats: stats.clone(),
                    score,
                }
            })
            .collect()
    }

    /// Calculate hotness score for a sequence
    fn calculate_hotness_score(&self, stats: &SequenceStats) -> f64 {
        // Score = (matches_per_minute / threshold) * success_rate * log(evaluations)
        let mpm_ratio =
            stats.matches_per_minute() / self.thresholds.min_matches_per_minute as f64;
        let success_rate = stats.success_rate();
        let eval_factor = (stats.evaluations as f64).ln().max(1.0);

        mpm_ratio * success_rate * eval_factor
    }

    /// Remove statistics for a sequence
    pub fn remove(&mut self, sequence_id: &str) -> bool {
        self.stats.remove(sequence_id).is_some()
    }

    /// Clear all statistics
    pub fn clear(&mut self) {
        self.stats.clear();
    }

    /// Get the number of tracked sequences
    pub fn len(&self) -> usize {
        self.stats.len()
    }

    /// Check if tracking any sequences
    pub fn is_empty(&self) -> bool {
        self.stats.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequence_stats() {
        let mut stats = SequenceStats::new();
        stats.record_evaluation(100);
        stats.record_match();

        assert_eq!(stats.evaluations, 1);
        assert_eq!(stats.matches, 1);
        assert_eq!(stats.success_rate(), 1.0);
        assert_eq!(stats.total_eval_time_ns, 100);
    }

    #[test]
    fn test_detector_creation() {
        let detector = HotSpotDetector::with_default_thresholds();
        assert!(detector.is_empty());
        assert_eq!(detector.len(), 0);
    }

    #[test]
    fn test_record_evaluation() {
        let mut detector = HotSpotDetector::with_default_thresholds();
        detector.record_evaluation("seq-1", 100);

        assert!(!detector.is_empty());
        assert_eq!(detector.len(), 1);

        let stats = detector.get_stats("seq-1").unwrap();
        assert_eq!(stats.evaluations, 1);
        assert_eq!(stats.total_eval_time_ns, 100);
    }

    #[test]
    fn test_hot_spot_detection() {
        let mut detector = HotSpotDetector::with_default_thresholds();

        // Record many evaluations and matches
        for _ in 0..1000 {
            detector.record_evaluation("seq-1", 100);
            detector.record_match("seq-1");
        }

        // Should be hot after enough matches
        assert!(detector.is_hot("seq-1"));
    }

    #[test]
    fn test_low_success_rate() {
        let thresholds = HotSpotThreshold {
            min_success_rate: 0.9,
            ..Default::default()
        };
        let mut detector = HotSpotDetector::new(thresholds);

        // Record evaluations with low success rate
        for _ in 0..1000 {
            detector.record_evaluation("seq-1", 100);
        }
        for _ in 0..100 {
            detector.record_match("seq-1");
        }

        // Should not be hot due to low success rate (10%)
        assert!(!detector.is_hot("seq-1"));
    }

    #[test]
    fn test_get_hot_spots() {
        let mut detector = HotSpotDetector::with_default_thresholds();

        // Make seq-1 hot
        for _ in 0..1000 {
            detector.record_evaluation("seq-1", 100);
            detector.record_match("seq-1");
        }

        // Make seq-2 not hot
        detector.record_evaluation("seq-2", 100);

        let hot_spots = detector.get_hot_spots();
        assert_eq!(hot_spots.len(), 1);
        assert_eq!(hot_spots[0].sequence_id, "seq-1");
        assert!(hot_spots[0].score > 0.0);
    }
}
