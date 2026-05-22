//! Circuit Breaker for Rule Resilience
//!
//! Prevents cascading failures by detecting when rules repeatedly fail,
//! timeout, or OOM, and temporarily disabling them.

use ahash::AHashMap;
use parking_lot::RwLock;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Health state of a rule from the circuit breaker perspective.
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    /// Rule is operating normally.
    Healthy,
    /// Rule is experiencing elevated failures (failure rate 0.0-1.0).
    Degraded(f32),
    /// Rule has been disabled due to repeated failures.
    Disabled(String),
}

/// Snapshot of a rule's health.
#[derive(Debug, Clone)]
pub struct RuleHealthStatus {
    /// Rule identifier.
    pub rule_id: String,
    /// Current circuit state.
    pub state: CircuitState,
    /// Timestamp of the most recent failure (if any).
    pub last_failure: Option<Instant>,
    /// Total failures recorded in the current window.
    pub failure_count: u64,
}

/// Trait for circuit breaker implementations.
///
/// Used by both `DetectionEngine` and `NfaEngine` to guard rule
/// evaluation against misbehaving rules.
pub trait CircuitBreaker: Send + Sync {
    /// Record a successful evaluation for a rule.
    fn record_success(&self, rule_id: &str);

    /// Record a failed evaluation for a rule.
    fn record_failure(&self, rule_id: &str, error: &str);

    /// Record a timeout for a rule.
    fn record_timeout(&self, rule_id: &str);

    /// Record an out-of-memory event for a rule.
    fn record_oom(&self, rule_id: &str);

    /// Returns true if the circuit breaker is open for this rule
    /// (evaluations should be skipped).
    fn is_open(&self, rule_id: &str) -> bool;

    /// Get the current circuit state for a rule.
    fn get_state(&self, rule_id: &str) -> CircuitState;

    /// Get detailed health status for a rule.
    fn get_health_status(&self, rule_id: &str) -> Option<RuleHealthStatus>;
}

/// Internal state of the sliding-window circuit breaker for a single rule.
#[derive(Debug)]
struct RuleCircuitState {
    /// Current phase of the circuit breaker.
    phase: RwLock<CircuitPhase>,
    /// Total successful evaluations (atomic, not windowed).
    success_count: AtomicU64,
    /// Total failures (atomic, not windowed).
    failure_count: AtomicU64,
    /// Total timeouts (atomic, not windowed).
    timeout_count: AtomicU64,
    /// Total OOM events (atomic, not windowed).
    oom_count: AtomicU64,
    /// Timestamps of recent failures within the sliding window.
    failure_window: RwLock<VecDeque<Instant>>,
    /// Timestamp of the last failure (any kind).
    last_failure: RwLock<Option<Instant>>,
}

impl RuleCircuitState {
    fn new() -> Self {
        Self {
            phase: RwLock::new(CircuitPhase::Closed),
            success_count: AtomicU64::new(0),
            failure_count: AtomicU64::new(0),
            timeout_count: AtomicU64::new(0),
            oom_count: AtomicU64::new(0),
            failure_window: RwLock::new(VecDeque::new()),
            last_failure: RwLock::new(None),
        }
    }
}

impl Default for RuleCircuitState {
    fn default() -> Self {
        Self::new()
    }
}

/// Phase of the circuit breaker state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitPhase {
    /// Normal operation - requests pass through.
    Closed,
    /// Failure threshold exceeded - requests are blocked until `until`.
    Open { until: Instant },
    /// Probing - allowing a single request to test recovery.
    HalfOpen,
}

/// Configuration for the sliding-window circuit breaker.
#[derive(Debug, Clone, Copy)]
pub struct CircuitBreakerConfig {
    /// Number of failures within the window before opening the circuit.
    pub failure_threshold: u64,
    /// Duration over which failures are counted.
    pub window_duration: Duration,
    /// Duration to keep the circuit open before attempting recovery.
    pub cooldown_duration: Duration,
    /// Failure rate (0.0-1.0) at which to report `Degraded` while Closed.
    pub degraded_threshold: f32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            window_duration: Duration::from_secs(60),
            cooldown_duration: Duration::from_secs(30),
            degraded_threshold: 0.2,
        }
    }
}

/// Sliding-window circuit breaker implementation.
///
/// Tracks failures in a per-rule sliding time window and transitions
/// between `Closed`, `Open`, and `HalfOpen` states.  All operations are
/// `Send + Sync` using `parking_lot` locks and atomic counters.
#[derive(Debug)]
pub struct SlidingWindowCircuitBreaker {
    config: CircuitBreakerConfig,
    states: Arc<RwLock<AHashMap<String, Arc<RuleCircuitState>>>>,
}

impl SlidingWindowCircuitBreaker {
    /// Create a new circuit breaker with the given configuration.
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            states: Arc::new(RwLock::new(AHashMap::new())),
        }
    }

    /// Ensure a state entry exists for a rule and return it.
    fn get_or_create_state(&self, rule_id: &str) -> Arc<RuleCircuitState> {
        let states = self.states.read();
        if let Some(state) = states.get(rule_id) {
            return state.clone();
        }
        drop(states);

        let mut states = self.states.write();
        states
            .entry(rule_id.to_string())
            .or_insert_with(|| Arc::new(RuleCircuitState::new()))
            .clone()
    }

    /// Clean stale failures outside the window and count current failures.
    fn prune_and_count(&self, state: &RuleCircuitState) -> u64 {
        let mut window = state.failure_window.write();
        let now = Instant::now();
        let cutoff = now - self.config.window_duration;

        while let Some(front) = window.front() {
            if *front < cutoff {
                window.pop_front();
            } else {
                break;
            }
        }

        window.len() as u64
    }

    /// Transition to Open if threshold exceeded.
    fn maybe_trip(&self, state: &RuleCircuitState, failure_count: u64) {
        if failure_count >= self.config.failure_threshold {
            let until = Instant::now() + self.config.cooldown_duration;
            let mut phase = state.phase.write();
            *phase = CircuitPhase::Open { until };
        }
    }

    /// Check if an Open circuit should transition to HalfOpen.
    fn maybe_attempt_reset(&self, state: &RuleCircuitState) {
        let mut phase = state.phase.write();
        if let CircuitPhase::Open { until } = *phase {
            if Instant::now() >= until {
                *phase = CircuitPhase::HalfOpen;
            }
        }
    }

    /// Compute the failure rate within the window.
    fn failure_rate(&self, state: &RuleCircuitState) -> f32 {
        let failures = self.prune_and_count(state);
        let successes = state.success_count.load(Ordering::Relaxed);
        let total = successes + failures;
        if total == 0 {
            0.0
        } else {
            failures as f32 / total as f32
        }
    }
}

impl CircuitBreaker for SlidingWindowCircuitBreaker {
    fn record_success(&self, rule_id: &str) {
        let state = self.get_or_create_state(rule_id);
        state.success_count.fetch_add(1, Ordering::Relaxed);

        let mut phase = state.phase.write();
        if matches!(*phase, CircuitPhase::HalfOpen) {
            // Recovery confirmed - close the circuit.
            *phase = CircuitPhase::Closed;
            // Clear failure window on recovery.
            drop(phase);
            state.failure_window.write().clear();
        }
    }

    fn record_failure(&self, rule_id: &str, _error: &str) {
        let state = self.get_or_create_state(rule_id);
        state.failure_count.fetch_add(1, Ordering::Relaxed);
        *state.last_failure.write() = Some(Instant::now());
        state.failure_window.write().push_back(Instant::now());

        let count = self.prune_and_count(&state);
        self.maybe_trip(&state, count);
    }

    fn record_timeout(&self, rule_id: &str) {
        let state = self.get_or_create_state(rule_id);
        state.timeout_count.fetch_add(1, Ordering::Relaxed);
        *state.last_failure.write() = Some(Instant::now());
        state.failure_window.write().push_back(Instant::now());

        let count = self.prune_and_count(&state);
        self.maybe_trip(&state, count);
    }

    fn record_oom(&self, rule_id: &str) {
        let state = self.get_or_create_state(rule_id);
        state.oom_count.fetch_add(1, Ordering::Relaxed);
        *state.last_failure.write() = Some(Instant::now());
        state.failure_window.write().push_back(Instant::now());

        let count = self.prune_and_count(&state);
        self.maybe_trip(&state, count);
    }

    fn is_open(&self, rule_id: &str) -> bool {
        let state = match self.states.read().get(rule_id).cloned() {
            Some(s) => s,
            None => return false,
        };

        self.maybe_attempt_reset(&state);

        let phase = state.phase.read();
        matches!(*phase, CircuitPhase::Open { .. })
    }

    fn get_state(&self, rule_id: &str) -> CircuitState {
        let state = match self.states.read().get(rule_id).cloned() {
            Some(s) => s,
            None => return CircuitState::Healthy,
        };

        self.maybe_attempt_reset(&state);

        let phase = *state.phase.read();
        match phase {
            CircuitPhase::Open { .. } => {
                CircuitState::Disabled("circuit open: too many failures".to_string())
            },
            CircuitPhase::HalfOpen => CircuitState::Degraded(1.0),
            CircuitPhase::Closed => {
                let rate = self.failure_rate(&state);
                if rate >= self.config.degraded_threshold {
                    CircuitState::Degraded(rate)
                } else {
                    CircuitState::Healthy
                }
            },
        }
    }

    fn get_health_status(&self, rule_id: &str) -> Option<RuleHealthStatus> {
        let state = self.states.read().get(rule_id).cloned()?;
        let failure_count = self.prune_and_count(&state);
        let last_failure = *state.last_failure.read();

        Some(RuleHealthStatus {
            rule_id: rule_id.to_string(),
            state: self.get_state(rule_id),
            last_failure,
            failure_count,
        })
    }
}

/// No-op circuit breaker that never trips.
#[derive(Debug, Clone, Default)]
pub struct NoOpCircuitBreaker;

impl CircuitBreaker for NoOpCircuitBreaker {
    fn record_success(&self, _rule_id: &str) {}

    fn record_failure(&self, _rule_id: &str, _error: &str) {}

    fn record_timeout(&self, _rule_id: &str) {}

    fn record_oom(&self, _rule_id: &str) {}

    fn is_open(&self, _rule_id: &str) -> bool {
        false
    }

    fn get_state(&self, _rule_id: &str) -> CircuitState {
        CircuitState::Healthy
    }

    fn get_health_status(&self, _rule_id: &str) -> Option<RuleHealthStatus> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_state_equality() {
        assert_eq!(CircuitState::Healthy, CircuitState::Healthy);
        assert_ne!(CircuitState::Healthy, CircuitState::Degraded(0.5));
        assert_eq!(
            CircuitState::Disabled("x".to_string()),
            CircuitState::Disabled("x".to_string())
        );
    }

    #[test]
    fn test_noop_circuit_breaker() {
        let cb = NoOpCircuitBreaker;
        cb.record_failure("r1", "oops");
        cb.record_timeout("r1");
        cb.record_oom("r1");
        assert!(!cb.is_open("r1"));
        assert_eq!(cb.get_state("r1"), CircuitState::Healthy);
        assert!(cb.get_health_status("r1").is_none());
    }

    #[test]
    fn test_sliding_window_starts_closed() {
        let cb = SlidingWindowCircuitBreaker::new(CircuitBreakerConfig::default());
        assert!(!cb.is_open("r1"));
        assert_eq!(cb.get_state("r1"), CircuitState::Healthy);
    }

    #[test]
    fn test_sliding_window_opens_after_threshold() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            window_duration: Duration::from_secs(60),
            cooldown_duration: Duration::from_secs(30),
            degraded_threshold: 0.2,
        };
        let cb = SlidingWindowCircuitBreaker::new(config);

        cb.record_failure("r1", "err1");
        assert!(!cb.is_open("r1"));

        cb.record_failure("r1", "err2");
        assert!(!cb.is_open("r1"));

        cb.record_failure("r1", "err3");
        assert!(cb.is_open("r1"));

        assert_eq!(
            cb.get_state("r1"),
            CircuitState::Disabled("circuit open: too many failures".to_string())
        );
    }

    #[test]
    fn test_sliding_window_timeout_triggers() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            window_duration: Duration::from_secs(60),
            cooldown_duration: Duration::from_secs(30),
            degraded_threshold: 0.2,
        };
        let cb = SlidingWindowCircuitBreaker::new(config);

        cb.record_timeout("r1");
        cb.record_timeout("r1");

        assert!(cb.is_open("r1"));
    }

    #[test]
    fn test_sliding_window_oom_triggers() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            window_duration: Duration::from_secs(60),
            cooldown_duration: Duration::from_secs(30),
            degraded_threshold: 0.2,
        };
        let cb = SlidingWindowCircuitBreaker::new(config);

        cb.record_oom("r1");
        assert!(cb.is_open("r1"));
    }

    #[test]
    fn test_sliding_window_closes_on_success() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            window_duration: Duration::from_secs(60),
            cooldown_duration: Duration::from_secs(30),
            degraded_threshold: 0.2,
        };
        let cb = SlidingWindowCircuitBreaker::new(config);

        // Trip the circuit.
        cb.record_failure("r1", "err1");
        cb.record_failure("r1", "err2");
        assert!(cb.is_open("r1"));

        // Simulate cooldown passing by manually forcing HalfOpen.
        // In practice we'd wait, but for unit tests we can manipulate
        // via success while the internal state is Open with a past deadline.
        // Instead, we'll just directly check that success in HalfOpen closes.
        {
            let state = cb.get_or_create_state("r1");
            *state.phase.write() = CircuitPhase::HalfOpen;
        }

        cb.record_success("r1");
        assert!(!cb.is_open("r1"));
        assert_eq!(cb.get_state("r1"), CircuitState::Healthy);
    }

    #[test]
    fn test_sliding_window_degraded_state() {
        let config = CircuitBreakerConfig {
            failure_threshold: 10,
            window_duration: Duration::from_secs(60),
            cooldown_duration: Duration::from_secs(30),
            degraded_threshold: 0.25,
        };
        let cb = SlidingWindowCircuitBreaker::new(config);

        // 1 success + 1 failure = 50% failure rate > 25% threshold.
        cb.record_success("r1");
        cb.record_failure("r1", "err");

        assert_eq!(cb.get_state("r1"), CircuitState::Degraded(0.5));
    }

    #[test]
    fn test_sliding_window_prunes_old_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            window_duration: Duration::from_millis(50),
            cooldown_duration: Duration::from_millis(50),
            degraded_threshold: 0.2,
        };
        let cb = SlidingWindowCircuitBreaker::new(config);

        cb.record_failure("r1", "err1");
        cb.record_failure("r1", "err2");
        assert!(cb.is_open("r1"));

        // Wait for both window and cooldown to expire.
        std::thread::sleep(Duration::from_millis(100));

        // After pruning, failures are gone and cooldown has elapsed,
        // so the circuit transitions to HalfOpen (not Open).
        assert!(!cb.is_open("r1"));

        // A success in HalfOpen should close the circuit.
        cb.record_success("r1");
        assert_eq!(cb.get_state("r1"), CircuitState::Healthy);
    }

    #[test]
    fn test_health_status() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            window_duration: Duration::from_secs(60),
            cooldown_duration: Duration::from_secs(30),
            degraded_threshold: 0.2,
        };
        let cb = SlidingWindowCircuitBreaker::new(config);

        let status = cb.get_health_status("r1");
        assert!(status.is_none());

        cb.record_failure("r1", "err");
        let status = cb.get_health_status("r1").unwrap();
        assert_eq!(status.rule_id, "r1");
        assert_eq!(status.failure_count, 1);
        assert!(status.last_failure.is_some());
        assert_eq!(status.state, CircuitState::Degraded(1.0));
    }

    #[test]
    fn test_concurrent_access() {
        use std::thread;

        let config = CircuitBreakerConfig {
            failure_threshold: 1000,
            window_duration: Duration::from_secs(60),
            cooldown_duration: Duration::from_secs(30),
            degraded_threshold: 0.9,
        };
        let cb = Arc::new(SlidingWindowCircuitBreaker::new(config));

        let mut handles = Vec::new();

        // Spawn threads that record successes.
        for _ in 0..4 {
            let cb = cb.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    cb.record_success("r1");
                }
            }));
        }

        // Spawn threads that record failures.
        for _ in 0..4 {
            let cb = cb.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..25 {
                    cb.record_failure("r1", "err");
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let status = cb.get_health_status("r1").unwrap();
        // 400 successes, 100 failures.
        assert_eq!(status.failure_count, 100);
        assert!(!cb.is_open("r1"));
    }

    #[test]
    fn test_halfopen_allows_probe() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            window_duration: Duration::from_secs(60),
            cooldown_duration: Duration::from_millis(10),
            degraded_threshold: 0.2,
        };
        let cb = SlidingWindowCircuitBreaker::new(config);

        cb.record_failure("r1", "err");
        assert!(cb.is_open("r1"));

        // Wait for cooldown to elapse so circuit becomes HalfOpen.
        std::thread::sleep(Duration::from_millis(50));
        assert!(!cb.is_open("r1"));

        // In HalfOpen, another failure should immediately reopen.
        cb.record_failure("r1", "err2");
        assert!(cb.is_open("r1"));
    }
}
