//! Resource Budgeting for Rule Evaluation
//!
//! Provides per-rule budget tracking to prevent runaway rules from
//! consuming excessive CPU, memory, or time.

use ahash::AHashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Budget constraints for a single rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleBudget {
    /// Maximum CPU fuel (Wasm instruction count) per evaluation.
    pub max_cpu_fuel: u64,
    /// Maximum memory in megabytes per evaluation.
    pub max_memory_mb: usize,
    /// Maximum evaluation time in milliseconds.
    pub max_eval_time_ms: u64,
    /// Maximum evaluations per second (rate limit).
    pub max_evaluations_per_sec: u64,
}

impl Default for RuleBudget {
    fn default() -> Self {
        Self {
            max_cpu_fuel: 10_000_000, // 10M instructions
            max_memory_mb: 128,
            max_eval_time_ms: 100,
            max_evaluations_per_sec: 10_000,
        }
    }
}

/// Result of a budget check.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BudgetStatus {
    /// Consumption is well within limits.
    WithinBudget,
    /// Consumption is approaching a limit (0.0 - 1.0 ratio).
    NearLimit(f32),
    /// A budget limit has been exceeded.
    Exceeded,
}

impl BudgetStatus {
    /// Returns true if the budget has been exceeded.
    pub fn is_exceeded(&self) -> bool {
        matches!(self, BudgetStatus::Exceeded)
    }

    /// Returns true if the budget is within acceptable limits.
    pub fn is_ok(&self) -> bool {
        !self.is_exceeded()
    }
}

/// Per-rule consumption snapshot.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleConsumption {
    /// CPU fuel consumed (instructions).
    pub cpu_fuel: u64,
    /// Memory consumed in bytes.
    pub memory_bytes: usize,
    /// Evaluation time.
    pub eval_time: Duration,
    /// Number of evaluations in the current second.
    pub evaluations_this_sec: u64,
}

/// Tracks per-rule resource consumption against configured budgets.
///
/// `BudgetTracker` is thread-safe (`Send + Sync`) and designed for
/// concurrent use across the detection engine and NFA engine.
#[derive(Debug, Clone)]
pub struct BudgetTracker {
    budgets: Arc<RwLock<AHashMap<String, RuleBudget>>>,
    consumption: Arc<RwLock<AHashMap<String, RuleConsumptionState>>>,
}

/// Internal mutable state for a rule's consumption.
#[derive(Debug)]
struct RuleConsumptionState {
    /// Atomic counter for total CPU fuel consumed.
    cpu_fuel: AtomicU64,
    /// Atomic counter for peak memory observed (bytes).
    memory_bytes: AtomicU64,
    /// Atomic counter for evaluations in the current second.
    evaluations_this_sec: AtomicU64,
    /// Timestamp of the last evaluation (for rate limiting).
    last_eval_time: RwLock<Instant>,
    /// Timestamp when the current second started (for rate limiting).
    current_sec_start: RwLock<Instant>,
}

impl RuleConsumptionState {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            cpu_fuel: AtomicU64::new(0),
            memory_bytes: AtomicU64::new(0),
            evaluations_this_sec: AtomicU64::new(0),
            last_eval_time: RwLock::new(now),
            current_sec_start: RwLock::new(now),
        }
    }
}

impl Default for RuleConsumptionState {
    fn default() -> Self {
        Self::new()
    }
}

impl BudgetTracker {
    /// Create a new `BudgetTracker` with no configured budgets.
    pub fn new() -> Self {
        Self {
            budgets: Arc::new(RwLock::new(AHashMap::new())),
            consumption: Arc::new(RwLock::new(AHashMap::new())),
        }
    }

    /// Register a budget for a specific rule.
    pub fn set_budget(&self, rule_id: impl Into<String>, budget: RuleBudget) {
        let id = rule_id.into();
        let mut budgets = self.budgets.write();
        budgets.insert(id.clone(), budget);

        // Ensure consumption state exists.
        let mut consumption = self.consumption.write();
        consumption.entry(id).or_default();
    }

    /// Remove a rule's budget and consumption tracking.
    pub fn remove_rule(&self, rule_id: &str) {
        let mut budgets = self.budgets.write();
        budgets.remove(rule_id);
        let mut consumption = self.consumption.write();
        consumption.remove(rule_id);
    }

    /// Record consumption for a rule and return the current budget status.
    ///
    /// This is the primary entry-point used by `DetectionEngine` and
    /// `NfaEngine` after each evaluation.
    pub fn check_budget(&self, rule_id: &str, consumption: RuleConsumption) -> BudgetStatus {
        let budgets = self.budgets.read();
        let budget = match budgets.get(rule_id) {
            Some(b) => *b,
            None => return BudgetStatus::WithinBudget,
        };
        drop(budgets);

        let states = self.consumption.read();
        let state = match states.get(rule_id) {
            Some(s) => s,
            None => return BudgetStatus::WithinBudget,
        };

        // Update atomic counters.
        state
            .cpu_fuel
            .fetch_add(consumption.cpu_fuel, Ordering::Relaxed);
        let prev_mem = state
            .memory_bytes
            .fetch_max(consumption.memory_bytes as u64, Ordering::Relaxed);
        let peak_mem = prev_mem.max(consumption.memory_bytes as u64);

        // Update rate limit window.
        {
            let mut sec_start = state.current_sec_start.write();
            let mut last_eval = state.last_eval_time.write();
            let now = Instant::now();
            *last_eval = now;

            if now.duration_since(*sec_start) >= Duration::from_secs(1) {
                // Rolled over to a new second.
                *sec_start = now;
                state.evaluations_this_sec.store(1, Ordering::Relaxed);
            } else {
                state.evaluations_this_sec.fetch_add(1, Ordering::Relaxed);
            }
        }

        let total_cpu = state.cpu_fuel.load(Ordering::Relaxed);
        let evals_this_sec = state.evaluations_this_sec.load(Ordering::Relaxed);

        // Check hard limits first.
        if consumption.cpu_fuel > budget.max_cpu_fuel {
            return BudgetStatus::Exceeded;
        }
        let max_memory_bytes = budget
            .max_memory_mb
            .saturating_mul(1024)
            .saturating_mul(1024);
        if consumption.memory_bytes > max_memory_bytes {
            return BudgetStatus::Exceeded;
        }
        if consumption.eval_time.as_millis() as u64 > budget.max_eval_time_ms {
            return BudgetStatus::Exceeded;
        }
        if evals_this_sec > budget.max_evaluations_per_sec {
            return BudgetStatus::Exceeded;
        }

        // Compute the highest utilization ratio.
        let cpu_ratio = total_cpu as f32 / budget.max_cpu_fuel.max(1) as f32;
        let mem_ratio = peak_mem as f32
            / (budget.max_memory_mb as u64)
                .saturating_mul(1024)
                .saturating_mul(1024)
                .max(1) as f32;
        let time_ratio =
            consumption.eval_time.as_millis() as f32 / budget.max_eval_time_ms.max(1) as f32;
        let rate_ratio = evals_this_sec as f32 / budget.max_evaluations_per_sec.max(1) as f32;

        let max_ratio = cpu_ratio.max(mem_ratio).max(time_ratio).max(rate_ratio);

        if max_ratio > 1.0 {
            BudgetStatus::Exceeded
        } else if max_ratio >= 0.8 {
            BudgetStatus::NearLimit(max_ratio)
        } else {
            BudgetStatus::WithinBudget
        }
    }

    /// Get the current consumption snapshot for a rule.
    pub fn get_consumption(&self, rule_id: &str) -> Option<RuleConsumption> {
        let states = self.consumption.read();
        let state = states.get(rule_id)?;

        Some(RuleConsumption {
            cpu_fuel: state.cpu_fuel.load(Ordering::Relaxed),
            memory_bytes: state.memory_bytes.load(Ordering::Relaxed) as usize,
            eval_time: Duration::default(),
            evaluations_this_sec: state.evaluations_this_sec.load(Ordering::Relaxed),
        })
    }

    /// Reset all consumption counters for a rule.
    pub fn reset(&self, rule_id: &str) {
        let states = self.consumption.read();
        if let Some(state) = states.get(rule_id) {
            state.cpu_fuel.store(0, Ordering::Relaxed);
            state.memory_bytes.store(0, Ordering::Relaxed);
            state.evaluations_this_sec.store(0, Ordering::Relaxed);
            *state.last_eval_time.write() = Instant::now();
            *state.current_sec_start.write() = Instant::now();
        }
    }

    /// Reset all tracked consumption.
    pub fn reset_all(&self) {
        let states = self.consumption.read();
        for (_id, state) in states.iter() {
            state.cpu_fuel.store(0, Ordering::Relaxed);
            state.memory_bytes.store(0, Ordering::Relaxed);
            state.evaluations_this_sec.store(0, Ordering::Relaxed);
            *state.last_eval_time.write() = Instant::now();
            *state.current_sec_start.write() = Instant::now();
        }
    }
}

impl Default for BudgetTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_budget_default() {
        let budget = RuleBudget::default();
        assert_eq!(budget.max_cpu_fuel, 10_000_000);
        assert_eq!(budget.max_memory_mb, 128);
        assert_eq!(budget.max_eval_time_ms, 100);
        assert_eq!(budget.max_evaluations_per_sec, 10_000);
    }

    #[test]
    fn test_budget_status_helpers() {
        assert!(BudgetStatus::WithinBudget.is_ok());
        assert!(!BudgetStatus::WithinBudget.is_exceeded());
        assert!(BudgetStatus::NearLimit(0.85).is_ok());
        assert!(BudgetStatus::Exceeded.is_exceeded());
        assert!(!BudgetStatus::Exceeded.is_ok());
    }

    #[test]
    fn test_budget_tracker_no_budget() {
        let tracker = BudgetTracker::new();
        let consumption = RuleConsumption {
            cpu_fuel: 1_000_000_000,
            memory_bytes: 1024 * 1024 * 1024,
            eval_time: Duration::from_secs(10),
            evaluations_this_sec: 100_000,
        };
        // No budget configured -> always WithinBudget.
        assert_eq!(tracker.check_budget("rule-1", consumption), BudgetStatus::WithinBudget);
    }

    #[test]
    fn test_budget_tracker_within_budget() {
        let tracker = BudgetTracker::new();
        tracker.set_budget(
            "rule-1",
            RuleBudget {
                max_cpu_fuel: 1_000_000,
                max_memory_mb: 64,
                max_eval_time_ms: 50,
                max_evaluations_per_sec: 100,
            },
        );

        let consumption = RuleConsumption {
            cpu_fuel: 100_000,
            memory_bytes: 1024 * 1024,
            eval_time: Duration::from_millis(10),
            evaluations_this_sec: 1,
        };

        assert_eq!(tracker.check_budget("rule-1", consumption), BudgetStatus::WithinBudget);
    }

    #[test]
    fn test_budget_tracker_cpu_exceeded() {
        let tracker = BudgetTracker::new();
        tracker.set_budget(
            "rule-1",
            RuleBudget {
                max_cpu_fuel: 1_000,
                max_memory_mb: 64,
                max_eval_time_ms: 50,
                max_evaluations_per_sec: 100,
            },
        );

        let consumption = RuleConsumption {
            cpu_fuel: 2_000,
            memory_bytes: 1024,
            eval_time: Duration::from_millis(1),
            evaluations_this_sec: 1,
        };

        assert_eq!(tracker.check_budget("rule-1", consumption), BudgetStatus::Exceeded);
    }

    #[test]
    fn test_budget_tracker_memory_exceeded() {
        let tracker = BudgetTracker::new();
        tracker.set_budget(
            "rule-1",
            RuleBudget {
                max_cpu_fuel: 1_000_000,
                max_memory_mb: 1,
                max_eval_time_ms: 50,
                max_evaluations_per_sec: 100,
            },
        );

        let consumption = RuleConsumption {
            cpu_fuel: 100,
            memory_bytes: 2 * 1024 * 1024, // 2 MB > 1 MB limit
            eval_time: Duration::from_millis(1),
            evaluations_this_sec: 1,
        };

        assert_eq!(tracker.check_budget("rule-1", consumption), BudgetStatus::Exceeded);
    }

    #[test]
    fn test_budget_tracker_time_exceeded() {
        let tracker = BudgetTracker::new();
        tracker.set_budget(
            "rule-1",
            RuleBudget {
                max_cpu_fuel: 1_000_000,
                max_memory_mb: 64,
                max_eval_time_ms: 10,
                max_evaluations_per_sec: 100,
            },
        );

        let consumption = RuleConsumption {
            cpu_fuel: 100,
            memory_bytes: 1024,
            eval_time: Duration::from_millis(20),
            evaluations_this_sec: 1,
        };

        assert_eq!(tracker.check_budget("rule-1", consumption), BudgetStatus::Exceeded);
    }

    #[test]
    fn test_budget_tracker_near_limit() {
        let tracker = BudgetTracker::new();
        tracker.set_budget(
            "rule-1",
            RuleBudget {
                max_cpu_fuel: 1_000,
                max_memory_mb: 1,
                max_eval_time_ms: 10,
                max_evaluations_per_sec: 10,
            },
        );

        // 90% of CPU budget.
        let consumption = RuleConsumption {
            cpu_fuel: 900,
            memory_bytes: 1024,
            eval_time: Duration::from_millis(1),
            evaluations_this_sec: 1,
        };

        assert_eq!(tracker.check_budget("rule-1", consumption), BudgetStatus::NearLimit(0.9));
    }

    #[test]
    fn test_budget_tracker_rate_limit() {
        let tracker = BudgetTracker::new();
        tracker.set_budget(
            "rule-1",
            RuleBudget {
                max_cpu_fuel: 1_000_000,
                max_memory_mb: 64,
                max_eval_time_ms: 50,
                max_evaluations_per_sec: 5,
            },
        );

        // First 5 evaluations are fine.
        for _ in 0..5 {
            let status = tracker.check_budget(
                "rule-1",
                RuleConsumption {
                    cpu_fuel: 100,
                    memory_bytes: 1024,
                    eval_time: Duration::from_millis(1),
                    evaluations_this_sec: 0,
                },
            );
            assert!(!status.is_exceeded());
        }

        // 6th evaluation exceeds rate limit.
        let status = tracker.check_budget(
            "rule-1",
            RuleConsumption {
                cpu_fuel: 100,
                memory_bytes: 1024,
                eval_time: Duration::from_millis(1),
                evaluations_this_sec: 0,
            },
        );
        assert!(status.is_exceeded());
    }

    #[test]
    fn test_budget_tracker_reset() {
        let tracker = BudgetTracker::new();
        tracker.set_budget(
            "rule-1",
            RuleBudget {
                max_cpu_fuel: 1_000,
                max_memory_mb: 64,
                max_eval_time_ms: 50,
                max_evaluations_per_sec: 5,
            },
        );

        // Consume budget.
        let _ = tracker.check_budget(
            "rule-1",
            RuleConsumption {
                cpu_fuel: 500,
                memory_bytes: 1024 * 1024,
                eval_time: Duration::from_millis(10),
                evaluations_this_sec: 1,
            },
        );

        let before = tracker.get_consumption("rule-1").unwrap();
        assert_eq!(before.cpu_fuel, 500);

        tracker.reset("rule-1");

        let after = tracker.get_consumption("rule-1").unwrap();
        assert_eq!(after.cpu_fuel, 0);
        assert_eq!(after.memory_bytes, 0);
    }

    #[test]
    fn test_budget_tracker_concurrent() {
        use std::thread;

        let tracker = BudgetTracker::new();
        tracker.set_budget(
            "rule-concurrent",
            RuleBudget {
                max_cpu_fuel: u64::MAX,
                max_memory_mb: usize::MAX,
                max_eval_time_ms: u64::MAX,
                max_evaluations_per_sec: u64::MAX,
            },
        );

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let tracker = tracker.clone();
                thread::spawn(move || {
                    for _ in 0..100 {
                        let _ = tracker.check_budget(
                            "rule-concurrent",
                            RuleConsumption {
                                cpu_fuel: 1,
                                memory_bytes: 1,
                                eval_time: Duration::from_millis(1),
                                evaluations_this_sec: 0,
                            },
                        );
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let consumption = tracker.get_consumption("rule-concurrent").unwrap();
        assert_eq!(consumption.cpu_fuel, 1000);
    }
}
