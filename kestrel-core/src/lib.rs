//! Kestrel Core
//!
//! Core functionality including EventBus and control plane components.

pub mod action;
pub mod alert;
pub mod eventbus;
pub mod replay;
pub mod time;

use std::time::Duration;

pub use action::{
    ActionCapabilities, ActionDecision, ActionError, ActionEvidence, ActionExecutor, ActionResult,
    ActionTarget, ActionType, NoOpExecutor,
};
pub use alert::{Alert, AlertHandle, AlertOutput, AlertOutputConfig, EventEvidence, Severity};
/// Re-export common types
pub use eventbus::{EventBus, EventBusConfig, EventBusHandle};
pub use replay::{BinaryLog, ReplayConfig, ReplayError, ReplaySource, ReplayStats};
pub use time::{MockTimeProvider, RealTimeProvider, TimeManager, TimeProvider};

/// Configuration for backpressure handling
#[derive(Debug, Clone)]
pub struct BackpressureConfig {
    /// Maximum events in queue before applying backpressure
    pub queue_depth: usize,

    /// Timeout when waiting for backpressure to clear
    pub backpressure_timeout: Duration,

    /// Whether to drop events when queue is full (or block)
    pub drop_on_full: bool,
}

impl Default for BackpressureConfig {
    fn default() -> Self {
        Self {
            queue_depth: 10000,
            backpressure_timeout: Duration::from_secs(5),
            drop_on_full: false,
        }
    }
}

/// Metrics for monitoring
#[derive(Debug, Default)]
pub struct Metrics {
    pub events_received: u64,
    pub events_processed: u64,
    pub events_dropped: u64,
    pub backpressure_count: u64,
}
