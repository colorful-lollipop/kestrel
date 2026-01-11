//! Kestrel Core
//!
//! Core functionality including EventBus and control plane components.

use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::{timeout, Duration};
use tracing::{debug, error, warn};

pub mod eventbus;
pub mod alert;
pub mod time;
pub mod replay;

/// Re-export common types
pub use eventbus::{EventBus, EventBusConfig, EventBusHandle};
pub use alert::{Alert, AlertHandle, AlertOutput, AlertOutputConfig, Severity, EventEvidence};
pub use time::{TimeProvider, RealTimeProvider, MockTimeProvider, TimeManager};
pub use replay::{BinaryLog, ReplaySource, ReplayConfig, ReplayError, ReplayStats};

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
