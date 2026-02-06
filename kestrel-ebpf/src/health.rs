//! eBPF Health Checker
//!
//! Provides health monitoring and automatic recovery for eBPF components.
//! Detects ring buffer issues and triggers fallback to alternative event sources.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Health status of the eBPF subsystem
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfHealthStatus {
    /// Healthy - events are flowing normally
    Healthy,
    /// Degraded - some events may be dropped
    Degraded,
    /// Unhealthy - ring buffer not accessible
    Unhealthy,
    /// Fallback mode - using fanotify or other alternative
    Fallback,
}

impl std::fmt::Display for EbpfHealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EbpfHealthStatus::Healthy => write!(f, "healthy"),
            EbpfHealthStatus::Degraded => write!(f, "degraded"),
            EbpfHealthStatus::Unhealthy => write!(f, "unhealthy"),
            EbpfHealthStatus::Fallback => write!(f, "fallback"),
        }
    }
}

/// Health check configuration
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    /// Interval between health checks
    pub check_interval: Duration,
    /// Maximum time without events before considered unhealthy
    pub max_event_gap: Duration,
    /// Number of consecutive failures before triggering fallback
    pub failure_threshold: usize,
    /// Enable automatic recovery attempts
    pub auto_recover: bool,
    /// Recovery backoff interval
    pub recovery_interval: Duration,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(5),
            max_event_gap: Duration::from_secs(30),
            failure_threshold: 3,
            auto_recover: true,
            recovery_interval: Duration::from_secs(10),
        }
    }
}

/// Health metrics for monitoring
#[derive(Debug, Default)]
pub struct HealthMetrics {
    /// Total events received
    pub events_received: AtomicU64,
    /// Total events dropped
    pub events_dropped: AtomicU64,
    /// Consecutive failures
    pub consecutive_failures: AtomicUsize,
    /// Last event timestamp
    pub last_event_time: AtomicU64,
    /// Health check runs
    pub check_runs: AtomicU64,
}

impl HealthMetrics {
    /// Record an event received
    pub fn record_event(&self) {
        self.events_received.fetch_add(1, Ordering::Relaxed);
        self.last_event_time.store(
            Instant::now().elapsed().as_secs(),
            Ordering::Relaxed,
        );
        // Reset consecutive failures on success
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }

    /// Record an event dropped
    pub fn record_dropped(&self) {
        self.events_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failure
    pub fn record_failure(&self) {
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Get snapshot of metrics
    pub fn snapshot(&self) -> HealthMetricsSnapshot {
        HealthMetricsSnapshot {
            events_received: self.events_received.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            consecutive_failures: self.consecutive_failures.load(Ordering::Relaxed),
            last_event_time: self.last_event_time.load(Ordering::Relaxed),
            check_runs: self.check_runs.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of health metrics
#[derive(Debug, Clone)]
pub struct HealthMetricsSnapshot {
    pub events_received: u64,
    pub events_dropped: u64,
    pub consecutive_failures: usize,
    pub last_event_time: u64,
    pub check_runs: u64,
}

/// eBPF Health Checker
///
/// Monitors the health of eBPF components and triggers recovery actions.
pub struct EbpfHealthChecker {
    config: HealthCheckConfig,
    metrics: Arc<HealthMetrics>,
    status_tx: watch::Sender<EbpfHealthStatus>,
    status_rx: watch::Receiver<EbpfHealthStatus>,
}

impl EbpfHealthChecker {
    /// Create a new health checker
    pub fn new(config: HealthCheckConfig) -> Self {
        let (status_tx, status_rx) = watch::channel(EbpfHealthStatus::Healthy);
        
        Self {
            config,
            metrics: Arc::new(HealthMetrics::default()),
            status_tx,
            status_rx,
        }
    }

    /// Get the metrics reference
    pub fn metrics(&self) -> &Arc<HealthMetrics> {
        &self.metrics
    }

    /// Get current health status
    pub fn status(&self) -> EbpfHealthStatus {
        *self.status_rx.borrow()
    }

    /// Subscribe to health status changes
    pub fn subscribe(&self) -> watch::Receiver<EbpfHealthStatus> {
        self.status_rx.clone()
    }

    /// Start the health check loop
    ///
    /// This spawns a background task that continuously monitors health
    /// and triggers recovery actions when needed.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let config = self.config.clone();
        let metrics = self.metrics.clone();
        let status_tx = self.status_tx.clone();

        tokio::spawn(async move {
            info!("eBPF health checker started");
            
            let mut last_check = Instant::now();
            let mut recovery_attempts = 0;

            loop {
                tokio::time::sleep(config.check_interval).await;

                let metrics_snapshot = metrics.snapshot();
                metrics.check_runs.fetch_add(1, Ordering::Relaxed);

                // Determine health status
                let new_status = Self::evaluate_health(&config, &metrics_snapshot, last_check);
                let current_status = *status_tx.borrow();

                if new_status != current_status {
                    warn!(
                        old_status = %current_status,
                        new_status = %new_status,
                        consecutive_failures = metrics_snapshot.consecutive_failures,
                        "eBPF health status changed"
                    );

                    // Update status
                    let _ = status_tx.send(new_status);

                    // Trigger recovery if needed
                    if new_status == EbpfHealthStatus::Unhealthy 
                        && config.auto_recover 
                        && recovery_attempts < 3 
                    {
                        recovery_attempts += 1;
                        warn!(
                            attempt = recovery_attempts,
                            "Attempting eBPF recovery"
                        );
                        // Recovery action will be triggered by collector
                    }
                }

                // Reset recovery attempts if healthy
                if new_status == EbpfHealthStatus::Healthy {
                    recovery_attempts = 0;
                }

                last_check = Instant::now();
            }
        })
    }

    /// Evaluate current health status
    fn evaluate_health(
        config: &HealthCheckConfig,
        metrics: &HealthMetricsSnapshot,
        last_check: Instant,
    ) -> EbpfHealthStatus {
        // Check for consecutive failures
        if metrics.consecutive_failures >= config.failure_threshold {
            return EbpfHealthStatus::Unhealthy;
        }

        // Check event flow
        let time_since_last_event = Instant::now().duration_since(last_check);
        
        if metrics.events_received == 0 && time_since_last_event > config.max_event_gap {
            // No events received for a while - might be unhealthy
            if metrics.consecutive_failures > 0 {
                return EbpfHealthStatus::Degraded;
            }
        }

        // Check drop rate
        let total_events = metrics.events_received + metrics.events_dropped;
        if total_events > 100 {
            let drop_rate = metrics.events_dropped as f64 / total_events as f64;
            if drop_rate > 0.1 {
                // More than 10% drop rate
                return EbpfHealthStatus::Degraded;
            }
        }

        EbpfHealthStatus::Healthy
    }

    /// Manually trigger recovery
    pub async fn trigger_recovery(&self) -> Result<(), HealthCheckError> {
        info!("Manual recovery triggered");
        let _ = self.status_tx.send(EbpfHealthStatus::Healthy);
        Ok(())
    }

    /// Stop the health checker
    pub fn stop(&self) {
        // The background task will be cancelled when the handle is dropped
        debug!("eBPF health checker stopped");
    }
}

/// Health check errors
#[derive(Debug, thiserror::Error)]
pub enum HealthCheckError {
    #[error("Health check already running")]
    AlreadyRunning,

    #[error("Failed to update status: {0}")]
    StatusUpdateFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_display() {
        assert_eq!(EbpfHealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(EbpfHealthStatus::Degraded.to_string(), "degraded");
        assert_eq!(EbpfHealthStatus::Unhealthy.to_string(), "unhealthy");
        assert_eq!(EbpfHealthStatus::Fallback.to_string(), "fallback");
    }

    #[test]
    fn test_health_metrics() {
        let metrics = HealthMetrics::default();
        
        metrics.record_event();
        assert_eq!(metrics.events_received.load(Ordering::Relaxed), 1);
        
        metrics.record_dropped();
        assert_eq!(metrics.events_dropped.load(Ordering::Relaxed), 1);
        
        metrics.record_failure();
        assert_eq!(metrics.consecutive_failures.load(Ordering::Relaxed), 1);
        
        // Recording event should reset failures
        metrics.record_event();
        assert_eq!(metrics.consecutive_failures.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_health_checker_new() {
        let config = HealthCheckConfig::default();
        let checker = EbpfHealthChecker::new(config);
        
        assert_eq!(checker.status(), EbpfHealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_health_subscription() {
        let config = HealthCheckConfig::default();
        let checker = EbpfHealthChecker::new(config);
        
        let mut rx = checker.subscribe();
        assert_eq!(*rx.borrow(), EbpfHealthStatus::Healthy);
    }
}
