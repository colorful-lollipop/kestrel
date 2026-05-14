//! Pluggable Alert Sink System
//!
//! Provides the `AlertSink` trait for routing alerts to arbitrary destinations,
//! along with built-in `StdoutSink`, `FileSink`, and `AlertRouter` implementations.

use crate::Alert;
use std::sync::Arc;
use thiserror::Error;

/// Status returned by a sink after emitting an alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmitStatus {
    /// The alert was successfully delivered.
    Acknowledged,
    /// The alert was buffered and will be delivered later.
    Buffered,
    /// The alert was dropped with a reason.
    Dropped(String),
}

/// Backpressure level reported by a sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Backpressure {
    /// Operating normally.
    Normal,
    /// Experiencing mild backpressure.
    Elevated,
    /// Critical backpressure; consider shedding load.
    Critical,
}

/// Health snapshot for a single sink.
#[derive(Debug, Clone)]
pub struct SinkHealth {
    /// Whether the sink is currently healthy.
    pub healthy: bool,
    /// Estimated lag in milliseconds.
    pub lag_ms: u64,
    /// Number of consecutive errors.
    pub consecutive_errors: u64,
    /// Number of alerts dropped since start.
    pub alerts_dropped: u64,
    /// Most recent error message, if any.
    pub last_error: Option<String>,
}

impl Default for SinkHealth {
    fn default() -> Self {
        Self {
            healthy: true,
            lag_ms: 0,
            consecutive_errors: 0,
            alerts_dropped: 0,
            last_error: None,
        }
    }
}

/// Errors that can occur when emitting to a sink.
#[derive(Debug, Error)]
pub enum AlertSinkError {
    #[error("Unavailable: {0}")]
    Unavailable(String),
    #[error("Serialization failed: {0}")]
    Serialization(String),
    #[error("Transport failed: {0}")]
    Transport(String),
}

/// Pluggable destination for alerts.
pub trait AlertSink: Send + Sync {
    /// Emit a single alert.
    fn emit(
        &self,
        alert: &Alert,
    ) -> Result<(EmitStatus, Backpressure), AlertSinkError>;

    /// Emit a batch of alerts.
    fn emit_batch(
        &self,
        alerts: &[Alert],
    ) -> Result<(EmitStatus, Backpressure), AlertSinkError> {
        let mut overall = EmitStatus::Acknowledged;
        let mut max_bp = Backpressure::Normal;
        for alert in alerts {
            let (status, bp) = self.emit(alert)?;
            if matches!(status, EmitStatus::Dropped(_)) {
                overall = status;
            }
            max_bp = max_bp.max(bp);
        }
        Ok((overall, max_bp))
    }

    /// Flush any buffered alerts.
    fn flush(&self) -> Result<(), AlertSinkError> {
        Ok(())
    }

    /// Return current health snapshot.
    fn health(&self) -> SinkHealth {
        SinkHealth::default()
    }

    /// Gracefully shut down the sink.
    fn shutdown(&self) -> Result<(), AlertSinkError> {
        self.flush()
    }
}

/// Stdout sink implementation.
pub struct StdoutSink {
    pretty: bool,
}

impl StdoutSink {
    /// Create a new `StdoutSink`.
    pub fn new(pretty: bool) -> Self {
        Self { pretty }
    }
}

impl AlertSink for StdoutSink {
    fn emit(
        &self,
        alert: &Alert,
    ) -> Result<(EmitStatus, Backpressure), AlertSinkError> {
        let json = if self.pretty {
            serde_json::to_string_pretty(alert)
        } else {
            serde_json::to_string(alert)
        }
        .map_err(|e| AlertSinkError::Serialization(e.to_string()))?;

        println!("{}", json);
        Ok((EmitStatus::Acknowledged, Backpressure::Normal))
    }
}

/// File sink implementation.
pub struct FileSink {
    path: std::path::PathBuf,
    file: parking_lot::Mutex<std::fs::File>,
}

impl FileSink {
    /// Return the path this sink writes to.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Create a new `FileSink` appending to `path`.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Result<Self, std::io::Error> {
        let path = path.into();
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self {
            path,
            file: parking_lot::Mutex::new(file),
        })
    }
}

impl AlertSink for FileSink {
    fn emit(
        &self,
        alert: &Alert,
    ) -> Result<(EmitStatus, Backpressure), AlertSinkError> {
        let json = serde_json::to_string(alert)
            .map_err(|e| AlertSinkError::Serialization(e.to_string()))?;

        use std::io::Write;
        let mut file = self.file.lock();
        writeln!(file, "{}", json)
            .map_err(|e| AlertSinkError::Transport(e.to_string()))?;

        Ok((EmitStatus::Acknowledged, Backpressure::Normal))
    }
}

/// Multiplexes alerts to multiple named sinks.
pub struct AlertRouter {
    sinks: Vec<(String, Arc<dyn AlertSink>)>,
}

impl AlertRouter {
    /// Create an empty router.
    pub fn new() -> Self {
        Self { sinks: Vec::new() }
    }

    /// Register a named sink.
    pub fn add_sink(&mut self, name: impl Into<String>, sink: Arc<dyn AlertSink>) {
        self.sinks.push((name.into(), sink));
    }

    /// Emit an alert to every registered sink.
    pub fn emit(&self, alert: &Alert) -> Result<(), AlertSinkError> {
        for (_name, sink) in &self.sinks {
            sink.emit(alert)?;
        }
        Ok(())
    }

    /// Return health for every registered sink.
    pub fn health(&self) -> Vec<(String, SinkHealth)> {
        self.sinks
            .iter()
            .map(|(name, sink)| (name.clone(), sink.health()))
            .collect()
    }
}

impl AlertSink for AlertRouter {
    fn emit(
        &self,
        alert: &Alert,
    ) -> Result<(EmitStatus, Backpressure), AlertSinkError> {
        let mut overall = EmitStatus::Acknowledged;
        let mut max_bp = Backpressure::Normal;
        for (_name, sink) in &self.sinks {
            let (status, bp) = sink.emit(alert)?;
            if matches!(status, EmitStatus::Dropped(_)) {
                overall = status;
            }
            max_bp = max_bp.max(bp);
        }
        Ok((overall, max_bp))
    }

    fn health(&self) -> SinkHealth {
        let mut healthy = true;
        let mut max_lag = 0;
        let mut total_errors = 0;
        let mut total_dropped = 0;
        for (_name, sink) in &self.sinks {
            let h = sink.health();
            healthy &= h.healthy;
            max_lag = max_lag.max(h.lag_ms);
            total_errors += h.consecutive_errors;
            total_dropped += h.alerts_dropped;
        }
        SinkHealth {
            healthy,
            lag_ms: max_lag,
            consecutive_errors: total_errors,
            alerts_dropped: total_dropped,
            last_error: None,
        }
    }

    fn shutdown(&self) -> Result<(), AlertSinkError> {
        for (_name, sink) in &self.sinks {
            sink.shutdown()?;
        }
        Ok(())
    }
}

impl Default for AlertRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_schema::Severity;

    fn test_alert() -> Alert {
        Alert {
            id: "alert-test-001".to_string(),
            rule_id: "rule-test-001".to_string(),
            rule_name: "Test Rule".to_string(),
            severity: Severity::High,
            timestamp_ns: 1234567890,
            title: "Test Alert".to_string(),
            description: Some("A test alert for sinks".to_string()),
            events: vec![],
            context: serde_json::json!({}),
        }
    }

    #[test]
    fn test_stdout_sink_emit() {
        let sink = StdoutSink::new(false);
        let alert = test_alert();
        let (status, bp) = sink.emit(&alert).unwrap();
        assert_eq!(status, EmitStatus::Acknowledged);
        assert_eq!(bp, Backpressure::Normal);
    }

    #[test]
    fn test_file_sink_emit() {
        let tmp_dir = std::env::temp_dir();
        let path = tmp_dir.join("kestrel_alert_sink_test.jsonl");
        // Clean up any stale file.
        let _ = std::fs::remove_file(&path);

        let sink = FileSink::new(&path).unwrap();
        let alert = test_alert();
        let (status, bp) = sink.emit(&alert).unwrap();
        assert_eq!(status, EmitStatus::Acknowledged);
        assert_eq!(bp, Backpressure::Normal);

        // Verify file content.
        let contents = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(parsed["id"], "alert-test-001");
        assert_eq!(parsed["rule_id"], "rule-test-001");

        // Clean up.
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_alert_router_emit() {
        let mut router = AlertRouter::new();
        let sink = Arc::new(StdoutSink::new(false));
        router.add_sink("stdout", sink);

        let alert = test_alert();
        router.emit(&alert).unwrap();

        let health = router.health();
        assert_eq!(health.len(), 1);
        assert_eq!(health[0].0, "stdout");
        assert!(health[0].1.healthy);
    }

    #[test]
    fn test_emit_batch_default_impl() {
        let sink = StdoutSink::new(false);
        let alerts = vec![test_alert(), test_alert()];
        let (status, bp) = sink.emit_batch(&alerts).unwrap();
        assert_eq!(status, EmitStatus::Acknowledged);
        assert_eq!(bp, Backpressure::Normal);
    }

    #[test]
    fn test_sink_health_default() {
        let health = SinkHealth::default();
        assert!(health.healthy);
        assert_eq!(health.lag_ms, 0);
        assert_eq!(health.consecutive_errors, 0);
        assert_eq!(health.alerts_dropped, 0);
        assert_eq!(health.last_error, None);
    }
}
