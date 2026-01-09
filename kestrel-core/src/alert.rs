//! Alert System
//!
//! This module handles alert generation and output.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

/// Alert record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Unique alert ID
    pub id: String,

    /// Rule ID that generated this alert
    pub rule_id: String,

    /// Rule name
    pub rule_name: String,

    /// Alert severity
    pub severity: Severity,

    /// Alert timestamp (wall clock)
    pub timestamp_ns: u64,

    /// Alert title/message
    pub title: String,

    /// Alert description
    pub description: Option<String>,

    /// Captured event data (evidence)
    pub events: Vec<EventEvidence>,

    /// Additional context
    pub context: serde_json::Value,
}

/// Alert severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

/// Event evidence captured in an alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEvidence {
    /// Event type ID
    pub event_type_id: u16,

    /// Event timestamp
    pub timestamp_ns: u64,

    /// Captured fields
    pub fields: Vec<(String, serde_json::Value)>,
}

/// Alert output configuration
#[derive(Debug, Clone)]
pub struct AlertOutputConfig {
    /// Output to stdout
    pub stdout: bool,

    /// Output to file
    pub file: Option<std::path::PathBuf>,

    /// Channel size for alert buffering
    pub channel_size: usize,
}

impl Default for AlertOutputConfig {
    fn default() -> Self {
        Self {
            stdout: true,
            file: None,
            channel_size: 1000,
        }
    }
}

/// Alert output handle
#[derive(Debug, Clone)]
pub struct AlertHandle {
    sender: mpsc::Sender<Alert>,
}

impl AlertHandle {
    /// Emit an alert
    pub async fn emit(&self, alert: Alert) -> Result<(), AlertError> {
        self.sender
            .send(alert)
            .await
            .map_err(|_| AlertError::OutputClosed)?;
        Ok(())
    }

    /// Try to emit without blocking
    pub fn try_emit(&self, alert: Alert) -> Result<(), AlertError> {
        self.sender
            .try_send(alert)
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => AlertError::OutputFull,
                mpsc::error::TrySendError::Closed(_) => AlertError::OutputClosed,
            })?;
        Ok(())
    }
}

/// Alert output system
pub struct AlertOutput {
    _handle: tokio::task::JoinHandle<()>,
    handle: AlertHandle,
}

impl AlertOutput {
    /// Create a new alert output system
    pub fn new(config: AlertOutputConfig) -> Self {
        let (sender, mut receiver) = mpsc::channel(config.channel_size);

        let handle = AlertHandle { sender };

        let _handle = tokio::spawn(async move {
            while let Some(alert) = receiver.recv().await {
                if config.stdout {
                    Self::output_stdout(&alert);
                }

                if let Some(ref path) = config.file {
                    if let Err(e) = Self::output_file(&alert, path) {
                        error!(
                            path = %path.display(),
                            error = %e,
                            "Failed to write alert to file"
                        );
                    }
                }
            }

            debug!("Alert output system shutting down");
        });

        Self { _handle, handle }
    }

    /// Get a handle for emitting alerts
    pub fn handle(&self) -> AlertHandle {
        self.handle.clone()
    }

    /// Output alert to stdout
    fn output_stdout(alert: &Alert) {
        let json = serde_json::to_string_pretty(alert).unwrap_or_else(|_| {
            format!("{{ \"error\": \"Failed to serialize alert {}\" }}", alert.id)
        });
        println!("{}", json);
    }

    /// Output alert to file
    fn output_file(alert: &Alert, path: &std::path::Path) -> Result<(), AlertError> {
        let json = serde_json::to_string_pretty(alert)
            .map_err(|e: serde_json::Error| AlertError::SerializationError(e.to_string()))?;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e: std::io::Error| AlertError::IoError(e.to_string()))?;

        file.write_all(json.as_bytes())
            .map_err(|e: std::io::Error| AlertError::IoError(e.to_string()))?;
        file.write_all(b"\n")
            .map_err(|e: std::io::Error| AlertError::IoError(e.to_string()))?;

        Ok(())
    }
}

/// Alert errors
#[derive(Debug, Error)]
pub enum AlertError {
    #[error("Alert output is closed")]
    OutputClosed,

    #[error("Alert output is full")]
    OutputFull,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("IO error: {0}")]
    IoError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_alert_output() {
        let config = AlertOutputConfig {
            stdout: false,
            ..Default::default()
        };

        let output = AlertOutput::new(config);
        let handle = output.handle();

        let alert = Alert {
            id: "alert-001".to_string(),
            rule_id: "rule-001".to_string(),
            rule_name: "Test Rule".to_string(),
            severity: Severity::High,
            timestamp_ns: 1234567890,
            title: "Test Alert".to_string(),
            description: Some("A test alert".to_string()),
            events: vec![],
            context: serde_json::json!({}),
        };

        let result = handle.emit(alert).await;
        assert!(result.is_ok());
    }
}
