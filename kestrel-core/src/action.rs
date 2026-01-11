//! Action System for Real-time Enforcement
//!
//! This module provides the action system for blocking/deny/kill/quarantine operations.
//! It supports both inline (blocking) and async (alert-only) modes.

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Action type - represents the enforcement action to take
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionType {
    /// Block/deny the operation (inline enforcement only)
    Block,

    /// Kill the process
    Kill,

    /// Quarantine the file (mark as suspicious)
    Quarantine,

    /// Alert only (no enforcement)
    Alert,
}

impl fmt::Display for ActionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActionType::Block => write!(f, "block"),
            ActionType::Kill => write!(f, "kill"),
            ActionType::Quarantine => write!(f, "quarantine"),
            ActionType::Alert => write!(f, "alert"),
        }
    }
}

/// Target of the action
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionTarget {
    /// Process execution (execve/execveat)
    ProcessExec { pid: u32, executable: String },

    /// File operation (open/write/rename/unlink)
    FileOp { pid: u32, path: String },

    /// Network operation (connect/sendto)
    NetworkOp { pid: u32, addr: String },

    /// Memory operation (mmap/mprotect/process_vm_writev)
    MemoryOp { pid: u32 },
}

/// Action decision - result of evaluating a rule against an event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionDecision {
    /// Unique decision ID
    pub id: String,

    /// Rule ID that generated this decision
    pub rule_id: String,

    /// Action to take
    pub action: ActionType,

    /// Target of the action
    pub target: ActionTarget,

    /// Decision timestamp (nanoseconds)
    pub timestamp_ns: u64,

    /// Reason for this decision (for audit)
    pub reason: String,

    /// Evidence/events that led to this decision
    pub evidence: Vec<ActionEvidence>,
}

/// Evidence associated with an action decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionEvidence {
    /// Event type ID
    pub event_type_id: u16,

    /// Event timestamp
    pub timestamp_ns: u64,

    /// Relevant fields
    pub fields: Vec<(String, serde_json::Value)>,
}

/// Result of attempting to execute an action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    /// Decision ID this result corresponds to
    pub decision_id: String,

    /// Whether the action was successful
    pub success: bool,

    /// Error message if unsuccessful
    pub error: Option<String>,

    /// Actual action taken (may differ from requested)
    pub actual_action: Option<ActionType>,

    /// Result timestamp
    pub timestamp_ns: u64,
}

/// Action errors
#[derive(Debug, Error)]
pub enum ActionError {
    #[error("Action not supported in current mode: {0}")]
    NotSupported(String),

    #[error("Permission denied for action: {0}")]
    PermissionDenied(String),

    #[error("Target not found: {0}")]
    TargetNotFound(String),

    #[error("Action failed: {0}")]
    ActionFailed(String),

    #[error("Invalid action: {0}")]
    InvalidAction(String),
}

/// Capability flags for what actions are available
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActionCapabilities {
    /// Block/deny operations supported
    pub can_block: bool,

    /// Kill processes supported
    pub can_kill: bool,

    /// Quarantine files supported
    pub can_quarantine: bool,

    /// Alert-only mode
    pub alert_only: bool,
}

impl ActionCapabilities {
    /// Full enforcement capabilities
    pub fn enforce() -> Self {
        Self {
            can_block: true,
            can_kill: true,
            can_quarantine: true,
            alert_only: false,
        }
    }

    /// Alert-only mode (no enforcement)
    pub fn alert_only() -> Self {
        Self {
            can_block: false,
            can_kill: false,
            can_quarantine: false,
            alert_only: true,
        }
    }

    /// Check if an action type is supported
    pub fn supports(&self, action: ActionType) -> bool {
        match action {
            ActionType::Block => self.can_block,
            ActionType::Kill => self.can_kill,
            ActionType::Quarantine => self.can_quarantine,
            ActionType::Alert => true, // Always supported
        }
    }
}

/// Action executor - handles the actual enforcement
pub trait ActionExecutor: Send + Sync {
    /// Execute an action decision
    fn execute(&self, decision: &ActionDecision) -> Result<ActionResult, ActionError>;

    /// Get the capabilities of this executor
    fn capabilities(&self) -> ActionCapabilities;
}

/// No-op executor for alert-only mode
#[derive(Debug, Clone, Default)]
pub struct NoOpExecutor;

impl ActionExecutor for NoOpExecutor {
    fn execute(&self, decision: &ActionDecision) -> Result<ActionResult, ActionError> {
        Ok(ActionResult {
            decision_id: decision.id.clone(),
            success: true,
            error: None,
            actual_action: Some(ActionType::Alert),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        })
    }

    fn capabilities(&self) -> ActionCapabilities {
        ActionCapabilities::alert_only()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_type_display() {
        assert_eq!(ActionType::Block.to_string(), "block");
        assert_eq!(ActionType::Kill.to_string(), "kill");
        assert_eq!(ActionType::Quarantine.to_string(), "quarantine");
        assert_eq!(ActionType::Alert.to_string(), "alert");
    }

    #[test]
    fn test_action_capabilities() {
        let enforce = ActionCapabilities::enforce();
        assert!(enforce.can_block);
        assert!(enforce.can_kill);
        assert!(enforce.can_quarantine);
        assert!(!enforce.alert_only);

        let alert_only = ActionCapabilities::alert_only();
        assert!(!alert_only.can_block);
        assert!(!alert_only.can_kill);
        assert!(!alert_only.can_quarantine);
        assert!(alert_only.alert_only);
    }

    #[test]
    fn test_action_capabilities_supports() {
        let caps = ActionCapabilities::enforce();
        assert!(caps.supports(ActionType::Block));
        assert!(caps.supports(ActionType::Kill));
        assert!(caps.supports(ActionType::Quarantine));
        assert!(caps.supports(ActionType::Alert));

        let alert_only = ActionCapabilities::alert_only();
        assert!(!alert_only.supports(ActionType::Block));
        assert!(!alert_only.supports(ActionType::Kill));
        assert!(!alert_only.supports(ActionType::Quarantine));
        assert!(alert_only.supports(ActionType::Alert));
    }

    #[test]
    fn test_noop_executor() {
        let executor = NoOpExecutor::default();
        let decision = ActionDecision {
            id: "test-001".to_string(),
            rule_id: "rule-001".to_string(),
            action: ActionType::Block,
            target: ActionTarget::ProcessExec {
                pid: 1234,
                executable: "/bin/test".to_string(),
            },
            timestamp_ns: 1234567890,
            reason: "Test".to_string(),
            evidence: vec![],
        };

        let result = executor.execute(&decision).unwrap();
        assert!(result.success);
        assert_eq!(result.decision_id, "test-001");
        assert_eq!(result.actual_action, Some(ActionType::Alert));

        let caps = executor.capabilities();
        assert!(caps.alert_only);
    }
}
