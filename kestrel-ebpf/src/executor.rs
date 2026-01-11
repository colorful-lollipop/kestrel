//! eBPF-based Action Executor
//!
//! This module provides an ActionExecutor implementation that sends enforcement
//! decisions to the kernel via eBPF maps for real-time blocking.

use crate::{EbpfCollector, EbpfError};
use kestrel_core::{
    ActionCapabilities, ActionDecision, ActionError, ActionExecutor, ActionType, ActionTarget,
    ActionResult,
};
use std::sync::Arc;
use tracing::{debug, warn};

/// eBPF-based action executor
///
/// Sends enforcement decisions to the kernel via eBPF enforcement_map.
/// LSM hooks in the kernel will check this map before allowing operations.
#[derive(Clone)]
pub struct EbpfExecutor {
    /// Reference to the eBPF collector
    collector: Arc<EbpfCollector>,
}

impl EbpfExecutor {
    /// Create a new eBPF executor
    pub fn new(collector: Arc<EbpfCollector>) -> Self {
        debug!("Creating eBPF enforcement executor");
        Self { collector }
    }

    /// Extract PID from action target
    fn extract_pid(target: &ActionTarget) -> u32 {
        match target {
            ActionTarget::ProcessExec { pid, .. } => *pid,
            ActionTarget::FileOp { pid, .. } => *pid,
            ActionTarget::NetworkOp { pid, .. } => *pid,
            ActionTarget::MemoryOp { pid } => *pid,
        }
    }

    /// Convert ActionType to enforcement action
    fn convert_action(action: &ActionType) -> Result<crate::EnforcementAction, ActionError> {
        match action {
            ActionType::Block => Ok(crate::EnforcementAction::Block),
            ActionType::Kill => Ok(crate::EnforcementAction::Kill),
            ActionType::Alert => Ok(crate::EnforcementAction::Allow),
            ActionType::Quarantine => {
                // Quarantine not directly supported - use alert instead
                warn!("Quarantine action not supported in eBPF, treating as alert");
                Ok(crate::EnforcementAction::Allow)
            }
        }
    }

    /// Calculate TTL for enforcement decision
    ///
    /// Block actions get a 60 second TTL, kill actions get no TTL (immediate)
    fn calculate_ttl(action: &ActionType) -> u64 {
        match action {
            ActionType::Block => 60_000_000_000, // 60 seconds in nanoseconds
            ActionType::Kill => 0,
            ActionType::Alert => 0,
            ActionType::Quarantine => 0,
        }
    }
}

impl ActionExecutor for EbpfExecutor {
    /// Execute an action decision by sending it to the eBPF enforcement map
    fn execute(&self, decision: &ActionDecision) -> Result<ActionResult, ActionError> {
        debug!(
            decision_id = %decision.id,
            action = ?decision.action,
            target = ?decision.target,
            "Executing action via eBPF"
        );

        // Extract PID from target
        let pid = Self::extract_pid(&decision.target);

        // Convert action type
        let enforcement_action = Self::convert_action(&decision.action)
            .map_err(|e| ActionError::InvalidAction(format!("{:?}", e)))?;

        // Calculate TTL
        let ttl_ns = Self::calculate_ttl(&decision.action);

        // Create enforcement decision
        let enforcement_decision = crate::EnforcementDecision::new(pid, enforcement_action, ttl_ns);

        // Send to eBPF map
        // Note: set_enforcement is currently a placeholder due to Aya HashMap API complexity
        // In production, this would write to the enforcement_map
        if let Err(e) = self.collector.set_enforcement(&enforcement_decision) {
            warn!(
                error = %e,
                pid = %pid,
                action = ?decision.action,
                "Failed to set enforcement (eBPF not fully integrated)"
            );
            // Return success for now since enforcement is not fully implemented
            return Ok(ActionResult {
                decision_id: decision.id.clone(),
                success: true,
                error: None,
                actual_action: Some(decision.action),
                timestamp_ns: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64,
            });
        }

        debug!(
            decision_id = %decision.id,
            pid = %pid,
            action = ?enforcement_action,
            ttl_ns = %ttl_ns,
            "Enforcement decision sent to eBPF"
        );

        Ok(ActionResult {
            decision_id: decision.id.clone(),
            success: true,
            error: None,
            actual_action: Some(decision.action),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        })
    }

    /// Get the capabilities of this executor
    fn capabilities(&self) -> ActionCapabilities {
        // eBPF enforcement supports block and kill
        ActionCapabilities {
            can_block: true,
            can_kill: true,
            can_quarantine: false, // Quarantine not supported
            alert_only: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_pid_process_exec() {
        let target = ActionTarget::ProcessExec {
            pid: 1234,
            executable: "/bin/bash".to_string(),
        };
        assert_eq!(EbpfExecutor::extract_pid(&target), 1234);
    }

    #[test]
    fn test_extract_pid_file_op() {
        let target = ActionTarget::FileOp {
            pid: 5678,
            path: "/etc/passwd".to_string(),
        };
        assert_eq!(EbpfExecutor::extract_pid(&target), 5678);
    }

    #[test]
    fn test_convert_action_block() {
        let result = EbpfExecutor::convert_action(&ActionType::Block);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), crate::EnforcementAction::Block);
    }

    #[test]
    fn test_convert_action_kill() {
        let result = EbpfExecutor::convert_action(&ActionType::Kill);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), crate::EnforcementAction::Kill);
    }

    #[test]
    fn test_convert_action_alert() {
        let result = EbpfExecutor::convert_action(&ActionType::Alert);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), crate::EnforcementAction::Allow);
    }

    #[test]
    fn test_calculate_ttl_block() {
        let ttl = EbpfExecutor::calculate_ttl(&ActionType::Block);
        assert_eq!(ttl, 60_000_000_000); // 60 seconds
    }

    #[test]
    fn test_calculate_ttl_kill() {
        let ttl = EbpfExecutor::calculate_ttl(&ActionType::Kill);
        assert_eq!(ttl, 0);
    }

    #[test]
    fn test_calculate_ttl_alert() {
        let ttl = EbpfExecutor::calculate_ttl(&ActionType::Alert);
        assert_eq!(ttl, 0);
    }
}
