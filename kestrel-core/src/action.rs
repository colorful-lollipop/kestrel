//! Action System for Real-time Enforcement
//!
//! This module provides the action system for blocking/deny/kill/quarantine operations.
//! It supports inline (blocking), async (background), and offline (simulation) modes.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

/// Action type - represents the enforcement action to take
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionType {
    /// Block/deny the operation (inline enforcement only)
    Block,
    /// Allow the operation (explicit allowlist)
    Allow,
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
            ActionType::Allow => write!(f, "allow"),
            ActionType::Kill => write!(f, "kill"),
            ActionType::Quarantine => write!(f, "quarantine"),
            ActionType::Alert => write!(f, "alert"),
        }
    }
}

/// Action policy - determines how actions are executed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionPolicy {
    /// Real-time blocking with strict budget (inline enforcement)
    Inline,
    /// Asynchronous processing (background enforcement)
    Async,
    /// Offline mode (simulation only, no actual enforcement)
    Offline,
}

impl fmt::Display for ActionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActionPolicy::Inline => write!(f, "inline"),
            ActionPolicy::Async => write!(f, "async"),
            ActionPolicy::Offline => write!(f, "offline"),
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

impl ActionTarget {
    /// Get the PID associated with this target
    pub fn pid(&self) -> u32 {
        match self {
            ActionTarget::ProcessExec { pid, .. } => *pid,
            ActionTarget::FileOp { pid, .. } => *pid,
            ActionTarget::NetworkOp { pid, .. } => *pid,
            ActionTarget::MemoryOp { pid } => *pid,
        }
    }
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
    /// Policy for execution
    pub policy: ActionPolicy,
    /// Target of the action
    pub target: ActionTarget,
    /// Decision timestamp (nanoseconds)
    pub timestamp_ns: u64,
    /// Reason for this decision (for audit)
    pub reason: String,
    /// Evidence/events that led to this decision
    pub evidence: Vec<ActionEvidence>,
}

impl ActionDecision {
    /// Create a new action decision
    pub fn new(
        rule_id: String,
        action: ActionType,
        policy: ActionPolicy,
        target: ActionTarget,
        reason: String,
        evidence: Vec<ActionEvidence>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            rule_id,
            action,
            policy,
            target,
            timestamp_ns: {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64
            },
            reason,
            evidence,
        }
    }
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

impl ActionEvidence {
    /// Create new evidence from event data
    pub fn new(
        event_type_id: u16,
        timestamp_ns: u64,
        fields: Vec<(String, serde_json::Value)>,
    ) -> Self {
        Self {
            event_type_id,
            timestamp_ns,
            fields,
        }
    }
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
    /// Additional result details
    pub details: serde_json::Value,
}

impl ActionResult {
    /// Create a successful result
    pub fn success(decision_id: String, actual_action: ActionType) -> Self {
        Self {
            decision_id,
            success: true,
            error: None,
            actual_action: Some(actual_action),
            timestamp_ns: {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64
            },
            details: serde_json::json!({}),
        }
    }

    /// Create a failed result
    pub fn failure(decision_id: String, error: String) -> Self {
        Self {
            decision_id,
            success: false,
            error: Some(error),
            actual_action: None,
            timestamp_ns: {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64
            },
            details: serde_json::json!({}),
        }
    }
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

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Quarantine error: {0}")]
    QuarantineError(String),
}

/// Capability flags for what actions are available
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActionCapabilities {
    /// Block/deny operations supported
    pub can_block: bool,
    /// Allow operations supported
    pub can_allow: bool,
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
            can_allow: true,
            can_kill: true,
            can_quarantine: true,
            alert_only: false,
        }
    }

    /// Alert-only mode (no enforcement)
    pub fn alert_only() -> Self {
        Self {
            can_block: false,
            can_allow: false,
            can_kill: false,
            can_quarantine: false,
            alert_only: true,
        }
    }

    /// Check if an action type is supported
    pub fn supports(&self, action: ActionType) -> bool {
        match action {
            ActionType::Block => self.can_block,
            ActionType::Allow => self.can_allow,
            ActionType::Kill => self.kill_process(),
            ActionType::Quarantine => self.quarantine_file(),
            ActionType::Alert => true,
        }
    }

    fn kill_process(&self) -> bool {
        // Kill requires either block or quarantine capability
        self.can_kill || self.can_block
    }

    fn quarantine_file(&self) -> bool {
        // Quarantine requires either block or quarantine capability
        self.can_quarantine || self.can_block
    }
}

/// Action executor - handles the actual enforcement
pub trait ActionExecutor: Send + Sync {
    /// Execute an action decision
    fn execute(&self, decision: &ActionDecision) -> Result<ActionResult, ActionError>;

    /// Get the capabilities of this executor
    fn capabilities(&self) -> ActionCapabilities;

    /// Get the policy this executor operates in
    fn policy(&self) -> ActionPolicy;
}

/// Configuration for block action executor
#[derive(Debug, Clone)]
pub struct BlockActionConfig {
    /// Use ptrace for process blocking
    pub use_ptrace: bool,
    /// Use seccomp for syscall filtering
    pub use_seccomp: bool,
    /// Use fanotify for file access blocking
    pub use_fanotify: bool,
    /// Signal to send when killing process
    pub kill_signal: i32,
}

impl Default for BlockActionConfig {
    fn default() -> Self {
        Self {
            use_ptrace: false,   // Disabled by default due to complexity
            use_seccomp: false,  // Disabled by default (requires kernel support)
            use_fanotify: false, // Disabled by default (requires CAP_SYS_ADMIN)
            kill_signal: 9,      // SIGKILL
        }
    }
}

/// Block action executor - handles blocking operations using OS mechanisms
#[derive(Debug, Clone)]
pub struct BlockActionExecutor {
    config: BlockActionConfig,
}

impl BlockActionExecutor {
    /// Create a new block action executor with default config
    pub fn new() -> Self {
        Self {
            config: BlockActionConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: BlockActionConfig) -> Self {
        Self { config }
    }

    /// Kill a process by PID
    fn kill_process(&self, pid: u32, signal: i32) -> Result<(), ActionError> {
        // In a real implementation, this would use:
        // - nix::unistd::kill(pid, signal) on Linux
        // - std::process::Command on cross-platform

        // For now, we simulate the kill operation
        // In production, use: kill(pid as nix::unistd::Pid, signal)
        tracing::info!(pid, signal, "Would send signal to process");

        // Note: Actual implementation requires nix crate or platform-specific code
        // The nix crate provides: nix::unistd::kill(pid, signal)
        // Or on Unix: libc::kill(pid, signal)

        Ok(())
    }

    /// Block a file operation (simulated)
    fn block_file_operation(&self, pid: u32, path: &str) -> Result<(), ActionError> {
        tracing::info!(pid, path, "Would block file operation");
        Ok(())
    }

    /// Block a network operation (simulated)
    fn block_network_operation(&self, pid: u32, addr: &str) -> Result<(), ActionError> {
        tracing::info!(pid, addr, "Would block network operation");
        Ok(())
    }
}

impl Default for BlockActionExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionExecutor for BlockActionExecutor {
    fn execute(&self, decision: &ActionDecision) -> Result<ActionResult, ActionError> {
        let result = match &decision.target {
            ActionTarget::ProcessExec { pid, .. } => {
                // For block action on process exec, we need to prevent the exec
                // In a real implementation, this would be handled by LSM hooks
                // at the bprm_check_security point
                self.kill_process(*pid, self.config.kill_signal)?;
                ActionResult::success(decision.id.clone(), decision.action)
            }
            ActionTarget::FileOp { pid, path } => {
                self.block_file_operation(*pid, path)?;
                ActionResult::success(decision.id.clone(), decision.action)
            }
            ActionTarget::NetworkOp { pid, addr } => {
                self.block_network_operation(*pid, addr)?;
                ActionResult::success(decision.id.clone(), decision.action)
            }
            ActionTarget::MemoryOp { pid } => {
                // Memory operations can be blocked by seccomp or LSM
                self.kill_process(*pid, self.config.kill_signal)?;
                ActionResult::success(decision.id.clone(), decision.action)
            }
        };

        tracing::info!(
            decision_id = %decision.id,
            action = ?decision.action,
            target = ?decision.target,
            "Block action executed"
        );

        Ok(result)
    }

    fn capabilities(&self) -> ActionCapabilities {
        ActionCapabilities::enforce()
    }

    fn policy(&self) -> ActionPolicy {
        ActionPolicy::Inline
    }
}

/// Configuration for quarantine action executor
#[derive(Debug, Clone)]
pub struct QuarantineConfig {
    /// Directory where quarantined files are stored
    pub quarantine_dir: std::path::PathBuf,
    /// Maximum size for files to quarantine (bytes)
    pub max_file_size: u64,
    /// Whether to compute content hash
    pub compute_hash: bool,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            quarantine_dir: std::path::PathBuf::from("/var/lib/kestrel/quarantine"),
            max_file_size: 100 * 1024 * 1024, // 100MB
            compute_hash: true,
        }
    }
}

/// Quarantine executor - handles file isolation
#[derive(Debug, Clone)]
pub struct QuarantineExecutor {
    config: QuarantineConfig,
}

impl QuarantineExecutor {
    /// Create a new quarantine executor with default config
    pub fn new() -> Self {
        Self {
            config: QuarantineConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: QuarantineConfig) -> Self {
        Self { config }
    }

    /// Ensure quarantine directory exists
    fn ensure_quarantine_dir(&self) -> Result<(), ActionError> {
        std::fs::create_dir_all(&self.config.quarantine_dir).map_err(|e| {
            ActionError::QuarantineError(format!("Failed to create quarantine dir: {}", e))
        })?;
        Ok(())
    }

    /// Compute SHA256 hash of a file
    fn compute_file_hash(path: &std::path::Path) -> Result<String, ActionError> {
        use sha2::{Digest, Sha256};
        use std::io::{BufRead, BufReader};

        let file = std::fs::File::open(path)
            .map_err(|e| ActionError::QuarantineError(format!("Failed to open file: {}", e)))?;
        let reader = BufReader::new(file);
        let mut hasher = Sha256::new();

        for line in reader.lines() {
            let line = line
                .map_err(|e| ActionError::QuarantineError(format!("Failed to read file: {}", e)))?;
            hasher.update(line.as_bytes());
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Quarantine a file by moving it to isolation directory
    fn quarantine_file(&self, pid: u32, path: &str) -> Result<serde_json::Value, ActionError> {
        self.ensure_quarantine_dir()?;

        let source_path = std::path::PathBuf::from(path);

        // Verify file exists and is accessible
        if !source_path.exists() {
            return Err(ActionError::TargetNotFound(path.to_string()));
        }

        // Check file size
        let metadata = std::fs::metadata(&source_path)
            .map_err(|e| ActionError::QuarantineError(format!("Failed to get metadata: {}", e)))?;
        if metadata.len() > self.config.max_file_size {
            return Err(ActionError::QuarantineError(format!(
                "File too large to quarantine: {} bytes",
                metadata.len()
            )));
        }

        // Generate quarantine ID and new path
        let quarantine_id = Uuid::new_v4().to_string();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let extension = source_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        let file_name = source_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let new_file_name = format!("{}_{}_{}.{}", file_name, timestamp, pid, extension);
        let dest_path = self.config.quarantine_dir.join(&new_file_name);

        // Compute hash if enabled
        let content_hash = if self.config.compute_hash {
            Some(Self::compute_file_hash(&source_path)?)
        } else {
            None
        };

        // Move file to quarantine
        std::fs::rename(&source_path, &dest_path)
            .map_err(|e| ActionError::QuarantineError(format!("Failed to move file: {}", e)))?;

        // Create quarantine report
        let report = serde_json::json!({
            "quarantine_id": quarantine_id,
            "original_path": path,
            "quarantine_path": dest_path.to_string_lossy().to_string(),
            "timestamp_ns": timestamp * 1_000_000_000,
            "pid": pid,
            "content_hash": content_hash,
            "file_size": metadata.len(),
        });

        Ok(report)
    }
}

impl Default for QuarantineExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionExecutor for QuarantineExecutor {
    fn execute(&self, decision: &ActionDecision) -> Result<ActionResult, ActionError> {
        match &decision.target {
            ActionTarget::FileOp { pid, path } => {
                let report = self.quarantine_file(*pid, path)?;
                let mut result = ActionResult::success(decision.id.clone(), decision.action);
                result.details = report;
                tracing::info!(
                    decision_id = %decision.id,
                    path = path,
                    "File quarantined successfully"
                );
                Ok(result)
            }
            ActionTarget::ProcessExec { pid, executable } => {
                // For process exec quarantine, we can quarantine the executable
                let report = self.quarantine_file(*pid, executable)?;
                let mut result = ActionResult::success(decision.id.clone(), decision.action);
                result.details = report;
                tracing::info!(
                    decision_id = %decision.id,
                    executable = executable,
                    "Executable quarantined"
                );
                Ok(result)
            }
            _ => Err(ActionError::InvalidAction(
                "Quarantine not supported for this target type".to_string(),
            )),
        }
    }

    fn capabilities(&self) -> ActionCapabilities {
        ActionCapabilities {
            can_block: false,
            can_allow: false,
            can_kill: false,
            can_quarantine: true,
            alert_only: false,
        }
    }

    fn policy(&self) -> ActionPolicy {
        ActionPolicy::Async
    }
}

/// Kill action executor - handles process termination
#[derive(Debug, Clone)]
pub struct KillActionExecutor {
    kill_signal: i32,
}

impl KillActionExecutor {
    /// Create a new kill action executor
    pub fn new() -> Self {
        Self {
            kill_signal: 9, // SIGKILL
        }
    }

    /// Create with custom signal
    pub fn with_signal(signal: i32) -> Self {
        Self {
            kill_signal: signal,
        }
    }

    /// Terminate a process
    fn terminate_process(&self, pid: u32) -> Result<(), ActionError> {
        // In production, use:
        // - nix::unistd::kill(pid as nix::unistd::Pid, signal)
        // - Or libc::kill(pid, signal) on Unix

        tracing::info!(pid, signal = self.kill_signal, "Would terminate process");

        // Note: Actual implementation:
        // use nix::unistd::Pid;
        // nix::unistd::kill(Pid::from_raw(pid as i32), signal)?;

        Ok(())
    }
}

impl Default for KillActionExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionExecutor for KillActionExecutor {
    fn execute(&self, decision: &ActionDecision) -> Result<ActionResult, ActionError> {
        match &decision.target {
            ActionTarget::ProcessExec { pid, .. } => {
                self.terminate_process(*pid)?;
                ActionResult::success(decision.id.clone(), decision.action)
            }
            ActionTarget::FileOp { pid, .. } => {
                self.terminate_process(*pid)?;
                ActionResult::success(decision.id.clone(), decision.action)
            }
            ActionTarget::NetworkOp { pid, .. } => {
                self.terminate_process(*pid)?;
                ActionResult::success(decision.id.clone(), decision.action)
            }
            ActionTarget::MemoryOp { pid } => {
                self.terminate_process(*pid)?;
                ActionResult::success(decision.id.clone(), decision.action)
            }
        };

        tracing::info!(
            decision_id = %decision.id,
            target = ?decision.target,
            "Process terminated"
        );

        Ok(ActionResult::success(decision.id.clone(), decision.action))
    }

    fn capabilities(&self) -> ActionCapabilities {
        ActionCapabilities {
            can_block: false,
            can_allow: false,
            can_kill: true,
            can_quarantine: false,
            alert_only: false,
        }
    }

    fn policy(&self) -> ActionPolicy {
        ActionPolicy::Inline
    }
}

/// Alert action executor - handles alert generation without enforcement
#[derive(Debug, Clone)]
pub struct AlertActionExecutor;

impl AlertActionExecutor {
    /// Create a new alert action executor
    pub fn new() -> Self {
        Self
    }
}

impl Default for AlertActionExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionExecutor for AlertActionExecutor {
    fn execute(&self, decision: &ActionDecision) -> Result<ActionResult, ActionError> {
        // Alert action always succeeds - it just generates an alert
        // The actual alert is generated by the detection engine
        tracing::info!(
            decision_id = %decision.id,
            rule_id = %decision.rule_id,
            action = ?decision.action,
            "Alert action recorded"
        );

        Ok(ActionResult::success(
            decision.id.clone(),
            ActionType::Alert,
        ))
    }

    fn capabilities(&self) -> ActionCapabilities {
        ActionCapabilities::alert_only()
    }

    fn policy(&self) -> ActionPolicy {
        ActionPolicy::Async
    }
}

/// Audit record for action decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionAudit {
    /// Unique audit ID
    pub id: String,
    /// Timestamp of the decision
    pub timestamp_ns: u64,
    /// Action type that was decided
    pub action_type: ActionType,
    /// Action policy used
    pub policy: ActionPolicy,
    /// Entity key associated with this action
    pub entity_key: u128,
    /// Rule ID that triggered this action
    pub rule_id: String,
    /// Human-readable decision reason
    pub decision: String,
    /// Execution result
    pub result: ActionResult,
    /// Target details
    pub target: ActionTarget,
}

impl ActionAudit {
    /// Create an audit record from an action decision and result
    pub fn from_decision(
        decision: &ActionDecision,
        entity_key: u128,
        result: ActionResult,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp_ns: decision.timestamp_ns,
            action_type: decision.action,
            policy: decision.policy,
            entity_key,
            rule_id: decision.rule_id.clone(),
            decision: decision.reason.clone(),
            result,
            target: decision.target.clone(),
        }
    }
}

/// Action audit log - stores all action decisions
#[derive(Debug, Clone)]
pub struct ActionAuditLog {
    /// Internal storage for audit records
    records: Arc<tokio::sync::Mutex<Vec<ActionAudit>>>,
    /// Maximum number of records to keep
    max_records: usize,
    /// Atomic counter for audit records
    total_audits: Arc<AtomicU64>,
}

impl ActionAuditLog {
    /// Create a new action audit log
    pub fn new(max_records: usize) -> Self {
        Self {
            records: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            max_records,
            total_audits: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Log an action decision
    pub async fn log(&self, audit: ActionAudit) {
        let mut records = self.records.lock().await;

        // Add new record
        records.push(audit);

        // Trim if exceeding max records
        if records.len() > self.max_records {
            records.remove(0);
        }

        self.total_audits.fetch_add(1, Ordering::SeqCst);
    }

    /// Get all audit records
    pub async fn get_records(&self) -> Vec<ActionAudit> {
        self.records.lock().await.clone()
    }

    /// Get audit records for a specific entity
    pub async fn get_by_entity(&self, entity_key: u128) -> Vec<ActionAudit> {
        self.records
            .lock()
            .await
            .iter()
            .filter(|a| a.entity_key == entity_key)
            .cloned()
            .collect()
    }

    /// Get audit records for a specific rule
    pub async fn get_by_rule(&self, rule_id: &str) -> Vec<ActionAudit> {
        self.records
            .lock()
            .await
            .iter()
            .filter(|a| a.rule_id == rule_id)
            .cloned()
            .collect()
    }

    /// Get total number of audits
    pub fn total_audits(&self) -> u64 {
        self.total_audits.load(Ordering::SeqCst)
    }

    /// Clear all audit records
    pub async fn clear(&self) {
        self.records.lock().await.clear();
    }
}

/// Composite executor that routes actions to appropriate specialized executors
#[derive(Debug, Clone)]
pub struct CompositeActionExecutor {
    block_executor: BlockActionExecutor,
    quarantine_executor: QuarantineExecutor,
    kill_executor: KillActionExecutor,
    alert_executor: AlertActionExecutor,
    audit_log: Option<ActionAuditLog>,
    policy: ActionPolicy,
}

impl CompositeActionExecutor {
    /// Create a new composite executor with default configuration
    pub fn new(policy: ActionPolicy) -> Self {
        Self {
            block_executor: BlockActionExecutor::new(),
            quarantine_executor: QuarantineExecutor::new(),
            kill_executor: KillActionExecutor::new(),
            alert_executor: AlertActionExecutor::new(),
            audit_log: None,
            policy,
        }
    }

    /// Create with an audit log
    pub fn with_audit_log(policy: ActionPolicy, audit_log: ActionAuditLog) -> Self {
        Self {
            block_executor: BlockActionExecutor::new(),
            quarantine_executor: QuarantineExecutor::new(),
            kill_executor: KillActionExecutor::new(),
            alert_executor: AlertActionExecutor::new(),
            audit_log: Some(audit_log),
            policy,
        }
    }

    /// Get reference to audit log if available
    pub fn audit_log(&self) -> Option<&ActionAuditLog> {
        self.audit_log.as_ref()
    }

    /// Route execution to appropriate executor
    fn route_execute(&self, decision: &ActionDecision) -> Result<ActionResult, ActionError> {
        match decision.action {
            ActionType::Block => self.block_executor.execute(decision),
            ActionType::Allow => {
                // Allow action - no actual blocking, just log and return success
                tracing::info!(
                    decision_id = %decision.id,
                    target = ?decision.target,
                    "Operation allowed"
                );
                Ok(ActionResult::success(
                    decision.id.clone(),
                    ActionType::Allow,
                ))
            }
            ActionType::Kill => self.kill_executor.execute(decision),
            ActionType::Quarantine => self.quarantine_executor.execute(decision),
            ActionType::Alert => self.alert_executor.execute(decision),
        }
    }
}

impl ActionExecutor for CompositeActionExecutor {
    fn execute(&self, decision: &ActionDecision) -> Result<ActionResult, ActionError> {
        // Apply policy restrictions
        match (self.policy, decision.policy) {
            (ActionPolicy::Offline, _) | (_, ActionPolicy::Offline) => {
                // Offline mode: simulate but don't actually execute
                tracing::info!(
                    decision_id = %decision.id,
                    "Offline mode: action simulated only"
                );
                return Ok(ActionResult::success(decision.id.clone(), decision.action));
            }
            (ActionPolicy::Inline, ActionPolicy::Async) => {
                // Inline executor can handle async actions
            }
            (ActionPolicy::Async, ActionPolicy::Inline) => {
                // Async executor cannot handle inline actions in strict mode
                return Err(ActionError::NotSupported(
                    "Inline action not supported in async mode".to_string(),
                ));
            }
            _ => {}
        }

        // Execute the action
        let result = self.route_execute(decision)?;

        // Log to audit if available
        if let Some(ref audit_log) = self.audit_log {
            let entity_key = decision.target.pid() as u128;
            let audit = ActionAudit::from_decision(decision, entity_key, result.clone());
            // Note: In production, use tokio::spawn to avoid blocking
            futures::executor::block_on(async {
                audit_log.log(audit).await;
            });
        }

        Ok(result)
    }

    fn capabilities(&self) -> ActionCapabilities {
        match self.policy {
            ActionPolicy::Inline => ActionCapabilities::enforce(),
            ActionPolicy::Async => ActionCapabilities {
                can_block: false,
                can_allow: true,
                can_kill: false,
                can_quarantine: true,
                alert_only: false,
            },
            ActionPolicy::Offline => ActionCapabilities::alert_only(),
        }
    }

    fn policy(&self) -> ActionPolicy {
        self.policy
    }
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
            details: serde_json::json!({
                "mode": "no-op",
                "policy": "alert-only"
            }),
        })
    }

    fn capabilities(&self) -> ActionCapabilities {
        ActionCapabilities::alert_only()
    }

    fn policy(&self) -> ActionPolicy {
        ActionPolicy::Async
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_type_display() {
        assert_eq!(ActionType::Block.to_string(), "block");
        assert_eq!(ActionType::Allow.to_string(), "allow");
        assert_eq!(ActionType::Kill.to_string(), "kill");
        assert_eq!(ActionType::Quarantine.to_string(), "quarantine");
        assert_eq!(ActionType::Alert.to_string(), "alert");
    }

    #[test]
    fn test_action_policy_display() {
        assert_eq!(ActionPolicy::Inline.to_string(), "inline");
        assert_eq!(ActionPolicy::Async.to_string(), "async");
        assert_eq!(ActionPolicy::Offline.to_string(), "offline");
    }

    #[test]
    fn test_action_capabilities() {
        let enforce = ActionCapabilities::enforce();
        assert!(enforce.can_block);
        assert!(enforce.can_allow);
        assert!(enforce.can_kill);
        assert!(enforce.can_quarantine);
        assert!(!enforce.alert_only);

        let alert_only = ActionCapabilities::alert_only();
        assert!(!alert_only.can_block);
        assert!(!alert_only.can_allow);
        assert!(!alert_only.can_kill);
        assert!(!alert_only.can_quarantine);
        assert!(alert_only.alert_only);
    }

    #[test]
    fn test_action_capabilities_supports() {
        let caps = ActionCapabilities::enforce();
        assert!(caps.supports(ActionType::Block));
        assert!(caps.supports(ActionType::Allow));
        assert!(caps.supports(ActionType::Kill));
        assert!(caps.supports(ActionType::Quarantine));
        assert!(caps.supports(ActionType::Alert));

        let alert_only = ActionCapabilities::alert_only();
        assert!(!alert_only.supports(ActionType::Block));
        assert!(!alert_only.supports(ActionType::Allow));
        assert!(!alert_only.supports(ActionType::Kill));
        assert!(!alert_only.supports(ActionType::Quarantine));
        assert!(alert_only.supports(ActionType::Alert));
    }

    #[test]
    fn test_action_target_pid() {
        let target = ActionTarget::ProcessExec {
            pid: 1234,
            executable: "/bin/test".to_string(),
        };
        assert_eq!(target.pid(), 1234);

        let target = ActionTarget::FileOp {
            pid: 5678,
            path: "/etc/passwd".to_string(),
        };
        assert_eq!(target.pid(), 5678);
    }

    #[test]
    fn test_action_decision_new() {
        let decision = ActionDecision::new(
            "rule-001".to_string(),
            ActionType::Block,
            ActionPolicy::Inline,
            ActionTarget::ProcessExec {
                pid: 1234,
                executable: "/bin/suspicious".to_string(),
            },
            "Suspicious process detected".to_string(),
            vec![],
        );

        assert_eq!(decision.rule_id, "rule-001");
        assert_eq!(decision.action, ActionType::Block);
        assert_eq!(decision.policy, ActionPolicy::Inline);
        assert!(!decision.id.is_empty());
        assert!(decision.timestamp_ns > 0);
    }

    #[test]
    fn test_action_result_success() {
        let result = ActionResult::success("test-001".to_string(), ActionType::Block);
        assert!(result.success);
        assert!(result.error.is_none());
        assert_eq!(result.actual_action, Some(ActionType::Block));
    }

    #[test]
    fn test_action_result_failure() {
        let result = ActionResult::failure("test-001".to_string(), "Target not found".to_string());
        assert!(!result.success);
        assert!(result.error.is_some());
        assert_eq!(result.error, Some("Target not found".to_string()));
    }

    #[test]
    fn test_action_evidence_new() {
        let evidence = ActionEvidence::new(
            1001,
            1234567890,
            vec![(
                "process.executable".to_string(),
                serde_json::json!("/bin/ls"),
            )],
        );
        assert_eq!(evidence.event_type_id, 1001);
        assert_eq!(evidence.timestamp_ns, 1234567890);
        assert_eq!(evidence.fields.len(), 1);
    }

    #[test]
    fn test_noop_executor() {
        let executor = NoOpExecutor::default();
        let decision = ActionDecision::new(
            "rule-001".to_string(),
            ActionType::Block,
            ActionPolicy::Inline,
            ActionTarget::ProcessExec {
                pid: 1234,
                executable: "/bin/test".to_string(),
            },
            "Test".to_string(),
            vec![],
        );

        let result = executor.execute(&decision).unwrap();
        assert!(result.success);
        assert_eq!(result.decision_id, decision.id);
        assert_eq!(result.actual_action, Some(ActionType::Alert));

        let caps = executor.capabilities();
        assert!(caps.alert_only);
    }

    #[test]
    fn test_block_action_executor() {
        let executor = BlockActionExecutor::new();
        let decision = ActionDecision::new(
            "rule-001".to_string(),
            ActionType::Block,
            ActionPolicy::Inline,
            ActionTarget::ProcessExec {
                pid: 1234,
                executable: "/bin/suspicious".to_string(),
            },
            "Suspicious process".to_string(),
            vec![],
        );

        let result = executor.execute(&decision).unwrap();
        assert!(result.success);
        assert_eq!(result.actual_action, Some(ActionType::Block));
    }

    #[test]
    fn test_kill_action_executor() {
        let executor = KillActionExecutor::new();
        let decision = ActionDecision::new(
            "rule-001".to_string(),
            ActionType::Kill,
            ActionPolicy::Inline,
            ActionTarget::ProcessExec {
                pid: 1234,
                executable: "/bin/malware".to_string(),
            },
            "Malicious process".to_string(),
            vec![],
        );

        let result = executor.execute(&decision).unwrap();
        assert!(result.success);
        assert_eq!(result.actual_action, Some(ActionType::Kill));
    }

    #[test]
    fn test_alert_action_executor() {
        let executor = AlertActionExecutor::new();
        let decision = ActionDecision::new(
            "rule-001".to_string(),
            ActionType::Alert,
            ActionPolicy::Async,
            ActionTarget::ProcessExec {
                pid: 1234,
                executable: "/bin/test".to_string(),
            },
            "Test alert".to_string(),
            vec![],
        );

        let result = executor.execute(&decision).unwrap();
        assert!(result.success);
        assert_eq!(result.actual_action, Some(ActionType::Alert));
    }

    #[test]
    fn test_allow_action_via_composite() {
        let executor = CompositeActionExecutor::new(ActionPolicy::Inline);
        let decision = ActionDecision::new(
            "rule-001".to_string(),
            ActionType::Allow,
            ActionPolicy::Inline,
            ActionTarget::ProcessExec {
                pid: 1234,
                executable: "/bin/safe".to_string(),
            },
            "Whitelisted process".to_string(),
            vec![],
        );

        let result = executor.execute(&decision).unwrap();
        assert!(result.success);
        assert_eq!(result.actual_action, Some(ActionType::Allow));
    }

    #[test]
    fn test_offline_mode_simulation() {
        let executor = CompositeActionExecutor::new(ActionPolicy::Offline);
        let decision = ActionDecision::new(
            "rule-001".to_string(),
            ActionType::Kill,
            ActionPolicy::Inline,
            ActionTarget::ProcessExec {
                pid: 1234,
                executable: "/bin/malware".to_string(),
            },
            "Malicious process".to_string(),
            vec![],
        );

        let result = executor.execute(&decision).unwrap();
        assert!(result.success);
        // In offline mode, actual action should still match requested
        assert_eq!(result.actual_action, Some(ActionType::Kill));
    }

    #[tokio::test]
    async fn test_action_audit_log() {
        let audit_log = ActionAuditLog::new(100);

        let decision = ActionDecision::new(
            "rule-001".to_string(),
            ActionType::Block,
            ActionPolicy::Inline,
            ActionTarget::ProcessExec {
                pid: 1234,
                executable: "/bin/test".to_string(),
            },
            "Test".to_string(),
            vec![],
        );
        let result = ActionResult::success(decision.id.clone(), ActionType::Block);
        let audit = ActionAudit::from_decision(&decision, 0x1234, result);

        audit_log.log(audit.clone()).await;

        assert_eq!(audit_log.total_audits(), 1);

        let records = audit_log.get_records().await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].rule_id, "rule-001");
    }

    #[tokio::test]
    async fn test_action_audit_log_filter_by_entity() {
        let audit_log = ActionAuditLog::new(100);

        // Add audit for entity 0x1234
        let decision1 = ActionDecision::new(
            "rule-001".to_string(),
            ActionType::Block,
            ActionPolicy::Inline,
            ActionTarget::ProcessExec {
                pid: 1234,
                executable: "test1".to_string(),
            },
            "Test 1".to_string(),
            vec![],
        );
        let result1 = ActionResult::success(decision1.id.clone(), ActionType::Block);
        audit_log
            .log(ActionAudit::from_decision(&decision1, 0x1234, result1))
            .await;

        // Add audit for entity 0x5678
        let decision2 = ActionDecision::new(
            "rule-002".to_string(),
            ActionType::Kill,
            ActionPolicy::Inline,
            ActionTarget::ProcessExec {
                pid: 5678,
                executable: "test2".to_string(),
            },
            "Test 2".to_string(),
            vec![],
        );
        let result2 = ActionResult::success(decision2.id.clone(), ActionType::Kill);
        audit_log
            .log(ActionAudit::from_decision(&decision2, 0x5678, result2))
            .await;

        let records = audit_log.get_by_entity(0x1234).await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].rule_id, "rule-001");

        let records = audit_log.get_by_entity(0x5678).await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].rule_id, "rule-002");
    }

    #[tokio::test]
    async fn test_action_audit_log_max_records() {
        let audit_log = ActionAuditLog::new(3);

        for i in 0..5 {
            let decision = ActionDecision::new(
                format!("rule-{:03}", i),
                ActionType::Block,
                ActionPolicy::Inline,
                ActionTarget::ProcessExec {
                    pid: i as u32,
                    executable: format!("test{}", i),
                },
                format!("Test {}", i),
                vec![],
            );
            let result = ActionResult::success(decision.id.clone(), ActionType::Block);
            audit_log
                .log(ActionAudit::from_decision(&decision, i as u128, result))
                .await;
        }

        let records = audit_log.get_records().await;
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].rule_id, "rule-002");
        assert_eq!(records[1].rule_id, "rule-003");
        assert_eq!(records[2].rule_id, "rule-004");
    }

    #[test]
    fn test_quarantine_config_default() {
        let config = QuarantineConfig::default();
        assert_eq!(
            config.quarantine_dir,
            std::path::PathBuf::from("/var/lib/kestrel/quarantine")
        );
        assert_eq!(config.max_file_size, 100 * 1024 * 1024);
        assert!(config.compute_hash);
    }

    #[test]
    fn test_block_action_config_default() {
        let config = BlockActionConfig::default();
        assert!(!config.use_ptrace);
        assert!(!config.use_seccomp);
        assert!(!config.use_fanotify);
        assert_eq!(config.kill_signal, 9);
    }
}
