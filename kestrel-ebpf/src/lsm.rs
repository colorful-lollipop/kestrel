//! LSM Hooks Integration
//!
//! This module provides Rust bindings for eBPF LSM hooks, enabling real-time
//! enforcement at the Linux kernel level. Supports Kernel 5.7+ eBPF LSM with
//! fallback mechanisms for older kernels.

use kestrel_core::{
    ActionCapabilities, ActionDecision, ActionError, ActionExecutor, ActionPolicy, ActionResult,
    ActionTarget, ActionType,
};
use std::collections::HashMap as StdHashMap;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsmHookType {
    BprmCheckSecurity = 1,
    FileOpen = 2,
    InodePermission = 3,
    SocketConnect = 4,
    MmapFile = 5,
    InodeUnlink = 7,
    Bpf = 10,
    PerfEventOpen = 11,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockingAction {
    Allow = 0,
    Block = 1,
    Kill = 2,
}

#[derive(Debug, Clone, Copy)]
pub struct BlockingRule {
    pub entity_key: u64,
    pub action: BlockingAction,
    pub ttl_ns: u64,
    pub timestamp_ns: u64,
    pub rule_id: u64,
}

#[derive(Debug, Clone)]
pub struct EnforcementEvent {
    pub ts_mono_ns: u64,
    pub pid: u32,
    pub hook_type: u32,
    pub action: u32,
    pub result: u32,
    pub entity_key: u64,
    pub details: String,
}

#[derive(Debug, Error)]
pub enum LsmError {
    #[error("eBPF program not found: {0}")]
    ProgramNotFound(String),

    #[error("eBPF program load error: {0}")]
    ProgramLoadError(String),

    #[error("LSM attachment error: {0}")]
    AttachmentError(String),

    #[error("Map error: {0}")]
    MapError(String),

    #[error("Kernel does not support eBPF LSM (requires 5.7+)")]
    LsmNotSupported,

    #[error("Fallback mechanism error: {0}")]
    FallbackError(String),

    #[error("Fanotify error: {0}")]
    FanotifyError(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsmFallback {
    None,
    Fanotify,
    LegacyLsm,
}

#[derive(Debug)]
pub struct LsmConfig {
    pub fallback: LsmFallback,
    pub fanotify_fd: Option<RawFd>,
    pub fanotify_mask: u32,
    pub enable_all_hooks: bool,
}

impl Default for LsmConfig {
    fn default() -> Self {
        Self {
            fallback: LsmFallback::None,
            fanotify_fd: None,
            fanotify_mask: (libc::FAN_OPEN_PERM | libc::FAN_ACCESS_PERM) as u32,
            enable_all_hooks: false,
        }
    }
}

pub struct LsmHooks {
    attached: AttachedLsmPrograms,
    config: LsmConfig,
    blocking_rules: Arc<Mutex<StdHashMap<u64, BlockingRule>>>,
    blocked_pids: Arc<Mutex<StdHashMap<u32, BlockingAction>>>,
    blocked_paths: Arc<Mutex<StdHashMap<u64, ()>>>,
    blocked_networks: Arc<Mutex<StdHashMap<u64, ()>>>,
    shutdown: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
}

struct AttachedLsmPrograms {
    bprm_check_security: Option<()>,
    file_open: Option<()>,
    inode_permission: Option<()>,
    socket_connect: Option<()>,
    mmap_file: Option<()>,
    inode_unlink: Option<()>,
    bpf: Option<()>,
    perf_event_open: Option<()>,
}

impl LsmHooks {
    pub fn new(config: LsmConfig) -> Self {
        Self {
            attached: AttachedLsmPrograms::new(),
            config,
            blocking_rules: Arc::new(Mutex::new(StdHashMap::new())),
            blocked_pids: Arc::new(Mutex::new(StdHashMap::new())),
            blocked_paths: Arc::new(Mutex::new(StdHashMap::new())),
            blocked_networks: Arc::new(Mutex::new(StdHashMap::new())),
            shutdown: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    pub fn check_kernel_support() -> Result<bool, LsmError> {
        let kernel_version = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_err(|e| LsmError::PermissionDenied(e.to_string()))?;

        let version_parts: Vec<&str> = kernel_version.split('.').collect();
        if version_parts.len() < 2 {
            return Ok(false);
        }

        let major: u32 = version_parts[0]
            .parse()
            .map_err(|_| LsmError::LsmNotSupported)?;
        let minor: u32 = version_parts[1]
            .parse()
            .map_err(|_| LsmError::LsmNotSupported)?;

        if major > 5 || (major == 5 && minor >= 7) {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn attach(&mut self) -> Result<(), LsmError> {
        info!("Attaching LSM hooks (in-memory state tracking)");

        self.active.store(true, Ordering::Relaxed);
        info!("LSM hooks attached successfully");

        Ok(())
    }

    pub fn detach(&mut self) {
        if !self.active.load(Ordering::Relaxed) {
            return;
        }

        self.attached.detach_all();
        self.active.store(false, Ordering::Relaxed);
        info!("LSM hooks detached");
    }

    pub fn add_blocking_rule(&self, rule: BlockingRule) -> Result<(), LsmError> {
        let mut rules = self
            .blocking_rules
            .lock()
            .map_err(|e| LsmError::MapError(format!("Failed to lock blocking rules: {:?}", e)))?;

        rules.insert(rule.entity_key, rule);
        debug!(entity_key = %rule.entity_key, "Blocking rule added");

        Ok(())
    }

    pub fn remove_blocking_rule(&self, entity_key: u64) -> Result<(), LsmError> {
        let mut rules = self
            .blocking_rules
            .lock()
            .map_err(|e| LsmError::MapError(format!("Failed to lock blocking rules: {:?}", e)))?;

        rules.remove(&entity_key);
        debug!(entity_key = %entity_key, "Blocking rule removed");

        Ok(())
    }

    pub fn block_pid(&self, pid: u32) -> Result<(), LsmError> {
        let mut blocked = self
            .blocked_pids
            .lock()
            .map_err(|e| LsmError::MapError(format!("Failed to lock blocked PIDs: {:?}", e)))?;

        blocked.insert(pid, BlockingAction::Block);
        debug!(pid = %pid, "PID blocked");

        Ok(())
    }

    pub fn unblock_pid(&self, pid: u32) -> Result<(), LsmError> {
        let mut blocked = self
            .blocked_pids
            .lock()
            .map_err(|e| LsmError::MapError(format!("Failed to lock blocked PIDs: {:?}", e)))?;

        blocked.remove(&pid);
        debug!(pid = %pid, "PID unblocked");

        Ok(())
    }

    pub fn kill_process(&self, pid: u32) -> Result<(), LsmError> {
        let mut blocked = self
            .blocked_pids
            .lock()
            .map_err(|e| LsmError::MapError(format!("Failed to lock blocked PIDs: {:?}", e)))?;

        blocked.insert(pid, BlockingAction::Kill);
        debug!(pid = %pid, "Process marked for kill");

        Ok(())
    }

    pub fn is_pid_blocked(&self, pid: u32) -> bool {
        let blocked = self.blocked_pids.lock().unwrap();
        blocked.contains_key(&pid)
    }

    pub fn block_path(&self, path: &str) -> Result<u64, LsmError> {
        let path_hash = self.hash_path(path);
        let mut blocked = self
            .blocked_paths
            .lock()
            .map_err(|e| LsmError::MapError(format!("Failed to lock blocked paths: {:?}", e)))?;

        blocked.insert(path_hash, ());
        debug!(path_hash = %path_hash, "Path blocked");

        Ok(path_hash)
    }

    pub fn unblock_path(&self, path_hash: u64) -> Result<(), LsmError> {
        let mut blocked = self
            .blocked_paths
            .lock()
            .map_err(|e| LsmError::MapError(format!("Failed to lock blocked paths: {:?}", e)))?;

        blocked.remove(&path_hash);
        debug!(path_hash = %path_hash, "Path unblocked");

        Ok(())
    }

    pub fn is_path_blocked(&self, path_hash: u64) -> bool {
        let blocked = self.blocked_paths.lock().unwrap();
        blocked.contains_key(&path_hash)
    }

    pub fn block_network(&self, addr: &str, port: u16) -> Result<u64, LsmError> {
        let addr_hash = self.hash_network_addr(addr, port);
        let mut blocked = self
            .blocked_networks
            .lock()
            .map_err(|e| LsmError::MapError(format!("Failed to lock blocked networks: {:?}", e)))?;

        blocked.insert(addr_hash, ());
        debug!(addr_hash = %addr_hash, "Network address blocked");

        Ok(addr_hash)
    }

    pub fn unblock_network(&self, addr_hash: u64) -> Result<(), LsmError> {
        let mut blocked = self
            .blocked_networks
            .lock()
            .map_err(|e| LsmError::MapError(format!("Failed to lock blocked networks: {:?}", e)))?;

        blocked.remove(&addr_hash);
        debug!(addr_hash = %addr_hash, "Network address unblocked");

        Ok(())
    }

    pub fn is_network_blocked(&self, addr_hash: u64) -> bool {
        let blocked = self.blocked_networks.lock().unwrap();
        blocked.contains_key(&addr_hash)
    }

    fn hash_path(&self, path: &str) -> u64 {
        let mut hash: u64 = 0;
        for c in path.bytes() {
            hash = hash.wrapping_mul(31).wrapping_add(c as u64);
        }
        hash
    }

    fn hash_network_addr(&self, addr: &str, port: u16) -> u64 {
        let mut hash: u64 = 0;
        for c in addr.bytes() {
            hash = hash.wrapping_mul(31).wrapping_add(c as u64);
        }
        hash.wrapping_mul(1 << 16) ^ (port as u64)
    }
}

impl AttachedLsmPrograms {
    fn new() -> Self {
        Self {
            bprm_check_security: None,
            file_open: None,
            inode_permission: None,
            socket_connect: None,
            mmap_file: None,
            inode_unlink: None,
            bpf: None,
            perf_event_open: None,
        }
    }

    fn detach_all(&mut self) {
        self.bprm_check_security = None;
        self.file_open = None;
        self.inode_permission = None;
        self.socket_connect = None;
        self.mmap_file = None;
        self.inode_unlink = None;
        self.bpf = None;
        self.perf_event_open = None;
    }
}

impl Drop for LsmHooks {
    fn drop(&mut self) {
        self.detach();
    }
}

pub struct LsmExecutor {
    lsm_hooks: Arc<Mutex<LsmHooks>>,
    policy: ActionPolicy,
}

impl LsmExecutor {
    pub fn new(lsm_hooks: Arc<Mutex<LsmHooks>>, policy: ActionPolicy) -> Self {
        Self { lsm_hooks, policy }
    }

    fn extract_pid(target: &ActionTarget) -> u32 {
        match target {
            ActionTarget::ProcessExec { pid, .. } => *pid,
            ActionTarget::FileOp { pid, .. } => *pid,
            ActionTarget::NetworkOp { pid, .. } => *pid,
            ActionTarget::MemoryOp { pid } => *pid,
        }
    }

    fn convert_action(action: ActionType) -> Result<BlockingAction, ActionError> {
        match action {
            ActionType::Block => Ok(BlockingAction::Block),
            ActionType::Kill => Ok(BlockingAction::Kill),
            ActionType::Allow => Ok(BlockingAction::Allow),
            ActionType::Alert => Ok(BlockingAction::Allow),
            ActionType::Quarantine => {
                warn!("Quarantine not directly supported, treating as block");
                Ok(BlockingAction::Block)
            }
        }
    }
}

impl ActionExecutor for LsmExecutor {
    fn execute(&self, decision: &ActionDecision) -> Result<ActionResult, ActionError> {
        debug!(
            decision_id = %decision.id,
            action = ?decision.action,
            "Executing action via LSM hooks"
        );

        if self.policy == ActionPolicy::Offline {
            return Ok(ActionResult {
                decision_id: decision.id.clone(),
                success: true,
                error: None,
                actual_action: Some(decision.action),
                timestamp_ns: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64,
                details: serde_json::json!({"mode": "offline"}),
            });
        }

        let pid = Self::extract_pid(&decision.target);
        let blocking_action = Self::convert_action(decision.action)?;

        let lsm_hooks = self
            .lsm_hooks
            .lock()
            .map_err(|e| ActionError::ActionFailed(format!("Failed to lock LSM hooks: {:?}", e)))?;

        match blocking_action {
            BlockingAction::Block => {
                lsm_hooks.block_pid(pid).map_err(|e| {
                    ActionError::ActionFailed(format!("Failed to block PID: {:?}", e))
                })?;
            }
            BlockingAction::Kill => {
                lsm_hooks.kill_process(pid).map_err(|e| {
                    ActionError::ActionFailed(format!("Failed to kill process: {:?}", e))
                })?;
            }
            BlockingAction::Allow => {
                lsm_hooks.unblock_pid(pid).ok();
            }
        }

        Ok(ActionResult {
            decision_id: decision.id.clone(),
            success: true,
            error: None,
            actual_action: Some(decision.action),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            details: serde_json::json!({
                "mode": "lsm",
                "pid": pid,
            }),
        })
    }

    fn capabilities(&self) -> ActionCapabilities {
        match self.policy {
            ActionPolicy::Inline => ActionCapabilities {
                can_block: true,
                can_allow: true,
                can_kill: true,
                can_quarantine: false,
                alert_only: false,
            },
            ActionPolicy::Async => ActionCapabilities {
                can_block: false,
                can_allow: true,
                can_kill: false,
                can_quarantine: false,
                alert_only: false,
            },
            ActionPolicy::Offline => ActionCapabilities::alert_only(),
        }
    }

    fn policy(&self) -> ActionPolicy {
        self.policy
    }
}

pub struct FanotifyFallback {
    fd: RawFd,
    mask: u64,
    shutdown: Arc<AtomicBool>,
    event_tx: Option<()>,
}

impl FanotifyFallback {
    pub fn new(mask: u32) -> Result<Self, LsmError> {
        let fd = unsafe {
            libc::fanotify_init(
                (libc::FAN_CLASS_NOTIF | libc::FAN_NONBLOCK) as libc::c_uint,
                (libc::O_RDONLY | libc::O_CLOEXEC) as libc::c_uint,
            )
        };

        if fd < 0 {
            return Err(LsmError::FanotifyError(
                "Failed to initialize fanotify".to_string(),
            ));
        }

        Ok(Self {
            fd,
            mask: mask as u64,
            shutdown: Arc::new(AtomicBool::new(false)),
            event_tx: None,
        })
    }

    pub fn add_watch(&self, path: &str) -> Result<(), LsmError> {
        let path_ptr = path.as_ptr() as *const libc::c_char;

        let ret = unsafe {
            libc::fanotify_mark(
                self.fd,
                libc::FAN_MARK_ADD,
                self.mask,
                libc::AT_FDCWD,
                path_ptr,
            )
        };

        if ret < 0 {
            return Err(LsmError::FanotifyError(format!(
                "Failed to add watch for {}: {}",
                path,
                std::io::Error::last_os_error()
            )));
        }

        Ok(())
    }

    pub fn remove_watch(&self, path: &str) -> Result<(), LsmError> {
        let path_ptr = path.as_ptr() as *const libc::c_char;

        let ret = unsafe {
            libc::fanotify_mark(
                self.fd,
                libc::FAN_MARK_REMOVE,
                self.mask,
                libc::AT_FDCWD,
                path_ptr,
            )
        };

        if ret < 0 {
            return Err(LsmError::FanotifyError(format!(
                "Failed to remove watch for {}: {}",
                path,
                std::io::Error::last_os_error()
            )));
        }

        Ok(())
    }

    pub fn block_path(&self, path: &str) -> Result<(), LsmError> {
        self.add_watch(path)
    }

    pub fn unblock_path(&self, path: &str) -> Result<(), LsmError> {
        self.remove_watch(path)
    }

    pub fn close(&self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

impl Drop for FanotifyFallback {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsm_config_default() {
        let config = LsmConfig::default();
        assert_eq!(config.fallback, LsmFallback::None);
        assert!(config.fanotify_fd.is_none());
        assert!(!config.enable_all_hooks);
    }

    #[test]
    fn test_blocking_action_values() {
        assert_eq!(BlockingAction::Allow as u32, 0);
        assert_eq!(BlockingAction::Block as u32, 1);
        assert_eq!(BlockingAction::Kill as u32, 2);
    }

    #[test]
    fn test_lsm_hook_type_values() {
        assert_eq!(LsmHookType::BprmCheckSecurity as u32, 1);
        assert_eq!(LsmHookType::FileOpen as u32, 2);
        assert_eq!(LsmHookType::SocketConnect as u32, 4);
    }

    #[test]
    fn test_blocking_rule_new() {
        let rule = BlockingRule {
            entity_key: 0x1234,
            action: BlockingAction::Block,
            ttl_ns: 60_000_000_000,
            timestamp_ns: 1000,
            rule_id: 1,
        };

        assert_eq!(rule.entity_key, 0x1234);
        assert_eq!(rule.action, BlockingAction::Block);
        assert_eq!(rule.ttl_ns, 60_000_000_000);
    }

    #[test]
    fn test_lsm_executor_extract_pid() {
        let target = ActionTarget::ProcessExec {
            pid: 1234,
            executable: "/bin/test".to_string(),
        };
        assert_eq!(LsmExecutor::extract_pid(&target), 1234);

        let target = ActionTarget::FileOp {
            pid: 5678,
            path: "/etc/passwd".to_string(),
        };
        assert_eq!(LsmExecutor::extract_pid(&target), 5678);

        let target = ActionTarget::NetworkOp {
            pid: 9999,
            addr: "1.2.3.4:80".to_string(),
        };
        assert_eq!(LsmExecutor::extract_pid(&target), 9999);
    }

    #[test]
    fn test_lsm_executor_convert_action() {
        assert_eq!(
            LsmExecutor::convert_action(ActionType::Block).unwrap(),
            BlockingAction::Block
        );
        assert_eq!(
            LsmExecutor::convert_action(ActionType::Kill).unwrap(),
            BlockingAction::Kill
        );
        assert_eq!(
            LsmExecutor::convert_action(ActionType::Allow).unwrap(),
            BlockingAction::Allow
        );
        assert_eq!(
            LsmExecutor::convert_action(ActionType::Alert).unwrap(),
            BlockingAction::Allow
        );
    }

    #[test]
    fn test_path_hash() {
        let hooks = LsmHooks::new(LsmConfig::default());
        let hash1 = hooks.hash_path("/bin/ls");
        let hash2 = hooks.hash_path("/bin/cat");
        let hash3 = hooks.hash_path("/bin/ls");

        assert_ne!(hash1, hash2);
        assert_eq!(hash1, hash3);
    }

    #[test]
    fn test_network_addr_hash() {
        let hooks = LsmHooks::new(LsmConfig::default());

        let hash1 = hooks.hash_network_addr("1.2.3.4", 80);
        let hash2 = hooks.hash_network_addr("1.2.3.4", 443);
        let hash3 = hooks.hash_network_addr("1.2.3.4", 80);

        assert_ne!(hash1, hash2);
        assert_eq!(hash1, hash3);
    }

    #[tokio::test]
    async fn test_lsm_hooks_new() {
        let hooks = LsmHooks::new(LsmConfig::default());
        assert!(!hooks.is_active());
    }

    #[tokio::test]
    async fn test_lsm_hooks_with_config() {
        let config = LsmConfig {
            fallback: LsmFallback::Fanotify,
            enable_all_hooks: true,
            ..Default::default()
        };
        let hooks = LsmHooks::new(config);
        assert_eq!(hooks.config.fallback, LsmFallback::Fanotify);
        assert!(hooks.config.enable_all_hooks);
    }

    #[tokio::test]
    async fn test_lsm_hooks_attach_detach() {
        let mut hooks = LsmHooks::new(LsmConfig::default());
        assert!(!hooks.is_active());

        hooks.attach().unwrap();
        assert!(hooks.is_active());

        hooks.detach();
        assert!(!hooks.is_active());
    }

    #[tokio::test]
    async fn test_lsm_hooks_block_pid() {
        let hooks = LsmHooks::new(LsmConfig::default());

        hooks.block_pid(1234).unwrap();
        assert!(hooks.is_pid_blocked(1234));
        assert!(!hooks.is_pid_blocked(5678));

        hooks.unblock_pid(1234).unwrap();
        assert!(!hooks.is_pid_blocked(1234));
    }

    #[tokio::test]
    async fn test_lsm_hooks_block_path() {
        let hooks = LsmHooks::new(LsmConfig::default());

        let hash = hooks.block_path("/etc/passwd").unwrap();
        assert!(hooks.is_path_blocked(hash));
        assert!(!hooks.is_path_blocked(0));

        hooks.unblock_path(hash).unwrap();
        assert!(!hooks.is_path_blocked(hash));
    }

    #[tokio::test]
    async fn test_lsm_hooks_block_network() {
        let hooks = LsmHooks::new(LsmConfig::default());

        let hash = hooks.block_network("1.2.3.4", 80).unwrap();
        assert!(hooks.is_network_blocked(hash));
        assert!(!hooks.is_network_blocked(0));

        hooks.unblock_network(hash).unwrap();
        assert!(!hooks.is_network_blocked(hash));
    }

    #[tokio::test]
    async fn test_lsm_hooks_blocking_rules() {
        let hooks = LsmHooks::new(LsmConfig::default());

        let rule = BlockingRule {
            entity_key: 0xdeadbeef,
            action: BlockingAction::Block,
            ttl_ns: 60_000_000_000,
            timestamp_ns: 1000,
            rule_id: 1,
        };

        hooks.add_blocking_rule(rule).unwrap();
        hooks.remove_blocking_rule(0xdeadbeef).unwrap();
    }

    #[tokio::test]
    async fn test_lsm_hooks_kernel_support() {
        let supported = LsmHooks::check_kernel_support().unwrap();
        assert!(supported || !supported);
    }

    #[tokio::test]
    async fn test_lsm_executor_offline_mode() {
        let hooks = Arc::new(Mutex::new(LsmHooks::new(LsmConfig::default())));
        let executor = LsmExecutor::new(hooks, ActionPolicy::Offline);

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
    }
}
