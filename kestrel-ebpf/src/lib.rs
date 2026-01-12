//! eBPF Collector
//!
//! This module provides the main eBPF collector implementation for collecting
//! security events from the Linux kernel using eBPF programs.

mod executor;
mod lsm;
mod normalize;
mod programs;

pub use executor::{BlockStatus, EbpfExecutor, EbpfExecutorConfig, EbpfExecutorMetrics};
pub use lsm::{
    BlockingAction, BlockingRule, EnforcementEvent, FanotifyFallback, LsmConfig, LsmError,
    LsmExecutor, LsmFallback, LsmHookType, LsmHooks,
};
pub use normalize::EventNormalizer;
pub use programs::{AttachedPrograms, ProgramManager};

use aya::maps::HashMap;
use aya::Ebpf;
use aya::Pod;
use kestrel_event::Event;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EbpfEventType {
    ProcessExec,
    ProcessExit,
    FileOpen,
    FileRename,
    FileUnlink,
    NetworkConnect,
    NetworkSend,
}

#[derive(Debug, thiserror::Error)]
pub enum EbpfError {
    #[error("Program not found: {0}")]
    ProgramNotFound(String),

    #[error("Program error: {0}")]
    ProgramError(String),

    #[error("Map error: {0}")]
    MapError(String),

    #[error("Attachment error: {0}")]
    AttachmentError(String),

    #[error("Normalization error: {0}")]
    NormalizationError(String),

    #[error("Collection error: {0}")]
    CollectionError(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementAction {
    Allow,
    Block,
    Kill,
}

#[derive(Debug, Clone, Copy)]
pub struct EnforcementDecision {
    pub pid: u32,
    pub action: EnforcementAction,
    pub ttl_ns: u64,
    pub timestamp_ns: u64,
}

unsafe impl Pod for EnforcementDecision {}

impl EnforcementDecision {
    pub fn new(pid: u32, action: EnforcementAction, ttl_ns: u64) -> Self {
        Self {
            pid,
            action,
            ttl_ns,
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RawEbpfEvent {
    pub event_type: u32,
    pub ts_mono_ns: u64,
    pub entity_key: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub path_len: u32,
    pub cmdline_len: u32,
    pub exit_code: i32,
}

#[derive(Debug, Clone)]
pub struct ExecveEvent {
    pub ts_mono_ns: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub entity_key: u32,
    pub comm: [u8; 16],
    pub pathname: [u8; 256],
    pub args: [u8; 512],
}

pub struct EbpfCollector {
    ebpf: Arc<Mutex<Ebpf>>,
    attached: AttachedPrograms,
    event_tx: mpsc::Sender<Event>,
    shutdown: Arc<AtomicBool>,
    interests: Arc<std::sync::RwLock<HashSet<EbpfEventType>>>,
    normalizer: normalize::EventNormalizer,
    next_event_id: Arc<AtomicU64>,
    _polling_handle: Option<tokio::task::JoinHandle<()>>,
}

impl EbpfCollector {
    pub fn new(event_tx: mpsc::Sender<Event>, ebpf: Ebpf) -> Self {
        use kestrel_schema::SchemaRegistry;

        // Create schema registry for normalizer
        let schema = Arc::new(SchemaRegistry::new());

        Self {
            ebpf: Arc::new(Mutex::new(ebpf)),
            attached: AttachedPrograms::new(),
            event_tx,
            shutdown: Arc::new(AtomicBool::new(false)),
            interests: Arc::new(std::sync::RwLock::new(HashSet::new())),
            normalizer: normalize::EventNormalizer::new(schema),
            next_event_id: Arc::new(AtomicU64::new(1)),
            _polling_handle: None,
        }
    }

    pub async fn load(&mut self) -> Result<(), EbpfError> {
        info!("Loading eBPF programs");

        let mut programs = ProgramManager::new(self.ebpf.clone());
        programs.attach_process_programs()?;
        programs.attach_file_programs()?;
        programs.attach_network_programs()?;

        info!("eBPF programs loaded successfully");
        Ok(())
    }

    pub async fn start(&mut self) -> Result<(), EbpfError> {
        info!("Starting eBPF collector");

        let mut programs = ProgramManager::new(self.ebpf.clone());
        programs.attach_process_programs()?;
        programs.attach_file_programs()?;
        programs.attach_network_programs()?;

        // Start ring buffer polling
        let polling_handle = self.start_ringbuf_polling().await?;
        self._polling_handle = Some(polling_handle);

        info!("eBPF collector started");
        Ok(())
    }

    /// Start the ring buffer polling task
    ///
    /// This spawns an async task that continuously polls the ring buffer
    /// for events from eBPF programs, normalizes them, and sends them to EventBus.
    async fn start_ringbuf_polling(&self) -> Result<tokio::task::JoinHandle<()>, EbpfError> {
        use aya::maps::RingBuf;
        use std::mem::size_of;

        let ebpf_clone = self.ebpf.clone();
        let event_tx = self.event_tx.clone();
        let normalizer = self.normalizer.clone();
        let next_event_id = self.next_event_id.clone();
        let shutdown = self.shutdown.clone();
        let interests = self.interests.clone();

        let handle = tokio::task::spawn(async move {
            info!("Ring buffer polling task started");

            // Track if we've logged ring buffer error (avoid spam)
            let mut ringbuf_error_logged = false;

            // Polling loop
            loop {
                // Check shutdown flag
                if shutdown.load(Ordering::Relaxed) {
                    info!("Ring buffer polling received shutdown signal");
                    break;
                }

                // Check if process events are interesting
                let should_collect = interests
                    .read()
                    .unwrap()
                    .contains(&EbpfEventType::ProcessExec);

                if !should_collect {
                    // Sleep briefly if not interested
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    continue;
                }

                // Read from ring buffer (with lock held briefly)
                let event_data = {
                    let ebpf = ebpf_clone.lock().unwrap();
                    let ringbuf_result: Result<RingBuf<_>, _> = ebpf
                        .map("rb")
                        .ok_or_else(|| {
                            EbpfError::MapError("Ring buffer map 'rb' not found".to_string())
                        })
                        .and_then(|m| {
                            m.try_into()
                                .map_err(|e| EbpfError::MapError(format!("{:?}", e)))
                        });

                    match ringbuf_result {
                        Ok(mut ringbuf) => {
                            ringbuf_error_logged = false; // Reset on success
                                                          // Try to read next event
                            ringbuf.next().map(|item| {
                                let bytes: &[u8] = &item;
                                bytes.to_vec() // Copy data to release lock
                            })
                        }
                        Err(e) => {
                            // Log error only once
                            if !ringbuf_error_logged {
                                error!("Failed to access ring buffer: {}", e);
                                error!("Event collection will not work");
                                ringbuf_error_logged = true;
                            }
                            None
                        }
                    }
                }; // Lock released here

                // Process event (without lock)
                if let Some(bytes) = event_data {
                    let expected_size = size_of::<ExecveEvent>();

                    if bytes.len() != expected_size {
                        warn!(
                            expected = expected_size,
                            actual = bytes.len(),
                            "Ring buffer item size mismatch, skipping"
                        );
                        continue;
                    }

                    // Parse ExecveEvent from bytes
                    let exec_event: ExecveEvent =
                        unsafe { std::ptr::read(bytes.as_ptr() as *const ExecveEvent) };

                    debug!(
                        pid = exec_event.pid,
                        comm = ?std::str::from_utf8(&exec_event.comm),
                        "Received execve event from ring buffer"
                    );

                    // Assign event ID
                    let event_id = next_event_id.fetch_add(1, Ordering::Relaxed);

                    // Normalize event
                    match normalizer.normalize_execve_event(&exec_event, event_id) {
                        Ok(kestrel_event) => {
                            // Send to EventBus
                            if let Err(e) = event_tx.try_send(kestrel_event) {
                                // Channel full or closed
                                use tokio::sync::mpsc::error::TrySendError;
                                match e {
                                    TrySendError::Closed(_) => {
                                        error!("EventBus channel closed, stopping polling");
                                        break;
                                    }
                                    TrySendError::Full(_) => {
                                        // Channel full - log metric but don't block eBPF
                                        warn!(
                                            "EventBus channel full, dropping event (backpressure)"
                                        );
                                    }
                                }
                            } else {
                                debug!(
                                    event_id = event_id,
                                    pid = exec_event.pid,
                                    "Event sent to EventBus successfully"
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                pid = exec_event.pid,
                                "Failed to normalize execve event"
                            );
                        }
                    }
                } else {
                    // No events available, sleep briefly to avoid busy-wait
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                }
            }

            info!("Ring buffer polling task stopped");
        });

        Ok(handle)
    }

    pub async fn stop(&mut self) {
        info!("Stopping eBPF collector");

        // Set shutdown flag first
        self.shutdown.store(true, Ordering::Relaxed);

        // Wait for polling task to finish
        if let Some(handle) = self._polling_handle.take() {
            info!("Waiting for ring buffer polling task to finish...");
            match tokio::time::timeout(tokio::time::Duration::from_secs(5), handle).await {
                Ok(Ok(())) => {
                    info!("Ring buffer polling task stopped gracefully");
                }
                Ok(Err(e)) => {
                    warn!("Ring buffer polling task stopped with error: {:?}", e);
                }
                Err(_) => {
                    warn!("Ring buffer polling task did not stop within timeout, continuing");
                }
            }
        }

        // Detach eBPF programs
        self.attached.detach_all();

        let mut programs = ProgramManager::new(self.ebpf.clone());
        programs.detach_all().ok();

        info!("eBPF collector stopped");
    }

    pub fn set_enforcement(&self, decision: &EnforcementDecision) -> Result<(), EbpfError> {
        debug!(pid = decision.pid, action = ?decision.action, "Setting enforcement");

        let mut ebpf = self
            .ebpf
            .lock()
            .map_err(|e| EbpfError::ProgramError(format!("{:?}", e)))?;
        let map = ebpf
            .map_mut("enforcement_map")
            .ok_or_else(|| EbpfError::MapError("enforcement_map not found".to_string()))?;

        let mut hash_map: HashMap<_, u32, EnforcementDecision> = map
            .try_into()
            .map_err(|e| EbpfError::MapError(format!("{:?}", e)))?;

        hash_map.insert(&decision.pid, decision, 0).map_err(|e| {
            EbpfError::MapError(format!("Failed to insert into enforcement_map: {}", e))
        })?;

        debug!(pid = decision.pid, "Enforcement decision written to kernel");
        Ok(())
    }

    pub fn update_interests(&self, event_types: &[EbpfEventType]) {
        let mut interests = self.interests.write().unwrap();
        interests.clear();

        for event_type in event_types {
            debug!(?event_type, "Adding event type interest");
            interests.insert(*event_type);
        }

        debug!(count = interests.len(), "Updated event interests");
    }

    pub fn get_interests(&self) -> HashSet<EbpfEventType> {
        self.interests.read().unwrap().clone()
    }

    pub fn is_interesting(&self, event_type: EbpfEventType) -> bool {
        self.interests.read().unwrap().contains(&event_type)
    }

    pub fn ebpf(&self) -> &Arc<Mutex<Ebpf>> {
        &self.ebpf
    }
}

impl Drop for EbpfCollector {
    fn drop(&mut self) {
        if !self.shutdown.load(Ordering::Relaxed) {
            warn!("EbpfCollector dropped without calling stop()");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attached_programs_new() {
        let attached = AttachedPrograms::new();
        assert!(attached.execve_tracepoint.is_none());
        assert!(attached.lsm_bprm_check_security.is_none());
    }

    #[test]
    fn test_attached_programs_detach_all() {
        let mut attached = AttachedPrograms::new();
        attached.detach_all();
        assert!(attached.execve_tracepoint.is_none());
    }
}
