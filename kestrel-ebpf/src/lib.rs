//! Kestrel eBPF Event Collector
//!
//! This module provides eBPF-based event collection for Linux systems.
//! Uses clang for eBPF compilation and libbpf via Aya for loading.

mod normalize;
mod pushdown;

pub use normalize::EventNormalizer;
pub use pushdown::InterestPushdown;

use anyhow::Result;
use aya::{maps::RingBuf, programs::Program, Ebpf, EbpfLoader};
use kestrel_core::EventBus;
use kestrel_event::Event;
use kestrel_schema::SchemaRegistry;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Configuration for eBPF collector
#[derive(Debug, Clone)]
pub struct EbpfConfig {
    /// Enable process event collection
    pub enable_process: bool,

    /// Enable file event collection
    pub enable_file: bool,

    /// Enable network event collection
    pub enable_network: bool,

    /// Channel size for events
    pub event_channel_size: usize,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            enable_process: true,
            enable_file: false,    // Not implemented yet
            enable_network: false, // Not implemented yet
            event_channel_size: 4096,
        }
    }
}

/// eBPF event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EbpfEventType {
    /// Process exec (execve/execveat)
    ProcessExec,

    /// Process exit
    ProcessExit,

    /// File open
    FileOpen,

    /// File rename
    FileRename,

    /// File unlink (delete)
    FileUnlink,

    /// Network connect
    NetworkConnect,

    /// Network send data
    NetworkSend,
}

/// Raw eBPF event from kernel (legacy format for compatibility)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RawEbpfEvent {
    pub event_type: u32,
    pub ts_mono_ns: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub exit_code: i32,
    pub path_len: u32,
    pub cmdline_len: u32,
    pub addr_len: u32,
    pub entity_key: u64,
}

/// Raw eBPF exec event from kernel (matches C struct)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
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

/// eBPF collector error
#[derive(Debug, Error)]
pub enum EbpfError {
    #[error("Failed to load eBPF program: {0}")]
    LoadError(String),

    #[error("Failed to attach eBPF program: {0}")]
    AttachError(String),

    #[error("Failed to read eBPF event: {0}")]
    EventReadError(String),

    #[error("Normalization error: {0}")]
    NormalizationError(String),

    #[error("Permission denied (requires root/CAP_BPF)")]
    PermissionDenied,

    #[error("Unsupported kernel version: {0}")]
    UnsupportedKernel(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("eBPF object file not found: {0}")]
    ObjectNotFound(String),

    #[error("Aya error: {0}")]
    Aya(String),
}

impl From<aya::EbpfError> for EbpfError {
    fn from(err: aya::EbpfError) -> Self {
        EbpfError::Aya(format!("{}", err))
    }
}

/// eBPF event collector
///
/// Manages eBPF programs and collects events from the kernel via ring buffer.
pub struct EbpfCollector {
    /// eBPF object (wrapped in Arc<Mutex> for safe sharing with async tasks)
    ebpf: Arc<Mutex<Ebpf>>,

    /// Configuration
    config: EbpfConfig,

    /// Schema registry
    schema: Arc<SchemaRegistry>,

    /// Event normalizer
    normalizer: EventNormalizer,

    /// Event channel sender
    event_tx: mpsc::Sender<Event>,

    /// Running flag
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,

    /// Event ID counter (atomic for thread safety)
    event_id_counter: Arc<std::sync::atomic::AtomicU64>,

    /// Polling task handle (for graceful shutdown)
    polling_task: Option<tokio::task::JoinHandle<()>>,
}

impl EbpfCollector {
    /// Create a new eBPF collector
    pub async fn new(
        config: EbpfConfig,
        schema: Arc<SchemaRegistry>,
        event_bus: &EventBus,
    ) -> Result<Self, EbpfError> {
        info!("Initializing eBPF collector");

        // Check if running as root
        if !nix::unistd::Uid::effective().is_root() {
            return Err(EbpfError::PermissionDenied);
        }

        // Load eBPF program
        let ebpf = Self::load_ebpf()?;

        // Create event channel
        let (event_tx, mut event_rx) = mpsc::channel(config.event_channel_size);

        // Create normalizer
        let normalizer = EventNormalizer::new(schema.clone());

        // Spawn event processing task
        let event_bus_handle = event_bus.handle();
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                if let Err(e) = event_bus_handle.publish(event).await {
                    error!(error = %e, "Failed to publish event to EventBus");
                }
            }
        });

        let collector = Self {
            ebpf: Arc::new(Mutex::new(ebpf)),
            config,
            schema,
            normalizer,
            event_tx,
            running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            event_id_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            polling_task: None,
        };

        info!("eBPF collector initialized successfully");
        Ok(collector)
    }

    /// Load eBPF program into kernel
    fn load_ebpf() -> Result<Ebpf, EbpfError> {
        // Try to load the compiled eBPF object file
        // The build script compiles to OUT_DIR/main.bpf.o
        let out_dir = PathBuf::from(
            std::env::var("OUT_DIR")
                .map_err(|e| EbpfError::LoadError(format!("OUT_DIR not set: {}", e)))?,
        );

        let obj_path = out_dir.join("main.bpf.o");

        if !obj_path.exists() {
            // Try pre-built location (for when build.rs was skipped in tests)
            let alt_path = PathBuf::from("target/bpf/main.bpf.o");
            if alt_path.exists() {
                info!("Using pre-built eBPF object from target/bpf/main.bpf.o");
                return Self::load_ebpf_from_path(&alt_path);
            }

            return Err(EbpfError::ObjectNotFound(obj_path.display().to_string()));
        }

        Self::load_ebpf_from_path(&obj_path)
    }

    fn load_ebpf_from_path(path: &PathBuf) -> Result<Ebpf, EbpfError> {
        info!(path = %path.display(), "Loading eBPF program");

        // Read the object file
        let mut file = File::open(path)
            .map_err(|e| EbpfError::LoadError(format!("Failed to open eBPF object: {}", e)))?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| EbpfError::LoadError(format!("Failed to read eBPF object: {}", e)))?;

        // Load eBPF object
        let ebpf = EbpfLoader::new()
            .load(&data)
            .map_err(|e| EbpfError::LoadError(format!("Failed to load eBPF: {}", e)))?;

        info!("eBPF program loaded successfully");
        Ok(ebpf)
    }

    /// Start collecting events
    pub async fn start(&mut self) -> Result<(), EbpfError> {
        info!("Starting eBPF event collection");

        // Attach tracepoint for execve
        if self.config.enable_process {
            self.attach_execve_tracepoint()?;
        }

        // Start ring buffer polling
        self.start_ringbuf_polling().await?;

        info!("eBPF event collection started");
        Ok(())
    }

    /// Attach execve tracepoint
    fn attach_execve_tracepoint(&mut self) -> Result<(), EbpfError> {
        info!("Attaching execve tracepoint");

        let mut ebpf = self
            .ebpf
            .lock()
            .map_err(|e| EbpfError::Aya(format!("Mutex lock error: {}", e)))?;

        // Load the tracepoint program
        let program: &mut Program = ebpf
            .program_mut("handle_execve")
            .ok_or_else(|| EbpfError::AttachError("handle_execve program not found".to_string()))?;

        // Try to downcast to TracePoint using TryInto trait
        use std::convert::TryInto;
        let tracepoint_program: &mut aya::programs::TracePoint =
            program.try_into().map_err(|_| {
                EbpfError::AttachError("handle_execve is not a TracePoint program".to_string())
            })?;

        // Attach to sys_enter_execve tracepoint
        tracepoint_program
            .load()
            .map_err(|e| EbpfError::AttachError(format!("Failed to load tracepoint: {}", e)))?;

        tracepoint_program
            .attach("syscalls", "sys_enter_execve")
            .map_err(|e| EbpfError::AttachError(format!("Failed to attach tracepoint: {}", e)))?;

        info!("execve tracepoint attached successfully");
        Ok(())
    }

    /// Start polling the ring buffer for events
    async fn start_ringbuf_polling(&mut self) -> Result<(), EbpfError> {
        info!("Starting ring buffer polling");

        // Set running flag
        self.running
            .store(true, std::sync::atomic::Ordering::Release);

        // Clone data for the polling task
        let running = self.running.clone();
        let event_tx = self.event_tx.clone();
        let event_id_counter = self.event_id_counter.clone();
        let normalizer = self.normalizer.clone();
        let ebpf = self.ebpf.clone();

        // Spawn the polling task
        let polling_task = tokio::spawn(async move {
            Self::ringbuf_poll_loop(ebpf, event_tx, event_id_counter, normalizer, running).await;
        });

        self.polling_task = Some(polling_task);

        info!("Ring buffer polling started successfully");
        Ok(())
    }

    /// Ring buffer polling loop
    async fn ringbuf_poll_loop(
        ebpf: Arc<Mutex<Ebpf>>,
        event_tx: mpsc::Sender<Event>,
        event_id_counter: Arc<std::sync::atomic::AtomicU64>,
        normalizer: EventNormalizer,
        running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        debug!("Ring buffer polling loop started");

        // Poll interval for backoff when no events available
        let poll_interval = std::time::Duration::from_millis(10);

        'outer: loop {
            // Check running flag at the start of each iteration
            if !running.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }

            // Scope the lock to ensure it's dropped before any await
            // Collect events into a vector, then send them after dropping the lock
            let events_to_send = {
                let ebpf_guard = ebpf.lock();
                if let Err(e) = ebpf_guard {
                    error!(error = %e, "Failed to lock eBPF mutex");
                    break 'outer;
                }
                let ebpf_ref = ebpf_guard.unwrap();

                // Get the ring buffer map
                let map = match ebpf_ref.map("events") {
                    Some(m) => m,
                    None => {
                        warn!("Ring buffer map 'events' not found, will retry...");
                        continue 'outer;
                    }
                };

                // Create the RingBuf - this borrows from the map/ebpf_ref
                let mut ring_buf = match RingBuf::try_from(map) {
                    Ok(rb) => rb,
                    Err(e) => {
                        error!(error = %e, "Failed to create RingBuf from map");
                        continue 'outer;
                    }
                };

                // Collect events from the ring buffer
                let mut events = Vec::new();

                while let Some(data) = ring_buf.next() {
                    // Parse the raw event
                    let exec_event: &ExecveEvent =
                        unsafe { &*(data.as_ptr() as *const ExecveEvent) };

                    // Generate event ID
                    let event_id =
                        event_id_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    // Normalize the execve event
                    match normalizer.normalize_execve_event(exec_event, event_id) {
                        Ok(normalized) => events.push(normalized),
                        Err(e) => warn!(error = %e, "Failed to normalize execve event"),
                    }
                }

                events
            };

            // Lock is dropped here, now we can safely await

            // Check if we have events to process
            let has_events = !events_to_send.is_empty();

            // Send all collected events
            for event in events_to_send {
                if let Err(e) = event_tx.send(event).await {
                    error!(error = %e, "Failed to send event to channel");
                }
            }

            // If no events were processed, sleep briefly to avoid busy-waiting
            if !has_events {
                tokio::time::sleep(poll_interval).await;
            }

            // Small yield to be fair to other tasks
            tokio::task::yield_now().await;
        }

        debug!("Ring buffer polling loop exiting");
    }

    /// Create a Kestrel Event from a raw execve event
    /// (Deprecated - normalization is now handled by EventNormalizer)
    #[deprecated(note = "Use EventNormalizer::normalize instead")]
    fn create_event_from_execve(raw: &ExecveEvent, event_id: u64) -> Option<Event> {
        // Extract command line from args
        let cmdline = Self::extract_cstring::<512>(&raw.args)
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        // Extract comm (process name)
        let comm = Self::extract_cstring::<16>(&raw.comm)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Build entity key from PID and timestamp
        let entity_key = ((raw.pid as u128) << 32) | (raw.ts_mono_ns as u128);

        // Build the event
        Event::builder()
            .event_type(1) // exec event type
            .ts_mono(raw.ts_mono_ns)
            .ts_wall(raw.ts_mono_ns)
            .entity_key(entity_key)
            .field(1000, kestrel_schema::TypedValue::String(comm))
            .field(1001, kestrel_schema::TypedValue::String(cmdline))
            .field(1002, kestrel_schema::TypedValue::I64(raw.pid as i64))
            .field(1003, kestrel_schema::TypedValue::I64(raw.ppid as i64))
            .field(1004, kestrel_schema::TypedValue::I64(raw.uid as i64))
            .field(1005, kestrel_schema::TypedValue::I64(raw.gid as i64))
            .build()
            .ok()
    }

    /// Extract null-terminated C string from byte array
    fn extract_cstring<const N: usize>(arr: &[u8; N]) -> Option<String> {
        let mut end = 0;
        for (i, &byte) in arr.iter().enumerate() {
            if byte == 0 {
                end = i;
                break;
            }
            end = i + 1;
        }

        if end == 0 {
            return None;
        }

        String::from_utf8(arr[..end].to_vec()).ok()
    }

    /// Stop collecting events
    pub async fn stop(&mut self) -> Result<(), EbpfError> {
        info!("Stopping eBPF event collection");

        // Set running flag to false
        self.running
            .store(false, std::sync::atomic::Ordering::Release);

        // Wait for polling task to finish
        if let Some(task) = self.polling_task.take() {
            task.await
                .map_err(|e| EbpfError::Aya(format!("Failed to stop polling task: {}", e)))?;
        }

        // TODO: Detach eBPF programs

        info!("eBPF event collection stopped");
        Ok(())
    }

    /// Update interest pushdown based on loaded rules
    pub fn update_interests(&mut self, event_types: Vec<EbpfEventType>) {
        // TODO: Implement interest pushdown
        debug!(count = event_types.len(), "Updated interest pushdown");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_config_default() {
        let config = EbpfConfig::default();
        assert!(config.enable_process);
        assert!(!config.enable_file);
        assert!(!config.enable_network);
    }

    #[test]
    fn test_execve_event_size() {
        // Ensure the struct size matches what we expect
        // Actual size: 8 (ts) + 4*4 (pid/ppid/uid/gid/entity_key) + 16 + 256 + 512 = 816
        assert_eq!(std::mem::size_of::<ExecveEvent>(), 816);
    }
}
