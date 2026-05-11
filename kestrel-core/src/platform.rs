//! Platform Abstraction Layer
//!
//! This module provides platform-agnostic abstractions for event collection,
//! enabling cross-platform development (Linux, macOS, Windows) and testing.
//!
//! # Key Types
//!
//! - [`EventCollector`] — Core trait for any event source (eBPF, replay, mock)
//! - [`PlatformInfo`] — Describes platform capabilities
//! - [`MockEventCollector`] — Generates synthetic events for testing
//! - [`ReplayEventCollector`] — Replays events from a binary log file

use async_trait::async_trait;
use kestrel_event::Event;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{info, warn};

// ============================================================================
// Platform Capability & Info
// ============================================================================

/// Platform capability flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlatformCapability {
    /// Can trace process execution
    ProcessTracing,
    /// Can trace file operations
    FileTracing,
    /// Can trace network operations
    NetworkTracing,
    /// Can perform inline blocking
    InlineBlocking,
    /// Supports LSM hooks
    LsmHooks,
    /// Supports kprobes
    Kprobes,
    /// Supports tracepoints
    Tracepoints,
    /// Supports perf events
    PerfEvents,
}

/// Platform information and capabilities
#[derive(Debug, Clone)]
pub struct PlatformInfo {
    /// Platform name (e.g., "linux", "macos", "mock")
    pub name: String,
    /// Platform version
    pub version: String,
    /// Kernel/OS version
    pub kernel_version: String,
    /// Supported capabilities
    pub capabilities: Vec<PlatformCapability>,
}

impl PlatformInfo {
    /// Check if a specific capability is supported
    pub fn has_capability(&self, cap: PlatformCapability) -> bool {
        self.capabilities.contains(&cap)
    }

    /// Create mock platform info for testing
    pub fn mock() -> Self {
        Self {
            name: "mock".into(),
            version: "1.0".into(),
            kernel_version: "5.15.0-mock".into(),
            capabilities: vec![
                PlatformCapability::ProcessTracing,
                PlatformCapability::FileTracing,
                PlatformCapability::Kprobes,
                PlatformCapability::Tracepoints,
            ],
        }
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Platform-related errors
#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("Capability not supported: {0:?}")]
    CapabilityNotSupported(PlatformCapability),

    #[error("Platform initialization failed: {0}")]
    InitializationError(String),

    #[error("Platform shutdown failed: {0}")]
    ShutdownError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Event channel closed")]
    ChannelClosed,

    #[error("Replay error: {0}")]
    ReplayError(String),
}

// ============================================================================
// EventCollector Trait
// ============================================================================

/// Core trait for event sources.
///
/// Any event source (eBPF, replay, mock, file-based) implements this trait.
/// The engine consumes events through this abstraction, decoupling it from
/// platform-specific collection mechanisms.
///
/// # Implementations
///
/// - [`MockEventCollector`] — For testing and development
/// - [`ReplayEventCollector`] — For offline replay
/// - `EbpfCollector` — For live Linux eBPF collection (in `kestrel-ebpf`)
///
/// # Example
///
/// ```ignore
/// let mut collector = MockEventCollector::generate_test_events(100);
/// let (tx, mut rx) = mpsc::channel(1024);
/// collector.start(tx).await?;
///
/// while let Some(event) = rx.recv().await {
///     // Process event
/// }
/// collector.stop().await?;
/// ```
#[async_trait]
pub trait EventCollector: Send + Sync {
    /// Start collecting events, sending them to the provided channel.
    ///
    /// The collector should spawn a background task that continuously
    /// sends events to `event_tx` until [`stop()`](EventCollector::stop) is called.
    async fn start(&mut self, event_tx: mpsc::Sender<Event>) -> Result<(), PlatformError>;

    /// Stop collecting events and clean up resources.
    async fn stop(&mut self) -> Result<(), PlatformError>;

    /// Human-readable name for this collector (e.g., "ebpf", "replay", "mock").
    fn name(&self) -> &str;

    /// Platform info, if applicable.
    fn platform_info(&self) -> Option<&PlatformInfo> {
        None
    }
}

// ============================================================================
// MockEventCollector
// ============================================================================

/// Mock event collector for testing and development.
///
/// Generates synthetic events and sends them through the channel.
/// Useful for:
/// - Unit and integration tests
/// - macOS/Windows development without eBPF
/// - Performance benchmarking
pub struct MockEventCollector {
    events: Vec<Event>,
    name: String,
    shutdown: Option<tokio::task::JoinHandle<()>>,
}

impl MockEventCollector {
    /// Create a new mock collector with the given events.
    pub fn new(events: Vec<Event>) -> Self {
        Self {
            events,
            name: "mock".into(),
            shutdown: None,
        }
    }

    /// Create a mock collector with a custom name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Generate a standard set of test events.
    ///
    /// Creates `count` events with sequential timestamps and
    /// cycling entity keys (0..3).
    pub fn generate_test_events(count: usize) -> Self {
        let events: Vec<Event> = (0..count)
            .map(|i| {
                let entity_key = (i as u128) % 4;
                let ts = (i as u64) * 1_000_000; // 1ms apart

                Event::builder()
                    .event_type(1) // ProcessExec
                    .ts_mono(ts)
                    .ts_wall(ts)
                    .entity_key(entity_key)
                    .event_id(i as u64)
                    .build()
                    .unwrap()
            })
            .collect();

        Self::new(events)
    }
}

#[async_trait]
impl EventCollector for MockEventCollector {
    async fn start(&mut self, event_tx: mpsc::Sender<Event>) -> Result<(), PlatformError> {
        let events = std::mem::take(&mut self.events);
        let count = events.len();

        let handle = tokio::spawn(async move {
            for event in events {
                if event_tx.send(event).await.is_err() {
                    warn!("MockEventCollector: channel closed, stopping");
                    break;
                }
            }
        });

        self.shutdown = Some(handle);
        info!(count, "MockEventCollector started");
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), PlatformError> {
        if let Some(handle) = self.shutdown.take() {
            handle.abort();
        }
        info!("MockEventCollector stopped");
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

// ============================================================================
// ReplayEventCollector
// ============================================================================

/// Replay event collector for offline analysis.
///
/// Reads events from a binary log file and replays them through the engine.
/// This enables:
/// - Offline forensic analysis
/// - Deterministic rule testing
/// - Development on non-Linux platforms
pub struct ReplayEventCollector {
    log_path: PathBuf,
    shutdown: Option<tokio::task::JoinHandle<()>>,
}

impl ReplayEventCollector {
    /// Create a new replay collector for the given log file.
    pub fn new(log_path: PathBuf) -> Self {
        Self {
            log_path,
            shutdown: None,
        }
    }
}

#[async_trait]
impl EventCollector for ReplayEventCollector {
    async fn start(&mut self, event_tx: mpsc::Sender<Event>) -> Result<(), PlatformError> {
        let log_path = self.log_path.clone();

        // Use the existing JsonLog infrastructure to read events
        let schema = Arc::new(kestrel_schema::SchemaRegistry::new());
        let binary_log = crate::JsonLog::new(schema);

        let events = binary_log
            .read_events(log_path.clone())
            .map_err(|e| PlatformError::ReplayError(format!("Failed to read log: {}", e)))?;

        let count = events.len();
        info!(count, path = %log_path.display(), "ReplayEventCollector loaded events");

        let handle = tokio::spawn(async move {
            for event in events {
                if event_tx.send(event).await.is_err() {
                    warn!("ReplayEventCollector: channel closed, stopping");
                    break;
                }
            }
            info!("ReplayEventCollector: all events sent");
        });

        self.shutdown = Some(handle);
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), PlatformError> {
        if let Some(handle) = self.shutdown.take() {
            handle.abort();
        }
        info!("ReplayEventCollector stopped");
        Ok(())
    }

    fn name(&self) -> &str {
        "replay"
    }
}

// ============================================================================
// CollectorFactory
// ============================================================================

/// Factory for creating event collectors based on CLI arguments.
///
/// This abstracts the collector creation logic, making the CLI
/// platform-agnostic.
pub struct CollectorFactory;

impl CollectorFactory {
    /// Create a collector based on the specified type.
    ///
    /// # Arguments
    /// * `collector_type` — "mock", "replay", or "ebpf"
    /// * `log_path` — Path for replay collector (ignored for others)
    /// * `count` — Event count for mock collector (ignored for others)
    pub fn create(
        collector_type: &str,
        log_path: Option<PathBuf>,
        count: Option<usize>,
    ) -> Result<Box<dyn EventCollector>, PlatformError> {
        match collector_type {
            "mock" => {
                let count = count.unwrap_or(100);
                Ok(Box::new(MockEventCollector::generate_test_events(count)))
            },
            "replay" => {
                let path = log_path.ok_or_else(|| {
                    PlatformError::ReplayError("Replay requires --log path".into())
                })?;
                Ok(Box::new(ReplayEventCollector::new(path)))
            },
            _ => Err(PlatformError::InitializationError(format!(
                "Unknown collector type: {}",
                collector_type
            ))),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_info_mock() {
        let info = PlatformInfo::mock();
        assert_eq!(info.name, "mock");
        assert!(info.has_capability(PlatformCapability::ProcessTracing));
        assert!(!info.has_capability(PlatformCapability::InlineBlocking));
    }

    #[test]
    fn test_platform_info_has_capability() {
        let info = PlatformInfo {
            name: "test".into(),
            version: "1.0".into(),
            kernel_version: "5.15.0".into(),
            capabilities: vec![PlatformCapability::LsmHooks, PlatformCapability::Kprobes],
        };

        assert!(info.has_capability(PlatformCapability::LsmHooks));
        assert!(info.has_capability(PlatformCapability::Kprobes));
        assert!(!info.has_capability(PlatformCapability::InlineBlocking));
    }

    #[tokio::test]
    async fn test_mock_event_collector() {
        let mut collector = MockEventCollector::generate_test_events(10);
        let (tx, mut rx) = mpsc::channel(1024);

        collector.start(tx).await.unwrap();

        let mut count = 0;
        while let Some(_event) = rx.recv().await {
            count += 1;
        }

        assert_eq!(count, 10);
        collector.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_mock_event_collector_with_name() {
        let collector = MockEventCollector::generate_test_events(5)
            .with_name("test-collector");
        assert_eq!(collector.name(), "test-collector");
    }

    #[tokio::test]
    async fn test_collector_factory_mock() {
        let collector = CollectorFactory::create("mock", None, Some(5)).unwrap();
        assert_eq!(collector.name(), "mock");
    }

    #[tokio::test]
    async fn test_collector_factory_replay_no_path() {
        let result = CollectorFactory::create("replay", None, None);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_collector_factory_unknown_type() {
        let result = CollectorFactory::create("unknown", None, None);
        assert!(result.is_err());
    }
}
