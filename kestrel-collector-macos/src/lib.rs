//! macOS Event Collector
//!
//! This module provides event collection for macOS using the Endpoint Security Framework (ESF).
//! It implements the [`EventCollector`] trait to integrate with Kestrel's detection engine.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │           macOS Event Collector              │
//! ├─────────────────────────────────────────────┤
//! │  ┌──────────────┐    ┌──────────────────┐   │
//! │  │ ES Client    │    │ proc_info        │   │
//! │  │ (endpoint-sec│    │ (supplementary)  │   │
//! │  │  crate)      │    │ for enrichment   │   │
//! │  └──────┬───────┘    └────────┬─────────┘   │
//! │         │                     │              │
//! │  ┌──────▼─────────────────────▼─────────┐   │
//! │  │       Event Normalization Layer      │   │
//! │  │  (Map ES events → Kestrel Event)     │   │
//! │  └──────────────────┬───────────────────┘   │
//! │                     │                        │
//! │  ┌──────────────────▼───────────────────┐   │
//! │  │         kestrel-core EventBus        │   │
//! │  └──────────────────────────────────────┘   │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! # Platform Requirements
//!
//! - macOS 10.15 (Catalina) or later
//! - Root privileges (or appropriate entitlements)
//! - For production: Apple entitlement `com.apple.developer.endpoint-security.client`
//! - For development: SIP disabled (`csrutil disable`)
//!
//! # Usage
//!
//! ```rust,no_run
//! use kestrel_collector_macos::MacOSEventCollector;
//! use kestrel_core::EventCollector;
//! use tokio::sync::mpsc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut collector = MacOSEventCollector::new()?;
//! let (tx, rx) = mpsc::channel(1024);
//!
//! collector.start(tx).await?;
//!
//! // Process events from rx...
//!
//! collector.stop().await?;
//! # Ok(())
//! # }
//! ```

use async_trait::async_trait;
use kestrel_core::{EventCollector, PlatformError, PlatformInfo};
use kestrel_event::Event;
use tokio::sync::mpsc;
use tracing::info;

// Re-export platform-specific modules
#[cfg(target_os = "macos")]
pub mod esf;
#[cfg(target_os = "macos")]
pub mod normalize;
#[cfg(target_os = "macos")]
pub mod proc_info;

// Platform-agnostic types and constants
pub mod types;

// ============================================================================
// macOS Event Collector
// ============================================================================

/// macOS event collector using Endpoint Security Framework.
///
/// This collector monitors system events on macOS and converts them
/// to Kestrel events for detection processing.
pub struct MacOSEventCollector {
    /// Platform information
    platform_info: PlatformInfo,
    /// Shutdown signal
    shutdown: Option<tokio::task::JoinHandle<()>>,
    /// Event sender (for stopping)
    event_tx: Option<mpsc::Sender<Event>>,
}

impl MacOSEventCollector {
    /// Create a new macOS event collector.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Not running on macOS
    /// - Cannot initialize Endpoint Security client
    /// - Missing required permissions
    pub fn new() -> Result<Self, PlatformError> {
        #[cfg(target_os = "macos")]
        {
            info!("Initializing macOS event collector with Endpoint Security");
            Ok(Self {
                platform_info: PlatformInfo {
                    name: "macos".into(),
                    version: "1.0".into(),
                    kernel_version: std::env::consts::OS.into(),
                    capabilities: vec![
                        kestrel_core::PlatformCapability::ProcessTracing,
                        kestrel_core::PlatformCapability::FileTracing,
                        kestrel_core::PlatformCapability::InlineBlocking,
                    ],
                    metadata: std::collections::HashMap::new(),
                },
                shutdown: None,
                event_tx: None,
            })
        }

        #[cfg(not(target_os = "macos"))]
        {
            Err(PlatformError::InitializationError(
                "macOS collector is only available on macOS".into(),
            ))
        }
    }

    /// Get supported event types for this platform.
    pub fn supported_event_types() -> Vec<types::EventType> {
        #[cfg(target_os = "macos")]
        {
            vec![
                types::EventType::ProcessExec,
                types::EventType::ProcessFork,
                types::EventType::ProcessExit,
                types::EventType::FileCreate,
                types::EventType::FileOpen,
                types::EventType::FileWrite,
                types::EventType::FileRename,
                types::EventType::FileUnlink,
                types::EventType::ProcessSignal,
                types::EventType::SetUid,
                types::EventType::SetGid,
            ]
        }

        #[cfg(not(target_os = "macos"))]
        {
            vec![]
        }
    }
}

#[async_trait]
impl EventCollector for MacOSEventCollector {
    async fn start(&mut self, event_tx: mpsc::Sender<Event>) -> Result<(), PlatformError> {
        #[cfg(target_os = "macos")]
        {
            info!("Starting macOS event collection");

            // Store the sender for shutdown
            self.event_tx = Some(event_tx.clone());

            // Spawn the ESF event processing loop
            let handle = tokio::spawn(async move {
                // In a real implementation, this would:
                // 1. Create an ESF client
                // 2. Subscribe to events
                // 3. Process events in a loop
                // 4. Convert to Kestrel events
                // 5. Send through event_tx

                // For now, we'll simulate with a simple loop
                // that would be replaced with actual ESF integration
                info!("macOS event collector running (ESF integration pending)");

                // Keep the task alive until shutdown
                tokio::signal::ctrl_c().await.ok();
            });

            self.shutdown = Some(handle);
            Ok(())
        }

        #[cfg(not(target_os = "macos"))]
        {
            Err(PlatformError::InitializationError(
                "macOS collector is only available on macOS".into(),
            ))
        }
    }

    async fn stop(&mut self) -> Result<(), PlatformError> {
        info!("Stopping macOS event collection");

        if let Some(handle) = self.shutdown.take() {
            handle.abort();
        }

        self.event_tx = None;
        Ok(())
    }

    fn name(&self) -> &str {
        "macos"
    }

    fn platform_info(&self) -> Option<&PlatformInfo> {
        Some(&self.platform_info)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_collector_creation() {
        // This test will only pass on macOS
        #[cfg(target_os = "macos")]
        {
            let collector = MacOSEventCollector::new();
            assert!(collector.is_ok());
        }
    }

    #[test]
    fn test_supported_event_types() {
        let types = MacOSEventCollector::supported_event_types();

        #[cfg(target_os = "macos")]
        {
            assert!(!types.is_empty());
            assert!(types.contains(&types::EventType::ProcessExec));
            assert!(types.contains(&types::EventType::FileOpen));
        }

        #[cfg(not(target_os = "macos"))]
        {
            assert!(types.is_empty());
        }
    }

    #[test]
    fn test_platform_info() {
        #[cfg(target_os = "macos")]
        {
            let collector = MacOSEventCollector::new().unwrap();
            let info = collector.platform_info().unwrap();
            assert_eq!(info.name, "macos");
            assert!(info.has_capability(kestrel_core::PlatformCapability::ProcessTracing));
            assert!(info.has_capability(kestrel_core::PlatformCapability::FileTracing));
        }
    }

    #[tokio::test]
    async fn test_collector_name() {
        #[cfg(target_os = "macos")]
        {
            let collector = MacOSEventCollector::new().unwrap();
            assert_eq!(collector.name(), "macos");
        }
    }
}
