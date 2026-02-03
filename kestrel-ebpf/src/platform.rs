//! Platform Abstraction Layer for eBPF
//!
//! This module provides abstractions to decouple the eBPF platform layer
//! from the engine layer, enabling better portability and testing.

use std::collections::HashMap;
use thiserror::Error;

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
    /// Platform name (e.g., "linux", "mock")
    pub name: String,
    /// Platform version
    pub version: String,
    /// Kernel version
    pub kernel_version: String,
    /// Supported capabilities
    pub capabilities: Vec<PlatformCapability>,
    /// Platform-specific metadata
    pub metadata: HashMap<String, String>,
}

impl PlatformInfo {
    /// Check if a specific capability is supported
    pub fn has_capability(&self, cap: PlatformCapability) -> bool {
        self.capabilities.contains(&cap)
    }

    /// Create mock platform info for testing
    pub fn mock() -> Self {
        Self {
            name: "mock".to_string(),
            version: "1.0".to_string(),
            kernel_version: "5.15.0-mock".to_string(),
            capabilities: vec![
                PlatformCapability::ProcessTracing,
                PlatformCapability::FileTracing,
                PlatformCapability::Kprobes,
                PlatformCapability::Tracepoints,
            ],
            metadata: HashMap::new(),
        }
    }
}

/// Event type registry
///
/// Provides a dynamic registry for event types, decoupling event type
/// definitions from the platform implementation.
#[derive(Debug)]
pub struct EventTypeRegistry {
    /// Event type name to ID mapping
    name_to_id: HashMap<String, u16>,
    /// Event type ID to name mapping
    id_to_name: HashMap<u16, String>,
    /// Next available event type ID
    next_id: u16,
}

impl EventTypeRegistry {
    /// Create a new event type registry with default event types
    pub fn new() -> Self {
        let mut registry = Self::empty();

        // Register default event types
        registry.register("process_exec");
        registry.register("process_exit");
        registry.register("file_open");
        registry.register("file_write");
        registry.register("file_rename");
        registry.register("file_unlink");
        registry.register("network_connect");
        registry.register("network_send");
        registry.register("network_recv");

        registry
    }

    /// Create an empty registry
    pub fn empty() -> Self {
        Self {
            name_to_id: HashMap::new(),
            id_to_name: HashMap::new(),
            next_id: 1000, // Start from 1000 to avoid conflicts with built-in types
        }
    }

    /// Register a new event type
    pub fn register(&mut self, name: &str) -> u16 {
        if let Some(&id) = self.name_to_id.get(name) {
            return id;
        }

        let id = self.next_id;
        self.next_id += 1;

        self.name_to_id.insert(name.to_string(), id);
        self.id_to_name.insert(id, name.to_string());

        id
    }

    /// Get event type ID by name
    pub fn get_id(&self, name: &str) -> Option<u16> {
        self.name_to_id.get(name).copied()
    }

    /// Get event type name by ID
    pub fn get_name(&self, id: u16) -> Option<&str> {
        self.id_to_name.get(&id).map(|s| s.as_str())
    }

    /// Check if an event type exists
    pub fn has_type(&self, name: &str) -> bool {
        self.name_to_id.contains_key(name)
    }

    /// List all registered event types
    pub fn list_types(&self) -> Vec<(u16, &str)> {
        self.id_to_name
            .iter()
            .map(|(&id, name)| (id, name.as_str()))
            .collect()
    }
}

impl Default for EventTypeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Platform abstraction trait
///
/// This trait abstracts platform-specific operations, allowing the
/// engine to work with different platforms (Linux, mock for testing, etc.)
pub trait Platform: Send + Sync {
    /// Get platform information
    fn info(&self) -> &PlatformInfo;

    /// Check if a capability is supported
    fn has_capability(&self, cap: PlatformCapability) -> bool {
        self.info().has_capability(cap)
    }

    /// Get the event type registry
    fn event_types(&self) -> &EventTypeRegistry;

    /// Probe for a specific capability
    ///
    /// This performs a runtime check to see if a capability is actually
    /// available, as opposed to checking the capability list which may
    /// be based on static configuration.
    fn probe_capability(&self, cap: PlatformCapability) -> Result<bool, PlatformError>;

    /// Initialize the platform
    fn initialize(&mut self) -> Result<(), PlatformError>;

    /// Shutdown the platform
    fn shutdown(&mut self) -> Result<(), PlatformError>;
}

/// Platform errors
#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("Capability not supported: {0:?}")]
    CapabilityNotSupported(PlatformCapability),

    #[error("Platform initialization failed: {0}")]
    InitializationError(String),

    #[error("Platform shutdown failed: {0}")]
    ShutdownError(String),

    #[error("Capability probe failed: {0}")]
    ProbeError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Mock platform for testing
pub struct MockPlatform {
    info: PlatformInfo,
    event_types: EventTypeRegistry,
    initialized: bool,
}

impl MockPlatform {
    /// Create a new mock platform
    pub fn new() -> Self {
        Self {
            info: PlatformInfo::mock(),
            event_types: EventTypeRegistry::new(),
            initialized: false,
        }
    }

    /// Create a mock platform with custom capabilities
    pub fn with_capabilities(caps: Vec<PlatformCapability>) -> Self {
        let mut info = PlatformInfo::mock();
        info.capabilities = caps;

        Self {
            info,
            event_types: EventTypeRegistry::new(),
            initialized: false,
        }
    }
}

impl Default for MockPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl Platform for MockPlatform {
    fn info(&self) -> &PlatformInfo {
        &self.info
    }

    fn event_types(&self) -> &EventTypeRegistry {
        &self.event_types
    }

    fn probe_capability(&self, cap: PlatformCapability) -> Result<bool, PlatformError> {
        Ok(self.info.has_capability(cap))
    }

    fn initialize(&mut self) -> Result<(), PlatformError> {
        self.initialized = true;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), PlatformError> {
        self.initialized = false;
        Ok(())
    }
}

/// Platform manager
///
/// Manages the platform abstraction and provides access to platform-specific
/// functionality without coupling to concrete implementations.
pub struct PlatformManager {
    /// The current platform
    platform: Box<dyn Platform>,
}

impl PlatformManager {
    /// Create a new platform manager with the given platform
    pub fn new(platform: Box<dyn Platform>) -> Self {
        Self { platform }
    }

    /// Create a platform manager with a mock platform (for testing)
    pub fn mock() -> Self {
        Self::new(Box::new(MockPlatform::new()))
    }

    /// Initialize the platform
    pub fn initialize(&mut self) -> Result<(), PlatformError> {
        self.platform.initialize()
    }

    /// Shutdown the platform
    pub fn shutdown(&mut self) -> Result<(), PlatformError> {
        self.platform.shutdown()
    }

    /// Get platform information
    pub fn info(&self) -> &PlatformInfo {
        self.platform.info()
    }

    /// Check if a capability is supported
    pub fn has_capability(&self, cap: PlatformCapability) -> bool {
        self.platform.has_capability(cap)
    }

    /// Probe for a capability
    pub fn probe_capability(&self, cap: PlatformCapability) -> Result<bool, PlatformError> {
        self.platform.probe_capability(cap)
    }

    /// Get event type registry
    pub fn event_types(&self) -> &EventTypeRegistry {
        self.platform.event_types()
    }

    /// Get event type ID by name
    pub fn get_event_type_id(&self, name: &str) -> Option<u16> {
        self.platform.event_types().get_id(name)
    }

    /// Get event type name by ID
    pub fn get_event_type_name(&self, id: u16) -> Option<&str> {
        self.platform.event_types().get_name(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_registry() {
        let mut registry = EventTypeRegistry::empty();

        // Register event types
        let id1 = registry.register("test_event");
        let id2 = registry.register("another_event");

        // IDs should be unique
        assert_ne!(id1, id2);

        // Lookup by name
        assert_eq!(registry.get_id("test_event"), Some(id1));
        assert_eq!(registry.get_id("another_event"), Some(id2));
        assert_eq!(registry.get_id("unknown"), None);

        // Lookup by ID
        assert_eq!(registry.get_name(id1), Some("test_event"));
        assert_eq!(registry.get_name(id2), Some("another_event"));
        assert_eq!(registry.get_name(9999), None);

        // Duplicate registration returns same ID
        let id1_again = registry.register("test_event");
        assert_eq!(id1, id1_again);
    }

    #[test]
    fn test_mock_platform() {
        let mut platform = MockPlatform::new();

        // Initially not initialized
        assert!(!platform.initialized);

        // Initialize
        platform.initialize().unwrap();
        assert!(platform.initialized);

        // Check capabilities
        assert!(platform.has_capability(PlatformCapability::ProcessTracing));
        assert!(!platform.has_capability(PlatformCapability::InlineBlocking));

        // Probe capability
        assert!(platform.probe_capability(PlatformCapability::ProcessTracing).unwrap());

        // Shutdown
        platform.shutdown().unwrap();
        assert!(!platform.initialized);
    }

    #[test]
    fn test_platform_manager() {
        let mut manager = PlatformManager::mock();

        // Initialize
        manager.initialize().unwrap();

        // Check capabilities
        assert!(manager.has_capability(PlatformCapability::ProcessTracing));

        // Event types
        let id = manager.get_event_type_id("process_exec");
        assert!(id.is_some());

        let name = manager.get_event_type_name(id.unwrap());
        assert_eq!(name, Some("process_exec"));
    }

    #[test]
    fn test_platform_info_mock() {
        let info = PlatformInfo::mock();

        assert_eq!(info.name, "mock");
        assert!(info.has_capability(PlatformCapability::ProcessTracing));
        assert!(!info.has_capability(PlatformCapability::InlineBlocking));
    }
}
