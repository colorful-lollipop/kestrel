//! eBPF Event Types
//!
//! This module contains the event type definitions used by eBPF programs.
//! These are pure data structures that don't depend on Linux-specific APIs,
//! allowing them to be tested on any platform (including macOS).

use kestrel_schema::{SchemaRegistry, TypedValue};
use std::sync::Arc;
use tracing::{debug, warn};

// ============================================================================
// Event Type IDs (must match eBPF C programs)
// ============================================================================

/// Process execution event type
pub const EVENT_TYPE_PROCESS_EXEC: u32 = 1;

/// Process exit event type
pub const EVENT_TYPE_PROCESS_EXIT: u32 = 2;

/// File open event type
pub const EVENT_TYPE_FILE_OPEN: u32 = 3;

/// File rename event type
pub const EVENT_TYPE_FILE_RENAME: u32 = 4;

/// File unlink event type
pub const EVENT_TYPE_FILE_UNLINK: u32 = 5;

/// Network connect event type
pub const EVENT_TYPE_NETWORK_CONNECT: u32 = 6;

/// Network send event type
pub const EVENT_TYPE_NETWORK_SEND: u32 = 7;

// ============================================================================
// Raw eBPF Event Structures
// ============================================================================

/// Raw eBPF event header (legacy format)
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

/// Execve event from eBPF (C struct format)
///
/// This matches the C struct layout from `main.bpf.c`:
/// ```c
/// struct execve_event_t {
///     u64 ts_mono_ns;
///     u32 pid, ppid, uid, gid, entity_key;
///     char comm[16], pathname[256], args[512];
/// };
/// ```
#[repr(C)]
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

/// Live event envelope from ring buffer
///
/// This is the unified event format used by the ring buffer:
/// ```c
/// struct live_event_t {
///     u32 event_type, event_size;
///     u64 ts_mono_ns;
///     u32 pid, ppid, uid, gid, entity_key, subtype;
///     u32 aux_u32_1, aux_u32_2;
///     u64 aux_u64_1;
///     char comm[16], primary[256], secondary[256];
/// };
/// ```
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LiveEvent {
    pub event_type: u32,
    pub event_size: u32,
    pub ts_mono_ns: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub entity_key: u32,
    pub subtype: u32,
    pub aux_u32_1: u32,
    pub aux_u32_2: u32,
    pub aux_u64_1: u64,
    pub comm: [u8; 16],
    pub primary: [u8; 256],
    pub secondary: [u8; 256],
}

// ============================================================================
// Event Type Enum
// ============================================================================

/// Supported eBPF event types
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

impl EbpfEventType {
    /// Get the numeric event type ID
    pub fn as_u32(&self) -> u32 {
        match self {
            Self::ProcessExec => EVENT_TYPE_PROCESS_EXEC,
            Self::ProcessExit => EVENT_TYPE_PROCESS_EXIT,
            Self::FileOpen => EVENT_TYPE_FILE_OPEN,
            Self::FileRename => EVENT_TYPE_FILE_RENAME,
            Self::FileUnlink => EVENT_TYPE_FILE_UNLINK,
            Self::NetworkConnect => EVENT_TYPE_NETWORK_CONNECT,
            Self::NetworkSend => EVENT_TYPE_NETWORK_SEND,
        }
    }

    /// Create from numeric event type ID
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            EVENT_TYPE_PROCESS_EXEC => Some(Self::ProcessExec),
            EVENT_TYPE_PROCESS_EXIT => Some(Self::ProcessExit),
            EVENT_TYPE_FILE_OPEN => Some(Self::FileOpen),
            EVENT_TYPE_FILE_RENAME => Some(Self::FileRename),
            EVENT_TYPE_FILE_UNLINK => Some(Self::FileUnlink),
            EVENT_TYPE_NETWORK_CONNECT => Some(Self::NetworkConnect),
            EVENT_TYPE_NETWORK_SEND => Some(Self::NetworkSend),
            _ => None,
        }
    }

    /// Get the event type name
    pub fn name(&self) -> &'static str {
        match self {
            Self::ProcessExec => "process_exec",
            Self::ProcessExit => "process_exit",
            Self::FileOpen => "file_open",
            Self::FileRename => "file_rename",
            Self::FileUnlink => "file_unlink",
            Self::NetworkConnect => "network_connect",
            Self::NetworkSend => "network_send",
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parse null-terminated byte array into String
///
/// Returns None if the array is empty or contains only null bytes.
pub fn parse_bytes(bytes: &[u8]) -> Option<String> {
    // Find the first null byte or use the entire array
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());

    if end == 0 {
        return None;
    }

    String::from_utf8(bytes[..end].to_vec()).ok()
}

/// Create a standard entity key from process information
///
/// This creates a deterministic entity key from pid and start time,
/// which can be used for process tree correlation.
pub fn create_entity_key(pid: u32, ppid: u32, ts_mono_ns: u64) -> u64 {
    // Simple hash: pid + ppid * 100000 + timestamp modulo
    // In production, this should use a proper hash function
    (pid as u64) + (ppid as u64) * 100_000 + (ts_mono_ns % 1_000_000)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_conversion() {
        assert_eq!(EbpfEventType::ProcessExec.as_u32(), 1);
        assert_eq!(EbpfEventType::FileOpen.as_u32(), 3);
        assert_eq!(EbpfEventType::NetworkConnect.as_u32(), 6);
    }

    #[test]
    fn test_event_type_from_u32() {
        assert_eq!(EbpfEventType::from_u32(1), Some(EbpfEventType::ProcessExec));
        assert_eq!(EbpfEventType::from_u32(3), Some(EbpfEventType::FileOpen));
        assert_eq!(EbpfEventType::from_u32(99), None);
    }

    #[test]
    fn test_event_type_name() {
        assert_eq!(EbpfEventType::ProcessExec.name(), "process_exec");
        assert_eq!(EbpfEventType::FileOpen.name(), "file_open");
        assert_eq!(EbpfEventType::NetworkConnect.name(), "network_connect");
    }

    #[test]
    fn test_parse_bytes_valid() {
        let bytes = b"hello\0\0\0";
        assert_eq!(parse_bytes(bytes), Some("hello".to_string()));
    }

    #[test]
    fn test_parse_bytes_empty() {
        let bytes = [0u8; 16];
        assert_eq!(parse_bytes(&bytes), None);
    }

    #[test]
    fn test_parse_bytes_no_null() {
        let bytes = b"hello";
        assert_eq!(parse_bytes(bytes), Some("hello".to_string()));
    }

    #[test]
    fn test_parse_bytes_utf8_invalid() {
        let bytes = [0xFF, 0xFE, 0x00]; // Invalid UTF-8
        assert_eq!(parse_bytes(&bytes), None);
    }

    #[test]
    fn test_create_entity_key() {
        let key1 = create_entity_key(100, 1, 1000000);
        let key2 = create_entity_key(100, 1, 1000000);
        let key3 = create_entity_key(101, 1, 1000000);

        // Same pid/ppid/timestamp should produce same key
        assert_eq!(key1, key2);

        // Different pid should produce different key
        assert_ne!(key1, key3);
    }
}
