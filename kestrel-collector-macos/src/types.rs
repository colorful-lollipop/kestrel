//! macOS Event Types
//!
//! This module defines the event types and structures for macOS event collection.
//! These types are platform-agnostic and can be used for testing on any platform.

use serde::{Deserialize, Serialize};

// ============================================================================
// Event Types
// ============================================================================

/// macOS event types that can be collected via Endpoint Security Framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    // Process events
    ProcessExec,
    ProcessFork,
    ProcessExit,
    ProcessSignal,

    // File events
    FileCreate,
    FileOpen,
    FileWrite,
    FileRename,
    FileUnlink,
    FileLink,
    FileTruncate,

    // Permission events
    SetUid,
    SetGid,
    SetEuid,
    SetEgid,
    SetReuid,
    SetRegid,

    // Memory events
    Mmap,
    Mprotect,

    // IPC events
    UnixDomainSocketConnect,
    UnixDomainSocketBind,

    // Login events
    LoginLogin,
    LoginLogout,
    LoginAuthenticate,

    // BTM events
    BtmLaunchItemAdd,
    BtmLaunchItemRemove,

    // XProtect events
    XpMalwareDetected,
    XpMalwareRemediated,

    // Other events
    IokitOpen,
    XpcConnect,
    Sudo,
}

impl EventType {
    /// Convert to a numeric ID for Kestrel events.
    pub fn to_event_type_id(&self) -> u16 {
        match self {
            // Process events
            EventType::ProcessExec => 1,
            EventType::ProcessFork => 2,
            EventType::ProcessExit => 3,
            EventType::ProcessSignal => 4,

            // File events
            EventType::FileCreate => 10,
            EventType::FileOpen => 11,
            EventType::FileWrite => 12,
            EventType::FileRename => 13,
            EventType::FileUnlink => 14,
            EventType::FileLink => 15,
            EventType::FileTruncate => 16,

            // Permission events
            EventType::SetUid => 20,
            EventType::SetGid => 21,
            EventType::SetEuid => 22,
            EventType::SetEgid => 23,
            EventType::SetReuid => 24,
            EventType::SetRegid => 25,

            // Memory events
            EventType::Mmap => 30,
            EventType::Mprotect => 31,

            // IPC events
            EventType::UnixDomainSocketConnect => 40,
            EventType::UnixDomainSocketBind => 41,

            // Login events
            EventType::LoginLogin => 50,
            EventType::LoginLogout => 51,
            EventType::LoginAuthenticate => 52,

            // BTM events
            EventType::BtmLaunchItemAdd => 60,
            EventType::BtmLaunchItemRemove => 61,

            // XProtect events
            EventType::XpMalwareDetected => 70,
            EventType::XpMalwareRemediated => 71,

            // Other events
            EventType::IokitOpen => 80,
            EventType::XpcConnect => 81,
            EventType::Sudo => 82,
        }
    }

    /// Create from a numeric ID.
    pub fn from_event_type_id(id: u16) -> Option<Self> {
        match id {
            1 => Some(EventType::ProcessExec),
            2 => Some(EventType::ProcessFork),
            3 => Some(EventType::ProcessExit),
            4 => Some(EventType::ProcessSignal),
            10 => Some(EventType::FileCreate),
            11 => Some(EventType::FileOpen),
            12 => Some(EventType::FileWrite),
            13 => Some(EventType::FileRename),
            14 => Some(EventType::FileUnlink),
            15 => Some(EventType::FileLink),
            16 => Some(EventType::FileTruncate),
            20 => Some(EventType::SetUid),
            21 => Some(EventType::SetGid),
            22 => Some(EventType::SetEuid),
            23 => Some(EventType::SetEgid),
            24 => Some(EventType::SetReuid),
            25 => Some(EventType::SetRegid),
            30 => Some(EventType::Mmap),
            31 => Some(EventType::Mprotect),
            40 => Some(EventType::UnixDomainSocketConnect),
            41 => Some(EventType::UnixDomainSocketBind),
            50 => Some(EventType::LoginLogin),
            51 => Some(EventType::LoginLogout),
            52 => Some(EventType::LoginAuthenticate),
            60 => Some(EventType::BtmLaunchItemAdd),
            61 => Some(EventType::BtmLaunchItemRemove),
            70 => Some(EventType::XpMalwareDetected),
            71 => Some(EventType::XpMalwareRemediated),
            80 => Some(EventType::IokitOpen),
            81 => Some(EventType::XpcConnect),
            82 => Some(EventType::Sudo),
            _ => None,
        }
    }

    /// Get the human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            EventType::ProcessExec => "process_exec",
            EventType::ProcessFork => "process_fork",
            EventType::ProcessExit => "process_exit",
            EventType::ProcessSignal => "process_signal",
            EventType::FileCreate => "file_create",
            EventType::FileOpen => "file_open",
            EventType::FileWrite => "file_write",
            EventType::FileRename => "file_rename",
            EventType::FileUnlink => "file_unlink",
            EventType::FileLink => "file_link",
            EventType::FileTruncate => "file_truncate",
            EventType::SetUid => "set_uid",
            EventType::SetGid => "set_gid",
            EventType::SetEuid => "set_euid",
            EventType::SetEgid => "set_egid",
            EventType::SetReuid => "set_reuid",
            EventType::SetRegid => "set_regid",
            EventType::Mmap => "mmap",
            EventType::Mprotect => "mprotect",
            EventType::UnixDomainSocketConnect => "unix_socket_connect",
            EventType::UnixDomainSocketBind => "unix_socket_bind",
            EventType::LoginLogin => "login",
            EventType::LoginLogout => "logout",
            EventType::LoginAuthenticate => "authenticate",
            EventType::BtmLaunchItemAdd => "launch_item_add",
            EventType::BtmLaunchItemRemove => "launch_item_remove",
            EventType::XpMalwareDetected => "malware_detected",
            EventType::XpMalwareRemediated => "malware_remediated",
            EventType::IokitOpen => "iokit_open",
            EventType::XpcConnect => "xpc_connect",
            EventType::Sudo => "sudo",
        }
    }
}

// ============================================================================
// Raw Event Structures
// ============================================================================

/// Raw event from Endpoint Security Framework.
///
/// This structure represents a raw event before normalization.
/// It contains the essential fields that are common to all event types.
#[derive(Debug, Clone)]
pub struct RawEsfEvent {
    /// Event type
    pub event_type: EventType,
    /// Timestamp in nanoseconds (monotonic)
    pub timestamp_ns: u64,
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Process name/comm
    pub comm: String,
    /// Primary data (path, socket address, etc.)
    pub primary: String,
    /// Secondary data (args, destination, etc.)
    pub secondary: String,
    /// Additional metadata
    pub metadata: EventMetadata,
}

/// Additional metadata for events.
#[derive(Debug, Clone, Default)]
pub struct EventMetadata {
    /// Exit code (for process exit)
    pub exit_code: Option<i32>,
    /// Signal number (for signal events)
    pub signal: Option<i32>,
    /// File mode/permissions
    pub mode: Option<u32>,
    /// Source path (for rename/link)
    pub source_path: Option<String>,
    /// Destination path (for rename/link)
    pub dest_path: Option<String>,
    /// Socket type (for socket events)
    pub socket_type: Option<u32>,
    /// Address family
    pub address_family: Option<u32>,
    /// Code signing flags
    pub cs_flags: Option<u32>,
    /// Is platform binary
    pub is_platform_binary: Option<bool>,
}

// ============================================================================
// Process Information
// ============================================================================

/// Process information for enrichment.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Process name
    pub name: String,
    /// Executable path
    pub executable: String,
    /// Command line arguments
    pub args: Vec<String>,
    /// Working directory
    pub cwd: String,
    /// Start time (nanoseconds since epoch)
    pub start_time_ns: u64,
}

// ============================================================================
// Constants
// ============================================================================

/// Maximum length for process name
pub const MAX_COMM_LEN: usize = 16;

/// Maximum length for paths
pub const MAX_PATH_LEN: usize = 1024;

/// Maximum length for arguments
pub const MAX_ARGS_LEN: usize = 4096;

// ============================================================================
// Helper Functions
// ============================================================================

/// Create an entity key from process ID and timestamp.
///
/// This creates a unique identifier for a process instance.
pub fn create_entity_key(pid: u32, timestamp_ns: u64) -> u128 {
    ((pid as u128) << 64) | (timestamp_ns as u128)
}

/// Parse a null-terminated byte array into a String.
pub fn parse_bytes(data: &[u8]) -> Option<String> {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let bytes = &data[..end];

    if bytes.is_empty() {
        return None;
    }

    std::str::from_utf8(bytes).ok().map(|s| s.to_string())
}

/// Truncate a string to a maximum length.
pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_conversion() {
        let event_type = EventType::ProcessExec;
        let id = event_type.to_event_type_id();
        assert_eq!(id, 1);

        let converted = EventType::from_event_type_id(id);
        assert_eq!(converted, Some(event_type));
    }

    #[test]
    fn test_event_type_name() {
        assert_eq!(EventType::ProcessExec.name(), "process_exec");
        assert_eq!(EventType::FileOpen.name(), "file_open");
        assert_eq!(EventType::Sudo.name(), "sudo");
    }

    #[test]
    fn test_event_type_roundtrip() {
        let all_types = vec![
            EventType::ProcessExec,
            EventType::ProcessFork,
            EventType::ProcessExit,
            EventType::FileCreate,
            EventType::FileOpen,
            EventType::FileWrite,
            EventType::SetUid,
            EventType::Mmap,
            EventType::LoginLogin,
            EventType::XpMalwareDetected,
            EventType::Sudo,
        ];

        for event_type in all_types {
            let id = event_type.to_event_type_id();
            let converted = EventType::from_event_type_id(id);
            assert_eq!(converted, Some(event_type), "Failed for {:?}", event_type);
        }
    }

    #[test]
    fn test_create_entity_key() {
        let pid = 1234;
        let timestamp = 1000000000;
        let key = create_entity_key(pid, timestamp);

        // Verify the key contains both components
        assert_eq!((key >> 64) as u32, pid);
        assert_eq!(key as u64, timestamp);
    }

    #[test]
    fn test_parse_bytes() {
        // Normal string
        let data = b"hello\0";
        assert_eq!(parse_bytes(data), Some("hello".to_string()));

        // Empty string
        let data = b"\0";
        assert_eq!(parse_bytes(data), None);

        // No null terminator
        let data = b"hello";
        assert_eq!(parse_bytes(data), Some("hello".to_string()));

        // Empty data
        let data = b"";
        assert_eq!(parse_bytes(data), None);
    }

    #[test]
    fn test_truncate_string() {
        let s = "hello world";
        assert_eq!(truncate_string(s, 5), "he...");
        assert_eq!(truncate_string(s, 20), "hello world");
        assert_eq!(truncate_string(s, 11), "hello world");
    }

    #[test]
    fn test_raw_esf_event_default() {
        let event = RawEsfEvent {
            event_type: EventType::ProcessExec,
            timestamp_ns: 1234567890,
            pid: 1000,
            ppid: 1,
            uid: 501,
            gid: 20,
            comm: "test".to_string(),
            primary: "/usr/bin/test".to_string(),
            secondary: "--arg1 --arg2".to_string(),
            metadata: EventMetadata::default(),
        };

        assert_eq!(event.event_type, EventType::ProcessExec);
        assert_eq!(event.pid, 1000);
        assert!(event.metadata.exit_code.is_none());
    }
}
