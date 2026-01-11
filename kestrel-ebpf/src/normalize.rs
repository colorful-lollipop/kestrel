//! Event Normalization
//!
//! Normalizes raw eBPF events into Kestrel Event format.
//! Handles process tree resolution, path normalization, and user information.

use crate::{EbpfError, ExecveEvent, RawEbpfEvent};
use kestrel_event::Event;
use kestrel_schema::{SchemaRegistry, TypedValue};
use std::sync::Arc;
use tracing::{debug, warn};

/// Event normalizer
///
/// Converts raw eBPF events into normalized Kestrel Events with proper
/// schema field IDs and data types.
#[derive(Clone)]
pub struct EventNormalizer {
    schema: Arc<SchemaRegistry>,
}

impl EventNormalizer {
    /// Create a new event normalizer
    pub fn new(schema: Arc<SchemaRegistry>) -> Self {
        Self { schema }
    }

    /// Normalize a raw eBPF event into a Kestrel Event
    pub fn normalize(&self, raw: &RawEbpfEvent, data: &[u8]) -> Result<Event, EbpfError> {
        debug!(event_type = raw.event_type, "Normalizing event");

        // Determine event type and create appropriate event
        match raw.event_type {
            1 => self.normalize_process_exec(raw, data),
            2 => self.normalize_process_exit(raw, data),
            3 => self.normalize_file_open(raw, data),
            4 => self.normalize_file_rename(raw, data),
            5 => self.normalize_file_unlink(raw, data),
            6 => self.normalize_network_connect(raw, data),
            7 => self.normalize_network_send(raw, data),
            _ => {
                warn!(event_type = raw.event_type, "Unknown event type");
                Err(EbpfError::NormalizationError(format!(
                    "Unknown event type: {}",
                    raw.event_type
                )))
            }
        }
    }

    /// Normalize an execve event from ring buffer
    ///
    /// This handles the actual C struct format from eBPF programs.
    pub fn normalize_execve_event(
        &self,
        exec: &ExecveEvent,
        event_id: u64,
    ) -> Result<Event, EbpfError> {
        debug!(pid = exec.pid, comm = ?self.parse_bytes(&exec.comm), "Normalizing execve event");

        let mut builder = Event::builder()
            .event_id(event_id)
            .event_type(1) // PROCESS_EXEC
            .ts_mono(exec.ts_mono_ns)
            .ts_wall(exec.ts_mono_ns) // Use mono time for now
            .entity_key(exec.entity_key as u128);

        // Add PID (convert u32 to u64)
        if let Some(pid_field) = self.schema.get_field_id("process.pid") {
            builder = builder.field(pid_field, TypedValue::U64(exec.pid as u64));
        }

        // Add PPID (convert u32 to u64)
        if let Some(ppid_field) = self.schema.get_field_id("process.ppid") {
            builder = builder.field(ppid_field, TypedValue::U64(exec.ppid as u64));
        }

        // Add UID (convert u32 to u64)
        if let Some(uid_field) = self.schema.get_field_id("process.uid") {
            builder = builder.field(uid_field, TypedValue::U64(exec.uid as u64));
        }

        // Add GID (convert u32 to u64)
        if let Some(gid_field) = self.schema.get_field_id("process.gid") {
            builder = builder.field(gid_field, TypedValue::U64(exec.gid as u64));
        }

        // Parse and add comm (process name)
        if let Some(comm_str) = self.parse_bytes(&exec.comm) {
            if let Some(comm_field) = self.schema.get_field_id("process.name") {
                builder = builder.field(comm_field, TypedValue::String(comm_str));
            }
        }

        // Parse and add executable path
        if let Some(path_str) = self.parse_bytes(&exec.pathname) {
            if let Some(exec_field) = self.schema.get_field_id("process.executable") {
                builder = builder.field(exec_field, TypedValue::String(path_str));
            }
        }

        // Parse and add command line arguments
        if let Some(args_str) = self.parse_bytes(&exec.args) {
            if let Some(cmdline_field) = self.schema.get_field_id("process.command_line") {
                builder = builder.field(cmdline_field, TypedValue::String(args_str));
            }
        }

        builder.build().map_err(|e| {
            EbpfError::NormalizationError(format!("Failed to build execve event: {}", e))
        })
    }

    /// Parse a null-terminated byte array into a String
    fn parse_bytes(&self, data: &[u8]) -> Option<String> {
        // Find null terminator
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        let bytes = &data[..end];

        if bytes.is_empty() {
            return None;
        }

        std::str::from_utf8(bytes).ok().map(|s| s.to_string())
    }

    /// Normalize process exec event
    fn normalize_process_exec(&self, raw: &RawEbpfEvent, data: &[u8]) -> Result<Event, EbpfError> {
        let mut builder = Event::builder()
            .event_type(1) // PROCESS_EXEC
            .ts_mono(raw.ts_mono_ns)
            .ts_wall(raw.ts_mono_ns) // Use mono time for now
            .entity_key(raw.entity_key as u128);

        // Add PID (convert u32 to u64)
        if let Some(pid_field) = self.schema.get_field_id("process.pid") {
            builder = builder.field(pid_field, TypedValue::U64(raw.pid as u64));
        }

        // Add PPID (convert u32 to u64)
        if let Some(ppid_field) = self.schema.get_field_id("process.ppid") {
            builder = builder.field(ppid_field, TypedValue::U64(raw.ppid as u64));
        }

        // Add UID (convert u32 to u64)
        if let Some(uid_field) = self.schema.get_field_id("process.uid") {
            builder = builder.field(uid_field, TypedValue::U64(raw.uid as u64));
        }

        // Add GID (convert u32 to u64)
        if let Some(gid_field) = self.schema.get_field_id("process.gid") {
            builder = builder.field(gid_field, TypedValue::U64(raw.gid as u64));
        }

        // Parse and add executable path
        let path = self.parse_path(data, 0, raw.path_len as usize);
        if let Some(path_str) = path {
            if let Some(exec_field) = self.schema.get_field_id("process.executable") {
                builder = builder.field(exec_field, TypedValue::String(path_str));
            }
        }

        // Parse and add command line
        let cmdline_offset = raw.path_len as usize;
        let cmdline = self.parse_path(data, cmdline_offset, raw.cmdline_len as usize);
        if let Some(cmdline_str) = cmdline {
            if let Some(cmdline_field) = self.schema.get_field_id("process.command_line") {
                builder = builder.field(cmdline_field, TypedValue::String(cmdline_str));
            }
        }

        builder.build().map_err(|e| {
            EbpfError::NormalizationError(format!("Failed to build process exec event: {}", e))
        })
    }

    /// Normalize process exit event
    fn normalize_process_exit(&self, raw: &RawEbpfEvent, _data: &[u8]) -> Result<Event, EbpfError> {
        let mut builder = Event::builder()
            .event_type(2) // PROCESS_EXIT
            .ts_mono(raw.ts_mono_ns)
            .ts_wall(raw.ts_mono_ns)
            .entity_key(raw.entity_key as u128);

        // Add PID (convert u32 to u64)
        if let Some(pid_field) = self.schema.get_field_id("process.pid") {
            builder = builder.field(pid_field, TypedValue::U64(raw.pid as u64));
        }

        // Add PPID (convert u32 to u64)
        if let Some(ppid_field) = self.schema.get_field_id("process.ppid") {
            builder = builder.field(ppid_field, TypedValue::U64(raw.ppid as u64));
        }

        // Add exit code (convert i32 to i64)
        if let Some(exit_code_field) = self.schema.get_field_id("process.exit_code") {
            builder = builder.field(exit_code_field, TypedValue::I64(raw.exit_code as i64));
        }

        builder.build().map_err(|e| {
            EbpfError::NormalizationError(format!("Failed to build process exit event: {}", e))
        })
    }

    /// Normalize file open event
    fn normalize_file_open(&self, raw: &RawEbpfEvent, data: &[u8]) -> Result<Event, EbpfError> {
        let mut builder = Event::builder()
            .event_type(3) // FILE_OPEN
            .ts_mono(raw.ts_mono_ns)
            .ts_wall(raw.ts_mono_ns)
            .entity_key(raw.entity_key as u128);

        // Add PID (convert u32 to u64)
        if let Some(pid_field) = self.schema.get_field_id("process.pid") {
            builder = builder.field(pid_field, TypedValue::U64(raw.pid as u64));
        }

        // Parse and add file path
        let path = self.parse_path(data, 0, raw.path_len as usize);
        if let Some(path_str) = path {
            if let Some(path_field) = self.schema.get_field_id("file.path") {
                builder = builder.field(path_field, TypedValue::String(path_str));
            }
        }

        builder.build().map_err(|e| {
            EbpfError::NormalizationError(format!("Failed to build file open event: {}", e))
        })
    }

    /// Normalize file rename event
    fn normalize_file_rename(&self, raw: &RawEbpfEvent, _data: &[u8]) -> Result<Event, EbpfError> {
        let mut builder = Event::builder()
            .event_type(4) // FILE_RENAME
            .ts_mono(raw.ts_mono_ns)
            .ts_wall(raw.ts_mono_ns)
            .entity_key(raw.entity_key as u128);

        // Add PID (convert u32 to u64)
        if let Some(pid_field) = self.schema.get_field_id("process.pid") {
            builder = builder.field(pid_field, TypedValue::U64(raw.pid as u64));
        }

        builder.build().map_err(|e| {
            EbpfError::NormalizationError(format!("Failed to build file rename event: {}", e))
        })
    }

    /// Normalize file unlink event
    fn normalize_file_unlink(&self, raw: &RawEbpfEvent, _data: &[u8]) -> Result<Event, EbpfError> {
        let mut builder = Event::builder()
            .event_type(5) // FILE_UNLINK
            .ts_mono(raw.ts_mono_ns)
            .ts_wall(raw.ts_mono_ns)
            .entity_key(raw.entity_key as u128);

        // Add PID (convert u32 to u64)
        if let Some(pid_field) = self.schema.get_field_id("process.pid") {
            builder = builder.field(pid_field, TypedValue::U64(raw.pid as u64));
        }

        builder.build().map_err(|e| {
            EbpfError::NormalizationError(format!("Failed to build file unlink event: {}", e))
        })
    }

    /// Normalize network connect event
    fn normalize_network_connect(
        &self,
        raw: &RawEbpfEvent,
        _data: &[u8],
    ) -> Result<Event, EbpfError> {
        let mut builder = Event::builder()
            .event_type(6) // NETWORK_CONNECT
            .ts_mono(raw.ts_mono_ns)
            .ts_wall(raw.ts_mono_ns)
            .entity_key(raw.entity_key as u128);

        // Add PID (convert u32 to u64)
        if let Some(pid_field) = self.schema.get_field_id("process.pid") {
            builder = builder.field(pid_field, TypedValue::U64(raw.pid as u64));
        }

        builder.build().map_err(|e| {
            EbpfError::NormalizationError(format!("Failed to build network connect event: {}", e))
        })
    }

    /// Normalize network send event
    fn normalize_network_send(&self, raw: &RawEbpfEvent, _data: &[u8]) -> Result<Event, EbpfError> {
        let mut builder = Event::builder()
            .event_type(7) // NETWORK_SEND
            .ts_mono(raw.ts_mono_ns)
            .ts_wall(raw.ts_mono_ns)
            .entity_key(raw.entity_key as u128);

        // Add PID (convert u32 to u64)
        if let Some(pid_field) = self.schema.get_field_id("process.pid") {
            builder = builder.field(pid_field, TypedValue::U64(raw.pid as u64));
        }

        builder.build().map_err(|e| {
            EbpfError::NormalizationError(format!("Failed to build network send event: {}", e))
        })
    }

    /// Parse a null-terminated string from raw data
    fn parse_path(&self, data: &[u8], offset: usize, len: usize) -> Option<String> {
        if offset + len > data.len() {
            return None;
        }

        let slice = &data[offset..offset + len];
        // Find null terminator
        let end = slice.iter().position(|&b| b == 0).unwrap_or(len);
        let bytes = &slice[..end];

        std::str::from_utf8(bytes).ok().map(|s| s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_schema::SchemaRegistry;

    #[test]
    fn test_normalizer_creation() {
        let schema = Arc::new(SchemaRegistry::new());
        let normalizer = EventNormalizer::new(schema);
        // Schema starts with 0 fields
        assert_eq!(normalizer.schema.list_fields().len(), 0);
    }

    #[test]
    fn test_parse_path_valid() {
        let schema = Arc::new(SchemaRegistry::new());
        let normalizer = EventNormalizer::new(schema);

        let data = b"/usr/bin/bash\x00extra data";
        let path = normalizer.parse_path(data, 0, 14);
        assert_eq!(path, Some("/usr/bin/bash".to_string()));
    }

    #[test]
    fn test_parse_path_offset() {
        let schema = Arc::new(SchemaRegistry::new());
        let normalizer = EventNormalizer::new(schema);

        let data = b"/usr/bin/bash\x00/usr/bin/ls\x00extra";
        // After "/usr/bin/bash\x00" (14 chars), the second string starts at position 15
        let path = normalizer.parse_path(data, 15, 11);
        // The string "/usr/bin/ls" is only 11 characters, but we start at position 15
        // So we get "usr/bin/ls" without the leading slash
        assert_eq!(path, Some("usr/bin/ls".to_string()));
    }

    #[test]
    fn test_parse_path_out_of_bounds() {
        let schema = Arc::new(SchemaRegistry::new());
        let normalizer = EventNormalizer::new(schema);

        let data = b"/usr/bin/bash\x00";
        let path = normalizer.parse_path(data, 0, 100);
        assert_eq!(path, None);
    }

    #[test]
    fn test_parse_bytes_valid() {
        let schema = Arc::new(SchemaRegistry::new());
        let normalizer = EventNormalizer::new(schema);

        let data = [b'b', b'a', b's', b'h', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = normalizer.parse_bytes(&data);
        assert_eq!(result, Some("bash".to_string()));
    }

    #[test]
    fn test_parse_bytes_empty() {
        let schema = Arc::new(SchemaRegistry::new());
        let normalizer = EventNormalizer::new(schema);

        let data = [0u8; 16];
        let result = normalizer.parse_bytes(&data);
        assert_eq!(result, None);
    }

    #[test]
    fn test_normalize_execve_event() {
        use crate::ExecveEvent;
        use kestrel_schema::FieldDef;

        let mut schema = SchemaRegistry::new();
        // Register fields that the normalizer uses
        let _ = schema.register_field(FieldDef {
            path: "process.pid".to_string(),
            data_type: kestrel_schema::FieldDataType::U64,
            description: None,
        });
        let _ = schema.register_field(FieldDef {
            path: "process.ppid".to_string(),
            data_type: kestrel_schema::FieldDataType::U64,
            description: None,
        });
        let _ = schema.register_field(FieldDef {
            path: "process.uid".to_string(),
            data_type: kestrel_schema::FieldDataType::U64,
            description: None,
        });
        let _ = schema.register_field(FieldDef {
            path: "process.gid".to_string(),
            data_type: kestrel_schema::FieldDataType::U64,
            description: None,
        });
        let _ = schema.register_field(FieldDef {
            path: "process.name".to_string(),
            data_type: kestrel_schema::FieldDataType::String,
            description: None,
        });
        let _ = schema.register_field(FieldDef {
            path: "process.executable".to_string(),
            data_type: kestrel_schema::FieldDataType::String,
            description: None,
        });
        let _ = schema.register_field(FieldDef {
            path: "process.command_line".to_string(),
            data_type: kestrel_schema::FieldDataType::String,
            description: None,
        });

        let schema = Arc::new(schema);
        let normalizer = EventNormalizer::new(schema.clone());

        let mut exec = ExecveEvent {
            ts_mono_ns: 1234567890000,
            pid: 1001,
            ppid: 1000,
            uid: 1000,
            gid: 1000,
            entity_key: 12345,
            comm: [0u8; 16],
            pathname: [0u8; 256],
            args: [0u8; 512],
        };

        // Set comm
        exec.comm[..4].copy_from_slice(b"test");
        // Set pathname
        exec.pathname[..13].copy_from_slice(b"/usr/bin/test");
        // Set args
        exec.args[..4].copy_from_slice(b"test");

        let result = normalizer.normalize_execve_event(&exec, 1);
        assert!(result.is_ok());

        let event = result.unwrap();
        assert_eq!(event.event_id, 1);
        assert_eq!(event.event_type_id, 1);
        assert_eq!(event.ts_mono_ns, 1234567890000);
        assert_eq!(event.entity_key, 12345);
    }
}
