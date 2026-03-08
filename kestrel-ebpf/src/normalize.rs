//! Event Normalization
//!
//! Normalizes raw eBPF events into Kestrel Event format.
//! Handles process tree resolution, path normalization, and user information.

use crate::{EbpfError, ExecveEvent, LiveEvent, RawEbpfEvent};
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
            },
        }
    }

    /// Normalize a live telemetry event from the shared ring buffer envelope.
    pub fn normalize_live_event(
        &self,
        event: &LiveEvent,
        event_id: u64,
    ) -> Result<Event, EbpfError> {
        match event.event_type {
            1 => self.normalize_live_process_event(event, event_id),
            3 => self.normalize_live_file_event(event, event_id),
            6 => self.normalize_live_network_event(event, event_id),
            other => Err(EbpfError::NormalizationError(format!(
                "Unsupported live event type: {}",
                other
            ))),
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
            .event_type(1) // PROCESS
            .ts_mono(exec.ts_mono_ns)
            .ts_wall(exec.ts_mono_ns)
            .entity_key(exec.entity_key as u128)
            .source("ebpf");

        if let Some(entity_field) = self.schema.get_field_id("process.entity_id") {
            builder = builder.field(entity_field, TypedValue::U64(exec.entity_key as u64));
        }
        if let Some(operation_field) = self.schema.get_field_id("process.operation") {
            builder = builder.field(operation_field, TypedValue::String("exec".to_string()));
        }
        if let Some(pid_field) = self.schema.get_field_id("process.pid") {
            builder = builder.field(pid_field, TypedValue::U64(exec.pid as u64));
        }
        if let Some(ppid_field) = self.schema.get_field_id("process.ppid") {
            builder = builder.field(ppid_field, TypedValue::U64(exec.ppid as u64));
        }
        if let Some(uid_field) = self.schema.get_field_id("process.uid") {
            builder = builder.field(uid_field, TypedValue::U64(exec.uid as u64));
        }
        if let Some(gid_field) = self.schema.get_field_id("process.gid") {
            builder = builder.field(gid_field, TypedValue::U64(exec.gid as u64));
        }
        if let Some(comm_str) = self.parse_bytes(&exec.comm) {
            if let Some(comm_field) = self.schema.get_field_id("process.name") {
                builder = builder.field(comm_field, TypedValue::String(comm_str));
            }
        }
        if let Some(path_str) = self.parse_bytes(&exec.pathname) {
            if let Some(exec_field) = self.schema.get_field_id("process.executable") {
                builder = builder.field(exec_field, TypedValue::String(path_str));
            }
        }
        if let Some(args_str) = self.parse_bytes(&exec.args) {
            if let Some(cmdline_field) = self.schema.get_field_id("process.command_line") {
                builder = builder.field(cmdline_field, TypedValue::String(args_str));
            }
        }

        builder.build().map_err(|e| {
            EbpfError::NormalizationError(format!("Failed to build execve event: {}", e))
        })
    }

    fn normalize_live_process_event(
        &self,
        event: &LiveEvent,
        event_id: u64,
    ) -> Result<Event, EbpfError> {
        let mut builder = Event::builder()
            .event_id(event_id)
            .event_type(1)
            .ts_mono(event.ts_mono_ns)
            .ts_wall(event.ts_mono_ns)
            .entity_key(event.entity_key as u128)
            .source("ebpf");

        if let Some(entity_field) = self.schema.get_field_id("process.entity_id") {
            builder = builder.field(entity_field, TypedValue::U64(event.entity_key as u64));
        }
        if let Some(operation_field) = self.schema.get_field_id("process.operation") {
            let op = match event.subtype {
                1 => "exec",
                2 => "exit",
                _ => "unknown",
            };
            builder = builder.field(operation_field, TypedValue::String(op.to_string()));
        }
        if let Some(pid_field) = self.schema.get_field_id("process.pid") {
            builder = builder.field(pid_field, TypedValue::U64(event.pid as u64));
        }
        if let Some(ppid_field) = self.schema.get_field_id("process.ppid") {
            builder = builder.field(ppid_field, TypedValue::U64(event.ppid as u64));
        }
        if let Some(uid_field) = self.schema.get_field_id("process.uid") {
            builder = builder.field(uid_field, TypedValue::U64(event.uid as u64));
        }
        if let Some(gid_field) = self.schema.get_field_id("process.gid") {
            builder = builder.field(gid_field, TypedValue::U64(event.gid as u64));
        }
        if let Some(comm_field) = self.schema.get_field_id("process.name") {
            if let Some(comm) = self.parse_bytes(&event.comm) {
                builder = builder.field(comm_field, TypedValue::String(comm));
            }
        }
        if let Some(exec_field) = self.schema.get_field_id("process.executable") {
            if let Some(path) = self.parse_bytes(&event.primary) {
                builder = builder.field(exec_field, TypedValue::String(path));
            }
        }
        if let Some(cmdline_field) = self.schema.get_field_id("process.command_line") {
            if let Some(args) = self.parse_bytes(&event.secondary) {
                builder = builder.field(cmdline_field, TypedValue::String(args));
            }
        }
        if event.subtype == 2 {
            if let Some(exit_code_field) = self.schema.get_field_id("process.exit_code") {
                builder =
                    builder.field(exit_code_field, TypedValue::I64(event.aux_u32_1 as i32 as i64));
            }
        }

        builder.build().map_err(|e| {
            EbpfError::NormalizationError(format!("Failed to build live process event: {}", e))
        })
    }

    fn normalize_live_file_event(
        &self,
        event: &LiveEvent,
        event_id: u64,
    ) -> Result<Event, EbpfError> {
        let mut builder = Event::builder()
            .event_id(event_id)
            .event_type(3)
            .ts_mono(event.ts_mono_ns)
            .ts_wall(event.ts_mono_ns)
            .entity_key(event.entity_key as u128)
            .source("ebpf");

        if let Some(entity_field) = self.schema.get_field_id("process.entity_id") {
            builder = builder.field(entity_field, TypedValue::U64(event.entity_key as u64));
        }
        if let Some(operation_field) = self.schema.get_field_id("file.operation") {
            let op = match event.subtype {
                1 => "open",
                _ => "unknown",
            };
            builder = builder.field(operation_field, TypedValue::String(op.to_string()));
        }
        if let Some(pid_field) = self.schema.get_field_id("process.pid") {
            builder = builder.field(pid_field, TypedValue::U64(event.pid as u64));
        }
        let name = self.parse_bytes(&event.primary);
        let directory = self.parse_bytes(&event.secondary);
        if let Some(directory_value) = directory.as_ref() {
            if let Some(directory_field) = self.schema.get_field_id("file.directory") {
                builder =
                    builder.field(directory_field, TypedValue::String(directory_value.clone()));
            }
        }
        if let Some(name_value) = name.as_ref() {
            if let Some(name_field) = self.schema.get_field_id("file.name") {
                builder = builder.field(name_field, TypedValue::String(name_value.clone()));
            }
            if let Some(path_field) = self.schema.get_field_id("file.path") {
                let path_value = directory
                    .as_ref()
                    .map(|dir| format!("{}/{}", dir.trim_end_matches('/'), name_value))
                    .unwrap_or_else(|| name_value.clone());
                builder = builder.field(path_field, TypedValue::String(path_value));
            }
        }
        if event.aux_u64_1 > 0 {
            if let Some(inode_field) = self.schema.get_field_id("file.inode") {
                builder = builder.field(inode_field, TypedValue::U64(event.aux_u64_1));
            }
        }

        builder.build().map_err(|e| {
            EbpfError::NormalizationError(format!("Failed to build live file event: {}", e))
        })
    }

    fn normalize_live_network_event(
        &self,
        event: &LiveEvent,
        event_id: u64,
    ) -> Result<Event, EbpfError> {
        let mut builder = Event::builder()
            .event_id(event_id)
            .event_type(6)
            .ts_mono(event.ts_mono_ns)
            .ts_wall(event.ts_mono_ns)
            .entity_key(event.entity_key as u128)
            .source("ebpf");

        if let Some(entity_field) = self.schema.get_field_id("process.entity_id") {
            builder = builder.field(entity_field, TypedValue::U64(event.entity_key as u64));
        }
        if let Some(operation_field) = self.schema.get_field_id("network.operation") {
            let op = match event.subtype {
                1 => "connect",
                _ => "unknown",
            };
            builder = builder.field(operation_field, TypedValue::String(op.to_string()));
        }
        if let Some(pid_field) = self.schema.get_field_id("process.pid") {
            builder = builder.field(pid_field, TypedValue::U64(event.pid as u64));
        }
        let family = (event.aux_u32_1 >> 16) as u16;
        let port = (event.aux_u32_1 & 0xFFFF) as u16;
        if family == 2 {
            let ip = std::net::Ipv4Addr::from(event.aux_u32_2.to_ne_bytes()).to_string();
            if let Some(destination_field) = self.schema.get_field_id("network.destination") {
                builder = builder.field(destination_field, TypedValue::String(ip));
            }
        }
        if port > 0 {
            if let Some(port_field) = self.schema.get_field_id("network.dest_port") {
                builder = builder.field(port_field, TypedValue::U64(port as u64));
            }
        }

        builder.build().map_err(|e| {
            EbpfError::NormalizationError(format!("Failed to build live network event: {}", e))
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
            .event_type(1) // PROCESS
            .ts_mono(raw.ts_mono_ns)
            .ts_wall(raw.ts_mono_ns)
            .entity_key(raw.entity_key as u128)
            .source("ebpf");

        if let Some(entity_field) = self.schema.get_field_id("process.entity_id") {
            builder = builder.field(entity_field, TypedValue::U64(raw.entity_key));
        }
        if let Some(operation_field) = self.schema.get_field_id("process.operation") {
            builder = builder.field(operation_field, TypedValue::String("exec".to_string()));
        }
        if let Some(pid_field) = self.schema.get_field_id("process.pid") {
            builder = builder.field(pid_field, TypedValue::U64(raw.pid as u64));
        }
        if let Some(ppid_field) = self.schema.get_field_id("process.ppid") {
            builder = builder.field(ppid_field, TypedValue::U64(raw.ppid as u64));
        }
        if let Some(uid_field) = self.schema.get_field_id("process.uid") {
            builder = builder.field(uid_field, TypedValue::U64(raw.uid as u64));
        }
        if let Some(gid_field) = self.schema.get_field_id("process.gid") {
            builder = builder.field(gid_field, TypedValue::U64(raw.gid as u64));
        }

        let path = self.parse_path(data, 0, raw.path_len as usize);
        if let Some(path_str) = path {
            if let Some(exec_field) = self.schema.get_field_id("process.executable") {
                builder = builder.field(exec_field, TypedValue::String(path_str));
            }
        }

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
            .event_type(1) // PROCESS
            .ts_mono(raw.ts_mono_ns)
            .ts_wall(raw.ts_mono_ns)
            .entity_key(raw.entity_key as u128)
            .source("ebpf");

        if let Some(entity_field) = self.schema.get_field_id("process.entity_id") {
            builder = builder.field(entity_field, TypedValue::U64(raw.entity_key));
        }
        if let Some(operation_field) = self.schema.get_field_id("process.operation") {
            builder = builder.field(operation_field, TypedValue::String("exit".to_string()));
        }
        if let Some(pid_field) = self.schema.get_field_id("process.pid") {
            builder = builder.field(pid_field, TypedValue::U64(raw.pid as u64));
        }
        if let Some(ppid_field) = self.schema.get_field_id("process.ppid") {
            builder = builder.field(ppid_field, TypedValue::U64(raw.ppid as u64));
        }
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
            .event_type(3) // FILE
            .ts_mono(raw.ts_mono_ns)
            .ts_wall(raw.ts_mono_ns)
            .entity_key(raw.entity_key as u128)
            .source("ebpf");

        if let Some(entity_field) = self.schema.get_field_id("process.entity_id") {
            builder = builder.field(entity_field, TypedValue::U64(raw.entity_key));
        }
        if let Some(operation_field) = self.schema.get_field_id("file.operation") {
            builder = builder.field(operation_field, TypedValue::String("open".to_string()));
        }
        if let Some(pid_field) = self.schema.get_field_id("process.pid") {
            builder = builder.field(pid_field, TypedValue::U64(raw.pid as u64));
        }

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
            .event_type(3) // FILE
            .ts_mono(raw.ts_mono_ns)
            .ts_wall(raw.ts_mono_ns)
            .entity_key(raw.entity_key as u128)
            .source("ebpf");

        if let Some(entity_field) = self.schema.get_field_id("process.entity_id") {
            builder = builder.field(entity_field, TypedValue::U64(raw.entity_key));
        }
        if let Some(operation_field) = self.schema.get_field_id("file.operation") {
            builder = builder.field(operation_field, TypedValue::String("rename".to_string()));
        }
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
            .event_type(3) // FILE
            .ts_mono(raw.ts_mono_ns)
            .ts_wall(raw.ts_mono_ns)
            .entity_key(raw.entity_key as u128)
            .source("ebpf");

        if let Some(entity_field) = self.schema.get_field_id("process.entity_id") {
            builder = builder.field(entity_field, TypedValue::U64(raw.entity_key));
        }
        if let Some(operation_field) = self.schema.get_field_id("file.operation") {
            builder = builder.field(operation_field, TypedValue::String("unlink".to_string()));
        }
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
            .event_type(6) // NETWORK
            .ts_mono(raw.ts_mono_ns)
            .ts_wall(raw.ts_mono_ns)
            .entity_key(raw.entity_key as u128)
            .source("ebpf");

        if let Some(entity_field) = self.schema.get_field_id("process.entity_id") {
            builder = builder.field(entity_field, TypedValue::U64(raw.entity_key));
        }
        if let Some(operation_field) = self.schema.get_field_id("network.operation") {
            builder = builder.field(operation_field, TypedValue::String("connect".to_string()));
        }
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
            .event_type(6) // NETWORK
            .ts_mono(raw.ts_mono_ns)
            .ts_wall(raw.ts_mono_ns)
            .entity_key(raw.entity_key as u128)
            .source("ebpf");

        if let Some(entity_field) = self.schema.get_field_id("process.entity_id") {
            builder = builder.field(entity_field, TypedValue::U64(raw.entity_key));
        }
        if let Some(operation_field) = self.schema.get_field_id("network.operation") {
            builder = builder.field(operation_field, TypedValue::String("send".to_string()));
        }
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
        use kestrel_schema::register_builtin_linux_schema;

        let schema = Arc::new(SchemaRegistry::new());
        register_builtin_linux_schema(schema.as_ref()).unwrap();
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

        exec.comm[..4].copy_from_slice(b"test");
        exec.pathname[..13].copy_from_slice(b"/usr/bin/test");
        exec.args[..4].copy_from_slice(b"test");

        let event = normalizer.normalize_execve_event(&exec, 1).unwrap();
        assert_eq!(event.event_id, 1);
        assert_eq!(event.event_type_id, 1);
        assert_eq!(event.ts_mono_ns, 1234567890000);
        assert_eq!(event.entity_key, 12345);
        assert_eq!(event.source_id.as_deref(), Some("ebpf"));

        let operation_field = schema.get_field_id("process.operation").unwrap();
        assert_eq!(event.get_field(operation_field).and_then(|v| v.as_str()), Some("exec"));
    }

    #[test]
    fn test_normalize_file_event_uses_category_type_and_operation() {
        use kestrel_schema::register_builtin_linux_schema;

        let schema = Arc::new(SchemaRegistry::new());
        register_builtin_linux_schema(schema.as_ref()).unwrap();
        let normalizer = EventNormalizer::new(schema.clone());

        let raw = RawEbpfEvent {
            event_type: 4,
            ts_mono_ns: 55,
            entity_key: 77,
            pid: 123,
            ppid: 122,
            uid: 1000,
            gid: 1000,
            path_len: 0,
            cmdline_len: 0,
            exit_code: 0,
        };

        let event = normalizer.normalize(&raw, &[]).unwrap();
        assert_eq!(event.event_type_id, 3);

        let operation_field = schema.get_field_id("file.operation").unwrap();
        assert_eq!(event.get_field(operation_field).and_then(|v| v.as_str()), Some("rename"));
    }

    #[test]
    fn test_normalize_live_file_open_event() {
        use kestrel_schema::register_builtin_linux_schema;

        let schema = Arc::new(SchemaRegistry::new());
        register_builtin_linux_schema(schema.as_ref()).unwrap();
        let normalizer = EventNormalizer::new(schema.clone());

        let mut live = LiveEvent {
            event_type: 3,
            event_size: 0,
            ts_mono_ns: 99,
            pid: 321,
            ppid: 0,
            uid: 1000,
            gid: 1000,
            entity_key: 88,
            subtype: 1,
            aux_u32_1: 0,
            aux_u32_2: 0,
            aux_u64_1: 12345,
            comm: [0; 16],
            primary: [0; 256],
            secondary: [0; 256],
        };

        live.primary[..10].copy_from_slice(b"passwd.txt");
        live.secondary[..4].copy_from_slice(b"etc/");

        let event = normalizer.normalize_live_event(&live, 7).unwrap();
        assert_eq!(event.event_type_id, 3);
        let operation_field = schema.get_field_id("file.operation").unwrap();
        let directory_field = schema.get_field_id("file.directory").unwrap();
        let name_field = schema.get_field_id("file.name").unwrap();
        let inode_field = schema.get_field_id("file.inode").unwrap();
        let path_field = schema.get_field_id("file.path").unwrap();
        assert_eq!(event.get_field(operation_field).and_then(|v| v.as_str()), Some("open"));
        assert_eq!(event.get_field(directory_field).and_then(|v| v.as_str()), Some("etc/"));
        assert_eq!(event.get_field(name_field).and_then(|v| v.as_str()), Some("passwd.txt"));
        assert_eq!(event.get_field(path_field).and_then(|v| v.as_str()), Some("etc/passwd.txt"));
        assert_eq!(event.get_field(inode_field).and_then(|v| v.as_u64()), Some(12345));
    }

    #[test]
    fn test_normalize_live_network_event_extracts_port_and_destination() {
        use kestrel_schema::register_builtin_linux_schema;

        let schema = Arc::new(SchemaRegistry::new());
        register_builtin_linux_schema(schema.as_ref()).unwrap();
        let normalizer = EventNormalizer::new(schema.clone());

        let live = LiveEvent {
            event_type: 6,
            event_size: 0,
            ts_mono_ns: 101,
            pid: 123,
            ppid: 0,
            uid: 1000,
            gid: 1000,
            entity_key: 66,
            subtype: 1,
            aux_u32_1: ((2u32) << 16) | 443,
            aux_u32_2: u32::from_ne_bytes([192, 168, 1, 10]),
            aux_u64_1: 0,
            comm: [0; 16],
            primary: [0; 256],
            secondary: [0; 256],
        };

        let event = normalizer.normalize_live_event(&live, 8).unwrap();
        assert_eq!(event.event_type_id, 6);
        let destination_field = schema.get_field_id("network.destination").unwrap();
        let port_field = schema.get_field_id("network.dest_port").unwrap();
        assert_eq!(
            event.get_field(destination_field).and_then(|v| v.as_str()),
            Some("192.168.1.10")
        );
        assert_eq!(event.get_field(port_field).and_then(|v| v.as_u64()), Some(443));
    }
}
