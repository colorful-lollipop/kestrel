//! Event Normalization
//!
//! Normalizes raw ESF events into Kestrel Event format.
//! Handles field mapping, entity key generation, and event enrichment.

use kestrel_core::PlatformError;
use kestrel_event::Event;
use kestrel_schema::{SchemaRegistry, TypedValue};
use std::sync::Arc;
use tracing::debug;

use crate::types::{RawEsfEvent, create_entity_key};

// ============================================================================
// Event Normalizer
// ============================================================================

/// Normalizes macOS ESF events into Kestrel Events.
#[derive(Clone)]
pub struct EventNormalizer {
    schema: Arc<SchemaRegistry>,
}

impl EventNormalizer {
    /// Create a new event normalizer.
    pub fn new(schema: Arc<SchemaRegistry>) -> Self {
        Self { schema }
    }

    /// Normalize a raw ESF event into a Kestrel Event.
    pub fn normalize(&self, raw: &RawEsfEvent) -> Result<Event, PlatformError> {
        debug!(
            event_type = ?raw.event_type,
            pid = raw.pid,
            "Normalizing ESF event"
        );

        let entity_key = create_entity_key(raw.pid, raw.timestamp_ns);

        // Build event - take ownership at each step
        let builder = Event::builder()
            .event_type(raw.event_type.to_event_type_id())
            .ts_mono(raw.timestamp_ns)
            .ts_wall(raw.timestamp_ns)
            .entity_key(entity_key)
            .source("macos");

        let builder = self.add_common_fields(builder, raw);
        let builder = self.add_event_specific_fields(builder, raw);

        builder.build().map_err(|e| {
            PlatformError::InitializationError(format!("Failed to build event: {}", e))
        })
    }

    fn add_common_fields(
        &self,
        mut b: kestrel_event::EventBuilder,
        raw: &RawEsfEvent,
    ) -> kestrel_event::EventBuilder {
        if let Some(fid) = self.schema.get_field_id("process.pid") {
            b = b.field(fid, TypedValue::U64(raw.pid as u64));
        }
        if let Some(fid) = self.schema.get_field_id("process.ppid") {
            b = b.field(fid, TypedValue::U64(raw.ppid as u64));
        }
        if let Some(fid) = self.schema.get_field_id("process.uid") {
            b = b.field(fid, TypedValue::U64(raw.uid as u64));
        }
        if let Some(fid) = self.schema.get_field_id("process.gid") {
            b = b.field(fid, TypedValue::U64(raw.gid as u64));
        }
        if let Some(fid) = self.schema.get_field_id("process.comm") {
            if !raw.comm.is_empty() {
                b = b.field(fid, TypedValue::String(raw.comm.clone().into()));
            }
        }
        b
    }

    fn add_event_specific_fields(
        &self,
        b: kestrel_event::EventBuilder,
        raw: &RawEsfEvent,
    ) -> kestrel_event::EventBuilder {
        match raw.event_type {
            crate::types::EventType::ProcessExec => self.add_exec_fields(b, raw),
            crate::types::EventType::ProcessExit => self.add_exit_fields(b, raw),
            crate::types::EventType::ProcessSignal => self.add_signal_fields(b, raw),
            crate::types::EventType::FileCreate
            | crate::types::EventType::FileOpen
            | crate::types::EventType::FileWrite
            | crate::types::EventType::FileUnlink => self.add_file_fields(b, raw),
            crate::types::EventType::FileRename => self.add_rename_fields(b, raw),
            _ => b,
        }
    }

    fn add_exec_fields(
        &self,
        mut b: kestrel_event::EventBuilder,
        raw: &RawEsfEvent,
    ) -> kestrel_event::EventBuilder {
        if let Some(fid) = self.schema.get_field_id("file.path") {
            if !raw.primary.is_empty() {
                b = b.field(fid, TypedValue::String(raw.primary.clone().into()));
            }
        }
        if let Some(fid) = self.schema.get_field_id("process.args") {
            if !raw.secondary.is_empty() {
                b = b.field(fid, TypedValue::String(raw.secondary.clone().into()));
            }
        }
        if let Some(fid) = self.schema.get_field_id("process.cs_flags") {
            if let Some(flags) = raw.metadata.cs_flags {
                b = b.field(fid, TypedValue::U64(flags as u64));
            }
        }
        b
    }

    fn add_exit_fields(
        &self,
        mut b: kestrel_event::EventBuilder,
        raw: &RawEsfEvent,
    ) -> kestrel_event::EventBuilder {
        if let Some(fid) = self.schema.get_field_id("process.exit_code") {
            if let Some(code) = raw.metadata.exit_code {
                b = b.field(fid, TypedValue::I64(code as i64));
            }
        }
        b
    }

    fn add_signal_fields(
        &self,
        mut b: kestrel_event::EventBuilder,
        raw: &RawEsfEvent,
    ) -> kestrel_event::EventBuilder {
        if let Some(fid) = self.schema.get_field_id("process.signal") {
            if let Some(sig) = raw.metadata.signal {
                b = b.field(fid, TypedValue::I64(sig as i64));
            }
        }
        b
    }

    fn add_file_fields(
        &self,
        mut b: kestrel_event::EventBuilder,
        raw: &RawEsfEvent,
    ) -> kestrel_event::EventBuilder {
        if let Some(fid) = self.schema.get_field_id("file.path") {
            if !raw.primary.is_empty() {
                b = b.field(fid, TypedValue::String(raw.primary.clone().into()));
            }
        }
        if let Some(fid) = self.schema.get_field_id("file.mode") {
            if let Some(mode) = raw.metadata.mode {
                b = b.field(fid, TypedValue::U64(mode as u64));
            }
        }
        b
    }

    fn add_rename_fields(
        &self,
        mut b: kestrel_event::EventBuilder,
        raw: &RawEsfEvent,
    ) -> kestrel_event::EventBuilder {
        if let Some(fid) = self.schema.get_field_id("file.source_path") {
            if let Some(ref src) = raw.metadata.source_path {
                b = b.field(fid, TypedValue::String(src.clone().into()));
            }
        }
        if let Some(fid) = self.schema.get_field_id("file.dest_path") {
            if let Some(ref dst) = raw.metadata.dest_path {
                b = b.field(fid, TypedValue::String(dst.clone().into()));
            }
        }
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EventMetadata, EventType};

    #[test]
    fn test_normalize_exec() {
        let schema = Arc::new(SchemaRegistry::new());
        let norm = EventNormalizer::new(schema);
        let raw = RawEsfEvent {
            event_type: EventType::ProcessExec,
            timestamp_ns: 100,
            pid: 1,
            ppid: 0,
            uid: 0,
            gid: 0,
            comm: "sh".into(),
            primary: "/bin/sh".into(),
            secondary: "-c id".into(),
            metadata: EventMetadata::default(),
        };
        assert!(norm.normalize(&raw).is_ok());
    }

    #[test]
    fn test_normalize_file() {
        let schema = Arc::new(SchemaRegistry::new());
        let norm = EventNormalizer::new(schema);
        let raw = RawEsfEvent {
            event_type: EventType::FileOpen,
            timestamp_ns: 200,
            pid: 42,
            ppid: 1,
            uid: 501,
            gid: 20,
            comm: "cat".into(),
            primary: "/etc/passwd".into(),
            secondary: String::new(),
            metadata: EventMetadata {
                mode: Some(0o644),
                ..Default::default()
            },
        };
        assert!(norm.normalize(&raw).is_ok());
    }

    #[test]
    fn test_normalize_rename() {
        let schema = Arc::new(SchemaRegistry::new());
        let norm = EventNormalizer::new(schema);
        let raw = RawEsfEvent {
            event_type: EventType::FileRename,
            timestamp_ns: 300,
            pid: 99,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: "mv".into(),
            primary: "/tmp/a".into(),
            secondary: "/tmp/b".into(),
            metadata: EventMetadata {
                source_path: Some("/tmp/a".into()),
                dest_path: Some("/tmp/b".into()),
                ..Default::default()
            },
        };
        assert!(norm.normalize(&raw).is_ok());
    }
}
