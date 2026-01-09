//! Kestrel Event Model
//!
//! This module defines the event structure used throughout the Kestrel detection engine.
//! Events are designed for high performance and reproducibility.

use kestrel_schema::*;
use smallvec::SmallVec;

/// Represents a single event in the system
#[derive(Debug, Clone)]
pub struct Event {
    /// Event type identifier
    pub event_type_id: EventTypeId,

    /// Monotonic timestamp (for ordering and windows)
    pub ts_mono_ns: TimestampMono,

    /// Wall clock timestamp (for display and forensics)
    pub ts_wall_ns: TimestampWall,

    /// Entity key for grouping (e.g., process + start_time)
    pub entity_key: EntityKey,

    /// Event fields (sparse storage using field_id -> value mapping)
    pub fields: SmallVec<[(FieldId, TypedValue); 8]>,

    /// Optional source identifier
    pub source_id: Option<String>,
}

impl Event {
    /// Create a new event
    pub fn new(
        event_type_id: EventTypeId,
        ts_mono_ns: TimestampMono,
        ts_wall_ns: TimestampWall,
        entity_key: EntityKey,
    ) -> Self {
        Self {
            event_type_id,
            ts_mono_ns,
            ts_wall_ns,
            entity_key,
            fields: SmallVec::new(),
            source_id: None,
        }
    }

    /// Add a field to the event
    pub fn with_field(mut self, field_id: FieldId, value: TypedValue) -> Self {
        self.fields.push((field_id, value));
        self
    }

    /// Get a field value by field ID
    pub fn get_field(&self, field_id: FieldId) -> Option<&TypedValue> {
        self.fields.iter().find(|(id, _)| *id == field_id).map(|(_, v)| v)
    }

    /// Check if event has a specific field
    pub fn has_field(&self, field_id: FieldId) -> bool {
        self.fields.iter().any(|(id, _)| *id == field_id)
    }

    /// Set source identifier
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source_id = Some(source.into());
        self
    }

    /// Create an event builder
    pub fn builder() -> EventBuilder {
        EventBuilder::default()
    }
}

/// Event builder for convenient event construction
#[derive(Debug, Default)]
pub struct EventBuilder {
    event_type_id: Option<EventTypeId>,
    ts_mono_ns: Option<TimestampMono>,
    ts_wall_ns: Option<TimestampWall>,
    entity_key: Option<EntityKey>,
    fields: SmallVec<[(FieldId, TypedValue); 8]>,
    source_id: Option<String>,
}

impl EventBuilder {
    /// Set event type
    pub fn event_type(mut self, event_type_id: EventTypeId) -> Self {
        self.event_type_id = Some(event_type_id);
        self
    }

    /// Set monotonic timestamp
    pub fn ts_mono(mut self, ts: TimestampMono) -> Self {
        self.ts_mono_ns = Some(ts);
        self
    }

    /// Set wall clock timestamp
    pub fn ts_wall(mut self, ts: TimestampWall) -> Self {
        self.ts_wall_ns = Some(ts);
        self
    }

    /// Set entity key
    pub fn entity_key(mut self, key: EntityKey) -> Self {
        self.entity_key = Some(key);
        self
    }

    /// Add a field
    pub fn field(mut self, field_id: FieldId, value: TypedValue) -> Self {
        self.fields.push((field_id, value));
        self
    }

    /// Set source
    pub fn source(mut self, source: impl Into<String>) -> Self {
        self.source_id = Some(source.into());
        self
    }

    /// Build the event
    pub fn build(self) -> Result<Event, BuildError> {
        Ok(Event {
            event_type_id: self
                .event_type_id
                .ok_or(BuildError::MissingField("event_type_id"))?,
            ts_mono_ns: self
                .ts_mono_ns
                .ok_or(BuildError::MissingField("ts_mono_ns"))?,
            ts_wall_ns: self
                .ts_wall_ns
                .ok_or(BuildError::MissingField("ts_wall_ns"))?,
            entity_key: self
                .entity_key
                .ok_or(BuildError::MissingField("entity_key"))?,
            fields: self.fields,
            source_id: self.source_id,
        })
    }
}

/// Error building an event
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("Missing required field: {0}")]
    MissingField(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_builder() {
        let event = Event::builder()
            .event_type(1)
            .ts_mono(1234567890)
            .ts_wall(1234567890)
            .entity_key(42)
            .field(1, TypedValue::String("test".into()))
            .build()
            .unwrap();

        assert_eq!(event.event_type_id, 1);
        assert_eq!(event.ts_mono_ns, 1234567890);
        assert_eq!(event.entity_key, 42);
        assert!(event.has_field(1));
    }

    #[test]
    fn test_event_get_field() {
        let event = Event::builder()
            .event_type(1)
            .ts_mono(0)
            .ts_wall(0)
            .entity_key(0)
            .field(1, TypedValue::I64(42))
            .build()
            .unwrap();

        let value = event.get_field(1).unwrap();
        assert_eq!(value.as_i64(), Some(42));
    }

    #[test]
    fn test_event_with_source() {
        let event = Event::builder()
            .event_type(1)
            .ts_mono(0)
            .ts_wall(0)
            .entity_key(0)
            .source("ebpf")
            .build()
            .unwrap();

        assert_eq!(event.source_id.as_ref().map(|s| s.as_str()), Some("ebpf"));
    }
}

// Re-export kestrel_schema for convenience
pub use kestrel_schema;
