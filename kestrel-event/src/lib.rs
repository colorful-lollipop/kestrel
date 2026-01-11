//! Kestrel Event Model
//!
//! This module defines the event structure used throughout the Kestrel detection engine.
//! Events are designed for high performance and reproducibility.

use kestrel_schema::*;
use smallvec::SmallVec;

/// Represents a single event in the system
#[derive(Debug, Clone)]
pub struct Event {
    /// Unique event ID (monotonically increasing, for stable sorting in replay)
    pub event_id: u64,

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
            event_id: 0, // Will be assigned by event collector
            event_type_id,
            ts_mono_ns,
            ts_wall_ns,
            entity_key,
            fields: SmallVec::new(),
            source_id: None,
        }
    }

    /// Add a field to the event (inserts in sorted order for binary search)
    pub fn with_field(mut self, field_id: FieldId, value: TypedValue) -> Self {
        let pos = self.fields.partition_point(|(id, _)| *id < field_id);
        self.fields.insert(pos, (field_id, value));
        self
    }

    /// Get a field value by field ID using binary search (O(log n))
    pub fn get_field(&self, field_id: FieldId) -> Option<&TypedValue> {
        self.fields
            .binary_search_by_key(&field_id, |(id, _)| *id)
            .ok()
            .map(|idx| &self.fields[idx].1)
    }

    /// Check if event has a specific field using binary search (O(log n))
    pub fn has_field(&self, field_id: FieldId) -> bool {
        self.fields
            .binary_search_by_key(&field_id, |(id, _)| *id)
            .is_ok()
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
    event_id: Option<u64>,
    event_type_id: Option<EventTypeId>,
    ts_mono_ns: Option<TimestampMono>,
    ts_wall_ns: Option<TimestampWall>,
    entity_key: Option<EntityKey>,
    fields: SmallVec<[(FieldId, TypedValue); 8]>,
    source_id: Option<String>,
}

impl EventBuilder {
    /// Set event ID
    pub fn event_id(mut self, event_id: u64) -> Self {
        self.event_id = Some(event_id);
        self
    }

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

    /// Build the event (sorts fields for binary search optimization)
    pub fn build(self) -> Result<Event, BuildError> {
        let mut fields = self.fields;
        fields.sort_by_key(|(id, _)| *id);
        Ok(Event {
            event_id: self.event_id.unwrap_or(0),
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
            fields,
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

    #[test]
    fn test_event_fields_sorted_for_binary_search() {
        let event = Event::builder()
            .event_type(1)
            .ts_mono(0)
            .ts_wall(0)
            .entity_key(0)
            .field(5, TypedValue::I64(50))
            .field(1, TypedValue::I64(10))
            .field(3, TypedValue::I64(30))
            .field(2, TypedValue::I64(20))
            .field(4, TypedValue::I64(40))
            .build()
            .unwrap();

        let ids: Vec<FieldId> = event.fields.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![1, 2, 3, 4, 5]);

        assert_eq!(event.get_field(1).unwrap().as_i64(), Some(10));
        assert_eq!(event.get_field(3).unwrap().as_i64(), Some(30));
        assert_eq!(event.get_field(5).unwrap().as_i64(), Some(50));
        assert_eq!(event.get_field(99), None);

        assert!(event.has_field(1));
        assert!(event.has_field(5));
        assert!(!event.has_field(99));
    }

    #[test]
    fn test_event_with_field_maintains_sort_order() {
        let event = Event::new(1, 0, 0, 0)
            .with_field(3, TypedValue::String("third".into()))
            .with_field(1, TypedValue::String("first".into()))
            .with_field(5, TypedValue::String("fifth".into()))
            .with_field(2, TypedValue::String("second".into()))
            .with_field(4, TypedValue::String("fourth".into()));

        let ids: Vec<FieldId> = event.fields.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![1, 2, 3, 4, 5]);
    }
}

// Re-export kestrel_schema for convenience
pub use kestrel_schema;
