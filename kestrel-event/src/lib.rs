//! Kestrel Event Model
//!
//! This module defines the event structure used throughout the Kestrel detection engine.
//! Events are designed for high performance and reproducibility.

use kestrel_schema::*;
use smallvec::SmallVec;

/// Represents a single event in the system
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

    /// Get a field value by field ID
    /// For small field counts (≤8), uses linear search for better cache locality
    /// For larger counts, uses binary search (O(log n))
    #[inline]
    pub fn get_field(&self, field_id: FieldId) -> Option<&TypedValue> {
        // For small field counts, linear search is faster due to cache locality
        if self.fields.len() <= 8 {
            self.fields
                .iter()
                .find(|(id, _)| *id == field_id)
                .map(|(_, value)| value)
        } else {
            self.fields
                .binary_search_by_key(&field_id, |(id, _)| *id)
                .ok()
                .map(|idx| &self.fields[idx].1)
        }
    }

    /// Check if event has a specific field
    /// For small field counts (≤8), uses linear search for better cache locality
    /// For larger counts, uses binary search (O(log n))
    #[inline]
    pub fn has_field(&self, field_id: FieldId) -> bool {
        if self.fields.len() <= 8 {
            self.fields.iter().any(|(id, _)| *id == field_id)
        } else {
            self.fields
                .binary_search_by_key(&field_id, |(id, _)| *id)
                .is_ok()
        }
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

    /// Get a field value as u32, with a default fallback
    ///
    /// Looks up the field by ID, converts to u32 if possible.
    pub fn get_field_as_u32(&self, field_id: FieldId, default: u32) -> u32 {
        self.get_field(field_id)
            .and_then(|value| match value {
                TypedValue::U64(v) => u32::try_from(*v).ok(),
                TypedValue::I64(v) if *v >= 0 => u32::try_from(*v).ok(),
                _ => None,
            })
            .unwrap_or(default)
    }

    /// Get a field value as String, with a default fallback
    pub fn get_field_as_string(
        &self,
        field_id: FieldId,
        default: impl Into<std::sync::Arc<str>>,
    ) -> std::sync::Arc<str> {
        self.get_field(field_id)
            .and_then(|value| match value {
                TypedValue::String(s) => Some(std::sync::Arc::clone(s)),
                _ => None,
            })
            .unwrap_or_else(|| default.into())
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

pub mod host_api;

/// Predicate evaluation error type
#[derive(Debug, Clone, thiserror::Error)]
pub enum PredicateError {
    #[error("Predicate error: {0}")]
    Error(String),
    #[error("Predicate not found: {0}")]
    NotFound(String),
    #[error("Evaluation failed: {0}")]
    EvaluationFailed(String),
}

/// Result type for predicate operations
pub type PredicateResult<T> = Result<T, PredicateError>;

/// Trait for evaluating predicates against events
///
/// This trait is implemented by Wasm and Lua runtimes to provide
/// predicate evaluation capabilities to the NFA engine.
#[async_trait::async_trait]
pub trait PredicateEvaluator: Send + Sync {
    /// Evaluate a predicate against an event
    async fn evaluate(&self, predicate_id: &str, event: &Event) -> PredicateResult<bool>;

    /// Get the field IDs required by a predicate
    fn get_required_fields(&self, predicate_id: &str) -> PredicateResult<Vec<u32>>;

    /// Check if a predicate exists
    fn has_predicate(&self, predicate_id: &str) -> bool;
}

// Re-export kestrel_schema for convenience
pub use kestrel_schema;

/// Test helpers for constructing events in tests.
pub mod test_helpers {
    use super::*;

    /// Create a test event with common defaults
    pub fn test_event(event_type: u16, entity_key: u128, ts_mono: u64) -> Event {
        Event::builder()
            .event_type(event_type)
            .entity_key(entity_key)
            .ts_mono(ts_mono)
            .ts_wall(ts_mono)
            .build()
            .expect("test event build should not fail")
    }

    /// Create a test event with fields
    pub fn test_event_with_fields(
        event_type: u16,
        entity_key: u128,
        ts_mono: u64,
        fields: Vec<(FieldId, TypedValue)>,
    ) -> Event {
        let mut builder = Event::builder()
            .event_type(event_type)
            .entity_key(entity_key)
            .ts_mono(ts_mono)
            .ts_wall(ts_mono);

        for (field_id, value) in fields {
            builder = builder.field(field_id, value);
        }

        builder.build().expect("test event build should not fail")
    }
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

        assert_eq!(event.source_id.as_deref(), Some("ebpf"));
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
