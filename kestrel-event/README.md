# Kestrel Event Model

**Foundation Layer - Event Structure & Field Storage**

## Module Goal

Define the Event structure used throughout Kestrel's detection pipeline:
- Sparse field storage using SmallVec (stack optimization for typical <8 fields)
- Sorted fields with binary search for O(log n) lookups
- Event builder pattern for convenient construction

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Event                                 │
├─────────────────────────────────────────────────────────────┤
│ event_id: u64         # Monotonically increasing ID         │
│ event_type_id: u16    # Type of event (exec=1, open=2...)   │
│ ts_mono_ns: u64       # Monotonic timestamp (ordering)      │
│ ts_wall_ns: u64       # Wall clock timestamp (display)      │
│ entity_key: u128      # Entity grouping key                 │
│ fields: SmallVec<[(FieldId, TypedValue); 8]>  # Sparse     │
│ source_id: Option<String>  # Event source (ebpf, replay)   │
└─────────────────────────────────────────────────────────────┘

# Fields stored sorted by FieldId for binary search
# Typical event has 4-8 fields → stays on stack
```

## Core Interfaces

### Event Construction
```rust
impl Event {
    pub fn new(
        event_type_id: EventTypeId,
        ts_mono_ns: TimestampMono,
        ts_wall_ns: TimestampWall,
        entity_key: EntityKey,
    ) -> Self;
    
    pub fn with_field(mut self, field_id: FieldId, value: TypedValue) -> Self {
        // Inserts in sorted position for binary search
        let pos = self.fields.partition_point(|(id, _)| *id < field_id);
        self.fields.insert(pos, (field_id, value));
        self
    }
}
```

### Field Lookup (O(log n) via binary search)
```rust
impl Event {
    pub fn get_field(&self, field_id: FieldId) -> Option<&TypedValue> {
        // Binary search: ~3 comparisons for 8 fields vs ~8 for linear
        self.fields
            .binary_search_by_key(&field_id, |(id, _)| *id)
            .ok()
            .map(|idx| &self.fields[idx].1)
    }
    
    pub fn has_field(&self, field_id: FieldId) -> bool {
        self.fields.binary_search_by_key(&field_id, |(id, _)| *id).is_ok()
    }
}
```

### EventBuilder
```rust
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
    pub fn build(self) -> Result<Event, BuildError> {
        let mut fields = self.fields;
        fields.sort_by_key(|(id, _)| *id);  // Ensure sorted order
        Ok(Event { fields, ... })
    }
}
```

## Usage Example

```rust
use kestrel_event::{Event, TypedValue};
use kestrel_schema::TimestampMono;

let event = Event::builder()
    .event_type(1)  // exec event
    .ts_mono(1_000_000_000)
    .ts_wall(1_000_000_000)
    .entity_key(0xabc123)  // process ID as entity key
    .field(1, TypedValue::String("/bin/ls".into()))   // executable
    .field(2, TypedValue::I64(1234))                  // pid
    .field(3, TypedValue::I64(5678))                  // ppid
    .build()
    .unwrap();

// Field lookup (O(log n))
let executable = event.get_field(1).unwrap();
assert_eq!(executable.as_str(), Some("/bin/ls"));

// Type conversion
let pid = event.get_field(2).unwrap().as_i64();
assert_eq!(pid, Some(1234));
```

## Performance Characteristics

| Operation | Time Complexity | Notes |
|-----------|----------------|-------|
| Field lookup | O(log n) | Binary search on sorted fields |
| Field insertion | O(n) | Must maintain sort order |
| Typical memory | ~64 bytes | 4 fields + Event struct (stack) |
| Max inline fields | 8 | SmallVec optimization |

### Comparison: Linear vs Binary Search

For an event with 8 fields:
- **Before (O(n))**: Up to 8 comparisons
- **After (O(log n))**: Exactly 3 comparisons

```rust
// Linear scan (old)
fields.iter().find(|(id, _)| *id == field_id)

// Binary search (new)  
fields.binary_search_by_key(&field_id, |(id, _)| *id)
```

## Planned Evolution

### v0.8 (Current)
- [x] Sorted fields + binary search
- [x] SmallVec for stack optimization
- [x] Builder pattern

### v0.9
- [ ] Field compression (delta encoding)
- [ ] Bulk field loading
- [ ] Field projection (lazy evaluation)

### v1.0
- [ ] Compressed event format
- [ ] Memory-mapped events
- [ ] Zero-copy field access

## Test Coverage

```bash
cargo test -p kestrel-event --lib

# Tests
test_event_builder              # Builder pattern works
test_event_get_field            # Binary search lookup
test_event_with_source          # Source ID setting
test_event_fields_sorted        # Fields sorted by ID
test_event_with_field_sorts     # with_field maintains order
```

## Dependencies

```
kestrel-event
├── kestrel-schema (TypedValue, FieldId, etc.)
├── smallvec (stack-optimized vector)
└── ahash (fast hashing)
```

## Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("Missing required field: {0}")]
    MissingField(&'static str),
}
```
