# Kestrel Event Schema

**Foundation Layer - Type System & Schema Registry**

## Module Goal

Provide the foundational type system for Kestrel's detection engine, enabling:
- Strongly typed field definitions with stable FieldId
- Schema registry for field path → ID mapping
- TypedValue enum for type-safe value representation

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Code                         │
├─────────────────────────────────────────────────────────────┤
│  SchemaRegistry                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ get_field_id("process.executable") → FieldId(1)     │   │
│  │ get_field(1) → FieldDef { path, data_type }         │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  TypedValue                                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ I64(i64) | U64(u64) | F64(f64) | Bool(bool)        │   │
│  │ String(String) | Bytes(Vec<u8>) | Array(Vec<T>)    │   │
│  │ Null                                               │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Core Types

### FieldId
```rust
pub type FieldId = u32;  // Stable identifier for fast lookups
```

### EventTypeId
```rust
pub type EventTypeId = u16;  // Identifies event types (exec=1, open=2, etc.)
```

### EntityKey
```rust
pub type EntityKey = u128;  // Groups related events (process + start_time)
```

### Timestamp Types
```rust
pub type TimestampMono = u64;  // Monotonic nanoseconds (ordering)
pub type TimestampWall = u64;  // Wall clock nanoseconds (display)
```

## Key Interfaces

### SchemaRegistry
```rust
pub struct SchemaRegistry {
    pub fn new() -> Self;
    
    // Field management
    pub fn register_field(&mut self, def: FieldDef) -> Result<FieldId, SchemaError>;
    pub fn get_field(&self, id: FieldId) -> Option<&FieldDef>;
    pub fn get_field_id(&self, path: &str) -> Option<FieldId>;
    
    // Event type management  
    pub fn register_event_type(&mut self, def: EventTypeDef) -> Result<EventTypeId, SchemaError>;
    pub fn get_event_type_id(&self, name: &str) -> Option<EventTypeId>;
}
```

### FieldDef
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDef {
    pub path: String,              // e.g., "process.executable"
    pub data_type: FieldDataType,  // Type of the field
    pub description: Option<String>,
}
```

## Usage Example

```rust
use kestrel_schema::{SchemaRegistry, FieldDef, FieldDataType};

let mut schema = SchemaRegistry::new();

// Register a field
let field = FieldDef {
    path: "process.executable".to_string(),
    data_type: FieldDataType::String,
    description: Some("Process executable path".to_string()),
};
let field_id = schema.register_field(field).unwrap();

// Lookup by path
let id = schema.get_field_id("process.executable").unwrap();
assert_eq!(id, 1);

// Lookup by ID
let def = schema.get_field(1).unwrap();
assert_eq!(def.path, "process.executable");
```

## Planned Evolution

### v0.8 (Current)
- [x] Stable FieldId system
- [x] Basic type support (I64, U64, String, Bool, F64)
- [x] SchemaRegistry with path → ID mapping

### v0.9
- [ ] Nested field support (e.g., "process.parent.pid")
- [ ] Schema versioning for hot reload
- [ ] Type coercion rules

### v1.0
- [ ] Schema federation across nodes
- [ ] Schema evolution validation
- [ ] Custom field types via plugins

## Test Coverage

```bash
cargo test -p kestrel-schema --lib

# Tests
test_register_field          # Field registration and ID assignment
test_field_path_lookup       # Path → ID resolution
test_duplicate_field         # Duplicate registration error
test_typed_value_serde       # Serialization round-trip
```

## Dependencies

```
kestrel-schema
├── serde (serialization)
├── ahash (fast hashing)
└── thiserror (error handling)
```

## Performance

- Field lookup: O(1) via HashMap
- Field registration: O(1) amortized
- Memory: ~32 bytes per registered field
