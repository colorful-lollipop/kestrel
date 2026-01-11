# Kestrel Event - Planning Document

## Current Status (v0.8)

**Stable** - Event structure optimized with binary search

### Completed
- Event struct with sparse fields (SmallVec)
- Sorted fields + binary search (O(log n) lookup)
- EventBuilder pattern
- Field type conversion (as_i64, as_str, etc.)
- Source identification

### Test Coverage
```
cargo test -p kestrel-event --lib
test_event_builder                      ✓
test_event_get_field                    ✓
test_event_with_source                  ✓
test_event_fields_sorted                ✓
test_event_with_field_sorts             ✓
```

## Planned Evolution

### v0.9 - Performance Optimization
```
Milestone: Reduce memory and improve throughput
├─ Field compression
│  ├─ Delta encoding for sequential field IDs
│  ├─ Type-specific compression
│  └─ SmallVec inline expansion (8 → 16)
│
├─ Bulk operations
│  ├─ with_fields() for batch insertion
│  ├─ drain_fields() for iteration
│  └─ retain_fields() for filtering
│
└─ Field projection
   ├─ Lazy field loading
   ├─ Projection API for field selection
   └─ Clone-on-read optimization
```

### v1.0 - Zero-Copy Architecture
```
Milestone: Eliminate unnecessary copies
├─ Compressed format
│  ├─ Binary encoding (protobuf-like)
│  ├─ Memory-mapped events
│  └─ Shared buffer backing
│
├─ Zero-copy field access
│  ├─ Borrowed TypedValue
│  ├─ Rc/Arc for shared strings
│  └─ Reference counting for large data
│
└─ Event pooling
   ├─ Event allocator
   ├─ Reset/reuse pattern
   └─ Reduced allocation
```

## API Evolution

### v0.9 Additions
```rust
impl Event {
    // Batch operations
    pub fn with_fields(self, fields: &[(FieldId, TypedValue)]) -> Self;
    pub fn drain_fields(&mut self) -> impl Iterator<Item = (FieldId, TypedValue)>;
    pub fn retain_fields(&mut self, filter: impl Fn(FieldId, &TypedValue) -> bool);
    
    // Projection
    pub fn project(&self, fields: &[FieldId]) -> Event;
    pub fn get_fields_typed<T>(&self, ids: &[FieldId]) -> Vec<Option<T>>;
}
```

### v1.0 Changes
```rust
// Potential breaking change
pub fn get_field(&self, field_id: FieldId) -> Option<&TypedValue>;
// May become:
pub fn get_field(&self, field_id: FieldId) -> Option<&TypedValue<'_>>;  // Lifetime
```

## Performance Targets

| Metric | Target | Current |
|--------|--------|---------|
| Field lookup (8 fields) | <100ns | ~80ns |
| Event construction | <1μs | ~500ns |
| Clone (4 fields) | <200ns | ~150ns |
| Memory (4 fields) | <64 bytes | ~56 bytes |

## Dependencies to Add

```
# v0.9
parking_lot = "0.12"    # Faster synchronization

# v1.0
memmap2 = "0.9"         # Memory-mapped events
lz4_flex = "0.11"       # Fast compression
