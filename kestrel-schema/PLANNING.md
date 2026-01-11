# Kestrel Schema - Planning Document

## Current Status (v0.8)

**Stable** - Foundation layer complete

### Completed
- FieldId type system (u32)
- SchemaRegistry with path → ID mapping
- TypedValue enum with all basic types
- EventTypeId and EntityKey types
- Serialization support

### Test Coverage
```
cargo test -p kestrel-schema --lib
test_register_field          ✓
test_field_path_lookup       ✓
test_duplicate_field         ✓
test_typed_value_serde       ✓
```

## Planned Evolution

### v0.9 - Schema Federation
```
Milestone: Support schema sharing across nodes
├─ Nested field support
│  ├─ path: "process.parent.pid"
│  ├─ parser: Split by "."
│  └─ storage: Hierarchical map
│
├─ Schema versioning
│  ├─ Version field in FieldDef
│  ├─ Hot reload with compatibility check
│  └─ Migration API
│
└─ Type coercion
   ├─ I64 → F64 automatic
   ├─ String → regex pattern
   └─ Custom coercion rules
```

### v1.0 - Advanced Schema
```
Milestone: Enterprise features
├─ Schema federation
│  ├─ Remote schema registry (gRPC)
│  ├─ Schema sync protocol
│  └─ Conflict resolution
│
├─ Schema evolution
│  ├─ Backward compatibility checking
│  ├─ Field deprecation workflow
│  └─ Breaking change detection
│
└─ Custom types
   ├─ Plugin system for custom types
   ├─ Type validators
   └─ Custom serialization
```

## API Compatibility

### v0.x Guarantees
- FieldId: u32 (stable)
- EventTypeId: u16 (stable)
- EntityKey: u128 (stable)
- TypedValue variants: stable

### Deprecation Policy
- 2 minor version deprecation notice
- Full migration guide
- Compatibility shim

## Performance Targets

| Metric | Target | Current |
|--------|--------|---------|
| Field lookup | <50ns | ~30ns |
| Schema registration | <100μs | ~50μs |
| Memory per field | <64 bytes | ~48 bytes |

## Dependencies to Add

```
# v0.9
prost = "0.12"          # gRPC serialization
tonic = "0.11"          # gRPC server

# v1.0
dyn-clone = "1.0"       # Custom type plugins
