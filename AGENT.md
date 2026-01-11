# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Kestrel is a next-generation endpoint behavior detection engine written in Rust. It combines eBPF for event collection, a host-executed NFA for sequence matching, and dual runtime support (Wasm + LuaJIT) for rule predicates with EQL compatibility. See [plan.md](./plan.md) for the complete technical specification and [README.md](./README.md) for project status.

## Development Commands

### Building

```bash
# Debug build (faster compilation)
cargo build

# Release build (optimized)
cargo build --release

# Build specific crate
cargo build -p kestrel-schema
```

### Testing

```bash
# Run all tests (workspace-wide)
cargo test --workspace

# Run tests for a specific crate
cargo test -p kestrel-schema

# Run tests with output
cargo test --workspace -- --nocapture

# Run specific test
cargo test test_register_field --workspace
```

### Code Quality

```bash
# Format code
cargo fmt

# Lint with clippy
cargo clippy --workspace

# Fix clippy warnings automatically
cargo clippy --workspace --fix
```

### Running the CLI

```bash
# Run detection engine with default rules directory
cargo run --bin kestrel -- run

# Run with specific rules directory
cargo run --bin kestrel -- run --rules /path/to/rules

# Validate rules without running
cargo run --bin kestrel -- validate --rules ./rules

# List all loaded rules
cargo run --bin kestrel -- list --rules ./rules
```

### Example Rule Locations

The project includes example rules in:
- `rules/wasm_example_rule/` - Wasm-based rule example
- `rules/lua_example_rule/` - Lua-based rule example

See respective `README.md` files in those directories for details on rule structure.

## Architecture Overview

Kestrel uses a layered, modular architecture. Understanding the crate dependencies is critical:

### Crate Dependency Graph

```
kestrel-schema/      (foundation - no dependencies on other kestrel crates)
    ↓
kestrel-event/       (depends on schema)
    ↓
kestrel-core/        (depends on event, schema)
    ↓
kestrel-rules/       (depends on event, schema)
    ↓
kestrel-engine/      (depends on core, event, rules, schema, optional runtimes)
    ↓
kestrel-cli/         (depends on engine)
    ↓

kestrel-runtime-wasm/  (parallel to engine - depends on schema, event)
kestrel-runtime-lua/   (parallel to engine - depends on schema, event)
kestrel-eql/           (parallel to engine - depends on schema, event)
```

### Key Abstractions

**SchemaRegistry** (`kestrel-schema`): Central type system that maps field paths (like "process.executable") to numeric FieldIds. Field ID lookups are much faster than string comparisons - always use IDs at runtime.

**Event** (`kestrel-event`): Sparse data structure using `SmallVec` for field storage. Events have dual timestamps (monotonic for ordering, wall clock for forensics) and an EntityKey for grouping related events (e.g., by process).

**EventBus** (`kestrel-core`): Async transport with batching, backpressure, and configurable queue depths. Uses tokio channels and semaphores for flow control.

**RuleManager** (`kestrel-rules`): Handles rule loading from JSON/YAML/EQL formats. Supports concurrent loading with semaphore limits and version management.

**DetectionEngine** (`kestrel-engine`): Central coordinator that wires together EventBus, AlertOutput, RuleManager, and optional runtime engines (Wasm/Lua).

## Core Design Principles

1. **Test-Driven Development**: The project uses TDD. Always write tests before implementing new features. Look at existing test patterns in each crate.

2. **Strong Typing via SchemaRegistry**: All event fields are registered in the SchemaRegistry at startup. Rules compile field paths to FieldIds once, then use integer IDs for all runtime access.

3. **Sparse Events**: Events only store non-null fields using `SmallVec` for inline optimization. This is critical for memory efficiency at scale.

4. **Async-First**: Built on Tokio throughout. Use async/await for I/O and concurrent operations.

5. **Dual Runtime Future**: Both Wasm and LuaJIT will implement the same Predicate ABI:
   - `pred_init(ctx)` - Initialize predicate state
   - `pred_eval(event, ctx) -> bool` - Evaluate if event matches
   - `pred_capture(event, ctx) -> captures` - Extract matched data

6. **Three Execution Modes**: The same detection core will support:
   - Inline/Enforce (real-time blocking)
   - Online/Detect (real-time detection)
   - Offline/Replay (forensic analysis with identical results)

## Phase Development Status

The project follows a phased approach (see plan.md §12):

- **Phase 0** (Complete): Architecture skeleton - Event Schema, EventBus, RuleManager, Alert system
- **Phase 1**: Wasm Runtime + Host API v1
- **Phase 2**: LuaJIT Runtime integration
- **Phase 3**: EQL Compiler (eqlc)
- **Phase 4**: Host NFA Sequence Engine
- **Phase 5**: eBPF collection layer
- **Phase 6**: Real-time blocking
- **Phase 7**: Offline replay with reproducibility

When implementing features, consider which phase they belong to and don't build capabilities ahead of their phase dependencies.

## Common Patterns

### Adding a New Event Field

```rust
// In kestrel-schema, register the field
let field_id = registry.register_field(FieldDef {
    path: "process.executable".to_string(),
    data_type: FieldDataType::String,
    description: Some("Process executable path".to_string()),
})?;
```

### Creating an Event

```rust
use kestrel_event::Event;

let event = Event::builder()
    .event_type_id(event_type_id)
    .ts_mono_ns(ts_now)
    .ts_wall_ns(wall_now)
    .entity_key(entity_key)
    .field(field_id, TypedValue::String("/bin/bash".to_string()))
    .build();
```

### Working with the RuleManager

```rust
use kestrel_rules::{RuleManager, RuleManagerConfig};

let config = RuleManagerConfig {
    rules_dir: PathBuf::from("./rules"),
    watch_enabled: false,
    max_concurrent_loads: 4,
};

let manager = RuleManager::new(config);
let stats = manager.load_all().await?;
```

## Performance Considerations

- **Field IDs over strings**: Always use `FieldId` (u32) for runtime field access, not string paths
- **SmallVec optimization**: Events use `SmallVec` for inline storage of small field sets
- **ahash over std::collections**: Uses ahash for faster hashing throughout
- **Arc for shared data**: SchemaRegistry uses Arc for cheap cloning of shared registries
- **Batching**: EventBus processes events in configurable batch sizes to reduce overhead
- **Backpressure**: Configurable queue depths and timeouts prevent unbounded memory growth

## Testing Guidelines

- Unit tests go in the same module as the code, in a `#[cfg(test)]` module
- Integration tests go in `tests/` directory within each crate
- Use `tempfile` crate for creating temporary directories in tests (already a dependency)
- Mock expensive operations; focus on testing logic, not I/O
- Example test patterns can be found in `kestrel-schema/src/lib.rs`

## Git Workflow

The project uses conventional commits (see recent commit history):
- `feat:` for new features
- `docs:` for documentation changes
- `fix:` for bug fixes
- `refactor:` for code restructuring without behavior changes

Commit messages should be descriptive and reference relevant issue/PR numbers when applicable.