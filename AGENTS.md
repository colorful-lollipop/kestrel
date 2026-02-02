# AGENTS.md

This file provides guidance for AI coding agents working with the Kestrel project.

## Project Overview

**Kestrel** is a next-generation endpoint behavior detection engine written in Rust. It combines eBPF for kernel-level event collection, a host-executed NFA (Non-deterministic Finite Automaton) for sequence matching, and dual runtime support (Wasm + LuaJIT) for rule predicates with EQL (Event Query Language) compatibility.

### Key Characteristics

- **Language**: Rust (Edition 2021, MSRV 1.82)
- **Platform**: Linux kernel 5.10+ (eBPF support required)
- **Architecture**: Modular workspace with 18 crates
- **License**: Apache-2.0
- **Status**: Production-ready (v1.0.0)

### Target Use Cases

- Endpoint EDR (Endpoint Detection and Response)
- Application whitelisting
- Threat hunting
- Security research with reproducible offline analysis

## Workspace Structure

The project is organized as a Cargo workspace with the following crates:

### Core Crates (Foundation Layer)

| Crate | Description | Dependencies |
|-------|-------------|--------------|
| `kestrel-schema` | Type system, FieldId mapping, SchemaRegistry | None (foundation) |
| `kestrel-event` | Sparse event structure with dual timestamps | schema |
| `kestrel-core` | EventBus, Alert, Action, Time/Replay | schema, event |

### Engine Crates (Processing Layer)

| Crate | Description | Dependencies |
|-------|-------------|--------------|
| `kestrel-rules` | Rule loading/management (JSON/YAML/EQL) | schema, event |
| `kestrel-engine` | Detection engine core, rule evaluation | core, rules, nfa |
| `kestrel-nfa` | NFA sequence engine with state management | schema, event |
| `kestrel-hybrid-engine` | Hybrid DFA/NFA engine | nfa, lazy-dfa |

### Runtime Crates (Execution Layer)

| Crate | Description | Dependencies |
|-------|-------------|--------------|
| `kestrel-runtime-wasm` | Wasmtime integration, Host API v1 | schema, event |
| `kestrel-runtime-lua` | LuaJIT integration via mlua | schema, event |
| `kestrel-eql` | EQL parser, IR, Wasm codegen | schema, event |

### Platform Crates (System Layer)

| Crate | Description | Dependencies |
|-------|-------------|--------------|
| `kestrel-ebpf` | eBPF programs, LSM hooks, RingBuf | core |
| `kestrel-ffi` | Foreign Function Interface bindings | engine |

### Tooling Crates

| Crate | Description | Dependencies |
|-------|-------------|--------------|
| `kestrel-cli` | Main CLI binary (`kestrel` command) | engine |
| `kestrel-benchmark` | Performance testing suite | engine |

### Algorithm Crates

| Crate | Description |
|-------|-------------|
| `kestrel-ac-dfa` | Aho-Corasick DFA implementation |
| `kestrel-lazy-dfa` | Lazy DFA construction |

### Dependency Graph

```
kestrel-schema (foundation - no internal deps)
    ↓
kestrel-event
    ↓
kestrel-core
    ↓
kestrel-rules
    ↓
kestrel-engine ← kestrel-nfa ← (runtime-wasm, runtime-lua, eql)
    ↓
kestrel-cli
```

## Build Commands

### Development Build

```bash
# Debug build (faster compilation, slower execution)
cargo build --workspace

# Build specific crate
cargo build -p kestrel-engine
```

### Release Build

```bash
# Optimized release build
# - opt-level = 3
# - lto = true
# - codegen-units = 1
# - strip = true
cargo build --workspace --release

# Release binary location: target/release/kestrel
```

### Feature Flags

The engine supports optional features:

```bash
# Build with only Wasm runtime
cargo build -p kestrel-engine --no-default-features --features wasm

# Build with only Lua runtime
cargo build -p kestrel-engine --no-default-features --features lua

# Build with both (default)
cargo build -p kestrel-engine --features "wasm,lua"
```

## Testing Commands

### Run All Tests

```bash
# Run all tests across workspace
cargo test --workspace

# Run with output visible
cargo test --workspace -- --nocapture

# Run tests for specific crate
cargo test -p kestrel-schema
cargo test -p kestrel-nfa
```

### Integration Tests

```bash
# E2E tests
cargo test --workspace --test '*e2e*'

# Specific integration test files
# - kestrel-engine/tests/detection_scenarios.rs
# - kestrel-engine/tests/integration_e2e.rs
# - kestrel-hybrid-engine/tests/comprehensive_e2e.rs
```

### Code Coverage

```bash
# Using cargo-llvm-cov
cargo install cargo-llvm-cov
cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info

# Or using tarpaulin
cargo install cargo-tarpaulin
cargo tarpaulin --workspace --out Html
```

## Code Quality Commands

### Formatting

```bash
# Format all code (uses rustfmt.toml config)
cargo fmt --all

# Check formatting without changes
cargo fmt --all -- --check
```

### Linting

```bash
# Run clippy with project config (uses clippy.toml)
cargo clippy --workspace --all-targets

# Treat warnings as errors (CI mode)
cargo clippy --workspace --all-targets -- -D warnings

# Auto-fix clippy warnings
cargo clippy --workspace --fix
```

## Running the Application

### CLI Usage

```bash
# Run detection engine with default rules directory
cargo run --bin kestrel -- run

# Run with specific rules directory
cargo run --bin kestrel -- run --rules /path/to/rules

# Set log level (trace, debug, info, warn, error)
cargo run --bin kestrel -- run --rules ./rules --log-level debug

# Validate rules without running
cargo run --bin kestrel -- validate --rules ./rules

# List all loaded rules
cargo run --bin kestrel -- list --rules ./rules
```

### After Release Build

```bash
./target/release/kestrel run --rules ./rules
```

## Code Style Guidelines

### Rustfmt Configuration (rustfmt.toml)

- **Edition**: 2021
- **Max width**: 100 characters
- **Tab spaces**: 4 (spaces, not tabs)
- **Newline**: Unix style
- **Imports**: Grouped (StdExternalCrate), reordered
- **Comments**: Wrapped at 100 chars, normalized

### Clippy Configuration (clippy.toml)

- **Cognitive complexity threshold**: 30
- **Too many arguments threshold**: 7
- **Type complexity threshold**: 250
- **Enum variant size threshold**: 200
- **Wildcard imports**: Warn on all

### Coding Standards

1. **Error Handling**
   - Use `Result<T>` for recoverable errors
   - Use `thiserror` for custom error types
   - Avoid panics in library code
   - Use `anyhow` for application-level errors

2. **Documentation**
   - Document all public APIs with rustdoc (`///`)
   - Include examples in documentation
   - Use Conventional Commits for commit messages

3. **Performance**
   - Use `FieldId` (u32) for runtime field access, never strings
   - Prefer `Arc` over `Rc` in async code
   - Use `parking_lot` for locks in hot paths
   - Use `ahash` instead of `std::collections::HashMap`

4. **Async Patterns**
   - Built on Tokio throughout
   - Use async/await for I/O and concurrent operations
   - Use `tokio::sync::RwLock` for async-compatible locking

## Testing Guidelines

### Unit Tests

- Place in `#[cfg(test)]` module in same file
- Test both success and error paths
- Use descriptive test names following `test_<what>_<condition>` pattern
- Follow AAA pattern (Arrange, Act, Assert)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_builder_creates_valid_event() {
        // Arrange
        let event_type = 1001;
        let timestamp = 1234567890;

        // Act
        let event = Event::builder()
            .event_type(event_type)
            .ts_mono(timestamp)
            .build()
            .unwrap();

        // Assert
        assert_eq!(event.event_type_id(), event_type);
        assert_eq!(event.ts_mono_ns, timestamp);
    }
}
```

### Integration Tests

- Place in `tests/` directory within each crate
- Test component interactions
- Use `tempfile` crate for temporary directories
- Use realistic data where possible

### Test Data

Example rules are located in:
- `rules/wasm_example_rule/` - Wasm-based rule example
- `rules/lua_example_rule/` - Lua-based rule example
- `rules/example_rule.json` - JSON rule example

## Key Design Principles

1. **Strong Typing via SchemaRegistry**: All event fields are registered at startup. Rules compile field paths to FieldIds once, then use integer IDs for all runtime access.

2. **Sparse Events**: Events only store non-null fields using `SmallVec` for inline optimization (8-element inline storage).

3. **Dual Timestamps**: Events carry both monotonic (for ordering/windows) and wall-clock timestamps (for forensics).

4. **Three Execution Modes**:
   - `Inline`: Real-time blocking with strict budget
   - `Detect`: Real-time detection, alert-only
   - `Offline`: Forensic analysis with deterministic results

5. **Entity Grouping**: Events are grouped by `EntityKey` (u128) for sequence detection across related events.

## Security Considerations

### Privilege Requirements

- **eBPF operations**: Require `CAP_BPF` or root privileges
- **LSM hooks**: Require appropriate LSM capabilities
- **Rule loading**: Should be restricted to trusted users

### Sandboxing

- **Wasm runtime**: Rules run in sandboxed Wasm environment with configurable memory limits
- **Lua runtime**: Sandboxed via mlua with restricted standard library
- **Resource limits**: CPU fuel, memory quotas, and timeouts enforced

### Security Best Practices

1. Always review third-party rules before deployment
2. Start with detection-only mode before enabling blocking
3. Enable audit logging for all blocking actions
4. Use deterministic replay to verify rule behavior
5. Test blocking rules thoroughly before production deployment

### Vulnerability Reporting

- **Email**: security@kestrel-detection.org
- **Do NOT** file public issues for security vulnerabilities
- Response timeline: Critical (7 days), High (14 days), Medium (30 days)

## Development Phases

The project follows a phased development approach:

| Phase | Status | Description |
|-------|--------|-------------|
| 0 | ✅ Complete | Architecture skeleton |
| 1 | ✅ Complete | Wasm Runtime + Host API v1 |
| 2 | ✅ Complete | LuaJIT Runtime integration |
| 3 | ✅ Complete | EQL Compiler |
| 4 | ✅ Complete | Host NFA Sequence Engine |
| 5 | ✅ Complete | eBPF collection layer |
| 6 | ✅ Complete | Real-time blocking (LSM hooks) |
| 7 | ✅ Complete | Offline replay with reproducibility |

## Common Patterns

### Adding a New Event Field

```rust
// In kestrel-schema
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
    .build()?;
```

### Working with RuleManager

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

## Documentation

- **Technical spec**: [plan.md](./plan.md)
- **Development log**: [PROGRESS.md](./PROGRESS.md)
- **API docs**: [docs/api.md](./docs/api.md)
- **Contributing**: [CONTRIBUTING.md](./CONTRIBUTING.md)
- **Security**: [SECURITY.md](./SECURITY.md)

## External Dependencies

Key external crates used:

| Crate | Version | Purpose |
|-------|---------|---------|
| tokio | 1.42 | Async runtime |
| serde | 1.0 | Serialization |
| wasmtime | 26.0 | Wasm runtime |
| mlua | 0.10 | Lua runtime (LuaJIT) |
| aya | 0.13 | eBPF framework |
| smallvec | 1.13 | Inline storage |
| ahash | 0.8 | Fast hashing |
| thiserror | 2.0 | Error definitions |
| tracing | 0.1 | Logging |
| clap | 4.5 | CLI parsing |

## CI/CD

GitHub Actions workflows (`.github/workflows/ci.yml`):

1. **test-stable**: Build and test on stable Rust (Ubuntu, macOS)
2. **test-msrv**: Test on Minimum Supported Rust Version (1.82)
3. **docs**: Build and upload documentation
4. **audit**: Security audit with cargo-audit
5. **coverage**: Code coverage with cargo-llvm-cov
6. **binary-size**: Check release binary sizes
7. **integration**: Integration and E2E tests

All PRs must pass:
- `cargo fmt --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

## Language

Project documentation and comments are primarily in **English**, with some Chinese documentation in README_CN.md for local users.
