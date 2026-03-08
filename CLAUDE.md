# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Summary

Kestrel is a next-generation endpoint behavior detection engine (Rust, ~35k LOC, 18 crates). It uses eBPF for kernel event collection, a host-executed NFA for sequence matching, dual Wasm/LuaJIT runtimes for rule predicates, and EQL (Event Query Language) compatibility. Target: Linux endpoint detection with offline reproducible replay.

## Build & Test Commands

```bash
# Build
cargo build --workspace                    # Debug build
cargo build --workspace --release          # Release build (LTO, strip)
cargo build -p kestrel-engine              # Single crate

# Test
cargo test --workspace                     # All tests
cargo test -p kestrel-nfa                  # Single crate tests
cargo test -p kestrel-engine --test detection_scenarios  # Specific test file
cargo test --workspace -- --nocapture      # With stdout visible
cargo test --workspace --test '*e2e*'      # E2E/integration tests only

# Lint & Format
cargo fmt --all                            # Format (uses rustfmt.toml)
cargo fmt --all -- --check                 # Check formatting
cargo clippy --workspace --all-targets     # Lint (uses clippy.toml)
cargo clippy --workspace --all-targets -- -D warnings  # CI-strict lint

# Run CLI
cargo run --bin kestrel -- run --rules ./rules --log-level info
cargo run --bin kestrel -- validate --rules ./rules
cargo run --bin kestrel -- list --rules ./rules
```

## Architecture Overview

### Layered Crate Dependency Graph

```
kestrel-schema          ← Foundation: FieldId, TypedValue, SchemaRegistry, Severity, RuleMetadata
    ↓
kestrel-event           ← Sparse event model: SmallVec<[(FieldId, TypedValue); 8]>, dual timestamps
    ↓
kestrel-core            ← EventBus (batching/backpressure), Alert, Action, Replay, Time
    ↓
kestrel-rules           ← RuleManager: hot-reload, version management, atomic swap
    ↓
kestrel-engine          ← DetectionEngine: orchestrates NFA + runtimes + rules
    ↓
kestrel-cli             ← CLI binary: run / validate / list / replay subcommands
```

### Detection Pipeline (Data Plane)

```
Event Sources (eBPF/replay/API)
  → EventBus (partition → worker threads)
    → Hybrid Engine routes per-rule:
        AC-DFA  → simple string literal rules (8x faster)
        LazyDFA → hot simple sequences (dynamic compile+cache)
        NFA     → complex rules (regex, until, captures)
      → Predicate evaluation (Wasm OR LuaJIT, same Host API)
        → StateStore (TTL/LRU/Quota per-rule/per-entity)
          → Alerts / Actions (block/allow/detect)
```

### Key Design Patterns

- **FieldId (u32)**: All event field paths resolve to integer IDs at rule load time; runtime never does string comparison for field access.
- **Dual timestamps**: `ts_mono_ns` (monotonic, for ordering/windows) + `ts_wall_ns` (wall clock, for forensics). Replay determinism depends on monotonic timestamps.
- **Entity grouping**: `EntityKey` (u128) groups related events (e.g., pid+start_time) for NFA sequence tracking.
- **Sparse events**: `SmallVec<[(FieldId, TypedValue); 8]>` stores only non-null fields, sorted by FieldId for O(log n) binary search.
- **Unified Runtime trait**: Both Wasm and Lua implement the same `Runtime` trait with `evaluate(predicate_id, event)` → `EvalResult`. Runtimes are interchangeable per-rule.
- **Three execution modes**: Inline (blocking with strict budget), Detect (alert-only), Offline (deterministic replay).

### Crate Roles (beyond the dependency chain)

| Crate | Role |
|-------|------|
| `kestrel-nfa` | NFA sequence engine: PartialMatch tracking, maxspan/until/by semantics, StateStore |
| `kestrel-eql` | EQL parser → IR → Wasm codegen |
| `kestrel-ac-dfa` | Aho-Corasick multi-pattern DFA for string literal pre-filtering |
| `kestrel-lazy-dfa` | HotSpotDetector + NFA→DFA converter + LRU DFA cache |
| `kestrel-hybrid-engine` | RuleComplexityAnalyzer → auto-selects AC-DFA/LazyDFA/NFA/Hybrid strategy |
| `kestrel-runtime-wasm` | Wasmtime-based runtime with instance pool |
| `kestrel-runtime-lua` | mlua (LuaJIT) runtime |
| `kestrel-ebpf` | eBPF collector, event normalization, InterestPushdown, LSM hooks |
| `kestrel-ffi` | C ABI wrappers for embedding engine in C/C++/Python/Go |
| `kestrel-benchmark` | Criterion-based performance benchmarks |
| `kestrel-lab` | Battle Lab: scenario execution, replay validation, attack simulation |

## Code Conventions

- **Rust edition 2021, MSRV 1.82**
- **Line width**: 100 chars (rustfmt.toml)
- **Imports**: grouped as `StdExternalCrate`, reordered
- **Error handling**: `thiserror` for library errors, `anyhow` for application errors, no panics in library code
- **Async**: Tokio throughout, `async_trait` for trait objects
- **Hashing**: `ahash` instead of std HashMap in hot paths; `dashmap` for concurrent maps
- **Commit messages**: Conventional Commits (`feat(scope): description`)
- **Tests**: `test_<what>_<condition>` naming, AAA pattern. `unwrap`/`expect`/`dbg!` allowed in tests only.

## Development Principles

Read `plan.md` for the full technical whitepaper. Key principles:

1. **Test-driven development** — write tests first
2. **Use git** — conventional commits, feature branches
3. **World-class open source quality** — aim for the standard of top-tier projects
4. **先闭环，再扩功能** — close the loop before adding features
5. **先真实场景，再写更多规则** — real scenarios before more rules
6. **先资源边界，再追求复杂表达能力** — resource bounds before complex expressiveness
7. **所有优化都落到可观测、可测试、可回放的路径上** — all optimizations must be observable, testable, replayable
