# Kestrel Architecture

## Overview

Kestrel is a next-generation endpoint behavioral detection engine built with Rust. It combines eBPF for kernel-level event collection, host-executed NFA for sequence matching, and dual runtime support (Wasm + LuaJIT) for rule predicates.

## Architecture Layers

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Platform Layer                                │
│  kestrel-ebpf (eBPF收集)  │  kestrel-ffi (FFI)  │  kestrel-cli    │
├─────────────────────────────────────────────────────────────────────┤
│                        Runtime Layer                                 │
│  kestrel-runtime-wasm  │  kestrel-runtime-lua  │  kestrel-eql     │
├─────────────────────────────────────────────────────────────────────┤
│                        Engine Layer                                  │
│           kestrel-engine (检测引擎)  │  kestrel-nfa (NFA引擎)       │
├─────────────────────────────────────────────────────────────────────┤
│                        Core Layer                                    │
│  kestrel-core (EventBus, Alert, Action)  │  kestrel-rules           │
├─────────────────────────────────────────────────────────────────────┤
│                      Foundation Layer                                │
│         kestrel-schema (类型系统)  │  kestrel-event (事件结构)      │
└─────────────────────────────────────────────────────────────────────┘
```

## Layer Details

### Foundation Layer

#### kestrel-schema
- **Purpose**: Type system and schema registry
- **Key Types**: `FieldId`, `EventTypeId`, `EntityKey`, `TypedValue`
- **Performance**: Uses `DashMap` for concurrent access without locking

#### kestrel-event
- **Purpose**: Event structure and builder
- **Key Features**:
  - Sparse event storage with `SmallVec`
  - Dual timestamps (monotonic + wall clock)
  - O(log n) field lookup via binary search

### Core Layer

#### kestrel-core
- **EventBus**: Multi-partition event transport with backpressure
- **Alert/Action**: Alert generation and enforcement actions
- **Replay**: Deterministic offline event replay
- **Time**: Mock time provider for testing

#### kestrel-rules
- **Purpose**: Rule loading and management
- **Features**: Hot-reloading, JSON/YAML/EQL support

### Engine Layer

#### kestrel-engine
- **DetectionEngine**: Main detection orchestrator
- **Runtime Trait**: Abstract interface for Wasm/Lua runtimes
- **Engine Modes**: Inline (blocking), Detect (alert-only), Offline (replay)

#### kestrel-nfa
- **Purpose**: Non-deterministic finite automaton for sequence detection
- **Features**:
  - Partial match tracking per entity
  - Time windows (maxspan)
  - Termination conditions (until)
  - StateStore with TTL/LRU/Quota

### Runtime Layer

#### kestrel-runtime-wasm
- Wasmtime integration
- Host API v1 for field access
- Instance pooling for performance

#### kestrel-runtime-lua
- LuaJIT integration via mlua
- Same Host API as Wasm
- Fast iteration for trusted rules

#### kestrel-eql
- EQL parser and compiler
- IR generation
- Wasm code generation

### Platform Layer

#### kestrel-ebpf
- eBPF program loading and management
- RingBuf polling for events
- LSM hooks for enforcement
- Health checker for monitoring

## Key Design Patterns

### 1. Event Flow

```
eBPF Probe → RingBuf → EventNormalizer → EventBus → DetectionEngine
                                                        ↓
                                                NFA Engine / Single Event Rules
                                                        ↓
                                                Predicate Evaluation (Wasm/Lua)
                                                        ↓
                                                Alert Generation
```

### 2. Runtime Abstraction

```rust
#[async_trait]
pub trait Runtime: Send + Sync {
    async fn evaluate(&self, predicate_id: &str, event: &Event) -> RuntimeResult<EvalResult>;
    fn runtime_type(&self) -> RuntimeType;
    fn capabilities(&self) -> RuntimeCapabilities;
}
```

### 3. Health Monitoring

The eBPF subsystem includes comprehensive health checking:
- Event flow monitoring
- Drop rate detection
- Automatic recovery attempts
- Fallback mode support

## Performance Characteristics

| Component | Metric | Value |
|-----------|--------|-------|
| EventBus | Throughput | 10k+ EPS |
| NFA Engine | Sequence Match | < 10μs |
| Schema Registry | Read | Lock-free |
| Wasm Runtime | Evaluation | < 1μs |

## Extension Points

1. **New Event Sources**: Implement `EventSource` trait
2. **New Runtimes**: Implement `Runtime` trait
3. **New Actions**: Implement `ActionExecutor` trait
4. **New Partition Strategies**: Implement `Partitioner` trait

## Security Considerations

- Wasm sandboxing with configurable memory limits
- LuaJIT sandbox via mlua
- eBPF program verification by kernel
- LSM hooks require appropriate capabilities

## Testing

- Unit tests: 350+ across workspace
- Integration tests: E2E scenarios
- Deterministic replay testing
- Performance benchmarks

## License

Apache License 2.0
