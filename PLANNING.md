# Kestrel Project Planning Document

## Project Vision

**High-performance, rule-based threat detection engine for endpoints**

## Core Principles

1. **Performance First** - Target <1μs predicate evaluation
2. **Deterministic** - Same input → same output (critical for forensics)
3. **Extensible** - Modular architecture with clear interfaces
4. **Test-Driven** - Each feature has tests before implementation

## Phase Overview

| Phase | Focus | Status |
|-------|-------|--------|
| Phase 0-4 | Foundation | ✅ Complete |
| Phase 5 | Core Implementation | ✅ Complete |
| Phase 5.5 | Core Fixes & Tests | ✅ Complete |
| Phase 5.6 | Performance Optimization | ⏳ Pending |
| Phase 5.7 | Feature Complete | ⏳ Pending |
| Phase 6 | Real-time Blocking | 🔲 Pending |
| Phase 7 | Enterprise Features | 🔲 Pending |

## Module Dependencies

```
                        ┌─────────────────┐
                        │   kestrel-cli   │
                        └────────┬────────┘
                                 │
            ┌────────────────────┼────────────────────┐
            │                    │                    │
   ┌────────▼────────┐  ┌───────▼────────┐  ┌───────▼────────┐
   │  kestrel-engine │  │  kestrel-ebpf  │  │  kestrel-rules │
   └────────┬────────┘  └────────────────┘  └────────────────┘
            │
     ┌──────┼──────────────────────────────────────────┐
     │      │                                          │
┌────▼────┐ │ ┌──────────────────────────────────────┐ │
│kestrel- │ ▼ │          kestrel-core                │ │
│runtime- │ │ │ ┌─────────────┐ ┌─────────────────┐  │ │
│wasm     │ └►│  EventBus    │ │  TimeManager    │  │ │
└─────────┘   │  (partitions)│ │  (mock/sync)    │  │ │
              │ └─────────────┘ └─────────────────┘  │ │
              │ ┌───────────────────────────────────┐ │ │
              │ │  AlertOutput / Replay             │ │ │
              │ └───────────────────────────────────┘ │ │
              └────────────────────────────────────────┘ │
            │                    │                        │
   ┌────────▼────────┐  ┌───────▼────────┐  ┌────────────▼────────┐
   │  kestrel-nfa    │  │ kestrel-eql    │  │   kestrel-runtime-  │
   │  (sequences)    │  │  (compiler)    │  │     lua             │
   └─────────────────┘  └────────────────┘  └─────────────────────┘
            │                    │
            │          ┌─────────┴─────────┐
            │          │                   │
            │   ┌───────▼───────┐  ┌───────▼───────┐
            │   │kestrel-schema │  │ kestrel-event │
            │   │  (types)      │  │  (struct)     │
            │   └───────────────┘  └───────────────┘
            │
            └────────────────────────────────────────────────────┐
                                                              │
                                             kestrel-runtime-wasm
```

## Completed Work (Session Summary)

### P1-3: Event Field Lookup Optimization
- **File**: `kestrel-event/src/lib.rs`
- **Change**: O(n) linear → O(log n) binary search
- **Impact**: ~2-3x faster field lookups for 8-field events
- **Tests**: 2 new tests added

### P0-3: Single-Event Rule Evaluation Tests
- **File**: `kestrel-engine/src/lib.rs`
- **Tests**: 3 new integration tests
  - `test_single_event_rule_eval_always_match`
  - `test_single_event_rule_no_match_different_event_type`
  - `test_eval_event_multiple_single_event_rules`
- **Status**: All 6 engine tests passing

### Documentation: Module READMEs
- `kestrel-schema/README.md`
- `kestrel-event/README.md`
- `kestrel-core/README.md`
- `kestrel-rules/README.md`
- `kestrel-eql/README.md`
- `kestrel-nfa/README.md`
- `kestrel-runtime-wasm/README.md`
- `kestrel-runtime-lua/README.md`
- `kestrel-ebpf/README.md`
- `kestrel-engine/README.md`
- `kestrel-cli/README.md`

## Test Status

| Crate | Tests | Status |
|-------|-------|--------|
| kestrel-schema | 4/4 | ✅ Passing |
| kestrel-event | 5/5 | ✅ Passing |
| kestrel-core | 16/16 | ✅ Passing |
| kestrel-rules | 4/4 | ✅ Passing |
| kestrel-eql | 35/35 | ✅ Passing |
| kestrel-nfa | 21/21 | ✅ Passing |
| kestrel-runtime-wasm | 3/3 | ✅ Passing |
| kestrel-runtime-lua | 2/2 | ✅ Passing |
| kestrel-engine | 6/6 | ✅ Passing |
| kestrel-ebpf | 14/14 | ✅ Passing |
| **Total** | **~130 tests** | **✅ All Passing** |

## Next Tasks (Priority Order)

### P0 - Blocking (Block v0.8 Release)

1. **eBPF Ring Buffer Polling**
   - `kestrel-ebpf/src/lib.rs::start_ringbuf_polling()`
   - Complete execve → Kestrel Event conversion
   - Connect to EventBus
   - Estimated: 3-5 days

2. **Single-Event Rule E2E Integration**
   - `compile_single_event_rule()` → `eval_event()` flow
   - Test with real Wasm predicates
   - Estimated: 2 days

### P1 - Critical (Block v0.8.1)

1. **Wasm Instance Pool Optimization**
   - `kestrel-runtime-wasm/src/lib.rs`
   - Reuse Store/Instance instead of create each time
   - Target: <500ns evaluation
   - Estimated: 4 days

2. **EventBus Multi-Worker**
   - `kestrel-core/src/eventbus.rs`
   - Complete partition → worker mapping
   - Backpressure configuration
   - Estimated: 3 days

### P2 - Important (v0.9)

1. **Documentation**
   - API docs for all public types
   - Example rules
   - Performance guide

2. **Lua Runtime Completion**
   - Full feature parity with Wasm
   - Performance optimization

3. **Alert Correlation**
   - Group related alerts
   - Reduce alert fatigue

## Performance Targets

| Component | Metric | Current | Target |
|-----------|--------|---------|--------|
| Wasm Runtime | pred_eval | ~500ns | <500ns |
| EventBus | publish | ~5μs | <5μs |
| Event lookup | get_field | ~80ns | <50ns |
| NFA Engine | process_event | ~10μs | <5μs |
| Memory | Idle | ~80MB | <100MB |

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| eBPF complexity | Medium | High | Aya framework, incremental |
| Wasm performance | Low | High | Instance pooling, benchmarks |
| Lua sandbox escape | Low | Medium | Disable FFI, limits |
| Memory growth | Medium | Medium | Eviction strategies |

## Quality Gates (v0.8)

- [ ] All tests pass (cargo test --workspace)
- [ ] No clippy warnings (cargo clippy --workspace)
- [ ] Format check (cargo fmt --check)
- [ ] Documentation coverage >80%
- [ ] Performance benchmarks pass
- [ ] Security audit (basic)

## Versioning

- **v0.7.x**: Foundation (COMPLETE)
- **v0.8.x**: Core Complete (IN PROGRESS)
- **v0.9.x**: Blocking Features (PLANNED)
- **v1.0.0**: Production Ready (PLANNED)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

### Quick Start

```bash
# Setup
git clone https://github.com/kestrel-detection/kestrel.git
cd Kestrel
cargo build --release

# Test
cargo test --workspace

# Add a feature
git checkout -b feature/my-feature
# ... implement ...
git add .
git commit -m "feat: description"
git push origin feature/my-feature
```

## Contact

- GitHub Issues: Bug reports and feature requests
- GitHub Discussions: Questions and ideas
- Discord: Real-time chat (link in README)

## Acknowledgments

- Elastic EQL for query language design
- Aya for eBPF framework
- Wasmtime for WebAssembly runtime
- Rust team for excellent tooling
