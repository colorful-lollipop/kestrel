# Phase B-2: Performance Benchmarks (criterion.rs) Implementation Guide

**Task**: Establish performance benchmarking suite for Kestrel event processing engine

**Target**: 20+ comprehensive benchmarks with baseline tracking and regression detection

**Estimated Time**: 3-4 days

---

## Task Description

Implement criterion.rs-based benchmarking suite for Kestrel workspace with:
- Microbenchmarks for core operations (event creation, field lookup, etc.)
- Macrobenchmarks for end-to-end workflows (NFA processing, Wasm evaluation)
- Baseline storage and regression detection
- CI/CD integration for automated performance tracking
- HTML reports for visualization

**Performance Targets** (from plan.md):
- Single-event evaluation: < 1μs
- Sequence rule evaluation: < 10μs
- 1k EPS sustained load
- 10k EPS peak throughput

---

## Prerequisites

1. **Rust 1.82+** installed and in PATH
2. **Criterion.rs 0.5** available
3. **Workspace structure** with multiple crates
4. **Linux environment** (for best benchmark stability)
5. **Optional**: `hyperfine` for ad-hoc benchmarking

---

## Step-by-Step Implementation

### Step 1: Add Criterion to Workspace

Create/update `Cargo.toml` to add dev-dependencies:

```toml
# Add to workspace Cargo.toml
[workspace]
members = [
    "kestrel-core",
    "kestrel-schema",
    "kestrel-event",
    "kestrel-engine",
    "kestrel-rules",
    "kestrel-runtime-wasm",
    "kestrel-runtime-lua",
    "kestrel-eql",
    "kestrel-nfa",
    "kestrel-ebpf",
    "kestrel-cli",
]

# Workspace dev-dependencies (shared across all members)
[workspace.dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }
pprof = { version = "0.14", features = ["criterion", "flamegraph"] }
```

**Location**: `Cargo.toml`

---

### Step 2: Create Benchmark Structure

```bash
# Create benchmarks directory for each crate
mkdir -p kestrel-event/benches
mkdir -p kestrel-schema/benches
mkdir -p kestrel-core/benches
mkdir -p kestrel-engine/benches
mkdir -p kestrel-nfa/benches
mkdir -p kestrel-runtime-wasm/benches

# Verify structure
tree -L 3
```

**Location**: Multiple `benches/` directories

---

### Step 3: Benchmark Event Creation (kestrel-event)

Create file `kestrel-event/benches/event_creation.rs`:

```rust
//! Event Creation Benchmarks
//!
//! Benchmarks Event and EventBuilder performance

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use kestrel_event::{Event, EventBuilder, TypedValue};
use kestrel_schema::{FieldDataType, SchemaRegistry};
use std::sync::Arc;

fn bench_event_builder(c: &mut Criterion) {
    let schema = Arc::new(SchemaRegistry::new());
    let mut registry = schema.as_ref().clone();

    // Register fields
    let pid_field = registry
        .register_field(FieldDef {
            path: "process.pid".to_string(),
            data_type: FieldDataType::U64,
            description: None,
        })
        .unwrap();

    let name_field = registry
        .register_field(FieldDef {
            path: "process.name".to_string(),
            data_type: FieldDataType::String,
            description: None,
        })
        .unwrap();

    let schema = Arc::new(registry);

    // Benchmark: Event creation with minimal fields
    c.bench_function("event_builder_minimal", |b| {
        b.iter(|| {
            Event::builder()
                .event_type(1)
                .ts_mono(1_700_000_000_000_000_000u64)
                .ts_wall(1_700_000_000_000_000_000u64)
                .entity_key(12345)
                .build()
                .unwrap()
        })
    });

    // Benchmark: Event creation with single field
    c.bench_function("event_builder_single_field", |b| {
        b.iter(|| {
            Event::builder()
                .event_type(1)
                .ts_mono(1_700_000_000_000_000_000u64)
                .ts_wall(1_700_000_000_000_000_000u64)
                .entity_key(12345)
                .field(pid_field, TypedValue::U64(12345))
                .build()
                .unwrap()
        })
    });

    // Benchmark: Event creation with multiple fields
    c.bench_function("event_builder_multiple_fields", |b| {
        b.iter(|| {
            Event::builder()
                .event_type(1)
                .ts_mono(1_700_000_000_000_000_000u64)
                .ts_wall(1_700_000_000_000_000_000u64)
                .entity_key(12345)
                .field(pid_field, TypedValue::U64(12345))
                .field(name_field, TypedValue::String("test_process".to_string()))
                .field(pid_field + 1, TypedValue::I64(-1))
                .field(name_field + 1, TypedValue::String("/bin/bash".to_string()))
                .build()
                .unwrap()
        })
    });

    // Benchmark: Batch event creation (throughput)
    let mut group = c.benchmark_group("batch_event_creation");
    group.throughput(Throughput::Elements(100));
    group.bench_function("create_100_events", |b| {
        b.iter(|| {
            (0..100)
                .map(|i| {
                    Event::builder()
                        .event_type(1)
                        .ts_mono(1_700_000_000_000_000_000u64 + (i as u64 * 1000))
                        .ts_wall(1_700_000_000_000_000_000u64 + (i as u64 * 1000))
                        .entity_key(12345 + i as u128)
                        .field(pid_field, TypedValue::U64(12345 + i as u64))
                        .build()
                        .unwrap()
                })
                .collect::<Vec<_>>()
        })
    });
    group.finish();
}

criterion_group!(benches, bench_event_builder);
criterion_main!(benches);
```

**Location**: `kestrel-event/benches/event_creation.rs`

---

### Step 4: Benchmark Field Lookup (kestrel-event)

Create file `kestrel-event/benches/field_lookup.rs`:

```rust
//! Field Lookup Benchmarks
//!
//! Benchmarks event field access and TypedValue performance

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kestrel_event::Event;
use kestrel_schema::{FieldDataType, FieldDef, SchemaRegistry, TypedValue};
use std::sync::Arc;

fn bench_field_lookup(c: &mut Criterion) {
    let mut schema = SchemaRegistry::new();

    // Register 50 fields (realistic event schema)
    let field_ids: Vec<u32> = (0..50)
        .map(|i| {
            schema
                .register_field(FieldDef {
                    path: format!("field_{}", i),
                    data_type: match i % 6 {
                        0 => FieldDataType::U64,
                        1 => FieldDataType::I64,
                        2 => FieldDataType::F64,
                        3 => FieldDataType::String,
                        4 => FieldDataType::Bool,
                        _ => FieldDataType::Bytes,
                    },
                    description: None,
                })
                .unwrap()
        })
        .collect();

    // Create event with all fields
    let mut builder = Event::builder()
        .event_type(1)
        .ts_mono(1_700_000_000_000_000_000u64)
        .ts_wall(1_700_000_000_000_000_000u64)
        .entity_key(12345);

    for (i, &field_id) in field_ids.iter().enumerate() {
        let value = match i % 6 {
            0 => TypedValue::U64(12345),
            1 => TypedValue::I64(-12345),
            2 => TypedValue::F64(12345.6789),
            3 => TypedValue::String("test_string_value".to_string()),
            4 => TypedValue::Bool(true),
            _ => TypedValue::Bytes(vec![1, 2, 3, 4, 5]),
        };
        builder = builder.field(field_id, value);
    }

    let event = builder.build().unwrap();

    // Benchmark: Lookup first field (best case)
    c.bench_function("field_lookup_first", |b| {
        b.iter(|| event.get_field(black_box(field_ids[0])))
    });

    // Benchmark: Lookup middle field (average case)
    c.bench_function("field_lookup_middle", |b| {
        b.iter(|| event.get_field(black_box(field_ids[25])))
    });

    // Benchmark: Lookup last field (worst case)
    c.bench_function("field_lookup_last", |b| {
        b.iter(|| event.get_field(black_box(field_ids[49])))
    });

    // Benchmark: Sequential lookups of all fields
    c.bench_function("field_lookup_all_sequential", |b| {
        b.iter(|| {
            for &field_id in field_ids.iter() {
                let _ = event.get_field(field_id);
            }
        })
    });

    // Benchmark: TypedValue extraction
    let typed_event = event.clone();
    c.bench_function("typed_value_extract_u64", |b| {
        b.iter(|| {
            if let Some(TypedValue::U64(v)) = typed_event.get_field(field_ids[0]) {
                black_box(v);
            }
        })
    });

    c.bench_function("typed_value_extract_string", |b| {
        b.iter(|| {
            if let Some(TypedValue::String(s)) = typed_event.get_field(field_ids[3]) {
                black_box(s.clone());
            }
        })
    });
}

criterion_group!(benches, bench_field_lookup);
criterion_main!(benches);
```

**Location**: `kestrel-event/benches/field_lookup.rs`

---

### Step 5: Benchmark NFA Processing (kestrel-nfa)

Create file `kestrel-nfa/benches/nfa_processing.rs`:

```rust
//! NFA Processing Benchmarks
//!
//! Benchmarks sequence rule evaluation performance

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use kestrel_event::Event;
use kestrel_nfa::{
    CompiledSequence, NfaEngine, NfaEngineConfig, NfaSequence, PredicateEvaluator,
    SeqStep, NfaResult,
};
use kestrel_schema::{SchemaRegistry};
use std::sync::Arc;

// Mock evaluator for benchmarking (always matches)
struct BenchmarkPredicateEvaluator;

impl PredicateEvaluator for BenchmarkPredicateEvaluator {
    fn evaluate(&self, _id: &str, _e: &Event) -> NfaResult<bool> {
        Ok(true) // Fast path: always match
    }

    fn get_required_fields(&self, _id: &str) -> NfaResult<Vec<u32>> {
        Ok(vec![])
    }

    fn has_predicate(&self, _id: &str) -> bool {
        true
    }
}

fn bench_nfa_single_sequence(c: &mut Criterion) {
    let schema = Arc::new(SchemaRegistry::new());
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(BenchmarkPredicateEvaluator);
    let mut nfa = NfaEngine::new(NfaEngineConfig::default(), evaluator, schema);

    // Load a single sequence rule
    let sequence = CompiledSequence {
        id: "bench-seq-1".to_string(),
        sequence: NfaSequence::new(
            "bench-seq-1".to_string(),
            100, // by field ID
            vec![
                SeqStep::new(0, "step1".to_string(), 1),
                SeqStep::new(1, "step2".to_string(), 1),
                SeqStep::new(2, "step3".to_string(), 1),
            ],
            Some(5000), // 5 second maxspan
            None,
        ),
        rule_id: "bench-rule-1".to_string(),
        rule_name: "Benchmark Sequence 1".to_string(),
    };
    nfa.load_sequence(sequence).unwrap();

    // Benchmark: Single event processing (no match)
    let event_no_match = Event::builder()
        .event_type(2)
        .ts_mono(1_000_000_000u64)
        .ts_wall(1_000_000_000u64)
        .entity_key(99999)
        .build()
        .unwrap();

    c.bench_function("nfa_process_single_event_no_match", |b| {
        b.iter(|| nfa.process_event(black_box(&event_no_match)))
    });

    // Benchmark: Single event processing (matches first step)
    let event_match_step1 = Event::builder()
        .event_type(1)
        .ts_mono(1_000_000_000u64)
        .ts_wall(1_000_000_000u64)
        .entity_key(12345)
        .build()
        .unwrap();

    c.bench_function("nfa_process_single_event_match_step1", |b| {
        b.iter(|| nfa.process_event(black_box(&event_match_step1)))
    });

    // Benchmark: Complete sequence (3 steps)
    let mut group = c.benchmark_group("nfa_complete_sequence");
    group.throughput(Throughput::Elements(1));
    group.bench_function("process_3_step_sequence", |b| {
        b.iter(|| {
            let base_time = 1_000_000_000u64;

            // Step 1
            let e1 = Event::builder()
                .event_type(1)
                .ts_mono(base_time)
                .ts_wall(base_time)
                .entity_key(54321)
                .build()
                .unwrap();
            nfa.process_event(&e1).unwrap();

            // Step 2
            let e2 = Event::builder()
                .event_type(1)
                .ts_mono(base_time + 1_000_000)
                .ts_wall(base_time + 1_000_000)
                .entity_key(54321)
                .build()
                .unwrap();
            nfa.process_event(&e2).unwrap();

            // Step 3 (should trigger alert)
            let e3 = Event::builder()
                .event_type(1)
                .ts_mono(base_time + 2_000_000)
                .ts_wall(base_time + 2_000_000)
                .entity_key(54321)
                .build()
                .unwrap();
            nfa.process_event(&e3)
        })
    });
    group.finish();
}

fn bench_nfa_multiple_sequences(c: &mut Criterion) {
    let schema = Arc::new(SchemaRegistry::new());
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(BenchmarkPredicateEvaluator);
    let mut nfa = NfaEngine::new(NfaEngineConfig::default(), evaluator, schema);

    // Load 100 sequences
    for i in 0..100 {
        let sequence = CompiledSequence {
            id: format!("bench-seq-{}", i),
            sequence: NfaSequence::new(
                format!("bench-seq-{}", i),
                100 + (i % 10),
                vec![
                    SeqStep::new(0, "step1".to_string(), 1),
                    SeqStep::new(1, "step2".to_string(), 1),
                    SeqStep::new(2, "step3".to_string(), 1),
                ],
                Some(5000),
                None,
            ),
            rule_id: format!("bench-rule-{}", i),
            rule_name: format!("Benchmark Sequence {}", i),
        };
        nfa.load_sequence(sequence).unwrap();
    }

    let event = Event::builder()
        .event_type(1)
        .ts_mono(1_000_000_000u64)
        .ts_wall(1_000_000_000u64)
        .entity_key(12345)
        .build()
        .unwrap();

    c.bench_function("nfa_process_event_100_sequences", |b| {
        b.iter(|| nfa.process_event(black_box(&event)))
    });
}

criterion_group!(benches, bench_nfa_single_sequence, bench_nfa_multiple_sequences);
criterion_main!(benches);
```

**Location**: `kestrel-nfa/benches/nfa_processing.rs`

---

### Step 6: Benchmark Wasm Evaluation (kestrel-runtime-wasm)

Create file `kestrel-runtime-wasm/benches/wasm_evaluation.rs`:

```rust
//! Wasm Evaluation Benchmarks
//!
//! Benchmarks Wasm predicate evaluation performance

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use kestrel_event::Event;
use kestrel_runtime_wasm::{WasmConfig, WasmContext, WasmEngine};
use kestrel_schema::{FieldDataType, FieldDef, SchemaRegistry};
use std::sync::Arc;

fn create_test_wasm_module() -> (Vec<u8>, Arc<SchemaRegistry>, u32) {
    let mut schema = SchemaRegistry::new();

    // Register fields
    let pid_field = schema
        .register_field(FieldDef {
            path: "process.pid".to_string(),
            data_type: FieldDataType::U64,
            description: None,
        })
        .unwrap();

    let schema = Arc::new(schema);

    // Simple WAT that returns true for PID 12345
    let wat = r#"
      (module
        (import "kestrel" "event_get_u64" (func $event_get_u64 (param i64 i32) (result i64)))
        (import "kestrel" "pred_eval" (func $pred_eval (param i64 i32) (result i32)))

        (memory (export "memory") 1)

        (func (export "pred_eval") (param $event_handle i64) (param $ctx i32) (result i32)
          (local.get $event_handle)
          (local.get 0) ;; field_id for process.pid
          call $event_get_u64
          i64.const 12345
          i64.eq
          i32.eqz ;; return 1 if true, 0 if false
        )
      )
    "#;

    let module = wat::parse_str(wat).expect("Failed to parse WAT");

    (module, schema, pid_field)
}

fn bench_wasm_compilation(c: &mut Criterion) {
    let (wasm_bytes, _, _) = create_test_wasm_module();

    c.bench_function("wasm_compile_module", |b| {
        b.iter(|| {
            let config = WasmConfig::default();
            let mut engine = WasmEngine::new(config).unwrap();
            let _ctx = WasmContext::new(&mut engine).unwrap();
        })
    });
}

fn bench_wasm_evaluation(c: &mut Criterion) {
    let (wasm_bytes, schema, pid_field) = create_test_wasm_module();

    let config = WasmConfig::default();
    let mut engine = WasmEngine::new(config).unwrap();
    let ctx = WasmContext::new(&mut engine).unwrap();

    let predicate_id = "test-pred".to_string();

    // Compile module
    engine
        .compile_rule(&predicate_id, wasm_bytes.clone(), vec![pid_field])
        .unwrap();

    // Create event that matches
    let event_match = Event::builder()
        .event_type(1)
        .ts_mono(1_000_000_000u64)
        .ts_wall(1_000_000_000u64)
        .entity_key(12345)
        .field(pid_field, kestrel_schema::TypedValue::U64(12345))
        .build()
        .unwrap();

    // Create event that doesn't match
    let event_no_match = Event::builder()
        .event_type(1)
        .ts_mono(1_000_000_000u64)
        .ts_wall(1_000_000_000u64)
        .entity_key(99999)
        .field(pid_field, kestrel_schema::TypedValue::U64(99999))
        .build()
        .unwrap();

    // Benchmark: Wasm evaluation (match)
    c.bench_function("wasm_eval_predicate_match", |b| {
        b.iter(|| {
            engine
                .eval_adhoc_predicate(&predicate_id, &event_match)
                .unwrap()
        })
    });

    // Benchmark: Wasm evaluation (no match)
    c.bench_function("wasm_eval_predicate_no_match", |b| {
        b.iter(|| {
            engine
                .eval_adhoc_predicate(&predicate_id, &event_no_match)
                .unwrap()
        })
    });

    // Benchmark: Batch Wasm evaluation (throughput)
    let mut group = c.benchmark_group("batch_wasm_evaluation");
    group.throughput(Throughput::Elements(100));
    group.bench_function("eval_100_predicates", |b| {
        b.iter(|| {
            (0..100)
                .map(|i| {
                    if i % 2 == 0 {
                        engine
                            .eval_adhoc_predicate(&predicate_id, &event_match)
                            .unwrap()
                    } else {
                        engine
                            .eval_adhoc_predicate(&predicate_id, &event_no_match)
                            .unwrap()
                    }
                })
                .collect::<Vec<_>>()
        })
    });
    group.finish();
}

criterion_group!(benches, bench_wasm_compilation, bench_wasm_evaluation);
criterion_main!(benches);
```

**Location**: `kestrel-runtime-wasm/benches/wasm_evaluation.rs`

---

### Step 7: Update Cargo.toml for Each Crate

For each crate with benchmarks, update `Cargo.toml`:

```toml
# kestrel-event/Cargo.toml
[package]
name = "kestrel-event"
version = "0.1.0"
edition = "2021"

[dependencies]
# ... existing dependencies ...

[dev-dependencies]
criterion = { workspace = true }

[[bench]]
name = "event_creation"
harness = false

[[bench]]
name = "field_lookup"
harness = false
```

Repeat for:
- `kestrel-schema/benches/`
- `kestrel-core/benches/`
- `kestrel-engine/benches/`
- `kestrel-nfa/benches/`
- `kestrel-runtime-wasm/benches/`

---

### Step 8: Create Benchmark Configuration

Create file `.cargo/config.toml`:

```toml
[bench]
# Enable unstable benchmark features
debug = true
```

**Location**: `.cargo/config.toml`

---

### Step 9: Run Benchmarks and Save Baseline

```bash
# Run all benchmarks in workspace
cargo bench --workspace

# This will generate:
# - target/criterion/ (HTML reports)
# - target/criterion/baseline/ (saved baselines)
```

### Step 10: Integrate with CI/CD

Update `.github/workflows/bench.yml` (from Phase B-1):

```yaml
name: Benchmarks

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  workflow_dispatch:

env:
  CARGO_INCREMENTAL: '0'

jobs:
  bench:
    name: Performance Benchmarks
    runs-on: ubuntu-latest
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust stable
        uses: dtolnay/rust-toolchain@stable

      - name: Install benchmark dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y libdw-dev libbfd-dev

      - name: Cache dependencies and benchmarks
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry/index
            ~/.cargo/registry/cache
            ~/.cargo/git/db
            target/release
            target/criterion
          key: ${{ runner.os }}-bench-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            ${{ runner.os }}-bench-

      - name: Run benchmarks
        run: |
          cargo bench --workspace -- --save-baseline main

      - name: Upload benchmark results
        uses: actions/upload-artifact@v4
        with:
          name: benchmark-results
          path: target/criterion/
          retention-days: 30

      - name: Check for regressions
        run: |
          echo "📈 Benchmark results generated"
          echo "📁 Report location: target/criterion/report/"
          echo "ℹ️  Manual review required for regression detection"
          echo ""
          echo "To compare with baseline:"
          echo "  cargo bench --workspace -- --baseline main"
```

**Location**: `.github/workflows/bench.yml`

---

## Verification Steps

### 1. Run All Benchmarks Locally

```bash
# Run all benchmarks
cargo bench --workspace

# Expected output:
# - target/criterion/event_creation/report/index.html
# - target/criterion/field_lookup/report/index.html
# - target/criterion/nfa_processing/report/index.html
# - target/criterion/wasm_evaluation/report/index.html

# Open HTML reports
open target/criterion/report/index.html
```

### 2. Verify Benchmarks Meet Targets

Check performance targets:

```bash
# Check event creation performance
grep "time" target/criterion/event_creation/report/index.html

# Check NFA processing performance
grep "time" target/criterion/nfa_processing/report/index.html

# Check Wasm evaluation performance
grep "time" target/criterion/wasm_evaluation/report/index.html
```

Expected results (targets):
- `event_builder_minimal`: < 100ns
- `field_lookup_first`: < 50ns
- `nfa_process_single_event_no_match`: < 5μs
- `wasm_eval_predicate_match`: < 1μs

### 3. Save Baseline

```bash
# Save baseline after successful run
cargo bench --workspace -- --save-baseline main

# Verify baseline saved
ls -la target/criterion/baseline/main/
```

### 4. Test Regression Detection

```bash
# Introduce intentional regression (e.g., add sleep)
# Edit benchmark code temporarily

# Compare with baseline
cargo bench --workspace -- --baseline main

# View comparison
open target/criterion/report/index.html
```

### 5. Verify CI Integration

```bash
# Create test branch
git checkout -b feature/benchmarks-test
git add .
git commit -m "feat: Add performance benchmarks"
git push origin feature/benchmarks-test

# Create PR and verify benchmark workflow runs
gh pr create --title "Add Benchmarks" --body "Testing benchmark workflow"
```

---

## Rollback Plan

### Scenario 1: Benchmark Compilation Errors

**Symptoms**: `cargo bench` fails with compilation errors

**Rollback**:
```bash
# Remove failing benchmark files
rm kestrel-event/benches/failing_benchmark.rs

# Commit rollback
git add kestrel-event/benches/
git commit -m "rollback: Remove failing benchmark"
```

### Scenario 2: Benchmarks Too Slow

**Symptoms**: Benchmark execution takes > 1 hour

**Optimization**:
```rust
// Reduce sample size in Criterion configuration
use criterion::{Criterion, BenchmarkId};

fn benchmark_group_with_config() {
    let mut c = Criterion::default()
        .sample_size(100)  // Default is 100, reduce to 50
        .warm_up_time(std::time::Duration::from_secs(3))
        .measurement_time(std::time::Duration::from_secs(5));

    // Run benchmarks with custom config
}
```

### Scenario 3: Instability (High Variance)

**Symptoms**: High coefficient of variance (> 10%)

**Stabilization**:
```rust
// Increase sample size
let mut c = Criterion::default()
    .sample_size(500)  // More samples
    .warm_up_time(std::time::Duration::from_secs(10))
    .measurement_time(std::time::Duration::from_secs(30));
```

---

## Success Criteria

### Phase B-2 Completion Checklist

- [ ] Criterion added to workspace dev-dependencies
- [ ] 5+ benchmark files created (event_creation, field_lookup, nfa_processing, etc.)
- [ ] All benchmarks compile without errors
- [ ] Benchmarks complete in < 15 minutes
- [ ] HTML reports generated successfully
- [ ] Baseline saved to `target/criterion/baseline/main/`
- [ ] Performance targets verified (< 1μs for event evaluation)
- [ ] CI workflow runs benchmarks successfully
- [ ] Benchmark artifacts uploaded to CI
- [ ] No unstable benchmarks (CoV < 10%)

---

## Next Steps

### Integration with Phase B Tasks

1. **Phase B-3 (Load Testing)**: Use benchmark results to validate load testing targets
2. **Phase B-4 (Coverage)**: Ensure benchmarks don't skew coverage stats

### Future Enhancements

1. **Additional Benchmarks**:
   - EventBus throughput benchmarks
   - Alert generation performance
   - Memory allocation benchmarks

2. **Advanced Features**:
   - Flamegraph generation via pprof
   - Custom comparison thresholds
   - Automated regression detection in CI

3. **Performance Monitoring**:
   - Integrate with CodSpeedHQ for continuous performance tracking
   - Set up performance degradation alerts

---

## Code Examples

### Example: Custom Criterion Configuration

```rust
use criterion::{Criterion, BenchmarkId, PlotConfiguration, Throughput};

fn custom_benchmark_config(c: &mut Criterion) {
    let plot_config = PlotConfiguration::default()
        .summary_scale(logarithmic)
        .confidence_level(0.95);

    c.bench_function("custom_plot", |b| {
        b.iter(|| {
            // benchmark code
        })
    });
}
```

### Example: Parameterized Benchmarks

```rust
fn bench_parameterized(c: &mut Criterion) {
    let mut group = c.benchmark_group("parameterized");
    group.throughput(Throughput::Elements(1));

    for size in [10, 100, 1000, 10000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let data = vec![0u8; size];
                // benchmark code
                black_box(data.len())
            })
        });
    }

    group.finish();
}
```

---

## Troubleshooting

### Issue: "Cannot find crate `criterion`"

**Solution**:
```bash
# Add criterion to workspace dev-dependencies
cargo add criterion --dev --workspace

# Or manually add to Cargo.toml
```

### Issue: Benchmarks unstable (high variance)

**Solution**:
1. Disable CPU frequency scaling:
   ```bash
   sudo cpupower frequency-set -g performance
   ```

2. Disable turbo boost:
   ```bash
   echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
   ```

3. Run benchmarks with more samples:
   ```rust
   Criterion::default().sample_size(500)
   ```

### Issue: HTML reports not generated

**Solution**:
```bash
# Ensure html_reports feature is enabled
cargo bench --features html_reports

# Or install with feature
cargo install cargo-criterion --features html_reports
```

---

## References

- **Criterion.rs Book**: https://bheisler.github.io/criterion.rs/book/
- **Criterion.rs GitHub**: https://github.com/bheisler/criterion.rs
- **Tokio Benchmarks**: https://github.com/tokio-rs/tokio/tree/master/tokio/benches
- **Rust Benchmarking Guide**: https://nnethercote.github.io/perf-book/benchmarking.html

---

**Implementation Status**: Draft

**Next Review**: After baseline benchmarks are run and validated
