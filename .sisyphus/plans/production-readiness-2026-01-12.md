# Kestrel Production Readiness Work Plan

**Plan ID**: PR-2026-01-12-001
**Status**: Draft
**Created**: 2026-01-12
**Target**: v1.0.0 Production Release

---

## Executive Summary

Kestrel has world-class architectural foundations but lacks the **operational maturity** required for production deployment. This plan addresses critical gaps in testing, documentation accuracy, CI/CD automation, and performance validation to position Kestrel as a top-tier open-source detection engine.

### Current State Assessment

| Dimension | Status | Gap |
|-----------|---------|-----|
| **Architecture** | ✅ World-class | None |
| **Core Implementation** | ✅ Complete | None |
| **Test Coverage** | ⚠️ Partial | 5/6 integration tests failing |
| **CI/CD Automation** | ❌ Missing | 0% automated testing |
| **Performance Validation** | ❌ Missing | No benchmarks |
| **Documentation Accuracy** | ❌ Critical errors | Claims 138/138 tests passing (false) |
| **Load Testing** | ❌ Missing | No stress testing |
| **Code Coverage** | ❌ Missing | No coverage reports |

**Overall Production Readiness**: **35%**

---

## Critical Findings

### 1. Critical Bug in NFA Engine (P0)
**Location**: `kestrel-nfa/src/engine.rs:279-300`

**Issue**: `get_expected_state()` returns `1` instead of `0` when no partial match exists, causing all sequence detection to fail from the first event.

**Impact**: 5/6 integration tests failing; core detection capability broken.

**Root Cause**: Function initializes `max_state = 0` and unconditionally adds 1, instead of using `Option<NfaStateId>` to distinguish "no match found" from "match at state 0".

---

### 2. Documentation Integrity Crisis (P0)
**Critical Inaccuracies**:

1. **README.md** claims "138/138 tests passing" (lines 275, 288)
   - **Reality**: ~47/52 tests passing, 5 critical failures
   - **Impact**: Severely undermines project credibility

2. **README.md** claims "Phase 6: ✅ 完成" (lines 268-276)
   - **Reality**: Enforcement is placeholder code (`EbpfExecutor::execute()` has "enforcement is not fully integrated" comment)
   - **Impact**: Misleads users about production capabilities

3. **README.md** claims "Phase 7: ✅ 离线可复现完成" (lines 287-288)
   - **Reality**: No verification of 100% reproducibility guarantee
   - **Impact**: Claims critical requirement without evidence

---

### 3. Missing Operational Infrastructure (P1)

| Missing Component | World-Class Standard | Kestrel Status |
|-----------------|---------------------|----------------|
| CI/CD Pipeline | GitHub Actions, 100% automated | 0% |
| Performance Benchmarks | criterion.rs, 20+ benchmarks | 0 |
| Load Testing | Sustained 10k EPS validation | 0 |
| Code Coverage | tarpaulin, 80%+ target | 0 |
| Memory Safety | miri/ASAN in CI | 0 |
| Send/Sync Verification | cargo check --tests | 0 |

---

## Phase Roadmap to Production

### Phase A: Critical Fixes (Week 1) 🔴

**Goal**: Restore integrity and fix broken core functionality

#### A-1: Fix NFA Engine Bug (P0-1)
- **File**: `kestrel-nfa/src/engine.rs`
- **Function**: `get_expected_state()`
- **Fix**: Change from `max_state: NfaStateId = 0` to `max_state: Option<NfaStateId> = None`
- **Verification**: All 5 failing tests in `kestrel-engine/tests/detection_scenarios.rs` pass
- **Effort**: 2-4 hours

**Before Fix**:
```rust
fn get_expected_state(&self, sequence: &NfaSequence, entity_key: u128) -> NfaResult<NfaStateId> {
    let mut max_state: NfaStateId = 0;  // ❌ Wrong initialization
    for step in &sequence.steps {
        if let Some(pm) = self.state_store.get(&sequence.id, entity_key, step.state_id) {
            if !pm.terminated && pm.current_state >= max_state {
                max_state = pm.current_state;
            }
        }
    }
    Ok(max_state.saturating_add(1))  // ❌ Always adds 1
}
```

**After Fix**:
```rust
fn get_expected_state(&self, sequence: &NfaSequence, entity_key: u128) -> NfaResult<NfaStateId> {
    let mut max_state: Option<NfaStateId> = None;  // ✅ Use Option
    for step in &sequence.steps {
        if let Some(pm) = self.state_store.get(&sequence.id, entity_key, step.state_id) {
            if !pm.terminated {
                match max_state {
                    None => max_state = Some(pm.current_state),
                    Some(current) if pm.current_state > current => max_state = Some(pm.current_state),
                    _ => {}
                }
            }
        }
    }
    Ok(max_state.map(|s| s.saturating_add(1)).unwrap_or(0))  // ✅ Returns 0 if no match
}
```

---

#### A-2: Update Documentation Accuracy (P0-2)
- **Files**: `README.md`, `PROGRESS.md`
- **Changes**:
  1. Remove "138/138 测试通过" claim → Update to actual count (~47/52 passing)
  2. Change Phase 6 badge from "5.8-success" → "5.6-partial"
  3. Update Phase 6 status from "✅ 完成" → "🚧 部分完成"
  4. Document actual enforcement capability vs placeholder
  5. Add "Known Issues" section explaining test failures
- **Policy**: Never mark phase as "complete" without 100% passing tests
- **Effort**: 2-3 hours

---

#### A-3: Verify All Tests Pass (P0-3)
- **Command**: `cargo test --workspace`
- **Expected Result**: All ~52 tests passing
- **Verification**: Test results saved to `.sisyphus/verification/test_results.txt`
- **Effort**: 30 minutes

**Success Criteria**: ✅ All 5 failing tests now pass, zero test failures

---

### Phase B: Testing Infrastructure (Week 2-3) 🟡

**Goal**: Establish world-class testing foundation with CI/CD automation

#### B-1: Create CI/CD Pipeline (P1-1)
- **File**: `.github/workflows/ci.yml`
- **Components**:
  1. **Lint Job**:
     - `cargo fmt --check`
     - `cargo clippy --workspace --all-features -- -D warnings`
  2. **Test Job**:
     - `cargo test --workspace`
     - `cargo test --workspace --release`
  3. **Coverage Job** (optional):
     - `cargo tarpaulin --workspace --out Html --out Lcov`
     - Upload to Codecov
- **Platforms**: Ubuntu latest, macOS (optional)
- **Effort**: 1-2 days

**Template**:
```yaml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always

jobs:
  lint:
    name: Lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - name: Format check
        run: cargo fmt --check
      - name: Clippy
        run: cargo clippy --workspace --all-features -- -D warnings

  test:
    name: Test
    runs-on: ubuntu-latest
    strategy:
      matrix:
        mode: [debug, release]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Cache cargo
        uses: actions/cache@v4
        with:
          path: ~/.cargo/registry
          key: ${{ runner.os }}-cargo-registry-${{ hashFiles('**/Cargo.lock') }}
      - name: Cache target
        uses: actions/cache@v4
        with:
          path: target
          key: ${{ runner.os }}-cargo-target-${{ hashFiles('**/Cargo.lock') }}
      - name: Build
        run: cargo build --workspace
      - name: Test
        run: cargo test --workspace
```

---

#### B-2: Add Performance Benchmark Infrastructure (P1-2)
- **Dependency**: Add `criterion = "0.5"` to dev-dependencies in `Cargo.toml`
- **New File**: `kestrel-engine/benches/benchmark.rs`
- **Benchmarks to Add**:
  1. `bench_event_processing`: Single event evaluation latency
  2. `bench_sequence_detection`: NFA sequence evaluation
  3. `bench_wasm_evaluation`: Wasm predicate evaluation
  4. `bench_event_field_lookup`: Event::get_field() performance
  5. `bench_nfa_state_management`: StateStore operations
- **Baseline Targets** (from plan.md):
  - Single event evaluation: <1μs
  - Sequence evaluation: <10μs
  - Wasm pred_eval: <500ns
  - Event field lookup: <50ns
- **Effort**: 3-4 days

**Example Benchmark**:
```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_event_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_processing");

    for event_count in [1, 10, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(event_count),
            event_count,
            |b, &count| {
                b.iter(|| {
                    process_events(black_box(count));
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_event_processing);
criterion_main!(benches);
```

---

#### B-3: Implement Load Testing Framework (P1-3)
- **New File**: `kestrel-engine/tests/load_scenarios.rs`
- **Test Scenarios**:
  1. `test_sustained_1k_eps`: Process 1,000 events/second for 60 seconds
  2. `test_burst_10k_eps`: Process 10,000 events/second for 10 seconds
  3. `test_memory_stability_1m_events`: Process 1M events, monitor memory growth
  4. `test_high_concurrency`: 16 worker partitions under load
- **Metrics to Track**:
  - Events processed per second (EPS)
  - P50/P95/P99 latency
  - Memory allocation/deallocation
  - CPU usage
  - Event drops (backpressure)
- **Effort**: 4-5 days

---

#### B-4: Add Code Coverage Tracking (P1-4)
- **Tool**: `tarpaulin`
- **Integration**:
  1. Add to `Cargo.toml` dev-dependencies
  2. Add coverage job to CI pipeline
  3. Generate HTML and LCOV reports
  4. Upload to Codecov (optional)
- **Target**: 80%+ code coverage for all critical paths
- **Effort**: 1 day

```bash
# Local development
cargo tarpaulin --workspace --out Html

# CI integration
cargo tarpaulin --workspace --out Lcov --output-dir ./coverage
```

---

### Phase C: Comprehensive E2E Testing (Week 4-5) 🟢

**Goal**: Expand from 3 e2e scenarios to 20+ real-world attack patterns

#### C-1: Expand E2E Attack Scenarios (P2-1)
- **Current**: 3 scenarios (privilege escalation, ransomware, entity isolation)
- **Target**: 20+ scenarios covering MITRE ATT&CK techniques
- **Categories**:
  1. **Initial Access** (4 scenarios):
     - Phishing execution (doc → powershell)
     - Exploit kit delivery
     - Supply chain compromise
     - Valid accounts abuse
  2. **Execution** (5 scenarios):
     - Command and scripting interpreter
     - User execution
     - Scripting abuse (PowerShell, WMI)
     - Signed binary proxy
     - DLL side-loading
  3. **Persistence** (3 scenarios):
     - Registry run keys
     - Scheduled tasks
     - Startup folder persistence
  4. **Privilege Escalation** (2 scenarios):
     - Sudo/su abuse
     - Named pipe impersonation
  5. **Defense Evasion** (3 scenarios):
     - Process injection
     - File deletion (artifacts)
     - Masquerading (legitimate name abuse)
  6. **Credential Access** (2 scenarios):
     - Credential dumping
     - Shadow file access
  7. **Discovery** (2 scenarios):
     - System network configuration discovery
     - Process enumeration
  8. **Lateral Movement** (2 scenarios):
     - Remote services (SSH, RDP)
     - SMB/Windows admin share
  9. **Collection** (2 scenarios):
     - Email collection
     - Data from local system
  10. **Exfiltration** (2 scenarios):
     - Web service exfiltration
     - Data compressed for exfiltration
  11. **Command and Control** (2 scenarios):
     - Application layer protocol (HTTP, DNS)
     - Proxy/Encrypted channel
  12. **Impact** (1 scenario):
     - Data destruction (ransomware)

- **File**: `kestrel-engine/tests/attack_scenarios.rs`
- **Effort**: 2-3 weeks

---

#### C-2: Add Real Event Trace Fixtures (P2-2)
- **Directory**: `tests/fixtures/traces/`
- **Trace Sources**:
  1. Real syscall traces from Linux systems
  2. Synthetic attack traces
  3. Known-good baselines (normal system activity)
  4. Known-bad attack samples
- **Format**: JSON (compatible with existing BinaryLog format)
- **Metadata**: Each trace file includes expected behavior (alerts, no alerts)
- **Effort**: 1-2 weeks

---

#### C-3: Offline Reproducibility Validation (P2-3)
- **New File**: `kestrel-core/tests/replay_reproducibility.rs`
- **Tests**:
  1. `test_replay_produces_same_alerts`: Same event log → same alerts
  2. `test_multiple_replays_consistent`: Replay 10 times → identical results
  3. `test_cross_machine_reproducibility`: Replay on different systems → same output
  4. `test_engine_version_locking`: Different engine versions → different warnings
  5. `test_schema_version_compatibility`: Schema changes handled gracefully
- **Verification**: Automated comparison of replay results
- **Effort**: 1 week

---

### Phase D: Production Hardening (Week 6-8) 🔵

**Goal**: Validate production deployment requirements

#### D-1: Memory Safety Verification (P2-1)
- **Tools**: miri (for UB detection), ASAN (for memory bugs)
- **Integration**:
  1. Add to CI pipeline (nightly build)
  2. Run miri on critical code paths
  3. Add ASAN instrumentation for release builds
- **Scope**:
  - Memory allocation/deallocation
  - Thread safety violations
  - Data race detection
  - Undefined behavior
- **Effort**: 1-2 weeks

---

#### D-2: Send/Sync Verification (P2-2)
- **Tool**: `cargo check --tests --all-features`
- **Goal**: Ensure all async types are properly Send + Sync
- **Critical Components**:
  - EventBus handles
  - Event passing across workers
  - NFA state storage
  - Alert output channels
- **Effort**: 3-5 days

---

#### D-3: Security Boundary Testing (P2-3)
- **New File**: `kestrel-runtime-wasm/tests/safety.rs`, `kestrel-runtime-lua/tests/safety.rs`
- **Tests**:
  1. Fuel limits enforced (Wasm)
  2. Memory limits enforced (Wasm)
  3. FFI restrictions (Lua)
  4. Escape attempts blocked
  5. Infinite loop protection
- **Effort**: 1 week

---

#### D-4: Production Deployment Guide (P2-4)
- **New File**: `docs/DEPLOYMENT.md`
- **Contents**:
  1. System requirements (kernel version, permissions)
  2. Prerequisites (CAP_BPF, clang, LLVM)
  3. Installation steps (release build, setup)
  4. Configuration (rules, tuning)
  5. Performance tuning recommendations
  6. Troubleshooting guide
  7. Security considerations
  8. Monitoring and alerting
- **Effort**: 3-5 days

---

#### D-5: Governance and Contributing Docs (P2-5)
- **New Files**:
  - `CONTRIBUTING.md` (comprehensive)
  - `SECURITY.md` (responsible disclosure)
  - `GOVERNANCE.md` (decision-making process)
  - `MAINTAINERS.md` (project maintainers)
- **Contents**:
  - Development workflow
  - PR review process
  - Code review checklist
  - Release process
  - Security vulnerability reporting
- **Effort**: 1 week

---

## Success Metrics (Production Readiness)

| Metric | Target | Validation Method |
|--------|---------|-------------------|
| **All Tests Passing** | 100% (0 failures) | `cargo test --workspace` |
| **CI/CD Automation** | 100% | All PRs auto-tested |
| **Code Coverage** | 80%+ | tarpaulin reports |
| **Performance Targets Met** | All 5 benchmarks < target | Criterion benchmarks |
| **Load Tests Passing** | 10k EPS sustained | Load test results |
| **Documentation Accuracy** | 100% | Audit against implementation |
| **E2E Scenarios** | 20+ ATT&CK techniques | Test suite count |
| **Reproducibility Verified** | 100% consistent | Replay tests |
| **Memory Safety** | 0 UB/leaks | miri/ASAN results |
| **Security Boundaries** | All enforced | Safety tests |

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| NFA bug fix introduces regressions | Low | Medium | Comprehensive unit tests |
| CI/CD setup delays development | Low | Low | Start with minimal pipeline |
| Performance targets not met | Medium | High | Early benchmarking, profiling |
| E2E scenarios too complex | Medium | Medium | Start with high-value scenarios |
| OSS best practices adoption slows progress | Low | Low | Prioritize critical gaps first |

---

## Resource Requirements

### Timeline
- **Phase A (Critical Fixes)**: 1 week (2026-01-12 to 2026-01-19)
- **Phase B (Testing Infrastructure)**: 2-3 weeks (2026-01-19 to 2026-02-09)
- **Phase C (E2E Testing)**: 2-3 weeks (2026-02-09 to 2026-03-02)
- **Phase D (Production Hardening)**: 3-4 weeks (2026-03-02 to 2026-03-30)
- **Total**: 8-11 weeks to production readiness

### Effort Estimate
| Phase | Person-Weeks |
|-------|--------------|
| A: Critical Fixes | 1.0 |
| B: Testing Infrastructure | 2.5 |
| C: E2E Testing | 4.0 |
| D: Production Hardening | 3.5 |
| **Total** | **11.0 person-weeks** |

### Skill Requirements
- Rust developer (core bug fixes): 1 person
- DevOps/CI/CD engineer (pipeline setup): 0.5 person
- Security researcher (ATT&CK scenarios): 0.5 person
- Performance engineer (benchmarks/load tests): 0.5 person

---

## Dependencies

### Internal
- [ ] NFA engine bug fix (A-1) must complete before E2E tests (C-1)
- [ ] CI/CD pipeline (B-1) must complete before enabling automated testing
- [ ] Load testing framework (B-3) must complete before performance validation (D-1)

### External
- [ ] GitHub Actions for CI/CD
- [ ] Codecov account for coverage reports (optional)
- [ ] Criterion.rs for benchmarking
- [ ] Tarpaulin for code coverage

---

## Milestones

| Milestone | Date | Success Criteria |
|-----------|-------|----------------|
| **M1: Integrity Restored** | 2026-01-19 | ✅ All tests passing, docs accurate |
| **M2: CI/CD Operational** | 2026-02-02 | ✅ Automated testing on all PRs |
| **M3: Performance Validated** | 2026-02-16 | ✅ All benchmarks meet targets |
| **M4: E2E Coverage Expanded** | 2026-03-02 | ✅ 20+ attack scenarios |
| **M5: Production Ready** | 2026-03-30 | ✅ All success metrics met |

---

## Next Actions (Immediate)

1. **Today (2026-01-12)**:
   - [ ] Fix NFA engine bug in `kestrel-nfa/src/engine.rs`
   - [ ] Update README.md test count accuracy
   - [ ] Verify all tests pass locally

2. **This Week (Week 1)**:
   - [ ] Create minimal CI/CD pipeline (lint + test)
   - [ ] Add basic performance benchmarks
   - [ ] Create GitHub Actions workflow

3. **Next Week (Week 2)**:
   - [ ] Expand CI/CD with coverage tracking
   - [ ] Implement load testing framework
   - [ ] Write 5 additional e2e attack scenarios

---

## Appendix: Detailed Implementation Notes

### A-1: NFA Bug Fix Validation Plan

After applying the fix, verify with:

```bash
# Run all engine tests
cargo test -p kestrel-engine

# Run specific failing tests
cargo test -p kestrel-engine --test detection_scenarios

# Expected output:
# test test_process_injection_sequence ... ok
# test test_file_exfiltration_sequence ... ok
# test test_c2_beaconing_pattern ... ok
# test test_entity_isolation ... ok
# test test_multiple_sequences_different_entities ... ok
# test result: ok. 6 passed; 0 failed
```

### B-2: Performance Benchmark Baseline

Establish baseline before any optimizations:

```bash
cargo bench --bench benchmark

# Expected baseline (before optimization):
# event_processing/d1               time:   [100-500] ns
# event_processing/d10              time:   [200-1000] ns
# event_processing/d100             time:   [1000-5000] ns
# event_processing/d1000            time:   [10000-50000] ns
# sequence_detection                 time:   [5000-15000] ns
# wasm_evaluation                   time:   [300-800] ns
# event_field_lookup               time:   [50-200] ns
```

### C-1: E2E Scenario Template

Each attack scenario follows this pattern:

```rust
#[tokio::test]
async fn test_attack_name() {
    // 1. Setup: Register schema, create engine, load rules
    let schema = Arc::new(SchemaRegistry::new());
    let engine = DetectionEngine::new(config);
    engine.load_sequence_rule(eql_rule).await;

    // 2. Simulate: Generate event stream representing attack
    let events = generate_attack_events();

    // 3. Detect: Process events through engine
    let alerts = engine.eval_events(events).await;

    // 4. Verify: Expect specific alerts at specific points
    assert_eq!(alerts.len(), expected_count);
    assert_alert_at_step(&alerts, step_number, expected_fields);
}
```

### D-4: Deployment Guide Outline

```markdown
# Kestrel Production Deployment Guide

## System Requirements
- Linux kernel 5.10+ (for eBPF support)
- CAP_BPF capability or root access
- Rust 1.82+ (for building from source)
- 4GB+ RAM minimum, 8GB+ recommended

## Quick Start
\`\`\`bash
# Download release binary
wget https://github.com/kestrel-detection/kestrel/releases/download/v1.0.0/kestrel-linux-amd64

# Make executable
chmod +x kestrel-linux-amd64

# Run with default configuration
sudo ./kestrel-linux-amd64 run

# Verify installation
kestrel-linux-amd64 --version
\`\`\`

## Configuration
...
```

---

**End of Work Plan**

**Next Step**: Implement A-1 (NFA engine bug fix) and A-2 (documentation update) immediately to restore project integrity.
