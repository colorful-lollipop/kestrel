# Updated Work Plan: Including Rule Performance CLI

**Plan ID**: PR-2026-01-12-001-UPDATED
**Status**: Updated
**Created**: 2026-01-12
**Updated**: 2026-01-12 (Added Phase B-5)

---

## New Requirement Added

### User Request (2026-01-12)
"我们的lua脚本或者eql都会被执行，我想我们应该有一个评估系统，看下每个脚本占用的内存，性能，平均存在事件等指标。一个简单的类似top的cli就行"

Translation: "Our Lua scripts or EQL will all be executed, I think we should have an evaluation system to see the memory used by each script, performance, average existing events and other metrics. A simple CLI similar to top is fine."

---

## Updated Roadmap

### Phase A: Critical Fixes (Week 1) 🔴
**Status**: In Progress (tasks distributed)

| Task | Assignee | Status | Time Estimate |
|------|-----------|---------|--------------|
| A-1: Fix NFA Engine Bug | 🔄 Executing | 30 min |
| A-2: Update Documentation | ✅ Complete | 15 min |
| A-3: Verify All Tests Pass | 🔄 Executing | 5 min |

**New Task**: Phase B-5 (see below)

---

### Phase B: Testing Infrastructure (Week 2-3) 🟡
**Status**: In Progress (guides being created)

| Task | Assignee | Status | Time Estimate |
|------|-----------|---------|--------------|
| B-1: CI/CD Pipeline | 🔄 Creating guides | 1-2 days |
| B-2: Performance Benchmarks | 🔄 Creating guides | 3-4 days |
| B-3: Load Testing Framework | 🔄 Creating guides | 4-5 days |
| B-4: Code Coverage Tracking | 🔄 Creating guides | 1 day |
| **B-5: Rule Performance CLI** | 📝 **NEW** | 7.5-10.5 days |

**Note**: B-5 is a high-priority addition based on user request.

---

### Phase B-5: Rule Performance Monitoring CLI (NEW) 🎯

**Priority**: P1-High
**Estimated Time**: 7.5-10.5 days
**Complexity**: Medium

**Deliverables**:
1. `kestrel-perf` CLI binary (top-like interface)
2. Real-time rule metrics dashboard
3. Per-rule memory tracking (Lua/Wasm)
4. Per-rule performance metrics (CPU, latency)
5. Event hit rates and alert rates
6. Export mode (JSON/CSV)

**Key Features**:
- Real-time dashboard (auto-refresh every 2s)
- Sortable by CPU/Memory/Events
- Filterable by rule type (Lua/EQL/Sequence/Wasm)
- Color-coded severity (red=high, green=low)
- Interactive controls (r=refresh, q=quit, s=sort)
- Export mode for historical analysis

**Implementation Guide Created**: `.sisyphus/drafts/phase-b-5-rule-perf-cli.md`

---

## Updated Timeline

### Original Timeline
| Phase | Duration | Person-Weeks |
|--------|-----------|---------------|
| A: Critical Fixes | 1 week | 1.0 |
| B: Testing Infrastructure | 2-3 weeks | 2.5 |
| C: E2E Testing | 2-3 weeks | 4.0 |
| D: Production Hardening | 3-4 weeks | 3.5 |
| **Original Total** | **8-11 weeks** | **11.0** |

### Updated Timeline (with B-5)
| Phase | Duration | Person-Weeks |
|--------|-----------|---------------|
| A: Critical Fixes | 1 week | 1.0 |
| B: Testing Infrastructure | 3-4 weeks | 4.5 |
| B-5: Rule Performance CLI | 1-5 weeks | 2.5 |
| C: E2E Testing | 2-3 weeks | 4.0 |
| D: Production Hardening | 3-4 weeks | 3.5 |
| **Updated Total** | **10-13 weeks** | **15.5** |

**Impact**: +2 weeks, +4.5 person-weeks

---

## Updated Success Metrics

| Metric | Target | Validation |
|--------|---------|------------|
| Test Pass Rate | 100% | `cargo test --workspace` |
| CI/CD Automation | 100% | All PRs auto-tested |
| Code Coverage | 80%+ | tarpaulin reports |
| Performance Targets | All 5 < target | Criterion benchmarks |
| Load Tests | 10k EPS sustained | Load test results |
| **NEW**: Rule Performance CLI | Operational | `kestrel-perf` runs |
| **NEW**: Real-time Metrics | Visible | Dashboard displays all rules |
| **NEW**: Memory Tracking | Accurate | Per-rule memory reported |

**New Targets**: 7/9 metrics (was 6/9)

---

## Resource Requirements Update

### Team Composition (Updated)
- **1× Rust Developer** (core fixes + infrastructure + CLI tool)
- **0.5× DevOps Engineer** (CI/CD setup)
- **0.5× Security Researcher** (ATT&CK scenarios)
- **0.5× Performance Engineer** (benchmarks + load tests)
- **0.5× UX/CLI Developer** (kestrel-perf TUI interface) - NEW

### Updated Effort Estimate
| Phase | Original | Updated | Change |
|--------|----------|---------|--------|
| A: Critical Fixes | 1.0 | 1.0 | 0 |
| B: Testing Infrastructure | 2.5 | 4.5 | +2.0 |
| B-5: Rule Performance CLI | 0 | 2.5 | +2.5 |
| C: E2E Testing | 4.0 | 4.0 | 0 |
| D: Production Hardening | 3.5 | 3.5 | 0 |
| **Total** | **11.0** | **15.5** | **+4.5** |

---

## Phase B-5 Integration

### Dependencies
- **On A**: None (can start after A-3 completes)
- **On B-1, B-2, B-3, B-4**: None (can be parallel)
- **Critical**: DetectionEngine API stable (from Phase A)

### Integration Points
1. **DetectionEngine** (kestrel-engine)
   - Add `rule_metrics: Arc<RwLock<RuleMetricsMap>>`
   - Methods: `get_all_metrics()`, `get_metrics(rule_id)`

2. **Lua Runtime** (kestrel-runtime-lua)
   - Track memory per predicate
   - Expose `get_memory_usage(predicate_id)`

3. **Wasm Runtime** (kestrel-runtime-wasm)
   - Track memory per predicate
   - Expose `get_memory_usage(predicate_id)`

4. **NFA Engine** (kestrel-nfa)
   - Track state memory per sequence
   - Expose metrics to detection engine

5. **CLI Tool** (kestrel-cli)
   - New binary: `kestrel-perf`
   - Connect to engine's metrics API
   - Render real-time dashboard

---

## Updated Risk Assessment

| Risk | Probability | Impact | Status |
|------|-------------|--------|--------|
| NFA fix introduces regressions | Low | Medium | Monitoring |
| CI/CD setup delays development | Low | Low | Acceptable |
| Performance targets not met | Medium | High | Monitoring via B-5 |
| E2E scenarios too complex | Medium | Medium | Planning |
| OSS best practices slow progress | Low | Low | Prioritization |
| **NEW**: Performance CLI adds overhead | Low | Medium | Design <1% overhead |
| **NEW**: Memory tracking inaccurate | Medium | High | Testing + validation |

---

## Updated Milestones

| Milestone | Date | Success Criteria |
|-----------|-------|-----------------|
| M1: Integrity Restored | 2026-01-12 | ✅ All tests passing, docs accurate |
| M2: CI/CD Operational | 2026-01-14 | ✅ Automated testing on all PRs |
| M3: Performance Validated | 2026-01-16 | ✅ All benchmarks meet targets |
| M4: E2E Coverage Expanded | 2026-01-23 | ✅ 20+ attack scenarios |
| **NEW**: M5: Performance CLI Operational | 2026-01-19 | ✅ `kestrel-perf` dashboard working |
| M6: Production Ready | 2026-02-06 | ✅ All success metrics met |

**Note**: Production date moved from 2026-03-30 to 2026-02-06 due to added requirement.

---

## Next Actions (Updated)

### Immediate (Today - 2026-01-12)
- [ ] Monitor A-1 agent completion (NFA fix)
- [ ] Monitor A-3 agent completion (test verification)
- [ ] Review B-5 implementation guide
- [ ] Assign B-5 implementation to agent

### Short-term (Week 2)
- [ ] Execute Phase B-1 (CI/CD pipeline)
- [ ] Execute Phase B-2 (benchmarks)
- [ ] Execute Phase B-3 (load testing)
- [ ] Execute Phase B-4 (code coverage)
- [ ] Execute Phase B-5 (rule performance CLI)

### Medium-term (Week 3-4)
- [ ] Review Phase B results
- [ ] Proceed to Phase C (E2E testing)
- [ ] Plan Phase D (production hardening)

---

## Artifacts Created

### Planning Documents
- ✅ `.sisyphus/plans/production-readiness-2026-01-12.md` (updated)
- ✅ `.sisyphus/plans/EXECUTIVE-SUMMARY.md`

### Implementation Guides (Phase A)
- ✅ `.sisyphus/drafts/phase-a-1-fix-nfa-bug.md`
- ✅ `.sisyphus/drafts/phase-a-2-documentation-accuracy.md`
- ✅ `.sisyphus/drafts/phase-a-3-verify-tests.md`

### Implementation Guides (Phase B)
- 🔄 `.sisyphus/drafts/phase-b-1-ci-cd.md` (in progress)
- 🔄 `.sisyphus/drafts/phase-b-2-benchmarks.md` (in progress)
- 🔄 `.sisyphus/drafts/phase-b-3-load-testing.md` (in progress)
- 🔄 `.sisyphus/drafts/phase-b-4-code-coverage.md` (in progress)
- ✅ `.sisyphus/drafts/phase-b-5-rule-perf-cli.md` (NEW)

### Status Documents
- ✅ `.sisyphus/drafts/phase-a-status.md`
- ✅ `.sisyphus/drafts/EXECUTION-DASHBOARD.md`

---

## Change Summary

### What Changed
1. **Added**: Phase B-5 (Rule Performance CLI) to work plan
2. **Updated**: Timeline from 8-11 weeks to 10-13 weeks
3. **Updated**: Person-weeks from 11.0 to 15.5
4. **Updated**: Success metrics from 6 to 7 (added CLI operational)
5. **Created**: Detailed implementation guide for B-5
6. **Added**: New milestone (M5: Performance CLI Operational)

### What Stayed the Same
1. Phases A-D structure unchanged
2. Phases B-1 through B-4 unchanged
3. Phase C (E2E Testing) unchanged
4. Phase D (Production Hardening) unchanged

---

**Updated Work Plan Complete**
**Ready for execution**: Phase A tasks in progress, Phase B guides being created
**Next Step**: Monitor Phase A completion, then proceed to Phase B execution
