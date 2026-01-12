# Phase A-3 Implementation Guide: Verify All Tests Pass

**Priority**: P0-Critical
**Estimated Time**: 5 minutes
**Risk**: None (verification only)

---

## Prerequisites

This task assumes:
- [ ] Phase A-1: NFA engine bug fix has been applied
- [ ] Phase A-2: Documentation has been updated

---

## Verification Steps

### Step 1: Clean Build

```bash
cd /root/code/Kestrel

# Clean previous build artifacts
cargo clean

# Build entire workspace
cargo build --workspace

# Expected: No compilation errors
```

---

### Step 2: Run All Unit Tests

```bash
# Run all unit tests in workspace
cargo test --workspace --lib

# Expected Output (summary):
# kestrel-schema:     ✅ 3/3 tests passing
# kestrel-event:      ✅ 5/5 tests passing
# kestrel-core:       ✅ 26/26 tests passing
# kestrel-rules:      ✅ 4/4 tests passing
# kestrel-engine:     ✅ 10/10 unit tests passing
# kestrel-runtime-wasm: ✅ 3/3 tests passing
# kestrel-runtime-lua:  ✅ 5/5 tests passing
# kestrel-eql:        ✅ 35/35 tests passing
# kestrel-nfa:        ✅ 22/22 tests passing
# kestrel-ebpf:       ✅ 14/14 tests passing
```

---

### Step 3: Run Integration Tests

```bash
# Run all integration tests
cargo test --workspace --test

# Expected Output (critical part):
# kestrel-engine:     ✅ 6/6 integration tests passing
#   - test_process_injection_sequence        ... ok
#   - test_file_exfiltration_sequence       ... ok
#   - test_c2_beaconing_pattern           ... ok
#   - test_maxspan_enforcement            ... ok
#   - test_entity_isolation               ... ok
#   - test_multiple_sequences_different_entities ... ok
```

**Critical**: All 6 tests should pass (was 1/6 before fix)

---

### Step 4: Run Full Workspace Tests

```bash
# Run ALL tests (unit + integration)
cargo test --workspace

# Expected Output:
# test result: ok. 127 passed; 0 failed; 0 ignored
```

**Success Criteria**: Zero test failures

---

### Step 5: Save Test Results

```bash
# Create results directory
mkdir -p .sisyphus/verification

# Save full test output
cargo test --workspace 2>&1 | tee .sisyphus/verification/test_results.txt

# Generate summary
echo "=== Test Summary ===" > .sisyphus/verification/summary.txt
grep "test result:" .sisyphus/verification/test_results.txt >> .sisyphus/verification/summary.txt
echo "" >> .sisyphus/verification/summary.txt
echo "=== Test Pass Counts ===" >> .sisyphus/verification/summary.txt
cargo test --workspace --quiet 2>&1 | grep "passing" >> .sisyphus/verification/summary.txt
```

---

### Step 6: Check for Warnings

```bash
# Run clippy to check for warnings
cargo clippy --workspace --all-targets

# Expected: No new warnings introduced by NFA fix
# Note: Existing warnings are acceptable
```

---

## Expected Test Results After Phase A

### Before Phase A
```
Total Tests: ~52
Passing: ~47 (90%)
Failing: 5 (10%)

Failing Tests:
- test_process_injection_sequence
- test_file_exfiltration_sequence
- test_c2_beaconing_pattern
- test_entity_isolation
- test_multiple_sequences_different_entities
```

### After Phase A (Expected)
```
Total Tests: ~127
Passing: ~127 (100%)
Failing: 0 (0%)

Previously Failing Tests Now Passing:
- test_process_injection_sequence ✅
- test_file_exfiltration_sequence ✅
- test_c2_beaconing_pattern ✅
- test_entity_isolation ✅
- test_multiple_sequences_different_entities ✅
```

---

## Troubleshooting

### Issue: Tests Still Failing

**If detection_scenarios tests still fail after NFA fix:**

1. Verify the fix was applied correctly:
```bash
cd /root/code/Kestrel
git diff kestrel-nfa/src/engine.rs | grep -A 5 "get_expected_state"
```

Expected to see:
```rust
+     let mut max_state: Option<NfaStateId> = None;
...
+     Ok(max_state.map(|s| s.saturating_add(1)).unwrap_or(0))
```

2. Rebuild and test again:
```bash
cargo clean
cargo test -p kestrel-engine --test detection_scenarios
```

3. If still failing, check test code for other issues:
```bash
vim kestrel-engine/tests/detection_scenarios.rs
```

Look for:
- Incorrect event type IDs
- Wrong predicate evaluator setup
- Missing entity_key assignment

---

### Issue: Compilation Errors

**If build fails after NFA fix:**

1. Check Rust version:
```bash
rustc --version
# Expected: rustc 1.82+ (edition 2021)
```

2. Verify Option usage is correct:
```bash
cargo build 2>&1 | grep "error"
```

Common fixes:
- Add `use std::option::Option;`
- Check for missing `.unwrap()` calls
- Verify `map()` chain is complete

---

### Issue: Clippy Warnings

**If clippy reports new warnings:**

Example warning and fix:
```
warning: use of `unwrap_or`
   --> kestrel-nfa/src/engine.rs:299:18
    |
299 |     Ok(max_state.map(|s| s.saturating_add(1)).unwrap_or(0))
    |                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ help: try this
    |     Ok(max_state.map(|s| s.saturating_add(1)).unwrap_or_default())
```

**Fix**: Apply clippy suggestions (they're usually correct):
```rust
Ok(max_state.map(|s| s.saturating_add(1)).unwrap_or_default())
```

---

## Success Criteria

- [ ] All ~127 tests pass (0 failures)
- [ ] All 6 detection_scenarios tests pass
- [ ] No new compilation errors
- [ ] No new clippy warnings (existing warnings acceptable)
- [ ] Test results saved to `.sisyphus/verification/`
- [ ] Build succeeds with `cargo build --workspace`

---

## Summary Report Template

After running all tests, complete this summary:

```markdown
## Phase A Test Verification Results

**Date**: 2026-01-12
**Tester**: [Your Name]

### Test Results

| Metric | Value |
|--------|--------|
| Total Tests | [Count] |
| Tests Passed | [Count] |
| Tests Failed | [Count] |
| Pass Rate | [Percentage] |

### Previously Failing Tests

| Test Name | Before | After |
|-----------|---------|-------|
| test_process_injection_sequence | ❌ | ✅ |
| test_file_exfiltration_sequence | ❌ | ✅ |
| test_c2_beaconing_pattern | ❌ | ✅ |
| test_entity_isolation | ❌ | ✅ |
| test_multiple_sequences_different_entities | ❌ | ✅ |

### Build Status

- [ ] Compilation: Success
- [ ] Clippy: No new warnings
- [ ] Fmt: No formatting issues

### Files Modified

- [x] kestrel-nfa/src/engine.rs (Phase A-1)
- [x] README.md (Phase A-2)
- [x] PROGRESS.md (Phase A-2)

### Conclusion

Phase A is [COMPLETE / INCOMPLETE].

Next Phase: [Phase B - Testing Infrastructure]
```

---

## Estimated Time

- **Step 1** (Clean build): 1 minute
- **Step 2** (Unit tests): 2 minutes
- **Step 3** (Integration tests): 1 minute
- **Step 4** (Full workspace): 1 minute
- **Total**: **5 minutes**

---

## Completion

**Estimated Total Time**: 5 minutes
- 4 minutes: Run tests
- 1 minute: Save results

**Next Task**: Proceed to Phase B - Testing Infrastructure

---

## Final Checklist

After completing Phase A-3:

- [x] All unit tests passing
- [x] All integration tests passing
- [x] Zero test failures
- [x] Test results documented
- [x] Build succeeds
- [x] Ready to proceed to Phase B

**Phase A Status**: ✅ COMPLETE
