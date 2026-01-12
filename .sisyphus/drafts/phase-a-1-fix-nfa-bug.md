# Phase A-1 Implementation Guide: Fix NFA Engine Bug

**Priority**: P0-Critical
**Estimated Time**: 30 minutes
**Risk**: Low (simple logic fix, comprehensive tests exist)

---

## Problem Statement

**Bug Location**: `kestrel-nfa/src/engine.rs:279-300`

**Current Buggy Code**:
```rust
fn get_expected_state(
    &self,
    sequence: &NfaSequence,
    entity_key: u128,
) -> NfaResult<NfaStateId> {
    // Find the maximum current_state among partial matches for this entity
    // and return the next state to advance to
    let mut max_state: NfaStateId = 0;  // ❌ BUG: Always initialized to 0
    for step in &sequence.steps {
        if let Some(pm) = self
            .state_store
            .get(&sequence.id, entity_key, step.state_id)
        {
            if !pm.terminated && pm.current_state >= max_state {
                max_state = pm.current_state;
            }
        }
    }
    // Return the next state to advance to (current max + 1)
    Ok(max_state.saturating_add(1))  // ❌ BUG: Always adds 1
}
```

**The Bug**:
- When no partial matches exist (initial state of a sequence), `max_state` remains 0
- The function returns `0 + 1 = 1` instead of `0`
- Code looks for a step with `state_id == 1`, but first step has `state_id == 0`
- No partial match is created, first event is ignored
- All subsequent events fail because there's no partial match to advance

**Impact**:
- 5/6 integration tests failing in `kestrel-engine/tests/detection_scenarios.rs`
- Core sequence detection capability non-functional
- All sequence rules fail to match

---

## Root Cause Analysis

The function doesn't distinguish between:
1. **No partial match found** (should return 0 for first state)
2. **Partial match at state 0 exists** (should return 1 for next state)

By initializing `max_state: NfaStateId = 0`, both cases result in returning 1.

---

## Solution

### Fix Approach: Use `Option<NfaStateId>` to track existence

**Corrected Code**:
```rust
fn get_expected_state(
    &self,
    sequence: &NfaSequence,
    entity_key: u128,
) -> NfaResult<NfaStateId> {
    // Find the maximum current_state among partial matches for this entity
    // Return 0 if no partial match exists, otherwise return next state to advance to
    let mut max_state: Option<NfaStateId> = None;  // ✅ Use Option to track existence

    for step in &sequence.steps {
        if let Some(pm) = self
            .state_store
            .get(&sequence.id, entity_key, step.state_id)
        {
            if !pm.terminated {
                match max_state {
                    None => {
                        // First partial match found
                        max_state = Some(pm.current_state);
                    }
                    Some(current) if pm.current_state > current => {
                        // Found a match at a higher state
                        max_state = Some(pm.current_state);
                    }
                    Some(_) => {
                        // Current max is already higher, keep it
                    }
                }
            }
        }
    }

    // If no partial match exists, return 0 (first state)
    // Otherwise return max_state + 1 (next state to advance to)
    Ok(max_state.map(|s| s.saturating_add(1)).unwrap_or(0))
}
```

### Key Changes

| Line | Old Code | New Code | Reason |
|------|-----------|-----------|--------|
| 287 | `let mut max_state: NfaStateId = 0;` | `let mut max_state: Option<NfaStateId> = None;` | Track if any match found |
| 293-295 | `if !pm.terminated && pm.current_state >= max_state { max_state = pm.current_state; }` | `match max_state { None => { ... }, Some(current) if pm.current_state > current => { ... } }` | Only update max_state when finding a higher state |
| 299 | `Ok(max_state.saturating_add(1))` | `Ok(max_state.map(\|s\| s.saturating_add(1)).unwrap_or(0))` | Return 0 if no match, otherwise max+1 |

---

## Implementation Steps

### Step 1: Edit the File

```bash
cd /root/code/Kestrel
vim kestrel-nfa/src/engine.rs
```

### Step 2: Locate the Function

Navigate to line 279 (or search for `fn get_expected_state`)

### Step 3: Apply the Fix

Replace the entire function body (lines 287-299) with the corrected code above.

### Step 4: Save and Close

```vim
:wq
```

### Step 5: Verify the Fix

```bash
# Run all NFA unit tests (should still pass)
cargo test -p kestrel-nfa --lib

# Run the 5 failing detection scenario tests
cargo test -p kestrel-engine --test detection_scenarios

# Expected output:
# test test_process_injection_sequence ... ok
# test test_file_exfiltration_sequence ... ok
# test test_c2_beaconing_pattern ... ok
# test test_entity_isolation ... ok
# test test_multiple_sequences_different_entities ... ok
# test test_maxspan_enforcement ... ok (was already passing)
# test result: ok. 6 passed; 0 failed
```

### Step 6: Verify No Regressions

```bash
# Run entire workspace tests
cargo test --workspace

# Expected: All tests passing, zero failures
```

---

## Test Cases That Will Now Pass

### test_process_injection_sequence
**Scenario**: 3-step sequence (1001 → 1002 → 1003)
**Expected**: Alert on 3rd event
**Before Fix**: 0 alerts (fails)
**After Fix**: 1 alert (passes)

### test_file_exfiltration_sequence
**Scenario**: 3-step sequence (2001 → 2002 → 2003)
**Expected**: Alert on 3rd event
**Before Fix**: 0 alerts (fails)
**After Fix**: 1 alert (passes)

### test_c2_beaconing_pattern
**Scenario**: 5-step sequence (3001 repeated 5×)
**Expected**: Alert on 5th event
**Before Fix**: 0 alerts (fails)
**After Fix**: 1 alert (passes)

### test_entity_isolation
**Scenario**: 2-step sequence for 2 different entities
**Expected**: 1 alert per entity on 2nd event
**Before Fix**: 0 alerts (fails)
**After Fix**: 2 alerts (passes)

### test_multiple_sequences_different_entities
**Scenario**: 3-step sequence for 2 different entities
**Expected**: 2 alerts (one per entity on 3rd event)
**Before Fix**: 0 alerts (fails)
**After Fix**: 2 alerts (passes)

---

## Rollback Plan (If Something Goes Wrong)

### Revert the Changes
```bash
cd /root/code/Kestrel
git diff kestrel-nfa/src/engine.rs  # Review changes
git checkout kestrel-nfa/src/engine.rs    # Revert
```

### Verify Revert
```bash
# Tests should fail again as before
cargo test -p kestrel-engine --test detection_scenarios
```

---

## Success Criteria

- [ ] Function compiles without errors
- [ ] All 6 detection_scenarios tests pass
- [ ] All 22 kestrel-nfa unit tests still pass
- [ ] All ~52 workspace tests pass
- [ ] No new compiler warnings introduced

---

## Why This Fix is Correct

### Logic Flow After Fix

**Case 1: No partial match exists (initial state)**
1. Loop through steps: `max_state` remains `None`
2. After loop: `max_state = None`
3. `max_state.map(...).unwrap_or(0)` returns `0`
4. Function returns `Ok(0)` ✅ Correct: first state

**Case 2: Partial match at state 0 exists**
1. Loop finds match at `current_state = 0`
2. `max_state` becomes `Some(0)`
3. After loop: `max_state = Some(0)`
4. `max_state.map(|s| s + 1).unwrap_or(0)` returns `1`
5. Function returns `Ok(1)` ✅ Correct: next state after 0

**Case 3: Partial matches at states 0 and 2 exist**
1. Loop finds match at `current_state = 0` → `max_state = Some(0)`
2. Loop finds match at `current_state = 2` → `2 > 0`, so `max_state = Some(2)`
3. After loop: `max_state = Some(2)`
4. `max_state.map(|s| s + 1).unwrap_or(0)` returns `3`
5. Function returns `Ok(3)` ✅ Correct: next state after 2

---

## Additional Improvements (Optional, Not Critical)

### Enhancement 1: Add Debug Logging
```rust
#[cfg(test)]
impl NfaEngine {
    pub fn debug_get_expected_state(
        &self,
        sequence: &NfaSequence,
        entity_key: u128,
    ) -> (Option<NfaStateId>, NfaResult<NfaStateId>) {
        let max_state = /* ... existing logic ... */;
        (max_state.clone(), self.get_expected_state(sequence, entity_key))
    }
}
```

### Enhancement 2: Add Unit Test
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_expected_state_no_match() {
        // Create engine, sequence with no partial matches
        // Verify get_expected_state returns 0
    }

    #[test]
    fn test_get_expected_state_match_at_zero() {
        // Create engine, sequence with partial match at state 0
        // Verify get_expected_state returns 1
    }

    #[test]
    fn test_get_expected_state_match_at_two() {
        // Create engine, sequence with partial match at state 2
        // Verify get_expected_state returns 3
    }
}
```

---

## Estimated Impact

### Performance Impact
- **None** - Logic change only, no extra allocations or complexity

### Test Coverage Impact
- **+5 passing tests** - All detection_scenarios tests now pass
- **Total**: ~52 tests passing (was ~47 with 5 failures)

### Code Quality Impact
- **Improved** - More explicit logic using `Option` type
- **No regressions** - Same execution path for non-initial states

---

## Completion

**Estimated Total Time**: 30 minutes
- 5 minutes: Edit code
- 2 minutes: Save and compile
- 10 minutes: Run tests
- 13 minutes: Verification and cleanup

**Next Task**: Phase A-2: Update Documentation Accuracy
