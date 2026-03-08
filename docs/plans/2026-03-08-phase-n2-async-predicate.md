# Async Predicate Evaluator Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make `PredicateEvaluator` async, propagate the async call chain through `kestrel-nfa` and `kestrel-engine`, and remove the Wasm runtime's synchronous predicate bridge.

**Architecture:** `PredicateEvaluator::evaluate` becomes async. `NfaEngine` awaits predicate evaluation, `DetectionEngine` awaits partition-local NFA processing, and runtime/mock implementations adopt the async trait signature.

**Tech Stack:** Rust 2021, Tokio, `async-trait`, `kestrel-nfa`, `kestrel-engine`, `kestrel-runtime-wasm`, `kestrel-runtime-lua`.

---

### Task 1: Add failing async NFA coverage

**Files:**
- Modify: `kestrel-nfa/src/engine.rs`
- Modify: `kestrel-nfa/src/lib.rs`

**Step 1: Write the failing test**
- Add a minimal async evaluator test that awaits `NfaEngine::process_event` and proves a sequence can complete through the new async trait path.

**Step 2: Run test to verify it fails**
- Run: `cargo test -p kestrel-nfa test_process_event_with_async_predicate -- --nocapture`
- Expected: FAIL because `PredicateEvaluator` and `process_event` are still synchronous.

**Step 3: Write minimal implementation**
- Convert the trait and the NFA call chain to async only as needed to make the test pass.

**Step 4: Run test to verify it passes**
- Run: `cargo test -p kestrel-nfa test_process_event_with_async_predicate -- --nocapture`
- Expected: PASS.

### Task 2: Adapt engine routing to await partition-local NFA evaluation

**Files:**
- Modify: `kestrel-engine/src/lib.rs`
- Test: `kestrel-engine/src/lib.rs`

**Step 1: Write the failing test**
- Add or update an engine-level sequence test that awaits a full async NFA path from `DetectionEngine::eval_event`.

**Step 2: Run test to verify it fails**
- Run: `cargo test -p kestrel-engine test_eval_event_sequence_match_async_nfa -- --nocapture`
- Expected: FAIL because engine code still expects a synchronous `process_event`.

**Step 3: Write minimal implementation**
- Await partition-local `process_event` calls in direct and background paths.

**Step 4: Run test to verify it passes**
- Run: `cargo test -p kestrel-engine test_eval_event_sequence_match_async_nfa -- --nocapture`
- Expected: PASS.

### Task 3: Remove Wasm synchronous predicate bridge and update implementations

**Files:**
- Modify: `kestrel-runtime-wasm/src/lib.rs`
- Modify: `kestrel-runtime-lua/src/lib.rs`
- Modify: test/benchmark/mock files implementing `PredicateEvaluator`

**Step 1: Write the failing coverage**
- Add or update Wasm-side coverage that exercises the async predicate trait implementation.

**Step 2: Run test to verify it fails**
- Run: `cargo test -p kestrel-runtime-wasm -- --nocapture`
- Expected: FAIL or compile error until implementations adopt the async trait.

**Step 3: Write minimal implementation**
- Remove `block_in_place` bridge in Wasm and update all evaluator implementations to the new async trait.

**Step 4: Run test to verify it passes**
- Run: `cargo test -p kestrel-runtime-wasm -- --nocapture`
- Expected: PASS.

### Task 4: Verify and polish

**Files:**
- Modify as needed: touched Rust files
- Check: `docs/plans/2026-03-08-phase-n2-async-predicate-design.md`

**Step 1: Run focused verification**
- Run: `cargo test -p kestrel-nfa && cargo test -p kestrel-engine && cargo test -p kestrel-runtime-wasm`
- Expected: PASS.

**Step 2: Run lint**
- Run: `cargo clippy --workspace --all-targets -- -D warnings`
- Expected: PASS.

**Step 3: Run workspace verification**
- Run: `cargo test --workspace`
- Expected: PASS.
