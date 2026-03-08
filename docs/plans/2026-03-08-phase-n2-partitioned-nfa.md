# Partitioned NFA Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the single shared NFA instance in `kestrel-engine` with per-partition NFA instances aligned to EventBus partitions.

**Architecture:** `DetectionEngine` will own one `NfaEngine` per EventBus partition and use the same partitioning logic as `EventBus` to route sequence evaluation. Sequence rule management will broadcast load/unload to every partition, while single-event rule handling stays global.

**Tech Stack:** Rust 2021, Tokio, existing `kestrel-core::eventbus` partitioning primitives, `kestrel-nfa`.

---

### Task 1: Add a failing engine test for partitioned sequence evaluation

**Files:**
- Modify: `kestrel-engine/src/lib.rs`
- Test: `kestrel-engine/src/lib.rs`

**Step 1: Write the failing test**
- Add a unit test that builds an engine with `event_bus.partitions = 4`, loads a simple two-step sequence, and verifies a matching entity still produces an alert.

**Step 2: Run test to verify it fails**
- Run: `cargo test -p kestrel-engine test_partitioned_nfa_sequence_match -- --nocapture`
- Expected: FAIL because the engine still assumes a single global NFA path.

**Step 3: Write minimal implementation**
- Introduce partition-aware NFA storage and routing only as needed to make the test pass.

**Step 4: Run test to verify it passes**
- Run: `cargo test -p kestrel-engine test_partitioned_nfa_sequence_match -- --nocapture`
- Expected: PASS.

### Task 2: Broadcast sequence load/unload across all partitions

**Files:**
- Modify: `kestrel-engine/src/lib.rs`
- Test: `kestrel-engine/src/lib.rs`

**Step 1: Write the failing test**
- Add a test proving unload removes a sequence for every partition, not just one.

**Step 2: Run test to verify it fails**
- Run: `cargo test -p kestrel-engine test_partitioned_nfa_unload_all_partitions -- --nocapture`
- Expected: FAIL because unload only affects one NFA instance.

**Step 3: Write minimal implementation**
- Broadcast load/unload operations and annotate partition-specific failures.

**Step 4: Run test to verify it passes**
- Run: `cargo test -p kestrel-engine test_partitioned_nfa_unload_all_partitions -- --nocapture`
- Expected: PASS.

### Task 3: Route batched events by partition in the hot path

**Files:**
- Modify: `kestrel-engine/src/lib.rs`
- Test: `kestrel-engine/src/lib.rs`

**Step 1: Write the failing test**
- Add a test that feeds multiple entities across partitions and verifies both sequences complete without shared-state interference.

**Step 2: Run test to verify it fails**
- Run: `cargo test -p kestrel-engine test_partitioned_nfa_multi_entity_batches -- --nocapture`
- Expected: FAIL or expose the single-lock routing bottleneck assumptions.

**Step 3: Write minimal implementation**
- Group batch events by partition and evaluate groups concurrently while preserving per-partition order.

**Step 4: Run test to verify it passes**
- Run: `cargo test -p kestrel-engine test_partitioned_nfa_multi_entity_batches -- --nocapture`
- Expected: PASS.

### Task 4: Verify and polish

**Files:**
- Modify: `kestrel-engine/src/lib.rs`
- Check: `docs/plans/2026-03-08-phase-n2-partitioned-nfa-design.md`

**Step 1: Run crate-level verification**
- Run: `cargo test -p kestrel-engine`
- Expected: PASS.

**Step 2: Run crate-level lint**
- Run: `cargo clippy -p kestrel-engine --all-targets -- -D warnings`
- Expected: PASS.

**Step 3: Run workspace verification**
- Run: `cargo build --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
- Expected: PASS.
