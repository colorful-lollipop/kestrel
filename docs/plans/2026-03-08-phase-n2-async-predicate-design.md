# Phase N2 Async Predicate Evaluator Design

**Date:** 2026-03-08
**Source:** `docs/next_optimization_plan.md`
**Scope:** Implement Phase N2 item 2 only: make `PredicateEvaluator` asynchronous and remove the Wasm runtime's synchronous bridge.

## Goal

Convert the predicate evaluation path from a synchronous trait call into an async call chain so the runtime-specific engines can execute predicates without blocking the Tokio executor.

## Current Problem

`kestrel-nfa::PredicateEvaluator` is currently synchronous. `NfaEngine::process_event` and its internal sequence-matching helpers therefore run synchronously as well. This forces async runtimes, especially `kestrel-runtime-wasm`, to bridge back into sync code with `block_in_place` and `Handle::block_on`, adding scheduler overhead and limiting future concurrency improvements.

## Chosen Approach

Make `PredicateEvaluator::evaluate` an async trait method and propagate that change through the NFA engine and the detection engine.

This is the cleanest fit for the optimization plan because:
- `DetectionEngine` already runs in async Tokio contexts.
- Only predicate evaluation truly needs to await; the rest of the NFA logic can remain structurally unchanged.
- Wasm can then await its runtime API directly and remove the current synchronous bridge.

## Architecture

### PredicateEvaluator API

Update `kestrel-nfa::PredicateEvaluator` so that:
- `evaluate` becomes async and still returns `NfaResult<bool>`
- `get_required_fields` remains synchronous
- `has_predicate` remains synchronous

This keeps metadata queries cheap while enabling runtime-backed predicate execution to await naturally.

### NFA call chain

Convert the sequence path in `kestrel-nfa` to async:
- `NfaEngine::process_event`
- `process_sequence_event_optimized`
- `step_matches`
- any helper that directly or indirectly awaits predicate evaluation

Only the predicate-dependent branch should await. State management, time-window checks, and transition bookkeeping remain unchanged in behavior.

### DetectionEngine integration

`DetectionEngine` already exposes async entry points and uses async mutexes. The per-partition NFA work from Phase N2 item 1 remains intact; each partition-local NFA call simply becomes `await`-based in:
- `eval_event`
- the background batch-processing task in `start`

Single-event rule handling remains unchanged.

### Runtime implementations

#### Wasm

`kestrel-runtime-wasm` will implement the async trait directly and await `eval_loaded_predicate`. This removes the current `block_in_place` and `Handle::block_on` bridge from predicate evaluation.

#### Lua

`kestrel-runtime-lua` will implement the async trait with the same internal predicate logic as today. The body remains effectively synchronous, but the interface aligns with the rest of the engine.

#### Tests, mocks, benchmarks, FFI helpers

All `PredicateEvaluator` implementations across tests, benchmarks, and support crates must migrate to the async signature so the workspace compiles consistently.

## Data Flow

### Event evaluation

`DetectionEngine::eval_event`:
- routes the event to the correct partition-local NFA
- awaits `process_event`
- preserves current alert aggregation semantics

`DetectionEngine::start`:
- receives EventBus batches asynchronously
- preserves per-partition ordering
- awaits each partition-local NFA evaluation while continuing to process batches in the existing async task model

### Sequence matching

`NfaEngine::process_event`:
- handles single-event and sequence rules exactly as before
- awaits only where step predicates are evaluated
- keeps existing state transitions, maxspan checks, and match materialization behavior

## Error Handling

- `evaluate` continues to return `NfaResult<bool>`; only the call style changes.
- Wasm and Lua predicate execution errors remain mapped to `NfaError::PredicateError` or the existing crate-specific conversion path.
- `NfaEngine::process_event` keeps current semantics: a rule-level failure is surfaced the same way it is today.
- `DetectionEngine` continues counting errors without changing fail-open or fail-closed policy behavior.

## Testing Strategy

Follow TDD for this implementation.

### New or updated coverage

1. `kestrel-nfa`: a minimal async evaluator test proving `process_event().await` can complete a sequence.
2. `kestrel-engine`: at least one end-to-end sequence match test through the async NFA path.
3. `kestrel-runtime-wasm`: a predicate evaluation test proving the async trait path still drives loaded Wasm predicates.
4. Workspace-wide compile coverage for all mock and benchmark evaluators implementing the updated trait.

### Verification commands

- `cargo test -p kestrel-nfa`
- `cargo test -p kestrel-engine`
- `cargo test -p kestrel-runtime-wasm`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

## Out of Scope

This design intentionally does not include:
- budget tracker atomics
- NFA event clone reduction
- metrics lock removal
- single-event rule snapshot `Arc<Vec<_>>` conversion
- broader API redesign beyond async predicate evaluation
