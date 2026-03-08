# Phase N2 Partitioned NFA Design

**Date:** 2026-03-08
**Source:** `docs/next_optimization_plan.md`
**Scope:** Implement Phase N2 item 1 only: remove the global NFA mutex bottleneck by aligning sequence evaluation with EventBus partitions.

## Goal

Replace the single shared NFA instance in `kestrel-engine` with per-partition NFA instances so sequence evaluation scales with EventBus worker partitions while preserving current rule semantics.

## Current Problem

`DetectionEngine` currently keeps a single `Arc<Mutex<Option<NfaEngine>>>`. Every event, regardless of entity or partition, must acquire the same async mutex before sequence evaluation. This serializes the hottest path in the engine and caps sequence throughput at roughly single-thread performance.

## Chosen Approach

Use one `NfaEngine` per EventBus partition.

This matches the recommendation in `docs/next_optimization_plan.md` and the existing `EventBus` design:
- EventBus already partitions events deterministically.
- The default partition strategies keep related events stable within a partition.
- Sequence state is keyed by `entity_key`, so colocating an entity’s events in one partition naturally isolates state without requiring cross-partition synchronization.

## Architecture

### DetectionEngine storage

Replace the single NFA handle with a collection owned by the engine, sized to `event_bus.partitions.max(1)`.

The engine keeps:
- partition count
- a partitioner compatible with the EventBus partition strategy
- `Vec<Arc<Mutex<Option<NfaEngine>>>>` for sequence engines

This keeps the `NfaEngine` API stable for this round and confines the refactor to `kestrel-engine`.

### Event routing

When the engine receives a batch from the EventBus sink, it will:
1. clone the single-event rule snapshot once
2. group the batch by partition using the same partitioning logic as `EventBusHandle`
3. evaluate partition groups concurrently
4. process events in-order within each partition group

This preserves per-partition ordering and removes cross-partition lock contention.

### Rule propagation

Sequence rule load/unload operations become broadcast operations:
- load sequence into every partition NFA
- unload sequence from every partition NFA

If any partition fails, return an error annotated with the partition id.

### Metrics

Existing engine counters remain unchanged.

For NFA-specific stats exposed by `DetectionEngine`, aggregate values across all partition NFAs by summing counters and merging per-sequence views conservatively. This is sufficient for Phase N2 item 1 and avoids bundling the later `metrics` refactor into this change.

## Data Flow

### Startup

`DetectionEngine::new`:
- reads `config.event_bus.partitions`
- creates one `NfaEngine` per partition when sequence evaluation is enabled
- stores a matching partitioner for future routing

### Event evaluation

`DetectionEngine::start` and `DetectionEngine::eval_event`:
- compute target partition for each event
- call `eval_event_with_rules` with the selected partition NFA only
- keep single-event evaluation logic unchanged

### Sequence management

`load_sequence` and `unload_sequence`:
- iterate over all partition NFA instances
- apply the operation to each partition
- surface the first failure with partition context

## Error Handling

- Partition-local event processing errors increment the shared engine error counter and do not stop other partitions.
- Sequence load/unload failures include the partition id in the returned `EngineError` message.
- `partitions=1` remains a fully supported fast path and should behave identically to current behavior.

## Testing Strategy

Follow TDD for this implementation.

### New coverage

1. `partitions=1` remains behavior-compatible.
2. Same `entity_key` across a multi-step sequence still matches when multiple partitions exist.
3. Distinct entities routed to different partitions can both complete sequences.
4. Sequence load is visible to all partition NFAs.
5. Sequence unload removes rules from all partition NFAs.

### Verification commands

- `cargo test -p kestrel-engine`
- `cargo clippy -p kestrel-engine --all-targets -- -D warnings`
- `cargo build --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

## Out of Scope

This design intentionally does not include:
- async `PredicateEvaluator`
- budget tracker atomics
- NFA event clone reduction
- metrics lock removal
- single-event rule snapshot `Arc<Vec<_>>` conversion

Those remain for later Phase N2 slices.
