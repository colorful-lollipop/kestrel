# Kestrel NFA Engine

**Runtime Layer - Non-deterministic Finite Automaton for Sequence Detection**

## Module Goal

Execute sequence detection patterns using NFA (Non-deterministic Finite Automaton):
- Track partial sequence matches per entity
- Support time-based windows (maxspan)
- Efficient state management with TTL/LRU/Quota eviction
- Deterministic replay support

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    NFA Engine                                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Input: Event Stream                                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Event(event_type=1, entity_key=0x123)               │   │
│  │ Event(event_type=2, entity_key=0x123)               │   │
│  │ Event(event_type=3, entity_key=0x123)               │   │
│  └─────────────────────────────────────────────────────┘   │
│                        ↓                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ State Store (per-entity partial matches)            │   │
│  │ ┌───────────────────────────────────────────────┐   │   │
│  │ │ Entity 0x123                                  │   │   │
│  │ │ ├── Sequence "attack" (step 1/3)             │   │   │
│  │ │ │   captures: {exe: "/bin/curl"}              │   │   │
│  │ │ │   expires: 10000000000 ns                   │   │   │
│  │ │ └──────────────────────────────────────────────┘   │   │
│  │ │ Entity 0x456                                  │   │   │
│  │ │ └── ...                                         │   │   │
│  │ └───────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────┘   │
│                        ↓                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Sequence Match Output                               │   │
│  │ { rule_id, sequence_id, entity_key, captures }     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Core Concepts

### Sequence Definition
```rust
pub struct CompiledSequence {
    pub sequence_id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub steps: Vec<SeqStep>,
    pub maxspan_ms: u64,        // Time window
    pub required_fields: Vec<u32>,
}

pub struct SeqStep {
    pub event_type: EventTypeId,
    pub predicate: Option<IrPredicate>,  // Optional filter
    pub captures: Vec<String>,           // Fields to capture
}
```

### State Store
```rust
pub struct StateStore {
    sequences: HashMap<EntityKey, Vec<PartialMatch>>,
    config: StoreConfig,
}

pub struct PartialMatch {
    pub sequence_id: String,
    pub step_index: usize,
    pub started_at: TimestampMono,
    pub expires_at: TimestampMono,
    pub captures: HashMap<String, TypedValue>,
    pub event_ids: Vec<u64>,  // For reproducibility
}
```

## Core Interfaces

### NfaEngine
```rust
pub struct NfaEngine {
    sequences: Arc<RwLock<Vec<CompiledSequence>>>,
    state_store: StateStore,
    predicate_evaluator: Option<Arc<dyn PredicateEvaluator>>,
}

impl NfaEngine {
    pub fn new(config: NfaEngineConfig, evaluator: Option<Arc<dyn PredicateEvaluator>>) -> Self;
    
    pub fn load_sequence(&mut self, sequence: CompiledSequence);
    
    pub fn process_event(&mut self, event: &Event) -> Result<Vec<SequenceMatch>, NfaError>;
    
    pub fn cleanup_expired(&mut self, now_ns: u64) -> Vec<PartialMatch>;
}
```

### PredicateEvaluator
```rust
#[async_trait::async_trait]
pub trait PredicateEvaluator: Send + Sync {
    async fn evaluate(
        &self,
        rule_id: &str,
        predicate_id: &str,
        event: &Event,
    ) -> Result<bool, PredicateError>;
}
```

## Usage Example

```rust
use kestrel_nfa::{NfaEngine, NfaEngineConfig, CompiledSequence, SeqStep};
use kestrel_eql::ir::{IrPredicate, IrCondition, IrOp, IrValue};
use kestrel_event::Event;
use kestrel_schema::TypedValue;

// Create engine
let config = NfaEngineConfig {
    max_sequences_per_entity: 100,
    max_captures_per_sequence: 10,
    default_ttl_ms: 60000,
};
let engine = NfaEngine::new(config, None);

// Define sequence: curl → dns → file write
let sequence = CompiledSequence {
    sequence_id: "curl-dns-write".to_string(),
    rule_id: "detect-attack".to_string(),
    rule_name: "Detect Attack Pattern".to_string(),
    steps: vec![
        SeqStep {
            event_type: 1,  // exec event
            predicate: None,
            captures: vec!["process.executable".to_string()],
        },
        SeqStep {
            event_type: 2,  // dns event
            predicate: None,
            captures: vec!["dns.query".to_string()],
        },
        SeqStep {
            event_type: 3,  // file write
            predicate: Some(IrPredicate {
                required_fields: vec![1],
                conditions: vec![IrCondition::Comparison {
                    field_id: 1,
                    op: IrOp::EndsWith,
                    value: IrValue::String("/etc/passwd".to_string()),
                }],
            }),
            captures: vec!["file.path".to_string()],
        },
    ],
    maxspan_ms: 10000,  // 10 second window
    required_fields: vec![1, 2, 3],
};

engine.load_sequence(sequence);

// Process events
let event1 = Event::builder()
    .event_type(1)
    .ts_mono(1_000_000_000)
    .entity_key(0x123)
    .field(1, TypedValue::String("/bin/curl".into()))
    .build()
    .unwrap();

let matches = engine.process_event(&event1)?;
assert!(matches.is_empty());  // Not complete yet

let event2 = Event::builder()
    .event_type(2)
    .ts_mono(1_001_000_000)
    .entity_key(0x123)
    .field(2, TypedValue::String("evil.com".into()))
    .build()
    .unwrap();

let matches = engine.process_event(&event2)?;
assert!(matches.is_empty());  // Still not complete

let event3 = Event::builder()
    .event_type(3)
    .ts_mono(1_002_000_000)
    .entity_key(0x123)
    .field(1, TypedValue::String("/etc/passwd".into()))
    .field(3, TypedValue::String("/etc/passwd".into()))
    .build()
    .unwrap();

let matches = engine.process_event(&event3)?;
assert_eq!(matches.len(), 1);  // Full sequence matched!
assert_eq!(matches[0].sequence_id, "curl-dns-write");
```

## Eviction Strategies

### TTL (Time-To-Live)
```rust
pub struct TtlEvictionStrategy {
    max_age_ns: u64,
}

impl EvictionStrategy for TtlEvictionStrategy {
    fn evict(&self, states: &mut [PartialMatch], now_ns: u64) {
        states.retain(|s| s.expires_at > now_ns);
    }
}
```

### LRU (Least Recently Used)
```rust
pub struct LruEvictionStrategy {
    max_entries: usize,
}

impl EvictionStrategy for LruEvictionStrategy {
    fn evict(&self, states: &mut [PartialMatch], _now_ns: u64) {
        if states.len() > self.max_entries {
            states.sort_by_key(|s| s.last_accessed);
            states.truncate(self.max_entries);
        }
    }
}
```

### Quota
```rust
pub struct QuotaEvictionStrategy {
    max_memory_bytes: usize,
}
```

## Planned Evolution

### v0.8 (Current)
- [x] Basic sequence detection
- [x] Maxspan windows
- [x] TTL/LRU/Quota eviction
- [x] Captures

### v0.9
- [ ] Subsequence detection (not all steps required)
- [ ] Quantifiers (*, +, ?)
- [ ] Negative lookahead
- [ ] Parallel sequence evaluation

### v1.0
- [ ] DFA optimization
- [ ] Distributed state (Redis)
- [ ] Sequence compression
- [ ] Real-time visualization

## Test Coverage

```bash
cargo test -p kestrel-nfa --lib

# Engine Tests
test_process_single_step            # Single step advancement
test_process_full_sequence          # Complete match
test_maxspan_enforcement            # Time window
test_different_entities             # Entity isolation
test_cleanup_expired                # TTL eviction

# State Store Tests
test_lru_eviction                   # LRU strategy
test_ttl_eviction                   # TTL strategy
test_quota_eviction                 # Memory quota
test_capture_preservation           # Field captures
```

## Dependencies

```
kestrel-nfa
├── kestrel-schema (type definitions)
├── kestrel-event (Event struct)
├── kestrel-eql (IR for predicates)
├── tokio (async runtime)
├── ahash (fast hashing)
├── smallvec (stack-optimized storage)
├── parking_lot (efficient locking)
└── priority-queue (heap operations)
```

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Process event | O(s * e) | s = sequences, e = entities |
| Sequence match | O(c) | c = captures |
| State cleanup | O(n) | n = total partial matches |
| Memory per match | ~100 bytes | Excluding captures |
| Max throughput | 100k events/sec | Single thread |
