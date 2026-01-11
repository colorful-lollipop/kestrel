# Kestrel Wasm Runtime

**Runtime Layer - WebAssembly Predicate Evaluation Engine**

## Module Goal

Execute compiled EQL predicates as WebAssembly modules:
- Fast predicate evaluation (<1μs P99 target)
- Safe sandbox execution
- Host function API for event field access
- Module caching and instance pooling

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Wasm Runtime Engine                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ WasmEngine                                           │   │
│  │ ├── modules: HashMap<RuleId, CompiledModule>        │   │
│  │ │   └── instance_pre: InstancePre<WasmContext>      │   │
│  │ ├── instance_pool: HashMap<RuleId, InstancePool>    │   │
│  │ │   └── semaphore: Arc<Semaphore>                   │   │
│  │ ├── regex_cache: HashMap<Pattern, Regex>            │   │
│  │ └── glob_cache: HashMap<Pattern, GlobMatcher>       │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Wasm Context (per-call)                             │   │
│  │ ├── event: Option<Event>                            │   │
│  │ ├── schema: Arc<SchemaRegistry>                     │   │
│  │ ├── alerts: Arc<Mutex<Vec<Alert>>>                  │   │
│  │ ├── regex_cache: Arc<HashMap<Pattern, Regex>>       │   │
│  │ └── glob_cache: Arc<HashMap<Pattern, Glob>>         │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Host Functions (imported by Wasm)                   │   │
│  │ ├── event_get_i64(field_id) → i64                  │   │
│  │ ├── event_get_u64(field_id) → u64                  │   │
│  │ ├── event_get_f64(field_id) → f64                  │   │
│  │ ├── event_get_bool(field_id) → i32 (0/1)           │   │
│  │ ├── event_get_str(field_id, buf_ptr) → len         │   │
│  │ ├── alert_emit(rule_id)                             │   │
│  │ ├── regex_match(pattern_ptr, text_ptr) → i32       │   │
│  │ └── glob_match(pattern_ptr, text_ptr) → i32        │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Core Interfaces

### WasmEngine
```rust
pub struct WasmEngine {
    engine: wasmtime::Engine,
    linker: wasmtime::Linker<WasmContext>,
    modules: Arc<RwLock<HashMap<String, CompiledModule>>>,
    instance_pool: Arc<RwLock<HashMap<String, InstancePool>>>,
    regex_cache: Arc<RwLock<HashMap<String, Regex>>>,
    glob_cache: Arc<RwLock<HashMap<String, Glob>>>,
    schema: Arc<SchemaRegistry>,
}

impl WasmEngine {
    pub fn new(config: WasmConfig, schema: Arc<SchemaRegistry>) -> Result<Self, WasmRuntimeError>;
    
    pub async fn compile_rule(&self, rule_id: &str, wasm_bytes: &[u8]) 
        -> Result<(), WasmRuntimeError>;
    
    pub async fn evaluate(&self, rule_id: &str, event: &Event) 
        -> Result<bool, WasmRuntimeError>;
    
    pub async fn eval_adhoc_predicate(&self, wasm_bytes: &[u8], event: &Event)
        -> Result<bool, WasmRuntimeError>;
}
```

### WasmConfig
```rust
#[derive(Debug, Clone)]
pub struct WasmConfig {
    pub max_memory_pages: u32,       // Default: 256 (16MB)
    pub max_table_elements: u32,     // Default: 10000
    pub enable_reference_types: bool, // Default: true
    pub instance_pool_size: usize,   // Default: 10 per rule
    pub instance_timeout_ms: u64,    // Default: 5000
}
```

## Wasm Module Interface

Every compiled predicate module exports:

```wat
;; Required exports
(func $pred_eval (export "pred_eval") (result i32)
  ;; Returns 1 if predicate matches, 0 otherwise
)

(memory (export "memory") 1)
;; Data section with string literals
(data (i32.const 100) "/bin/bash\0")
```

## Host Function API

### Field Access
```rust
// Get i64 field value
fn event_get_i64(event_handle: i32, field_id: i32) -> i64 {
    // Returns 0 if field not found or wrong type
}

// Get string field (returns length, copies to provided buffer)
fn event_get_str(event_handle: i32, field_id: i32, buf_ptr: i32) -> i32 {
    // Returns string length, copies to memory at buf_ptr
}

// Check if field exists
fn event_has_field(event_handle: i32, field_id: i32) -> i32 {
    // Returns 1 if field exists, 0 otherwise
}
```

### String Functions
```rust
fn string_contains(haystack_ptr: i32, haystack_len: i32, needle_ptr: i32, needle_len: i32) -> i32;
fn string_starts_with(s_ptr: i32, s_len: i32, prefix_ptr: i32, prefix_len: i32) -> i32;
fn string_ends_with(s_ptr: i32, s_len: i32, suffix_ptr: i32, suffix_len: i32) -> i32;
```

### Pattern Matching
```rust
fn regex_match(pattern_ptr: i32, pattern_len: i32, text_ptr: i32, text_len: i32) -> i32;
fn glob_match(pattern_ptr: i32, pattern_len: i32, text_ptr: i32, text_len: i32) -> i32;
```

## Usage Example

```rust
use kestrel_runtime_wasm::{WasmEngine, WasmConfig};
use kestrel_event::{Event, TypedValue};
use kestrel_schema::SchemaRegistry;

let schema = Arc::new(SchemaRegistry::new());
let config = WasmConfig::default();
let engine = WasmEngine::new(config, schema).unwrap();

// Compiled Wasm bytes (from EQL compiler)
let wasm_bytes = std::fs::read("rules/compiled/example.wasm").unwrap();

// Load rule
engine.compile_rule("detect-bash", &wasm_bytes).await.unwrap();

// Create event
let event = Event::builder()
    .event_type(1)
    .ts_mono(1_000_000_000)
    .ts_wall(1_000_000_000)
    .entity_key(0x123)
    .field(1, TypedValue::String("/bin/bash".into()))
    .field(2, TypedValue::I64(1234))
    .build()
    .unwrap();

// Evaluate
let matched = engine.evaluate("detect-bash", &event).await.unwrap();
assert!(matched);
```

## Instance Pooling

For high-throughput scenarios, instances are pooled:

```rust
pub struct InstancePool {
    instances: Vec<PooledInstance>,
    semaphore: Arc<Semaphore>,
}

pub struct PooledInstance {
    store: Store<WasmContext>,
    instance: Instance,
    in_use: bool,
}

impl WasmEngine {
    async fn acquire_instance(&self, rule_id: &str) -> Result<PooledInstance, WasmRuntimeError> {
        let pool = self.instance_pool.read().await;
        let permit = pool.semaphore.clone().acquire_owned().await?;
        // Get or create instance...
    }
    
    async fn release_instance(&self, rule_id: &str, instance: PooledInstance) {
        // Return to pool...
    }
}
```

## Planned Evolution

### v0.8 (Current)
- [x] Basic Wasm execution
- [x] Host function API
- [x] Instance pooling
- [x] Regex/glob caching
- [x] <1μs evaluation target

### v0.9
- [ ] SIMD for regex
- [ ] Component model
- [ ] Threading support
- [ ] GPU offload

### v1.0
- [ ] Distributed caching
- [ ] Hot module reload
- [ ] Custom WASI
- [ ] Performance profiling

## Test Coverage

```bash
cargo test -p kestrel-runtime-wasm --lib

# Engine Tests
test_engine_create                # Engine initialization
test_compile_and_load             # Module compilation
test_evaluate_simple              # Basic evaluation
test_evaluate_with_fields         # Field access
test_instance_pooling             # Pool behavior

# Host Function Tests
test_event_get_i64                # i64 field access
test_event_get_str                # String field access
test_event_get_bool               # Bool field access
test_string_contains              # Contains function
test_regex_match                  # Regex matching
test_glob_match                   # Glob matching
```

## Dependencies

```
kestrel-runtime-wasm
├── kestrel-schema (type definitions)
├── kestrel-event (Event struct)
├── kestrel-nfa (PredicateEvaluator trait)
├── wasmtime (Wasm runtime)
├── regex (regex implementation)
├── glob (glob pattern matching)
├── tokio (async runtime)
└── tracing (logging)
```

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Instance acquire | ~50μs | From pool |
| Instance release | ~10μs | To pool |
| pred_eval | <1μs | P99 target |
| Field lookup | ~100ns | Per field |
| Regex cache hit | ~50ns | |
| Memory per instance | ~64KB | Wasm runtime |
