# Kestrel Detection Engine

**Core Layer - Event Processing, Rule Evaluation, Alert Generation**

## Module Goal

Coordinate the complete detection pipeline:
- Event ingestion from multiple sources
- Rule compilation (EQL → Wasm/Lua)
- Single-event and sequence detection
- Alert generation and output

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Detection Engine                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Event Processing Pipeline                            │   │
│  │                                                      │   │
│  │  EventBus                                            │   │
│  │    ↓                                                 │   │
│  │  ┌──────────────────────────────────────────────┐   │   │
│  │  │ DetectionEngine::eval_event(event)           │   │   │
│  │  │ ├── NFA Engine (sequence rules)              │   │   │
│  │  │ │   └── CompiledSequence → SequenceMatch     │   │   │
│  │  │ │                                            │   │   │
│  │  │ └── Single-Event Rules                       │   │   │
│  │  │     └── CompiledPredicate → Alert            │   │   │
│  │  └──────────────────────────────────────────────┘   │   │
│  │    ↓                                                 │   │
│  │  AlertOutput                                         │   │
│  │                                                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Rule Lifecycle:                                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ RuleManager                                          │   │
│  │   ↓ load_all()                                       │   │
│  │  ┌──────────────────────────────────────────────┐   │   │
│  │  │ DetectionEngine::compile_rules()             │   │   │
│  │  │ ├── EQL → IR → Wasm (single-event)           │   │   │
│  │  │ └── EQL → IR → CompiledSequence (NFA)        │   │    └ │
│  │──────────────────────────────────────────────┘   │   │
│  │   ↓ store                                           │   │
│  │  ┌──────────────────────────────────────────────┐   │   │
│  │  │ single_event_rules: Vec<SingleEventRule>     │   │   │
│  │  │ nfa_engine.load_sequence(CompiledSequence)   │   │   │
│  │  └──────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Core Types

### DetectionEngine
```rust
pub struct DetectionEngine {
    _event_bus: EventBus,
    _alert_output: AlertOutput,
    rule_manager: Arc<RuleManager>,
    schema: Arc<SchemaRegistry>,
    
    #[cfg(feature = "wasm")]
    wasm_engine: Option<Arc<WasmEngine>>,
    
    #[cfg(feature = "wasm")]
    eql_compiler: std::sync::Mutex<Option<EqlCompiler>>,
    
    nfa_engine: Option<NfaEngine>,
    
    single_event_rules: Arc<tokio::sync::RwLock<Vec<SingleEventRule>>>,
    
    alerts_generated: Arc<std::sync::atomic::AtomicU64>,
}
```

### SingleEventRule
```rust
pub struct SingleEventRule {
    pub rule_id: String,
    pub rule_name: String,
    pub event_type: u16,
    pub severity: Severity,
    pub description: Option<String>,
    pub predicate: CompiledPredicate,
}

#[derive(Debug, Clone)]
pub enum CompiledPredicate {
    #[cfg(feature = "wasm")]
    Wasm {
        wasm_bytes: Vec<u8>,
        required_fields: Vec<u32>,
    },
    #[cfg(feature = "lua")]
    Lua {
        script: String,
        required_fields: Vec<u32>,
    },
    AlwaysMatch,
}
```

## Core Interfaces

```rust
impl DetectionEngine {
    pub async fn new(config: EngineConfig) -> Result<Self, EngineError>;
    
    pub fn rule_manager(&self) -> &Arc<RuleManager>;
    
    pub async fn compile_single_event_rule(&self, rule: &Rule) 
        -> Result<(), EngineError>;
    
    pub async fn compile_rules(&self) -> Result<(), EngineError>;
    
    pub async fn eval_event(&mut self, event: &Event) 
        -> Result<Vec<Alert>, EngineError>;
    
    pub async fn stats(&self) -> EngineStats;
    
    pub fn load_sequence(&mut self, sequence: CompiledSequence) 
        -> Result<(), EngineError>;
}
```

### EngineConfig
```rust
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub event_bus: EventBusConfig,
    pub alert_output: AlertOutputConfig,
    pub rules_dir: std::path::PathBuf,
    
    #[cfg(feature = "wasm")]
    pub wasm_config: Option<WasmConfig>,
    
    pub nfa_config: Option<NfaEngineConfig>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            event_bus: EventBusConfig::default(),
            alert_output: AlertOutputConfig::default(),
            rules_dir: std::path::PathBuf::from("./rules"),
            #[cfg(feature = "wasm")]
            wasm_config: None,
            nfa_config: Some(NfaEngineConfig::default()),
        }
    }
}
```

## Usage Example

```rust
use kestrel_engine::{DetectionEngine, EngineConfig};
use kestrel_event::{Event, TypedValue};
use kestrel_core::{EventBusConfig, AlertOutputConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create engine
    let config = EngineConfig {
        rules_dir: std::path::PathBuf::from("./rules"),
        ..Default::default()
    };
    let mut engine = DetectionEngine::new(config).await?;
    
    // Compile rules
    engine.compile_rules().await?;
    
    // Get stats
    let stats = engine.stats().await;
    println!("Rules loaded: {}", stats.rule_count);
    println!("Single-event rules: {}", stats.single_event_rule_count);
    
    // Create event
    let event = Event::builder()
        .event_type(1)  // exec event
        .ts_mono(1_000_000_000)
        .ts_wall(1_000_000_000)
        .entity_key(0x123)
        .field(1, TypedValue::String("/bin/bash".into()))
        .field(2, TypedValue::I64(1234))
        .build()
        .unwrap();
    
    // Evaluate
    let alerts = engine.eval_event(&event).await?;
    
    for alert in alerts {
        println!("ALERT: {} - {}", alert.rule_id, alert.title);
    }
    
    Ok(())
}
```

## Alert Structure

```rust
pub struct Alert {
    pub id: String,                    // Unique alert ID
    pub rule_id: String,               // Rule that triggered
    pub rule_name: String,
    pub severity: Severity,            // Informational/Low/Medium/High/Critical
    pub title: String,
    pub description: Option<String>,
    pub timestamp_ns: u64,
    pub events: Vec<EventEvidence>,    // Matching events
    pub context: serde_json::Value,    // Additional context
}

pub struct EventEvidence {
    pub event_type_id: u16,
    pub timestamp_ns: u64,
    pub fields: Vec<(FieldId, TypedValue)>,
}
```

## Rule Flow

```
Rule File (JSON/YAML)
        ↓
    RuleManager::load_all()
        ↓
    DetectionEngine::compile_rules()
        ├─→ EqlCompiler::compile_to_ir()
        │       ↓
        │   IrRule { predicates, rule_type }
        │       ↓
        ├─→ EqlCompiler::compile_to_wasm()  [single-event]
        │   → WasmEngine::compile_rule()
        │       ↓
        │   single_event_rules.push()
        │
        └─→ CompiledSequence  [sequence]
            → nfa_engine.load_sequence()
                ↓
            EventBus::subscribe()
                ↓
            DetectionEngine::eval_event()
                ↓
            AlertOutput::emit()
```

## Planned Evolution

### v0.8 (Current)
- [x] Single-event rule evaluation
- [x] Sequence rule evaluation (NFA)
- [x] Rule compilation (EQL → Wasm)
- [x] Alert generation
- [x] Stats tracking

### v0.9
- [ ] Rule dependencies
- [ ] Composite rules
- [ ] Alert correlation
- [ ] Performance tuning

### v1.0
- [ ] Distributed detection
- [ ] Real-time blocking
- [ ] Rule versioning
- [ ] Performance profiling

## Test Coverage

```bash
cargo test -p kestrel-engine --lib

# Engine Tests
test_engine_create                          # Engine initialization
test_stats_includes_single_event_rules      # Stats include rules
test_single_event_rule_always_match         # AlwaysMatch predicate
test_single_event_rule_eval_always_match    # Alert generation
test_single_event_rule_no_match_different_event_type  # Type filtering
test_eval_event_multiple_single_event_rules # Multiple rule matching
```

## Dependencies

```
kestrel-engine
├── kestrel-schema (type definitions)
├── kestrel-event (Event struct)
├── kestrel-core (EventBus, AlertOutput, TimeManager)
├── kestrel-rules (RuleManager)
├── kestrel-nfa (NfaEngine, PredicateEvaluator)
├── kestrel-eql (EqlCompiler, IrRule)
├── kestrel-runtime-wasm (WasmEngine, optional)
├── kestrel-runtime-lua (LuaEngine, optional)
├── tokio (async runtime)
└── wat (WAT → Wasm conversion)
```

## Performance

| Operation | Target | Notes |
|-----------|--------|-------|
| Event eval | <10μs | P99 including NFA |
| Single-event rule | <1μs | Wasm predicate |
| Alert generation | <100μs | |
| Rule compilation | ~5ms | Per rule |
| Memory per rule | ~1KB | Wasm bytecode |
