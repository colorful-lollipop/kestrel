# Kestrel API Documentation

This page provides an overview of the Kestrel APIs and links to detailed documentation.

## Table of Contents

- [Core APIs](#core-apis)
- [Library APIs](#library-apis)
- [Host API](#host-api)
- [Command Line Interface](#command-line-interface)
- [Configuration](#configuration)

## Core APIs

### Detection Engine

The main detection engine API for evaluating events and generating alerts.

**Module**: `kestrel-engine`

**Example**:
```rust
use kestrel_engine::{DetectionEngine, EngineConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = EngineConfig::default();
    let mut engine = DetectionEngine::new(config).await?;

    // Load rules
    engine.load_rules_from_dir("/path/to/rules").await?;

    // Evaluate event
    let event = create_test_event();
    let alerts = engine.eval_event(event).await?;

    for alert in alerts {
        println!("Alert: {}", alert.rule_name);
    }

    Ok(())
}
```

**Key Types**:
- `DetectionEngine` - Main engine
- `EngineConfig` - Engine configuration
- `SingleEventRule` - Single event rule
- `CompiledSequence` - Compiled sequence rule

**Documentation**: [rustdoc](https://kestrel-detection.github.io/kestrel/kestrel_engine/index.html)

---

### EventBus

Multi-partition event bus for parallel event processing.

**Module**: `kestrel-core::eventbus`

**Example**:
```rust
use kestrel_core::{EventBus, EventBusConfig, EventBusHandle};
use kestrel_event::Event;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = EventBusConfig {
        partitions: 4,
        channel_size: 10000,
        batch_size: 100,
        ..Default::default()
    };

    let bus = EventBus::new(config);
    let handle = bus.handle();

    // Subscribe to events
    let mut rx = handle.subscribe();
    tokio::spawn(async move {
        while let Ok(batch) = rx.recv().await {
            for event in batch {
                process_event(event);
            }
        }
    });

    // Publish events
    let event = Event::builder()
        .event_type(1001)
        .ts_mono(1234567890)
        .build();

    handle.publish(event).await?;

    Ok(())
}
```

**Key Types**:
- `EventBus` - Event bus
- `EventBusConfig` - Configuration
- `EventBusHandle` - Publishing handle
- `EventBusMetrics` - Metrics

---

### NFA Engine

Host-executed NFA for sequence detection.

**Module**: `kestrel-nfa`

**Example**:
```rust
use kestrel_nfa::{NfaEngine, NfaSequence, SeqStep};

let mut engine = NfaEngine::new();

let sequence = NfaSequence {
    id: "seq-1".to_string(),
    steps: vec![
        SeqStep {
            state_id: 0,
            event_type_id: 1001,
            predicate: None,
        },
        SeqStep {
            state_id: 1,
            event_type_id: 1002,
            predicate: None,
        },
    ],
    maxspan_ns: 5_000_000_000, // 5 seconds
    until: None,
};

engine.load_sequence(sequence)?;

// Process events
let event = create_event(1001);
let alerts = engine.process_event(event)?;
```

**Key Types**:
- `NfaEngine` - NFA engine
- `NfaSequence` - Compiled sequence
- `SeqStep` - Sequence step
- `PartialMatch` - In-progress match

---

## Library APIs

### Event Schema

Strongly-typed event schema system.

**Module**: `kestrel-schema`

**Example**:
```rust
use kestrel_schema::{SchemaRegistry, FieldType};

let registry = SchemaRegistry::new();

// Register event type
registry.register_event_type("process", 1001)?;

// Register fields
registry.register_field("process.executable", FieldType::String)?;
registry.register_field("process.pid", FieldType::U64)?;

// Get field ID
let field_id = registry.get_field_id("process.executable")?;
```

**Key Types**:
- `SchemaRegistry` - Schema registry
- `FieldType` - Field type enum
- `EventDescriptor` - Event type descriptor

---

### Event Model

Event representation and builder.

**Module**: `kestrel-event`

**Example**:
```rust
use kestrel_event::{Event, TypedValue};

let event = Event::builder()
    .event_type(1001)
    .ts_mono(1234567890)
    .ts_wall(1234567890)
    .entity_key(0x1234)
    .field("process.executable", TypedValue::String("/bin/bash".to_string()))
    .field("process.pid", TypedValue::U64(1234))
    .build()?;
```

**Key Types**:
- `Event` - Event struct
- `EventBuilder` - Builder pattern
- `TypedValue` - Typed value enum

---

### Rule Manager

Rule loading and management.

**Module**: `kestrel-rules`

**Example**:
```rust
use kestrel_rules::{RuleManager, RulePackage};

let manager = RuleManager::new();

// Load rule package
let package = RulePackage::from_dir("/path/to/rule")?;
manager.load_package(package)?;

// Get loaded rules
let rules = manager.get_rules();
```

**Key Types**:
- `RuleManager` - Rule manager
- `RulePackage` - Rule package
- `RuleMetadata` - Rule metadata

---

## Host API

The Host API provides functions for Wasm and Lua predicates to interact with the engine.

### Event Access

```c
// C/Wasm signature
const char *event_get_str(event_handle, field_id);
int64_t event_get_i64(event_handle, field_id);
uint64_t event_get_u64(event_handle, field_id);
bool event_get_bool(event_handle, field_id);
```

```lua
-- Lua
local str = kestrel.event_get_str(event_handle, field_id)
local num = kestrel.event_get_i64(event_handle, field_id)
```

### Pattern Matching

```c
bool re_match(re_id, const char *str);
bool glob_match(glob_id, const char *str);
```

```lua
local matched = kestrel.re_match(re_id, str)
local matched = kestrel.glob_match(glob_id, pattern)
```

### Alert Emission

```c
void alert_emit(const char *alert_json);
```

```lua
kestrel.alert_emit(alert_json)
```

### Full Reference

See:
- [Wasm Rule Package Guide](../examples/wasm_rule_package.md)
- [Lua Rule Package Guide](../examples/lua_rule_package.md)

---

## Command Line Interface

### Commands

```bash
# Run detection engine
kestrel run [OPTIONS]

# Validate rules
kestrel validate --rules <PATH>

# List loaded rules
kestrel list --rules <PATH>

# Test with event
kestrel test --rules <PATH> --event <FILE>

# Show schema
kestrel schema [--show event_types|fields]

# Version info
kestrel --version
```

### Global Options

```
--log-level <LEVEL>    trace, debug, info, warn, error
--config <PATH>        Configuration file (TOML)
-v, --verbose          Increase verbosity
-q, --quiet            Decrease verbosity
```

### Run Command

```
kestrel run [OPTIONS]

OPTIONS:
  --rules <PATH>           Rules directory
  --mode <MODE>            detect, enforce, offline
  --event-sources <LIST>   ebpf,audit,socket
  --workers <NUM>          Worker threads
  --max-memory <MB>        Memory limit
  --output <TYPE>          stdout,file,syslog
```

---

## Configuration

### Config File Structure (TOML)

```toml
[general]
log_level = "info"
mode = "detect"
workers = 4
max_memory_mb = 2048

[engine]
event_bus_partitions = 4
channel_size = 10000
batch_size = 100

[ebpf]
enabled = true
program_path = "/opt/kestrel/bpf"
ringbuf_size = 4096

[wasm]
enabled = true
memory_limit_mb = 16
fuel_limit = 1000000
instance_pool_size = 10

[lua]
enabled = true
jit_enabled = true
memory_limit_mb = 16

[alerts]
output = ["stdout", "file"]
file_path = "/var/log/kestrel/alerts.json"
file_rotation = "daily"

[performance]
enable_profiling = false
metrics_port = 9090
```

### Environment Variables

```bash
# Override config file location
export KESTREL_CONFIG=/path/to/config.toml

# Override log level
export KESTREL_LOG_LEVEL=debug

# Override rules directory
export KESTREL_RULES=/path/to/rules
```

---

## Generated Documentation

Full API documentation is generated by rustdoc and available at:

**Online**: https://kestrel-detection.github.io/kestrel/

**Local Generation**:
```bash
# Generate docs
cargo doc --workspace --no-deps --all-features

# Open in browser
cargo doc --workspace --no-deps --all-features --open
```

### Crate Documentation

| Crate | Description | Link |
|-------|-------------|------|
| `kestrel-core` | Core types and EventBus | [docs](kestrel_core/index.html) |
| `kestrel-schema` | Event schema system | [docs](kestrel_schema/index.html) |
| `kestrel-event` | Event model | [docs](kestrel_event/index.html) |
| `kestrel-rules` | Rule management | [docs](kestrel_rules/index.html) |
| `kestrel-engine` | Detection engine | [docs](kestrel_engine/index.html) |
| `kestrel-nfa` | NFA sequence engine | [docs](kestrel_nfa/index.html) |
| `kestrel-eql` | EQL compiler | [docs](kestrel_eql/index.html) |
| `kestrel-runtime-wasm` | Wasm runtime | [docs](kestrel_runtime_wasm/index.html) |
| `kestrel-runtime-lua` | Lua runtime | [docs](kestrel_runtime_lua/index.html) |
| `kestrel-ebpf` | eBPF collection | [docs](kestrel_ebpf/index.html) |

---

## Examples

### Creating a Custom Event Source

```rust
use kestrel_core::EventBusHandle;
use kestrel_event::Event;

struct MyEventSource {
    handle: EventBusHandle,
}

impl MyEventSource {
    async fn run(&self) -> Result<(), Error> {
        loop {
            // Collect event from source
            let event = collect_event().await?;

            // Publish to bus
            self.handle.publish(event).await?;

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
```

### Writing a Custom Predicate

```wat
;; example.wat
(module
  (import "kestrel" "event_get_str"
    (func $event_get_str (param i64 i32) (result i32)))
  (import "kestrel" "alert_emit"
    (func $alert_emit (param i32 i32)))

  (memory (export "memory") 1)

  (func (export "pred_eval") (param i64 i32) (result i32)
    (local.get 0)
    (i64.const 1)  ;; field_id
    (call $event_get_str)
    (memory.size)
    (i32.const 100)
    (i32.mul)
    (call $check_suspicious)  ;; custom function
    (if (then
      (i32.const 0)
      (i32.const 1024)
      (call $alert_emit)
    ))
    (i32.const 1))  ;; return true
)
```

### Adding a Custom Action

```rust
use kestrel_core::Action;

pub struct CustomAction {
    name: String,
}

impl Action for CustomAction {
    fn execute(&self, context: &ActionContext) -> Result<ActionResult> {
        // Custom logic here
        println!("Executing custom action: {}", self.name);

        Ok(ActionResult {
            success: true,
            message: "Custom action executed".to_string(),
        })
    }
}
```

---

**Last Updated**: 2025-01-12
