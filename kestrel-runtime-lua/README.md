# Kestrel Lua Runtime

**Runtime Layer - LuaJIT Predicate Evaluation Engine**

## Module Goal

Execute predicates using Lua/LuaJIT scripting:
- Alternative to Wasm for complex predicates
- FFI integration with native libraries
- High-performance JIT compilation
- Lua ecosystem integration

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Lua Runtime Engine                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ LuaEngine                                            │   │
│  │ ├── lua: Arc<Lua>                                   │   │
│  │ ├── config: LuaConfig                               │   │
│  │ └── schema: Arc<SchemaRegistry>                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Lua Context                                          │   │
│  │ ├── event: LuaUserData<EventContext>               │   │
│  │ ├── schema: LuaUserData<SchemaContext>             │   │
│  │ └── alerts: LuaTable                                │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Lua Functions (available to scripts)                │   │
│  │ ├── event.get_i64(field_id) → number               │   │
│  │ ├── event.get_str(field_id) → string               │   │
│  │ ├── event.has_field(field_id) → boolean            │   │
│  │ ├── string.contains(s, pattern) → boolean          │   │
│  │ ├── string.startswith(s, prefix) → boolean         │   │
│  │ ├── string.endswith(s, suffix) → boolean           │   │
│  │ ├── string.glob_match(s, pattern) → boolean        │   │
│  │ ├── regex.match(pattern, text) → boolean           │   │
│  │ └── alert.emit(rule_id, message)                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Core Interfaces

### LuaEngine
```rust
pub struct LuaEngine {
    lua: Arc<Lua>,
    config: LuaConfig,
    schema: Arc<SchemaRegistry>,
}

impl LuaEngine {
    pub fn new(config: LuaConfig, schema: Arc<SchemaRegistry>) -> Result<Self, LuaRuntimeError>;
    
    pub async fn evaluate(&self, script: &str, event: &Event) 
        -> Result<bool, LuaRuntimeError>;
    
    pub async fn evaluate_rule(&self, rule_id: &str, event: &Event)
        -> Result<bool, LuaRuntimeError>;
}
```

### LuaConfig
```derive(Debug, Clone)]
pub struct LuaConfig {
    pub memory_limit_kb: usize,      // Default: 1024
    pub instruction_limit: usize,    // Default: 1_000_000
    pub enable_ffi: bool,            // Default: false
    pub enable_jit: bool,            // Default: true
}
```

## Lua Script Format

```lua
-- Simple predicate
return function(event)
    local exe = event:get_str(1)  -- field_id 1 = executable
    if not exe then
        return false
    end
    
    -- Check for suspicious binary
    return string.contains(exe, "/tmp/") or 
           string.endswith(exe, ".sh") and
           not string.startswith(exe, "/bin/")
end
```

### Using the event API

```lua
-- Get field values
local pid = event:get_i64(2)     -- i64 field
local name = event:get_str(3)    -- string field
local flag = event:get_bool(4)   -- bool field

-- Check field existence
if event:has_field(5) then
    local value = event:get_i64(5)
end

-- String operations
if string.contains(name, "evil") then
    return true
end

if string.startswith(name, "/tmp/") then
    return true
end

-- Pattern matching
if regex.match("suspicious.*pattern", name) then
    return true
end

if string.glob_match(name, "*/evil*") then
    return true
end

-- Emit alert
alert.emit("detect-suspicious", "Found suspicious pattern")

return false
```

## Usage Example

```rust
use kestrel_runtime_lua::{LuaEngine, LuaConfig};
use kestrel_event::{Event, TypedValue};
use kestrel_schema::SchemaRegistry;

let schema = Arc::new(SchemaRegistry::new());
let config = LuaConfig::default();
let engine = LuaEngine::new(config, schema).unwrap();

let script = r#"
return function(event)
    local exe = event:get_str(1)
    if exe and (string.contains(exe, "/tmp/") or string.endswith(exe, ".sh")) then
        return true
    end
    return false
end
"#;

let event = Event::builder()
    .event_type(1)
    .ts_mono(1_000_000_000)
    .ts_wall(1_000_000_000)
    .entity_key(0x123)
    .field(1, TypedValue::String("/tmp/malicious.sh".into()))
    .build()
    .unwrap();

let matched = engine.evaluate(script, &event).await.unwrap();
assert!(matched);
```

## Security

### Sandboxing
```rust
// Limit memory usage
let config = LuaConfig {
    memory_limit_kb: 1024,  // 1MB limit
    instruction_limit: 1_000_000,  // Prevent infinite loops
    enable_ffi: false,  // Disable FFI for security
    enable_jit: true,
};

// Unsafe functions are blocked
let result = engine.evaluate("io.popen('rm -rf /')", &event).await;
// Returns error: FFI is disabled
```

## Planned Evolution

### v0.8 (Current)
- [x] Basic Lua execution
- [x] Event API
- [x] String/regex functions
- [x] Sandboxing

### v0.9
- [ ] Lua packages
- [ ] Native modules
- [ ] Debugging tools
- [ ] Hot reload

### v1.0
- [ ] Full Lua 5.4 support
- [ ] Profiling
- [ ] Distributed Lua
- [ ] WASI support

## Test Coverage

```bash
cargo test -p kestrel-runtime-lua --lib

# Engine Tests
test_engine_create            # Engine initialization
test_evaluate_simple          # Basic evaluation
test_evaluate_with_fields     # Field access
test_sandbox_memory_limit     # Memory limits
test_sandbox_instructions     # Instruction limits

# Function Tests
test_string_contains          # Contains function
test_string_starts_with       # StartsWith function
test_regex_match              # Regex matching
test_glob_match               # Glob matching
```

## Dependencies

```
kestrel-runtime-lua
├── kestrel-schema (type definitions)
├── kestrel-event (Event struct)
├── mlua (LuaJIT bindings)
├── regex (regex implementation)
├── glob (glob pattern matching)
├── tokio (async runtime)
└── tracing (logging)
```

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Script init | ~100μs | First execution |
| Script eval | ~500ns | P99 target |
| Field lookup | ~50ns | Per field |
| Memory per script | ~10KB | Compiled bytecode |
