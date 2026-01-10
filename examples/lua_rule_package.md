# Lua Rule Package Guide

## Overview

Kestrel supports LuaJIT as a runtime for detection predicates, alongside Wasm. Lua rules provide a dynamic, flexible development experience with good runtime performance through JIT compilation.

## Package Structure

```
my-lua-rule/
├── manifest.json       # Rule metadata (same format as Wasm)
└── predicate.lua       # Lua predicate script
```

## Predicate ABI

### Required Functions

#### pred_init() -> number
Initialize the predicate. Called once when the rule is loaded.

```lua
function pred_init()
    -- Initialize rule state
    return 0  -- Success
end
```

#### pred_eval(event) -> boolean
Evaluate an event. Called for each event.

```lua
function pred_eval(event)
    local pid = kestrel.event_get_i64(event, 1)
    return pid > 1000
end
```

### Optional Functions

#### pred_capture(event) -> table
Capture fields from matching event for alert generation.

```lua
function pred_capture(event)
    return {
        pid = kestrel.event_get_i64(event, 1),
        name = kestrel.event_get_str(event, 2)
    }
end
```

## Host API v1

All Host API functions are accessed via the `kestrel` module:

### Event Field Reading

```lua
local value_i64 = kestrel.event_get_i64(event, field_id)
local value_u64 = kestrel.event_get_u64(event, field_id)
local value_str = kestrel.event_get_str(event, field_id)
```

### Pattern Matching

```lua
local matches = kestrel.re_match(re_id, text)
local matches = kestrel.glob_match(glob_id, text)
```

### Alert Emission

```lua
kestrel.alert_emit(event)
```

## Example: Complete Rule

```lua
-- pred_init
function pred_init()
    return 0
end

-- pred_eval
function pred_eval(event)
    -- Get process PID
    local pid = kestrel.event_get_i64(event, 1)

    -- Get process name
    local name = kestrel.event_get_str(event, 2)

    -- Check conditions
    if pid > 1000 and string.find(name, "suspicious") then
        kestrel.alert_emit(event)
        return true
    end

    return false
end

-- pred_capture (optional)
function pred_capture(event)
    return {
        pid = kestrel.event_get_i64(event, 1),
        name = kestrel.event_get_str(event, 2)
    }
end
```

## Comparison with Wasm

| Feature | LuaJIT | Wasm |
|---------|--------|------|
| **Development Speed** | Fast (no compilation) | Slower (compile step) |
| **Performance** | ~1-2μs | <1μs |
| **Type Safety** | Dynamic (runtime checks) | Static (compile-time) |
| **Startup Time** | ~10-100ms (JIT warmup) | ~1-10ms (AOT cache) |
| **Sandboxing** | Light sandbox | Strong isolation |
| **Portability** | LuaJIT required | Any Wasm runtime |
| **String Operations** | Native | Requires hostcall |
| **Memory Model** | Automatic GC | Manual linear memory |

## When to Use Lua

- **Rapid Prototyping**: Quick iteration without compilation
- **Complex String Logic**: Native string operations
- **Team Expertise**: Team familiar with Lua
- **Trusted Rules**: Internal rules where sandboxing is less critical

## When to Use Wasm

- **Production Rules**: Compiled, verified rulesets
- **Maximum Performance**: Critical detection paths
- **Third-Party Rules**: Untrusted rules requiring strong sandboxing
- **Portability**: Rules that must run everywhere

## Loading Lua Rules

```rust
use kestrel_runtime_lua::{LuaEngine, LuaConfig, RuleManifest};

// Create engine
let config = LuaConfig::default();
let engine = LuaEngine::new(config, schema)?;

// Register Host API
engine.register_host_api()?;

// Load rule
let manifest = serde_json::from_str::<RuleManifest>(
    &std::fs::read_to_string("manifest.json")?
)?;
let script = std::fs::read_to_string("predicate.lua")?;

engine.load_predicate(manifest, script).await?;

// Evaluate
let result = engine.eval(rule_id, &event).await?;
```

## Performance Optimization

1. **Enable JIT**: Default enabled for best performance
2. **Avoid Hot String Operations**: Cache string results
3. **Use Local Variables**: `local` is faster than globals
4. **Early Returns**: Return as soon as result is known
5. **Minimize Host Calls**: Each call has overhead

## Best Practices

1. **Keep Predicates Simple**: Move complex logic to Host NFA (Phase 4)
2. **Use Numeric Comparisons**: Faster than string matching
3. **Return Early**: Avoid unnecessary computation
4. **Document Field IDs**: Comments explaining field_id usage
5. **Test Both Runtimes**: Verify Wasm and Lua give same results

## Debugging

Enable Lua debug prints:
```lua
function pred_eval(event)
    local pid = kestrel.event_get_i64(event, 1)
    print("Debug: PID = " .. pid)  -- Prints to stdout
    return pid > 1000
end
```

Enable Rust tracing:
```rust
tracing_subscriber::fmt()
    .with_max_level(tracing::Level::DEBUG)
    .init();
```

## Migration: Wasm to Lua

### Wasm (WAT)
```wat
(func (export "pred_eval") (param $event_handle i32) (result i32)
  (call $event_get_i64 (local.get $event_handle) (i32.const 1))
  (i64.const 1000)
  (i64.gt_u)
  (if (result i32)
    (then (i32.const 1))
    (else (i32.const 0))
  )
)
```

### Lua (Equivalent)
```lua
function pred_eval(event)
    local pid = kestrel.event_get_i64(event, 1)
    return pid > 1000
end
```

## Migration: Lua to Wasm

### Lua
```lua
function pred_eval(event)
    local name = kestrel.event_get_str(event, 2)
    return string.find(name, "sus") ~= nil
end
```

### Wasm (WAT) - Requires Host API for string operations
```wat
;; More complex, requires memory management
;; Use Wasm for production, Lua for development
```

## Next Steps

- See `rules/lua_example_rule/` for complete example
- Read `PROGRESS.md` for implementation status
- Check `plan.md` for EQL compiler roadmap (Phase 3)
- Compare with Wasm example at `rules/wasm_example_rule/`

## Dual Runtime Strategy

Kestrel supports both runtimes simultaneously:

1. **Development Phase**: Write rules in Lua for quick iteration
2. **Validation Phase**: Test rules thoroughly with Lua
3. **Production Phase**: Compile to Wasm for performance and security
4. **Runtime Choice**: Use either runtime based on needs

Both runtimes implement the **same Predicate ABI** and **same Host API v1**, ensuring consistent behavior.
