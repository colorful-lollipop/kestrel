# Lua Example Rule

This directory contains an example Lua predicate for Kestrel.

## Rule Description

**Rule ID:** `lua-example-001`
**Name:** Lua Example Rule - High PID Detection
**Description:** Example Lua rule that demonstrates the predicate ABI (matches all events for demo purposes)

## Lua Predicate ABI

All Lua predicates must implement the following functions:

### pred_init()
Initialize the predicate (called once when the rule is loaded).

**Returns:** `number` - 0 for success, < 0 for error

```lua
function pred_init()
    -- Initialize rule state
    return 0  -- Success
end
```

### pred_eval(event)
Evaluate an event (called for each event).

**Parameters:**
- `event` - Event to evaluate

**Returns:** `boolean` - true if match, false otherwise

```lua
function pred_eval(event)
    -- Get field value
    local pid = kestrel.event_get_i64(event, 1)

    -- Check condition
    if pid > 1000 then
        return true  -- Match
    end

    return false  -- No match
end
```

### pred_capture(event) (Optional)
Capture fields from a matching event for alert generation.

**Parameters:**
- `event` - Event that matched

**Returns:** `table` - Table with captured fields

```lua
function pred_capture(event)
    return {
        pid = kestrel.event_get_i64(event, 1),
        name = kestrel.event_get_str(event, 2)
    }
end
```

## Host API v1 Functions

Kestrel provides the following functions via the `kestrel` module:

### Event Field Reading

#### kestrel.event_get_i64(event, field_id) -> number
Get a signed 64-bit integer field value.

**Parameters:**
- `event` - Event object
- `field_id` - Field identifier (number)

**Returns:** `number` - Field value or 0 if not found

#### kestrel.event_get_u64(event, field_id) -> number
Get an unsigned 64-bit integer field value.

**Parameters:**
- `event` - Event object
- `field_id` - Field identifier (number)

**Returns:** `number` - Field value or 0 if not found

#### kestrel.event_get_str(event, field_id) -> string
Get a string field value.

**Parameters:**
- `event` - Event object
- `field_id` - Field identifier (number)

**Returns:** `string` - Field value or empty string if not found

### Pattern Matching

#### kestrel.re_match(re_id, text) -> boolean
Test if a string matches a pre-registered regex pattern.

**Parameters:**
- `re_id` - Regex pattern identifier (number)
- `text` - String to test

**Returns:** `boolean` - true if match, false otherwise

#### kestrel.glob_match(glob_id, text) -> boolean
Test if a string matches a pre-registered glob pattern.

**Parameters:**
- `glob_id` - Glob pattern identifier (number)
- `text` - String to test

**Returns:** `boolean` - true if match, false otherwise

### Alert Emission

#### kestrel.alert_emit(event) -> number
Emit an alert for the current event.

**Parameters:**
- `event` - Event object

**Returns:** `number` - 0 on success, < 0 on error

## Usage Example

### Loading a Lua Rule

```rust
use kestrel_runtime_lua::{LuaEngine, LuaConfig, RuleManifest};
use std::sync::Arc;

// Create engine
let config = LuaConfig::default();
let schema = Arc::new(kestrel_schema::SchemaRegistry::new());
let engine = LuaEngine::new(config, schema)?;

// Register Host API
engine.register_host_api()?;

// Load manifest
let manifest_json = std::fs::read_to_string("manifest.json")?;
let manifest: RuleManifest = serde_json::from_str(&manifest_json)?;

// Load Lua script
let script = std::fs::read_to_string("predicate.lua")?;

// Load predicate
engine.load_predicate(manifest, script).await?;

// Evaluate events
let event = create_test_event();
let result = engine.eval("lua-example-001", &event).await?;

if result.matched {
    println!("Rule matched event!");
}
```

## Advanced Example: Multiple Conditions

```lua
function pred_init()
    -- Register regex patterns
    -- This will be automated in the future
    return 0
end

function pred_eval(event)
    -- Get process name (field_id = 2)
    local name = kestrel.event_get_str(event, 2)

    -- Get PID (field_id = 1)
    local pid = kestrel.event_get_i64(event, 1)

    -- Match conditions:
    -- 1. Process name contains "suspicious"
    -- 2. PID > 1000 (user process)
    -- 3. Uses regex/glob patterns

    if string.find(name, "suspicious") and pid > 1000 then
        -- Emit alert
        kestrel.alert_emit(event)
        return true
    end

    return false
end
```

## Advanced Example: Regex Matching

```lua
function pred_init()
    return 0
end

function pred_eval(event)
    -- Get command line
    local cmd = kestrel.event_get_str(event, 3)

    -- Check if matches suspicious pattern
    -- (Assuming regex_id 1 was pre-registered)
    if kestrel.re_match(1, cmd) then
        kestrel.alert_emit(event)
        return true
    end

    return false
end
```

## Performance Tips

1. **Use LuaJIT JIT Compilation** - Enabled by default for best performance
2. **Avoid String Operations in Hot Paths** - String matching is slower than numeric
3. **Cache Values** - Store frequently accessed values in local variables
4. **Use Early Returns** - Return as soon as you know the result
5. **Keep Predicates Simple** - Complex logic is better in the Host NFA engine

## Debugging

Enable debug logging:
```rust
use tracing::Level;

tracing_subscriber::fmt()
    .with_max_level(Level::DEBUG)
    .init();
```

Add debug prints in Lua (for development):
```lua
function pred_eval(event)
    local pid = kestrel.event_get_i64(event, 1)
    print("Debug: PID = " .. pid)  -- Will appear in stdout
    return pid > 1000
end
```

## Testing

Create a simple test:
```rust
#[tokio::test]
async fn test_lua_predicate() {
    let engine = create_test_engine();

    let script = std::fs::read_to_string("predicate.lua").unwrap();
    let manifest = create_test_manifest();

    engine.load_predicate(manifest, script).await.unwrap();

    let event = create_test_event();
    let result = engine.eval("lua-example-001", &event).await.unwrap();

    assert!(result.matched);
}
```

## Differences from Wasm

### Advantages of Lua
- **Faster Development**: No compilation step, just edit and reload
- **Dynamic Typing**: Easier to write complex logic
- **Built-in String Operations**: String manipulation is native
- **Larger Ecosystem**: Many Lua libraries available

### Disadvantages of Lua
- **Less Type Safety**: Runtime type errors possible
- **Sandboxing**: Lua sandbox is lighter than Wasm
- **Startup Time**: LuaJIT JIT compilation adds overhead
- **Portability**: Wasm is more portable across platforms

### Performance Comparison

Target performance (per event evaluation):
- **Wasm**: <1μs (compiled, with pooling)
- **LuaJIT**: ~1-2μs (JIT compiled)
- **Lua Interpreter**: ~10-50μs (JIT disabled, cold start)

For most use cases, both runtimes are fast enough. Choose based on:
- **Development Speed**: Lua for rapid iteration
- **Production Stability**: Wasm for compiled, verified rules
- **Team Expertise**: Use what your team knows best

## Next Steps

- Create more complex predicates with multiple conditions
- Use regex and glob matching for string fields
- Implement field capture for rich alerts
- Compare performance with Wasm equivalent
- Contribute to Host API improvements

## Resources

- [Lua Reference Manual](https://www.lua.org/manual/5.1/)
- [LuaJIT Documentation](https://luajit.org/extensions.html)
- [mlua Documentation](https://docs.rs/mlua/)
- [Kestrel Host API v1](../../examples/wasm_rule_package.md)
- [Wasm vs Lua Comparison](../../PROGRESS.md)
