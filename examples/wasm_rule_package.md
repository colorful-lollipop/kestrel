# Wasm Rule Package Format

## Overview

Kestrel rule packages contain Wasm-compiled detection rules with metadata. Each package consists of:

1. **Manifest** (`manifest.json`) - Metadata and capabilities
2. **Wasm Module** (`rule.wasm`) - Compiled predicate logic
3. **Optional Resources** - Regex patterns, glob patterns, etc.

## Package Structure

```
my-rule/
├── manifest.json       # Rule metadata
├── rule.wasm          # Compiled Wasm module
└── resources/         # Optional resources
    ├── regexes.txt    # Pre-registered regex patterns
    └── globs.txt      # Pre-registered glob patterns
```

## Manifest Format

```json
{
  "format_version": "1.0",
  "metadata": {
    "rule_id": "suspicious-process-001",
    "rule_name": "Suspicious Process Execution",
    "rule_version": "1.0.0",
    "author": "Kestrel Team",
    "description": "Detects suspicious process execution patterns",
    "tags": ["process", "execution", "security"],
    "severity": "High",
    "schema_version": "1.0"
  },
  "capabilities": {
    "supports_inline": true,
    "requires_alert": true,
    "requires_block": false,
    "max_span_ms": null
  }
}
```

## Wasm Predicate ABI

All Wasm predicates must implement the following functions:

### pred_init(ctx)
Initialize the predicate (called once when rule is loaded).

**Parameters:** None
**Returns:** `i32` - 0 for success, < 0 for error

```wat
(func (export "pred_init") (result i32)
  (i32.const 0)  ; Return success
)
```

### pred_eval(event_handle, ctx)
Evaluate an event (called for each event).

**Parameters:**
- `event_handle: u32` - Handle to the event being evaluated
- **Context is accessed via host API**

**Returns:** `i32` - 1 for match, 0 for no match, < 0 for error

```wat
(func (export "pred_eval") (param $event_handle i32) (result i32)
  ;; Call host API to get event field
  (call $kestrel_event_get_i64
    (local.get $event_handle)
    (i32.const 1))  ; field_id for process.pid

  ;; Check if pid > 1000
  (i32.gt_u)
  (if (result i32)
    (then (i32.const 1))  ; Match
    (else (i32.const 0))  ; No match
  )
)
```

### pred_capture(event_handle, ctx) (Optional)
Capture fields from a matching event for alert generation.

**Parameters:**
- `event_handle: u32` - Handle to the event being evaluated

**Returns:** `i32` - Pointer to captured data in Wasm memory

## Host API v1 Functions

### Event Field Reading

#### event_get_i64(event_handle: u32, field_id: u32) -> i64
Get a signed 64-bit integer field value.

#### event_get_u64(event_handle: u32, field_id: u32) -> u64
Get an unsigned 64-bit integer field value.

#### event_get_str(event_handle: u32, field_id: u32, ptr: u32, len: u32) -> u32
Get a string field value. Writes to Wasm memory at `ptr` up to `len` bytes. Returns bytes written.

### Pattern Matching

#### re_match(re_id: u32, str_ptr: u32, str_len: u32) -> i32
Test if a string matches a pre-registered regex pattern. Returns 1 if match, 0 otherwise.

#### glob_match(glob_id: u32, str_ptr: u32, str_len: u32) -> i32
Test if a string matches a pre-registered glob pattern. Returns 1 if match, 0 otherwise.

### Alert Emission

#### alert_emit(event_handle: u32) -> i32
Emit an alert for the current event. Returns 0 on success, < 0 on error.

## Example: Minimal Wasm Rule (WAT)

```wat
(module
  ;; Import Host API functions
  (import "kestrel" "event_get_i64" (func $event_get_i64 (param i32 i32) (result i64)))

  ;; pred_init: Initialize the predicate
  (func (export "pred_init") (result i32)
    (i32.const 0)  ; Return success
  )

  ;; pred_eval: Evaluate an event
  (func (export "pred_eval") (param $event_handle i32) (result i32)
    ;; Get process.pid field (assuming field_id = 1)
    (call $event_get_i64
      (local.get $event_handle)
      (i32.const 1))

    ;; Check if pid > 1000 (user process)
    (i64.extend_i32_u)
    (i64.const 1000)
    (i64.gt_u)

    ;; Return 1 if match, 0 otherwise
    (if (result i32)
      (then (i32.const 1))
      (else (i32.const 0))
    )
  )
)
```

## Building Wasm Rules

### Using wat2wasm (WebAssembly Binary Toolkit)

```bash
# Install WABT
# Ubuntu/Debian: sudo apt-get install wabt
# macOS: brew install wabt

# Compile WAT to WASM
wat2wasm rule.wat -o rule.wasm

# Verify the module
wasm-objdump -d rule.wasm
```

### Using Rust

```rust
#![no_std]

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn pred_init() -> i32 {
    0 // Success
}

#[wasm_bindgen]
pub fn pred_eval(event_handle: u32) -> i32 {
    // Evaluation logic here
    0 // No match
}
```

Build with:
```bash
cargo build --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/rule.wasm .
```

### Using C/C++

```c
#include <stdint.h>

int32_t pred_init(void) {
    return 0; // Success
}

int32_t pred_eval(uint32_t event_handle) {
    // Evaluation logic here
    return 0; // No match
}
```

Build with Clang:
```bash
clang --target=wasm32-unknown-unknown -nostartfiles \
      -Wl,--no-entry -Wl,--export=pred_init -Wl,--export=pred_eval \
      -o rule.wasm rule.c
```

## Loading Wasm Rules

```rust
use kestrel_runtime_wasm::{WasmEngine, WasmConfig, RuleManifest};

// Create engine
let config = WasmConfig::default();
let engine = WasmEngine::new(config, schema)?;

// Load rule package
let manifest = serde_json::from_str::<RuleManifest>(
    &std::fs::read_to_string("manifest.json")?
)?;
let wasm_bytes = std::fs::read("rule.wasm")?;

engine.load_module(manifest, wasm_bytes).await?;

// Create predicate
let predicate = engine.create_predicate("suspicious-process-001")?;

// Evaluate events
let result = predicate.eval(&event).await?;
if result.matched {
    println!("Rule matched!");
}
```

## Performance Considerations

1. **Fuel Metering** - Each predicate evaluation has a fuel limit (default: 1M instructions)
2. **Memory Limits** - Each instance limited to 16MB by default
3. **Instance Pooling** - Instances are pooled to avoid repeated compilation overhead
4. **AOT Caching** - Compiled modules are cached for fast loading

## Security Considerations

Wasm rules run in a sandboxed environment with:

- **Memory isolation** - Each instance has isolated memory
- **Resource limits** - Fuel metering prevents infinite loops
- **No direct system access** - All system access goes through Host API
- **Type safety** - Wasm type system prevents memory corruption

## Debugging

Enable debug logging:
```rust
use tracing::Level;

tracing_subscriber::fmt()
    .with_max_level(Level::DEBUG)
    .init();
```

Enable fuel metering to catch performance issues:
```rust
let config = WasmConfig {
    enable_fuel: true,
    fuel_per_eval: 1_000_000,
    ..Default::default()
};
```

## Next Steps

- See `examples/` for complete rule examples
- Read `PROGRESS.md` for implementation status
- Check `plan.md` for EQL compiler roadmap (Phase 3)
