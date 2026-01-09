# Wasm Example Rule

This directory contains an example Wasm rule for Kestrel.

## Rule Description

**Rule ID:** `wasm-example-001`
**Name:** High PID Detection
**Description:** Detects processes with PID > 1000 (user-space processes)

## Building the Rule

### Prerequisites

Install the WebAssembly Binary Toolkit (WABT):

**Ubuntu/Debian:**
```bash
sudo apt-get install wabt
```

**macOS:**
```bash
brew install wabt
```

**From Source:**
```bash
git clone https://github.com/WebAssembly/wabt.git
cd wabt
mkdir build && cd build
cmake ..
make -j
```

### Compile

```bash
cd rules/wasm_example_rule
wat2wasm rule.wat -o rule.wasm
```

### Verify

```bash
# Disassemble to verify
wasm-objdump -d rule.wasm

# Check imports/exports
wasm-objdump -h rule.wasm
```

Expected exports:
- `pred_init` - Initialize function
- `pred_eval` - Evaluation function

Expected imports:
- `kestrel:event_get_i64` - Host API function

## Loading the Rule

### Using Kestrel CLI (Future)

```bash
# Load and validate the rule
kestrel load-rule rules/wasm_example_rule

# Run detection with the rule
kestrel run --rules rules/wasm_example_rule
```

### Programmatically

```rust
use kestrel_runtime_wasm::{WasmEngine, WasmConfig, RuleManifest};

// Create engine
let config = WasmConfig::default();
let schema = std::sync::Arc::new(kestrel_schema::SchemaRegistry::new());
let engine = WasmEngine::new(config, schema)?;

// Load manifest
let manifest_json = std::fs::read_to_string("manifest.json")?;
let manifest: RuleManifest = serde_json::from_str(&manifest_json)?;

// Load Wasm module
let wasm_bytes = std::fs::read("rule.wasm")?;
engine.load_module(manifest, wasm_bytes).await?;

// Create predicate
let predicate = engine.create_predicate("wasm-example-001")?;

// Evaluate events
for event in events {
    let result = predicate.eval(&event).await?;
    if result.matched {
        println!("Rule matched event!");
    }
}
```

## Testing

Create a simple test event:

```rust
use kestrel_event::{Event, EventBuilder};
use kestrel_schema::{FieldId, TypedValue};

let mut builder = EventBuilder::new();
builder.set_event_type_id(1); // process event type
builder.set_field(1, TypedValue::I64(1234)); // PID = 1234

let event = builder.build();
let result = predicate.eval(&event).await?;

assert!(result.matched); // Should match (1234 > 1000)
```

## Rule Logic

This rule demonstrates the basic Wasm predicate structure:

1. **pred_init**: Returns success (0)
2. **pred_eval**:
   - Gets the `process.pid` field (field_id = 1)
   - Compares it to threshold (1000)
   - Returns 1 (match) if PID > 1000
   - Returns 0 (no match) otherwise

## Extending the Rule

### Add More Fields

```wat
;; Get multiple fields
(call $event_get_i64
  (local.get $event_handle)
  (i32.const 2))  ; Get field_id 2

;; Add more logic
(i32.add)
```

### Use Regex Matching

```wat
(import "kestrel" "re_match" (func $re_match (param i32 i32 i32) (result i32)))

;; In pred_eval:
(call $re_match
  (i32.const 1)  ; regex_id
  (i32.const 0)  ; string pointer
  (i32.const 10))  ; string length
```

### Emit Alerts

```wat
(import "kestrel" "alert_emit" (func $alert_emit (param i32) (result i32)))

;; In pred_eval, when match detected:
(if (i32.gt_u)
  (then
    (call $alert_emit (local.get $event_handle))
    (i32.const 1)  ; Return match
  )
  (else
    (i32.const 0)  ; No match
  )
)
```

## Performance

Expected performance:
- **Compilation:** ~1-10ms (first time)
- **Instantiation:** <1ms (from cache)
- **Evaluation:** <1μs per event (with instance pooling)

Memory usage:
- **Module size:** ~200 bytes
- **Instance memory:** 1 page (64KB)
- **Overhead:** Minimal with pooling

## Troubleshooting

### "Failed to compile Wasm module"

Check that the Wasm file is valid:
```bash
wasm-validate rule.wasm
```

### "Function not found: pred_eval"

Verify exports:
```bash
wasm-objdump -h rule.wasm | grep Export
```

Should show:
```
 - func[1] name="pred_init"
 - func[2] name="pred_eval"
```

### "Invalid field ID"

Ensure field IDs are registered in the schema:
```rust
let pid_field_id = schema.register_field("process.pid", kestrel_schema::FieldType::I64)?;
```

## Next Steps

- Create more complex rules with multiple conditions
- Use regex and glob matching for string fields
- Implement sequence detection (Phase 4)
- Compile from EQL (Phase 3)

## Resources

- [WebAssembly Specification](https://webassembly.github.io/spec/)
- [WABT Tools](https://github.com/WebAssembly/wabt)
- [Kestrel Host API v1](../wasm_rule_package.md)
- [Wasmtime Documentation](https://docs.wasmtime.dev/)
