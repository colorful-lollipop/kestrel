# Kestrel EQL Compiler

**Runtime Layer - Event Query Language Parser, IR, Wasm Codegen**

## Module Goal

Compile EQL (Event Query Language) queries into executable predicates:
- **Parser**: Parse EQL syntax using pest grammar
- **IR**: Generate intermediate representation
- **Semantic Analysis**: Type checking and field resolution
- **Codegen**: Generate Wasm bytecode for predicate evaluation

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      EQL Compiler                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  EQL Query Input                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ event where process.executable == "/bin/bash"       │   │
│  │   and process.pid > 1000                            │   │
│  └─────────────────────────────────────────────────────┘   │
│                        ↓                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Parser (pest grammar)                               │   │
│  │ - Tokenization                                      │   │
│  │ - AST generation                                    │   │
│  │ - Syntax validation                                 │   │
│  └─────────────────────────────────────────────────────┘   │
│                        ↓                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Semantic Analyzer                                   │   │
│  │ - Type checking                                     │   │
│  │ - Field resolution                                  │   │
│  │ - Constant folding                                  │   │
│  └─────────────────────────────────────────────────────┘   │
│                        ↓                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ IR Generator                                        │   │
│  │ - Normalized AST                                   │   │
│  │ - Predicate IR                                      │   │
│  │ - Sequence IR                                       │   │
│  └─────────────────────────────────────────────────────┘   │
│                        ↓                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Wasm Codegen                                        │   │
│  │ - WAT generation                                    │   │
│  │ - Wasm compilation                                  │   │
│  │ - String literal pool                               │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## EQL Syntax Support

### Event Queries
```eql
event where process.executable == "/bin/bash"
event where process.pid > 1000
event where process.name in ("bash", "sh", "zsh")
event where contains(process.executable, "/tmp/")
event where process.executable wildcard "*/sh"
```

### Sequence Queries
```eql
sequence by process.pid
  [event where process.executable == "/bin/curl"]
  [event where event.name == "dns_lookup"]
  [event where file.path == "/etc/passwd"]
with maxspan 10s
```

### Comparison Operators
```eql
==  !=  <  <=  >  >=
```

### Logical Operators
```eql
and  or  not
```

### Functions
```eql
contains(field, "value")
startsWith(field, "prefix")
endsWith(field, "suffix")
wildcard(field, "pattern")
regex(field, "pattern")
```

## Core Interfaces

### EqlCompiler
```rust
pub struct EqlCompiler {
    schema: Arc<SchemaRegistry>,
}

impl EqlCompiler {
    pub fn new(schema: Arc<SchemaRegistry>) -> Self;
    
    pub fn compile(&self, query: &str) -> Result<IrRule, EqlError>;
    
    pub fn compile_to_ir(&self, definition: &EqlRule) -> Result<IrRule, EqlError>;
    
    pub fn compile_to_wasm(&self, definition: &EqlRule) -> Result<String, EqlError>;
}
```

### Intermediate Representation
```rust
pub enum IrRuleType {
    Event { event_type: String },
    Sequence { steps: Vec<IrSeqStep> },
}

pub struct IrRule {
    pub rule_type: IrRuleType,
    pub predicates: HashMap<String, IrPredicate>,
}

pub struct IrPredicate {
    pub required_fields: Vec<u32>,
    pub conditions: Vec<IrCondition>,
}

pub enum IrCondition {
    Comparison { field_id: u32, op: IrOp, value: IrValue },
    Function { name: String, args: Vec<IrValue> },
    Logical { op: IrLogicalOp, conditions: Vec<IrCondition> },
}
```

## Wasm Codegen

The compiler generates WebAssembly Text (WAT) format:

```wat
(module
  (import "env" "event_get_i64" (func $event_get_i64 (param i32 i32) (result i64)))
  (import "env" "event_get_str" (func $event_get_str (param i32 i32) (result i32)))
  (import "env" "alert_emit" (func $alert_emit (param i32)))
  
  (memory (export "memory") 1)
  (data (i32.const 100) "/bin/bash\0")  ;; String literal pool
  
  (func $pred_eval (export "pred_eval") (result i32)
    ;; Check process.executable == "/bin/bash"
    (local $field_id i32)
    (local $result i32)
    
    (local.set $field_id (i32.const 1))  ;; field_id = 1
    (local.set $result
      (call $event_get_str
        (local.get $field_id)
        (i32.const 100)))  ;; string offset
    
    ;; Compare result (returns 1 if equal)
    (i32.eq (local.get $result) (i32.const 1))
  )
)
```

## Usage Example

```rust
use kestrel_eql::{EqlCompiler, EqlRule};
use kestrel_schema::SchemaRegistry;

let schema = Arc::new(SchemaRegistry::new());
let compiler = EqlCompiler::new(schema);

// Compile EQL to IR
let ir = compiler.compile_to_ir(&EqlRule {
    eql: "event where process.executable == \"/bin/bash\"".to_string(),
})?;

match &ir.rule_type {
    IrRuleType::Event { event_type } => {
        println!("Event rule for: {}", event_type);
    }
    IrRuleType::Sequence { steps } => {
        println!("Sequence with {} steps", steps.len());
    }
}

// Compile to Wasm
let wasm_wat = compiler.compile_to_wasm(&EqlRule {
    eql: "event where process.pid > 1000".to_string(),
})?;

let wasm_bytes = wat::parse_str(&wasm_wat)?;
// Now wasm_bytes can be loaded into Wasm runtime
```

## Planned Evolution

### v0.8 (Current)
- [x] Basic event queries
- [x] Comparison operators
- [x] String functions (contains, startsWith, endsWith)
- [x] Wildcard/regex functions
- [x] Wasm codegen

### v0.9
- [ ] Full sequence support (all steps)
- [ ] Joins (multiple event types)
- [ ] Aggregations (count, sum, avg)
- [ ] Custom functions

### v1.0
- [ ] Full EQL spec compliance
- [ ] Query optimizer
- [ ] JIT compilation
- [ ] Query profiling

## Test Coverage

```bash
cargo test -p kestrel-eql --lib

# Parser Tests
test_parse_simple_event              # Basic event query
test_parse_sequence                  # Sequence syntax
test_parse_with_in_expression        # In clause
test_parse_with_complex_logic        # And/or/not
test_syntax_error_handling           # Error recovery

# Compiler Tests
test_compile_simple_event            # Basic compilation
test_compile_to_wasm                 # Wasm generation

# IR Tests
test_ir_rule_validation              # IR validation
test_ir_field_extraction             # Field extraction
test_ir_regex_extraction             # Regex detection

# Codegen Tests
test_arithmetic_operations           # + - * /
test_comparison_operators            # == != < > <= >=
test_function_call                   # contains, startsWith
test_string_literal_in_data_section  # String pooling
test_dispatcher_multiple_predicates  # Multi-predicate
```

## Dependencies

```
kestrel-eql
├── kestrel-schema (field types, schema registry)
├── pest (parser generator)
├── pest_derive (parser derive)
├── serde (serialization)
├── thiserror (error handling)
└── wat (WAT → Wasm conversion)
```

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Parse query | ~500μs | Simple queries |
| Semantic analysis | ~200μs | With field resolution |
| Wasm codegen | ~1ms | WAT generation |
| Wasm compilation | ~500μs | wat::parse_str |
| Predicate eval | <1μs | P99 target |

## Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum EqlError {
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Semantic error: {0}")]
    SemanticError(String),
    
    #[error("Codegen error: {0}")]
    CodegenError(String),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
}
```
