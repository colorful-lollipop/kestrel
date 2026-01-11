# Kestrel Rules Manager

**Core Layer - Rule Loading, Parsing, Hot Reload**

## Module Goal

Manage detection rules throughout their lifecycle:
- Load rules from files (JSON/YAML)
- Parse and validate rule structure
- Hot reload when rules change
- Expose rules to detection engine

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RuleManager                              │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Rule Cache (HashMap<RuleId, Rule>)                  │   │
│  │ - File watcher for rules_dir                        │   │
│  │ - Parse JSON/YAML into Rule struct                  │   │
│  │ - Validate rule structure                           │   │
│  │ - Hot reload on file changes                        │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  Rule Types                                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ RuleDefinition::Eql(EqlRule)    # EQL language      │   │
│  │ RuleDefinition::Wasm(WasmRule)  # Raw Wasm bytes    │   │
│  │ RuleDefinition::Lua(LuaRule)    # Lua script        │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Rule Structure

### Rule Metadata
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub id: String,           # Unique rule identifier
    pub name: String,         # Human-readable name
    pub severity: Severity,   # Informational/Low/Medium/High/Critical
    pub description: Option<String>,
}
```

### Rule Definition
```rust
#[derive(Debug, Clone)]
pub struct Rule {
    pub metadata: RuleMetadata,
    pub definition: RuleDefinition,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub enum RuleDefinition {
    Eql(EqlRule),     // EQL query
    Wasm(WasmRule),   // Raw Wasm module
    Lua(LuaRule),     // Lua script
}
```

### EQL Rule
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EqlRule {
    pub eql: String,  // The EQL query string
    pub output: Option<String>,  // Optional output format
}
```

## Core Interfaces

```rust
pub struct RuleManager {
    config: RuleManagerConfig,
    rules: Arc<RwLock<HashMap<String, Rule>>>,
    watcher: Option<RecommendedWatcher>,
}

impl RuleManager {
    pub fn new(config: RuleManagerConfig) -> Self;
    
    pub async fn load_all(&self) -> Result<LoadStats, RuleManagerError>;
    
    pub async fn get_rule(&self, id: &str) -> Option<Rule>;
    
    pub async fn list_rules(&self) -> Vec<String>;
    
    pub async fn rule_count(&self) -> usize;
    
    pub fn add_rule(&self, rule: Rule) -> Result<(), RuleManagerError>;
    
    pub fn remove_rule(&self, id: &str) -> Result<(), RuleManagerError>;
}
```

## Rule File Format

### JSON Format (`rules/my_rule.json`)
```json
{
  "metadata": {
    "id": "detect-suspicious-exec",
    "name": "Detect Suspicious Exec",
    "severity": "high",
    "description": "Detects execution of suspicious binaries"
  },
  "definition": {
    "eql": "event where process.executable == '/bin/bash'"
  },
  "enabled": true
}
```

### YAML Format (`rules/my_rule.yaml`)
```yaml
metadata:
  id: detect-suspicious-exec
  name: Detect Suspicious Exec
  severity: high
  description: Detects execution of suspicious binaries

definition:
  eql: |
    event where process.executable == '/bin/bash'

enabled: true
```

## Hot Reload

RuleManager watches the rules directory and automatically reloads on changes:

```rust
let config = RuleManagerConfig {
    rules_dir: PathBuf::from("./rules"),
    watch_enabled: true,     // Enable file watching
    max_concurrent_loads: 4, // Parallel loading
};

let manager = RuleManager::new(config);
manager.load_all().await?;

// Changes to rules/ are automatically detected
// Rules are reloaded without restarting
```

## Usage Example

```rust
use kestrel_rules::{RuleManager, RuleManagerConfig, Rule, RuleDefinition};
use kestrel_rules::Severity;

// Create rule manager
let config = RuleManagerConfig {
    rules_dir: PathBuf::from("./rules"),
    watch_enabled: false,
    max_concurrent_loads: 4,
};
let manager = RuleManager::new(config);

// Load all rules
let stats = manager.load_all().await?;
println!("Loaded {} rules", stats.loaded);

// List all rule IDs
let rule_ids = manager.list_rules().await;
println!("Rule IDs: {:?}", rule_ids);

// Get a specific rule
if let Some(rule) = manager.get_rule("detect-suspicious-exec").await {
    println!("Rule: {} = {}", rule.metadata.name, rule.metadata.severity);
}

// Manually add a rule
let rule = Rule {
    metadata: RuleMetadata {
        id: "test-rule".to_string(),
        name: "Test Rule".to_string(),
        severity: Severity::Medium,
        description: None,
    },
    definition: RuleDefinition::Eql(EqlRule {
        eql: "event where process.pid > 1000".to_string(),
    }),
    enabled: true,
};
manager.add_rule(rule)?;
```

## Planned Evolution

### v0.8 (Current)
- [x] JSON/YAML rule loading
- [x] Basic validation
- [x] Hot reload (file watching)
- [x] EQL rule support

### v0.9
- [ ] Rule dependencies (composite rules)
- [ ] Rule groups/categories
- [ ] Rule versioning
- [ ] Validation webhook

### v1.0
- [ ] Rule marketplace
- [ ] Cloud rule sync
- [ ] Collaborative rule editing
- [ ] Rule testing framework

## Test Coverage

```bash
cargo test -p kestrel-rules --lib

# Tests
test_load_json_rule              # JSON format parsing
test_load_yaml_rule              # YAML format parsing
test_rule_not_found              # Missing rule handling
test_hot_reload                  # File watching
test_duplicate_rule              # Duplicate ID error
test_rule_metadata               # Metadata parsing
```

## Dependencies

```
kestrel-rules
├── kestrel-schema (type definitions)
├── kestrel-core (Alert, Event)
├── tokio (async runtime)
├── serde_json (JSON parsing)
├── serde_yaml (YAML parsing)
├── notify (file watching)
└── tracing (logging)
```

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Initial load | O(n) | n = number of rule files |
| Single rule parse | ~1ms | YAML parsing is slower |
| Hot reload | O(changed) | Only modified files |
| Memory per rule | ~200 bytes | Excluding EQL query |

## Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum RuleManagerError {
    #[error("Rule file error: {0}")]
    RuleFileError(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Rule already exists: {0}")]
    RuleAlreadyExists(String),
    
    #[error("Rule not found: {0}")]
    RuleNotFound(String),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
}
```
