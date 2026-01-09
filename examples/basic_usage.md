# Basic Usage Examples

## Running the Engine

```bash
# Build the project
cargo build --release

# Run the engine with default settings
cargo run --bin kestrel -- run

# Run with custom rules directory
cargo run --bin kestrel -- run --rules /path/to/rules

# Run with debug logging
cargo run --bin kestrel -- run --log-level debug
```

## Validating Rules

```bash
# Validate all rules in the default directory
cargo run --bin kestrel -- validate

# Validate rules in a custom directory
cargo run --bin kestrel -- validate --rules /path/to/rules
```

## Listing Rules

```bash
# List all loaded rules
cargo run --bin kestrel -- list
```

## Creating Rules

Create a JSON rule file in the `rules/` directory:

```json
{
  "id": "my-rule-001",
  "name": "My Custom Rule",
  "description": "Detects something suspicious",
  "version": "1.0.0",
  "author": "Your Name",
  "tags": ["detection", "security"],
  "severity": "High"
}
```

Or use YAML format:

```yaml
id: my-rule-002
name: Another Custom Rule
description: Detects something else
version: "1.0.0"
author: Your Name
tags:
  - detection
  - security
severity: Medium
```

Or use EQL format (future support):

```eql
sequence by process.entity_id
  [process where event.type == "exec" and process.name == "suspicious"]
  [file where event.type == "create" and file.extension == "exe"]
```
