# Kestrel CLI

**Application Layer - Command-Line Interface**

## Module Goal

Provide a user-friendly CLI for running Kestrel:
- Start/stop the detection engine
- Manage rules directory
- Monitor engine status
- Interactive mode for debugging

## Usage

```bash
# Install
cargo install --path kestrel-cli

# Show help
kestrel --help

# Start the detection engine
kestrel run --rules ./rules

# Run with specific config
kestrel run --rules ./rules --wasm-workers 4

# Check engine status
kestrel status

# List loaded rules
kestrel rules list

# Validate a rule file
kestrel validate ./rules/my_rule.json

# Replay events from log
kestrel replay ./events.jsonl

# Interactive mode (REPL)
kestrel repl
```

## Commands

### run
Start the detection engine:

```bash
kestrel run [OPTIONS]

Options:
  --rules DIR          Rules directory (default: ./rules)
  --wasm               Enable Wasm runtime (default)
  --lua                Enable Lua runtime (default)
  --no-wasm            Disable Wasm runtime
  --no-lua             Disable Lua runtime
  --partitions NUM     Number of partitions (default: 4)
  --queue-size NUM     Queue size per partition (default: 1000)
  --output FORMAT      Alert output: stdout, file, webhook
  --webhook-url URL    Webhook URL for alerts
  -v, --verbose        Verbose output
```

### status
Show engine status:

```bash
kestrel status

# Output:
# Engine Status
# ─────────────
# Status: Running
# Uptime: 2m 34s
# Rules Loaded: 15
# Single-event Rules: 12
# Sequence Rules: 3
# Alerts Generated: 7
# Events Processed: 1,234
```

### rules
Manage rules:

```bash
# List all rules
kestrel rules list

# Show rule details
kestrel rules show <rule-id>

# Validate a rule file
kestrel rules validate <file.json>

# Enable/disable a rule
kestrel rules enable <rule-id>
kestrel rules disable <rule-id>
```

### replay
Replay events from log:

```bash
kestrel replay [OPTIONS] <log-file>

Options:
  --speed MULTIPLIER   Replay speed (default: 1.0)
  --loop               Loop replay indefinitely
  --count NUM          Maximum events to replay
```

### repl
Interactive REPL mode:

```bash
kestrel repl

# Kestrel REPL v0.8.0
# Type 'help' for commands

kestrel> status
Engine Status: Running

kestrel> rules list
ID                    Name                    Severity
detect-bash           Detect Bash Exec        High
detect-curl           Detect Curl Usage       Medium

kestrel> event send 1 '{"executable": "/bin/bash"}'
Event sent: 1

kestrel> alerts
Alert: detect-bash - Process bash executed
Timestamp: 2026-01-11T10:30:00Z

kestrel> exit
```

## Configuration File

Create `kestrel.yaml` for persistent configuration:

```yaml
# kestrel.yaml
engine:
  rules_dir: ./rules
  partitions: 4
  queue_size: 1000
  
wasm:
  enabled: true
  instance_pool_size: 10
  
lua:
  enabled: true
  
alerting:
  outputs:
    - type: stdout
    - type: webhook
      url: https://alerts.example.com/webhook
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Kestrel CLI                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ CLI App (clap)                                       │   │
│  │ ├── run Command                                      │   │
│  │ ├── status Command                                   │   │
│  │ ├── rules Command                                    │   │
│  │ │   ├── list Subcommand                              │   │
│  │ │   ├── show Subcommand                              │   │
│  │ │   ├── validate Subcommand                          │   │
│  │ │   └── enable/disable Subcommands                   │   │
│  │ ├── replay Command                                   │   │
│  │ └── repl Command                                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                        ↓                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Engine Wrapper                                       │   │
│  │ ├── DetectionEngine::new()                          │   │
│  │ ├── DetectionEngine::run()                          │   │
│  │ └── Status Reporter                                  │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Signal Handling

The CLI handles OS signals gracefully:

- `SIGINT` (Ctrl+C): Graceful shutdown with alert flush
- `SIGTERM`: Graceful shutdown
- `SIGHUP`: Reload configuration and rules

## Dependencies

```
kestrel-cli
├── kestrel-engine (detection engine)
├── kestrel-schema (type definitions)
├── kestrel-event (event types)
├── kestrel-rules (rule management)
├── clap (CLI parsing)
├── tokio (async runtime)
└── tracing (logging)
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Rule validation failed |
| 4 | Engine error |
| 5 | File not found |

## Shell Completion

Generate shell completion:

```bash
# Bash
kestrel generate-completion bash > kestrel.bash

# Zsh
kestrel generate-completion zsh > _kestrel

# Fish
kestrel generate-completion fish > kestrel.fish
```

## Planned Evolution

### v0.8 (Current)
- [x] Basic run/status/rules commands
- [x] REPL mode
- [x] Replay functionality
- [x] Configuration file

### v0.9
- [ ] Dashboard UI (crossterm)
- [ ] Hot rule reload
- [ ] Remote management (gRPC)
- [ ] Cloud integration

### v1.0
- [ ] Web UI
- [ ] Multi-node management
- [ ] Rule marketplace
- [ ] Performance profiling UI
