# Kestrel Tutorial

Welcome to the Kestrel tutorial! This guide will help you get started with Kestrel, from installation to writing your first rules and deploying in production.

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Writing Your First Rule](#writing-your-first-rule)
5. [Advanced Rule Concepts](#advanced-rule-concepts)
6. [Testing Rules](#testing-rules)
7. [Production Deployment](#production-deployment)
8. [Next Steps](#next-steps)

## Introduction

### What is Kestrel?

Kestrel is a next-generation endpoint behavioral detection engine that:
- Collects system events using eBPF (kernel-level, zero overhead)
- Detects threat patterns using EQL (Event Query Language)
- Supports sequence detection for multi-stage attacks
- Can block malicious actions in real-time
- Provides offline replay for incident response

### What You'll Learn

In this tutorial, you'll:
- Install and configure Kestrel
- Understand event sources and schemas
- Write EQL rules for common threats
- Test and validate rules
- Deploy Kestrel in production

### Prerequisites

- **OS**: Linux 5.10+ (Ubuntu 20.04+, Fedora 33+, or similar)
- **Rust**: 1.82+ (for building from source)
- **Permissions**: Root or CAP_BPF capability
- **Memory**: 2GB+ RAM recommended

## Installation

### Option 1: Build from Source

```bash
# Clone repository
git clone https://github.com/kestrel-detection/kestrel.git
cd Kestrel

# Build release version
cargo build --release

# Install binary
sudo install target/release/kestrel /usr/local/bin/
```

### Option 2: Download Binary

```bash
# Download latest release (Linux x86_64)
wget https://github.com/kestrel-detection/kestrel/releases/latest/download/kestrel-linux-x86_64.tar.gz

# Extract
tar xzf kestrel-linux-x86_64.tar.gz

# Install
sudo install kestrel /usr/local/bin/
```

### Verify Installation

```bash
kestrel --version
# Output: Kestrel 0.1.0
```

## Quick Start

### 1. Create a Working Directory

```bash
mkdir ~/kestrel-tutorial
cd ~/kestrel-tutorial
mkdir rules
```

### 2. Create Your First Rule

Create `rules/suspicious_exec.eql`:

```eql
process where process.executable == "/tmp/suspicious"
```

This rule detects when a process is executed from `/tmp/`, which is often suspicious.

### 3. Run Kestrel

```bash
# Start Kestrel with your rules
sudo kestrel run --rules ./rules
```

Kestrel will:
1. Load eBPF programs for event collection
2. Load your rules
3. Start processing events
4. Alert when the rule matches

### 4. Test Your Rule

In another terminal:

```bash
# Create a test executable
echo '#!/bin/sh' > /tmp/suspicious
echo 'echo "Hello from suspicious executable"' >> /tmp/suspicious
chmod +x /tmp/suspicious

# Run it (this should trigger an alert)
/tmp/suspicious
```

You should see an alert in Kestrel's output!

## Writing Your First Rule

### Rule Structure

An EQL rule has three parts:

```eql
// 1. Event type
process where

// 2. Conditions
  process.executable == "/tmp/suspicious" &&
  user.name != "root"

// 3. Optional: Grouping
by process.entity_id
```

### Common Event Types

```eql
// Process events
process where ...

// File events
file where ...

// Network events
network where ...

// System events
system where ...
```

### Comparisons and Operators

```eql
// Equality
process.executable == "/bin/bash"

// Inequality
process.executable != "/bin/bash"

// Wildcards
process.executable == "/tmp/*"

// Numeric comparisons
process.pid > 1000

// Boolean logic
process.executable == "/tmp/*" && user.name != "root"

// Negation
not process.executable in ("/usr/bin/*", "/bin/*")
```

## Advanced Rule Concepts

### Sequence Detection

Detect multi-stage attacks:

```eql
sequence by process.entity_id
  [process where process.executable == "/bin/bash"]
  [file where file.path == "/etc/passwd"]
  [network where network.destination == "malicious.com"]
with maxspan=30s
```

This detects:
1. A bash shell starts
2. Within 30 seconds, reads `/etc/passwd`
3. Then connects to `malicious.com`

### Grouping

Group events by entity:

```eql
sequence by process.entity_id
  [file where file.operation == "create"]
  [file where file.operation == "write"]
  [file where file.operation == "execute"]
```

This tracks files created, written to, and executed by the same process.

### Time Windows

Control sequence timing:

```eql
sequence with maxspan=5s
  [process where ...]
  [file where ...]
```

Time units:
- `s` - seconds
- `m` - minutes
- `h` - hours

### Aggregation

Count events:

```eql
sequence by process.entity_id
  [file where file.operation == "create"]
  [file where file.operation == "create"] with count > 10
```

Detects when a process creates more than 10 files.

## Testing Rules

### 1. Validate Syntax

```bash
kestrel validate rules/suspicious_exec.eql
```

### 2. Dry Run Mode

Test without actually blocking:

```bash
kestrel run --rules ./rules --dry-run
```

### 3. Test with Sample Data

Create test events:

```json
// test_events.json
[
  {
    "event_type_id": 1001,
    "timestamp_ns": 1234567890000000000,
    "fields": {
      "process.executable": "/tmp/suspicious",
      "process.pid": 12345,
      "user.name": "testuser"
    }
  }
]
```

Run test:

```bash
kestrel test --rule rules/suspicious_exec.eql --events test_events.json
```

## Production Deployment

### 1. Create Configuration

Create `/etc/kestrel/config.toml`:

```toml
[engine]
# Event buffer size
buffer_size = 10000

# Number of worker threads
workers = 4

[logging]
level = "info"
format = "json"

[actions]
# Enable blocking (use with caution!)
blocking_enabled = false
# Alert only mode
alert_only = true
```

### 2. Set Up Directories

```bash
sudo mkdir -p /etc/kestrel/rules
sudo mkdir -p /var/lib/kestrel
sudo mkdir -p /var/log/kestrel
```

### 3. Deploy Rules

```bash
sudo cp ~/kestrel-tutorial/rules/*.eql /etc/kestrel/rules/
```

### 4. Create Systemd Service

Create `/etc/systemd/system/kestrel.service`:

```ini
[Unit]
Description=Kestrel Detection Engine
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/kestrel run --rules /etc/kestrel/rules --config /etc/kestrel/config.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable kestrel
sudo systemctl start kestrel
```

### 5. Monitor Logs

```bash
# Follow logs
sudo journalctl -u kestrel -f

# Check status
sudo systemctl status kestrel
```

## Real-World Examples

### Detect Linux Malware

```eql
sequence by process.entity_id
  [process where process.executable == "/tmp/*"]
  [file where file.path == "/etc/ld.so.preload"]
  [network where network.destination == "192.168.1.100"]
with maxspan=1m
```

### Detect Privilege Escalation

```eql
sequence by user.id
  [process where process.executable == "/bin/sudo"]
  [process where process.executable == "/bin/bash"]
  [file where file.path == "/etc/shadow"]
with maxspan=30s
```

### Detect Data Exfiltration

```eql
sequence by process.entity_id
  [file where file.path == "*/sensitive/*"]
  [network where network.destination.port == 443 and network.bytes_sent > 1000000]
with maxspan=5m
```

## Best Practices

### 1. Write Specific Rules

❌ **Too broad**:
```eql
process where true
```

✅ **Specific**:
```eql
process where process.executable == "/tmp/*" and user.name != "root"
```

### 2. Use Grouping

Group related events:
```eql
sequence by process.entity_id
  [process where ...]
  [file where ...]
```

### 3. Set Time Windows

Prevent false positives with time limits:
```eql
sequence with maxspan=5m
  ...
```

### 4. Test Thoroughly

- Validate syntax
- Test with sample data
- Run in dry-run mode first
- Monitor in production

## Troubleshooting

### Rule Not Firing

1. **Validate syntax**: `kestrel validate rule.eql`
2. **Check logs**: Look for errors with `--log-level debug`
3. **Verify events**: Ensure events are being collected
4. **Test conditions**: Simplify rule to isolate issue

### High CPU Usage

1. **Reduce rule complexity**
2. **Filter event sources**
3. **Increase worker efficiency**
4. **Use release build**

### eBPF Load Failures

1. **Check kernel version**: Requires 5.10+
2. **Verify permissions**: Run with `sudo`
3. **Check BTF**: Some features require BTF support
4. **Review logs**: `dmesg | grep -i bpf`

## Next Steps

### Learn More

- **API Reference**: [docs/api.md](api.md)
- **Deployment Guide**: [docs/deployment.md](deployment.md)
- **Performance Tuning**: [docs/performance-analysis.md](performance-analysis.md)
- **Troubleshooting**: [docs/troubleshooting.md](troubleshooting.md)

### Explore Examples

Check out the `examples/` directory for more rule examples:
- `examples/basic_usage.md` - Basic usage patterns
- `examples/wasm_rule_package.md` - Wasm rule development
- `examples/lua_rule_package.md` - Lua rule development

### Join the Community

- **GitHub Discussions**: Participate in discussions
- **GitHub Issues**: Report bugs and request features
- **Contributing**: See [CONTRIBUTING.md](../CONTRIBUTING.md)

## Conclusion

Congratulations! You've completed the Kestrel tutorial. You should now be able to:

- ✅ Install and configure Kestrel
- ✅ Write EQL rules for threat detection
- ✅ Test and validate rules
- ✅ Deploy Kestrel in production

**What's Next?**

1. **Explore the examples**: Check out `examples/` directory
2. **Read the documentation**: See `docs/` for in-depth guides
3. **Join the community**: Participate in GitHub Discussions
4. **Contribute**: See [CONTRIBUTING.md](../CONTRIBUTING.md)

Happy threat hunting! 🎯

---

**Need Help?**

- **FAQ**: [FAQ.md](FAQ.md)
- **Support**: [SUPPORT.md](SUPPORT.md)
- **GitHub Issues**: [Report a problem](https://github.com/kestrel-detection/kestrel/issues)

**Last Updated**: 2025-01-14
