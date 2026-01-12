# Deployment Guide

This guide covers deploying Kestrel in production environments.

## Table of Contents

- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running in Production](#running-in-production)
- [Performance Tuning](#performance-tuning)
- [Monitoring](#monitoring)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

## System Requirements

### Minimum Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 2 cores | 4+ cores |
| **Memory** | 2 GB RAM | 4+ GB RAM |
| **Disk** | 500 MB | 2 GB+ |
| **OS** | Linux kernel 5.10+ | Linux kernel 6.0+ |
| **Rust** | 1.82+ | 1.82+ |

### Privileges

- **eBPF loading**: Requires `CAP_BPF` capability or root
- **LSM hooks**: Requires root or eBPF-LSM support
- **Tracepoints**: Requires `CAP_PERFMON` or root

## Installation

### From Source

```bash
# Clone repository
git clone https://github.com/kestrel-detection/kestrel.git
cd kestrel

# Build release binary
cargo build --release

# Install (optional)
sudo cp target/release/kestrel /usr/local/bin/
sudo cp target/release/kestrel-benchmark /usr/local/bin/
```

### From Pre-built Binary

Download the latest release from [GitHub Releases](https://github.com/kestrel-detection/kestrel/releases):

```bash
# Download
wget https://github.com/kestrel-detection/kestrel/releases/latest/download/kestrel-linux-x86_64.tar.gz

# Extract
tar xzf kestrel-linux-x86_64.tar.gz

# Install
sudo cp kestrel /usr/local/bin/
```

### Systemd Service

Create `/etc/systemd/system/kestrel.service`:

```ini
[Unit]
Description=Kestrel Detection Engine
After=network.target
Documentation=https://github.com/kestrel-detection/kestrel

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/kestrel
ExecStart=/usr/local/bin/kestrel run --rules /opt/kestrel/rules --log-level info
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/kestrel /var/lib/kestrel

# Resource limits
LimitNOFILE=65536
MemoryLimit=2G
CPUQuota=200%

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=kestrel

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable kestrel
sudo systemctl start kestrel
sudo systemctl status kestrel
```

## Configuration

### Command Line Options

```bash
kestrel run [OPTIONS]

OPTIONS:
    --rules <PATH>           Rules directory [default: ./rules]
    --config <PATH>          Configuration file (TOML)
    --log-level <LEVEL>      Log level: trace, debug, info, warn, error [default: info]
    --mode <MODE>            Execution mode: detect, enforce, offline [default: detect]
    --event-sources <SOURCES> Comma-separated event sources: ebpf,audit,socket [default: ebpf]
    --workers <NUM>          Number of worker threads [default: number of CPUs]
    --max-memory <MB>        Maximum memory usage in MB [default: 2048]
    --output <TYPE>          Alert output: stdout,file,syslog [default: stdout]
    --output-path <PATH>     File output path when --output=file
```

### Configuration File (TOML)

Create `/etc/kestrel/config.toml`:

```toml
[general]
log_level = "info"
mode = "detect"  # detect, enforce, offline
workers = 4
max_memory_mb = 2048

[engine]
event_bus_partitions = 4
channel_size = 10000
batch_size = 100

[ebpf]
enabled = true
program_path = "/opt/kestrel/bpf"
ringbuf_size = 4096  # pages

[wasm]
enabled = true
memory_limit_mb = 16
fuel_limit = 1000000
instance_pool_size = 10

[lua]
enabled = true
jit_enabled = true
memory_limit_mb = 16

[alerts]
output = ["stdout", "file"]
file_path = "/var/log/kestrel/alerts.json"
file_rotation = "daily"
retention_days = 30

[performance]
enable_profiling = false
metrics_port = 9090
```

## Running in Production

### Environment Setup

```bash
# Create directories
sudo mkdir -p /opt/kestrel/{rules,bpf}
sudo mkdir -p /var/log/kestrel
sudo mkdir -p /var/lib/kestrel

# Set permissions
sudo chown -R root:root /opt/kestrel
sudo chmod -R 755 /opt/kestrel
sudo chown -R root:root /var/log/kestrel
sudo chmod 755 /var/log/kestrel

# Copy rules
sudo cp -r rules/* /opt/kestrel/rules/
```

### Pre-flight Checks

```bash
# Check BPF capabilities
sudo bpftool feature

# Verify rule syntax
kestrel validate --rules /opt/kestrel/rules

# List loaded rules
kestrel list --rules /opt/kestrel/rules

# Dry run (if supported)
kestrel run --rules /opt/kestrel/rules --mode offline --dry-run
```

### Production Launch

```bash
# Start with systemd
sudo systemctl start kestrel

# Or run directly
sudo kestrel run \
  --rules /opt/kestrel/rules \
  --config /etc/kestrel/config.toml \
  --log-level info \
  --mode detect
```

## Performance Tuning

### Worker Threads

Match worker count to CPU cores:

```toml
[general]
workers = 8  # For 8-core CPU
```

### Event Bus Partitions

Increase for high throughput:

```toml
[engine]
event_bus_partitions = 16  # More parallelism
channel_size = 50000       # Larger buffer
```

### Memory Management

```toml
[wasm]
memory_limit_mb = 32       # Increase for complex rules
instance_pool_size = 20    # More pooled instances

[general]
max_memory_mb = 4096       # Higher limit
```

### eBPF Optimization

```toml
[ebpf]
ringbuf_size = 8192        # Larger ring buffer
perf_event_drain_interval_ms = 100
```

### CPU Pinning (Advanced)

Edit systemd service:

```ini
[Service]
CPUAffinity=0-3  # Pin to first 4 cores
```

## Monitoring

### Metrics Endpoint

Kestrel exposes metrics on HTTP endpoint (when enabled):

```toml
[performance]
metrics_port = 9090
```

Access metrics:

```bash
curl http://localhost:9090/metrics
```

### Key Metrics

- `kestrel_events_total`: Total events processed
- `kestrel_events_per_second`: Current EPS
- `kestrel_alerts_total`: Total alerts generated
- `kestrel_rules_loaded`: Number of loaded rules
- `kestrel_nfa_active_matches`: Active sequence matches
- `kestrel_memory_usage_bytes`: Current memory usage

### Logging

Logs go to systemd journal by default:

```bash
# View logs
sudo journalctl -u kestrel -f

# Filter by log level
sudo journalctl -u kestrel -p err

# Last 100 lines
sudo journalctl -u kestrel -n 100
```

### Health Checks

```bash
# Check if service is running
sudo systemctl is-active kestrel

# Check service status
sudo systemctl status kestrel

# Verify event processing
sudo journalctl -u kestrel --grep="events processed"
```

## Security Considerations

### Principle of Least Privilege

Run with minimal capabilities:

```bash
# Instead of root, use capabilities
sudo setcap cap_bpf,cap_perfmon,cap_net_admin,cap_sys_admin+ep /usr/local/bin/kestrel
```

### Rule Validation

Validate rules before deployment:

```bash
# Check syntax
kestrel validate --rules /opt/kestrel/rules

# Test in detect mode first
kestrel run --rules /opt/kestrel/rules --mode detect
```

### File Permissions

```bash
# Restrict rule files
sudo chmod 640 /opt/kestrel/rules/*
sudo chown root:kestrel-admin /opt/kestrel/rules/*

# Protect logs
sudo chmod 640 /var/log/kestrel/*
sudo chown root:kestrel-admin /var/log/kestrel/*
```

### Network Isolation

If Kestrel doesn't need network access:

```ini
[Service]
# In systemd service
RestrictAddressFamilies=AF_UNIX AF_NETLINK
PrivateNetwork=true
```

## Troubleshooting

### High CPU Usage

**Symptoms**: Kestrel using >50% CPU

**Diagnosis**:
```bash
# Check EPS
sudo journalctl -u kestrel --grep="events per second"

# Profile (if enabled)
curl http://localhost:9090/metrics | grep cpu
```

**Solutions**:
- Reduce event sources
- Filter events at eBPF level
- Increase worker partitions
- Disable expensive rules

### Memory Growth

**Symptoms**: Memory usage steadily increasing

**Diagnosis**:
```bash
# Check memory
sudo journalctl -u kestrel --grep="memory"
ps aux | grep kestrel
```

**Solutions**:
- Reduce StateStore quota
- Enable TTL/LRU more aggressively
- Limit Wasm instance pool
- Check for memory leaks in rules

### No Alerts Generated

**Symptoms**: Kestrel running but no alerts

**Diagnosis**:
```bash
# Check rules loaded
sudo journalctl -u kestrel --grep="rules loaded"

# Check events received
sudo journalctl -u kestrel --grep="events received"

# Test with sample event
kestrel test --rules /opt/kestrel/rules --event sample.json
```

**Solutions**:
- Verify rule syntax
- Check event type matches
- Enable debug logging
- Test with known-matching events

### eBPF Loading Failure

**Symptoms**: Failed to load eBPF programs

**Diagnosis**:
```bash
# Check kernel version
uname -r

# Check BPF capabilities
sudo bpftool feature

# Check logs
sudo journalctl -u kestrel -p err
```

**Solutions**:
- Update kernel to 5.10+
- Install clang and LLVM
- Run with root privileges
- Check SELinux/AppArmor policies

### High Event Latency

**Symptoms**: Events processed with delay

**Diagnosis**:
```bash
# Check metrics
curl http://localhost:9090/metrics | grep latency

# Check queue depth
curl http://localhost:9090/metrics | grep queue
```

**Solutions**:
- Increase worker count
- Reduce batch size
- Increase channel size
- Optimize slow rules

## Backup and Recovery

### Backup Configuration

```bash
# Backup rules
sudo tar czf kestrel-rules-$(date +%Y%m%d).tar.gz /opt/kestrel/rules

# Backup config
sudo cp /etc/kestrel/config.toml ./kestrel-config-$(date +%Y%m%d).toml
```

### Restore

```bash
# Restore rules
sudo tar xzf kestrel-rules-YYYYMMDD.tar.gz -C /

# Restore config
sudo cp kestrel-config-YYYYMMDD.toml /etc/kestrel/config.toml

# Restart
sudo systemctl restart kestrel
```

## Upgrading

### Upgrade Procedure

```bash
# Stop service
sudo systemctl stop kestrel

# Backup current version
sudo cp /usr/local/bin/kestrel /usr/local/bin/kestrel.backup

# Install new version
sudo cp kestrel /usr/local/bin/

# Verify
kestrel --version

# Start service
sudo systemctl start kestrel

# Verify logs
sudo journalctl -u kestrel -f
```

### Rolling Upgrade (Multi-instance)

```bash
# Upgrade instance 1
sudo systemctl stop kestrel@1
# Install new binary
sudo systemctl start kestrel@1

# Verify instance 1 is healthy
# Then repeat for other instances
```

## Additional Resources

- [Configuration Reference](configuration.md)
- [Performance Tuning Guide](performance.md)
- [Troubleshooting Guide](troubleshooting.md)
- [Security Best Practices](security.md)
