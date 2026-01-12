# Troubleshooting Guide

This guide helps diagnose and resolve common issues with Kestrel.

## Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Installation Issues](#installation-issues)
- [Runtime Issues](#runtime-issues)
- [Performance Issues](#performance-issues)
- [Rule Issues](#rule-issues)
- [eBPF Issues](#ebpf-issues)
- [Networking Issues](#networking-issues)
- [Getting Help](#getting-help)

## Quick Diagnostics

### Health Check Script

```bash
#!/bin/bash
# kestrel-health-check.sh

echo "=== Kestrel Health Check ==="
echo ""

# Check if running
if systemctl is-active --quiet kestrel; then
    echo "✓ Service is running"
else
    echo "✗ Service is NOT running"
fi

# Check version
echo ""
echo "Version:"
kestrel --version 2>/dev/null || echo "kestrel not found in PATH"

# Check recent errors
echo ""
echo "Recent errors (last 10):"
journalctl -u kestrel -p err -n 10 --no-pager

# Check resource usage
echo ""
echo "Resource usage:"
ps aux | grep '[k]estrel' | awk '{print "CPU: " $3"% MEM: " $4"%"}'

# Check metrics (if available)
echo ""
if curl -s http://localhost:9090/metrics > /dev/null; then
    echo "Metrics endpoint: ✓"
    echo "Events processed: $(curl -s http://localhost:9090/metrics | grep kestrel_events_total | awk '{print $2}')"
else
    echo "Metrics endpoint: ✗"
fi
```

## Installation Issues

### Problem: Build Fails with "cannot find -lbpf"

**Error Message:**
```
error: cannot find -lbpf
```

**Cause:** Missing eBPF development libraries

**Solution:**
```bash
# Ubuntu/Debian
sudo apt-get install -y libbpf-dev libelf-dev

# RHEL/CentOS
sudo yum install -y bpf-devel elfutils-libelf-devel

# Arch
sudo pacman -S bpf libelf
```

---

### Problem: "clang: command not found"

**Error Message:**
```
error: failed to execute command: clang
```

**Cause:** Missing clang compiler for eBPF programs

**Solution:**
```bash
# Ubuntu/Debian
sudo apt-get install -y clang llvm

# RHEL/CentOS
sudo yum install -y clang llvm

# Verify
clang --version
llvm-config --version
```

---

### Problem: Cargo Build Out of Memory

**Error Message:**
```
error: Could not compile kestrel-ebpf
fatal error: linker signal terminated
```

**Cause:** Limited memory during linking

**Solution:**
```bash
# Limit parallel jobs
CARGO_BUILD_JOBS=2 cargo build --release

# Or increase swap
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

## Runtime Issues

### Problem: Service Fails to Start

**Symptoms:**
```bash
$ sudo systemctl start kestrel
$ sudo systemctl status kestrel
● kestrel.service - Kestrel Detection Engine
   Loaded: loaded (/etc/systemd/system/kestrel.service)
   Active: failed (Result: exit-code)
```

**Diagnosis:**
```bash
# Check journal
sudo journalctl -u kestrel -n 50 --no-pager

# Manual run
sudo -u kestrel kestrel run --rules /opt/kestrel/rules
```

**Common Causes:**

1. **Permission Denied**
   ```
   Error: Permission denied (os error 13)
   ```
   - Fix file permissions
   - Run with correct user

2. **Rules Directory Missing**
   ```
   Error: rules directory not found: /opt/kestrel/rules
   ```
   ```bash
   sudo mkdir -p /opt/kestrel/rules
   sudo cp rules/* /opt/kestrel/rules/
   ```

3. **Port Already in Use**
   ```
   Error: bind() failed: address already in use
   ```
   ```bash
   # Check what's using the port
   sudo lsof -i :9090
   # Change metrics port in config
   ```

---

### Problem: High CPU Usage

**Symptoms:**
- Kestrel using 80-100% CPU
- System sluggish

**Diagnosis:**
```bash
# Check PID
ps aux | grep kestrel

# Profile (if perf available)
sudo perf top -p $(pidof kestrel)

# Check thread usage
ps -T -p $(pidof kestrel)
```

**Solutions:**

1. **Too Many Events**
   ```bash
   # Check EPS
   sudo journalctl -u kestrel --grep="events per second"
   ```
   - Reduce event sources
   - Filter at eBPF level

2. **Expensive Rules**
   ```bash
   # Check which rules are slow
   curl http://localhost:9090/metrics | grep rule_eval
   ```
   - Optimize regex patterns
   - Reduce predicate complexity
   - Disable unnecessary rules

3. **Insufficient Workers**
   ```toml
   # config.toml
   [general]
   workers = 8  # Increase workers
   ```

---

### Problem: Memory Leak

**Symptoms:**
- Memory usage steadily increasing
- OOM kills

**Diagnosis:**
```bash
# Monitor memory
watch -n 1 'ps aux | grep kestrel'

# Check memory metrics
curl http://localhost:9090/metrics | grep memory

# Valgrind (if available)
sudo valgrind --leak-check=full --track-origins=yes kestrel run
```

**Solutions:**

1. **StateStore Growth**
   ```bash
   # Check active matches
   curl http://localhost:9090/metrics | grep nfa_active_matches
   ```
   ```toml
   # config.toml
   [nfa]
   max_partial_matches = 1000  # Reduce from default
   ttl_seconds = 300  # Shorter TTL
   ```

2. **Wasm Instance Pool**
   ```bash
   # Check instance count
   curl http://localhost:9090/metrics | grep wasm_instances
   ```
   ```toml
   [wasm]
   instance_pool_size = 5  # Reduce pool
   ```

3. **Event Queue Buildup**
   ```bash
   # Check queue depth
   curl http://localhost:9090/metrics | grep queue_depth
   ```
   - Increase worker count
   - Reduce event rate

---

### Problem: No Alerts Generated

**Symptoms:**
- Kestrel running fine but no alerts
- Tests pass but production silent

**Diagnosis:**
```bash
# Check rules loaded
sudo journalctl -u kestrel --grep="loaded" | tail -5

# Check events received
sudo journalctl -u kestrel --grep="events received" | tail -5

# Test with known event
echo '{"event_type": 1001, "process.executable": "/tmp/test"}' | \
  kestrel test --rules /opt/kestrel/rules
```

**Common Causes:**

1. **Rule Not Enabled**
   ```bash
   # List loaded rules
   kestrel list --rules /opt/kestrel/rules
   ```

2. **Event Type Mismatch**
   ```bash
   # Check schema
   kestrel schema --show event_types
   ```

3. **Predicate Always False**
   - Enable debug logging
   - Add test alerts
   - Check predicate logic

## Performance Issues

### Problem: Low Throughput (< 1k EPS)

**Diagnosis:**
```bash
# Check current EPS
curl http://localhost:9090/metrics | grep events_per_second

# Run benchmark
kestrel-benchmark --throughput
```

**Solutions:**

1. **Single Worker**
   ```toml
   [general]
   workers = 4  # Use more workers
   ```

2. **Small Channel**
   ```toml
   [engine]
   channel_size = 10000  # Increase buffer
   ```

3. **CPU Saturation**
   - Reduce rule complexity
   - Filter at eBPF level
   - Use faster hardware

---

### Problem: High Latency (> 1ms P99)

**Diagnosis:**
```bash
# Check latency metrics
curl http://localhost:9090/metrics | grep latency_p99

# Run latency benchmark
kestrel-benchmark --latency
```

**Solutions:**

1. **Slow Predicates**
   - Profile Wasm/Lua code
   - Cache regex compilation
   - Use field IDs

2. **Lock Contention**
   ```bash
   # Check lock metrics
   curl http://localhost:9090/metrics | grep lock_contention
   ```
   - Increase partitions
   - Reduce shared state

3. **Large Batches**
   ```toml
   [engine]
   batch_size = 50  # Reduce from 100
   ```

## Rule Issues

### Problem: Rule Fails to Load

**Error:**
```
Error: Failed to load rule: Invalid EQL syntax
```

**Diagnosis:**
```bash
# Validate rule
kestrel validate --rules /opt/kestrel/rules --rule rule-name

# Check syntax
cat /opt/kestrel/rules/rule-name.eql
```

**Common Fixes:**

1. **Syntax Error**
   ```eql
   # Wrong
   process where process.executable = "/bin/bash"

   # Correct
   process where process.executable == "/bin/bash"
   ```

2. **Unknown Field**
   ```bash
   # List available fields
   kestrel schema --show fields
   ```

3. **Invalid Type**
   ```bash
   # Check field types
   kestrel schema --show field:process.executable
   ```

---

### Problem: False Positives

**Symptoms:**
- Alert triggered on legitimate activity
- Too many noise alerts

**Diagnosis:**
```bash
# View alert details
sudo journalctl -u kestrel --grep="alert" | tail -20

# Test with sample event
echo 'EVENT_JSON' | kestrel test --rules /opt/kestrel/rules
```

**Solutions:**

1. **Add Exception**
   ```eql
   process where
     process.executable == "/usr/bin/dockerd"
     and not user.id == 0  # Ignore root
   ```

2. **Refine Condition**
   ```eql
   # Too broad
   process where process.executable contains "curl"

   # More specific
   process where
     process.executable contains "curl"
     and process.command_line contains "http://suspicious.com"
   ```

3. **Add Context**
   ```eql
   sequence by process.entity_id
     [process where process.executable == "/bin/bash"]
     [file where file.path == "/etc/passwd"]
     with maxspan=5s
   ```

---

### Problem: False Negatives

**Symptoms:**
- Attack not detected
- Expected alert not generated

**Diagnosis:**
```bash
# Check if rule loaded
kestrel list --rules /opt/kestrel/rules

# Test with attack event
echo 'ATTACK_EVENT_JSON' | kestrel test --rules /opt/kestrel/rules

# Check logs for errors
sudo journalctl -u kestrel -p err
```

**Common Causes:**

1. **Wrong Event Type**
   - Verify event type matches
   - Check schema mapping

2. **Predicate Too Strict**
   ```eql
   # Too strict
   process where
     process.executable == "/usr/bin/curl"
     and process.command_line == "exact match required"

   # More flexible
   process where
     process.executable == "/usr/bin/curl"
     and process.command_line contains "suspicious"
   ```

3. **Timing Window**
   ```eql
   sequence with maxspan=5s  # Increase window
   ```

## eBPF Issues

### Problem: eBPF Program Fails to Load

**Error:**
```
Error: Failed to load eBPF program: Permission denied
```

**Diagnosis:**
```bash
# Check capabilities
sudo capsh --print | grep CAP_BPF

# Check kernel
uname -r
```

**Solutions:**

1. **Missing Capability**
   ```bash
   # Run with root
   sudo kestrel run

   # Or add capability
   sudo setcap cap_bpf+ep /usr/local/bin/kestrel
   ```

2. **Kernel Too Old**
   ```bash
   # Need 5.10+
   uname -r  # If < 5.10, upgrade kernel
   ```

3. **BTF Not Available**
   ```bash
   # Check BTF
   sudo bpftool btf show

   # Install BTF info
   sudo apt-get install linux-headers-$(uname -r)
   ```

---

### Problem: No Events from eBPF

**Symptoms:**
- eBPF loaded but no events
- Metrics show 0 EPS

**Diagnosis:**
```bash
# Check eBPF programs loaded
sudo bpftool prog show

# Check ring buffer
sudo bpftool map show

# Check logs
sudo journalctl -u kestrel --grep="eBPF"
```

**Solutions:**

1. **Program Not Attached**
   ```bash
   # Verify tracepoints exist
   sudo cat /sys/kernel/debug/tracing/available_events | grep execve
   ```

2. **Ring Buffer Not Polling**
   ```bash
   # Check if polling thread started
   sudo journalctl -u kestrel --grep="ringbuf"
   ```

3. **Interest Pushdown**
   - Verify event types in interest list
   - Check eBPF filter logic

## Networking Issues

### Problem: Metrics Endpoint Not Accessible

**Error:**
```
curl: (7) Failed to connect to localhost port 9090
```

**Diagnosis:**
```bash
# Check if metrics enabled
grep -A5 '\[performance\]' /etc/kestrel/config.toml

# Check if port in use
sudo lsof -i :9090
```

**Solution:**
```toml
[performance]
metrics_enabled = true
metrics_port = 9090
metrics_host = "0.0.0.0"
```

---

### Problem: Remote Syslog Not Sending

**Diagnosis:**
```bash
# Test syslog
logger -n syslog.example.com -P 514 "Test message"

# Check firewall
sudo iptables -L -n | grep 514
```

**Solution:**
```bash
# Allow syslog outbound
sudo iptables -A OUTPUT -p udp --dport 514 -j ACCEPT

# Or use local syslog
# Kestrel -> local syslog -> remote relay
```

## Getting Help

### Debug Mode

Enable verbose logging:

```bash
kestrel run --rules /opt/kestrel/rules --log-level trace
```

### Collect Diagnostics

```bash
#!/bin/bash
# collect-diagnostics.sh

OUTPUT="kestrel-diags-$(date +%Y%m%d-%H%M%S).tar.gz"

echo "Collecting Kestrel diagnostics..."

# Version
kestrel --version > version.txt

# Config
cp /etc/kestrel/config.toml config.toml

# Logs
journalctl -u kestrel -n 1000 > kestrel.log

# Metrics
curl -s http://localhost:9090/metrics > metrics.txt

# Rules
ls -la /opt/kestrel/rules/ > rules-list.txt

# System Info
uname -a > system.txt
rustc --version >> system.txt
cargo --version >> system.txt

# Package
tar czf $OUTPUT \
  version.txt \
  config.toml \
  kestrel.log \
  metrics.txt \
  rules-list.txt \
  system.txt

echo "Diagnostics saved to: $OUTPUT"
```

### Community Support

- **GitHub Discussions**: https://github.com/kestrel-detection/kestrel/discussions
- **GitHub Issues**: https://github.com/kestrel-detection/kestrel/issues
- **Security Issues**: security@kestrel-detection.org

### When Reporting Issues

Include:

1. **Kestrel Version**: `kestrel --version`
2. **OS/Kernel**: `uname -a`
3. **Rust Version**: `rustc --version`
3. **Configuration**: (sanitize sensitive data)
4. **Error Messages**: Full stack traces
5. **Steps to Reproduce**: Minimal reproduction case
6. **Diagnostics**: Attach collected diagnostics tarball

### Escalation Path

1. Check documentation and this guide
2. Search GitHub Issues/Discussions
3. Create new issue with diagnostics
4. For security issues, email directly

---

**Last Updated**: 2025-01-12
**Kestrel Version**: 1.0.0
