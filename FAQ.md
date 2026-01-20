# Frequently Asked Questions (FAQ)

## General Questions

### What is Kestrel?

Kestrel is a next-generation endpoint behavioral detection engine written in Rust. It uses eBPF for kernel-level event collection, NFA (Non-deterministic Finite Automaton) for sequence detection, and supports both Wasm and LuaJIT runtimes for rule execution.

### What operating systems does Kestrel support?

Kestrel is designed for Linux and HarmonyOS (Unix-like systems). It requires Linux kernel 5.10+ for eBPF support.

### What is the license?

Kestrel is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## Installation and Setup

### How do I install Kestrel?

See the [Installation Guide](README.md#installation) in the README.

```bash
git clone https://github.com/kestrel-detection/kestrel.git
cd Kestrel
cargo build --release
```

### What are the system requirements?

- **Rust**: 1.82 or later
- **Kernel**: Linux 5.10+ (for eBPF features)
- **Memory**: Minimum 512MB RAM (2GB+ recommended for production)
- **CPU**: Any modern 64-bit processor (x86_64 or ARM64)

### Why does compilation fail with eBPF errors?

eBPF compilation requires clang and LLVM development tools:

```bash
# Ubuntu/Debian
sudo apt-get install clang llvm libelf-dev

# Fedora/RHEL
sudo dnf install clang llvm elfutils-libelf-devel
```

## Configuration

### How do I configure Kestrel?

Configuration files are located in:
- `/etc/kestrel/config.toml` (Linux)
- `~/.kestrel/config.toml` (user-level)

See [Configuration Guide](docs/deployment.md) for details.

### How do I load rules?

```bash
# Run with default rules directory
kestrel run

# Specify custom rules directory
kestrel run --rules /path/to/rules

# Load specific rule file
kestrel run --rules /path/to/rule.json
```

### How do I set log levels?

```bash
kestrel run --log-level debug
kestrel run --log-level info
kestrel run --log-level warn
kestrel run --log-level error
```

## Performance

### What is the event throughput?

Kestrel is designed to handle **10,000+ events per second (EPS)** on modern hardware. See [Performance Benchmarks](docs/benchmark_results.md) for detailed metrics.

### How much memory does Kestrel use?

- **Idle**: < 50MB
- **Active (1k EPS)**: < 200MB
- **Active (10k EPS)**: < 500MB

Memory usage depends on the number of active rules and state retention.

### How can I improve performance?

1. **Optimize rules**: Reduce rule complexity
2. **Filter events**: Use event source filtering
3. **Adjust state TTL**: Reduce state retention time
4. **Use release builds**: Always use `--release` mode
5. **Tune worker threads**: Match CPU core count

See [Performance Tuning Guide](docs/performance-analysis.md) for more details.

## Rules and Detection

### What rule formats does Kestrel support?

- **EQL** (Elastic Query Language) - Primary format
- **JSON** - Structured rule definition
- **YAML** - Human-readable format

See [Rule Examples](examples/) for details.

### How do I write a rule?

See the [Rule Writing Guide](examples/basic_usage.md) and [EQL Reference](docs/api.md).

**Example EQL rule**:
```eql
sequence by process.entity_id
  [process where process.executable == "/bin/bash"]
  [file where file.path == "/etc/passwd"]
  [network where network.destination == "malicious.com"]
with maxspan=30s
```

### How do I test my rules?

```bash
# Test rule syntax
kestrel validate /path/to/rule.eql

# Test with sample events
kestrel test --rule /path/to/rule.eql --events /path/to/events.json
```

### What events can Kestrel detect?

Kestrel can detect:
- **Process events**: execution, termination, privilege changes
- **File events**: create, read, write, delete, rename
- **Network events**: connections, DNS queries
- **System events**: logins, privilege escalations

See [Event Schema](docs/api.md#event-schema) for the complete list.

## Troubleshooting

### Why am I not seeing any alerts?

Check the following:
1. **Rules are loaded**: `kestrel list-rules`
2. **Events are received**: Check logs with `--log-level debug`
3. **Rule conditions**: Verify rule logic matches your events
4. **Action policy**: Ensure alerts aren't being suppressed

See [Troubleshooting Guide](docs/troubleshooting.md) for more details.

### Why is Kestrel using high CPU?

Possible causes:
- **High event rate**: Reduce event sources or filter events
- **Complex rules**: Simplify rule conditions
- **State explosion**: Reduce state TTL or increase cleanup interval
- **Debug build**: Ensure you're using release mode

### How do I enable debug logging?

```bash
# Temporary
kestrel run --log-level debug

# Permanent (config.toml)
[logging]
level = "debug"
```

### Why do eBPF programs fail to load?

Common causes:
- **Kernel version**: Requires 5.10+ (check with `uname -r`)
- **Permissions**: Run with `sudo` or configure capabilities
- **BTF support**: Some kernels require BTF (check with `ls /sys/kernel/btf/vmlinux`)
- **SELinux**: May block eBPF loading (check audit logs)

## Integration

### How do I integrate Kestrel with SIEM?

Kestrel supports multiple output formats:
- **JSON**: Standard JSON output
- **Syslog**: RFC 5424 format
- **Elasticsearch**: Direct indexing

See [Integration Guide](docs/deployment.md#integration) for details.

### Can I use Kestrel with existing EQL rules?

Yes! Kestrel supports a subset of Elastic EQL. Most EQL rules work with minimal changes:
- Convert field names to Kestrel schema
- Adjust time window syntax
- Test thoroughly before production use

### Does Kestrel support blocking actions?

Yes! Kestrel supports:
- **Process blocking**: Prevent process execution
- **File blocking**: Prevent file operations
- **Network blocking**: Prevent network connections

See [Action System](docs/api.md#actions) for details.

**Note**: Blocking requires proper permissions and configuration.

## Development

### How do I contribute?

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution guide.

### How do I run tests?

```bash
# All tests
cargo test --workspace

# Specific crate
cargo test -p kestrel-engine

# With output
cargo test --workspace -- --nocapture

# Run benchmarks
cargo test -p kestrel-benchmark --bench '*' --release
```

### How do I build documentation?

```bash
# Build locally
cargo doc --workspace --open

# View online
# https://kestrel-detection.github.io/kestrel/
```

### What are the coding standards?

- **Rust style**: Follow `cargo fmt` output
- **Linter**: Pass `cargo clippy` with no warnings
- **Documentation**: Public APIs must have rustdoc comments
- **Tests**: All code must have tests (aim for >80% coverage)

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Security

### Is Kestrel safe to run in production?

Yes! Kestrel is designed with security in mind:
- **Memory safe**: Written in Rust
- **Privilege separation**: Minimal privileges for eBPF
- **Sandboxed runtimes**: Wasm and Lua are isolated
- **Audited code**: Regular security reviews

See [Security Policy](SECURITY.md) for details.

### How do I report a security vulnerability?

**DO NOT** file a public issue. See [SECURITY.md](SECURITY.md#reporting-a-vulnerability) for secure reporting.

### What data does Kestrel collect?

Kestrel processes system events locally. It does not:
- Send data to remote servers
- Collect personal information beyond system events
- Store sensitive data beyond what's needed for detection

## Support

### Where can I get help?

- **Documentation**: Start with [README.md](README.md) and [docs/](docs/)
- **GitHub Discussions**: Ask questions in [Discussions](https://github.com/kestrel-detection/kestrel/discussions)
- **GitHub Issues**: Report bugs in [Issues](https://github.com/kestrel-detection/kestrel/issues)
- **Security Issues**: See [SECURITY.md](SECURITY.md)

### Is commercial support available?

Currently, Kestrel does not offer official commercial support. See [SUPPORT.md](SUPPORT.md) for community support options.

### How do I stay updated?

- **Watch the repository**: Get notified of releases
- **Join Discussions**: Participate in community discussions
- **Read CHANGELOG.md**: Track version changes
- **Follow the roadmap**: Check [README.md](README.md#roadmap)

---

**Still have questions?**

- Open a [GitHub Discussion](https://github.com/kestrel-detection/kestrel/discussions)
- Ask in a [GitHub Issue](https://github.com/kestrel-detection/kestrel/issues)
- Check the [Documentation](docs/)

**Last Updated**: 2025-01-14
