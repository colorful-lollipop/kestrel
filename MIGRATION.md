# Migration Guide

This guide helps you migrate between versions of Kestrel.

## Version 0.2.0 → 0.3.0 (Future)

**Status**: Not yet released

### Breaking Changes

#### 1. Event Schema Changes

Field names have been normalized for consistency:

```diff
- process.executable
+ process.executable.path

- file.path
+ file.path.full

- network.destination
+ network.destination.address
```

**Migration**: Update your rules to use new field names.

**Script**:
```bash
# Automatic migration tool
cargo run --bin migrate-rules -- --old 0.2 --new 0.3 --rules /path/to/rules
```

#### 2. Configuration File Changes

Configuration file format has changed from YAML to TOML:

**Old format (`config.yaml`)**:
```yaml
logging:
  level: "info"
  format: "json"
```

**New format (`config.toml`)**:
```toml
[logging]
level = "info"
format = "json"
```

**Migration**: Convert your YAML configs to TOML, or use the migration tool.

#### 3. API Changes

Some public APIs have changed:

```rust
// Old
let event = Event::new(event_type, timestamp);

// New
let event = Event::builder()
    .event_type(event_type)
    .timestamp(timestamp)
    .build();
```

**Migration**: Update your code to use the builder pattern.

### Deprecated Features

- **Legacy rule format**: Pre-EQL JSON rules are deprecated
- **Python runtime**: Removed (use Wasm or LuaJIT)
- **Old CLI commands**: `kestrel daemon` → `kestrel run`

### New Features

- **Enhanced EQL support**: More query types and operators
- **Performance improvements**: 2x faster in some scenarios
- **Better error messages**: More helpful diagnostics

---

## Version 0.1.0 → 0.2.0

**Status**: Current version

### What Changed

#### 1. Initial Stable Release

This is the first stable release of Kestrel. Key features:
- ✅ Complete EQL compiler and runtime
- ✅ eBPF event collection
- ✅ Wasm and LuaJIT runtimes
- ✅ Real-time blocking capabilities
- ✅ Offline replay support

#### 2. Configuration

Initial configuration support:
- `/etc/kestrel/config.toml`
- Environment variable support
- Command-line overrides

#### 3. Rule Management

- Hot-reload without restart
- Rule validation and testing
- Multi-source rule loading

### Migration from Development Versions

If you were using pre-0.1.0 development versions:

1. **Backup your data**:
   ```bash
   cp -r /var/lib/kestrel /var/lib/kestrel.backup
   ```

2. **Update configuration**:
   - Old `~/.kestrel/config` → `/etc/kestrel/config.toml`
   - See [docs/deployment.md](docs/deployment.md) for new format

3. **Update rules**:
   - Run `kestrel validate --migrate` to check rule compatibility
   - Update deprecated field names and operators

4. **Test thoroughly**:
   ```bash
   kestrel run --dry-run --rules /path/to/rules
   ```

5. **Deploy**:
   ```bash
   sudo systemctl restart kestrel
   ```

---

## Pre-Release Versions

### Migrating from Alpha/Beta/RC Versions

If you're using alpha, beta, or RC versions:

1. **Check the CHANGELOG**:
   Review [CHANGELOG.md](CHANGELOG.md) for specific changes

2. **Export your rules**:
   ```bash
   kestrel export-rules --output rules_backup.json
   ```

3. **Upgrade**:
   ```bash
   cargo install kestrel --force
   # or
   sudo apt upgrade kestrel
   ```

4. **Re-import rules**:
   ```bash
   kestrel import-rules --input rules_backup.json
   ```

5. **Validate**:
   ```bash
   kestrel validate --all
   ```

---

## Data Migration

### Event Logs

Kestrel event logs are **backward compatible**. Old logs can be replayed with new versions.

**However**, note that:
- New fields may be added (old logs will use defaults)
- Field types won't change (breaking compatibility)
- Removed fields are ignored

### State Snapshots

If you're using state persistence (experimental):

```bash
# Export state from old version
kestrel export-state --output state_backup.json

# Import to new version
kestrel import-state --input state_backup.json
```

---

## Rule Migration

### Field Name Changes

Use the `kestrel migrate` tool to update rules:

```bash
# Interactive migration
kestrel migrate-rules --rules /path/to/rules --interactive

# Automatic migration
kestrel migrate-rules --rules /path/to/rules --auto --backup
```

### Syntax Changes

#### EQL Query Syntax

**Old syntax**:
```eql
process where exe = "/bin/bash"
```

**New syntax**:
```eql
process where process.executable == "/bin/bash"
```

#### Time Windows

**Old syntax**:
```eql
sequence with maxspan=5000
```

**New syntax**:
```eql
sequence with maxspan=5s
```

---

## Configuration Migration

### Automatic Migration

Kestrel provides automatic migration for configuration:

```bash
kestrel migrate-config --from 0.2 --to 0.3
```

### Manual Migration

Edit `/etc/kestrel/config.toml`:

```toml
# Check for deprecated options
# See documentation for new options

[engine]
# Old setting
event_buffer_size = 10000

# New setting (replaced)
# event_buffer_size → buffer.event_size
buffer.event_size = 10000
```

---

## Rollback Plan

If you need to rollback:

1. **Stop Kestrel**:
   ```bash
   sudo systemctl stop kestrel
   ```

2. **Restore from backup**:
   ```bash
   sudo cp -r /var/lib/kestrel.backup /var/lib/kestrel
   ```

3. **Restore old binary**:
   ```bash
   cargo install kestrel --version 0.2.0 --force
   # or
   sudo apt install kestrel=0.2.0
   ```

4. **Restart**:
   ```bash
   sudo systemctl start kestrel
   ```

---

## Testing Your Migration

### Dry Run Mode

Test without affecting production:

```bash
kestrel run \
  --rules /path/to/new/rules \
  --config /path/to/new/config \
  --dry-run \
  --duration 5m
```

### Validation Tools

```bash
# Validate configuration
kestrel validate-config

# Validate rules
kestrel validate-rules --rules /path/to/rules

# Test with sample data
kestrel test --rules /path/to/rules --events /path/to/test_events.json
```

---

## Known Migration Issues

### Issue: eBPF verifier fails

**Symptom**: eBPF program fails to load after upgrade.

**Solution**:
- Ensure kernel compatibility (5.10+)
- Update eBPF programs: `kestrel rebuild-ebpf`
- Check `dmesg` for verifier errors

### Issue: Rules don't match

**Symptom**: Previously matching rules no longer trigger.

**Solution**:
- Validate rules: `kestrel validate-rules`
- Check field names in schema
- Review rule logic for deprecated features

### Issue: Performance degradation

**Symptom**: Slower performance after upgrade.

**Solution**:
- Rebuild in release mode
- Check configuration defaults
- Review performance tuning guide

---

## Getting Help

If you encounter issues during migration:

1. **Check this guide** for known issues
2. **Review CHANGELOG.md** for version changes
3. **Search GitHub Issues** for similar problems
4. **Ask in GitHub Discussions**
5. **File an issue** if you find a bug

---

## Planning for Upgrades

### Before Upgrading

1. **Read the release notes** thoroughly
2. **Test in a staging environment** first
3. **Backup your data and configuration**
4. **Schedule a maintenance window** if needed
5. **Prepare a rollback plan**

### During Upgrade

1. **Stop the service** gracefully
2. **Install the new version**
3. **Migrate configuration** if needed
4. **Validate rules** with new version
5. **Start the service** and monitor logs

### After Upgrade

1. **Verify alerts are firing** as expected
2. **Check performance metrics**
3. **Monitor error logs** for issues
4. **Update documentation** and runbooks

---

**Need more help?**

- **FAQ**: See [FAQ.md](FAQ.md)
- **Support**: See [SUPPORT.md](SUPPORT.md)
- **Issues**: [GitHub Issues](https://github.com/kestrel-detection/kestrel/issues)

**Last Updated**: 2025-01-14
