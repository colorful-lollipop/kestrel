# Phase B-5: Rule Performance Monitoring CLI

**Priority**: P1-High
**Estimated Time**: 1-2 weeks
**Complexity**: Medium
**Added**: 2026-01-12 (New requirement from user)

---

## Task Specification

### 1. DESCRIPTION
Create a `kestrel-perf` CLI tool similar to Linux `top` that provides real-time monitoring and profiling of all loaded rules (Lua scripts, EQL rules, Wasm predicates).

### 2. PROBLEM STATEMENT
**Current Gap**:
- No visibility into per-rule memory usage
- No performance metrics per predicate
- Can't identify which rules are slow
- Can't track event hit rates per rule
- No alert rate monitoring

**User Need**:
"我们的lua脚本或者eql都会被执行，我想我们应该有一个评估系统，看下每个脚本占用的内存，性能，平均存在事件等指标。一个简单的类似top的cli就行"

Translation: "Our Lua scripts or EQL will all be executed, I think we should have an evaluation system to see the memory used by each script, performance, average existing events and other metrics. A simple CLI similar to top is fine."

### 3. REQUIRED FEATURES

#### Core Features (MVP)
1. **Real-time Dashboard** (top-like interface)
   - Sortable by CPU/memory/events
   - Auto-refresh every 1-5 seconds
   - Color-coded severity (red=high usage, yellow=medium, green=low)

2. **Per-Rule Metrics**
   - **Memory Usage**: Current and peak memory per rule
   - **CPU Time**: Total CPU time spent on each rule
   - **Event Hits**: Total events processed by each rule
   - **Alert Rate**: Alerts generated / events processed
   - **Avg Latency**: Average evaluation time per event (μs)
   - **Last Hit**: Timestamp of last event match

3. **Rule Categories**
   - Lua scripts (kestrel-runtime-lua)
   - EQL rules (kestrel-engine single-event)
   - Sequences (kestrel-nfa)
   - Wasm predicates (kestrel-runtime-wasm)

4. **Interactive Controls**
   - `r` - Refresh metrics
   - `q` - Quit
   - `s` - Sort by metric (CPU/Memory/Events)
   - `1-9` - Toggle rule category filter

5. **Historical Mode** (optional)
   - `--dump` - Export metrics to JSON/CSV
   - `--since` - Show metrics from time range
   - `--top-n` - Show top N rules by metric

### 4. EXPECTED OUTCOME
- `kestrel-perf` binary in kestrel-cli
- Real-time monitoring of all loaded rules
- Ability to identify performance bottlenecks
- Memory leak detection (rules growing over time)
- Performance optimization guidance

### 5. REQUIRED SKILLS
- Rust CLI development (clap/crossterm for TUI)
- Async programming (tokio)
- Metrics collection and aggregation
- Terminal UI (termion/crossterm)
- Engine integration (detection engine hooks)

### 6. REQUIRED TOOLS
- Read tool: Understand engine metrics APIs
- Write tool: Create new CLI binary
- Bash tool: Build and test

### 7. MUST DO

#### Implementation Steps

**Step 1: Design Metrics API**
```rust
// Add to kestrel-engine/src/lib.rs
pub struct RuleMetrics {
    pub rule_id: String,
    pub rule_type: RuleType,  // Lua, EQL, Sequence, Wasm
    pub memory_bytes: u64,      // Current memory usage
    pub peak_memory_bytes: u64,  // Peak memory usage
    pub cpu_time_ns: u64,       // Total CPU time spent
    pub events_processed: u64,  // Total events seen
    pub alerts_generated: u64,   // Total alerts from this rule
    pub avg_latency_ns: u64,    // Average evaluation time
    pub last_hit_ns: u64,       // Timestamp of last match
}

pub type RuleMetricsMap = HashMap<String, RuleMetrics>;
```

**Step 2: Extend DetectionEngine**
```rust
// In kestrel-engine/src/lib.rs
pub struct DetectionEngine {
    // ... existing fields ...
    pub rule_metrics: Arc<RwLock<RuleMetricsMap>>,
}

impl DetectionEngine {
    pub fn get_all_metrics(&self) -> RuleMetricsMap {
        self.rule_metrics.read().unwrap().clone()
    }

    pub fn get_metrics(&self, rule_id: &str) -> Option<RuleMetrics> {
        self.rule_metrics.read().unwrap().get(rule_id).cloned()
    }

    // Call this after each predicate evaluation
    fn record_predicate_eval(&self, rule_id: &str, latency_ns: u64) {
        // Update CPU time, avg latency, events processed
    }

    // Call this after each alert generation
    fn record_alert(&self, rule_id: &str) {
        // Update alerts_generated, alert rate
    }
}
```

**Step 3: Add Memory Tracking to Runtimes**

**Lua Runtime (kestrel-runtime-lua/src/lib.rs)**:
```rust
pub struct LuaEngine {
    // ... existing fields ...
    metrics_per_predicate: Arc<RwLock<HashMap<String, LuaMetrics>>>,
}

pub struct LuaMetrics {
    pub memory_bytes: u64,
    pub peak_memory_bytes: u64,
}

impl LuaEngine {
    pub fn get_memory_usage(&self, predicate_id: &str) -> Option<u64> {
        self.metrics_per_predicate.read().unwrap()
            .get(predicate_id)
            .map(|m| m.memory_bytes)
    }

    // Track memory allocation/deallocation
    fn track_memory(&self, predicate_id: &str, delta: i64) {
        // Update memory counters
    }
}
```

**Wasm Runtime (kestrel-runtime-wasm/src/lib.rs)**:
```rust
pub struct WasmEngine {
    // ... existing fields ...
    metrics_per_predicate: Arc<RwLock<HashMap<String, WasmMetrics>>>,
}

pub struct WasmMetrics {
    pub memory_bytes: u64,
    pub peak_memory_bytes: u64,
    pub fuel_consumed: u64,  // Track fuel usage
}

impl WasmEngine {
    pub fn get_memory_usage(&self, predicate_id: &str) -> Option<u64> {
        self.metrics_per_predicate.read().unwrap()
            .get(predicate_id)
            .map(|m| m.memory_bytes)
    }
}
```

**Step 4: Create CLI Tool**

**New file: kestrel-cli/src/perf.rs**
```rust
use clap::{Parser, Subcommand};
use crossterm::{execute, style, Stylize};
use tokio::time::{interval, Duration};

#[derive(Parser, Debug)]
#[command(name = "kestrel-perf")]
#[command(about = "Real-time rule performance monitoring (like top)", long_about = None)]
struct Opt {
    /// Refresh interval in seconds (default: 2)
    #[arg(short, long, default_value = "2")]
    interval: u64,

    /// Sort by metric (cpu|memory|events|alerts|latency)
    #[arg(short, long, default_value = "cpu")]
    sort: String,

    /// Filter by rule type (lua|eql|sequence|wasm|all)
    #[arg(short, long, default_value = "all")]
    filter: String,

    /// Show top N rules (default: 10)
    #[arg(short, long, default_value = "10")]
    top_n: usize,

    /// Export metrics to file
    #[arg(short, long, value_name = "FILE")]
    dump: Option<PathBuf>,

    /// Show metrics since timestamp (RFC3339)
    #[arg(long, value_name = "TIMESTAMP")]
    since: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::parse();

    if let Some(dump_file) = opt.dump {
        // Export mode
        export_metrics(dump_file, opt.filter).await?;
        return Ok(());
    }

    // Real-time monitoring mode
    run_monitor(opt).await
}

async fn run_monitor(opt: Opt) -> Result<(), Box<dyn std::error::Error>> {
    let mut interval = interval(Duration::from_secs(opt.interval));
    let mut engine = connect_to_engine().await?;

    // Terminal setup
    execute!(terminal::enable_raw_mode())?;

    loop {
        // Fetch metrics
        let metrics = engine.get_all_metrics().await?;

        // Filter and sort
        let mut filtered = filter_metrics(metrics, &opt.filter);
        sort_metrics(&mut filtered, &opt.sort);
        filtered.truncate(opt.top_n);

        // Clear screen and render
        execute!(terminal::clear(terminal::ClearType::All))?;
        render_dashboard(&filtered, &opt)?;

        // Wait for user input or refresh
        tokio::select! {
            _ = interval.tick() => continue,
            input = read_user_input() => {
                match input? {
                    Input::Quit => break,
                    Input::Refresh => continue,
                    Input::Sort(sort_key) => {
                        opt.sort = sort_key;
                    }
                    _ => {}
                }
            }
        }
    }

    execute!(terminal::disable_raw_mode())?;
    Ok(())
}

fn render_dashboard(metrics: &[(String, RuleMetrics)], opt: &Opt) -> Result<(), Box<dyn std::error::Error>> {
    // Header
    let header = format!(
        "{}{}",
        style("Kestrel Rule Performance Monitor").bold(),
        style(format!(" Interval: {}s | Sort: {} | Filter: {}",
            opt.interval, opt.sort, opt.filter)).dim()
    );
    println!("{}", header);
    println!();

    // Table header
    println!(
        "{:<5} {:<20} {:<10} {:<12} {:<12} {:<12} {:<10} {:<10} {:<10} {:<10}",
        "#", "Rule ID", "Type", "Memory", "Peak", "CPU (ns)", "Events", "Alerts", "Avg Lat", "Last Hit"
    );
    println!("{}", "-".repeat(120));

    // Metrics rows
    for (idx, (rule_id, m)) in metrics.iter().enumerate() {
        let memory_mb = format!("{:.2}", m.memory_bytes as f64 / 1024.0 / 1024.0);
        let peak_mb = format!("{:.2}", m.peak_memory_bytes as f64 / 1024.0 / 1024.0);
        let cpu_ms = format!("{:.2}", m.cpu_time_ns as f64 / 1_000_000.0);
        let alert_rate = if m.events_processed > 0 {
            format!("{:.2}%", (m.alerts_generated as f64 / m.events_processed as f64) * 100.0)
        } else {
            "N/A".to_string()
        };
        let avg_lat = format!("{:.2}", m.avg_latency_ns as f64 / 1000.0);
        let last_hit = if m.last_hit_ns > 0 {
            format_timestamp(m.last_hit_ns)
        } else {
            "Never".to_string()
        };

        // Color code by severity
        let row = style(format!(
            "{:<5} {:<20} {:<10} {:<12} {:<12} {:<12} {:<10} {:<10} {:<10} {:<10} {:<10}",
            idx + 1,
            rule_id,
            format!("{:?}", m.rule_type),
            memory_mb,
            peak_mb,
            cpu_ms,
            m.events_processed,
            m.alerts_generated,
            avg_lat,
            last_hit
        ));

        println!("{}", row);
    }

    println!();
    println!("Controls: [r] Refresh | [q] Quit | [s] Sort | [1-9] Filter");
    Ok(())
}

fn format_timestamp(ns: u64) -> String {
    let dt = DateTime::from_timestamp(ns as i64 / 1_000_000_000, 0);
    dt.format("%H:%M:%S").to_string()
}
```

**Step 5: Integrate into kestrel-cli**
```toml
# kestrel-cli/Cargo.toml
[dependencies]
crossterm = "0.27"
tokio = { version = "1", features = ["full"] }
chrono = "0.4"

[[bin]]
name = "kestrel-perf"
path = "src/perf.rs"
```

**Step 6: Add Metrics Collection Points**

In `kestrel-engine/src/lib.rs`, add metrics tracking:
```rust
impl DetectionEngine {
    async fn eval_event(&mut self, event: Event) -> Result<Vec<Alert>, EngineError> {
        let start = Instant::now();

        // Single-event rules
        for rule in self.single_event_rules.iter() {
            let rule_start = Instant::now();

            let matched = self.eval_single_event_rule(rule, &event).await?;

            let latency = rule_start.elapsed().as_nanos();
            self.record_predicate_eval(&rule.rule_id, latency);

            if matched {
                self.record_alert(&rule.rule_id);
            }
        }

        // Sequence rules via NFA
        let nfa_start = Instant::now();
        let sequence_matches = self.nfa_engine.process_event(&event)?;
        let nfa_latency = nfa_start.elapsed().as_nanos();

        for match in sequence_matches {
            // Track sequence evaluation
            self.record_sequence_eval(&match.sequence_id, nfa_latency);
        }

        Ok(alerts)
    }
}
```

**Step 7: Add Tests**
```rust
// kestrel-engine/tests/perf_monitoring.rs
#[tokio::test]
async fn test_metrics_collection() {
    // Create engine, process events
    // Verify metrics are tracked correctly
    let metrics = engine.get_all_metrics();
    assert!(metrics.len() > 0);
}

#[tokio::test]
async fn test_memory_tracking() {
    // Load Lua/Wasm rules
    // Process many events
    // Verify memory usage is tracked
    // Check for leaks (memory growing)
}
```

### 8. MUST NOT DO
- Do not modify existing detection logic (only add metrics hooks)
- Do not break existing engine APIs
- Do not add new dependencies without justification
- Do not create complex UI (keep top-like simplicity)
- Do not store historical metrics in memory (use disk if needed)

### 9. CONTEXT

**Project**: Kestrel - Next-generation endpoint behavior detection engine
**Current State**:
- Phase 0-5 complete
- Rules executed via Lua/EQL/Sequences/Wasm
- No performance visibility into individual rules

**User Need**:
Real-time monitoring tool to:
1. See per-rule memory usage
2. See per-rule performance (CPU time, latency)
3. See event hit rates and alert rates
4. Identify slow or memory-hungry rules
5. Simple interface like Linux `top`

**Inspiration**: Linux `top`, `htop`, Docker stats interfaces

### 10. SUCCESS CRITERIA

- [ ] `kestrel-perf` CLI tool builds and runs
- [ ] Real-time dashboard displays 10+ rules
- [ ] Metrics updated every 2 seconds
- [ ] Sortable by CPU/Memory/Events
- [ ] Filterable by rule type (Lua/EQL/Sequence/Wasm)
- [ ] Export mode works (`--dump` flag)
- [ ] Memory tracking accurate for Lua/Wasm
- [ ] CPU time tracking per rule
- [ ] Alert rate calculation correct
- [ ] No performance impact from monitoring (<1% overhead)

### 11. EXAMPLE OUTPUT

**Real-time Dashboard**:
```
Kestrel Rule Performance Monitor         Interval: 2s | Sort: cpu | Filter: all

#    Rule ID              Type      Memory    Peak       CPU (ns)   Events   Alerts   Avg Lat  Last Hit
--------------------------------------------------------------------------------------------
1    suspicious-exec        EQL       1.23 MB   1.45 MB    1,234,567  10,000    45       123.4    12:34:56
2    privilege-esc       Sequence  2.45 MB   3.12 MB    2,345,678  5,000     12       456.7    12:34:55
3    lua-script-001      Lua       0.45 MB   0.67 MB      567,890    2,000     8        234.5    12:34:56
4    wasm-pred-007       Wasm      0.78 MB   0.89 MB      890,123    8,500     123      45.6     12:34:57
5    file-access-monitor  EQL       0.12 MB   0.15 MB      234,567    15,000    23       12.3     12:34:58

Controls: [r] Refresh | [q] Quit | [s] Sort | [1-9] Filter
```

**Export Mode**:
```bash
$ kestrel-perf --dump metrics.json
Wrote metrics to metrics.json

$ cat metrics.json
{
  "timestamp": "2026-01-12T07:30:00Z",
  "rules": [
    {
      "rule_id": "suspicious-exec",
      "type": "EQL",
      "memory_bytes": 1287654,
      "peak_memory_bytes": 1519246,
      "cpu_time_ns": 1234567,
      "events_processed": 10000,
      "alerts_generated": 45,
      "avg_latency_ns": 123400,
      "last_hit_ns": 1736649696000000
    },
    ...
  ]
}
```

### 12. DEPENDENCIES

**On Phase A**:
- A-1: NFA fix (no direct dependency)
- A-2: Documentation (no dependency)
- A-3: Tests pass (no dependency)

**On Phase B**:
- None (can be done in parallel with CI/CD, benchmarks)

**Required Before**:
- DetectionEngine API is stable
- Metrics collection hooks in place

### 13. ESTIMATED TIME

- **Design**: 1 day (metrics API, data structures)
- **Implementation**: 5-7 days (CLI, integration, tests)
- **Testing**: 1-2 days (unit tests, integration tests)
- **Documentation**: 0.5 day (README, usage examples)
- **Total**: **7.5-10.5 days**

### 14. ROLLBACK PLAN

If issues arise:
```bash
# Remove CLI binary
cargo rm --bin kestrel-perf

# Remove metrics tracking code from engines
git checkout kestrel-engine/src/lib.rs
git checkout kestrel-runtime-lua/src/lib.rs
git checkout kestrel-runtime-wasm/src/lib.rs
```

---

## Additional Considerations

### Performance Impact
Monitoring overhead should be <1% of total engine time:
- Metrics collection: Atomic increment only (fast)
- Memory tracking: Only on allocation/deallocation (infrequent)
- Dashboard update: Separate thread, doesn't block detection

### Privacy/Security
- Metrics don't include event payloads (only counts/timings)
- Safe to share externally
- No sensitive data leakage risk

### Future Enhancements
- Web UI dashboard (beyond CLI)
- Historical metrics storage (database)
- Alerting on metrics anomalies (rule using >100MB, etc.)
- Comparison dashboard (before/after optimization)
- Per-rule performance profiling (hotspot identification)
