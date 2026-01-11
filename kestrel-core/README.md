# Kestrel Core Services

**Core Layer - Event Bus, Time Management, Alert System**

## Module Goal

Provide essential runtime services for the detection engine:
- **EventBus**: Multi-partition event distribution with backpressure
- **TimeManager**: Monotonic clock abstraction for reproducibility
- **AlertOutput**: Alert dispatch to various outputs
- **Replay**: Event replay from recorded logs

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      EventBus                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Partition 0 ───┬──→ Worker 0                        │   │
│  │                 │    ┌─────────────────────────┐    │   │
│  │ Partition 1 ────┼──→ Worker 1 (NFA Engine)    │    │   │
│  │                 │    └─────────────────────────┘    │   │
│  │ Partition N ────┴──→ Worker N                        │   │
│  │                 │                                    │   │
│  │ Backpressure ───┴──→ Drop/Block Strategy            │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  TimeManager ──→ Mock Time (Testing) / System Time         │
├─────────────────────────────────────────────────────────────┤
│  AlertOutput ──→ Console / File / SIEM / Webhook           │
├─────────────────────────────────────────────────────────────┤
│  Replay ──→ JSON Lines / Binary Log                        │
└─────────────────────────────────────────────────────────────┘
```

## Core Interfaces

### EventBus
```rust
pub struct EventBus {
    partitions: Vec<Partition>,
    shutdown: Arc<AtomicBool>,
    config: EventBusConfig,
}

impl EventBus {
    pub fn new(config: EventBusConfig) -> Self;
    
    pub async fn publish(&self, event: Event) -> Result<(), EventBusError>;
    
    pub fn subscribe(&self) -> EventBusSubscriber;
    
    pub async fn shutdown(&self);
}

pub struct EventBusConfig {
    pub num_partitions: usize,
    pub queue_size: usize,          // Per-partition queue size
    pub backpressure_timeout: u64,  // ms before applying backpressure
}
```

### TimeManager
```rust
pub struct TimeManager {
    mock_time: Arc<Mutex<Option<u64>>>,  // None = real time
    speed_multiplier: f64,
}

impl TimeManager {
    pub fn new() -> Self;
    
    pub fn now_mono_ns(&self) -> u64;
    
    // Mock time API for testing
    pub fn set_mock_time(&self, time_ns: u64);
    pub fn set_speed_multiplier(&self, multiplier: f64);
    pub fn advance_time(&self, delta_ns: u64);
}
```

### AlertOutput
```rust
pub struct AlertOutput {
    config: AlertOutputConfig,
    tx: mpsc::Sender<Alert>,
}

impl AlertOutput {
    pub fn new(config: AlertOutputConfig) -> Self;
    
    pub async fn emit(&self, alert: Alert) -> Result<(), AlertOutputError>;
}
```

### Replay
```rust
pub struct Replay {
    time_manager: TimeManager,
    event_bus: EventBus,
}

impl Replay {
    pub fn new(time_manager: TimeManager, event_bus: EventBus) -> Self;
    
    pub async fn replay(&self, path: impl AsRef<Path>) -> Result<ReplayStats, ReplayError>;
}
```

## Usage Example

```rust
use kestrel_core::{EventBus, EventBusConfig, TimeManager, AlertOutput, AlertOutputConfig};

// Create services
let event_bus = EventBus::new(EventBusConfig {
    num_partitions: 4,
    queue_size: 1000,
    backpressure_timeout: 100,
});

let time_manager = TimeManager::new();

let alert_output = AlertOutput::new(AlertOutputConfig {
    outputs: vec![AlertOutputType::Stdout],
});

// Publish event
let event = Event::builder()
    .event_type(1)
    .ts_mono(time_manager.now_mono_ns())
    .ts_wall(now())
    .entity_key(0)
    .field(1, TypedValue::String("/bin/bash".into()))
    .build()
    .unwrap();

event_bus.publish(event).await?;

// Subscribe to events
let mut subscriber = event_bus.subscribe();
while let Some(event) = subscriber.recv().await {
    // Process event...
}
```

## Mock Time for Testing

```rust
let time_manager = TimeManager::new();

// Set mock time
time_manager.set_mock_time(1_000_000_000);

// Advance time
time_manager.advance_time(100_000_000);  // +100ms
assert_eq!(time_manager.now_mono_ns(), 1_100_000_000);

// Speed multiplier (2x speed)
time_manager.set_speed_multiplier(2.0);
tokio::time::sleep(std::time::Duration::from_millis(100)).await;
assert_eq!(time_manager.now_mono_ns(), 1_100_000_000 + 200_000_000);
```

## Replay Format

Events are stored as JSON lines for compatibility:

```json
{"event_id":1,"event_type_id":1,"ts_mono_ns":1000000000,"ts_wall_ns":1000000000,"entity_key":0,"fields":{"1":{"String":"/bin/ls"}}}
{"event_id":2,"event_type_id":1,"ts_mono_ns":1000001000,"ts_wall_ns":1000001000,"entity_key":0,"fields":{"1":{"String":"/bin/cat"}}}
```

## Planned Evolution

### v0.8 (Current)
- [x] Multi-partition EventBus
- [x] Backpressure with configurable strategy
- [x] Mock time for testing
- [x] JSON replay

### v0.9
- [ ] Binary log format for performance
- [ ] Compression (zstd)
- [ ] Webhook alert output
- [ ] Alert deduplication

### v1.0
- [ ] Distributed EventBus (Kafka-compatible)
- [ ] Event compression (protobuf)
- [ ] Alert routing rules
- [ ] SIEM integrations (Splunk, ELK)

## Test Coverage

```bash
cargo test -p kestrel-core --lib

# EventBus Tests
test_eventbus_publish_subscribe    # Basic publish/subscribe
test_eventbus_partition_sharding   # Event sharding by entity_key
test_eventbus_backpressure         # Backpressure behavior
test_eventbus_shutdown             # Graceful shutdown

# TimeManager Tests  
test_time_mock                     # Mock time control
test_time_speed_multiplier         # Speed multiplier
test_time_advancement              # Time advancement

# Replay Tests
test_replay_deterministic          # Deterministic replay
test_replay_multiple_times         # Consistent results
test_replay_with_time_sync         # Mock time during replay
```

## Dependencies

```
kestrel-core
├── kestrel-schema (type definitions)
├── kestrel-event (Event struct)
├── tokio (async runtime)
├── serde_json (JSON serialization)
├── tracing (logging)
└── ahash (fast hashing)
```

## Performance Characteristics

| Component | Metric | Target |
|-----------|--------|--------|
| EventBus publish | < 10μs | P99 |
| EventBus subscribe | < 5μs | P99 |
| Replay throughput | 10k events/sec | Single thread |
| Memory per partition | ~queue_size * avg_event_size | Configurable |
