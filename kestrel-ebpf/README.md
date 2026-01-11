# Kestrel eBPF Collector

**Collection Layer - Kernel Event Collection via eBPF**

## Module Goal

Collect security events from the Linux kernel using eBPF:
- Zero-copy ring buffers for high performance
- execve, file, network event capture
- Event normalization to Kestrel Event format
- CO-RE (Compile Once, Run Everywhere) support

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  eBPF Collector                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Userspace (Rust)                                     │   │
│  │ ├── KestrelCollector                                │   │
│  │ │   ├── load_bpf()         → Load BPF programs     │   │
│  │ │   ├── start_polling()   → Start ring buffer      │   │
│  │ │   ├── handle_event()    → Process raw event      │   │
│  │ │   └── stop()            → Cleanup                │   │
│  │ ├── RingBuf reader                                  │   │
│  │ └── Event normalizer                                │   │
│  └─────────────────────────────────────────────────────┘   │
│                        ↓                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ eBPF Programs (Compiled to BPF bytecode)            │   │
│  │ ├── execve_trace   → Trace execve syscalls          │   │
│  │ ├── open_trace     → Trace file open                │   │
│  │ ├── connect_trace  → Trace network connections      │   │
│  │ └── uprobe_trace   → Trace library functions        │   │
│  └─────────────────────────────────────────────────────┘   │
│                        ↓                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Kernel (Linux 5.x+)                                  │   │
│  │ ├── perf events from syscalls                       │   │
│  │ ├── maps for data sharing                           │   │
│  │ └── ring buffers for zero-copy                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Supported Events

### Process Events (execve)
```rust
pub struct ExecveEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
    pub argv: [u64; 32],  // Pointers to strings
    pub arg_count: u32,
}
```

### File Events (openat)
```rust
pub struct OpenEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; 16],
    pub pathname: [u8; 256],
    pub flags: i32,
    pub mode: u32,
}
```

### Network Events (connect)
```rust
pub struct ConnectEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; 16],
    pub daddr: u32,        // IPv4 address
    pub dport: u16,        // Port
    pub family: u16,       // AF_INET / AF_INET6
}
```

## Core Interfaces

### KestrelCollector
```rust
pub struct KestrelCollector {
    bpf: Bpf,
    event_tx: mpsc::Sender<Event>,
    shutdown: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl KestrelCollector {
    pub fn new(
        event_tx: mpsc::Sender<Event>,
        config: CollectorConfig,
    ) -> Result<Self, CollectorError>;
    
    pub async fn load(&mut self) -> Result<(), CollectorError>;
    
    pub async fn start(&mut self) -> Result<(), CollectorError>;
    
    pub async fn stop(&mut self);
}
```

### CollectorConfig
```rust
#[derive(Debug, Clone)]
pub struct CollectorConfig {
    pub program_path: Option<PathBuf>,  // BPF .o file
    pub buffers: usize,                 // Ring buffer count
    pub buffer_size: usize,             // Per-buffer size
    pub event_types: Vec<EventType>,    // Which events to collect
}

#[derive(Debug, Clone, Copy)]
pub enum EventType {
    Exec,
    Open,
    Connect,
    Exit,
}
```

## Usage Example

```rust
use kestrel_ebpf::{KestrelCollector, CollectorConfig, EventType};
use kestrel_event::Event;
use kestrel_core::EventBus;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create event bus
    let event_bus = EventBus::new(EventBusConfig::default());
    let subscriber = event_bus.subscribe();
    
    // Create collector config
    let config = CollectorConfig {
        program_path: Some(PathBuf::from("/usr/share/kestrel/bpf/kestrel.o")),
        buffers: 4,
        buffer_size: 256 * 1024,  // 256KB
        event_types: vec![EventType::Exec, EventType::Open, EventType::Connect],
    };
    
    // Create and start collector
    let (event_tx, mut event_rx) = mpsc::channel(1000);
    let mut collector = KestrelCollector::new(event_tx, config).unwrap();
    collector.load().await?;
    collector.start().await?;
    
    // Process events
    while let Some(event) = event_rx.recv().await {
        println!("Received event: {:?}", event.event_type_id);
    }
    
    collector.stop().await;
    Ok(())
}
```

## Event Normalization

Raw eBPF events are converted to Kestrel Events:

```rust
impl KestrelCollector {
    fn normalize_execve(&self, raw: &ExecveEvent) -> Event {
        Event::builder()
            .event_type(1)  // exec event type
            .ts_mono(clock_gettime_mono())
            .ts_wall(clock_gettime_wall())
            .entity_key(entity_from_pid(raw.pid))
            .field(1, TypedValue::String(cstr_to_string(&raw.filename)))
            .field(2, TypedValue::U64(raw.pid as u64))
            .field(3, TypedValue::U64(raw.ppid as u64))
            .field(4, TypedValue::U64(raw.uid as u64))
            .source("ebpf")
            .build()
            .unwrap()
    }
}
```

## Building eBPF Programs

```bash
# Using clang/LLVM directly (aya-build alternative)
clang -O2 -target bpf -D__TARGET_ARCH_x86 \
    -I/usr/include \
    -c kestrel-ebpf/src/programs/exec.bpf.c \
    -o kestrel-ebpf/target/bpf/kestrel.o
```

## Planned Evolution

### v0.8 (Current)
- [x] execve tracing
- [x] openat tracing
- [x] connect tracing
- [x] Ring buffer polling

### v0.9
- [ ] kprobe/uprobe support
- [ ] Security context enrichment
- [ ] Event filtering in kernel
- [ ] Batch processing

### v1.0
- [ ] Full syscall coverage
- [ ] Container awareness
- [ ] Cloud metadata integration
- [ ] Performance metrics

## Test Coverage

```bash
cargo test -p kestrel-ebpf --lib

# Collector Tests
test_collector_create              # Constructor
test_config_validation             # Config validation
test_event_normalization           # Raw → Kestrel Event

# Integration Tests
test_ring_buffer_read              # Ring buffer polling
test_shutdown_clean                # Graceful shutdown
```

## Dependencies

```
kestrel-ebpf
├── kestrel-event (Event struct)
├── kestrel-schema (type definitions)
├── kestrel-core (EventBus)
├── aya (eBPF framework)
├── aya-log (logging)
├── nix (syscall wrappers)
├── tokio (async runtime)
└── tracing (logging)
```

## Performance

| Metric | Target | Notes |
|--------|--------|-------|
| Event latency | <10μs | From syscall to userspace |
| CPU overhead | <2% | Typical workload |
| Memory per event | ~64 bytes | Raw event |
| Ring buffer size | 256KB-1MB | Configurable |
| Max throughput | 100k events/sec | Per CPU core |
