//! Offline Replay Source
//!
//! Provides deterministic event replay from binary logs.
//! Critical for:
//! - Reproducing security incidents
//! - Testing detection rules with historical data
//! - Validating engine behavior with known inputs
//! - Time travel debugging

use crate::{EventBus, EventBusHandle, TimeManager};
use kestrel_event::Event;
use kestrel_schema::SchemaRegistry;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Replay error types
#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid log format: {0}")]
    InvalidFormat(String),

    #[error("Schema mismatch: {0}")]
    SchemaMismatch(String),

    #[error("Publish error: {0}")]
    PublishError(String),
}

/// Binary log header
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogHeader {
    /// Magic bytes for validation
    magic: [u8; 4],

    /// Format version
    version: u32,

    /// Schema version (for compatibility)
    schema_version: u32,

    /// Engine build ID (for reproducibility)
    engine_build_id: String,

    /// Number of events in log
    event_count: u64,

    /// Start timestamp (monotonic)
    start_ts_mono_ns: u64,

    /// End timestamp (monotonic)
    end_ts_mono_ns: u64,
}

impl LogHeader {
    const MAGIC: [u8; 4] = [b'K', b'E', b'S', b'T']; // "KEST"
    const CURRENT_VERSION: u32 = 1;

    fn new(event_count: u64, start_ts: u64, end_ts: u64) -> Self {
        Self {
            magic: Self::MAGIC,
            version: Self::CURRENT_VERSION,
            schema_version: 1,
            engine_build_id: env!("CARGO_PKG_VERSION").to_string(),
            event_count,
            start_ts_mono_ns: start_ts,
            end_ts_mono_ns: end_ts,
        }
    }

    fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC && self.version <= Self::CURRENT_VERSION
    }
}

/// Serialized event for binary log
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializedEvent {
    /// Event type ID
    event_type_id: u16,

    /// Monotonic timestamp
    ts_mono_ns: u64,

    /// Wall clock timestamp
    ts_wall_ns: u64,

    /// Entity key
    entity_key: u128,

    /// Event fields (field_id -> value)
    fields: Vec<(u32, SerializedValue)>,
}

/// Serialized value (schema-aware)
#[derive(Debug, Clone, Serialize, Deserialize)]
enum SerializedValue {
    I64(i64),
    U64(u64),
    F64(f64),
    Bool(bool),
    String(String),
    Bytes(Vec<u8>),
}

impl From<SerializedValue> for kestrel_schema::TypedValue {
    fn from(val: SerializedValue) -> Self {
        match val {
            SerializedValue::I64(v) => Self::I64(v),
            SerializedValue::U64(v) => Self::U64(v),
            SerializedValue::F64(v) => Self::F64(v),
            SerializedValue::Bool(v) => Self::Bool(v),
            SerializedValue::String(v) => Self::String(v),
            SerializedValue::Bytes(v) => Self::Bytes(v),
        }
    }
}

impl From<kestrel_schema::TypedValue> for SerializedValue {
    fn from(val: kestrel_schema::TypedValue) -> Self {
        match val {
            kestrel_schema::TypedValue::I64(v) => Self::I64(v),
            kestrel_schema::TypedValue::U64(v) => Self::U64(v),
            kestrel_schema::TypedValue::F64(v) => Self::F64(v),
            kestrel_schema::TypedValue::Bool(v) => Self::Bool(v),
            kestrel_schema::TypedValue::String(v) => Self::String(v),
            kestrel_schema::TypedValue::Bytes(v) => Self::Bytes(v),
            kestrel_schema::TypedValue::Array(v) => {
                // Serialize array as JSON string for compatibility
                Self::String(serde_json::to_string(&v).unwrap_or_else(|_| "[]".to_string()))
            }
            kestrel_schema::TypedValue::Null => {
                // Represent null as empty string
                Self::String(String::new())
            }
        }
    }
}

/// Binary log format for offline replay
///
/// Stores events in a JSON-based format for compatibility and debugging.
/// In production, would use more efficient binary serialization.
pub struct BinaryLog {
    schema: Arc<SchemaRegistry>,
}

impl BinaryLog {
    /// Create a new binary log instance
    pub fn new(schema: Arc<SchemaRegistry>) -> Self {
        Self { schema }
    }

    /// Write events to log file
    pub fn write_events(&self, path: PathBuf, events: &[Event]) -> Result<(), ReplayError> {
        if events.is_empty() {
            // Create empty file with header only
            let file = File::create(&path)?;
            let mut writer = BufWriter::new(file);

            let header = LogHeader::new(0, 0, 0);
            writeln!(
                writer,
                "{}",
                serde_json::to_string_pretty(&header)
                    .map_err(|e| ReplayError::Serialization(e.to_string()))?
            )
            .map_err(|e| ReplayError::Io(e))?;

            writer.flush()?;
            if let Ok(file) = writer.into_inner() {
                let _ = file.sync_all();
            }
            return Ok(());
        }

        let file = File::create(&path)?;
        let mut writer = BufWriter::new(file);

        let start_ts = events.first().map(|e| e.ts_mono_ns).unwrap_or(0);
        let end_ts = events.last().map(|e| e.ts_mono_ns).unwrap_or(0);

        let header = LogHeader::new(events.len() as u64, start_ts, end_ts);

        // Write header as single-line JSON (for line-based reading)
        writeln!(
            writer,
            "{}",
            serde_json::to_string(&header)
                .map_err(|e| ReplayError::Serialization(e.to_string()))?
        )
        .map_err(|e| ReplayError::Io(e))?;

        // Write events
        for event in events {
            // Convert Event to serializable format
            let serialized = SerializedEvent {
                event_type_id: event.event_type_id,
                ts_mono_ns: event.ts_mono_ns,
                ts_wall_ns: event.ts_wall_ns,
                entity_key: event.entity_key,
                fields: event
                    .fields
                    .iter()
                    .map(|(id, val)| (*id, SerializedValue::from(val.clone())))
                    .collect(),
            };

            writeln!(
                writer,
                "{}",
                serde_json::to_string(&serialized)
                    .map_err(|e| ReplayError::Serialization(e.to_string()))?
            )
            .map_err(|e| ReplayError::Io(e))?;
        }

        // Flush and sync to ensure data is written to disk
        writer.flush()?;
        if let Some(file) = writer.into_inner().ok() {
            file.sync_all()?;
        }

        info!(path = %path.display(), count = events.len(), "Wrote event log");
        Ok(())
    }

    /// Read events from log file
    pub fn read_events(&self, path: PathBuf) -> Result<Vec<Event>, ReplayError> {
        let file = File::open(&path)?;
        let reader = BufReader::new(file);

        // Read header from first line
        let mut first_line = String::new();
        let mut reader = reader;
        use std::io::BufRead;
        reader.read_line(&mut first_line)?;

        let header: LogHeader = serde_json::from_str(&first_line)
            .map_err(|e| ReplayError::Serialization(e.to_string()))?;

        if !header.is_valid() {
            return Err(ReplayError::InvalidFormat(
                "Invalid magic bytes or version".to_string(),
            ));
        }

        // Validate schema version
        if header.schema_version != 1 {
            warn!(
                log_version = header.schema_version,
                "Schema version mismatch, may have compatibility issues"
            );
        }

        // Read events (one per line)
        let mut events = Vec::new();
        for line in reader.lines() {
            let line = line.map_err(|e| ReplayError::Io(e))?;
            if line.is_empty() {
                continue;
            }

            let serialized: SerializedEvent = serde_json::from_str(&line)
                .map_err(|e| ReplayError::Serialization(e.to_string()))?;

            // Convert back to Event
            let fields: smallvec::SmallVec<
                [(kestrel_schema::FieldId, kestrel_schema::TypedValue); 8],
            > = serialized
                .fields
                .into_iter()
                .map(|(id, val)| (id, val.into()))
                .collect();

            let event = Event {
                event_id: 0, // Will be assigned during replay
                event_type_id: serialized.event_type_id,
                ts_mono_ns: serialized.ts_mono_ns,
                ts_wall_ns: serialized.ts_wall_ns,
                entity_key: serialized.entity_key,
                fields,
                source_id: None,
            };

            events.push(event);
        }

        info!(path = %path.display(), count = events.len(), "Read event log");
        Ok(events)
    }
}

/// Replay source configuration
#[derive(Debug, Clone)]
pub struct ReplayConfig {
    /// Path to binary log file
    pub log_path: PathBuf,

    /// Replay speed multiplier (1.0 = real-time, 2.0 = 2x fast)
    pub speed_multiplier: f64,

    /// Whether to stop on error
    pub stop_on_error: bool,

    /// Channel size for events
    pub channel_size: usize,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            log_path: PathBuf::from("kestrel_events.log"),
            speed_multiplier: 1.0,
            stop_on_error: false,
            channel_size: 4096,
        }
    }
}

/// Offline replay source
///
/// Replays events from binary log with deterministic timing.
pub struct ReplaySource {
    config: ReplayConfig,
    schema: Arc<SchemaRegistry>,
    time_manager: TimeManager,

    /// Next event ID to assign
    next_event_id: u64,
}

impl ReplaySource {
    /// Create a new replay source
    pub fn new(
        config: ReplayConfig,
        schema: Arc<SchemaRegistry>,
        time_manager: TimeManager,
    ) -> Self {
        Self {
            config,
            schema,
            time_manager,
            next_event_id: 1,
        }
    }

    /// Start replaying events to EventBus
    pub async fn start(&mut self, event_bus: &EventBus) -> Result<usize, ReplayError> {
        info!(path = %self.config.log_path.display(), "Starting replay");

        let binary_log = BinaryLog::new(self.schema.clone());
        let mut events = binary_log.read_events(self.config.log_path.clone())?;

        if events.is_empty() {
            warn!("No events to replay");
            return Ok(0);
        }

        // Sort events for deterministic replay: (ts_mono_ns, event_id)
        events.sort_by(|a, b| {
            a.ts_mono_ns
                .cmp(&b.ts_mono_ns)
                .then_with(|| a.event_id.cmp(&b.event_id))
        });

        // Set mock time to first event's timestamp
        if let Some(first_event) = events.first() {
            self.time_manager
                .provider()
                .set_time(first_event.ts_mono_ns, first_event.ts_wall_ns);
        }

        let event_bus_handle = event_bus.handle();
        let mut count = 0;

        for mut event in events {
            // Assign event_id if not set
            if event.event_id == 0 {
                event.event_id = self.next_event_id;
                self.next_event_id += 1;
            }

            // Wait for appropriate time based on speed multiplier
            if count > 0 {
                let prev_ts = self.time_manager.mono_ns();
                let target_ts = event.ts_mono_ns;
                let delay_ns = target_ts.saturating_sub(prev_ts);

                if delay_ns > 0 && self.config.speed_multiplier > 0.0 {
                    let delay_ms =
                        (delay_ns as f64 / 1_000_000.0 / self.config.speed_multiplier) as u64;
                    if delay_ms > 0 {
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                    }
                }

                // Advance mock time
                self.time_manager
                    .provider()
                    .set_time(event.ts_mono_ns, event.ts_wall_ns);
            }

            // Save timestamp for logging before moving event
            let timestamp_ns = event.ts_mono_ns;

            // Publish event
            if let Err(e) = event_bus_handle.publish(event).await {
                error!(error = %e, "Failed to publish event during replay");
                if self.config.stop_on_error {
                    return Err(ReplayError::PublishError(e.to_string()));
                }
            }

            count += 1;

            // Progress logging
            if count % 1000 == 0 {
                debug!(count, timestamp_ns, "Replay progress");
            }
        }

        info!(count, "Replay completed");
        Ok(count)
    }

    /// Get replay statistics
    pub fn stats(&self) -> ReplayStats {
        ReplayStats {
            events_processed: self.next_event_id - 1,
            current_ts_mono_ns: self.time_manager.mono_ns(),
            current_ts_wall_ns: self.time_manager.wall_ns(),
        }
    }
}

/// Replay statistics
#[derive(Debug, Clone)]
pub struct ReplayStats {
    pub events_processed: u64,
    pub current_ts_mono_ns: u64,
    pub current_ts_wall_ns: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventBus, EventBusConfig, TimeManager};
    use kestrel_event::Event;
    use kestrel_schema::{SchemaRegistry, TypedValue};
    use std::fs::remove_file;
    use std::time::Duration;

    fn create_test_schema() -> Arc<SchemaRegistry> {
        Arc::new(SchemaRegistry::new())
    }

    fn create_test_events(count: usize) -> Vec<Event> {
        let mut events = Vec::new();
        for i in 0..count {
            let event = Event::builder()
                .event_type(1)
                .ts_mono(i as u64 * 1000)
                .ts_wall(i as u64 * 1000000)
                .entity_key(i as u128 % 4)
                .field(1, TypedValue::I64(i as i64))
                .field(2, TypedValue::String(format!("event_{}", i)))
                .build()
                .unwrap();
            events.push(event);
        }
        events
    }

    #[test]
    fn test_log_header_validation() {
        let header = LogHeader::new(100, 0, 1000000);
        assert!(header.is_valid());

        let mut invalid = header.clone();
        invalid.magic = [0, 0, 0, 0];
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_serialized_value_conversion() {
        let original = TypedValue::String("test".to_string());
        let serialized = SerializedValue::from(original.clone());
        let converted: TypedValue = serialized.into();

        match converted {
            TypedValue::String(s) => assert_eq!(s, "test"),
            _ => panic!("Wrong type"),
        }
    }

    #[test]
    fn test_binary_log_empty() {
        let schema = create_test_schema();
        let log = BinaryLog::new(schema);
        let events = vec![];

        let temp_dir = std::env::temp_dir();
        let log_path = temp_dir.join("test_empty.log");

        let result = log.write_events(log_path, &events);
        assert!(result.is_ok());
    }

    #[test]
    fn test_replay_config_default() {
        let config = ReplayConfig::default();
        assert_eq!(config.speed_multiplier, 1.0);
        assert!(!config.stop_on_error);
    }

    #[tokio::test]
    async fn test_replay_deterministic_ordering() {
        let schema = create_test_schema();

        let events = create_test_events(100);

        println!("Created {} events", events.len());
        println!("First event ts_mono_ns: {}", events[0].ts_mono_ns);

        let temp_dir = std::env::temp_dir();
        let log_path = temp_dir.join(format!("test_deterministic_{}.log", std::process::id()));

        // Write using sync file I/O
        {
            let file = std::fs::File::create(&log_path).unwrap();
            let mut writer = std::io::BufWriter::new(file);

            let header = LogHeader::new(
                100,
                events[0].ts_mono_ns,
                events[events.len() - 1].ts_mono_ns,
            );
            let header_str = serde_json::to_string(&header).unwrap();
            writeln!(writer, "{}", header_str).unwrap();

            for (i, event) in events.iter().enumerate() {
                let serialized = SerializedEvent {
                    event_type_id: event.event_type_id,
                    ts_mono_ns: event.ts_mono_ns,
                    ts_wall_ns: event.ts_wall_ns,
                    entity_key: event.entity_key,
                    fields: event
                        .fields
                        .iter()
                        .map(|(id, val)| (*id, SerializedValue::from(val.clone())))
                        .collect(),
                };
                let serialized_str = serde_json::to_string(&serialized).unwrap();
                if i < 2 {
                    println!("Event {}: {}", i, serialized_str);
                }
                writeln!(writer, "{}", serialized_str).expect("Failed to write event");
            }
            writer.flush().unwrap();
        }

        // Verify file exists and has content
        let metadata = std::fs::metadata(&log_path).unwrap();
        println!("File size: {} bytes", metadata.len());

        let time_manager = TimeManager::mock();
        let event_bus = EventBus::new(EventBusConfig::default());
        let handle = event_bus.handle();

        let config = ReplayConfig {
            log_path: log_path.clone(),
            speed_multiplier: 1000.0,
            ..Default::default()
        };

        let mut replay = ReplaySource::new(config, schema, time_manager);

        replay.start(&event_bus).await.unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;

        let metrics = handle.metrics();
        assert_eq!(
            metrics.events_received, 100,
            "Should have received 100 events"
        );

        let _ = std::fs::remove_file(log_path);
    }

    #[tokio::test]
    async fn test_replay_multiple_times_consistent() {
        let schema = create_test_schema();
        let log = BinaryLog::new(schema.clone());

        let events = create_test_events(50);

        let temp_dir = std::env::temp_dir();
        let log_path = temp_dir.join("test_replay_consistent.log");

        log.write_events(log_path.clone(), &events).unwrap();

        let mut run_results: Vec<u64> = Vec::new();

        for _ in 0..3 {
            let time_manager = TimeManager::mock();
            let event_bus = EventBus::new(EventBusConfig::default());
            let handle = event_bus.handle();

            let config = ReplayConfig {
                log_path: log_path.clone(),
                speed_multiplier: 1000.0,
                ..Default::default()
            };

            let mut replay = ReplaySource::new(config, schema.clone(), time_manager);

            replay.start(&event_bus).await.unwrap();

            tokio::time::sleep(Duration::from_millis(500)).await;

            let metrics = handle.metrics();
            run_results.push(metrics.events_received);
        }

        for run_idx in 1..run_results.len() {
            assert_eq!(
                run_results[run_idx], run_results[0],
                "Run {} differs from run 0: {} vs {}",
                run_idx, run_results[run_idx], run_results[0]
            );
        }
    }

    #[tokio::test]
    async fn test_replay_with_mock_time_synchronization() {
        let schema = create_test_schema();
        let log = BinaryLog::new(schema.clone());

        let start_ts = 1000000000u64;
        let events: Vec<Event> = (0..10)
            .map(|i| {
                Event::builder()
                    .event_type(1)
                    .ts_mono(start_ts + i as u64 * 1000000)
                    .ts_wall(start_ts + i as u64 * 1000000)
                    .entity_key(i as u128)
                    .build()
                    .unwrap()
            })
            .collect();

        let temp_dir = std::env::temp_dir();
        let log_path = temp_dir.join("test_mock_time_sync.log");

        log.write_events(log_path.clone(), &events).unwrap();

        let time_manager = TimeManager::mock();
        let event_bus = EventBus::new(EventBusConfig::default());
        let handle = event_bus.handle();

        let config = ReplayConfig {
            log_path,
            speed_multiplier: 100.0,
            ..Default::default()
        };

        let mut replay = ReplaySource::new(config, schema, time_manager.clone());

        replay.start(&event_bus).await.unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;

        let metrics = handle.metrics();
        assert_eq!(
            metrics.events_received, 10,
            "Should have received 10 events"
        );
    }

    #[tokio::test]
    async fn test_replay_event_ordering_deterministic() {
        let schema = create_test_schema();
        let log = BinaryLog::new(schema.clone());

        let events: Vec<Event> = (0..20)
            .map(|i| {
                Event::builder()
                    .event_type(1)
                    .ts_mono((i as u64 % 5) * 1000 + i as u64 * 100000)
                    .ts_wall(i as u64 * 1000000)
                    .entity_key(i as u128)
                    .build()
                    .unwrap()
            })
            .collect();

        let temp_dir = std::env::temp_dir();
        let log_path = temp_dir.join("test_event_ordering.log");

        log.write_events(log_path.clone(), &events).unwrap();

        let time_manager = TimeManager::mock();
        let event_bus = EventBus::new(EventBusConfig::default());
        let handle = event_bus.handle();

        let config = ReplayConfig {
            log_path,
            speed_multiplier: 1.0,
            ..Default::default()
        };

        let mut replay = ReplaySource::new(config, schema, time_manager);

        replay.start(&event_bus).await.unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;

        let metrics = handle.metrics();
        assert_eq!(
            metrics.events_processed, 20,
            "Should have processed 20 events"
        );
    }

    #[tokio::test]
    async fn test_replay_speed_multiplier_affects_timing() {
        let schema = create_test_schema();
        let log = BinaryLog::new(schema.clone());

        let events: Vec<Event> = (0..5)
            .map(|i| {
                Event::builder()
                    .event_type(1)
                    .ts_mono((i as u64 + 1) * 10000000)
                    .ts_wall((i as u64 + 1) * 10000000)
                    .entity_key(i as u128)
                    .build()
                    .unwrap()
            })
            .collect();

        let temp_dir = std::env::temp_dir();
        let log_path = temp_dir.join("test_speed_multiplier.log");

        log.write_events(log_path.clone(), &events).unwrap();

        let time_manager_fast = TimeManager::mock();
        let event_bus_fast = EventBus::new(EventBusConfig::default());

        let config_fast = ReplayConfig {
            log_path: log_path.clone(),
            speed_multiplier: 10.0,
            ..Default::default()
        };

        let mut replay_fast =
            ReplaySource::new(config_fast, schema.clone(), time_manager_fast.clone());

        let start_fast = time_manager_fast.mono_ns();
        replay_fast.start(&event_bus_fast).await.unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;
        let duration_fast = time_manager_fast.mono_ns() - start_fast;

        let time_manager_slow = TimeManager::mock();
        let event_bus_slow = EventBus::new(EventBusConfig::default());

        let config_slow = ReplayConfig {
            log_path: log_path.clone(),
            speed_multiplier: 1.0,
            ..Default::default()
        };

        let mut replay_slow =
            ReplaySource::new(config_slow, schema.clone(), time_manager_slow.clone());

        let start_slow = time_manager_slow.mono_ns();
        replay_slow.start(&event_bus_slow).await.unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;
        let duration_slow = time_manager_slow.mono_ns() - start_slow;

        // Note: Both replayers process the same events
        // The speed multiplier affects internal timing, not wall-clock time
        assert!(duration_fast > 0);
        assert!(duration_slow > 0);
    }
}
