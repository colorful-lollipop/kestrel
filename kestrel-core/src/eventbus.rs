//! Event Bus Implementation
//!
//! The EventBus is responsible for transporting events from sources to detection workers.
//! It supports batching, backpressure, and partitioning.

use crate::BackpressureConfig;
use kestrel_event::Event;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info};

/// Partition strategy for distributing events across workers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionStrategy {
    /// Partition by entity key only (simple modulo)
    EntityKey,
    /// Partition by event type only
    EventType,
    /// Combined: event type first, then entity key within each type group
    Combined,
    /// Consistent hashing for better distribution
    ConsistentHash,
}

impl Default for PartitionStrategy {
    fn default() -> Self {
        PartitionStrategy::EntityKey
    }
}

/// Partitioner trait for pluggable partitioning logic
pub trait Partitioner: Send + Sync {
    /// Get partition index for an event
    fn partition(&self, event: &Event, partition_count: usize) -> usize;
}

/// Default partitioner using the configured strategy
pub struct DefaultPartitioner {
    strategy: PartitionStrategy,
}

impl DefaultPartitioner {
    pub fn new(strategy: PartitionStrategy) -> Self {
        Self { strategy }
    }
}

impl Partitioner for DefaultPartitioner {
    fn partition(&self, event: &Event, partition_count: usize) -> usize {
        if partition_count == 1 {
            return 0;
        }

        match self.strategy {
            PartitionStrategy::EntityKey => {
                // Simple modulo on entity_key
                (event.entity_key % partition_count as u128) as usize
            }
            PartitionStrategy::EventType => {
                // Use event_type_id for partition
                (event.event_type_id as usize) % partition_count
            }
            PartitionStrategy::Combined => {
                // Combine event_type and entity_key
                // This ensures events of the same type from the same entity go to the same partition
                let combined = ((event.event_type_id as u128) << 64) | event.entity_key;
                (combined % partition_count as u128) as usize
            }
            PartitionStrategy::ConsistentHash => {
                // Use consistent hashing for better distribution
                let mut hasher = DefaultHasher::new();
                event.entity_key.hash(&mut hasher);
                event.event_type_id.hash(&mut hasher);
                let hash = hasher.finish();
                (hash as usize) % partition_count
            }
        }
    }
}

/// Event bus configuration
#[derive(Debug, Clone)]
pub struct EventBusConfig {
    /// Channel buffer size per partition
    pub channel_size: usize,

    /// Batch size for worker delivery
    pub batch_size: usize,

    /// Number of worker partitions
    pub partitions: usize,

    /// Backpressure configuration
    pub backpressure: BackpressureConfig,

    /// Partition strategy
    pub partition_strategy: PartitionStrategy,

    /// Batch timeout - maximum time to wait before sending a partial batch
    pub batch_timeout_ms: u64,
}

impl Default for EventBusConfig {
    fn default() -> Self {
        Self {
            channel_size: 10000,
            batch_size: 100,
            partitions: 4,
            backpressure: BackpressureConfig::default(),
            partition_strategy: PartitionStrategy::default(),
            batch_timeout_ms: 100, // 100ms default batch timeout
        }
    }
}

/// Handle for publishing events to the bus
#[derive(Clone)]
pub struct EventBusHandle {
    senders: Arc<Vec<mpsc::Sender<Event>>>,
    partition_count: usize,
    metrics: Arc<EventBusMetrics>,
    backpressure_config: BackpressureConfig,
    partitioner: Arc<dyn Partitioner>,
}

impl std::fmt::Debug for EventBusHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBusHandle")
            .field("partition_count", &self.partition_count)
            .field("metrics", &self.metrics)
            .finish()
    }
}

impl EventBusHandle {
    /// Get partition index for an event
    fn get_partition(&self, event: &Event) -> usize {
        self.partitioner.partition(event, self.partition_count)
    }

    /// Publish a single event
    #[tracing::instrument(skip(self), fields(event_id = %event.ts_mono_ns, partition_id))]
    pub async fn publish(&self, event: Event) -> Result<(), PublishError> {
        let partition = self.get_partition(&event);
        let sender = &self.senders[partition];

        match sender.send(event).await {
            Ok(()) => {
                self.metrics.events_received.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(_) => {
                self.metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
                Err(PublishError::Closed)
            }
        }
    }

    /// Publish with backpressure - blocks until there's capacity
    pub async fn publish_with_backpressure(&self, event: Event) -> Result<(), PublishError> {
        let partition = self.get_partition(&event);

        let sender = &self.senders[partition];
        if sender.capacity() == 0 {
            self.metrics
                .backpressure_count
                .fetch_add(1, Ordering::Relaxed);

            let timeout_duration = Duration::from_millis(
                self.backpressure_config.backpressure_timeout.as_millis() as u64,
            );
            match timeout(timeout_duration, sender.reserve()).await {
                Ok(Ok(permit)) => {
                    permit.send(event);
                    self.metrics.events_received.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                _ => return Err(PublishError::BackpressureTimeout),
            }
        }

        sender.send(event).await.map_err(|_| PublishError::Closed)?;
        self.metrics.events_received.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Try to publish without blocking
    pub fn try_publish(&self, event: Event) -> Result<(), PublishError> {
        let partition = self.get_partition(&event);
        let sender = &self.senders[partition];

        match sender.try_send(event) {
            Ok(()) => {
                self.metrics.events_received.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.metrics.events_dropped.fetch_add(1, Ordering::Relaxed);
                match e {
                    mpsc::error::TrySendError::Full(_) => Err(PublishError::Full),
                    mpsc::error::TrySendError::Closed(_) => Err(PublishError::Closed),
                }
            }
        }
    }

    /// Get current metrics snapshot
    pub fn metrics(&self) -> EventBusMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Get number of partitions
    pub fn partition_count(&self) -> usize {
        self.partition_count
    }
}

/// Event bus for transporting events
pub struct EventBus {
    _handles: Vec<tokio::task::JoinHandle<()>>,
    handle: EventBusHandle,
    shutdown: Arc<AtomicBool>,
    #[allow(dead_code)]
    subscriber_tx: Option<mpsc::Sender<Vec<Event>>>,
}

impl EventBus {
    /// Create a new event bus with the given configuration
    /// The `sink` parameter provides the downstream consumer (e.g., DetectionEngine)
    pub fn new_with_sink(config: EventBusConfig, sink: mpsc::Sender<Vec<Event>>) -> Self {
        let metrics = Arc::new(EventBusMetrics::default());
        let partition_count = config.partitions.max(1);

        let mut senders = Vec::with_capacity(partition_count);
        let mut receivers = Vec::with_capacity(partition_count);

        for _ in 0..partition_count {
            let (sender, receiver) = mpsc::channel(config.channel_size);
            senders.push(sender);
            receivers.push(receiver);
        }

        let senders = Arc::new(senders);

        let partitioner: Arc<dyn Partitioner> = 
            Arc::new(DefaultPartitioner::new(config.partition_strategy));

        let handle = EventBusHandle {
            senders: senders.clone(),
            partition_count,
            metrics: metrics.clone(),
            backpressure_config: config.backpressure.clone(),
            partitioner,
        };

        let mut handles = Vec::new();
        let shutdown = Arc::new(AtomicBool::new(false));

        for partition_id in 0..partition_count {
            let receiver = receivers.remove(0);
            let metrics_clone = metrics.clone();
            let shutdown_clone = shutdown.clone();
            let sink_tx = sink.clone();

            let handle_task = tokio::spawn(async move {
                Self::worker_partition(
                    partition_id,
                    receiver,
                    sink_tx,
                    config.batch_size,
                    metrics_clone,
                    shutdown_clone,
                    config.batch_timeout_ms,
                )
                .await;
            });

            handles.push(handle_task);
        }

        info!(
            partitions = partition_count,
            batch_size = config.batch_size,
            channel_size = config.channel_size,
            "EventBus initialized with multiple workers"
        );

        Self {
            _handles: handles,
            handle,
            shutdown,
            subscriber_tx: None,
        }
    }

    /// Create a new event bus (legacy constructor, does not connect to downstream)
    #[deprecated(note = "Use new_with_sink() to connect to a downstream consumer")]
    pub fn new(config: EventBusConfig) -> Self {
        let (sink_tx, _sink_rx) = mpsc::channel(1);
        Self::new_with_sink(config, sink_tx)
    }

    /// Subscribe to events from the bus
    /// Returns a receiver that will receive event batches
    pub fn subscribe(&self) -> mpsc::Receiver<Vec<Event>> {
        let (tx, rx) = mpsc::channel(100);
        if let Some(subscriber_tx) = &self.subscriber_tx {
            let subscriber_tx = subscriber_tx.clone();
            tokio::spawn(async move {
                let _tx = tx;
                loop {
                    if subscriber_tx.is_closed() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            });
        }
        rx
    }

    /// Get a handle for publishing events
    pub fn handle(&self) -> EventBusHandle {
        self.handle.clone()
    }

    /// Worker partition that batches and delivers events
    #[tracing::instrument(skip(receiver, sink_tx, metrics, shutdown), fields(partition_id))]
    async fn worker_partition(
        partition_id: usize,
        mut receiver: mpsc::Receiver<Event>,
        sink_tx: mpsc::Sender<Vec<Event>>,
        batch_size: usize,
        metrics: Arc<EventBusMetrics>,
        shutdown: Arc<AtomicBool>,
        batch_timeout_ms: u64,
    ) {
        let mut batch = Vec::with_capacity(batch_size);
        let mut last_send = tokio::time::Instant::now();
        let batch_timeout = Duration::from_millis(batch_timeout_ms);

        loop {
            if shutdown.load(Ordering::Relaxed) {
                debug!(partition = partition_id, "Shutdown signal received");
                break;
            }

            // Check if we need to flush due to timeout
            let timeout_remaining = if !batch.is_empty() {
                let elapsed = last_send.elapsed();
                if elapsed >= batch_timeout {
                    // Flush batch due to timeout
                    let batch_len = batch.len();
                    if let Err(e) = sink_tx.send(std::mem::take(&mut batch)).await {
                        error!(
                            partition = partition_id,
                            error = %e,
                            "Failed to deliver batch on timeout"
                        );
                    } else {
                        metrics.events_processed.fetch_add(batch_len as u64, Ordering::Relaxed);
                        debug!(
                            partition = partition_id,
                            batch_size = batch_len,
                            "Flushed batch due to timeout"
                        );
                    }
                    batch = Vec::with_capacity(batch_size);
                    last_send = tokio::time::Instant::now();
                    batch_timeout
                    } else {
                        batch_timeout - elapsed
                    }
            } else {
                batch_timeout
            };

            tokio::select! {
                result = receiver.recv_many(&mut batch, batch_size) => {
                    match result {
                        0 => break, // Channel closed
                        count if count > 0 => {
                            debug!(
                                partition = partition_id,
                                batch_size = count,
                                "Received batch"
                            );

                            // Flush immediately if batch is full
                            if batch.len() >= batch_size {
                                let batch_len = batch.len();
                                if let Err(e) = sink_tx.send(std::mem::take(&mut batch)).await {
                                    error!(
                                        partition = partition_id,
                                        error = %e,
                                        "Failed to deliver batch"
                                    );
                                } else {
                                    metrics.events_processed.fetch_add(batch_len as u64, Ordering::Relaxed);
                                    last_send = tokio::time::Instant::now();
                                }
                                batch = Vec::with_capacity(batch_size);
                            }
                        }
                        _ => {}
                    }
                }
                _ = tokio::time::sleep(timeout_remaining) => {
                    // Timeout handled at the beginning of the loop
                }
            }
        }

        // Flush remaining events on shutdown
        if !batch.is_empty() {
            let batch_len = batch.len();
            let _ = sink_tx.send(batch).await;
            metrics
                .events_processed
                .fetch_add(batch_len as u64, Ordering::Relaxed);
        }

        debug!(partition = partition_id, "Worker partition shutting down");
    }
}

impl Drop for EventBus {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

/// Event bus metrics (atomic for lock-free access)
#[derive(Debug, Default)]
pub struct EventBusMetrics {
    events_received: AtomicU64,
    events_processed: AtomicU64,
    events_dropped: AtomicU64,
    backpressure_count: AtomicU64,
}

impl EventBusMetrics {
    fn snapshot(&self) -> EventBusMetricsSnapshot {
        EventBusMetricsSnapshot {
            events_received: self.events_received.load(Ordering::Relaxed),
            events_processed: self.events_processed.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            backpressure_count: self.backpressure_count.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of event bus metrics
#[derive(Debug, Clone)]
pub struct EventBusMetricsSnapshot {
    pub events_received: u64,
    pub events_processed: u64,
    pub events_dropped: u64,
    pub backpressure_count: u64,
}

/// Error publishing an event
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("Event bus is closed")]
    Closed,

    #[error("Event bus is full")]
    Full,

    #[error("Backpressure timeout")]
    BackpressureTimeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_bus(
        config: EventBusConfig,
    ) -> (EventBus, EventBusHandle, mpsc::Receiver<Vec<Event>>) {
        let (sink_tx, sink_rx) = mpsc::channel(1);
        let bus = EventBus::new_with_sink(config, sink_tx);
        let handle = bus.handle();
        (bus, handle, sink_rx)
    }

    #[tokio::test]
    async fn test_event_bus_basic() {
        let config = EventBusConfig::default();
        let (_bus, handle, _rx) = create_test_bus(config).await;

        let event = Event::builder()
            .event_type(1)
            .ts_mono(0)
            .ts_wall(0)
            .entity_key(0)
            .build()
            .unwrap();

        handle.publish(event).await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let metrics = handle.metrics();
        assert_eq!(metrics.events_received, 1);
    }

    #[tokio::test]
    async fn test_event_bus_batch() {
        let config = EventBusConfig {
            channel_size: 100,
            batch_size: 10,
            partitions: 1,
            ..Default::default()
        };
        let (_bus, handle, _rx) = create_test_bus(config).await;

        for i in 0..20 {
            let event = Event::builder()
                .event_type(1)
                .ts_mono(i)
                .ts_wall(i)
                .entity_key(i as u128)
                .build()
                .unwrap();
            handle.publish(event).await.unwrap();
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        let metrics = handle.metrics();
        assert_eq!(metrics.events_received, 20);
    }

    #[tokio::test]
    async fn test_event_bus_partitioning() {
        let config = EventBusConfig {
            partitions: 4,
            ..Default::default()
        };
        let (_bus, handle, _rx) = create_test_bus(config).await;

        assert_eq!(handle.partition_count(), 4);

        for i in 0..10 {
            let event = Event::builder()
                .event_type(1)
                .ts_mono(i)
                .ts_wall(i)
                .entity_key(i as u128)
                .build()
                .unwrap();
            handle.publish(event).await.unwrap();
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        let metrics = handle.metrics();
        assert_eq!(metrics.events_received, 10);
    }

    #[tokio::test]
    async fn test_event_bus_delivery() {
        let config = EventBusConfig {
            channel_size: 100,
            batch_size: 10,
            partitions: 1,
            ..Default::default()
        };
        let (_bus, handle, mut rx) = create_test_bus(config).await;

        let event = Event::builder()
            .event_type(1)
            .ts_mono(0)
            .ts_wall(0)
            .entity_key(0)
            .build()
            .unwrap();

        handle.publish(event).await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await;
        assert!(received.is_ok());
        let batch = received.unwrap().unwrap();
        assert_eq!(batch.len(), 1);
    }
}
