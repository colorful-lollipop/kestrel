//! Event Bus Implementation
//!
//! The EventBus is responsible for transporting events from sources to detection workers.
//! It supports batching, backpressure, and partitioning.

use crate::{BackpressureConfig, Metrics};
use kestrel_event::{Event, EventBuilder};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::{timeout, Duration};
use tracing::{debug, error, warn};

/// Event bus configuration
#[derive(Debug, Clone)]
pub struct EventBusConfig {
    /// Channel buffer size
    pub channel_size: usize,

    /// Batch size for worker delivery
    pub batch_size: usize,

    /// Number of worker partitions
    pub partitions: usize,

    /// Backpressure configuration
    pub backpressure: BackpressureConfig,
}

impl Default for EventBusConfig {
    fn default() -> Self {
        Self {
            channel_size: 10000,
            batch_size: 100,
            partitions: 4,
            backpressure: BackpressureConfig::default(),
        }
    }
}

/// Handle for publishing events to the bus
#[derive(Debug, Clone)]
pub struct EventBusHandle {
    sender: mpsc::Sender<Event>,
    metrics: Arc<EventBusMetrics>,
}

impl EventBusHandle {
    /// Publish a single event
    pub async fn publish(&self, event: Event) -> Result<(), PublishError> {
        self.sender
            .send(event)
            .await
            .map_err(|_| PublishError::Closed)?;
        self.metrics.events_received.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Try to publish without blocking
    pub fn try_publish(&self, event: Event) -> Result<(), PublishError> {
        self.sender.try_send(event).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => PublishError::Full,
            mpsc::error::TrySendError::Closed(_) => PublishError::Closed,
        })?;
        self.metrics.events_received.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Get current metrics snapshot
    pub fn metrics(&self) -> EventBusMetricsSnapshot {
        self.metrics.snapshot()
    }
}

/// Event bus for transporting events
pub struct EventBus {
    _handles: Vec<tokio::task::JoinHandle<()>>,
    handle: EventBusHandle,
}

impl EventBus {
    /// Create a new event bus with the given configuration
    pub fn new(config: EventBusConfig) -> Self {
        let metrics = Arc::new(EventBusMetrics::default());
        let (sender, receiver) = mpsc::channel(config.channel_size);

        let handle = EventBusHandle {
            sender,
            metrics: metrics.clone(),
        };

        let mut handles = Vec::new();

        // Create a single worker that processes events from the receiver
        // TODO: In the future, create multiple workers with proper partitioning
        let metrics_clone = metrics.clone();
        let handle_task = tokio::spawn(async move {
            Self::worker_partition(
                0,
                receiver,
                mpsc::channel(config.batch_size).0, // Dummy channel for now
                config.batch_size,
                metrics_clone,
            )
            .await;
        });

        handles.push(handle_task);

        Self {
            _handles: handles,
            handle,
        }
    }

    /// Get a handle for publishing events
    pub fn handle(&self) -> EventBusHandle {
        self.handle.clone()
    }

    /// Worker partition that batches and delivers events
    async fn worker_partition(
        partition_id: usize,
        mut receiver: mpsc::Receiver<Event>,
        worker_tx: mpsc::Sender<Vec<Event>>,
        batch_size: usize,
        metrics: Arc<EventBusMetrics>,
    ) {
        let mut batch = Vec::with_capacity(batch_size);

        loop {
            tokio::select! {
                result = receiver.recv_many(&mut batch, batch_size) => {
                    match result {
                        0 => break, // Channel closed
                        _ => {
                            debug!(
                                partition = partition_id,
                                batch_size = batch.len(),
                                "Processing batch"
                            );

                            // Process batch (for now, just count)
                            metrics.events_processed.fetch_add(batch.len() as u64, Ordering::Relaxed);
                            batch.clear();
                        }
                    }
                }
            }
        }

        debug!(partition = partition_id, "Worker partition shutting down");
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

    #[tokio::test]
    async fn test_event_bus_basic() {
        let config = EventBusConfig::default();
        let bus = EventBus::new(config);
        let handle = bus.handle();

        let event = Event::builder()
            .event_type(1)
            .ts_mono(0)
            .ts_wall(0)
            .entity_key(0)
            .build()
            .unwrap();

        handle.publish(event).await.unwrap();

        // Give time for processing
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
        let bus = EventBus::new(config);
        let handle = bus.handle();

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

        // Give time for processing
        tokio::time::sleep(Duration::from_millis(100)).await;

        let metrics = handle.metrics();
        assert_eq!(metrics.events_received, 20);
    }
}
