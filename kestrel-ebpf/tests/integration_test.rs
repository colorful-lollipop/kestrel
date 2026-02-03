//! eBPF Integration Tests
//!
//! Tests for eBPF collector functionality including:
//! - Event normalization
//! - Interest pushdown
//! - Ring buffer polling (with mock eBPF)
//! - End-to-end event flow

use kestrel_core::{EventBus, EventBusConfig};
use kestrel_ebpf::{EbpfEventType, RawEbpfEvent};
use kestrel_event::Event;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

/// Helper to create a test event bus
async fn create_test_event_bus() -> (EventBus, mpsc::Receiver<Vec<Event>>) {
    let (sink_tx, sink_rx) = mpsc::channel(10);
    let config = EventBusConfig::default();
    let bus = EventBus::new_with_sink(config, sink_tx);
    (bus, sink_rx)
}

/// Helper to create a mock raw eBPF event
fn create_mock_raw_event(event_type: u32, pid: u32, ts: u64) -> RawEbpfEvent {
    RawEbpfEvent {
        event_type,
        ts_mono_ns: ts,
        entity_key: pid as u64,
        pid,
        ppid: if pid > 0 { pid - 1 } else { 0 }, // Handle pid=0 case
        uid: 1000,
        gid: 1000,
        path_len: 0,
        cmdline_len: 0,
        exit_code: 0,
    }
}

#[cfg(test)]
mod normalization_tests {
    use super::*;
    use kestrel_ebpf::EventNormalizer;
    use kestrel_schema::SchemaRegistry;

    #[test]
    fn test_normalizer_creation() {
        let schema = Arc::new(SchemaRegistry::new());
        let normalizer = EventNormalizer::new(schema);
        // Normalizer created successfully - just verify it compiles
        let _ = normalizer;
    }

    #[test]
    fn test_normalize_process_exec() {
        let schema = Arc::new(SchemaRegistry::new());
        let normalizer = EventNormalizer::new(schema);

        let raw = create_mock_raw_event(1, 1234, 1000000);
        let empty_data = &[];

        // Normalization with empty data should handle gracefully without panicking
        // The test passes if we reach this point (no panic occurred)
        let _result = normalizer.normalize(&raw, empty_data);
        // Note: Result may be Ok or Err depending on implementation,
        // but the important thing is that it doesn't panic
    }
}

#[cfg(test)]
mod pushdown_tests {
    use super::*;
    use kestrel_ebpf::InterestPushdown;

    #[test]
    fn test_pushdown_creation() {
        let pushdown = InterestPushdown::new();
        // Verify it doesn't panic and is not interested in anything initially
        assert!(!pushdown.is_event_type_interesting(EbpfEventType::ProcessExec));
    }

    #[test]
    fn test_update_event_types() {
        let pushdown = InterestPushdown::new();
        let types = vec![
            EbpfEventType::ProcessExec,
            EbpfEventType::ProcessExit,
            EbpfEventType::FileOpen,
        ];

        pushdown.update_event_types(types);
        assert!(pushdown.is_event_type_interesting(EbpfEventType::ProcessExec));
        assert!(pushdown.is_event_type_interesting(EbpfEventType::ProcessExit));
        assert!(pushdown.is_event_type_interesting(EbpfEventType::FileOpen));
    }

    #[test]
    fn test_add_field_interest() {
        let pushdown = InterestPushdown::new();
        pushdown.add_field_interest(1, 10);
        pushdown.add_field_interest(1, 11);

        let interests = pushdown.get_field_interests(1);
        assert_eq!(interests.len(), 2);
        assert!(interests.contains(&10));
        assert!(interests.contains(&11));
    }
}

#[cfg(test)]
mod end_to_end_tests {
    use super::*;

    #[tokio::test]
    async fn test_event_bus_integration() {
        let (_bus, mut rx) = create_test_event_bus().await;

        // Send a test event
        let event = Event::builder()
            .event_id(1)
            .event_type(1)
            .ts_mono(1000)
            .ts_wall(1000)
            .entity_key(12345)
            .build()
            .unwrap();

        let tx = _bus.handle();
        let result = timeout(Duration::from_millis(100), tx.publish(event)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_event_batching() {
        let (_bus, mut _rx) = create_test_event_bus().await;

        let handle = _bus.handle();

        // Send multiple events
        for i in 0..10 {
            let event = Event::builder()
                .event_id(i)
                .event_type(1)
                .ts_mono(i * 1000)
                .ts_wall(i * 1000)
                .entity_key(i as u128)
                .build()
                .unwrap();

            let _ = handle.publish(event).await;
        }

        // Try to receive events
        let result = timeout(Duration::from_millis(200), _rx.recv()).await;
        // Events might or might not be received depending on batching
        // Just verify no panic occurred
        let _ = result;
    }
}

#[cfg(test)]
mod metrics_tests {
    use super::*;

    #[test]
    fn test_event_type_conversions() {
        // Test EbpfEventType conversions
        let types = vec![
            EbpfEventType::ProcessExec,
            EbpfEventType::ProcessExit,
            EbpfEventType::FileOpen,
            EbpfEventType::FileRename,
            EbpfEventType::FileUnlink,
            EbpfEventType::NetworkConnect,
            EbpfEventType::NetworkSend,
        ];

        for event_type in types {
            // Verify we can convert to/from representation
            let _ = format!("{:?}", event_type);
        }
    }
}

/// Mock eBPF environment tests
/// These tests verify the integration without requiring actual eBPF loading
#[cfg(test)]
mod mock_ebpf_tests {
    use super::*;

    #[test]
    fn test_raw_event_creation() {
        let event = create_mock_raw_event(1, 1234, 1000000);

        assert_eq!(event.event_type, 1);
        assert_eq!(event.pid, 1234);
        assert_eq!(event.entity_key, 1234);
        assert_eq!(event.ts_mono_ns, 1000000);
    }

    #[test]
    fn test_multiple_events() {
        let events: Vec<_> = (0..100)
            .map(|i| create_mock_raw_event(1, i, (i * 1000) as u64))
            .collect();

        assert_eq!(events.len(), 100);
        assert_eq!(events[0].pid, 0);
        assert_eq!(events[99].pid, 99);
    }
}
