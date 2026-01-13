//! eBPF Performance Benchmarks
//!
//! Performance baseline tests for eBPF collector components:
//! - Event normalization throughput
//! - Interest pushdown overhead
//! - Memory allocation patterns
//! - Multi-threaded scalability

use std::time::Instant;
use kestrel_ebpf::{EbpfEventType, InterestPushdown, RawEbpfEvent};
use kestrel_schema::SchemaRegistry;
use std::sync::Arc;

/// Helper to create mock raw event
fn create_mock_raw_event(event_type: u32, pid: u32, ts: u64) -> RawEbpfEvent {
    RawEbpfEvent {
        event_type,
        ts_mono_ns: ts,
        entity_key: pid as u64,
        pid,
        ppid: if pid > 0 { pid - 1 } else { 0 },
        uid: 1000,
        gid: 1000,
        path_len: 0,
        cmdline_len: 0,
        exit_code: 0,
    }
}

#[cfg(test)]
mod normalization_benchmarks {
    use super::*;
    use kestrel_ebpf::EventNormalizer;

    #[test]
    fn benchmark_normalizer_creation() {
        let schema = Arc::new(SchemaRegistry::new());
        let start = Instant::now();
        let iterations = 10_000;

        for _ in 0..iterations {
            let normalizer = EventNormalizer::new(schema.clone());
            let _ = normalizer;
        }

        let elapsed = start.elapsed();
        let per_op_ns = elapsed.as_nanos() / iterations as u128;

        println!("Normalizer creation: {} ns/op", per_op_ns);
        println!("Total time: {:?}", elapsed);

        // Assert reasonable performance (< 1µs per creation)
        assert!(per_op_ns < 1000, "Normalizer creation too slow: {} ns", per_op_ns);
    }

    #[test]
    fn benchmark_normalize_empty_data() {
        let schema = Arc::new(SchemaRegistry::new());
        let normalizer = EventNormalizer::new(schema);
        let raw = create_mock_raw_event(1, 1234, 1000000);
        let empty_data = &[];

        let start = Instant::now();
        let iterations = 100_000;

        for _ in 0..iterations {
            let _ = normalizer.normalize(&raw, empty_data);
        }

        let elapsed = start.elapsed();
        let per_op_ns = elapsed.as_nanos() / iterations as u128;

        println!("Normalize (empty data): {} ns/op", per_op_ns);
        println!("Throughput: {} M ops/s", 1000 / per_op_ns);

        // Assert reasonable performance
        assert!(per_op_ns < 10_000, "Normalization too slow: {} ns", per_op_ns);
    }

    #[test]
    fn benchmark_batch_normalization() {
        let schema = Arc::new(SchemaRegistry::new());
        let normalizer = EventNormalizer::new(schema);
        let events: Vec<_> = (0..1000)
            .map(|i| create_mock_raw_event(1, i, i as u64 * 1000))
            .collect();

        let start = Instant::now();
        let iterations = 100;

        for _ in 0..iterations {
            for event in &events {
                let empty_data = &[];
                let _ = normalizer.normalize(event, empty_data);
            }
        }

        let elapsed = start.elapsed();
        let total_ops = iterations * events.len();
        let per_op_ns = elapsed.as_nanos() / total_ops as u128;

        println!("Batch normalization: {} ns/op", per_op_ns);
        println!("Total operations: {}", total_ops);
        println!("Total time: {:?}", elapsed);

        assert!(per_op_ns < 10_000, "Batch normalization too slow: {} ns", per_op_ns);
    }
}

#[cfg(test)]
mod pushdown_benchmarks {
    use super::*;

    #[test]
    fn benchmark_pushdown_creation() {
        let start = Instant::now();
        let iterations = 10_000;

        for _ in 0..iterations {
            let pushdown = InterestPushdown::new();
            let _ = pushdown;
        }

        let elapsed = start.elapsed();
        let per_op_ns = elapsed.as_nanos() / iterations as u128;

        println!("Pushdown creation: {} ns/op", per_op_ns);

        assert!(per_op_ns < 1000, "Pushdown creation too slow: {} ns", per_op_ns);
    }

    #[test]
    fn benchmark_update_event_types() {
        let pushdown = InterestPushdown::new();
        let types = vec![
            EbpfEventType::ProcessExec,
            EbpfEventType::ProcessExit,
            EbpfEventType::FileOpen,
            EbpfEventType::FileRename,
            EbpfEventType::NetworkConnect,
        ];

        let start = Instant::now();
        let iterations = 100_000;

        for _ in 0..iterations {
            pushdown.update_event_types(types.clone());
        }

        let elapsed = start.elapsed();
        let per_op_ns = elapsed.as_nanos() / iterations as u128;

        println!("Update event types: {} ns/op", per_op_ns);

        assert!(per_op_ns < 50_000, "Update too slow: {} ns", per_op_ns);
    }

    #[test]
    fn benchmark_add_field_interest() {
        let pushdown = InterestPushdown::new();
        let start = Instant::now();
        let iterations = 100_000;

        for i in 0..iterations {
            pushdown.add_field_interest(1, i % 1000);
        }

        let elapsed = start.elapsed();
        let per_op_ns = elapsed.as_nanos() / iterations as u128;

        println!("Add field interest: {} ns/op", per_op_ns);

        assert!(per_op_ns < 50_000, "Add interest too slow: {} ns", per_op_ns);
    }

    #[test]
    fn benchmark_is_event_type_interesting() {
        let pushdown = InterestPushdown::new();
        pushdown.update_event_types(vec![
            EbpfEventType::ProcessExec,
            EbpfEventType::ProcessExit,
        ]);

        let start = Instant::now();
        let iterations = 1_000_000;

        for i in 0..iterations {
            let event_type = if i % 2 == 0 {
                EbpfEventType::ProcessExec
            } else {
                EbpfEventType::ProcessExit
            };
            let _ = pushdown.is_event_type_interesting(event_type);
        }

        let elapsed = start.elapsed();
        let per_op_ns = elapsed.as_nanos() / iterations as u128;

        println!("Is interesting check: {} ns/op", per_op_ns);
        println!("Throughput: {} M checks/s", 1000 / per_op_ns);

        // Should be very fast - just a hash lookup
        assert!(per_op_ns < 1500, "Interest check too slow: {} ns", per_op_ns);
    }

    #[test]
    fn benchmark_get_field_interests() {
        let pushdown = InterestPushdown::new();
        for i in 0..100 {
            pushdown.add_field_interest(1, i);
        }

        let start = Instant::now();
        let iterations = 100_000;

        for _ in 0..iterations {
            let _ = pushdown.get_field_interests(1);
        }

        let elapsed = start.elapsed();
        let per_op_ns = elapsed.as_nanos() / iterations as u128;

        println!("Get field interests: {} ns/op", per_op_ns);

        assert!(per_op_ns < 10_000, "Get interests too slow: {} ns", per_op_ns);
    }
}

#[cfg(test)]
mod memory_benchmarks {
    use super::*;

    #[test]
    fn benchmark_event_allocation() {
        let start = Instant::now();
        let iterations = 100_000;

        let events: Vec<_> = (0..iterations)
            .map(|i| create_mock_raw_event(1, i, i as u64 * 1000))
            .collect();

        let elapsed = start.elapsed();
        let per_op_ns = elapsed.as_nanos() / iterations as u128;

        println!("Event allocation: {} ns/op", per_op_ns);
        println!("Total events: {}", events.len());

        assert!(per_op_ns < 1000, "Event allocation too slow: {} ns", per_op_ns);
    }

    #[test]
    fn benchmark_vector_capacity_growth() {
        let start = Instant::now();
        let iterations = 10_000;

        let mut all_events = Vec::new();
        for i in 0..iterations {
            let event = create_mock_raw_event(1, i, i as u64 * 1000);
            all_events.push(event);
        }

        let elapsed = start.elapsed();
        let per_op_ns = elapsed.as_nanos() / iterations as u128;

        println!("Vector push (with growth): {} ns/op", per_op_ns);
        println!("Final capacity: {}", all_events.capacity());

        // Vector growth is amortized O(1), should be fast
        assert!(per_op_ns < 500, "Vector push too slow: {} ns", per_op_ns);
    }
}

#[cfg(test)]
mod scalability_benchmarks {
    use super::*;

    #[test]
    fn benchmark_large_field_interests() {
        let pushdown = InterestPushdown::new();
        let num_fields = 10_000;

        // Add many field interests
        for i in 0..num_fields {
            pushdown.add_field_interest(1, i);
        }

        // Benchmark lookup performance
        let start = Instant::now();
        let iterations = 10_000;

        for _ in 0..iterations {
            let _ = pushdown.get_field_interests(1);
        }

        let elapsed = start.elapsed();
        let per_op_ns = elapsed.as_nanos() / iterations as u128;

        println!("Get interests ({} fields): {} ns/op", num_fields, per_op_ns);

        // Should still be fast with HashSet
        assert!(per_op_ns < 100_000, "Large lookup too slow: {} ns", per_op_ns);
    }

    #[test]
    fn benchmark_multiple_event_types() {
        let pushdown = InterestPushdown::new();
        let all_types = vec![
            EbpfEventType::ProcessExec,
            EbpfEventType::ProcessExit,
            EbpfEventType::FileOpen,
            EbpfEventType::FileRename,
            EbpfEventType::FileUnlink,
            EbpfEventType::NetworkConnect,
            EbpfEventType::NetworkSend,
        ];

        pushdown.update_event_types(all_types.clone());

        let start = Instant::now();
        let iterations = 1_000_000;

        for i in 0..iterations {
            let event_type = all_types[i % all_types.len()];
            let _ = pushdown.is_event_type_interesting(event_type);
        }

        let elapsed = start.elapsed();
        let per_op_ns = elapsed.as_nanos() / iterations as u128;

        println!("Interest check (7 types): {} ns/op", per_op_ns);
        println!("Throughput: {} M checks/s", 1000 / per_op_ns);

        assert!(per_op_ns < 1500, "Multi-type check too slow: {} ns", per_op_ns);
    }
}
