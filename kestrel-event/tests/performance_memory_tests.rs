//! Performance and Memory Tests for Event Module
//!
//! 性能测试和内存使用测试，验证事件构建和处理性能

use kestrel_event::Event;
use kestrel_schema::TypedValue;
use std::time::Instant;

// =============================================================================
// Event Creation Performance Tests
// =============================================================================

#[test]
fn test_event_creation_performance() {
    let iterations = 100_000;
    let start = Instant::now();

    for i in 0..iterations {
        let _event = Event::builder()
            .event_id(i as u64)
            .event_type(1)
            .ts_mono(i as u64 * 1_000_000)
            .ts_wall(i as u64 * 1_000_000)
            .entity_key(i as u128)
            .build()
            .unwrap();
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Event creation: {} events in {:?} ({:.0} events/sec)",
        iterations, elapsed, ops_per_sec
    );

    assert!(
        ops_per_sec > 100_000.0,
        "Event creation too slow: {:.0} events/sec",
        ops_per_sec
    );
}

#[test]
fn test_event_with_fields_creation_performance() {
    let iterations = 50_000;
    let start = Instant::now();

    for i in 0..iterations {
        let _event = Event::builder()
            .event_id(i as u64)
            .event_type(1)
            .ts_mono(i as u64 * 1_000_000)
            .ts_wall(i as u64 * 1_000_000)
            .entity_key(i as u128)
            .field(1, TypedValue::I64(i as i64))
            .field(2, TypedValue::String(format!("process_{}", i)))
            .field(3, TypedValue::U64(i as u64))
            .build()
            .unwrap();
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Event with fields creation: {} events in {:?} ({:.0} events/sec)",
        iterations, elapsed, ops_per_sec
    );

    assert!(ops_per_sec > 50_000.0, "Event creation with fields too slow");
}

#[test]
fn test_event_builder_reuse_performance() {
    let iterations = 100_000;
    let start = Instant::now();

    for i in 0..iterations {
        // Each iteration creates a fresh builder
        let builder = Event::builder();
        let _event = builder
            .event_id(i as u64)
            .event_type(1)
            .ts_mono(i as u64 * 1_000_000)
            .ts_wall(i as u64 * 1_000_000)
            .entity_key(i as u128)
            .build()
            .unwrap();
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Event builder pattern: {} iterations in {:?} ({:.0} ops/sec)",
        iterations, elapsed, ops_per_sec
    );
}

// =============================================================================
// Memory Usage Tests
// =============================================================================

#[test]
fn test_event_memory_overhead() {
    use std::mem::size_of;

    let base_event_size = size_of::<Event>();
    println!("✅ Event base memory: {} bytes", base_event_size);

    // Create events with varying field counts
    let sizes = vec![0, 1, 5, 10, 20];

    for field_count in sizes {
        let mut builder = Event::builder()
            .event_id(1)
            .event_type(1)
            .ts_mono(1_000_000)
            .ts_wall(1_000_000)
            .entity_key(1);

        for i in 0..field_count {
            builder = builder.field(i as u32, TypedValue::I64(i as i64));
        }

        let _event = builder.build().unwrap();
        let estimated_size = base_event_size + field_count * 32; // Rough estimate

        println!("   Event with {} fields: ~{} bytes estimated", field_count, estimated_size);
    }
}

#[test]
fn test_event_field_storage_efficiency() {
    let iterations = 10_000;
    let mut events = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let event = Event::builder()
            .event_id(i as u64)
            .event_type((i % 10) as u16)
            .ts_mono(i as u64 * 1_000_000)
            .ts_wall(i as u64 * 1_000_000)
            .entity_key((i % 100) as u128)
            .field(1, TypedValue::I64(i as i64))
            .field(2, TypedValue::String(format!("string_{}", i % 1000)))
            .field(3, TypedValue::Bool(i % 2 == 0))
            .build()
            .unwrap();

        events.push(event);
    }

    // Verify all events stored correctly
    assert_eq!(events.len(), iterations);

    // Verify entity key grouping works
    let entity_0_count = events.iter().filter(|e| e.entity_key == 0).count();
    assert!(entity_0_count > 0, "Should have events for entity 0");

    println!("✅ Stored {} events with 3 fields each", iterations);

    // Clean up
    drop(events);
}

// =============================================================================
// Timestamp Handling Performance
// =============================================================================

#[test]
fn test_timestamp_comparison_performance() {
    let iterations = 1_000_000;

    let event1 = Event::builder()
        .event_id(1)
        .event_type(1)
        .ts_mono(1_000_000_000)
        .ts_wall(1_700_000_000_000_000_000)
        .entity_key(1)
        .build()
        .unwrap();

    let event2 = Event::builder()
        .event_id(2)
        .event_type(1)
        .ts_mono(1_000_001_000)
        .ts_wall(1_700_000_000_001_000_000)
        .entity_key(1)
        .build()
        .unwrap();

    let start = Instant::now();

    for _ in 0..iterations {
        let _ = event1.ts_mono_ns < event2.ts_mono_ns;
        let _ = event2.ts_mono_ns - event1.ts_mono_ns;
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Timestamp comparison: {} ops in {:?} ({:.0} ops/sec)",
        iterations, elapsed, ops_per_sec
    );

    assert!(ops_per_sec > 10_000_000.0, "Timestamp comparison too slow");
}

#[test]
fn test_monotonic_timestamp_ordering() {
    let count = 1000;
    let mut events = Vec::with_capacity(count);

    for i in 0..count {
        let event = Event::builder()
            .event_id(i as u64)
            .event_type(1)
            .ts_mono((count - i) as u64 * 1_000_000) // Reverse order
            .ts_wall(i as u64 * 1_000_000)
            .entity_key(1)
            .build()
            .unwrap();
        events.push(event);
    }

    // Sort by monotonic timestamp
    events.sort_by(|a, b| a.ts_mono_ns.cmp(&b.ts_mono_ns));

    // Verify ordering
    for i in 0..count - 1 {
        assert!(events[i].ts_mono_ns <= events[i + 1].ts_mono_ns);
    }

    println!("✅ Monotonic timestamp ordering verified for {} events", count);
}

// =============================================================================
// Field Access Performance
// =============================================================================

#[test]
fn test_field_access_performance() {
    let event = Event::builder()
        .event_id(1)
        .event_type(1)
        .ts_mono(1_000_000)
        .ts_wall(1_000_000)
        .entity_key(1)
        .field(1, TypedValue::I64(42))
        .field(2, TypedValue::String("test".to_string()))
        .field(3, TypedValue::Bool(true))
        .field(4, TypedValue::U64(12345))
        .field(5, TypedValue::F64(std::f64::consts::PI))
        .build()
        .unwrap();

    let iterations = 500_000;
    let start = Instant::now();

    for _ in 0..iterations {
        let _ = event.get_field(1);
        let _ = event.get_field(2);
        let _ = event.get_field(3);
        let _ = event.get_field(4);
        let _ = event.get_field(5);
    }

    let elapsed = start.elapsed();
    let ops_per_sec = (iterations * 5) as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Field access: {} accesses in {:?} ({:.0} accesses/sec)",
        iterations * 5,
        elapsed,
        ops_per_sec
    );

    assert!(ops_per_sec > 1_000_000.0, "Field access too slow");
}

#[test]
fn test_field_access_by_id_performance() {
    let mut builder = Event::builder()
        .event_id(1)
        .event_type(1)
        .ts_mono(1_000_000)
        .ts_wall(1_000_000)
        .entity_key(1);

    // Add many fields
    for i in 0..100 {
        builder = builder.field(i, TypedValue::I64(i as i64));
    }

    let event = builder.build().unwrap();

    let iterations = 100_000;
    let start = Instant::now();

    for _ in 0..iterations {
        for i in 0..100 {
            let _ = event.get_field(i);
        }
    }

    let elapsed = start.elapsed();
    let ops_per_sec = (iterations * 100) as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Field access (100 fields): {} accesses in {:?} ({:.0} accesses/sec)",
        iterations * 100,
        elapsed,
        ops_per_sec
    );
}

// =============================================================================
// Entity Key Handling
// =============================================================================

#[test]
fn test_entity_key_distribution_performance() {
    let entity_count = 1000;
    let events_per_entity = 100;
    let total_events = entity_count * events_per_entity;

    let start = Instant::now();

    for i in 0..total_events {
        let entity_key = (i % entity_count) as u128;
        let _event = Event::builder()
            .event_id(i as u64)
            .event_type(1)
            .ts_mono(i as u64 * 1_000_000)
            .ts_wall(i as u64 * 1_000_000)
            .entity_key(entity_key)
            .build()
            .unwrap();
    }

    let elapsed = start.elapsed();
    let ops_per_sec = total_events as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Entity key distribution: {} events across {} entities in {:?} ({:.0} events/sec)",
        total_events, entity_count, elapsed, ops_per_sec
    );
}

// =============================================================================
// Event Type Variation Tests
// =============================================================================

#[test]
fn test_multiple_event_types_performance() {
    let event_types: Vec<u16> = (1..=100).collect();
    let iterations = 10_000;

    let start = Instant::now();

    for i in 0..iterations {
        let event_type = event_types[i % event_types.len()];
        let _event = Event::builder()
            .event_id(i as u64)
            .event_type(event_type)
            .ts_mono(i as u64 * 1_000_000)
            .ts_wall(i as u64 * 1_000_000)
            .entity_key((i % 100) as u128)
            .build()
            .unwrap();
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Multiple event types ({} types): {} events in {:?} ({:.0} events/sec)",
        event_types.len(),
        iterations,
        elapsed,
        ops_per_sec
    );
}

// =============================================================================
// Edge Cases and Stress Tests
// =============================================================================

#[test]
fn test_large_field_count_performance() {
    let field_counts = vec![10, 50, 100, 200];

    for count in field_counts {
        let mut builder = Event::builder()
            .event_id(1)
            .event_type(1)
            .ts_mono(1_000_000)
            .ts_wall(1_000_000)
            .entity_key(1);

        for i in 0..count {
            builder = builder.field(i as u32, TypedValue::I64(i as i64));
        }

        let start = Instant::now();
        let event = builder.build().unwrap();
        let elapsed = start.elapsed();

        // Verify event was created successfully
        assert!(event.event_type_id > 0);

        println!("✅ Large field count ({} fields): built in {:?}", count, elapsed);
    }
}

#[test]
fn test_large_string_field_performance() {
    let large_string = "x".repeat(10000);

    let start = Instant::now();
    let event = Event::builder()
        .event_id(1)
        .event_type(1)
        .ts_mono(1_000_000)
        .ts_wall(1_000_000)
        .entity_key(1)
        .field(1, TypedValue::String(large_string.clone()))
        .build()
        .unwrap();
    let elapsed = start.elapsed();

    let retrieved = event.get_field(1).unwrap();
    assert_eq!(retrieved.as_str(), Some(large_string.as_str()));

    println!("✅ Large string field ({} bytes): built in {:?}", large_string.len(), elapsed);
}

#[test]
fn test_event_clone_performance() {
    let event = Event::builder()
        .event_id(1)
        .event_type(1)
        .ts_mono(1_000_000)
        .ts_wall(1_000_000)
        .entity_key(1)
        .field(1, TypedValue::I64(42))
        .field(2, TypedValue::String("test".to_string()))
        .field(3, TypedValue::Bool(true))
        .build()
        .unwrap();

    let iterations = 100_000;
    let start = Instant::now();

    for _ in 0..iterations {
        let _clone = event.clone();
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Event clone: {} clones in {:?} ({:.0} clones/sec)",
        iterations, elapsed, ops_per_sec
    );
}

#[test]
fn test_burst_event_creation() {
    let burst_sizes = vec![100, 1000, 10000];

    for size in burst_sizes {
        let start = Instant::now();

        for i in 0..size {
            let _event = Event::builder()
                .event_id(i as u64)
                .event_type((i % 10) as u16)
                .ts_mono(i as u64 * 1_000)
                .ts_wall(i as u64 * 1_000)
                .entity_key((i % 100) as u128)
                .field(1, TypedValue::I64(i as i64))
                .field(2, TypedValue::String(format!("event_{}", i)))
                .build()
                .unwrap();
        }

        let elapsed = start.elapsed();
        let ops_per_sec = size as f64 / elapsed.as_secs_f64();

        println!(
            "✅ Burst event creation ({} events): {:?} ({:.0} events/sec)",
            size, elapsed, ops_per_sec
        );
    }
}

// =============================================================================
// End-to-End Event Processing Simulation
// =============================================================================

#[test]
fn test_event_processing_pipeline_simulation() {
    // Simulate a real event processing pipeline
    let event_count = 10_000;
    let mut events = Vec::with_capacity(event_count);

    // Phase 1: Event creation (simulating event collection)
    let create_start = Instant::now();
    for i in 0..event_count {
        let event = Event::builder()
            .event_id(i as u64)
            .event_type(match i % 4 {
                0 => 1001, // process_exec
                1 => 1002, // file_open
                2 => 1003, // network_connect
                _ => 1004, // registry_set
            })
            .ts_mono(i as u64 * 1_000_000)
            .ts_wall(1_700_000_000_000_000_000 + i as u64 * 1_000_000)
            .entity_key((i % 500) as u128) // 500 different processes
            .field(1, TypedValue::I64((i % 65535) as i64)) // pid
            .field(2, TypedValue::String(format!("/bin/process_{}", i % 100))) // exe
            .field(3, TypedValue::U64(i as u64)) // sequence number
            .build()
            .unwrap();
        events.push(event);
    }
    let create_time = create_start.elapsed();

    // Phase 2: Event sorting (simulating time window processing)
    let sort_start = Instant::now();
    events.sort_by(|a, b| a.ts_mono_ns.cmp(&b.ts_mono_ns));
    let sort_time = sort_start.elapsed();

    // Phase 3: Entity grouping (simulating per-entity analysis)
    let group_start = Instant::now();
    let mut entity_events: std::collections::HashMap<u128, Vec<&Event>> =
        std::collections::HashMap::new();
    for event in &events {
        entity_events
            .entry(event.entity_key)
            .or_default()
            .push(event);
    }
    let group_time = group_start.elapsed();

    // Phase 4: Field access (simulating rule evaluation)
    let eval_start = Instant::now();
    let mut total_fields = 0;
    for event in &events {
        if event.get_field(1).is_some() {
            total_fields += 1;
        }
        if event.get_field(2).is_some() {
            total_fields += 1;
        }
        if event.get_field(3).is_some() {
            total_fields += 1;
        }
    }
    let eval_time = eval_start.elapsed();

    println!("✅ Event processing pipeline simulation ({} events):", event_count);
    println!(
        "   Creation: {:?} ({:.0} events/sec)",
        create_time,
        event_count as f64 / create_time.as_secs_f64()
    );
    println!("   Sorting: {:?}", sort_time);
    println!("   Entity grouping: {:?} ({} entities)", group_time, entity_events.len());
    println!("   Field access: {:?} ({} accesses)", eval_time, total_fields);

    assert_eq!(events.len(), event_count);
    assert_eq!(entity_events.len(), 500);
    assert_eq!(total_fields, event_count * 3);
}
