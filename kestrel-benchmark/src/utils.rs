use kestrel_event::Event;
use kestrel_schema::{FieldId, SchemaRegistry, TypedValue};
use rand::Rng;
use std::sync::Arc;

pub fn create_test_schema() -> Arc<SchemaRegistry> {
    Arc::new(SchemaRegistry::new())
}

pub fn generate_test_events(count: usize) -> Vec<Event> {
    let mut rng = rand::thread_rng();
    let mut events = Vec::with_capacity(count);

    for i in 0..count {
        let ts = 1_000_000_000u64 + (i as u64 * 1000);
        let entity_key = rng.gen_range(0..100u128);

        let event = Event::builder()
            .event_id(i as u64)
            .event_type(rng.gen_range(1..5))
            .ts_mono(ts)
            .ts_wall(ts)
            .entity_key(entity_key)
            .field(
                1,
                TypedValue::String(format!("/bin/cmd_{}", rng.gen_range(0..10))),
            )
            .field(2, TypedValue::I64(rng.gen()))
            .field(3, TypedValue::U64(rng.gen()))
            .field(4, TypedValue::Bool(rng.gen()))
            .build()
            .unwrap();

        events.push(event);
    }

    events
}

pub fn generate_matching_sequence_events(count: usize) -> Vec<Event> {
    let mut events = Vec::with_capacity(count);
    let entity_key = 0x123456789abcdefu128;

    for i in 0..count {
        let step = i % 3;
        let ts = 1_000_000_000u64 + (i as u64 * 1000);

        let event = match step {
            0 => Event::builder()
                .event_id(i as u64)
                .event_type(1)
                .ts_mono(ts)
                .ts_wall(ts)
                .entity_key(entity_key)
                .field(1, TypedValue::String("/bin/curl".into()))
                .build()
                .unwrap(),
            1 => Event::builder()
                .event_id(i as u64)
                .event_type(2)
                .ts_mono(ts)
                .ts_wall(ts)
                .entity_key(entity_key)
                .field(2, TypedValue::String("evil.com".into()))
                .build()
                .unwrap(),
            _ => Event::builder()
                .event_id(i as u64)
                .event_type(3)
                .ts_mono(ts)
                .ts_wall(ts)
                .entity_key(entity_key)
                .field(3, TypedValue::String("/etc/passwd".into()))
                .build()
                .unwrap(),
        };

        events.push(event);
    }

    events
}

pub fn generate_non_matching_events(count: usize) -> Vec<Event> {
    let mut rng = rand::thread_rng();
    let mut events = Vec::with_capacity(count);

    for i in 0..count {
        let ts = 1_000_000_000u64 + (i as u64 * 1000);
        let entity_key = rng.gen_range(0..100u128);

        let event = Event::builder()
            .event_id(i as u64)
            .event_type(10)
            .ts_mono(ts)
            .ts_wall(ts)
            .entity_key(entity_key)
            .field(1, TypedValue::String("/safe/command".into()))
            .field(2, TypedValue::I64(rng.gen()))
            .build()
            .unwrap();

        events.push(event);
    }

    events
}

pub fn create_single_test_event() -> Event {
    Event::builder()
        .event_id(0)
        .event_type(1)
        .ts_mono(1_000_000_000)
        .ts_wall(1_000_000_000)
        .entity_key(0x123456789abcdef)
        .field(1, TypedValue::String("/bin/bash".into()))
        .field(2, TypedValue::I64(1234))
        .field(3, TypedValue::U64(5678))
        .field(4, TypedValue::Bool(true))
        .build()
        .unwrap()
}

pub fn calculate_percentiles(
    values: &mut Vec<std::time::Duration>,
) -> (
    std::time::Duration,
    std::time::Duration,
    std::time::Duration,
) {
    values.sort();
    let len = values.len();

    let p50 = values[len / 2].clone();
    let p90 = values[(len * 90) / 100].clone();
    let p99 = values[(len * 99) / 100].clone();

    (p50, p90, p99)
}

pub fn format_duration(d: std::time::Duration) -> String {
    let nanos = d.as_nanos();
    if nanos < 1000 {
        format!("{} ns", nanos)
    } else if nanos < 1_000_000 {
        format!("{:.2} µs", nanos as f64 / 1000.0)
    } else if nanos < 1_000_000_000 {
        format!("{:.2} ms", nanos as f64 / 1_000_000.0)
    } else {
        format!("{:.2} s", nanos as f64 / 1_000_000_000.0)
    }
}

pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
