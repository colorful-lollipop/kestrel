// Event Processing Benchmarks
//
// Benchmarks for event creation, iteration, and cloning throughput.

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use kestrel_event::Event;
use kestrel_schema::TypedValue;

fn create_test_event(event_type: u16, ts: u64, entity_key: u128) -> Event {
    Event::builder()
        .event_type(event_type)
        .ts_mono(ts)
        .ts_wall(ts)
        .entity_key(entity_key)
        .field(1, TypedValue::String("/bin/bash".into()))
        .field(2, TypedValue::U64(1234))
        .field(3, TypedValue::String("/etc/passwd".into()))
        .field(4, TypedValue::I64(5678))
        .field(5, TypedValue::Bool(true))
        .field(6, TypedValue::String("192.168.1.1".into()))
        .field(7, TypedValue::U64(443))
        .field(8, TypedValue::String("curl".into()))
        .build()
        .unwrap()
}

fn create_test_event_16_fields(event_type: u16, ts: u64, entity_key: u128) -> Event {
    let mut builder = Event::builder()
        .event_type(event_type)
        .ts_mono(ts)
        .ts_wall(ts)
        .entity_key(entity_key);

    for i in 1..=16 {
        let value = match i % 4 {
            0 => TypedValue::String(format!("string_value_{}", i).into()),
            1 => TypedValue::U64(i as u64),
            2 => TypedValue::I64(i as i64),
            _ => TypedValue::Bool(i % 2 == 0),
        };
        builder = builder.field(i as u32, value);
    }

    builder.build().unwrap()
}

fn bench_event_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_creation");

    group.bench_function("8_fields", |b| {
        b.iter(|| {
            black_box(create_test_event(1, 1_000_000_000, 0x12345));
        });
    });

    group.bench_function("16_fields", |b| {
        b.iter(|| {
            black_box(create_test_event_16_fields(1, 1_000_000_000, 0x12345));
        });
    });

    group.finish();
}

fn bench_event_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_throughput");

    for event_count in [100, 1000, 10000].iter() {
        let events: Vec<Event> = (0..*event_count)
            .map(|i| {
                create_test_event(
                    1001 + (i % 10) as u16,
                    1_000_000_000 + i as u64,
                    i as u128,
                )
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("iterate", event_count),
            event_count,
            |b, _| {
                b.iter(|| {
                    for event in &events {
                        black_box(event.event_type_id);
                        black_box(event.ts_mono_ns);
                    }
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("clone", event_count),
            event_count,
            |b, _| {
                b.iter(|| {
                    for event in &events {
                        black_box(event.clone());
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_event_creation, bench_event_throughput);
criterion_main!(benches);
