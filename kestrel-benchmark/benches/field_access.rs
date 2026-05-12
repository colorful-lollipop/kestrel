// Field Access Benchmarks
//
// Benchmarks for event field lookup and TypedValue cloning.

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use kestrel_event::Event;
use kestrel_schema::TypedValue;

fn create_event_with_n_fields(n: usize) -> Event {
    let mut builder = Event::builder()
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(42);

    for i in 1..=n {
        let value = match i % 4 {
            0 => TypedValue::String(format!("value_{}", i).into()),
            1 => TypedValue::U64(i as u64),
            2 => TypedValue::I64(i as i64),
            _ => TypedValue::Bool(i % 2 == 0),
        };
        builder = builder.field(i as u32, value);
    }

    builder.build().unwrap()
}

fn bench_field_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("field_access");

    // Linear search (<=8 fields)
    let small_event = create_event_with_n_fields(8);
    group.bench_function("linear_search_8_fields", |b| {
        b.iter(|| {
            for i in 1..=8 {
                black_box(small_event.get_field(black_box(i as u32)));
            }
        });
    });

    // Binary search (>8 fields)
    let large_event = create_event_with_n_fields(16);
    group.bench_function("binary_search_16_fields", |b| {
        b.iter(|| {
            for i in 1..=16 {
                black_box(large_event.get_field(black_box(i as u32)));
            }
        });
    });

    // Benchmark searching for non-existent field
    group.bench_function("search_missing_field_small", |b| {
        b.iter(|| {
            black_box(small_event.get_field(black_box(999)));
        });
    });

    group.bench_function("search_missing_field_large", |b| {
        b.iter(|| {
            black_box(large_event.get_field(black_box(999)));
        });
    });

    // Varying field counts
    for field_count in [4, 8, 12, 16, 24, 32].iter() {
        let event = create_event_with_n_fields(*field_count);
        group.bench_with_input(
            BenchmarkId::new("get_field_all", field_count),
            field_count,
            |b, _| {
                b.iter(|| {
                    for i in 1..=*field_count {
                        black_box(event.get_field(black_box(i as u32)));
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_typed_value_clone(c: &mut Criterion) {
    let mut group = c.benchmark_group("typed_value_clone");

    let string_value =
        TypedValue::String("a moderately long string value for benchmarking".into());
    let arc_str: std::sync::Arc<str> =
        std::sync::Arc::from("a moderately long string value for benchmarking");
    let u64_value = TypedValue::U64(123_456_789);
    let bool_value = TypedValue::Bool(true);
    let i64_value = TypedValue::I64(-123_456_789);

    group.bench_function("string", |b| {
        b.iter(|| {
            black_box(string_value.clone());
        });
    });

    group.bench_function("arc_str_explicit", |b| {
        b.iter(|| {
            black_box(arc_str.clone());
        });
    });

    group.bench_function("u64", |b| {
        b.iter(|| {
            black_box(u64_value.clone());
        });
    });

    group.bench_function("bool", |b| {
        b.iter(|| {
            black_box(bool_value.clone());
        });
    });

    group.bench_function("i64", |b| {
        b.iter(|| {
            black_box(i64_value.clone());
        });
    });

    group.finish();
}

criterion_group!(benches, bench_field_access, bench_typed_value_clone);
criterion_main!(benches);
