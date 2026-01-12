use criterion::{BenchmarkGroup, BenchmarkId, Criterion};
use std::time::Duration;

use kestrel_core::{AlertOutputConfig, EventBusConfig};
use kestrel_engine::{DetectionEngine, EngineConfig};

use super::{create_test_schema, format_bytes, format_duration, generate_test_events};

const THROUGHPUT_EVENT_COUNTS: &[usize] = &[1000, 5000, 10000, 20000];

pub fn run_throughput_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");

    for &count in THROUGHPUT_EVENT_COUNTS {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter_custom(|iterations| {
                let runtime = tokio::runtime::Runtime::new().unwrap();

                let config = EngineConfig::default();

                let mut engine =
                    runtime.block_on(async { DetectionEngine::new(config).await.unwrap() });

                let events = generate_test_events(count);

                for event in &events[..100] {
                    runtime.block_on(async {
                        let _ = engine.eval_event(event).await;
                    });
                }

                let start = std::time::Instant::now();

                for _ in 0..iterations {
                    for event in &events {
                        runtime.block_on(async {
                            let _ = engine.eval_event(event).await;
                        });
                    }
                }

                let elapsed = start.elapsed();
                let total_events = count * iterations as usize;
                let eps = total_events as f64 / elapsed.as_secs_f64();
                let avg_latency = elapsed / (total_events as u32);

                println!("\n  Throughput: {:.0} events/second", eps);
                println!("  Average latency: {}", format_duration(avg_latency));

                elapsed
            });
        });
    }

    group.finish();
}

pub fn run_throughput_report() {
    println!("\n=== Throughput Benchmark Results ===\n");

    let runtime = tokio::runtime::Runtime::new().unwrap();

    let config = EngineConfig::default();

    let mut engine = runtime.block_on(async { DetectionEngine::new(config).await.unwrap() });

    for &count in THROUGHPUT_EVENT_COUNTS {
        let events = generate_test_events(count);

        for event in &events[..100] {
            runtime.block_on(async {
                let _ = engine.eval_event(event).await;
            });
        }

        let start = std::time::Instant::now();

        for event in &events {
            runtime.block_on(async {
                let _ = engine.eval_event(event).await;
            });
        }

        let elapsed = start.elapsed();
        let eps = count as f64 / elapsed.as_secs_f64();
        let avg_latency = elapsed / (count as u32);

        println!(
            "  {} events: {:.0} EPS (avg latency: {})",
            count,
            eps,
            format_duration(avg_latency)
        );
    }

    println!("\n  Target: 10,000 events/second");
}

pub fn run() {
    run_throughput_report();
}
