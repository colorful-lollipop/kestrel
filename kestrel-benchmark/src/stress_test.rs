use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kestrel_engine::{DetectionEngine, EngineConfig};

use super::format_bytes;

fn get_memory_usage() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|line| line.starts_with("VmRSS:"))?
        .split_whitespace()
        .nth(1)?
        .parse::<u64>()
        .ok()
        .map(|kb| kb * 1024)
}

pub fn run_stress_test(duration_secs: u64) {
    println!("\n=== Stress Test ({} seconds) ===\n", duration_secs);

    let runtime = tokio::runtime::Runtime::new().unwrap();

    let config = EngineConfig::default();

    let mut engine = runtime.block_on(async { DetectionEngine::new(config).await.unwrap() });

    let events_processed = Arc::new(AtomicUsize::new(0));
    let alerts_generated = Arc::new(AtomicUsize::new(0));
    let start_time = Instant::now();
    let start_memory = get_memory_usage().unwrap_or(0);

    println!("  Start memory: {}", format_bytes(start_memory));
    println!("  Processing events...\n");

    let mut event_id = 0usize;
    let mut batch = Vec::new();

    while start_time.elapsed() < Duration::from_secs(duration_secs) {
        batch.clear();

        for _ in 0..100 {
            if start_time.elapsed() >= Duration::from_secs(duration_secs) {
                break;
            }

            let event = generate_single_event(event_id);
            event_id += 1;
            batch.push(event);
        }

        for event in &batch {
            runtime.block_on(async {
                match engine.eval_event(event).await {
                    Ok(alerts) => {
                        events_processed.fetch_add(1, Ordering::Relaxed);
                        alerts_generated.fetch_add(alerts.len(), Ordering::Relaxed);
                    }
                    Err(_) => {}
                }
            });
        }

        if event_id % 10000 == 0 {
            let elapsed = start_time.elapsed();
            let processed = events_processed.load(Ordering::Relaxed);
            let current_memory = get_memory_usage().unwrap_or(start_memory);

            println!(
                "    {} events processed ({:.1} events/sec)",
                processed,
                processed as f64 / elapsed.as_secs_f64()
            );
            println!("    Current memory: {}", format_bytes(current_memory));
        }
    }

    let elapsed = start_time.elapsed();
    let processed = events_processed.load(Ordering::Relaxed);
    let alerts = alerts_generated.load(Ordering::Relaxed);
    let end_memory = get_memory_usage().unwrap_or(start_memory);

    println!("\n  Stress Test Results:");
    println!("    Total time: {:?}", elapsed);
    println!("    Total events processed: {}", processed);
    println!("    Total alerts generated: {}", alerts);
    println!(
        "    Throughput: {:.0} events/second",
        processed as f64 / elapsed.as_secs_f64()
    );
    println!("    End memory: {}", format_bytes(end_memory));
    println!(
        "    Memory growth: {}",
        format_bytes(end_memory.saturating_sub(start_memory))
    );

    let max_memory = end_memory;
    if max_memory > start_memory * 2 {
        println!("\n  WARNING: Memory grew by more than 100% - possible leak!");
    } else {
        println!("\n  Memory usage appears stable.");
    }
}

fn generate_single_event(id: usize) -> kestrel_event::Event {
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let ts = 1_000_000_000u64 + (id as u64 * 1000);
    let entity_key = rng.gen_range(0..100u128);

    kestrel_event::Event::builder()
        .event_id(id as u64)
        .event_type(rng.gen_range(1..5))
        .ts_mono(ts)
        .ts_wall(ts)
        .entity_key(entity_key)
        .field(
            1,
            kestrel_schema::TypedValue::String(format!("/bin/cmd_{}", rng.gen_range(0..10))),
        )
        .field(2, kestrel_schema::TypedValue::I64(rng.gen()))
        .field(3, kestrel_schema::TypedValue::U64(rng.gen()))
        .field(4, kestrel_schema::TypedValue::Bool(rng.gen()))
        .build()
        .unwrap()
}

pub fn run_concurrent_stress_test(_num_threads: usize, _duration_secs: u64) {
    println!("\n  Concurrent stress test skipped (complex async sharing required)");
}

pub fn run() {
    run_stress_test(30);
    run_concurrent_stress_test(4, 30);
}
