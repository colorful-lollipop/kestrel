use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use kestrel_core::{AlertOutputConfig, EventBusConfig};
use kestrel_engine::{DetectionEngine, EngineConfig};

use super::{format_bytes, generate_test_events};

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

pub fn run_memory_benchmark() {
    println!("\n=== Memory Usage Benchmark ===\n");

    let idle_memory = get_memory_usage().unwrap_or(0);
    println!("  Idle memory (baseline): {}", format_bytes(idle_memory));

    let runtime = tokio::runtime::Runtime::new().unwrap();

    let config = EngineConfig::default();

    println!("\n  Creating detection engine...");
    let engine_memory = get_memory_usage().unwrap_or(0) - idle_memory;
    println!("    Engine memory: {}", format_bytes(engine_memory));

    let mut engine = runtime.block_on(async { DetectionEngine::new(config).await.unwrap() });

    let after_engine = get_memory_usage().unwrap_or(0);
    println!("    Total with engine: {}", format_bytes(after_engine));

    runtime.block_on(async {
        engine.compile_rules().await.unwrap();
    });

    let after_rules = get_memory_usage().unwrap_or(0);
    let rules_memory = after_rules - after_engine;
    println!("\n  After loading rules:");
    println!("    Rules memory: {}", format_bytes(rules_memory));
    println!("    Total: {}", format_bytes(after_rules));

    println!("\n  Running throughput test (10000 events)...");
    let events = generate_test_events(10000);
    let peak_memory = Arc::new(AtomicU64::new(after_rules));

    for event in &events {
        runtime.block_on(async {
            let _ = engine.eval_event(event).await;
        });

        if let Some(mem) = get_memory_usage() {
            peak_memory.store(
                mem.max(peak_memory.load(Ordering::Relaxed)),
                Ordering::Relaxed,
            );
        }
    }

    let peak = peak_memory.load(Ordering::Relaxed);
    let peak_increase = peak - idle_memory;
    println!("\n  Peak memory during throughput:");
    println!("    Peak: {}", format_bytes(peak));
    println!("    Increase from idle: {}", format_bytes(peak_increase));

    println!("\n  Memory Targets:");
    println!("    Idle memory: < 50 MB");
    println!("    Per 10k events: < 100 MB");
}

pub fn run() {
    run_memory_benchmark();
}
