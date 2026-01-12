mod latency;
mod memory;
mod nfa;
mod stress_test;
mod throughput;
mod utils;
mod wasm_runtime;

pub use utils::{
    calculate_percentiles, create_single_test_event, create_test_schema, format_bytes,
    format_duration, generate_matching_sequence_events, generate_non_matching_events,
    generate_test_events,
};

use std::env;
use std::time::Instant;

fn print_header() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║           Kestrel Performance Benchmark Suite                   ║");
    println!("║                                                                ║");
    println!("║  Testing: 10k EPS throughput, <1µs latency, memory efficiency  ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!();
}

fn print_usage() {
    println!("Usage: kestrel-benchmark [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --all           Run all benchmarks (default)");
    println!("  --throughput    Run throughput benchmarks");
    println!("  --latency       Run latency benchmarks");
    println!("  --memory        Run memory benchmarks");
    println!("  --nfa           Run NFA engine benchmarks");
    println!("  --wasm          Run Wasm runtime benchmarks");
    println!("  --stress        Run stress tests");
    println!("  --help          Show this help message");
    println!();
}

fn main() {
    print_header();

    let args: Vec<String> = env::args().collect();
    let benchmark_type = args.get(1).map(|s| s.as_str()).unwrap_or("--all");

    let start = Instant::now();

    match benchmark_type {
        "--all" | "" => {
            throughput::run();
            println!();
            latency::run();
            println!();
            memory::run();
            println!();
            nfa::run();
            println!();
            wasm_runtime::run();
            println!();
            stress_test::run();
        }
        "--throughput" => throughput::run(),
        "--latency" => latency::run(),
        "--memory" => memory::run(),
        "--nfa" => nfa::run(),
        "--wasm" => wasm_runtime::run(),
        "--stress" => stress_test::run(),
        "--help" | "-h" | "help" => {
            print_usage();
            return;
        }
        _ => {
            println!("Unknown option: {}", benchmark_type);
            print_usage();
            return;
        }
    }

    let elapsed = start.elapsed();
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║  Benchmark completed in {:?}", elapsed);
    println!("╚════════════════════════════════════════════════════════════════╝");
}
