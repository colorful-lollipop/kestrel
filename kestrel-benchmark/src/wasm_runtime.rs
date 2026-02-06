use std::sync::Arc;
use std::time::Duration;

use kestrel_runtime_wasm::{WasmConfig, WasmEngine};

use super::{calculate_percentiles, create_single_test_event, format_duration};

const WASM_EVAL_SAMPLES: usize = 10000;
const WASM_WARMUP: usize = 1000;

pub fn run_wasm_benchmarks() {
    println!("\n=== Wasm Runtime Benchmark ===\n");

    let schema = Arc::new(kestrel_schema::SchemaRegistry::new());
    let config = WasmConfig::default();

    let engine = WasmEngine::new(config, schema.clone());

    match engine {
        Ok(wasm_engine) => {
            run_wasm_evaluation_benchmark(&wasm_engine);
        }
        Err(e) => {
            println!("  Warning: WasmEngine creation failed: {:?}", e);
            println!("  Skipping Wasm benchmarks.");
        }
    }
}

fn run_wasm_evaluation_benchmark(_engine: &WasmEngine) {
    println!("  Wasm Predicate Evaluation:");

    let wasm_bytes = wat::parse_str(
        r#"
        (module
            (func $pred_eval (export "pred_eval") (result i32)
                (i32.const 1)
            )
            (memory (export "memory") 1)
        )
    "#,
    )
    .unwrap();

    let schema = Arc::new(kestrel_schema::SchemaRegistry::new());
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let engine = WasmEngine::new(WasmConfig::default(), schema.clone()).unwrap();

    runtime.block_on(async {
        let result = engine
            .compile_rule("test_predicate", wasm_bytes.clone())
            .await;
        if let Err(e) = result {
            println!("    Warning: Failed to compile Wasm predicate: {:?}", e);
            return;
        }
    });

    let event = create_single_test_event();

    println!("  Warming up ({} iterations)...", WASM_WARMUP);
    for _ in 0..WASM_WARMUP {
        runtime.block_on(async {
            let predicate = engine.create_predicate("test_predicate").unwrap();
            let _ = predicate.eval(&event).await;
        });
    }

    println!(
        "  Measuring Wasm evaluation ({} samples)...\n",
        WASM_EVAL_SAMPLES
    );

    let mut latencies = Vec::with_capacity(WASM_EVAL_SAMPLES);

    for _ in 0..WASM_EVAL_SAMPLES {
        let start = std::time::Instant::now();
        runtime.block_on(async {
            let predicate = engine.create_predicate("test_predicate").unwrap();
            let _ = predicate.eval(&event).await;
        });
        latencies.push(start.elapsed());
    }

    let (p50, p90, p99) = calculate_percentiles(&mut latencies);

    println!("  Wasm Evaluation Latency:");
    println!("    P50: {}", format_duration(p50));
    println!("    P90: {}", format_duration(p90));
    println!("    P99: {}", format_duration(p99));

    let sum: Duration = latencies.iter().sum();
    let avg = sum / latencies.len() as u32;
    println!("    Avg: {}", format_duration(avg));

    let throughput = WASM_EVAL_SAMPLES as f64 / (sum.as_secs_f64());
    println!("    Throughput: {:.0} evaluations/second", throughput);

    println!("\n  Target: P99 < 500ns");
}

pub fn run_instance_pooling_benchmark() {
    println!("\n=== Wasm Instance Pooling Benchmark ===\n");

    let schema = Arc::new(kestrel_schema::SchemaRegistry::new());
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let config = WasmConfig {
        pool_size: 4,
        ..Default::default()
    };

    let engine = WasmEngine::new(config, schema.clone()).unwrap();

    let wasm_bytes = wat::parse_str(
        r#"
        (module
            (func $pred_eval (export "pred_eval") (result i32)
                (i32.const 1)
            )
            (memory (export "memory") 1)
        )
    "#,
    )
    .unwrap();

    runtime.block_on(async {
        engine
            .compile_rule("pooled_predicate", wasm_bytes.clone())
            .await
            .unwrap();
    });

    let event = create_single_test_event();

    println!("  Testing instance pool (5000 concurrent evaluations):");

    let start = std::time::Instant::now();

    runtime.block_on(async {
        let mut handles = Vec::new();

        for _ in 0..5000 {
            let engine_clone = engine.clone();
            let event_clone = event.clone();

            handles.push(tokio::spawn(async move {
                let predicate = engine_clone.create_predicate("pooled_predicate").unwrap();
                let _ = predicate.eval(&event_clone).await;
            }));
        }

        for handle in handles {
            let _ = handle.await;
        }
    });

    let elapsed = start.elapsed();
    let throughput = 5000.0 / elapsed.as_secs_f64();

    println!("    Total evaluations: 5000");
    println!("    Time: {:?}", elapsed);
    println!("    Throughput: {:.0} evaluations/second", throughput);
    println!("    Avg latency: {:?}", elapsed / 5000);
}

pub fn run_regex_glob_benchmark() {
    println!("\n=== Wasm Regex/Glob Cache Benchmark ===\n");

    let schema = Arc::new(kestrel_schema::SchemaRegistry::new());
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let engine = WasmEngine::new(WasmConfig::default(), schema.clone()).unwrap();

    runtime.block_on(async {
        engine.register_regex(r"\d{4}-\d{2}-\d{2}").await.unwrap();
        engine.register_glob("*.exe").await.unwrap();
    });

    println!("  Regex cache hit rate test:");

    let mut latencies = Vec::with_capacity(10000);

    for _ in 0..10000 {
        let start = std::time::Instant::now();
        runtime.block_on(async {
            let _ = engine
                .eval_adhoc_predicate(
                    &wat::parse_str(
                        r#"
                    (module
                        (func $pred_eval (export "pred_eval") (result i32)
                            (i32.const 1)
                        )
                        (memory (export "memory") 1)
                    )
                "#,
                    )
                    .unwrap(),
                    &create_single_test_event(),
                )
                .await;
        });
        latencies.push(start.elapsed());
    }

    let sum: Duration = latencies.iter().sum();
    let avg = sum / latencies.len() as u32;

    println!("    Avg latency (with cache): {}", format_duration(avg));
    println!("    Target: < 100ns (cache hit)");
}

pub fn run() {
    run_wasm_benchmarks();
    run_instance_pooling_benchmark();
    run_regex_glob_benchmark();
}
