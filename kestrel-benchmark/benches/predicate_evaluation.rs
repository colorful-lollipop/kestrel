// Predicate Evaluation Benchmarks
//
// Benchmarks comparing Wasm, Lua, and baseline predicate evaluation.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use kestrel_event::Event;
use kestrel_schema::{RuleManifest, RuleMetadata, SchemaRegistry, TypedValue};
use std::sync::Arc;

fn always_match_baseline(_event: &Event) -> bool {
    true
}

fn bench_predicate_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("predicate_evaluation");

    // AlwaysMatch baseline
    group.bench_function("always_match", |b| {
        let event = Event::builder()
            .event_type(1)
            .ts_mono(1000)
            .ts_wall(1000)
            .entity_key(42)
            .field(1, TypedValue::U64(1234))
            .build()
            .unwrap();

        b.iter(|| {
            black_box(always_match_baseline(black_box(&event)));
        });
    });

    // Wasm predicate evaluation
    group.bench_function("wasm", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let schema = Arc::new(SchemaRegistry::new());
        let mut config = kestrel_runtime_wasm::WasmConfig::default();
        config.enable_fuel = false;
        let engine = kestrel_runtime_wasm::WasmEngine::new(config, schema.clone()).unwrap();

        let wasm_bytes = wat::parse_str(
            r#"
            (module
                (func (export "pred_eval") (param i32) (result i32)
                    (i32.const 1)
                )
                (memory (export "memory") 1)
            )
            "#,
        )
        .unwrap();

        let manifest = RuleManifest::new(RuleMetadata::new("bench-wasm", "Bench Wasm"));

        rt.block_on(async {
            engine
                .load_module(manifest, wasm_bytes, ahash::AHashMap::new())
                .await
                .unwrap();
        });

        let event = Event::builder()
            .event_type(1)
            .ts_mono(1000)
            .ts_wall(1000)
            .entity_key(42)
            .field(1, TypedValue::U64(1234))
            .build()
            .unwrap();

        b.iter(|| {
            rt.block_on(async {
                black_box(
                    engine
                        .eval_loaded_predicate("bench-wasm", 0, black_box(&event))
                        .await
                        .unwrap(),
                );
            });
        });
    });

    // Lua predicate evaluation
    group.bench_function("lua", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let schema = Arc::new(SchemaRegistry::new());
        let engine = kestrel_runtime_lua::LuaEngine::new(
            kestrel_runtime_lua::LuaConfig::default(),
            schema.clone(),
        )
        .unwrap();

        let script = r#"
            function pred_eval(event)
                return true
            end
        "#
        .to_string();

        let manifest = RuleManifest::new(RuleMetadata::new("bench-lua", "Bench Lua"));

        rt.block_on(async {
            engine.load_predicate(manifest, script).await.unwrap();
        });

        let event = Event::builder()
            .event_type(1)
            .ts_mono(1000)
            .ts_wall(1000)
            .entity_key(42)
            .field(1, TypedValue::U64(1234))
            .build()
            .unwrap();

        b.iter(|| {
            rt.block_on(async {
                black_box(engine.eval("bench-lua", black_box(&event)).await.unwrap());
            });
        });
    });

    group.finish();
}

criterion_group!(benches, bench_predicate_evaluation);
criterion_main!(benches);
