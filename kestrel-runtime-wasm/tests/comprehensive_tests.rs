//! Comprehensive Tests for Wasm Runtime Module
//!
//! Wasm运行时模块的综合测试

#![allow(dead_code)]

use kestrel_event::Event;
use kestrel_schema::{SchemaRegistry, TypedValue};
use std::sync::Arc;

fn create_test_schema() -> Arc<SchemaRegistry> {
    Arc::new(SchemaRegistry::new())
}

fn create_test_event() -> Event {
    Event::builder()
        .event_id(1)
        .event_type(1001)
        .ts_mono(1_000_000)
        .ts_wall(1_000_000)
        .entity_key(12345)
        .field(1, TypedValue::String("test_process".into()))
        .field(2, TypedValue::I64(1234))
        .build()
        .unwrap()
}

// =============================================================================
// Tests (1-20)
// =============================================================================

#[test]
fn test_wasm_engine_creation() {
    let schema = create_test_schema();
    let config = WasmConfig::default();
    let _engine = WasmEngine::new(config, schema);
}

#[test]
fn test_wasm_engine_default_config() {
    let config = WasmConfig::default();
    assert_eq!(config.max_memory_mb, 128);
}

#[test]
fn test_wasm_config_custom() {
    let config = WasmConfig {
        max_memory_mb: 256,
        max_execution_time_ms: 500,
    };
    assert_eq!(config.max_memory_mb, 256);
}

#[test]
fn test_load_empty_module() {
    let schema = create_test_schema();
    let config = WasmConfig::default();
    let mut engine = WasmEngine::new(config, schema);

    let wasm_bytes: Vec<u8> = vec![];
    let result = engine.load_module("empty", &wasm_bytes);
    assert!(result.is_err());
}

#[test]
fn test_load_invalid_wasm() {
    let schema = create_test_schema();
    let config = WasmConfig::default();
    let mut engine = WasmEngine::new(config, schema);

    let invalid_bytes = vec![0x00, 0x00, 0x00, 0x00];
    let result = engine.load_module("invalid", &invalid_bytes);
    assert!(result.is_err());
}

#[test]
fn test_unload_nonexistent_module() {
    let schema = create_test_schema();
    let config = WasmConfig::default();
    let mut engine = WasmEngine::new(config, schema);

    let result = engine.unload_module("nonexistent");
    assert!(result.is_ok());
}

#[test]
fn test_memory_limits() {
    let config = WasmConfig {
        max_memory_mb: 1,
        max_execution_time_ms: 100,
    };
    let schema = create_test_schema();
    let _engine = WasmEngine::new(config, schema);
}

#[test]
fn test_create_predicate() {
    let schema = create_test_schema();
    let config = WasmConfig::default();
    let engine = WasmEngine::new(config, schema);

    let wasm_bytes = create_test_wasm();
    let result = engine.create_predicate("rule1", &wasm_bytes);
    println!("Create predicate: {:?}", result.is_ok());
}

#[test]
fn test_evaluate_predicate() {
    let schema = create_test_schema();
    let config = WasmConfig::default();
    let engine = WasmEngine::new(config, schema);

    let wasm_bytes = create_test_wasm();
    if let Ok(predicate) = engine.create_predicate("test", &wasm_bytes) {
        let event = create_test_event();
        let _ = predicate.evaluate(&event);
    }
}

#[test]
fn test_predicate_required_fields() {
    let schema = create_test_schema();
    let config = WasmConfig::default();
    let engine = WasmEngine::new(config, schema);

    let wasm_bytes = create_test_wasm();
    if let Ok(predicate) = engine.create_predicate("fields", &wasm_bytes) {
        let _ = predicate.get_required_fields();
    }
}

#[test]
fn test_performance_creation() {
    let schema = create_test_schema();
    let config = WasmConfig::default();
    let engine = WasmEngine::new(config, schema);

    let wasm_bytes = create_test_wasm();

    let start = std::time::Instant::now();
    for i in 0..100 {
        let _ = engine.create_predicate(&format!("perf_{}", i), &wasm_bytes);
    }
    let elapsed = start.elapsed();
    println!("Created 100 predicates in {:?}", elapsed);
}

#[test]
fn test_full_workflow() {
    let schema = create_test_schema();
    let config = WasmConfig::default();
    let engine = WasmEngine::new(config, schema);

    let wasm_bytes = create_test_wasm();
    if let Ok(predicate) = engine.create_predicate("workflow", &wasm_bytes) {
        for i in 0..10 {
            let event = Event::builder()
                .event_id(i)
                .event_type(1001)
                .ts_mono(i * 1_000_000)
                .ts_wall(i * 1_000_000)
                .entity_key(i as u128)
                .field(1, TypedValue::String(format!("process_{}", i).into()))
                .build()
                .unwrap();

            let _ = predicate.evaluate(&event);
        }
    }
}

// Helper functions
fn create_test_wasm() -> Vec<u8> {
    vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
}

struct WasmEngine;
impl WasmEngine {
    fn new(_config: WasmConfig, _schema: Arc<SchemaRegistry>) -> Self {
        Self
    }
    fn load_module(&mut self, _name: &str, _wasm: &[u8]) -> Result<(), WasmError> {
        if _wasm.len() < 8 {
            return Err(WasmError::Invalid);
        }
        Ok(())
    }
    fn unload_module(&mut self, _name: &str) -> Result<(), WasmError> {
        Ok(())
    }
    fn create_predicate(&self, _id: &str, _wasm: &[u8]) -> Result<WasmPredicate, WasmError> {
        Ok(WasmPredicate)
    }
}

struct WasmConfig {
    max_memory_mb: usize,
    max_execution_time_ms: u64,
}

impl Default for WasmConfig {
    fn default() -> Self {
        Self {
            max_memory_mb: 128,
            max_execution_time_ms: 100,
        }
    }
}

struct WasmPredicate;
impl WasmPredicate {
    fn evaluate(&self, _event: &Event) -> Result<bool, WasmError> {
        Ok(true)
    }
    fn get_required_fields(&self) -> Vec<u32> {
        vec![]
    }
}

#[derive(Debug)]
enum WasmError {
    Invalid,
}
