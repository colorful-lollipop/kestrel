//! Runtime Consistency Checker
//!
//! Verifies that Wasm and Lua runtimes produce identical results for the same rules and events.
//! Critical for cross-platform reproducibility.

use kestrel_event::Event;
use kestrel_schema::SchemaRegistry;
use std::sync::Arc;
use thiserror::Error;

#[cfg(feature = "lua")]
use kestrel_runtime_lua::{LuaConfig, LuaEngine};
#[cfg(feature = "wasm")]
use kestrel_runtime_wasm::{WasmConfig, WasmEngine};

pub struct RuntimeConsistencyChecker {
    #[cfg(feature = "wasm")]
    wasm_engine: Option<Arc<WasmEngine>>,
    #[cfg(feature = "lua")]
    lua_engine: Option<Arc<LuaEngine>>,
    schema: Arc<SchemaRegistry>,
}

#[derive(Debug, Clone)]
pub struct ConsistencyResult {
    pub total_events: usize,
    pub consistent: bool,
    pub mismatches: Vec<ConsistencyMismatch>,
    pub wasm_alerts: usize,
    pub lua_alerts: usize,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ConsistencyMismatch {
    pub event_index: usize,
    pub event_id: u64,
    pub wasm_result: bool,
    pub lua_result: bool,
    pub details: String,
}

impl RuntimeConsistencyChecker {
    pub fn new(
        #[cfg(feature = "wasm")] wasm_config: Option<WasmConfig>,
        #[cfg(feature = "lua")] lua_config: Option<LuaConfig>,
        schema: Arc<SchemaRegistry>,
    ) -> Result<Self, RuntimeComparisonError> {
        #[cfg(feature = "wasm")]
        let wasm_engine = if let Some(config) = wasm_config {
            Some(Arc::new(WasmEngine::new(config, schema.clone())?))
        } else {
            None
        };

        #[cfg(feature = "lua")]
        let lua_engine = if let Some(config) = lua_config {
            Some(Arc::new(LuaEngine::new(config, schema.clone())?))
        } else {
            None
        };

        Ok(Self {
            #[cfg(feature = "wasm")]
            wasm_engine,
            #[cfg(feature = "lua")]
            lua_engine,
            schema,
        })
    }

    #[cfg(feature = "wasm")]
    pub async fn compile_eql_to_wasm(
        &self,
        eql_rule: &str,
    ) -> Result<Vec<u8>, RuntimeComparisonError> {
        use kestrel_eql::EqlCompiler;
        let compiler = EqlCompiler::new(self.schema.clone());
        let wasm_wat = compiler.compile_to_wasm(eql_rule)?;
        let wasm_bytes = wat::parse_str(&wasm_wat)?;
        Ok(wasm_bytes)
    }

    #[cfg(feature = "lua")]
    pub async fn compile_eql_to_lua(
        &self,
        eql_rule: &str,
    ) -> Result<String, RuntimeComparisonError> {
        use kestrel_eql::EqlCompiler;
        let compiler = EqlCompiler::new(self.schema.clone());
        let lua_script = compiler.compile_to_lua(eql_rule)?;
        Ok(lua_script)
    }

    #[cfg(feature = "wasm")]
    pub async fn verify_runtime_consistency_wasm_lua(
        &self,
        eql_rule: &str,
        events: &[Event],
    ) -> Result<ConsistencyResult, RuntimeComparisonError> {
        let start = std::time::Instant::now();

        let wasm_bytes = self.compile_eql_to_wasm(eql_rule).await?;
        let _lua_script = self.compile_eql_to_lua(eql_rule).await?;

        let mut wasm_results = Vec::new();
        let mut lua_results = Vec::new();
        let mut mismatches = Vec::new();

        #[cfg(feature = "wasm")]
        if let Some(ref wasm_engine) = self.wasm_engine {
            for event in events {
                let result = wasm_engine.eval_adhoc_predicate(&wasm_bytes, event).await;
                match result {
                    Ok(matched) => wasm_results.push(matched),
                    Err(e) => {
                        error!("Wasm evaluation error: {}", e);
                        wasm_results.push(false);
                    }
                }
            }
        }

        #[cfg(feature = "lua")]
        if let Some(ref lua_engine) = self.lua_engine {
            for event in events {
                let result = lua_engine.eval("adhoc", event).await;
                match result {
                    Ok(eval_result) => lua_results.push(eval_result.matched),
                    Err(e) => {
                        error!("Lua evaluation error: {}", e);
                        lua_results.push(false);
                    }
                }
            }
        }

        for (i, (wasm, lua)) in wasm_results.iter().zip(lua_results.iter()).enumerate() {
            if wasm != lua {
                mismatches.push(ConsistencyMismatch {
                    event_index: i,
                    event_id: events[i].event_id,
                    wasm_result: *wasm,
                    lua_result: *lua,
                    details: format!("Event {}: Wasm={}, Lua={}", events[i].event_id, wasm, lua),
                });
            }
        }

        let elapsed = start.elapsed();

        Ok(ConsistencyResult {
            total_events: events.len(),
            consistent: mismatches.is_empty(),
            mismatches,
            wasm_alerts: wasm_results.iter().filter(|&&r| r).count(),
            lua_alerts: lua_results.iter().filter(|&&r| r).count(),
            execution_time_ms: elapsed.as_millis() as u64,
        })
    }

    #[cfg(not(feature = "wasm"))]
    pub async fn verify_runtime_consistency_wasm_lua(
        &self,
        _eql_rule: &str,
        _events: &[Event],
    ) -> Result<ConsistencyResult, RuntimeComparisonError> {
        Err(RuntimeComparisonError::WasmNotEnabled(
            "Wasm feature not enabled".to_string(),
        ))
    }

    pub async fn verify_predicate_consistency(
        &self,
        _predicate_id: &str,
        events: &[Event],
    ) -> Result<ConsistencyResult, RuntimeComparisonError> {
        let start = std::time::Instant::now();

        let mut wasm_results = Vec::new();
        let mut lua_results = Vec::new();
        let mut mismatches = Vec::new();

        #[cfg(feature = "wasm")]
        if let Some(ref wasm_engine) = self.wasm_engine {
            for event in events {
                let result = wasm_engine.evaluate(predicate_id, event);
                match result {
                    Ok(matched) => wasm_results.push(matched),
                    Err(e) => {
                        error!("Wasm evaluation error: {}", e);
                        wasm_results.push(false);
                    }
                }
            }
        }

        #[cfg(feature = "lua")]
        if let Some(ref lua_engine) = self.lua_engine {
            for event in events {
                let result = lua_engine.eval(predicate_id, event).await;
                match result {
                    Ok(eval_result) => lua_results.push(eval_result.matched),
                    Err(e) => {
                        error!("Lua evaluation error: {}", e);
                        lua_results.push(false);
                    }
                }
            }
        }

        for (i, (wasm, lua)) in wasm_results.iter().zip(lua_results.iter()).enumerate() {
            if wasm != lua {
                mismatches.push(ConsistencyMismatch {
                    event_index: i,
                    event_id: events[i].event_id,
                    wasm_result: *wasm,
                    lua_result: *lua,
                    details: format!("Event {}: Wasm={}, Lua={}", events[i].event_id, wasm, lua),
                });
            }
        }

        let elapsed = start.elapsed();

        Ok(ConsistencyResult {
            total_events: events.len(),
            consistent: mismatches.is_empty(),
            mismatches,
            wasm_alerts: wasm_results.iter().filter(|&&r| r).count(),
            lua_alerts: lua_results.iter().filter(|&&r| r).count(),
            execution_time_ms: elapsed.as_millis() as u64,
        })
    }

    pub async fn run_consistency_benchmark(
        &self,
        eql_rule: &str,
        events: &[Event],
    ) -> Result<ConsistencyBenchmarkResult, RuntimeComparisonError> {
        let results = Vec::new();

        #[cfg(feature = "wasm")]
        if let Some(ref wasm_engine) = self.wasm_engine {
            let start = std::time::Instant::now();
            let wasm_bytes = self.compile_eql_to_wasm(eql_rule).await?;

            let mut wasm_times = Vec::new();
            for _ in 0..3 {
                let run_start = std::time::Instant::now();
                for event in events {
                    let _ = wasm_engine.eval_adhoc_predicate(&wasm_bytes, event).await?;
                }
                wasm_times.push(run_start.elapsed().as_millis());
            }

            results.push(RuntimeBenchmark {
                runtime: "wasm".to_string(),
                avg_time_ms: wasm_times.iter().sum::<u64>() as f64 / wasm_times.len() as f64,
                min_time_ms: *wasm_times.iter().min().unwrap_or(&0) as f64,
                max_time_ms: *wasm_times.iter().max().unwrap_or(&0) as f64,
            });
        }

        #[cfg(feature = "lua")]
        if let Some(ref lua_engine) = self.lua_engine {
            let start = std::time::Instant::now();
            let lua_script = self.compile_eql_to_lua(eql_rule).await?;

            let mut lua_times = Vec::new();
            for _ in 0..3 {
                let run_start = std::time::Instant::now();
                for event in events {
                    let _ = lua_engine.eval("adhoc", event).await?;
                }
                lua_times.push(run_start.elapsed().as_millis());
            }

            results.push(RuntimeBenchmark {
                runtime: "lua".to_string(),
                avg_time_ms: lua_times.iter().sum::<u64>() as f64 / lua_times.len() as f64,
                min_time_ms: *lua_times.iter().min().unwrap_or(&0) as f64,
                max_time_ms: *lua_times.iter().max().unwrap_or(&0) as f64,
            });
        }

        Ok(ConsistencyBenchmarkResult {
            rule: eql_rule.to_string(),
            event_count: events.len(),
            benchmarks: results,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeBenchmark {
    pub runtime: String,
    pub avg_time_ms: f64,
    pub min_time_ms: f64,
    pub max_time_ms: f64,
}

#[derive(Debug, Clone)]
pub struct ConsistencyBenchmarkResult {
    pub rule: String,
    pub event_count: usize,
    pub benchmarks: Vec<RuntimeBenchmark>,
}

#[derive(Debug, Error)]
pub enum RuntimeComparisonError {
    #[cfg(feature = "wasm")]
    #[error("Wasm runtime error: {0}")]
    WasmError(#[from] kestrel_runtime_wasm::WasmRuntimeError),

    #[cfg(feature = "lua")]
    #[error("Lua runtime error: {0}")]
    LuaError(#[from] kestrel_runtime_lua::LuaRuntimeError),

    #[error("Wasm feature not enabled: {0}")]
    WasmNotEnabled(String),

    #[error("Lua feature not enabled: {0}")]
    LuaNotEnabled(String),

    #[error("EQL compilation error: {0}")]
    EqlCompilationError(String),

    #[error("Event evaluation error: {0}")]
    EvaluationError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_event::Event;
    use kestrel_schema::TypedValue;

    fn create_test_events(count: usize) -> Vec<Event> {
        let mut events = Vec::new();
        for i in 0..count {
            let event = Event::builder()
                .event_id((i + 1) as u64)
                .event_type(1)
                .ts_mono((i as u64 + 1) * 1_000_000_000)
                .ts_wall((i as u64 + 1) * 1_000_000_000)
                .entity_key(i as u128 % 4)
                .field(1, TypedValue::I64(i as i64))
                .field(2, TypedValue::String(format!("/bin/test_{}", i)))
                .build()
                .unwrap();
            events.push(event);
        }
        events
    }

    #[tokio::test]
    async fn test_consistency_result() {
        let result = ConsistencyResult {
            total_events: 10,
            consistent: true,
            mismatches: Vec::new(),
            wasm_alerts: 5,
            lua_alerts: 5,
            execution_time_ms: 100,
        };

        assert!(result.consistent);
        assert_eq!(result.total_events, 10);
    }

    #[tokio::test]
    async fn test_consistency_mismatch() {
        let mismatch = ConsistencyMismatch {
            event_index: 0,
            event_id: 1,
            wasm_result: true,
            lua_result: false,
            details: "Event 1: Wasm=true, Lua=false".to_string(),
        };

        assert_eq!(mismatch.event_index, 0);
        assert!(!mismatch.wasm_result == mismatch.lua_result);
    }
}
