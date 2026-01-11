//! Kestrel Wasm Runtime
//!
//! This module provides Wasm runtime support for predicate execution using Wasmtime.
//! Implements Host API v1 for event field access, regex/glob matching, and alert emission.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info};
use wasmtime::{
    Engine, Module, Store, Instance, Linker, Caller, Extern, TypedFunc,
    Config, InstancePre, InstanceAllocationStrategy,
};
use tokio::sync::{RwLock, Semaphore};

use kestrel_schema::{FieldId, TypedValue, SchemaRegistry};
use kestrel_event::Event;

/// Host API v1 for Wasm predicates
///
/// Provides functions for:
/// - Event field reading
/// - Regex/glob matching
/// - Alert emission
/// - Action blocking (inline mode)

pub mod host_api {
    use super::*;

    /// Event handle passed to Wasm (index into event store)
    pub type EventHandle = u32;

    /// Regex ID (pre-compiled regex handle)
    pub type RegexId = u32;

    /// Glob ID (pre-compiled glob handle)
    pub type GlobId = u32;

    /// Alert record structure
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AlertRecord {
        pub rule_id: String,
        pub severity: String,
        pub title: String,
        pub description: Option<String>,
        pub event_handles: Vec<EventHandle>,
        pub fields: HashMap<String, TypedValue>,
    }
}

use host_api::*;

/// Wasm runtime configuration
#[derive(Debug, Clone)]
pub struct WasmConfig {
    /// Enable AOT caching
    pub enable_aot_cache: bool,

    /// Directory for AOT cache
    pub aot_cache_dir: Option<PathBuf>,

    /// Maximum memory per instance (in MB)
    pub max_memory_mb: usize,

    /// Maximum execution time (in milliseconds)
    pub max_execution_time_ms: u64,

    /// Instance pool size
    pub pool_size: usize,

    /// Enable fuel metering (for execution time limiting)
    pub enable_fuel: bool,

    /// Fuel for single predicate evaluation (approximate instructions)
    pub fuel_per_eval: u64,
}

impl Default for WasmConfig {
    fn default() -> Self {
        Self {
            enable_aot_cache: true,
            aot_cache_dir: Some(PathBuf::from("./cache/wasm")),
            max_memory_mb: 16,
            max_execution_time_ms: 100,
            pool_size: 4,
            enable_fuel: true,
            fuel_per_eval: 1_000_000,
        }
    }
}

/// Predicate ABI (same for both Wasm and Lua)
///
/// All predicates must implement:
/// - pred_init(ctx) -> i32 (0 = success, < 0 = error)
/// - pred_eval(event_handle, ctx) -> i32 (1 = match, 0 = no match, < 0 = error)
/// - pred_capture(event_handle, ctx) -> captures_ptr (optional)

pub struct WasmEngine {
    engine: Engine,
    linker: Linker<WasmContext>,
    config: WasmConfig,
    schema: Arc<SchemaRegistry>,
    modules: Arc<RwLock<HashMap<String, CompiledModule>>>,
    instance_pool: Arc<RwLock<HashMap<String, InstancePool>>>,
    regex_cache: Arc<RwLock<HashMap<RegexId, regex::Regex>>>,
    glob_cache: Arc<RwLock<HashMap<GlobId, glob::Pattern>>>,
    next_regex_id: Arc<std::sync::atomic::AtomicU32>,
    next_glob_id: Arc<std::sync::atomic::AtomicU32>,
}

/// Compiled Wasm module with metadata
#[derive(Clone)]
struct CompiledModule {
    module: Module,
    instance_pre: InstancePre<WasmContext>,
    metadata: RuleMetadata,
}

/// Rule package metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub rule_id: String,
    pub rule_name: String,
    pub rule_version: String,
    pub author: Option<String>,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub severity: String,
    pub schema_version: String,
}

/// Rule package manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleManifest {
    pub format_version: String,
    pub metadata: RuleMetadata,
    pub capabilities: RuleCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCapabilities {
    pub supports_inline: bool,
    pub requires_alert: bool,
    pub requires_block: bool,
    pub max_span_ms: Option<u64>,
}

/// Instance pool for a specific module
struct InstancePool {
    instances: Vec<PooledInstance>,
    semaphore: Arc<Semaphore>,
}

/// Pooled Wasm instance
struct PooledInstance {
    store: Store<WasmContext>,
    instance: Instance,
    in_use: bool,
}

/// Wasm context (per-store)
#[derive(Clone)]
struct WasmContext {
    event: Option<Event>,
    schema: Arc<SchemaRegistry>,
    alerts: Arc<std::sync::Mutex<Vec<AlertRecord>>>,
    regex_cache: Arc<RwLock<HashMap<RegexId, regex::Regex>>>,
    glob_cache: Arc<RwLock<HashMap<GlobId, glob::Pattern>>>,
}

/// Wasm predicate
pub struct WasmPredicate {
    rule_id: String,
    module_name: String,
    engine: Arc<WasmEngine>,
}

/// Predicate evaluation result
#[derive(Debug, Clone)]
pub struct EvalResult {
    pub matched: bool,
    pub error: Option<String>,
    pub captured_fields: HashMap<String, TypedValue>,
}

/// Wasm errors
#[derive(Debug, Error)]
pub enum WasmRuntimeError {
    #[error("Failed to compile Wasm module: {0}")]
    CompilationError(String),

    #[error("Failed to instantiate module: {0}")]
    InstantiationError(String),

    #[error("Function not found: {0}")]
    FunctionNotFound(String),

    #[error("Execution timeout")]
    Timeout,

    #[error("Execution error: {0}")]
    ExecutionError(String),

    #[error("Out of fuel")]
    OutOfFuel,

    #[error("Memory limit exceeded")]
    MemoryLimitExceeded,

    #[error("Invalid event handle: {0}")]
    InvalidEventHandle(u32),

    #[error("Invalid field ID: {0}")]
    InvalidFieldId(FieldId),

    #[error("IO error: {0}")]
    IoError(String),
}

impl WasmEngine {
    /// Create a new Wasm engine
    pub fn new(config: WasmConfig, schema: Arc<SchemaRegistry>) -> Result<Self, WasmRuntimeError> {
        // Configure Wasmtime engine
        let mut engine_config = Config::new();
        engine_config.wasm_component_model(false);
        engine_config.async_support(false);

        // Configure pooling allocation for better performance
        engine_config.allocation_strategy(InstanceAllocationStrategy::Pooling(
            wasmtime::PoolingAllocationConfig::default()
        ));

        // Configure fuel metering
        if config.enable_fuel {
            engine_config.consume_fuel(true);
        }

        let engine = Engine::new(&engine_config)
            .map_err(|e| WasmRuntimeError::CompilationError(e.to_string()))?;

        let mut linker = Linker::new(&engine);

        // Register Host API v1 functions
        Self::register_host_api(&mut linker)?;

        // Create AOT cache directory if enabled
        if config.enable_aot_cache {
            if let Some(ref cache_dir) = config.aot_cache_dir {
                std::fs::create_dir_all(cache_dir)
                    .map_err(|e| WasmRuntimeError::IoError(e.to_string()))?;
            }
        }

        Ok(Self {
            engine,
            linker,
            config,
            schema,
            modules: Arc::new(RwLock::new(HashMap::new())),
            instance_pool: Arc::new(RwLock::new(HashMap::new())),
            regex_cache: Arc::new(RwLock::new(HashMap::new())),
            glob_cache: Arc::new(RwLock::new(HashMap::new())),
            next_regex_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            next_glob_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
        })
    }

    /// Register Host API v1 functions
    fn register_host_api(linker: &mut Linker<WasmContext>) -> Result<(), WasmRuntimeError> {
        // Event field reading: event_get_i64
        linker.func_wrap("kestrel", "event_get_i64", |mut caller: Caller<'_, WasmContext>, _event_handle: u32, field_id: u32| -> i64 {
            let ctx = caller.data();
            let event = match ctx.event.as_ref() {
                Some(e) => e,
                None => return 0,
            };

            let value = event.get_field(field_id);
            match value {
                Some(TypedValue::I64(v)) => *v,
                Some(TypedValue::U64(v)) => i64::try_from(*v).unwrap_or(i64::MAX),
                _ => 0,
            }
        }).map_err(|e| WasmRuntimeError::ExecutionError(e.to_string()))?;

        // Event field reading: event_get_u64
        linker.func_wrap("kestrel", "event_get_u64", |mut caller: Caller<'_, WasmContext>, _event_handle: u32, field_id: u32| -> u64 {
            let ctx = caller.data();
            let event = match ctx.event.as_ref() {
                Some(e) => e,
                None => return 0,
            };

            let value = event.get_field(field_id);
            match value {
                Some(TypedValue::U64(v)) => *v,
                Some(TypedValue::I64(v)) => u64::try_from(*v).unwrap_or(u64::MAX),
                _ => 0,
            }
        }).map_err(|e| WasmRuntimeError::ExecutionError(e.to_string()))?;

        // Event field reading: event_get_str
        linker.func_wrap("kestrel", "event_get_str", |mut caller: Caller<'_, WasmContext>, _event_handle: u32, field_id: u32, ptr: u32, len: u32| -> u32 {
            // Get event data first
            let (event, has_event) = {
                let ctx = caller.data();
                (ctx.event.clone(), ctx.event.is_some())
            };

            if !has_event {
                return 0;
            }

            let event = match event.as_ref() {
                Some(e) => e,
                None => return 0,
            };

            // Get memory
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(m)) => m,
                _ => return 0,
            };

            let value = event.get_field(field_id);
            if let Some(TypedValue::String(s)) = value {
                let bytes_to_write = std::cmp::min(len as usize, s.len());
                if let Err(_) = mem.write(&mut caller, ptr as usize, s.as_bytes()[..bytes_to_write].as_ref()) {
                    return 0;
                }
                return bytes_to_write as u32;
            }
            0
        }).map_err(|e| WasmRuntimeError::ExecutionError(e.to_string()))?;

        // Event field reading: event_get_bool
        linker.func_wrap("kestrel", "event_get_bool", |mut caller: Caller<'_, WasmContext>, _event_handle: u32, field_id: u32| -> i32 {
            let ctx = caller.data();
            let event = match ctx.event.as_ref() {
                Some(e) => e,
                None => return 0,
            };

            let value = event.get_field(field_id);
            match value {
                Some(TypedValue::Bool(v)) => if *v { 1 } else { 0 },
                Some(TypedValue::I64(v)) => if *v != 0 { 1 } else { 0 },
                Some(TypedValue::U64(v)) => if *v != 0 { 1 } else { 0 },
                _ => 0,
            }
        }).map_err(|e| WasmRuntimeError::ExecutionError(e.to_string()))?;

        // Regex matching
        linker.func_wrap("kestrel", "re_match", |mut caller: Caller<'_, WasmContext>, re_id: u32, ptr: u32, len: u32| -> i32 {
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(m)) => m,
                _ => return 0,
            };

            let ctx = caller.data();
            let cache = ctx.regex_cache.clone();

            let mut data = vec![0u8; len as usize];
            if let Err(_) = mem.read(&mut caller, ptr as usize, &mut data) {
                return 0;
            }

            let s = match std::str::from_utf8(&data) {
                Ok(s) => s,
                Err(_) => return 0,
            };

            let cache_guard = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(cache.read())
            });

            if let Some(re) = cache_guard.get(&re_id) {
                if re.is_match(s) {
                    return 1;
                }
            }
            0
        }).map_err(|e| WasmRuntimeError::ExecutionError(e.to_string()))?;

        // Glob matching
        linker.func_wrap("kestrel", "glob_match", |mut caller: Caller<'_, WasmContext>, glob_id: u32, ptr: u32, len: u32| -> i32 {
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(m)) => m,
                _ => return 0,
            };

            let ctx = caller.data();
            let cache = ctx.glob_cache.clone();

            let mut data = vec![0u8; len as usize];
            if let Err(_) = mem.read(&mut caller, ptr as usize, &mut data) {
                return 0;
            }

            let s = match std::str::from_utf8(&data) {
                Ok(s) => s,
                Err(_) => return 0,
            };

            let cache_guard = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(cache.read())
            });

            if let Some(pattern) = cache_guard.get(&glob_id) {
                if pattern.matches(s) {
                    return 1;
                }
            }
            0
        }).map_err(|e| WasmRuntimeError::ExecutionError(e.to_string()))?;

        // Alert emission
        linker.func_wrap("kestrel", "alert_emit", |mut _caller: Caller<'_, WasmContext>, _event_handle: u32| -> i32 {
            // For now, just return success
            // In a full implementation, this would capture event details
            0
        }).map_err(|e| WasmRuntimeError::ExecutionError(e.to_string()))?;

        Ok(())
    }

    /// Load a Wasm module from a rule package
    pub async fn load_module(&self, manifest: RuleManifest, wasm_bytes: Vec<u8>) -> Result<String, WasmRuntimeError> {
        let rule_id = manifest.metadata.rule_id.clone();

        info!(rule_id = %rule_id, "Loading Wasm module");

        // Compile the module
        let module = Module::from_binary(&self.engine, &wasm_bytes)
            .map_err(|e| WasmRuntimeError::CompilationError(e.to_string()))?;

        // Pre-instantiate for pooling
        let instance_pre = self.instance_pre(&module)
            .map_err(|e| WasmRuntimeError::InstantiationError(e.to_string()))?;

        // AOT cache if enabled
        if self.config.enable_aot_cache {
            if let Some(ref cache_dir) = self.config.aot_cache_dir {
                let _cache_path = cache_dir.join(format!("{}.cwasm", rule_id));
                // Serialize compiled module for future use
                // (Wasmtime doesn't directly support this yet, but we could cache the original bytes)
            }
        }

        let compiled = CompiledModule {
            module,
            instance_pre,
            metadata: manifest.metadata,
        };

        // Initialize instance pool
        let pool = InstancePool {
            instances: Vec::with_capacity(self.config.pool_size),
            semaphore: Arc::new(Semaphore::new(self.config.pool_size)),
        };

        let mut modules = self.modules.write().await;
        let mut pools = self.instance_pool.write().await;

        modules.insert(rule_id.clone(), compiled);
        pools.insert(rule_id.clone(), pool);

        info!(rule_id = %rule_id, "Wasm module loaded successfully");
        Ok(rule_id)
    }

    /// Create a predicate for a rule
    pub fn create_predicate(&self, rule_id: &str) -> Result<WasmPredicate, WasmRuntimeError> {
        Ok(WasmPredicate {
            rule_id: rule_id.to_string(),
            module_name: rule_id.to_string(),
            engine: Arc::new(self.clone()),
        })
    }

    /// Pre-instantiate a module for pooling
    fn instance_pre(&self, module: &Module) -> Result<InstancePre<WasmContext>, WasmRuntimeError> {
        self.linker.instantiate_pre(module)
            .map_err(|e| WasmRuntimeError::InstantiationError(e.to_string()))
    }

    /// Register a compiled regex pattern
    pub async fn register_regex(&self, pattern: &str) -> Result<RegexId, WasmRuntimeError> {
        let re = regex::Regex::new(pattern)
            .map_err(|e| WasmRuntimeError::CompilationError(e.to_string()))?;

        let id = self.next_regex_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut cache = self.regex_cache.write().await;
        cache.insert(id, re);
        Ok(id)
    }

    /// Register a compiled glob pattern
    pub async fn register_glob(&self, pattern: &str) -> Result<GlobId, WasmRuntimeError> {
        let glob = glob::Pattern::new(pattern)
            .map_err(|e| WasmRuntimeError::CompilationError(e.to_string()))?;

        let id = self.next_glob_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut cache = self.glob_cache.write().await;
        cache.insert(id, glob);
        Ok(id)
    }
}

impl Clone for WasmEngine {
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
            linker: self.linker.clone(),
            config: self.config.clone(),
            schema: self.schema.clone(),
            modules: self.modules.clone(),
            instance_pool: self.instance_pool.clone(),
            regex_cache: self.regex_cache.clone(),
            glob_cache: self.glob_cache.clone(),
            next_regex_id: self.next_regex_id.clone(),
            next_glob_id: self.next_glob_id.clone(),
        }
    }
}

/// Implement PredicateEvaluator trait for NFA engine integration
///
/// This allows the Wasm runtime to be used as a predicate evaluator
/// for the NFA sequence engine.
impl kestrel_nfa::PredicateEvaluator for WasmEngine {
    /// Evaluate a predicate against an event
    ///
    /// The predicate_id should be in the format "rule_id:predicate_id" where:
    /// - rule_id is the Wasm module identifier
    /// - predicate_id is the index of the predicate within the module
    fn evaluate(&self, predicate_id: &str, event: &kestrel_event::Event) -> kestrel_nfa::NfaResult<bool> {
        // Parse predicate_id as "rule_id:predicate_index"
        let parts: Vec<&str> = predicate_id.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(kestrel_nfa::NfaError::PredicateError(format!(
                "Invalid predicate_id format: {}, expected 'rule_id:predicate_index'",
                predicate_id
            )));
        }

        let rule_id = parts[0];
        let predicate_index: u32 = parts[1].parse().map_err(|_| {
            kestrel_nfa::NfaError::PredicateError(format!(
                "Invalid predicate index: {}",
                parts[1]
            ))
        })?;

        // Run async evaluation in blocking context
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let modules = self.modules.read().await;
                let compiled = modules.get(rule_id).ok_or_else(|| {
                    kestrel_nfa::NfaError::PredicateError(format!(
                        "Module not found: {}",
                        rule_id
                    ))
                })?;

                // Create a new store for this evaluation
                let mut store = Store::new(
                    &self.engine,
                    WasmContext {
                        event: Some(event.clone()),
                        schema: self.schema.clone(),
                        alerts: Arc::new(std::sync::Mutex::new(Vec::new())),
                        regex_cache: self.regex_cache.clone(),
                        glob_cache: self.glob_cache.clone(),
                    },
                );

                // Instantiate the module
                let instance = compiled.instance_pre.instantiate(&mut store).map_err(|e| {
                    kestrel_nfa::NfaError::PredicateError(format!(
                        "Instantiation failed: {}",
                        e
                    ))
                })?;

                // Get the pred_eval dispatcher function
                // Signature: (predicate_id: i32, event_handle: i32) -> i32
                let pred_eval = instance
                    .get_typed_func::<(u32, u32), i32>(&mut store, "pred_eval")
                    .map_err(|_| kestrel_nfa::NfaError::PredicateError(
                        "pred_eval function not found".to_string()
                    ))?;

                // Call the predicate with the predicate index
                let result = pred_eval
                    .call(&mut store, (predicate_index, 0))
                    .map_err(|e| {
                        kestrel_nfa::NfaError::PredicateError(format!(
                            "Execution failed: {}",
                            e
                        ))
                    })?;

                Ok(result == 1)
            })
        });

        result
    }

    /// Get the field IDs required by a predicate
    ///
    /// For now, returns empty vec since we don't track required fields
    fn get_required_fields(&self, _predicate_id: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
        Ok(Vec::new())
    }

    /// Check if a predicate exists
    fn has_predicate(&self, predicate_id: &str) -> bool {
        let parts: Vec<&str> = predicate_id.splitn(2, ':').collect();
        if parts.len() != 2 {
            return false;
        }

        let rule_id = parts[0];
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { self.modules.read().await.contains_key(rule_id) })
        })
    }
}

impl WasmPredicate {
    /// Initialize the predicate
    pub async fn init(&self) -> Result<(), WasmRuntimeError> {
        debug!(rule_id = %self.rule_id, "Initializing Wasm predicate");
        // Predicate initialization would happen here
        Ok(())
    }

    /// Evaluate an event
    pub async fn eval(&self, event: &Event) -> Result<EvalResult, WasmRuntimeError> {
        let modules = self.engine.modules.read().await;
        let compiled = modules.get(&self.rule_id)
            .ok_or_else(|| WasmRuntimeError::CompilationError(format!("Module not found: {}", self.rule_id)))?;

        // Create a new store for this evaluation
        let mut store = Store::new(
            &self.engine.engine,
            WasmContext {
                event: Some(event.clone()),
                schema: self.engine.schema.clone(),
                alerts: Arc::new(std::sync::Mutex::new(Vec::new())),
                regex_cache: self.engine.regex_cache.clone(),
                glob_cache: self.engine.glob_cache.clone(),
            },
        );

        // Instantiate the module
        let instance = compiled.instance_pre.instantiate(&mut store)
            .map_err(|e| WasmRuntimeError::InstantiationError(e.to_string()))?;

        // Get the pred_eval function
        let pred_eval = instance.get_typed_func::<u32, i32>(&mut store, "pred_eval")
            .map_err(|_| WasmRuntimeError::FunctionNotFound("pred_eval".to_string()))?;

        // Call the predicate
        let result = pred_eval.call(&mut store, 0)
            .map_err(|e| WasmRuntimeError::ExecutionError(e.to_string()))?;

        Ok(EvalResult {
            matched: result == 1,
            error: None,
            captured_fields: HashMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wasm_engine_create() {
        let config = WasmConfig::default();
        let schema = Arc::new(SchemaRegistry::new());
        let engine = WasmEngine::new(config, schema);
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_regex_registration() {
        let config = WasmConfig::default();
        let schema = Arc::new(SchemaRegistry::new());
        let engine = WasmEngine::new(config, schema).unwrap();

        let result = engine.register_regex(r"\d+").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_glob_registration() {
        let config = WasmConfig::default();
        let schema = Arc::new(SchemaRegistry::new());
        let engine = WasmEngine::new(config, schema).unwrap();

        let result = engine.register_glob("*.exe").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
    }
}
