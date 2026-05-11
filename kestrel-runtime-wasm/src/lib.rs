//! Kestrel Wasm Runtime
//!
//! This module provides Wasm runtime support for predicate execution using Wasmtime.
//! Implements Host API v1 for event field access, regex/glob matching, and alert emission.

use ahash::AHashMap;
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use parking_lot::{Mutex, RwLock};
use tokio::sync::Semaphore;
use tracing::{error, info};
use wasmtime::{
    Caller, Config, Engine, Extern, Instance, InstanceAllocationStrategy, InstancePre, Linker,
    Module, Store,
};

use kestrel_event::Event;
use kestrel_event::host_api::{HostApiContext, HostApiV1};
use kestrel_schema::{
    AlertRecord, EvalResult, FieldId, GlobId, RegexId, RuleCapabilities, RuleManifest,
    RuleMetadata, RuntimeCapabilities, RuntimeConfig, RuntimeType, SchemaRegistry,
};

// Re-export types from kestrel-schema for backward compatibility
pub use kestrel_schema::{
    AlertRecord as HostAlertRecord, EventHandle as HostEventHandle, FieldId as HostFieldId,
    GlobId as HostGlobId, RegexId as HostRegexId,
};

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

impl RuntimeConfig for WasmConfig {
    fn max_memory_mb(&self) -> usize {
        self.max_memory_mb
    }

    fn max_execution_time_ms(&self) -> u64 {
        self.max_execution_time_ms
    }

    fn instruction_limit(&self) -> Option<u64> {
        Some(self.fuel_per_eval)
    }
}

/// Predicate ABI (same for both Wasm and Lua)
///
/// All predicates must implement:
/// - pred_init(ctx) -> i32 (0 = success, < 0 = error)
/// - pred_eval(event_handle, ctx) -> i32 (1 = match, 0 = no match, < 0 = error)
/// - pred_capture(event_handle, ctx) -> captures_ptr (optional)
pub struct WasmEngine {
    pub engine: Engine,
    pub linker: Linker<WasmContext>,
    pub config: WasmConfig,
    pub schema: Arc<SchemaRegistry>,
    modules: Arc<RwLock<AHashMap<String, CompiledModule>>>,
    instance_pool: Arc<RwLock<AHashMap<String, Arc<InstancePool>>>>,
    pub regex_cache: Arc<RwLock<AHashMap<RegexId, regex::Regex>>>,
    pub glob_cache: Arc<RwLock<AHashMap<GlobId, glob::Pattern>>>,
    pub next_regex_id: Arc<std::sync::atomic::AtomicU32>,
    pub next_glob_id: Arc<std::sync::atomic::AtomicU32>,
    pub pool_metrics: Arc<PoolMetrics>,
}

/// Compiled Wasm module with metadata
#[derive(Clone)]
struct CompiledModule {
    module: Module,
    instance_pre: InstancePre<WasmContext>,
    metadata: RuleMetadata,
    /// Required fields per predicate (predicate_index -> field_ids)
    predicate_fields: AHashMap<u32, Vec<u32>>,
}

/// Pool metrics for tracking instance pool utilization
#[derive(Debug, Default)]
pub struct PoolMetrics {
    /// Total pool size (total instances)
    pub pool_size: std::sync::atomic::AtomicUsize,
    /// Currently active instances (in use)
    pub active_instances: std::sync::atomic::AtomicUsize,
    /// Total pool acquires
    pub total_acquires: std::sync::atomic::AtomicU64,
    /// Total pool releases
    pub total_releases: std::sync::atomic::AtomicU64,
    /// Total pool misses (had to create new instance)
    pub pool_misses: std::sync::atomic::AtomicU64,
    /// Total wait time for pool acquisition (nanoseconds)
    pub total_wait_ns: std::sync::atomic::AtomicU64,
    /// Peak wait time (nanoseconds)
    pub peak_wait_ns: std::sync::atomic::AtomicU64,
}

impl PoolMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_acquire(&self, wait_ns: u64) {
        self.total_acquires
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.active_instances
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.total_wait_ns
            .fetch_add(wait_ns, std::sync::atomic::Ordering::Relaxed);

        // Update peak wait time
        loop {
            let peak = self.peak_wait_ns.load(std::sync::atomic::Ordering::Relaxed);
            if wait_ns <= peak {
                break;
            }
            if self
                .peak_wait_ns
                .compare_exchange_weak(
                    peak,
                    wait_ns,
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                )
                .is_ok()
            {
                break;
            }
        }
    }

    pub fn record_release(&self) {
        self.total_releases
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.active_instances
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_miss(&self) {
        self.pool_misses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn set_pool_size(&self, size: usize) {
        self.pool_size
            .store(size, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get pool utilization percentage (0-100)
    pub fn utilization_pct(&self) -> f64 {
        let pool_size = self.pool_size.load(std::sync::atomic::Ordering::Relaxed);
        let active = self
            .active_instances
            .load(std::sync::atomic::Ordering::Relaxed);

        if pool_size > 0 {
            (active as f64 / pool_size as f64) * 100.0
        } else {
            0.0
        }
    }

    /// Get average wait time in nanoseconds
    pub fn avg_wait_ns(&self) -> u64 {
        let acquires = self
            .total_acquires
            .load(std::sync::atomic::Ordering::Relaxed);
        let total_wait = self
            .total_wait_ns
            .load(std::sync::atomic::Ordering::Relaxed);

        if acquires > 0 {
            total_wait / acquires
        } else {
            0
        }
    }

    /// Get cache hit rate percentage (0-100)
    pub fn cache_hit_rate_pct(&self) -> f64 {
        let acquires = self
            .total_acquires
            .load(std::sync::atomic::Ordering::Relaxed);
        let misses = self.pool_misses.load(std::sync::atomic::Ordering::Relaxed);

        if acquires > 0 {
            let hits = acquires.saturating_sub(misses);
            (hits as f64 / acquires as f64) * 100.0
        } else {
            0.0
        }
    }
}

/// Instance pool for a specific module
struct InstancePool {
    instances: Mutex<Vec<PooledInstance>>,
    semaphore: Arc<Semaphore>,
}

/// Pooled Wasm instance
struct PooledInstance {
    store: Store<WasmContext>,
    instance: Instance,
}

/// Wasm context (per-store)
#[derive(Clone)]
pub struct WasmContext {
    pub event: Option<Event>,
    pub schema: Arc<SchemaRegistry>,
    pub alerts: Arc<Mutex<Vec<AlertRecord>>>,
    pub regex_cache: Arc<RwLock<AHashMap<RegexId, regex::Regex>>>,
    pub glob_cache: Arc<RwLock<AHashMap<GlobId, glob::Pattern>>>,
    pub rule_metadata: RuleMetadata,
}

/// Wasm predicate
pub struct WasmPredicate {
    rule_id: String,
    engine: Arc<WasmEngine>,
}

impl WasmPredicate {
    /// Initialize the predicate
    pub async fn init(&self) -> Result<(), WasmRuntimeError> {
        tracing::debug!(rule_id = %self.rule_id, "Initializing Wasm predicate");
        // Predicate initialization would happen here
        Ok(())
    }

    /// Evaluate an event
    pub async fn eval(&self, event: &Event) -> Result<EvalResult, WasmRuntimeError> {
        let modules = self.engine.modules.read();
        let compiled = modules.get(&self.rule_id).ok_or_else(|| {
            WasmRuntimeError::CompilationError(format!("Module not found: {}", self.rule_id))
        })?;

        // Create a new store for this evaluation
        let mut store = Store::new(
            &self.engine.engine,
            WasmContext {
                event: Some(event.clone()),
                schema: self.engine.schema.clone(),
                alerts: Arc::new(Mutex::new(Vec::new())),
                regex_cache: self.engine.regex_cache.clone(),
                glob_cache: self.engine.glob_cache.clone(),
                rule_metadata: compiled.metadata.clone(),
            },
        );

        // Instantiate the module
        let instance = compiled
            .instance_pre
            .instantiate(&mut store)
            .map_err(|e| WasmRuntimeError::InstantiationError(e.to_string()))?;

        // Get the pred_eval function
        let pred_eval = instance
            .get_typed_func::<u32, i32>(&mut store, "pred_eval")
            .map_err(|_| WasmRuntimeError::FunctionNotFound("pred_eval".to_string()))?;

        // Call the predicate
        let result = pred_eval
            .call(&mut store, 0)
            .map_err(|e| WasmRuntimeError::ExecutionError(e.to_string()))?;

        Ok(EvalResult {
            matched: result == 1,
            error: None,
            captured_fields: AHashMap::new(),
        })
    }
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
            wasmtime::PoolingAllocationConfig::default(),
        ));

        // Configure fuel metering
        if config.enable_fuel {
            engine_config.consume_fuel(true);
        }

        let engine = kestrel_schema::map_err_string!(
            Engine::new(&engine_config),
            WasmRuntimeError::CompilationError
        )?;

        let mut linker = Linker::new(&engine);

        // Register Host API v1 functions
        Self::register_host_api(&mut linker)?;

        // Create AOT cache directory if enabled
        if config.enable_aot_cache {
            if let Some(ref cache_dir) = config.aot_cache_dir {
                kestrel_schema::map_err_string!(
                    std::fs::create_dir_all(cache_dir),
                    WasmRuntimeError::IoError
                )?;
            }
        }

        Ok(Self {
            engine,
            linker,
            config,
            schema,
            modules: Arc::new(RwLock::new(AHashMap::new())),
            instance_pool: Arc::new(RwLock::new(AHashMap::new())),
            regex_cache: Arc::new(RwLock::new(AHashMap::new())),
            glob_cache: Arc::new(RwLock::new(AHashMap::new())),
            next_regex_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            next_glob_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            pool_metrics: Arc::new(PoolMetrics::new()),
        })
    }

    /// Register Host API v1 functions
    fn register_host_api(linker: &mut Linker<WasmContext>) -> Result<(), WasmRuntimeError> {
        // Event field reading: event_get_i64
        linker
            .func_wrap(
                "kestrel",
                "event_get_i64",
                |caller: Caller<'_, WasmContext>, _event_handle: u32, field_id: u32| -> i64 {
                    let ctx = caller.data();
                    let api = HostApiContext {
                        event: ctx.event.as_ref(),
                        regex_cache: &ctx.regex_cache,
                        glob_cache: &ctx.glob_cache,
                        alerts: &ctx.alerts,
                        rule_metadata: Some(&ctx.rule_metadata),
                    };
                    api.event_get_i64(field_id).unwrap_or(0)
                },
            )
            .map_err(|e| WasmRuntimeError::ExecutionError(e.to_string()))?;

        // Event field reading: event_get_u64
        linker
            .func_wrap(
                "kestrel",
                "event_get_u64",
                |caller: Caller<'_, WasmContext>, _event_handle: u32, field_id: u32| -> u64 {
                    let ctx = caller.data();
                    let api = HostApiContext {
                        event: ctx.event.as_ref(),
                        regex_cache: &ctx.regex_cache,
                        glob_cache: &ctx.glob_cache,
                        alerts: &ctx.alerts,
                        rule_metadata: Some(&ctx.rule_metadata),
                    };
                    api.event_get_u64(field_id).unwrap_or(0)
                },
            )
            .map_err(|e| WasmRuntimeError::ExecutionError(e.to_string()))?;

        // Event field reading: event_get_str
        linker
            .func_wrap(
                "kestrel",
                "event_get_str",
                |mut caller: Caller<'_, WasmContext>,
                 _event_handle: u32,
                 field_id: u32,
                 ptr: u32,
                 len: u32|
                 -> u32 {
                    let s = {
                        let ctx = caller.data();
                        let api = HostApiContext {
                            event: ctx.event.as_ref(),
                            regex_cache: &ctx.regex_cache,
                            glob_cache: &ctx.glob_cache,
                            alerts: &ctx.alerts,
                            rule_metadata: Some(&ctx.rule_metadata),
                        };
                        match api.event_get_str(field_id) {
                            Some(value) => value.to_string(),
                            None => return 0,
                        }
                    };

                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(m)) => m,
                        _ => return 0,
                    };

                    let bytes_to_write = std::cmp::min(len as usize, s.len());
                    if mem
                        .write(&mut caller, ptr as usize, &s.as_bytes()[..bytes_to_write])
                        .is_err()
                    {
                        return 0;
                    }
                    bytes_to_write as u32
                },
            )
            .map_err(|e| WasmRuntimeError::ExecutionError(e.to_string()))?;

        // Event field reading: event_get_bool
        linker
            .func_wrap(
                "kestrel",
                "event_get_bool",
                |caller: Caller<'_, WasmContext>, _event_handle: u32, field_id: u32| -> i32 {
                    let ctx = caller.data();
                    let api = HostApiContext {
                        event: ctx.event.as_ref(),
                        regex_cache: &ctx.regex_cache,
                        glob_cache: &ctx.glob_cache,
                        alerts: &ctx.alerts,
                        rule_metadata: Some(&ctx.rule_metadata),
                    };
                    if api.event_get_bool(field_id).unwrap_or(false) {
                        1
                    } else {
                        0
                    }
                },
            )
            .map_err(|e| WasmRuntimeError::ExecutionError(e.to_string()))?;

        // Regex matching
        linker
            .func_wrap(
                "kestrel",
                "re_match",
                |mut caller: Caller<'_, WasmContext>, re_id: u32, ptr: u32, len: u32| -> i32 {
                    let text = {
                        let mem = match caller.get_export("memory") {
                            Some(Extern::Memory(m)) => m,
                            _ => return 0,
                        };

                        let mut data = vec![0u8; len as usize];
                        if mem.read(&mut caller, ptr as usize, &mut data).is_err() {
                            return 0;
                        }

                        match std::str::from_utf8(&data) {
                            Ok(s) => s.to_string(),
                            Err(_) => return 0,
                        }
                    };

                    let ctx = caller.data();
                    let api = HostApiContext {
                        event: ctx.event.as_ref(),
                        regex_cache: &ctx.regex_cache,
                        glob_cache: &ctx.glob_cache,
                        alerts: &ctx.alerts,
                        rule_metadata: Some(&ctx.rule_metadata),
                    };
                    if api.re_match(re_id, &text) {
                        1
                    } else {
                        0
                    }
                },
            )
            .map_err(|e| WasmRuntimeError::ExecutionError(e.to_string()))?;

        // Glob matching
        linker
            .func_wrap(
                "kestrel",
                "glob_match",
                |mut caller: Caller<'_, WasmContext>, glob_id: u32, ptr: u32, len: u32| -> i32 {
                    let text = {
                        let mem = match caller.get_export("memory") {
                            Some(Extern::Memory(m)) => m,
                            _ => return 0,
                        };

                        let mut data = vec![0u8; len as usize];
                        if mem.read(&mut caller, ptr as usize, &mut data).is_err() {
                            return 0;
                        }

                        match std::str::from_utf8(&data) {
                            Ok(s) => s.to_string(),
                            Err(_) => return 0,
                        }
                    };

                    let ctx = caller.data();
                    let api = HostApiContext {
                        event: ctx.event.as_ref(),
                        regex_cache: &ctx.regex_cache,
                        glob_cache: &ctx.glob_cache,
                        alerts: &ctx.alerts,
                        rule_metadata: Some(&ctx.rule_metadata),
                    };
                    if api.glob_match(glob_id, &text) {
                        1
                    } else {
                        0
                    }
                },
            )
            .map_err(|e| WasmRuntimeError::ExecutionError(e.to_string()))?;

        // Alert emission with field capture
        linker
            .func_wrap(
                "kestrel",
                "alert_emit",
                |caller: Caller<'_, WasmContext>, event_handle: u32| -> i32 {
                    let ctx = caller.data();
                    let api = HostApiContext {
                        event: ctx.event.as_ref(),
                        regex_cache: &ctx.regex_cache,
                        glob_cache: &ctx.glob_cache,
                        alerts: &ctx.alerts,
                        rule_metadata: Some(&ctx.rule_metadata),
                    };
                    let result = api.alert_emit(event_handle);
                    if result < 0 {
                        error!("No event in context for alert_emit");
                    }
                    result
                },
            )
            .map_err(|e| WasmRuntimeError::ExecutionError(e.to_string()))?;

        // Field capture function for pred_capture
        // Allows Wasm predicates to mark specific fields for inclusion in alerts
        linker
            .func_wrap(
                "kestrel",
                "capture_field",
                |caller: Caller<'_, WasmContext>, field_id: u32| -> i32 {
                    // Get the context data
                    let ctx = caller.data();

                    // Check if we have an event
                    let event = match ctx.event.as_ref() {
                        Some(e) => e,
                        None => {
                            error!("No event in context for capture_field");
                            return -1; // Error
                        },
                    };

                    // Get the field value
                    let value = match event.get_field(field_id) {
                        Some(v) => v.clone(),
                        None => return -2, // Field not found
                    };

                    // Store captured field in a dedicated capture map
                    // For now, we'll add it to a special alert record that can be retrieved later
                    let mut alerts = ctx.alerts.lock();

                    // Find or create a capture record
                    let capture_record = if alerts.is_empty() {
                        AlertRecord {
                            rule_id: "capture".to_string(),
                            severity: "info".to_string(),
                            title: "Field Capture".to_string(),
                            description: None,
                            event_handles: vec![],
                            fields: AHashMap::new(),
                        }
                    } else {
                        alerts.pop().unwrap()
                    };

                    // Add the captured field
                    let mut updated_record = capture_record;
                    updated_record
                        .fields
                        .insert(format!("field_{}", field_id), value);

                    alerts.push(updated_record);

                    0 // Success
                },
            )
            .map_err(|e| WasmRuntimeError::ExecutionError(e.to_string()))?;

        Ok(())
    }

    /// Compile a Wasm rule and extract metadata
    pub async fn compile_rule(
        &self,
        rule_id: &str,
        wasm_bytes: Vec<u8>,
    ) -> Result<(), WasmRuntimeError> {
        // For now, create default metadata
        // In a full implementation, this would extract metadata from the Wasm module
        let metadata = RuleMetadata::new(rule_id, format!("Rule {}", rule_id));

        let manifest = RuleManifest::new(metadata).with_capabilities(RuleCapabilities {
            supports_inline: true,
            requires_alert: true,
            requires_block: false,
            max_span_ms: None,
        });

        // Load the module with the generated manifest
        self.load_module(manifest, wasm_bytes, AHashMap::new()).await?;
        Ok(())
    }

    /// Load a Wasm module from a rule package
    pub async fn load_module(
        &self,
        manifest: RuleManifest,
        wasm_bytes: Vec<u8>,
        predicate_fields: AHashMap<u32, Vec<u32>>,
    ) -> Result<String, WasmRuntimeError> {
        let rule_id = manifest.metadata.rule_id.clone();

        info!(rule_id = %rule_id, "Loading Wasm module");

        let module = kestrel_schema::map_err_string!(
            Module::from_binary(&self.engine, &wasm_bytes),
            WasmRuntimeError::CompilationError
        )?;

        let instance_pre = self
            .instance_pre(&module)
            .map_err(|e| WasmRuntimeError::InstantiationError(e.to_string()))?;

        if self.config.enable_aot_cache {
            if let Some(ref cache_dir) = self.config.aot_cache_dir {
                let _cache_path = cache_dir.join(format!("{}.cwasm", rule_id));
            }
        }

        let compiled = CompiledModule {
            module,
            instance_pre,
            metadata: manifest.metadata,
            predicate_fields,
        };

        // Pre-populate the instance pool
        let pool_size = self.config.pool_size;
        let mut instances = Vec::with_capacity(pool_size);

        // Create pooled instances
        // Note: We can't reuse InstancePre, so we create new InstancePre for each pool entry
        for _ in 0..pool_size {
            let mut store = Store::new(
                &self.engine,
                WasmContext {
                    event: None,
                    schema: self.schema.clone(),
                    alerts: Arc::new(Mutex::new(Vec::new())),
                    regex_cache: self.regex_cache.clone(),
                    glob_cache: self.glob_cache.clone(),
                    rule_metadata: compiled.metadata.clone(),
                },
            );

            // Create a new InstancePre for this pool entry
            let instance_pre = self
                .linker
                .instantiate_pre(&compiled.module)
                .map_err(|e| WasmRuntimeError::InstantiationError(e.to_string()))?;

            let instance = instance_pre
                .instantiate(&mut store)
                .map_err(|e| WasmRuntimeError::InstantiationError(e.to_string()))?;

            instances.push(PooledInstance { store, instance });
        }

        let pool = Arc::new(InstancePool {
            instances: Mutex::new(instances),
            semaphore: Arc::new(Semaphore::new(pool_size)),
        });

        // Set pool size in metrics
        self.pool_metrics.set_pool_size(pool_size);

        let mut modules = self.modules.write();
        let mut pools = self.instance_pool.write();

        modules.insert(rule_id.clone(), compiled);
        pools.insert(rule_id.clone(), pool);

        info!(rule_id = %rule_id, pool_size, "Wasm module loaded successfully with instance pool");
        Ok(rule_id)
    }

    /// Evaluate a predicate from an already loaded module using the instance pool.
    pub async fn eval_loaded_predicate(
        &self,
        rule_id: &str,
        predicate_index: u32,
        event: &Event,
    ) -> Result<bool, WasmRuntimeError> {
        let pool = {
            let pools = self.instance_pool.read();
            pools.get(rule_id).cloned().ok_or_else(|| {
                WasmRuntimeError::CompilationError(format!("Module not found: {}", rule_id))
            })?
        };

        let _permit = pool
            .semaphore
            .acquire()
            .await
            .map_err(|e| WasmRuntimeError::ExecutionError(e.to_string()))?;

        let mut instance = {
            let mut instances = pool.instances.lock();
            instances.pop().ok_or_else(|| {
                WasmRuntimeError::ExecutionError("No available instances in pool".to_string())
            })?
        };

        instance.store.data_mut().event = Some(event.clone());
        let result = {
            let pred_eval = instance
                .instance
                .get_typed_func::<(u32,), i32>(&mut instance.store, "pred_eval")
                .map_err(|_| WasmRuntimeError::FunctionNotFound("pred_eval".to_string()))?;

            pred_eval
                .call(&mut instance.store, (predicate_index,))
                .map(|value| value == 1)
                .map_err(|e: wasmtime::Error| WasmRuntimeError::ExecutionError(e.to_string()))
        };
        instance.store.data_mut().event = None;

        {
            let mut instances = pool.instances.lock();
            instances.push(instance);
        }
        self.pool_metrics.record_release();

        result
    }

    /// Check if a module is loaded by rule ID.
    pub fn is_module_loaded(&self, rule_id: &str) -> bool {
        let pools = self.instance_pool.read();
        pools.contains_key(rule_id)
    }

    /// Compile and run an ad-hoc Wasm predicate
    pub async fn eval_adhoc_predicate(
        &self,
        wasm_bytes: &[u8],
        event: &Event,
    ) -> Result<bool, WasmRuntimeError> {
        use wasmtime::{Instance, Module, Store};

        let module = kestrel_schema::map_err_string!(
            Module::from_binary(&self.engine, wasm_bytes),
            WasmRuntimeError::CompilationError
        )?;

        let mut store = Store::new(
            &self.engine,
            WasmContext {
                event: Some(event.clone()),
                schema: self.schema.clone(),
                alerts: Arc::new(Mutex::new(Vec::new())),
                regex_cache: self.regex_cache.clone(),
                glob_cache: self.glob_cache.clone(),
                rule_metadata: RuleMetadata::new("adhoc", "Ad-hoc Predicate"),
            },
        );

        let instance = Instance::new(&mut store, &module, &[])
            .map_err(|e| WasmRuntimeError::InstantiationError(e.to_string()))?;

        let pred_eval = instance
            .get_typed_func::<(), i32>(&mut store, "pred_eval")
            .map_err(|_| WasmRuntimeError::FunctionNotFound("pred_eval".to_string()))?;

        let result = pred_eval
            .call(&mut store, ())
            .map_err(|e| WasmRuntimeError::ExecutionError(e.to_string()))?;

        Ok(result == 1)
    }

    /// Create a predicate for a rule
    pub fn create_predicate(&self, rule_id: &str) -> Result<WasmPredicate, WasmRuntimeError> {
        Ok(WasmPredicate {
            rule_id: rule_id.to_string(),
            engine: Arc::new(self.clone()),
        })
    }

    /// Pre-instantiate a module for pooling
    fn instance_pre(&self, module: &Module) -> Result<InstancePre<WasmContext>, WasmRuntimeError> {
        self.linker
            .instantiate_pre(module)
            .map_err(|e| WasmRuntimeError::InstantiationError(e.to_string()))
    }

    /// Register a compiled regex pattern
    pub async fn register_regex(&self, pattern: &str) -> Result<RegexId, WasmRuntimeError> {
        let re = kestrel_schema::map_err_string!(
            regex::Regex::new(pattern),
            WasmRuntimeError::CompilationError
        )?;

        let id = self
            .next_regex_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut cache = self.regex_cache.write();
        cache.insert(id, re);
        Ok(id)
    }

    /// Register a compiled glob pattern
    pub async fn register_glob(&self, pattern: &str) -> Result<GlobId, WasmRuntimeError> {
        let glob = kestrel_schema::map_err_string!(
            glob::Pattern::new(pattern),
            WasmRuntimeError::CompilationError
        )?;

        let id = self
            .next_glob_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut cache = self.glob_cache.write();
        cache.insert(id, glob);
        Ok(id)
    }

    /// Get runtime capabilities
    pub fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities {
            regex: true,
            glob: true,
            string_ops: true,
            math_ops: true,
            max_memory_mb: self.config.max_memory_mb,
            max_execution_time_ms: self.config.max_execution_time_ms,
        }
    }

    /// Get runtime type
    pub fn runtime_type(&self) -> RuntimeType {
        RuntimeType::Wasm
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
            pool_metrics: self.pool_metrics.clone(),
        }
    }
}

/// Implement PredicateEvaluator trait for NFA engine integration
///
/// This allows the Wasm runtime to be used as a predicate evaluator
/// for the NFA sequence engine.
#[async_trait::async_trait]
impl kestrel_nfa::PredicateEvaluator for WasmEngine {
    /// Evaluate a predicate against an event
    ///
    /// The predicate_id should be in the format "rule_id:predicate_id" where:
    /// - rule_id is the Wasm module identifier
    /// - predicate_id is the index of the predicate within the module
    async fn evaluate(
        &self,
        predicate_id: &str,
        event: &kestrel_event::Event,
    ) -> kestrel_nfa::NfaResult<bool> {
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
            kestrel_nfa::NfaError::PredicateError(format!("Invalid predicate index: {}", parts[1]))
        })?;

        let wait_start = std::time::Instant::now();
        let result = self
            .eval_loaded_predicate(rule_id, predicate_index, event)
            .await
            .map_err(|e| kestrel_nfa::NfaError::PredicateError(e.to_string()))?;
        let wait_ns = wait_start.elapsed().as_nanos() as u64;
        self.pool_metrics.record_acquire(wait_ns);
        Ok(result)
    }

    fn get_required_fields(&self, predicate_id: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
        // Parse predicate_id as "rule_id:predicate_index"
        let parts: Vec<&str> = predicate_id.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Ok(vec![]);
        }

        let rule_id = parts[0];
        let predicate_index: u32 = parts[1].parse().unwrap_or(0);

        // Look up required fields from compiled module
        let modules = self.modules.read();
        if let Some(compiled) = modules.get(rule_id) {
            if let Some(fields) = compiled.predicate_fields.get(&predicate_index) {
                return Ok(fields.clone());
            }
        }
        Ok(vec![])
    }

    fn has_predicate(&self, predicate_id: &str) -> bool {
        // Parse predicate_id as "rule_id:predicate_index"
        let parts: Vec<&str> = predicate_id.splitn(2, ':').collect();
        if parts.len() != 2 {
            return false;
        }

        let rule_id = parts[0];

        // Check if the module is loaded
        let pools = self.instance_pool.read();
        pools.contains_key(rule_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_config_defaults() {
        let config = WasmConfig::default();
        assert_eq!(config.max_memory_mb, 16);
        assert_eq!(config.max_execution_time_ms, 100);
        assert!(config.enable_fuel);
    }

    #[test]
    fn test_runtime_config_trait() {
        let config = WasmConfig::default();
        assert_eq!(config.max_memory_mb(), 16);
        assert_eq!(config.max_execution_time_ms(), 100);
        assert_eq!(config.instruction_limit(), Some(1_000_000));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_async_predicate_evaluator_accepts_loaded_module_ids() {
        let schema = Arc::new(SchemaRegistry::new());
        let engine = WasmEngine::new(WasmConfig::default(), schema).unwrap();

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

        engine.compile_rule("async-predicate", wasm_bytes).await.unwrap();

        assert!(kestrel_nfa::PredicateEvaluator::has_predicate(&engine, "async-predicate:0"));

        let event = Event::builder()
            .event_type(1)
            .ts_mono(1_000)
            .ts_wall(1_000)
            .entity_key(7)
            .build()
            .unwrap();

        let result = kestrel_nfa::PredicateEvaluator::evaluate(&engine, "invalid", &event).await;
        assert!(matches!(
            result,
            Err(kestrel_nfa::NfaError::PredicateError(message)) if message.contains("Invalid predicate_id format")
        ));
    }

    #[test]
    fn test_pool_metrics() {
        let metrics = PoolMetrics::new();
        metrics.set_pool_size(10);

        metrics.record_acquire(100);
        assert_eq!(metrics.utilization_pct(), 10.0);

        metrics.record_release();
        assert_eq!(metrics.utilization_pct(), 0.0);

        metrics.record_miss();
        assert_eq!(metrics.cache_hit_rate_pct(), 0.0); // 0 hits out of 1 acquire
    }
}
