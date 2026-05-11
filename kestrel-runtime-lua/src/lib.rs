//! Kestrel Lua Runtime
//!
//! This module provides LuaJIT runtime support for predicate execution using mlua.
//! Implements Host API v1 via FFI, consistent with Wasm runtime.

use ahash::AHashMap;
use anyhow::Result;
use mlua::{Function, Lua, RegistryKey};
use parking_lot::{Mutex, RwLock};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info};

use kestrel_event::Event;
use kestrel_event::host_api::{HostApiContext, HostApiV1};
use kestrel_schema::{
    AlertRecord, EvalResult, FieldId, GlobId, RegexId, RuleManifest, RuleMetadata,
    RuntimeCapabilities, RuntimeConfig, RuntimeType, SchemaRegistry,
};

// Re-export types from kestrel-schema for backward compatibility
pub use kestrel_schema::{
    AlertRecord as HostAlertRecord, EventHandle as HostEventHandle, FieldId as HostFieldId,
    GlobId as HostGlobId, RegexId as HostRegexId,
};

/// Lua runtime configuration
#[derive(Debug, Clone)]
pub struct LuaConfig {
    /// Enable JIT compilation
    pub enable_jit: bool,
    /// Maximum memory per Lua state (in MB)
    pub max_memory_mb: usize,
    /// Maximum execution time (in milliseconds)
    pub max_execution_time_ms: u64,
    /// Instruction limit for single predicate evaluation
    pub instruction_limit: Option<u64>,
}

impl Default for LuaConfig {
    fn default() -> Self {
        Self {
            enable_jit: true,
            max_memory_mb: 16,
            max_execution_time_ms: 100,
            instruction_limit: Some(1_000_000),
        }
    }
}

impl RuntimeConfig for LuaConfig {
    fn max_memory_mb(&self) -> usize {
        self.max_memory_mb
    }

    fn max_execution_time_ms(&self) -> u64 {
        self.max_execution_time_ms
    }

    fn instruction_limit(&self) -> Option<u64> {
        self.instruction_limit
    }
}

/// Lua runtime engine
pub struct LuaEngine {
    lua: Arc<Lua>,
    config: LuaConfig,
    _schema: Arc<SchemaRegistry>,
    predicates: Arc<RwLock<AHashMap<String, LuaPredicate>>>,
    regex_cache: Arc<RwLock<AHashMap<RegexId, regex::Regex>>>,
    glob_cache: Arc<RwLock<AHashMap<GlobId, glob::Pattern>>>,
    next_regex_id: Arc<std::sync::atomic::AtomicU32>,
    next_glob_id: Arc<std::sync::atomic::AtomicU32>,
    /// Current event (wrapped in Arc for thread-safe access)
    current_event: Arc<RwLock<Option<Event>>>,
    /// Alert collector (stores emitted alerts)
    current_alerts: Arc<Mutex<Vec<AlertRecord>>>,
    /// Current rule metadata for alert construction
    current_rule_metadata: Arc<RwLock<Option<RuleMetadata>>>,
}

/// Loaded Lua predicate
pub struct LuaPredicate {
    _rule_id: String,
    _init_func: Option<Function>,
    eval_func: RegistryKey,
    metadata: RuleMetadata,
}

/// Lua runtime errors
#[derive(Debug, Error)]
pub enum LuaRuntimeError {
    #[error("Failed to load Lua script: {0}")]
    LoadError(String),

    #[error("Execution error: {0}")]
    ExecutionError(String),

    #[error("Function not found: {0}")]
    FunctionNotFound(String),

    #[error("Execution timeout")]
    Timeout,

    #[error("Memory limit exceeded")]
    MemoryLimitExceeded,

    #[error("Invalid event handle: {0}")]
    InvalidEventHandle(u32),

    #[error("Invalid field ID: {0}")]
    InvalidFieldId(FieldId),

    #[error("IO error: {0}")]
    IoError(String),
}

impl LuaEngine {
    /// Create a new Lua engine
    pub fn new(config: LuaConfig, schema: Arc<SchemaRegistry>) -> Result<Self, LuaRuntimeError> {
        info!("Initializing LuaJIT runtime");

        // Create Lua instance
        let lua = Lua::new();

        // Configure JIT if enabled
        if config.enable_jit {
            debug!("LuaJIT enabled");
            // JIT is enabled by default in LuaJIT
        }

        let engine = Self {
            lua: Arc::new(lua),
            config,
            _schema: schema,
            predicates: Arc::new(RwLock::new(AHashMap::new())),
            regex_cache: Arc::new(RwLock::new(AHashMap::new())),
            glob_cache: Arc::new(RwLock::new(AHashMap::new())),
            next_regex_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            next_glob_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            current_event: Arc::new(RwLock::new(None)),
            current_alerts: Arc::new(Mutex::new(Vec::new())),
            current_rule_metadata: Arc::new(RwLock::new(None)),
        };

        // Register Host API functions
        engine.register_host_api()?;

        Ok(engine)
    }

    /// Register Host API v1 functions for Lua
    fn register_host_api(&self) -> Result<(), LuaRuntimeError> {
        let lua = &self.lua;

        // Create kestrel table for Host API
        let kestrel = lua
            .create_table()
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // Capture necessary data for closures
        let regex_cache = self.regex_cache.clone();
        let glob_cache = self.glob_cache.clone();
        let current_event = self.current_event.clone();
        let current_alerts = self.current_alerts.clone();
        let current_rule_metadata = self.current_rule_metadata.clone();

        // event_get_i64
        let event_ref = current_event.clone();
        let meta_ref = current_rule_metadata.clone();
        let re_cache = regex_cache.clone();
        let g_cache = glob_cache.clone();
        let alerts_ref = current_alerts.clone();
        let event_get_i64 = lua
            .create_function(move |_lua, (_event_handle, field_id): (u32, u32)| {
                let event_guard = event_ref.read();
                let meta_guard = meta_ref.read();
                let api = HostApiContext {
                    event: event_guard.as_ref(),
                    regex_cache: &*re_cache,
                    glob_cache: &*g_cache,
                    alerts: &*alerts_ref,
                    rule_metadata: meta_guard.as_ref(),
                };
                Ok(api.event_get_i64(field_id).unwrap_or(0i64))
            })
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        kestrel
            .set("event_get_i64", event_get_i64)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // event_get_u64
        let event_ref = current_event.clone();
        let meta_ref = current_rule_metadata.clone();
        let re_cache = regex_cache.clone();
        let g_cache = glob_cache.clone();
        let alerts_ref = current_alerts.clone();
        let event_get_u64 = lua
            .create_function(move |_lua, (_event_handle, field_id): (u32, u32)| {
                let event_guard = event_ref.read();
                let meta_guard = meta_ref.read();
                let api = HostApiContext {
                    event: event_guard.as_ref(),
                    regex_cache: &*re_cache,
                    glob_cache: &*g_cache,
                    alerts: &*alerts_ref,
                    rule_metadata: meta_guard.as_ref(),
                };
                Ok(api.event_get_u64(field_id).unwrap_or(0))
            })
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        kestrel
            .set("event_get_u64", event_get_u64)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // event_get_str
        let event_ref = current_event.clone();
        let meta_ref = current_rule_metadata.clone();
        let re_cache = regex_cache.clone();
        let g_cache = glob_cache.clone();
        let alerts_ref = current_alerts.clone();
        let event_get_str = lua
            .create_function(move |_lua, (_event_handle, field_id): (u32, u32)| {
                let event_guard = event_ref.read();
                let meta_guard = meta_ref.read();
                let api = HostApiContext {
                    event: event_guard.as_ref(),
                    regex_cache: &*re_cache,
                    glob_cache: &*g_cache,
                    alerts: &*alerts_ref,
                    rule_metadata: meta_guard.as_ref(),
                };
                Ok(api.event_get_str(field_id).unwrap_or("").to_string())
            })
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        kestrel
            .set("event_get_str", event_get_str)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // event_get_bool
        let event_ref = current_event.clone();
        let meta_ref = current_rule_metadata.clone();
        let re_cache = regex_cache.clone();
        let g_cache = glob_cache.clone();
        let alerts_ref = current_alerts.clone();
        let event_get_bool = lua
            .create_function(move |_lua, (_event_handle, field_id): (u32, u32)| {
                let event_guard = event_ref.read();
                let meta_guard = meta_ref.read();
                let api = HostApiContext {
                    event: event_guard.as_ref(),
                    regex_cache: &*re_cache,
                    glob_cache: &*g_cache,
                    alerts: &*alerts_ref,
                    rule_metadata: meta_guard.as_ref(),
                };
                Ok(api.event_get_bool(field_id).unwrap_or(false))
            })
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        kestrel
            .set("event_get_bool", event_get_bool)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // re_match
        let re_cache = regex_cache.clone();
        let g_cache = glob_cache.clone();
        let alerts_ref = current_alerts.clone();
        let re_match = lua
            .create_function(move |_lua, (re_id, text): (u32, String)| {
                let api = HostApiContext {
                    event: None,
                    regex_cache: &*re_cache,
                    glob_cache: &*g_cache,
                    alerts: &*alerts_ref,
                    rule_metadata: None,
                };
                Ok(api.re_match(re_id, &text))
            })
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        kestrel
            .set("re_match", re_match)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // glob_match
        let g_cache = glob_cache.clone();
        let re_cache = regex_cache.clone();
        let alerts_ref = current_alerts.clone();
        let glob_match = lua
            .create_function(move |_lua, (glob_id, text): (u32, String)| {
                let api = HostApiContext {
                    event: None,
                    regex_cache: &*re_cache,
                    glob_cache: &*g_cache,
                    alerts: &*alerts_ref,
                    rule_metadata: None,
                };
                Ok(api.glob_match(glob_id, &text))
            })
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        kestrel
            .set("glob_match", glob_match)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // alert_emit
        let event_ref = current_event.clone();
        let meta_ref = current_rule_metadata.clone();
        let re_cache = regex_cache.clone();
        let g_cache = glob_cache.clone();
        let alerts_ref = current_alerts.clone();
        let alert_emit = lua
            .create_function(move |_lua, event_handle: u32| {
                let event_guard = event_ref.read();
                let meta_guard = meta_ref.read();
                let api = HostApiContext {
                    event: event_guard.as_ref(),
                    regex_cache: &*re_cache,
                    glob_cache: &*g_cache,
                    alerts: &*alerts_ref,
                    rule_metadata: meta_guard.as_ref(),
                };
                Ok(api.alert_emit(event_handle))
            })
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        kestrel
            .set("alert_emit", alert_emit)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // Set kestrel table in globals
        lua.globals()
            .set("kestrel", kestrel)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        info!("Lua Host API registered successfully");
        Ok(())
    }

    /// Load a Lua predicate from script
    pub async fn load_predicate(
        &self,
        manifest: RuleManifest,
        script: String,
    ) -> Result<String, LuaRuntimeError> {
        let rule_id = manifest.metadata.rule_id.clone();

        info!(rule_id = %rule_id, "Loading Lua predicate");

        let lua = &self.lua;
        let predicate = self.load_predicate_internal(lua, &rule_id, script, manifest).await?;

        let mut predicates = self.predicates.write();
        predicates.insert(rule_id.clone(), predicate);

        info!(rule_id = %rule_id, "Lua predicate loaded successfully");
        Ok(rule_id)
    }

    /// Internal predicate loading
    async fn load_predicate_internal(
        &self,
        lua: &Lua,
        rule_id: &str,
        script: String,
        manifest: RuleManifest,
    ) -> Result<LuaPredicate, LuaRuntimeError> {
        // Load and execute the script
        lua.load(&script)
            .set_name(rule_id)
            .exec()
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // Get pred_init function (optional)
        let init_func: Option<Function> = lua
            .globals()
            .get("pred_init")
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // Get pred_eval function (required)
        let eval_func: Function = lua
            .globals()
            .get("pred_eval")
            .map_err(|_| LuaRuntimeError::FunctionNotFound("pred_eval".to_string()))?;

        let eval_key = lua
            .create_registry_value(eval_func)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        Ok(LuaPredicate {
            _rule_id: rule_id.to_string(),
            _init_func: init_func,
            eval_func: eval_key,
            metadata: manifest.metadata,
        })
    }

    /// Evaluate an event with a predicate
    pub async fn eval(&self, rule_id: &str, event: &Event) -> Result<EvalResult, LuaRuntimeError> {
        let predicates = self.predicates.read();
        let predicate = predicates
            .get(rule_id)
            .ok_or_else(|| LuaRuntimeError::FunctionNotFound(rule_id.to_string()))?;

        // Set current event
        let mut guard = self.current_event.write();
        *guard = Some(event.clone());
        drop(guard);

        // Set current rule metadata
        let mut guard = self.current_rule_metadata.write();
        *guard = Some(predicate.metadata.clone());
        drop(guard);

        // Clear previous alerts
        let mut guard = self.current_alerts.lock();
        guard.clear();
        drop(guard);

        let lua = &self.lua;

        // Get eval function from registry
        let eval_func = lua
            .registry_value::<Function>(&predicate.eval_func)
            .map_err(|e| LuaRuntimeError::ExecutionError(e.to_string()))?;

        // Call the predicate
        let result: std::result::Result<bool, mlua::Error> = eval_func.call(());

        // Clear current event after evaluation
        let mut guard = self.current_event.write();
        guard.take();
        drop(guard);

        // Clear current rule metadata after evaluation
        let mut guard = self.current_rule_metadata.write();
        guard.take();
        drop(guard);

        match result {
            Ok(match_status) => Ok(EvalResult {
                matched: match_status,
                error: None,
                captured_fields: AHashMap::new(),
            }),
            Err(e) => {
                // Clear current event on error too
                let mut guard = self.current_event.write();
                guard.take();
                drop(guard);
                // Clear current rule metadata on error too
                let mut guard = self.current_rule_metadata.write();
                guard.take();
                drop(guard);
                Ok(EvalResult {
                    matched: false,
                    error: Some(e.to_string()),
                    captured_fields: AHashMap::new(),
                })
            },
        }
    }

    /// Register a compiled regex pattern
    pub async fn register_regex(&self, pattern: &str) -> Result<RegexId, LuaRuntimeError> {
        let re =
            kestrel_schema::map_err_string!(
                regex::Regex::new(pattern),
                LuaRuntimeError::LoadError
            )?;

        let id = self
            .next_regex_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut cache = self.regex_cache.write();
        cache.insert(id, re);
        Ok(id)
    }

    /// Register a compiled glob pattern
    pub async fn register_glob(&self, pattern: &str) -> Result<GlobId, LuaRuntimeError> {
        let glob =
            kestrel_schema::map_err_string!(
                glob::Pattern::new(pattern),
                LuaRuntimeError::LoadError
            )?;

        let id = self
            .next_glob_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut cache = self.glob_cache.write();
        cache.insert(id, glob);
        Ok(id)
    }

    /// Check if a predicate is loaded
    pub fn has_predicate(&self, predicate_id: &str) -> bool {
        let predicates = self.predicates.read();
        predicates.contains_key(predicate_id)
    }

    /// Unload a predicate from the engine
    pub fn unload_predicate(&self, predicate_id: &str) {
        let mut predicates = self.predicates.write();
        predicates.remove(predicate_id);
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
        RuntimeType::Lua
    }
}

/// Implement PredicateEvaluator trait for NFA engine integration
///
/// This allows the Lua runtime to be used as a predicate evaluator
/// for the NFA sequence engine, enabling dual runtime support (Wasm + Lua).
#[async_trait::async_trait]
impl kestrel_nfa::PredicateEvaluator for LuaEngine {
    /// Evaluate a predicate against an event
    ///
    /// The predicate_id should be in the format "rule_id" where:
    /// - rule_id is the Lua predicate identifier
    async fn evaluate(
        &self,
        predicate_id: &str,
        event: &kestrel_event::Event,
    ) -> kestrel_nfa::NfaResult<bool> {
        // Set the current event context
        {
            let mut current_event = self.current_event.write();
            *current_event = Some(event.clone());
        }

        // Clear previous alerts
        {
            let mut alerts = self.current_alerts.lock();
            alerts.clear();
        }

        // Get the predicate and its metadata
        let metadata = {
            let predicates = self.predicates.read();
            let predicate = predicates.get(predicate_id).ok_or_else(|| {
                kestrel_nfa::NfaError::PredicateError(format!(
                    "Predicate not found: {}",
                    predicate_id
                ))
            })?;
            predicate.metadata.clone()
        };

        // Set current rule metadata
        {
            let mut meta = self.current_rule_metadata.write();
            *meta = Some(metadata);
        }

        // Get the Lua state
        let lua = &self.lua;

        // Get the pred_eval function
        let pred_eval: mlua::Function = lua.globals().get("pred_eval").map_err(|e| {
            kestrel_nfa::NfaError::PredicateError(format!(
                "Failed to get pred_eval function: {}",
                e
            ))
        })?;

        // Call the predicate with event_handle=0 (we only support one event at a time)
        let result: mlua::Value = pred_eval.call(0u32).map_err(|e| {
            kestrel_nfa::NfaError::PredicateError(format!("Failed to call pred_eval: {}", e))
        })?;

        // Convert result to boolean
        let matched = match result {
            mlua::Value::Boolean(b) => Ok(b),
            mlua::Value::Integer(i) => Ok(i != 0),
            mlua::Value::Number(n) => Ok(n != 0.0),
            _ => Ok(false),
        };

        // Clear the event context after evaluation
        {
            let mut current_event = self.current_event.write();
            *current_event = None;
        }

        // Clear the rule metadata after evaluation
        {
            let mut meta = self.current_rule_metadata.write();
            *meta = None;
        }

        matched
    }

    /// Get the field IDs required by a predicate
    ///
    /// For Lua predicates, we return an empty vec since we don't track
    /// field dependencies statically (Lua is dynamic).
    fn get_required_fields(&self, _predicate_id: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
        // Lua is dynamically typed, so we can't determine required fields statically
        // Returning empty vec means "potentially all fields"
        Ok(Vec::new())
    }

    /// Check if a predicate exists
    fn has_predicate(&self, predicate_id: &str) -> bool {
        let predicates = self.predicates.read();
        predicates.contains_key(predicate_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_schema::{RuleCapabilities, RuleMetadata, TypedValue};

    #[tokio::test]
    async fn test_lua_engine_create() {
        let config = LuaConfig::default();
        let schema = Arc::new(SchemaRegistry::new());
        let engine = LuaEngine::new(config, schema);
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_lua_predicate_load() {
        let config = LuaConfig::default();
        let schema = Arc::new(SchemaRegistry::new());
        let engine = LuaEngine::new(config, schema).unwrap();

        let script = r#"
            function pred_init()
                return 0  -- Success
            end

            function pred_eval(event)
                return 1  -- Match
            end
        "#
        .to_string();

        let manifest =
            RuleManifest::new(RuleMetadata::new("test-001", "Test Rule").with_severity("Low"))
                .with_capabilities(RuleCapabilities {
                    supports_inline: true,
                    requires_alert: true,
                    requires_block: false,
                    max_span_ms: None,
                });

        let result = engine.load_predicate(manifest, script).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_lua_eval_with_event() {
        let config = LuaConfig::default();
        let schema = Arc::new(SchemaRegistry::new());
        let engine = LuaEngine::new(config, schema).unwrap();

        let script = r#"
            function pred_init()
                return 0
            end

            function pred_eval(event)
                local pid = kestrel.event_get_i64(0, 1)
                return pid > 0 and pid < 10000
            end
        "#
        .to_string();

        let manifest =
            RuleManifest::new(RuleMetadata::new("test-eval", "Test Eval").with_severity("Low"))
                .with_capabilities(RuleCapabilities {
                    supports_inline: true,
                    requires_alert: true,
                    requires_block: false,
                    max_span_ms: None,
                });

        engine.load_predicate(manifest, script).await.unwrap();

        let event = Event::builder()
            .event_type(1)
            .ts_mono(0)
            .ts_wall(0)
            .entity_key(0)
            .field(1, TypedValue::I64(1234))
            .build()
            .unwrap();

        let result = engine.eval("test-eval", &event).await.unwrap();
        assert!(result.matched);
    }

    #[tokio::test]
    async fn test_regex_registration() {
        let config = LuaConfig::default();
        let schema = Arc::new(SchemaRegistry::new());
        let engine = LuaEngine::new(config, schema).unwrap();

        let result = engine.register_regex(r"\d+").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_glob_registration() {
        let config = LuaConfig::default();
        let schema = Arc::new(SchemaRegistry::new());
        let engine = LuaEngine::new(config, schema).unwrap();

        let result = engine.register_glob("*.exe").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
    }

    #[test]
    fn test_lua_config_defaults() {
        let config = LuaConfig::default();
        assert_eq!(config.max_memory_mb, 16);
        assert_eq!(config.max_execution_time_ms, 100);
        assert_eq!(config.instruction_limit, Some(1_000_000));
    }

    #[test]
    fn test_runtime_config_trait() {
        let config = LuaConfig::default();
        assert_eq!(config.max_memory_mb(), 16);
        assert_eq!(config.max_execution_time_ms(), 100);
        assert_eq!(config.instruction_limit(), Some(1_000_000));
    }
}
