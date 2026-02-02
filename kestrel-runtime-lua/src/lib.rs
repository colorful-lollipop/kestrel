//! Kestrel Lua Runtime
//!
//! This module provides LuaJIT runtime support for predicate execution using mlua.
//! Implements Host API v1 via FFI, consistent with Wasm runtime.

use anyhow::Result;
use mlua::{Function, Lua, RegistryKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock as StdRwLock};
use thiserror::Error;
use tracing::{debug, info};

use kestrel_event::Event;
use kestrel_schema::{FieldId, SchemaRegistry, TypedValue};

/// Host API v1 for Lua predicates (same as Wasm)
///
/// Provides functions for:
/// - Event field reading
/// - Regex/glob matching
/// - Alert emission

pub mod host_api {
    use super::*;

    /// Event handle (same as Wasm)
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

/// Lua runtime engine
pub struct LuaEngine {
    lua: Arc<Lua>,
    config: LuaConfig,
    schema: Arc<SchemaRegistry>,
    predicates: Arc<StdRwLock<HashMap<String, LuaPredicate>>>,
    regex_cache: Arc<StdRwLock<HashMap<RegexId, regex::Regex>>>,
    glob_cache: Arc<StdRwLock<HashMap<GlobId, glob::Pattern>>>,
    next_regex_id: Arc<std::sync::atomic::AtomicU32>,
    next_glob_id: Arc<std::sync::atomic::AtomicU32>,
    /// Current event (wrapped in Arc for thread-safe access)
    current_event: Arc<StdRwLock<Option<Event>>>,
    /// Alert collector (stores emitted alerts)
    current_alerts: Arc<StdRwLock<Vec<EventHandle>>>,
}

/// Loaded Lua predicate
pub struct LuaPredicate {
    rule_id: String,
    init_func: Option<Function>,
    eval_func: RegistryKey,
}

/// Predicate evaluation result
#[derive(Debug, Clone)]
pub struct EvalResult {
    pub matched: bool,
    pub error: Option<String>,
    pub captured_fields: HashMap<String, TypedValue>,
}

/// Rule package metadata (same as Wasm)
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

/// Rule package manifest (same as Wasm)
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
            schema,
            predicates: Arc::new(StdRwLock::new(HashMap::new())),
            regex_cache: Arc::new(StdRwLock::new(HashMap::new())),
            glob_cache: Arc::new(StdRwLock::new(HashMap::new())),
            next_regex_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            next_glob_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            current_event: Arc::new(StdRwLock::new(None)),
            current_alerts: Arc::new(StdRwLock::new(Vec::new())),
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

        // event_get_i64
        let event_ref = current_event.clone();
        let event_get_i64 = lua
            .create_function(move |_lua, (_event_handle, field_id): (u32, u32)| {
                let event_guard = event_ref.read().unwrap();
                if let Some(event) = event_guard.as_ref() {
                    let value = event.get_field(field_id);
                    match value {
                        Some(TypedValue::I64(v)) => Ok(*v),
                        Some(TypedValue::U64(v)) => {
                            if *v > i64::MAX as u64 {
                                Ok(i64::MAX)
                            } else {
                                Ok(*v as i64)
                            }
                        }
                        Some(TypedValue::Bool(v)) => Ok(if *v { 1 } else { 0 }),
                        _ => Ok(0i64),
                    }
                } else {
                    Ok(0i64)
                }
            })
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        kestrel
            .set("event_get_i64", event_get_i64)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // event_get_u64
        let event_ref = current_event.clone();
        let event_get_u64 = lua
            .create_function(move |_lua, (_event_handle, field_id): (u32, u32)| {
                let event_guard = event_ref.read().unwrap();
                if let Some(event) = event_guard.as_ref() {
                    let value = event.get_field(field_id);
                    match value {
                        Some(TypedValue::U64(v)) => Ok(*v),
                        Some(TypedValue::I64(v)) => {
                            if *v < 0 {
                                Ok(0)
                            } else {
                                Ok(*v as u64)
                            }
                        }
                        Some(TypedValue::Bool(v)) => Ok(if *v { 1 } else { 0 }),
                        _ => Ok(0),
                    }
                } else {
                    Ok(0)
                }
            })
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        kestrel
            .set("event_get_u64", event_get_u64)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // event_get_str
        let event_ref = current_event.clone();
        let event_get_str = lua
            .create_function(move |_lua, (_event_handle, field_id): (u32, u32)| {
                let event_guard = event_ref.read().unwrap();
                if let Some(event) = event_guard.as_ref() {
                    let value = event.get_field(field_id);
                    match value {
                        Some(TypedValue::String(s)) => Ok(s.to_string()),
                        _ => Ok(String::new()),
                    }
                } else {
                    Ok(String::new())
                }
            })
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        kestrel
            .set("event_get_str", event_get_str)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // event_get_bool
        let event_ref = current_event.clone();
        let event_get_bool = lua
            .create_function(move |_lua, (_event_handle, field_id): (u32, u32)| {
                let event_guard = event_ref.read().unwrap();
                if let Some(event) = event_guard.as_ref() {
                    let value = event.get_field(field_id);
                    match value {
                        Some(TypedValue::Bool(v)) => Ok(*v),
                        Some(TypedValue::I64(v)) => Ok(*v != 0),
                        Some(TypedValue::U64(v)) => Ok(*v != 0),
                        _ => Ok(false),
                    }
                } else {
                    Ok(false)
                }
            })
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        kestrel
            .set("event_get_bool", event_get_bool)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // re_match
        let re_cache = regex_cache.clone();
        let re_match = lua
            .create_function(move |_lua, (re_id, text): (u32, String)| {
                let cache = re_cache.read().unwrap();
                if let Some(re) = cache.get(&re_id) {
                    Ok(re.is_match(&text))
                } else {
                    Ok(false)
                }
            })
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        kestrel
            .set("re_match", re_match)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // glob_match
        let g_cache = glob_cache.clone();
        let glob_match = lua
            .create_function(move |_lua, (glob_id, text): (u32, String)| {
                let cache = g_cache.read().unwrap();
                if let Some(pattern) = cache.get(&glob_id) {
                    Ok(pattern.matches(&text))
                } else {
                    Ok(false)
                }
            })
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        kestrel
            .set("glob_match", glob_match)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // alert_emit
        let alerts_ref = current_alerts.clone();
        let alert_emit = lua
            .create_function(move |_lua, event_handle: u32| {
                let mut alerts = alerts_ref.write().unwrap();
                alerts.push(event_handle);
                Ok(0i32)
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
        let predicate = self.load_predicate_internal(lua, &rule_id, script).await?;

        let mut predicates = self.predicates.write().unwrap();
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
            rule_id: rule_id.to_string(),
            init_func,
            eval_func: eval_key,
        })
    }

    /// Evaluate an event with a predicate
    pub async fn eval(&self, rule_id: &str, event: &Event) -> Result<EvalResult, LuaRuntimeError> {
        let predicates = self.predicates.read().unwrap();
        let predicate = predicates
            .get(rule_id)
            .ok_or_else(|| LuaRuntimeError::FunctionNotFound(rule_id.to_string()))?;

        // Set current event
        *self.current_event.write().unwrap() = Some(event.clone());

        // Clear previous alerts
        self.current_alerts.write().unwrap().clear();

        let lua = &self.lua;

        // Get eval function from registry
        let eval_func = lua
            .registry_value::<Function>(&predicate.eval_func)
            .map_err(|e| LuaRuntimeError::ExecutionError(e.to_string()))?;

        // Call the predicate
        let result: std::result::Result<bool, mlua::Error> = eval_func.call(());

        // Clear current event after evaluation
        self.current_event.write().unwrap().take();

        match result {
            Ok(match_status) => Ok(EvalResult {
                matched: match_status,
                error: None,
                captured_fields: HashMap::new(),
            }),
            Err(e) => {
                // Clear current event on error too
                self.current_event.write().unwrap().take();
                Ok(EvalResult {
                    matched: false,
                    error: Some(e.to_string()),
                    captured_fields: HashMap::new(),
                })
            }
        }
    }

    /// Register a compiled regex pattern
    pub async fn register_regex(&self, pattern: &str) -> Result<RegexId, LuaRuntimeError> {
        let re =
            regex::Regex::new(pattern).map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        let id = self
            .next_regex_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut cache = self.regex_cache.write().unwrap();
        cache.insert(id, re);
        Ok(id)
    }

    /// Register a compiled glob pattern
    pub async fn register_glob(&self, pattern: &str) -> Result<GlobId, LuaRuntimeError> {
        let glob =
            glob::Pattern::new(pattern).map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        let id = self
            .next_glob_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut cache = self.glob_cache.write().unwrap();
        cache.insert(id, glob);
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let manifest = RuleManifest {
            format_version: "1.0".to_string(),
            metadata: RuleMetadata {
                rule_id: "test-001".to_string(),
                rule_name: "Test Rule".to_string(),
                rule_version: "1.0.0".to_string(),
                author: None,
                description: None,
                tags: vec![],
                severity: "Low".to_string(),
                schema_version: "1.0".to_string(),
            },
            capabilities: RuleCapabilities {
                supports_inline: true,
                requires_alert: true,
                requires_block: false,
                max_span_ms: None,
            },
        };

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

        let manifest = RuleManifest {
            format_version: "1.0".to_string(),
            metadata: RuleMetadata {
                rule_id: "test-eval".to_string(),
                rule_name: "Test Eval".to_string(),
                rule_version: "1.0.0".to_string(),
                author: None,
                description: None,
                tags: vec![],
                severity: "Low".to_string(),
                schema_version: "1.0".to_string(),
            },
            capabilities: RuleCapabilities {
                supports_inline: true,
                requires_alert: true,
                requires_block: false,
                max_span_ms: None,
            },
        };

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
}

/// Implement PredicateEvaluator trait for NFA engine integration
///
/// This allows the Lua runtime to be used as a predicate evaluator
/// for the NFA sequence engine, enabling dual runtime support (Wasm + Lua).
impl kestrel_nfa::PredicateEvaluator for LuaEngine {
    /// Evaluate a predicate against an event
    ///
    /// The predicate_id should be in the format "rule_id" where:
    /// - rule_id is the Lua predicate identifier
    fn evaluate(
        &self,
        predicate_id: &str,
        event: &kestrel_event::Event,
    ) -> kestrel_nfa::NfaResult<bool> {
        // Set the current event context
        {
            let mut current_event = self.current_event.write().unwrap();
            *current_event = Some(event.clone());
        }

        // Clear previous alerts
        {
            let mut alerts = self.current_alerts.write().unwrap();
            alerts.clear();
        }

        // Get the predicate
        let predicates = self.predicates.read().unwrap();
        let _predicate = predicates.get(predicate_id).ok_or_else(|| {
            kestrel_nfa::NfaError::PredicateError(format!("Predicate not found: {}", predicate_id))
        })?;

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
            let mut current_event = self.current_event.write().unwrap();
            *current_event = None;
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
        let predicates = self.predicates.read().unwrap();
        predicates.contains_key(predicate_id)
    }
}
