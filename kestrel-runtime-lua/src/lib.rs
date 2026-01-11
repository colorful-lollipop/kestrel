//! Kestrel Lua Runtime
//!
//! This module provides LuaJIT runtime support for predicate execution using mlua.
//! Implements Host API v1 via FFI, consistent with Wasm runtime.

use anyhow::Result;
use mlua::{Function, Lua, RegistryKey, Value as LuaValue};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
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
    predicates: Arc<RwLock<HashMap<String, LuaPredicate>>>,
    regex_cache: Arc<RwLock<HashMap<RegexId, regex::Regex>>>,
    glob_cache: Arc<RwLock<HashMap<GlobId, glob::Pattern>>>,
    next_regex_id: Arc<std::sync::atomic::AtomicU32>,
    next_glob_id: Arc<std::sync::atomic::AtomicU32>,
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

        Ok(Self {
            lua: Arc::new(lua),
            config,
            schema,
            predicates: Arc::new(RwLock::new(HashMap::new())),
            regex_cache: Arc::new(RwLock::new(HashMap::new())),
            glob_cache: Arc::new(RwLock::new(HashMap::new())),
            next_regex_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            next_glob_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
        })
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

        let mut predicates = self.predicates.write().await;
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
    pub async fn eval(&self, rule_id: &str, _event: &Event) -> Result<EvalResult, LuaRuntimeError> {
        let predicates = self.predicates.read().await;
        let predicate = predicates
            .get(rule_id)
            .ok_or_else(|| LuaRuntimeError::FunctionNotFound(rule_id.to_string()))?;

        let lua = &self.lua;

        // Get eval function from registry
        let eval_func = lua
            .registry_value::<Function>(&predicate.eval_func)
            .map_err(|e| LuaRuntimeError::ExecutionError(e.to_string()))?;

        // Call the predicate (for now, pass no event, just return true)
        let result: std::result::Result<bool, mlua::Error> = eval_func.call(());

        match result {
            Ok(match_status) => Ok(EvalResult {
                matched: match_status,
                error: None,
                captured_fields: HashMap::new(),
            }),
            Err(e) => Ok(EvalResult {
                matched: false,
                error: Some(e.to_string()),
                captured_fields: HashMap::new(),
            }),
        }
    }

    /// Register a compiled regex pattern
    pub async fn register_regex(&self, pattern: &str) -> Result<RegexId, LuaRuntimeError> {
        let re =
            regex::Regex::new(pattern).map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        let id = self
            .next_regex_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut cache = self.regex_cache.write().await;
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
        let mut cache = self.glob_cache.write().await;
        cache.insert(id, glob);
        Ok(id)
    }

    /// Register Host API v1 functions for Lua
    pub fn register_host_api(&self) -> Result<(), LuaRuntimeError> {
        let lua = &self.lua;

        // Create kestrel table for Host API
        let kestrel = lua
            .create_table()
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // event_get_i64
        let event_get_i64 = lua
            .create_function(move |_lua, (_event, _field_id): (LuaValue, u32)| {
                // TODO: Implement actual field reading
                Ok(0i64)
            })
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        kestrel
            .set("event_get_i64", event_get_i64)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // event_get_u64
        let event_get_u64 = lua
            .create_function(move |_lua, (_event, _field_id): (LuaValue, u32)| {
                // TODO: Implement actual field reading
                Ok(0u64)
            })
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        kestrel
            .set("event_get_u64", event_get_u64)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // event_get_str
        let event_get_str = lua
            .create_function(move |_lua, (_event, _field_id): (LuaValue, u32)| {
                // TODO: Implement actual field reading
                Ok("")
            })
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        kestrel
            .set("event_get_str", event_get_str)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // re_match
        let _regex_cache = self.regex_cache.clone();
        let re_match = lua
            .create_function(move |_lua, (_re_id, _text): (u32, String)| {
                // TODO: Implement actual regex matching
                Ok(false)
            })
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        kestrel
            .set("re_match", re_match)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // glob_match
        let _glob_cache = self.glob_cache.clone();
        let glob_match = lua
            .create_function(move |_lua, (_glob_id, _text): (u32, String)| {
                // TODO: Implement actual glob matching
                Ok(false)
            })
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        kestrel
            .set("glob_match", glob_match)
            .map_err(|e| LuaRuntimeError::LoadError(e.to_string()))?;

        // alert_emit
        let alert_emit = lua
            .create_function(move |_lua, _event: LuaValue| {
                // TODO: Implement actual alert emission
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

        Ok(())
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

        // Register Host API first
        engine.register_host_api().unwrap();

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
