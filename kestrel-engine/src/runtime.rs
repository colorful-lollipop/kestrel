//! Runtime abstraction layer
//!
//! This module provides a unified trait abstraction for different rule runtimes
//! (Wasm, Lua, etc.), allowing the engine to work with any runtime implementation
//! without direct dependency on specific runtime crates.

use kestrel_event::Event;
use kestrel_schema::{
    FieldId, RuleCapabilities, RuleManifest, RuleMetadata,
    RuntimeCapabilities as SchemaRuntimeCapabilities, RuntimeType as SchemaRuntimeType, SchemaRegistry,
};
use std::sync::Arc;
use thiserror::Error;

/// Unified runtime error type
#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("Compilation error: {0}")]
    CompilationError(String),

    #[error("Execution error: {0}")]
    ExecutionError(String),

    #[error("Runtime not available: {0}")]
    NotAvailable(String),

    #[error("Predicate not found: {0}")]
    PredicateNotFound(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Result type for runtime operations
pub type RuntimeResult<T> = Result<T, RuntimeError>;

/// Evaluation result from a runtime
/// Re-export from kestrel-schema for convenience
pub use kestrel_schema::EvalResult;

/// Re-export runtime types from kestrel-schema
pub use kestrel_schema::{RuntimeCapabilities, RuntimeType};

// Type aliases for internal use
type _RuntimeCapabilities = SchemaRuntimeCapabilities;
type _RuntimeType = SchemaRuntimeType;

/// Trait for rule runtimes (Wasm, Lua, etc.)
///
/// This trait abstracts the differences between various runtime implementations,
/// allowing the detection engine to work with any runtime without knowing
/// the specific implementation details.
#[async_trait::async_trait]
pub trait Runtime: Send + Sync {
    /// Evaluate a predicate against an event
    ///
    /// # Arguments
    /// * `predicate_id` - Unique identifier for the predicate
    /// * `event` - The event to evaluate against
    ///
    /// # Returns
    /// Evaluation result indicating whether the predicate matched
    async fn evaluate(&self, predicate_id: &str, event: &Event) -> RuntimeResult<EvalResult>;

    /// Evaluate an ad-hoc predicate (for single-event rules without pre-compilation)
    ///
    /// # Arguments
    /// * `bytes` - The predicate bytes (Wasm binary, Lua script, etc.)
    /// * `event` - The event to evaluate against
    ///
    /// # Returns
    /// Evaluation result
    async fn evaluate_adhoc(&self, bytes: &[u8], event: &Event) -> RuntimeResult<EvalResult>;

    /// Get the required fields for a predicate
    ///
    /// # Arguments
    /// * `predicate_id` - Unique identifier for the predicate
    ///
    /// # Returns
    /// List of field IDs required by the predicate
    fn required_fields(&self, predicate_id: &str) -> RuntimeResult<Vec<FieldId>>;

    /// Check if a predicate is loaded in this runtime
    ///
    /// # Arguments
    /// * `predicate_id` - Unique identifier for the predicate
    fn has_predicate(&self, predicate_id: &str) -> bool;

    /// Load a compiled predicate into the runtime
    ///
    /// # Arguments
    /// * `predicate_id` - Unique identifier for the predicate
    /// * `bytes` - The compiled predicate bytes
    async fn load_predicate(&self, predicate_id: &str, bytes: &[u8]) -> RuntimeResult<()>;

    /// Unload a predicate from the runtime
    ///
    /// # Arguments
    /// * `predicate_id` - Unique identifier for the predicate
    fn unload_predicate(&self, predicate_id: &str);

    /// Get the runtime type
    fn runtime_type(&self) -> RuntimeType;

    /// Get runtime capabilities
    fn capabilities(&self) -> RuntimeCapabilities;
}

/// Runtime manager that holds multiple runtimes
pub struct RuntimeManager {
    /// Available runtimes by type
    runtimes: std::collections::HashMap<RuntimeType, Arc<dyn Runtime>>,
    /// Schema registry
    schema: Arc<SchemaRegistry>,
}

impl RuntimeManager {
    /// Create a new runtime manager
    pub fn new(schema: Arc<SchemaRegistry>) -> Self {
        Self {
            runtimes: std::collections::HashMap::new(),
            schema,
        }
    }

    /// Register a runtime
    pub fn register_runtime(&mut self, runtime: Arc<dyn Runtime>) {
        let runtime_type = runtime.runtime_type();
        tracing::info!(runtime_type = %runtime_type, "Registering runtime");
        self.runtimes.insert(runtime_type, runtime);
    }

    /// Get a runtime by type
    pub fn get_runtime(&self, runtime_type: RuntimeType) -> Option<Arc<dyn Runtime>> {
        self.runtimes.get(&runtime_type).cloned()
    }

    /// Check if a runtime is available
    pub fn has_runtime(&self, runtime_type: RuntimeType) -> bool {
        self.runtimes.contains_key(&runtime_type)
    }

    /// Get the best available runtime for a given task
    ///
    /// Currently returns Wasm if available, otherwise Lua, otherwise Native
    pub fn preferred_runtime(&self) -> Option<Arc<dyn Runtime>> {
        // Priority: Wasm > Lua > Native
        self.get_runtime(RuntimeType::Wasm)
            .or_else(|| self.get_runtime(RuntimeType::Lua))
            .or_else(|| self.get_runtime(RuntimeType::Native))
    }

    /// Get all available runtime types
    pub fn available_runtimes(&self) -> Vec<RuntimeType> {
        self.runtimes.keys().copied().collect()
    }

    /// Evaluate a predicate using the best available runtime
    pub async fn evaluate(
        &self,
        predicate_id: &str,
        event: &Event,
    ) -> RuntimeResult<EvalResult> {
        // Try each runtime in priority order
        for runtime_type in [RuntimeType::Wasm, RuntimeType::Lua, RuntimeType::Native] {
            if let Some(runtime) = self.get_runtime(runtime_type) {
                if runtime.has_predicate(predicate_id) {
                    return runtime.evaluate(predicate_id, event).await;
                }
            }
        }

        Err(RuntimeError::PredicateNotFound(predicate_id.to_string()))
    }
}

/// Adapter for WasmEngine to implement Runtime trait
#[cfg(feature = "wasm")]
pub struct WasmRuntimeAdapter {
    inner: Arc<kestrel_runtime_wasm::WasmEngine>,
}

#[cfg(feature = "wasm")]
impl WasmRuntimeAdapter {
    /// Create a new Wasm runtime adapter
    pub fn new(engine: Arc<kestrel_runtime_wasm::WasmEngine>) -> Self {
        Self { inner: engine }
    }
}

#[cfg(feature = "wasm")]
#[async_trait::async_trait]
impl Runtime for WasmRuntimeAdapter {
    async fn evaluate(&self, predicate_id: &str, event: &Event) -> RuntimeResult<EvalResult> {
        // For now, use ad-hoc evaluation as the primary method
        // In production, you'd want to check if the module is loaded first
        Err(RuntimeError::NotAvailable(
            "Direct predicate evaluation not implemented for Wasm adapter".to_string(),
        ))
    }

    async fn evaluate_adhoc(&self, bytes: &[u8], event: &Event) -> RuntimeResult<EvalResult> {
        match self.inner.eval_adhoc_predicate(bytes, event).await {
            Ok(matched) => Ok(EvalResult::matched()),
            Err(e) => Err(RuntimeError::ExecutionError(e.to_string())),
        }
    }

    fn required_fields(&self, _predicate_id: &str) -> RuntimeResult<Vec<FieldId>> {
        // Wasm runtime doesn't expose this directly yet
        Ok(vec![])
    }

    fn has_predicate(&self, predicate_id: &str) -> bool {
        // Check if module exists in the engine
        // This is a simplified check - in production, you'd want a proper API
        true
    }

    async fn load_predicate(&self, predicate_id: &str, bytes: &[u8]) -> RuntimeResult<()> {
        let manifest = RuleManifest::new(
            RuleMetadata::new(predicate_id, predicate_id)
                .with_severity("medium")
        ).with_capabilities(RuleCapabilities {
            supports_inline: false,
            requires_alert: true,
            requires_block: false,
            max_span_ms: None,
        });
        
        self.inner
            .load_module(manifest, bytes.to_vec())
            .await
            .map_err(|e| RuntimeError::CompilationError(e.to_string()))?;
        
        Ok(())
    }

    fn unload_predicate(&self, _predicate_id: &str) {
        // No-op for now - WasmEngine doesn't have unload yet
    }

    fn runtime_type(&self) -> RuntimeType {
        RuntimeType::Wasm
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        self.inner.capabilities()
    }
}

/// Adapter for LuaEngine to implement Runtime trait
#[cfg(feature = "lua")]
pub struct LuaRuntimeAdapter {
    inner: Arc<kestrel_runtime_lua::LuaEngine>,
}

#[cfg(feature = "lua")]
impl LuaRuntimeAdapter {
    /// Create a new Lua runtime adapter
    pub fn new(engine: Arc<kestrel_runtime_lua::LuaEngine>) -> Self {
        Self { inner: engine }
    }
}

#[cfg(feature = "lua")]
#[async_trait::async_trait]
impl Runtime for LuaRuntimeAdapter {
    async fn evaluate(&self, predicate_id: &str, event: &Event) -> RuntimeResult<EvalResult> {
        match self.inner.eval(predicate_id, event).await {
            Ok(result) => Ok(result),
            Err(e) => Err(RuntimeError::ExecutionError(e.to_string())),
        }
    }

    async fn evaluate_adhoc(&self, _bytes: &[u8], _event: &Event) -> RuntimeResult<EvalResult> {
        // Lua runtime doesn't support ad-hoc evaluation yet
        Err(RuntimeError::NotAvailable(
            "Lua ad-hoc evaluation not supported".to_string(),
        ))
    }

    fn required_fields(&self, _predicate_id: &str) -> RuntimeResult<Vec<FieldId>> {
        // Lua runtime doesn't expose this directly yet
        Ok(vec![])
    }

    fn has_predicate(&self, predicate_id: &str) -> bool {
        self.inner.has_predicate(predicate_id)
    }

    async fn load_predicate(&self, predicate_id: &str, bytes: &[u8]) -> RuntimeResult<()> {
        let script = String::from_utf8(bytes.to_vec())
            .map_err(|e| RuntimeError::CompilationError(e.to_string()))?;
        
        let manifest = RuleManifest::new(
            RuleMetadata::new(predicate_id, predicate_id)
                .with_severity("medium")
        ).with_capabilities(RuleCapabilities {
            supports_inline: false,
            requires_alert: true,
            requires_block: false,
            max_span_ms: None,
        });
        
        self.inner
            .load_predicate(manifest, script)
            .await
            .map_err(|e| RuntimeError::CompilationError(e.to_string()))?;
        
        Ok(())
    }

    fn unload_predicate(&self, predicate_id: &str) {
        self.inner.unload_predicate(predicate_id);
    }

    fn runtime_type(&self) -> RuntimeType {
        RuntimeType::Lua
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        self.inner.capabilities()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockRuntime {
        runtime_type: RuntimeType,
    }

    #[async_trait::async_trait]
    impl Runtime for MockRuntime {
        async fn evaluate(&self, _predicate_id: &str, _event: &Event) -> RuntimeResult<EvalResult> {
            Ok(EvalResult::matched())
        }

        async fn evaluate_adhoc(&self, _bytes: &[u8], _event: &Event) -> RuntimeResult<EvalResult> {
            Ok(EvalResult::matched())
        }

        fn required_fields(&self, _predicate_id: &str) -> RuntimeResult<Vec<FieldId>> {
            Ok(vec![])
        }

        fn has_predicate(&self, _predicate_id: &str) -> bool {
            true
        }

        async fn load_predicate(&self, _predicate_id: &str, _bytes: &[u8]) -> RuntimeResult<()> {
            Ok(())
        }

        fn unload_predicate(&self, _predicate_id: &str) {}

        fn runtime_type(&self) -> RuntimeType {
            self.runtime_type
        }

        fn capabilities(&self) -> RuntimeCapabilities {
            RuntimeCapabilities::default()
        }
    }

    #[test]
    fn test_runtime_manager() {
        let schema = Arc::new(SchemaRegistry::new());
        let mut manager = RuntimeManager::new(schema);

        // Register mock runtimes
        manager.register_runtime(Arc::new(MockRuntime {
            runtime_type: RuntimeType::Wasm,
        }));
        manager.register_runtime(Arc::new(MockRuntime {
            runtime_type: RuntimeType::Lua,
        }));

        // Check availability
        assert!(manager.has_runtime(RuntimeType::Wasm));
        assert!(manager.has_runtime(RuntimeType::Lua));
        assert!(!manager.has_runtime(RuntimeType::Native));

        // Check preferred runtime
        let preferred = manager.preferred_runtime();
        assert!(preferred.is_some());
        assert_eq!(preferred.unwrap().runtime_type(), RuntimeType::Wasm);
    }

    #[test]
    fn test_eval_result() {
        let matched = EvalResult::matched();
        assert!(matched.matched);
        assert!(matched.error.is_none());

        let not_matched = EvalResult::not_matched();
        assert!(!not_matched.matched);

        let error = EvalResult::error("test error");
        assert!(!error.matched);
        assert_eq!(error.error, Some("test error".to_string()));
    }

    #[test]
    fn test_runtime_type_display() {
        assert_eq!(RuntimeType::Wasm.to_string(), "wasm");
        assert_eq!(RuntimeType::Lua.to_string(), "lua");
        assert_eq!(RuntimeType::Native.to_string(), "native");
    }

    #[test]
    fn test_runtime_capabilities_default() {
        let caps = RuntimeCapabilities::default();
        assert!(caps.regex);
        assert!(caps.glob);
        assert!(caps.string_ops);
        assert!(caps.math_ops);
        assert_eq!(caps.max_memory_mb, 128);
        assert_eq!(caps.max_execution_time_ms, 100);
    }
}
