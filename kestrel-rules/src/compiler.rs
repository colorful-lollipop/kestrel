//! Rule Compiler Interface
//!
//! This module provides traits for rule compilation, separating the
//! compilation logic from the rule manager and detection engine.

use crate::{Rule, RuleDefinition, RuleMetadata};
use std::collections::HashMap;
use thiserror::Error;

/// Errors that can occur during rule compilation
#[derive(Debug, Error, Clone)]
pub enum CompilationError {
    #[error("Syntax error: {0}")]
    SyntaxError(String),

    #[error("Semantic error: {0}")]
    SemanticError(String),

    #[error("Unsupported rule type: {0}")]
    UnsupportedType(String),

    #[error("Compilation failed: {0}")]
    CompilationFailed(String),

    #[error("Validation error: {0}")]
    ValidationError(String),
}

/// Result type for compilation operations
pub type CompileResult<T> = Result<T, CompilationError>;

/// Compiled rule representation
///
/// This is an opaque type that holds the compiled form of a rule,
/// ready for execution by the detection engine.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// Original rule metadata
    pub metadata: RuleMetadata,

    /// Compiled representation (type-erased)
    pub compiled: CompiledForm,

    /// Required fields for evaluation
    pub required_fields: Vec<u32>,

    /// Required event types for evaluation
    pub required_event_types: Vec<u16>,
}

/// Compiled form of a rule
#[derive(Debug, Clone)]
pub enum CompiledForm {
    /// No compilation needed (e.g., native predicates)
    Native,

    /// Wasm binary
    Wasm(Vec<u8>),

    /// Lua script
    Lua(String),

    /// Intermediate representation (for EQL)
    Ir(crate::IrRule),
}

/// Trait for rule compilers
///
/// Implement this trait to add support for new rule types.
/// The compiler converts a Rule into a CompiledRule.
pub trait RuleCompiler: Send + Sync {
    /// Check if this compiler can handle the given rule definition
    fn can_compile(&self, definition: &RuleDefinition) -> bool;

    /// Compile a rule
    ///
    /// # Arguments
    /// * `rule` - The rule to compile
    ///
    /// # Returns
    /// The compiled rule, or an error if compilation fails
    fn compile(&self, rule: &Rule) -> CompileResult<CompiledRule>;

    /// Validate a rule without compiling it
    ///
    /// # Arguments
    /// * `rule` - The rule to validate
    ///
    /// # Returns
    /// Ok if valid, or an error describing the problem
    fn validate(&self, rule: &Rule) -> CompileResult<()>;

    /// Get the compiler name
    fn name(&self) -> &str;

    /// Get the compiler version
    fn version(&self) -> &str;
}

/// Rule compilation manager
///
/// Manages multiple compilers and routes rules to the appropriate one.
pub struct CompilationManager {
    /// Registered compilers
    compilers: Vec<Box<dyn RuleCompiler>>,

    /// Cache of compiled rules
    cache: HashMap<String, CompiledRule>,

    /// Enable caching
    enable_cache: bool,
}

impl CompilationManager {
    /// Create a new compilation manager
    pub fn new() -> Self {
        Self {
            compilers: Vec::new(),
            cache: HashMap::new(),
            enable_cache: true,
        }
    }

    /// Create a new compilation manager without caching
    pub fn without_cache() -> Self {
        Self {
            compilers: Vec::new(),
            cache: HashMap::new(),
            enable_cache: false,
        }
    }

    /// Register a compiler
    pub fn register_compiler(&mut self, compiler: Box<dyn RuleCompiler>) {
        tracing::info!(name = %compiler.name(), version = %compiler.version(), "Registering compiler");
        self.compilers.push(compiler);
    }

    /// Compile a rule using the appropriate compiler
    ///
    /// # Arguments
    /// * `rule` - The rule to compile
    ///
    /// # Returns
    /// The compiled rule, or an error if no compiler can handle it
    pub fn compile(&mut self, rule: &Rule) -> CompileResult<CompiledRule> {
        let rule_id = &rule.metadata.id;

        // Check cache first
        if self.enable_cache {
            if let Some(compiled) = self.cache.get(rule_id) {
                tracing::debug!(rule_id = %rule_id, "Using cached compiled rule");
                return Ok(compiled.clone());
            }
        }

        // Find appropriate compiler
        let compiler = self
            .compilers
            .iter()
            .find(|c| c.can_compile(&rule.definition))
            .ok_or_else(|| {
                CompilationError::UnsupportedType(format!("{:?}", rule.definition))
            })?;

        // Compile the rule
        tracing::debug!(rule_id = %rule_id, compiler = %compiler.name(), "Compiling rule");
        let compiled = compiler.compile(rule)?;

        // Cache the result
        if self.enable_cache {
            self.cache.insert(rule_id.clone(), compiled.clone());
        }

        Ok(compiled)
    }

    /// Validate a rule without compiling
    pub fn validate(&self, rule: &Rule) -> CompileResult<()> {
        let compiler = self
            .compilers
            .iter()
            .find(|c| c.can_compile(&rule.definition))
            .ok_or_else(|| {
                CompilationError::UnsupportedType(format!("{:?}", rule.definition))
            })?;

        compiler.validate(rule)
    }

    /// Check if a rule type is supported
    pub fn is_supported(&self, definition: &RuleDefinition) -> bool {
        self.compilers.iter().any(|c| c.can_compile(definition))
    }

    /// List supported compiler names
    pub fn list_compilers(&self) -> Vec<(&str, &str)> {
        self.compilers
            .iter()
            .map(|c| (c.name(), c.version()))
            .collect()
    }

    /// Clear the compilation cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
        tracing::info!("Compilation cache cleared");
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> CacheStats {
        CacheStats {
            size: self.cache.len(),
            enabled: self.enable_cache,
        }
    }

    /// Invalidate a specific rule in the cache
    pub fn invalidate(&mut self, rule_id: &str) {
        self.cache.remove(rule_id);
        tracing::debug!(rule_id = %rule_id, "Invalidated cached rule");
    }
}

impl Default for CompilationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache statistics
#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    /// Number of entries in cache
    pub size: usize,
    /// Whether caching is enabled
    pub enabled: bool,
}

/// Intermediate representation for rules
#[derive(Debug, Clone)]
pub struct IrRule {
    /// Rule metadata
    pub metadata: RuleMetadata,
    /// Rule type
    pub rule_type: IrRuleType,
    /// Required fields
    pub required_fields: Vec<u32>,
}

/// Rule type in IR
#[derive(Debug, Clone)]
pub enum IrRuleType {
    /// Single event rule
    SingleEvent { predicate: IrPredicate },
    /// Sequence rule
    Sequence { steps: Vec<IrSequenceStep> },
}

/// Predicate in IR
#[derive(Debug, Clone)]
pub struct IrPredicate {
    /// Predicate ID
    pub id: String,
    /// Event type to match
    pub event_type: String,
    /// Condition expression (simplified)
    pub condition: IrCondition,
}

/// Sequence step in IR
#[derive(Debug, Clone)]
pub struct IrSequenceStep {
    /// Step ID
    pub id: String,
    /// Predicate for this step
    pub predicate: IrPredicate,
    /// Optional transition condition from previous step
    pub transition: Option<IrCondition>,
}

/// Condition expression in IR
#[derive(Debug, Clone)]
pub enum IrCondition {
    /// Always true
    Always,
    /// Field equals value
    FieldEq { field: String, value: String },
    /// Field contains substring
    FieldContains { field: String, substring: String },
    /// Field matches regex
    FieldRegex { field: String, pattern: String },
    /// Logical AND
    And(Box<IrCondition>, Box<IrCondition>),
    /// Logical OR
    Or(Box<IrCondition>, Box<IrCondition>),
    /// Logical NOT
    Not(Box<IrCondition>),
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCompiler {
        name: String,
        handles: Vec<String>,
    }

    impl RuleCompiler for MockCompiler {
        fn can_compile(&self, definition: &RuleDefinition) -> bool {
            match definition {
                RuleDefinition::Eql(_) => self.handles.contains(&"eql".to_string()),
                RuleDefinition::Wasm(_) => self.handles.contains(&"wasm".to_string()),
                RuleDefinition::Lua(_) => self.handles.contains(&"lua".to_string()),
            }
        }

        fn compile(&self, rule: &Rule) -> CompileResult<CompiledRule> {
            Ok(CompiledRule {
                metadata: rule.metadata.clone(),
                compiled: CompiledForm::Native,
                required_fields: vec![],
                required_event_types: vec![],
            })
        }

        fn validate(&self, _rule: &Rule) -> CompileResult<()> {
            Ok(())
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn version(&self) -> &str {
            "1.0.0"
        }
    }

    #[test]
    fn test_compilation_manager() {
        let mut manager = CompilationManager::new();

        // Register compilers
        manager.register_compiler(Box::new(MockCompiler {
            name: "eql-compiler".to_string(),
            handles: vec!["eql".to_string()],
        }));

        manager.register_compiler(Box::new(MockCompiler {
            name: "wasm-compiler".to_string(),
            handles: vec!["wasm".to_string()],
        }));

        // Check supported types
        assert!(manager.is_supported(&RuleDefinition::Eql("test".to_string())));
        assert!(!manager.is_supported(&RuleDefinition::Lua("test".to_string())));

        // List compilers
        let compilers = manager.list_compilers();
        assert_eq!(compilers.len(), 2);

        // Test compilation
        let rule = Rule {
            metadata: RuleMetadata {
                id: "test-001".to_string(),
                name: "Test Rule".to_string(),
                description: None,
                version: "1.0.0".to_string(),
                author: None,
                tags: vec![],
                severity: crate::Severity::Medium,
            },
            definition: RuleDefinition::Eql("process.name == \"bash\"".to_string()),
        };

        let compiled = manager.compile(&rule);
        assert!(compiled.is_ok());

        // Cache should have the rule
        let stats = manager.cache_stats();
        assert_eq!(stats.size, 1);

        // Second compile should use cache
        let compiled2 = manager.compile(&rule);
        assert!(compiled2.is_ok());
    }

    #[test]
    fn test_cache_stats() {
        let manager = CompilationManager::new();
        let stats = manager.cache_stats();
        assert_eq!(stats.size, 0);
        assert!(stats.enabled);
    }
}
