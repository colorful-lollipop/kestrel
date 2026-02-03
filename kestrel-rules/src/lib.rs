//! Kestrel Rule Management
//!
//! This module handles rule loading, hot-reloading, and lifecycle management.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, error, info, warn};

pub mod compiler;
pub use compiler::{
    CompileResult, CompiledForm, CompiledRule, CompilationError, CompilationManager,
    IrCondition, IrPredicate, IrRule, IrRuleType, IrSequenceStep, RuleCompiler,
};

/// Rule manager configuration
#[derive(Debug, Clone)]
pub struct RuleManagerConfig {
    /// Directory to load rules from
    pub rules_dir: PathBuf,

    /// Enable hot-reloading
    pub watch_enabled: bool,

    /// Maximum concurrent rule loads
    pub max_concurrent_loads: usize,
}

impl Default for RuleManagerConfig {
    fn default() -> Self {
        Self {
            rules_dir: PathBuf::from("./rules"),
            watch_enabled: true,
            max_concurrent_loads: 4,
        }
    }
}

/// Rule metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    /// Unique rule identifier
    pub id: String,

    /// Rule name
    pub name: String,

    /// Rule description
    pub description: Option<String>,

    /// Rule version
    pub version: String,

    /// Rule author
    pub author: Option<String>,

    /// Tags for categorization
    pub tags: Vec<String>,

    /// Severity level
    pub severity: Severity,
}

// Re-export Severity from kestrel-schema for backward compatibility
pub use kestrel_schema::Severity;

/// Rule severity levels (alias for kestrel_schema::Severity)
pub type RuleSeverity = kestrel_schema::Severity;

/// Loaded rule
#[derive(Debug, Clone)]
pub struct Rule {
    /// Rule metadata
    pub metadata: RuleMetadata,

    /// Rule definition (could be EQL, Wasm module, etc.)
    pub definition: RuleDefinition,
}

/// Rule definition
#[derive(Debug, Clone)]
pub enum RuleDefinition {
    /// EQL query
    Eql(String),

    /// Compiled Wasm module
    Wasm(Vec<u8>),

    /// Lua script
    Lua(String),
}

/// Rule manager
pub struct RuleManager {
    config: RuleManagerConfig,
    rules: Arc<RwLock<HashMap<String, Rule>>>,
    load_semaphore: Arc<Semaphore>,
}

impl RuleManager {
    /// Create a new rule manager
    pub fn new(config: RuleManagerConfig) -> Self {
        Self {
            config,
            rules: Arc::new(RwLock::new(HashMap::new())),
            load_semaphore: Arc::new(Semaphore::new(4)),
        }
    }

    /// Load all rules from the configured directory
    pub async fn load_all(&self) -> Result<LoadStats, RuleManagerError> {
        info!(dir = %self.config.rules_dir.display(), "Loading rules");

        let mut stats = LoadStats::default();

        if !self.config.rules_dir.exists() {
            warn!(
                "Rules directory does not exist: {}",
                self.config.rules_dir.display()
            );
            return Ok(stats);
        }

        let entries = std::fs::read_dir(&self.config.rules_dir)
            .map_err(|e| RuleManagerError::IoError(self.config.rules_dir.clone(), e))?;

        for entry in entries {
            let entry =
                entry.map_err(|e| RuleManagerError::IoError(self.config.rules_dir.clone(), e))?;
            let path = entry.path();

            if path.is_dir() {
                continue;
            }

            match self.load_rule_file(&path).await {
                Ok(_) => {
                    stats.loaded += 1;
                    debug!(path = %path.display(), "Loaded rule");
                }
                Err(e) => {
                    stats.failed += 1;
                    error!(path = %path.display(), error = %e, "Failed to load rule");
                }
            }
        }

        info!(
            loaded = stats.loaded,
            failed = stats.failed,
            "Rule loading complete"
        );

        Ok(stats)
    }

    /// Load a single rule file
    async fn load_rule_file(&self, path: &Path) -> Result<(), RuleManagerError> {
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .ok_or_else(|| RuleManagerError::InvalidRuleFormat(path.to_path_buf()))?;

        match extension {
            "json" => self.load_json_rule(path).await,
            "yaml" | "yml" => self.load_yaml_rule(path).await,
            "eql" => self.load_eql_rule(path).await,
            _ => Err(RuleManagerError::InvalidRuleFormat(path.to_path_buf())),
        }
    }

    /// Load a JSON rule file
    async fn load_json_rule(&self, path: &Path) -> Result<(), RuleManagerError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| RuleManagerError::IoError(path.to_path_buf(), e))?;

        let metadata: RuleMetadata = serde_json::from_str(&content)
            .map_err(|e| RuleManagerError::ParseError(path.to_path_buf(), e.to_string()))?;

        let rule = Rule {
            metadata: metadata.clone(),
            definition: RuleDefinition::Eql(content),
        };

        let mut rules = self.rules.write().await;
        rules.insert(metadata.id.clone(), rule);

        Ok(())
    }

    /// Load a YAML rule file
    async fn load_yaml_rule(&self, path: &Path) -> Result<(), RuleManagerError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| RuleManagerError::IoError(path.to_path_buf(), e))?;

        let metadata: RuleMetadata = serde_yaml::from_str(&content)
            .map_err(|e| RuleManagerError::ParseError(path.to_path_buf(), e.to_string()))?;

        let rule = Rule {
            metadata: metadata.clone(),
            definition: RuleDefinition::Eql(content),
        };

        let mut rules = self.rules.write().await;
        rules.insert(metadata.id.clone(), rule);

        Ok(())
    }

    /// Load an EQL rule file
    async fn load_eql_rule(&self, path: &Path) -> Result<(), RuleManagerError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| RuleManagerError::IoError(path.to_path_buf(), e))?;

        // Extract rule ID from filename
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let metadata = RuleMetadata {
            id: id.clone(),
            name: id.clone(),
            description: None,
            version: "1.0.0".to_string(),
            author: None,
            tags: vec![],
            severity: Severity::Medium,
        };

        let rule = Rule {
            metadata,
            definition: RuleDefinition::Eql(content),
        };

        let mut rules = self.rules.write().await;
        rules.insert(id, rule);

        Ok(())
    }

    /// Get a rule by ID
    pub async fn get_rule(&self, id: &str) -> Option<Rule> {
        self.rules.read().await.get(id).cloned()
    }

    /// List all rule IDs
    pub async fn list_rules(&self) -> Vec<String> {
        self.rules.read().await.keys().cloned().collect()
    }

    /// Get rule count
    pub async fn rule_count(&self) -> usize {
        self.rules.read().await.len()
    }
}

/// Rule loading statistics
#[derive(Debug, Default, Clone)]
pub struct LoadStats {
    pub loaded: usize,
    pub failed: usize,
}

/// Rule manager errors
#[derive(Debug, Error)]
pub enum RuleManagerError {
    #[error("IO error accessing {0:?}: {1}")]
    IoError(PathBuf, std::io::Error),

    #[error("Invalid rule format: {0:?}")]
    InvalidRuleFormat(PathBuf),

    #[error("Parse error in {0:?}: {1}")]
    ParseError(PathBuf, String),

    #[error("Rule load limit exceeded")]
    LoadLimitExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rule_manager_create() {
        let config = RuleManagerConfig::default();
        let manager = RuleManager::new(config);
        assert_eq!(manager.rule_count().await, 0);
    }

    #[tokio::test]
    async fn test_rule_load_json() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rule_file = temp_dir.path().join("test_rule.json");

        let rule_json = r#"{
            "id": "test-001",
            "name": "Test Rule",
            "description": "A test rule",
            "version": "1.0.0",
            "author": "Test Author",
            "tags": ["test"],
            "severity": "High"
        }"#;

        std::fs::write(&rule_file, rule_json).unwrap();

        let config = RuleManagerConfig {
            rules_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let manager = RuleManager::new(config);
        let stats = manager.load_all().await.unwrap();

        assert_eq!(stats.loaded, 1);
        assert_eq!(stats.failed, 0);

        let rule = manager.get_rule("test-001").await;
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().metadata.name, "Test Rule");
    }
}
