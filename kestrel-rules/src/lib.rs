//! Kestrel Rule Management
//!
//! This module handles rule loading, hot-reloading, and lifecycle management.

use anyhow::Result;
use kestrel_schema::RuleManifest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, error, info, warn};

pub mod compiler;
pub mod hot_reload;
pub use compiler::{
    CompilationError, CompilationManager, CompileResult, CompiledForm, CompiledRule, IrCondition,
    IrPredicate, IrRule, IrRuleType, IrSequenceStep, RuleCompiler,
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
        let max_concurrent_loads = config.max_concurrent_loads.max(1);
        Self {
            config,
            rules: Arc::new(RwLock::new(HashMap::new())),
            load_semaphore: Arc::new(Semaphore::new(max_concurrent_loads)),
        }
    }

    /// Load all rules from the configured directory
    pub async fn load_all(&self) -> Result<LoadStats, RuleManagerError> {
        info!(dir = %self.config.rules_dir.display(), "Loading rules");

        let mut stats = LoadStats::default();

        {
            let mut rules = self.rules.write().await;
            rules.clear();
        }

        if !self.config.rules_dir.exists() {
            warn!("Rules directory does not exist: {}", self.config.rules_dir.display());
            return Ok(stats);
        }

        let entries = std::fs::read_dir(&self.config.rules_dir)
            .map_err(|e| RuleManagerError::IoError(self.config.rules_dir.clone(), e))?;

        for entry in entries {
            let entry =
                entry.map_err(|e| RuleManagerError::IoError(self.config.rules_dir.clone(), e))?;
            let path = entry.path();

            let load_result = if path.is_dir() {
                self.load_rule_package(&path).await
            } else {
                self.load_rule_file(&path).await
            };

            match load_result {
                Ok(_) => {
                    stats.loaded += 1;
                    debug!(path = %path.display(), "Loaded rule");
                },
                Err(e) => {
                    stats.failed += 1;
                    error!(path = %path.display(), error = %e, "Failed to load rule");
                },
            }
        }

        info!(loaded = stats.loaded, failed = stats.failed, "Rule loading complete");

        Ok(stats)
    }

    /// Load a single rule file
    async fn load_rule_file(&self, path: &Path) -> Result<(), RuleManagerError> {
        let _permit = self
            .load_semaphore
            .acquire()
            .await
            .map_err(|_| RuleManagerError::LoadLimitExceeded)?;

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

    /// Load a directory-based rule package.
    async fn load_rule_package(&self, path: &Path) -> Result<(), RuleManagerError> {
        let _permit = self
            .load_semaphore
            .acquire()
            .await
            .map_err(|_| RuleManagerError::LoadLimitExceeded)?;

        let manifest_path = path.join("manifest.json");
        if !manifest_path.exists() {
            return Err(RuleManagerError::InvalidRuleFormat(path.to_path_buf()));
        }

        let manifest_content = std::fs::read_to_string(&manifest_path)
            .map_err(|e| RuleManagerError::IoError(manifest_path.clone(), e))?;
        let manifest: RuleManifest = serde_json::from_str(&manifest_content)
            .map_err(|e| RuleManagerError::ParseError(manifest_path.clone(), e.to_string()))?;

        let metadata = RuleMetadata::try_from(manifest)
            .map_err(|e| RuleManagerError::ParseError(manifest_path.clone(), e))?;

        let definition = self.load_rule_package_definition(path)?;
        self.insert_rule(Rule {
            metadata,
            definition,
        })
        .await
    }

    fn load_rule_package_definition(
        &self,
        path: &Path,
    ) -> Result<RuleDefinition, RuleManagerError> {
        let eql_path = path.join("rule.eql");
        if eql_path.exists() {
            let content = std::fs::read_to_string(&eql_path)
                .map_err(|e| RuleManagerError::IoError(eql_path.clone(), e))?;
            return Ok(RuleDefinition::Eql(content));
        }

        let lua_path = path.join("predicate.lua");
        if lua_path.exists() {
            let content = std::fs::read_to_string(&lua_path)
                .map_err(|e| RuleManagerError::IoError(lua_path.clone(), e))?;
            return Ok(RuleDefinition::Lua(content));
        }

        let wasm_path = path.join("rule.wasm");
        if wasm_path.exists() {
            let content = std::fs::read(&wasm_path)
                .map_err(|e| RuleManagerError::IoError(wasm_path.clone(), e))?;
            return Ok(RuleDefinition::Wasm(content));
        }

        let wat_path = path.join("rule.wat");
        if wat_path.exists() {
            let content = std::fs::read_to_string(&wat_path)
                .map_err(|e| RuleManagerError::IoError(wat_path.clone(), e))?;
            return Ok(RuleDefinition::Wasm(content.into_bytes()));
        }

        Err(RuleManagerError::InvalidRuleFormat(path.to_path_buf()))
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

        self.insert_rule(rule).await
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

        self.insert_rule(rule).await
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

        self.insert_rule(rule).await
    }

    async fn insert_rule(&self, rule: Rule) -> Result<(), RuleManagerError> {
        let mut rules = self.rules.write().await;
        let rule_id = rule.metadata.id.clone();
        if rules.contains_key(&rule_id) {
            return Err(RuleManagerError::DuplicateRuleId(rule_id));
        }

        rules.insert(rule_id, rule);

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

    /// Reload all rules from the configured directory atomically.
    ///
    /// New rules are loaded into a temporary map and then swapped atomically
    /// with the current rules. This ensures that rules are never in an inconsistent state.
    pub async fn reload_all(&self) -> Result<ReloadStats, RuleManagerError> {
        info!(dir = %self.config.rules_dir.display(), "Reloading rules");

        let mut new_rules = HashMap::new();
        let mut stats = ReloadStats::default();

        if !self.config.rules_dir.exists() {
            warn!("Rules directory does not exist: {}", self.config.rules_dir.display());
            return Ok(stats);
        }

        let entries = std::fs::read_dir(&self.config.rules_dir)
            .map_err(|e| RuleManagerError::IoError(self.config.rules_dir.clone(), e))?;

        for entry in entries {
            let entry =
                entry.map_err(|e| RuleManagerError::IoError(self.config.rules_dir.clone(), e))?;
            let path = entry.path();

            let load_result = if path.is_dir() {
                self.load_rule_package_returning_rule(&path).await
            } else {
                self.load_rule_file_returning_rule(&path).await
            };

            match load_result {
                Ok(rule) => {
                    let rule_id = rule.metadata.id.clone();
                    if new_rules.contains_key(&rule_id) {
                        stats.failed += 1;
                        error!(rule_id = %rule_id, path = %path.display(), "Duplicate rule ID");
                    } else {
                        new_rules.insert(rule_id, rule);
                        stats.loaded += 1;
                    }
                },
                Err(e) => {
                    stats.failed += 1;
                    error!(path = %path.display(), error = %e, "Failed to load rule");
                },
            }
        }

        // Compare with existing rules
        let existing_rules = self.rules.read().await;
        let existing_ids: std::collections::HashSet<_> = existing_rules.keys().collect();
        let new_ids: std::collections::HashSet<_> = new_rules.keys().collect();

        stats.added = new_ids.difference(&existing_ids).count();
        stats.removed = existing_ids.difference(&new_ids).count();
        stats.unchanged = existing_ids.intersection(&new_ids).count();

        // Atomically swap the rules
        drop(existing_rules);
        let mut rules = self.rules.write().await;
        *rules = new_rules;
        drop(rules);

        info!(
            loaded = stats.loaded,
            added = stats.added,
            removed = stats.removed,
            unchanged = stats.unchanged,
            failed = stats.failed,
            "Rule reload complete"
        );

        Ok(stats)
    }

    /// Load a single rule file and return the Rule
    async fn load_rule_file_returning_rule(&self, path: &Path) -> Result<Rule, RuleManagerError> {
        let _permit = self
            .load_semaphore
            .acquire()
            .await
            .map_err(|_| RuleManagerError::LoadLimitExceeded)?;

        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .ok_or_else(|| RuleManagerError::InvalidRuleFormat(path.to_path_buf()))?;

        match extension {
            "json" => {
                let content = std::fs::read_to_string(path)
                    .map_err(|e| RuleManagerError::IoError(path.to_path_buf(), e))?;
                let metadata: RuleMetadata = serde_json::from_str(&content)
                    .map_err(|e| RuleManagerError::ParseError(path.to_path_buf(), e.to_string()))?;
                Ok(Rule {
                    metadata: metadata.clone(),
                    definition: RuleDefinition::Eql(content),
                })
            },
            "yaml" | "yml" => {
                let content = std::fs::read_to_string(path)
                    .map_err(|e| RuleManagerError::IoError(path.to_path_buf(), e))?;
                let metadata: RuleMetadata = serde_yaml::from_str(&content)
                    .map_err(|e| RuleManagerError::ParseError(path.to_path_buf(), e.to_string()))?;
                Ok(Rule {
                    metadata: metadata.clone(),
                    definition: RuleDefinition::Eql(content),
                })
            },
            "eql" => {
                let content = std::fs::read_to_string(path)
                    .map_err(|e| RuleManagerError::IoError(path.to_path_buf(), e))?;
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
                Ok(Rule {
                    metadata,
                    definition: RuleDefinition::Eql(content),
                })
            },
            _ => Err(RuleManagerError::InvalidRuleFormat(path.to_path_buf())),
        }
    }

    /// Load a directory-based rule package and return the Rule.
    async fn load_rule_package_returning_rule(
        &self,
        path: &Path,
    ) -> Result<Rule, RuleManagerError> {
        let _permit = self
            .load_semaphore
            .acquire()
            .await
            .map_err(|_| RuleManagerError::LoadLimitExceeded)?;

        let manifest_path = path.join("manifest.json");
        if !manifest_path.exists() {
            return Err(RuleManagerError::InvalidRuleFormat(path.to_path_buf()));
        }

        let manifest_content = std::fs::read_to_string(&manifest_path)
            .map_err(|e| RuleManagerError::IoError(manifest_path.clone(), e))?;
        let manifest: RuleManifest = serde_json::from_str(&manifest_content)
            .map_err(|e| RuleManagerError::ParseError(manifest_path.clone(), e.to_string()))?;

        let metadata = RuleMetadata::try_from(manifest)
            .map_err(|e| RuleManagerError::ParseError(manifest_path.clone(), e))?;

        let definition = self.load_rule_package_definition(path)?;
        Ok(Rule {
            metadata,
            definition,
        })
    }
}

/// Rule loading statistics
#[derive(Debug, Default, Clone)]
pub struct LoadStats {
    pub loaded: usize,
    pub failed: usize,
}

/// Rule reload statistics
#[derive(Debug, Default, Clone)]
pub struct ReloadStats {
    pub loaded: usize,
    pub failed: usize,
    pub added: usize,
    pub removed: usize,
    pub unchanged: usize,
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

    #[error("Duplicate rule ID: {0}")]
    DuplicateRuleId(String),

    #[error("Rule load limit exceeded")]
    LoadLimitExceeded,
}

impl TryFrom<RuleManifest> for RuleMetadata {
    type Error = String;

    fn try_from(manifest: RuleManifest) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            id: manifest.metadata.rule_id,
            name: manifest.metadata.rule_name,
            description: manifest.metadata.description,
            version: manifest.metadata.rule_version,
            author: manifest.metadata.author,
            tags: manifest.metadata.tags,
            severity: parse_severity(&manifest.metadata.severity)?,
        })
    }
}

fn parse_severity(severity: &str) -> std::result::Result<Severity, String> {
    match severity.to_ascii_lowercase().as_str() {
        "informational" | "info" => Ok(Severity::Informational),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err(format!("unsupported severity: {severity}")),
    }
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

    #[tokio::test]
    async fn test_rule_load_directory_package_prefers_eql() {
        let temp_dir = tempfile::tempdir().unwrap();
        let package_dir = temp_dir.path().join("rule_pkg");
        std::fs::create_dir(&package_dir).unwrap();

        std::fs::write(
            package_dir.join("manifest.json"),
            r#"{
                "format_version": "1.0",
                "metadata": {
                    "rule_id": "pkg-001",
                    "rule_name": "Package Rule",
                    "rule_version": "1.0.0",
                    "author": "Test Author",
                    "description": "Package based rule",
                    "tags": ["package"],
                    "severity": "High",
                    "schema_version": "1.0"
                },
                "capabilities": {
                    "supports_inline": false,
                    "requires_alert": true,
                    "requires_block": false,
                    "max_span_ms": null
                }
            }"#,
        )
        .unwrap();
        std::fs::write(package_dir.join("rule.eql"), "process where true").unwrap();
        std::fs::write(package_dir.join("predicate.lua"), "function pred_eval() return true end")
            .unwrap();

        let manager = RuleManager::new(RuleManagerConfig {
            rules_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        });
        let stats = manager.load_all().await.unwrap();

        assert_eq!(stats.loaded, 1);
        let rule = manager.get_rule("pkg-001").await.unwrap();
        assert_eq!(rule.metadata.severity, Severity::High);
        match rule.definition {
            RuleDefinition::Eql(definition) => assert_eq!(definition, "process where true"),
            other => panic!("expected EQL definition, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_rule_load_directory_package_lua_fallback() {
        let temp_dir = tempfile::tempdir().unwrap();
        let package_dir = temp_dir.path().join("rule_pkg");
        std::fs::create_dir(&package_dir).unwrap();

        std::fs::write(
            package_dir.join("manifest.json"),
            r#"{
                "format_version": "1.0",
                "metadata": {
                    "rule_id": "pkg-lua-001",
                    "rule_name": "Lua Package Rule",
                    "rule_version": "1.0.0",
                    "author": null,
                    "description": null,
                    "tags": [],
                    "severity": "Low",
                    "schema_version": "1.0"
                },
                "capabilities": {
                    "supports_inline": false,
                    "requires_alert": true,
                    "requires_block": false,
                    "max_span_ms": null
                }
            }"#,
        )
        .unwrap();
        std::fs::write(package_dir.join("predicate.lua"), "return true").unwrap();

        let manager = RuleManager::new(RuleManagerConfig {
            rules_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        });
        let stats = manager.load_all().await.unwrap();

        assert_eq!(stats.loaded, 1);
        let rule = manager.get_rule("pkg-lua-001").await.unwrap();
        match rule.definition {
            RuleDefinition::Lua(script) => assert_eq!(script, "return true"),
            other => panic!("expected Lua definition, got {other:?}"),
        }
    }
}
