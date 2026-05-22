use async_trait::async_trait;
use kestrel_event::Event;
use kestrel_rules::{Rule, RuleDefinition};
use kestrel_schema::{SchemaRegistry, register_builtin_linux_schema};
use regex::Regex;
use std::sync::Arc;

/// Result of validating a rule.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub rule_id: Arc<str>,
    pub valid: bool,
    pub matched: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    pub fn new(rule_id: impl Into<Arc<str>>) -> Self {
        Self {
            rule_id: rule_id.into(),
            valid: true,
            matched: false,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

/// Trait for async rule validation against events.
#[async_trait]
pub trait EventValidator {
    /// Validate a rule's metadata and definition.
    fn validate_rule(&self, rule: &Rule) -> ValidationResult;

    /// Validate a rule by testing it against a single event.
    async fn validate_against_event(&self, rule: &Rule, event: &Event) -> ValidationResult;
}

/// Validates rules for structural correctness and schema compliance.
pub struct RuleValidator {
    schema: Arc<SchemaRegistry>,
    field_pattern: Regex,
}

impl RuleValidator {
    /// Create a new validator with the given schema registry.
    pub fn new(schema: Arc<SchemaRegistry>) -> Self {
        Self {
            schema,
            field_pattern: Regex::new(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+")
                .expect("valid field path regex"),
        }
    }

    /// Create a validator pre-populated with the built-in Linux schema.
    pub fn with_builtin_schema() -> Self {
        let schema = Arc::new(SchemaRegistry::new());
        let _ = register_builtin_linux_schema(&schema);
        Self::new(schema)
    }
}

#[async_trait]
impl EventValidator for RuleValidator {
    fn validate_rule(&self, rule: &Rule) -> ValidationResult {
        let mut result = ValidationResult::new(rule.metadata.id.clone());

        if rule.metadata.id.is_empty() {
            result.errors.push("Rule metadata.id is empty".to_string());
        }
        if rule.metadata.name.is_empty() {
            result
                .errors
                .push("Rule metadata.name is empty".to_string());
        }
        if rule.metadata.version.is_empty() {
            result
                .errors
                .push("Rule metadata.version is empty".to_string());
        }

        match &rule.definition {
            RuleDefinition::Eql(eql) => {
                if eql.is_empty() {
                    result.errors.push("EQL definition is empty".to_string());
                } else if !eql.contains("where") {
                    result
                        .errors
                        .push("EQL definition missing 'where' clause".to_string());
                }
                self.extract_field_warnings(eql, &mut result);
            },
            RuleDefinition::Wasm(wasm) => {
                if wasm.is_empty() {
                    result.errors.push("Wasm definition is empty".to_string());
                } else if wasm.len() < 4 || &wasm[0..4] != b"\0asm" {
                    result.warnings.push(
                        "Wasm definition missing magic bytes (may be WAT or invalid)".to_string(),
                    );
                }
            },
            RuleDefinition::Lua(lua) => {
                if lua.is_empty() {
                    result.errors.push("Lua definition is empty".to_string());
                }
                self.extract_field_warnings(lua, &mut result);
            },
        }

        result.valid = result.errors.is_empty();
        result
    }

    async fn validate_against_event(&self, rule: &Rule, event: &Event) -> ValidationResult {
        let mut result = self.validate_rule(rule);
        if !result.valid {
            return result;
        }

        let temp_dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(e) => {
                result.valid = false;
                result
                    .errors
                    .push(format!("Failed to create temp dir: {}", e));
                return result;
            },
        };

        if let Err(e) = crate::write_rule_package(temp_dir.path(), rule) {
            result.valid = false;
            result
                .errors
                .push(format!("Failed to write rule package: {}", e));
            return result;
        }

        let config = kestrel_engine::EngineConfig {
            rules_dir: temp_dir.path().to_path_buf(),
            mode: kestrel_engine::EngineMode::Offline,
            ..Default::default()
        };

        let engine = match kestrel_engine::DetectionEngine::new(config).await {
            Ok(e) => e,
            Err(e) => {
                result.valid = false;
                result
                    .errors
                    .push(format!("Failed to create engine: {}", e));
                return result;
            },
        };

        match engine.eval_event(event).await {
            Ok(alerts) => {
                result.matched = !alerts.is_empty();
                if alerts.is_empty() {
                    result.warnings.push("Rule did not match event".to_string());
                }
            },
            Err(e) => {
                result.valid = false;
                result
                    .errors
                    .push(format!("Event evaluation failed: {}", e));
            },
        }

        result
    }
}

impl RuleValidator {
    fn extract_field_warnings(&self, definition: &str, result: &mut ValidationResult) {
        for mat in self.field_pattern.find_iter(definition) {
            let path = mat.as_str();
            if self.schema.get_field_id(path).is_none() && path.contains('.') {
                result
                    .warnings
                    .push(format!("Field '{}' not found in schema registry", path));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_event::Event;
    use kestrel_rules::{RuleMetadata, Severity};

    fn test_rule() -> Rule {
        Rule {
            metadata: RuleMetadata {
                id: "test-001".to_string(),
                name: "Test Rule".to_string(),
                description: Some("A test rule".to_string()),
                version: "1.0.0".to_string(),
                author: Some("Tester".to_string()),
                tags: vec!["test".to_string()],
                severity: Severity::Medium,
            },
            definition: RuleDefinition::Eql("process where process.name == \"test\"".to_string()),
        }
    }

    #[test]
    fn test_validate_rule_valid() {
        let validator = RuleValidator::with_builtin_schema();
        let rule = test_rule();
        let result = validator.validate_rule(&rule);
        assert!(result.valid, "Expected valid, got errors: {:?}", result.errors);
        assert_eq!(result.rule_id.as_ref(), "test-001");
    }

    #[test]
    fn test_validate_rule_missing_id() {
        let validator = RuleValidator::with_builtin_schema();
        let mut rule = test_rule();
        rule.metadata.id = "".to_string();
        let result = validator.validate_rule(&rule);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("id is empty")));
    }

    #[test]
    fn test_validate_rule_empty_eql() {
        let validator = RuleValidator::with_builtin_schema();
        let mut rule = test_rule();
        rule.definition = RuleDefinition::Eql("".to_string());
        let result = validator.validate_rule(&rule);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("empty")));
    }

    #[test]
    fn test_validate_rule_missing_where() {
        let validator = RuleValidator::with_builtin_schema();
        let mut rule = test_rule();
        rule.definition = RuleDefinition::Eql("process".to_string());
        let result = validator.validate_rule(&rule);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("where")));
    }

    #[tokio::test]
    async fn test_validate_against_event() {
        let validator = RuleValidator::with_builtin_schema();
        let rule = test_rule();
        let event = Event::builder()
            .event_type(1)
            .ts_mono(1000)
            .ts_wall(1000)
            .entity_key(42)
            .build()
            .unwrap();
        let result = validator.validate_against_event(&rule, &event).await;
        // Should complete without engine construction errors
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.contains("Failed to create engine")),
            "Engine creation failed: {:?}",
            result.errors
        );
    }
}
