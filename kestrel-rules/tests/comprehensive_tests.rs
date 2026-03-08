//! Comprehensive Tests for Rules Module
//!
//! 规则模块的综合测试 - 覆盖更多边界条件和异常场景

use kestrel_rules::*;
use std::path::PathBuf;
use tempfile::TempDir;

// =============================================================================
// Rule Definition Tests (1-10)
// =============================================================================

#[test]
fn test_rule_definition_eql() {
    let def = RuleDefinition::Eql("process where process.name == \"bash\"".to_string());
    match &def {
        RuleDefinition::Eql(query) => assert_eq!(query, "process where process.name == \"bash\""),
        _ => panic!("Expected Eql variant"),
    }
}

#[test]
fn test_rule_definition_wasm() {
    let wasm_bytes = vec![0x00, 0x61, 0x73, 0x6d]; // Wasm magic bytes
    let def = RuleDefinition::Wasm(wasm_bytes.clone());
    match &def {
        RuleDefinition::Wasm(bytes) => assert_eq!(bytes, &wasm_bytes),
        _ => panic!("Expected Wasm variant"),
    }
}

#[test]
fn test_rule_definition_lua() {
    let def = RuleDefinition::Lua("return event.process.name == 'bash'".to_string());
    match &def {
        RuleDefinition::Lua(script) => assert!(script.contains("bash")),
        _ => panic!("Expected Lua variant"),
    }
}

#[test]
fn test_rule_metadata_creation() {
    let metadata = RuleMetadata {
        id: "test_rule".to_string(),
        name: "Test Rule".to_string(),
        description: Some("A test rule".to_string()),
        version: "1.0.0".to_string(),
        author: Some("Test Author".to_string()),
        tags: vec!["test".to_string(), "security".to_string()],
        severity: Severity::High,
    };

    assert_eq!(metadata.id, "test_rule");
    assert_eq!(metadata.severity, Severity::High);
}

#[test]
fn test_rule_metadata_clone() {
    let metadata = RuleMetadata {
        id: "test".to_string(),
        name: "Test".to_string(),
        description: None,
        version: "1.0".to_string(),
        author: None,
        tags: vec![],
        severity: Severity::Medium,
    };

    let cloned = metadata.clone();
    assert_eq!(cloned.id, metadata.id);
}

#[test]
fn test_rule_creation() {
    let rule = Rule {
        metadata: RuleMetadata {
            id: "rule1".to_string(),
            name: "Rule 1".to_string(),
            description: None,
            version: "1.0".to_string(),
            author: None,
            tags: vec![],
            severity: Severity::Low,
        },
        definition: RuleDefinition::Eql("process where true".to_string()),
    };

    assert_eq!(rule.metadata.id, "rule1");
}

#[test]
fn test_rule_severity_ordering() {
    assert!(Severity::Informational < Severity::Low);
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

#[test]
fn test_severity_display() {
    assert_eq!(format!("{}", Severity::Informational), "Informational");
    assert_eq!(format!("{}", Severity::Low), "Low");
    assert_eq!(format!("{}", Severity::Medium), "Medium");
    assert_eq!(format!("{}", Severity::High), "High");
    assert_eq!(format!("{}", Severity::Critical), "Critical");
}

#[test]
fn test_severity_default() {
    let default: Severity = Default::default();
    assert_eq!(default, Severity::Medium);
}

#[test]
fn test_rule_equality() {
    let rule1 = create_test_rule("rule1", "Rule 1");
    let rule2 = create_test_rule("rule1", "Rule 1");
    let rule3 = create_test_rule("rule2", "Rule 2");

    assert_eq!(rule1.metadata.id, rule2.metadata.id);
    assert_ne!(rule1.metadata.id, rule3.metadata.id);
}

// =============================================================================
// Configuration Tests (11-20)
// =============================================================================

#[test]
fn test_rule_manager_config_default() {
    let config = RuleManagerConfig::default();
    assert_eq!(config.rules_dir, PathBuf::from("./rules"));
    assert!(config.watch_enabled);
    assert_eq!(config.max_concurrent_loads, 4);
}

#[test]
fn test_rule_manager_config_custom() {
    let config = RuleManagerConfig {
        rules_dir: PathBuf::from("/custom/rules"),
        watch_enabled: false,
        max_concurrent_loads: 8,
    };

    assert_eq!(config.rules_dir, PathBuf::from("/custom/rules"));
    assert!(!config.watch_enabled);
    assert_eq!(config.max_concurrent_loads, 8);
}

#[test]
fn test_load_stats_default() {
    let stats = LoadStats::default();
    assert_eq!(stats.loaded, 0);
    assert_eq!(stats.failed, 0);
}

#[test]
fn test_load_stats_with_values() {
    let stats = LoadStats {
        loaded: 10,
        failed: 2,
    };

    assert_eq!(stats.loaded, 10);
    assert_eq!(stats.failed, 2);
}

#[test]
fn test_rule_manager_config_clone() {
    let config = RuleManagerConfig {
        rules_dir: PathBuf::from("/test"),
        watch_enabled: true,
        max_concurrent_loads: 4,
    };

    let cloned = config.clone();
    assert_eq!(cloned.rules_dir, config.rules_dir);
    assert_eq!(cloned.max_concurrent_loads, config.max_concurrent_loads);
}

// =============================================================================
// Rule Manager Creation Tests (21-30)
// =============================================================================

#[tokio::test]
async fn test_rule_manager_creation_empty() {
    let temp_dir = TempDir::new().unwrap();
    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);
    assert_eq!(manager.rule_count().await, 0);
}

#[tokio::test]
async fn test_rule_manager_get_nonexistent() {
    let temp_dir = TempDir::new().unwrap();
    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);
    let rule = manager.get_rule("nonexistent").await;
    assert!(rule.is_none());
}

#[tokio::test]
async fn test_rule_manager_list_empty() {
    let temp_dir = TempDir::new().unwrap();
    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);
    let rules = manager.list_rules().await;
    assert!(rules.is_empty());
}

#[tokio::test]
async fn test_rule_manager_load_single_json() {
    let temp_dir = TempDir::new().unwrap();
    let rule_file = temp_dir.path().join("test.json");

    let rule = serde_json::json!({
        "id": "test_rule",
        "name": "Test Rule",
        "version": "1.0.0",
        "severity": "High",
        "tags": ["test"]
    });
    std::fs::write(&rule_file, rule.to_string()).unwrap();

    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);
    let stats = manager.load_all().await.unwrap();

    assert_eq!(stats.loaded, 1);
    assert_eq!(stats.failed, 0);
    assert_eq!(manager.rule_count().await, 1);
}

#[tokio::test]
async fn test_rule_manager_load_single_yaml() {
    let temp_dir = TempDir::new().unwrap();
    let rule_file = temp_dir.path().join("test.yaml");

    let rule =
        "id: test_yaml_rule\nname: Test YAML Rule\nversion: \"1.0.0\"\nseverity: Medium\ntags: []";
    std::fs::write(&rule_file, rule).unwrap();

    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);
    let stats = manager.load_all().await.unwrap();

    assert_eq!(stats.loaded, 1);
    assert_eq!(manager.rule_count().await, 1);
}

#[tokio::test]
async fn test_rule_manager_load_single_eql() {
    let temp_dir = TempDir::new().unwrap();
    let rule_file = temp_dir.path().join("test.eql");

    std::fs::write(&rule_file, "process where process.name == \"bash\"").unwrap();

    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);
    let stats = manager.load_all().await.unwrap();

    assert_eq!(stats.loaded, 1);
    assert_eq!(manager.rule_count().await, 1);

    let rule = manager.get_rule("test").await;
    assert!(rule.is_some());
}

#[tokio::test]
async fn test_rule_manager_load_multiple() {
    let temp_dir = TempDir::new().unwrap();

    for i in 0..5 {
        let rule_file = temp_dir.path().join(format!("rule_{}.json", i));
        let rule = serde_json::json!({
            "id": format!("rule_{}", i),
            "name": format!("Rule {}", i),
            "version": "1.0.0",
            "severity": "Medium",
            "tags": []
        });
        std::fs::write(&rule_file, rule.to_string()).unwrap();
    }

    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);
    let stats = manager.load_all().await.unwrap();

    assert_eq!(stats.loaded, 5);
    assert_eq!(manager.rule_count().await, 5);
}

#[tokio::test]
async fn test_rule_manager_get_after_load() {
    let temp_dir = TempDir::new().unwrap();
    let rule_file = temp_dir.path().join("test.json");

    let rule = serde_json::json!({
        "id": "retrievable_rule",
        "name": "Retrievable Rule",
        "version": "1.0.0",
        "severity": "Critical",
        "tags": ["important"]
    });
    std::fs::write(&rule_file, rule.to_string()).unwrap();

    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);
    manager.load_all().await.unwrap();

    let rule = manager.get_rule("retrievable_rule").await;
    assert!(rule.is_some());
    assert_eq!(rule.unwrap().metadata.name, "Retrievable Rule");
}

#[tokio::test]
async fn test_rule_manager_list_after_load() {
    let temp_dir = TempDir::new().unwrap();

    for i in 0..3 {
        let rule_file = temp_dir.path().join(format!("rule_{}.json", i));
        let rule = serde_json::json!({
            "id": format!("list_rule_{}", i),
            "name": format!("List Rule {}", i),
            "version": "1.0.0",
            "severity": "Low",
            "tags": []
        });
        std::fs::write(&rule_file, rule.to_string()).unwrap();
    }

    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);
    manager.load_all().await.unwrap();

    let rules = manager.list_rules().await;
    assert_eq!(rules.len(), 3);
}

#[tokio::test]
async fn test_rule_manager_reload() {
    let temp_dir = TempDir::new().unwrap();
    let rule_file = temp_dir.path().join("initial.json");

    let rule = serde_json::json!({
        "id": "initial",
        "name": "Initial Rule",
        "version": "1.0.0",
        "severity": "Medium",
        "tags": []
    });
    std::fs::write(&rule_file, rule.to_string()).unwrap();

    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);
    manager.load_all().await.unwrap();

    // Add new rule
    let new_rule_file = temp_dir.path().join("new.json");
    let new_rule = serde_json::json!({
        "id": "new",
        "name": "New Rule",
        "version": "1.0.0",
        "severity": "High",
        "tags": []
    });
    std::fs::write(&new_rule_file, new_rule.to_string()).unwrap();

    // Reload
    let stats = manager.load_all().await.unwrap();
    assert_eq!(stats.loaded, 2);
}

// =============================================================================
// Error Handling Tests (31-40)
// =============================================================================

#[tokio::test]
async fn test_invalid_json_error() {
    let temp_dir = TempDir::new().unwrap();
    let rule_file = temp_dir.path().join("invalid.json");
    std::fs::write(&rule_file, "{not valid json}").unwrap();

    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);
    let stats = manager.load_all().await.unwrap();

    assert_eq!(stats.loaded, 0);
    assert_eq!(stats.failed, 1);
}

#[tokio::test]
async fn test_missing_required_field() {
    let temp_dir = TempDir::new().unwrap();
    let rule_file = temp_dir.path().join("incomplete.json");

    // Missing 'name' field
    let rule = serde_json::json!({
        "id": "incomplete",
        "version": "1.0.0",
        "severity": "Medium",
        "tags": []
    });
    std::fs::write(&rule_file, rule.to_string()).unwrap();

    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);
    let stats = manager.load_all().await.unwrap();

    // Should fail because 'name' is missing
    assert_eq!(stats.failed, 1);
}

#[tokio::test]
async fn test_empty_json_object() {
    let temp_dir = TempDir::new().unwrap();
    let rule_file = temp_dir.path().join("empty.json");
    std::fs::write(&rule_file, "{}").unwrap();

    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);
    let stats = manager.load_all().await.unwrap();

    assert_eq!(stats.failed, 1);
}

#[tokio::test]
async fn test_duplicate_rule_ids() {
    let temp_dir = TempDir::new().unwrap();

    // Create two files with same ID
    let rule1 = temp_dir.path().join("rule1.json");
    let rule2 = temp_dir.path().join("rule2.json");

    let content = serde_json::json!({
        "id": "duplicate_id",
        "name": "Rule",
        "version": "1.0.0",
        "severity": "Medium",
        "tags": []
    });

    std::fs::write(&rule1, content.to_string()).unwrap();
    std::fs::write(&rule2, content.to_string()).unwrap();

    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);
    let stats = manager.load_all().await.unwrap();

    // Duplicate IDs should be rejected within the same reload pass
    assert_eq!(stats.loaded, 1);
    assert_eq!(stats.failed, 1);
    assert_eq!(manager.rule_count().await, 1);
}

#[tokio::test]
async fn test_unsupported_file_extension() {
    let temp_dir = TempDir::new().unwrap();
    let rule_file = temp_dir.path().join("rule.txt");
    std::fs::write(&rule_file, "some content").unwrap();

    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);
    let stats = manager.load_all().await.unwrap();

    // May skip or fail unsupported files depending on implementation
    println!("Loaded: {}, Failed: {}", stats.loaded, stats.failed);
}

#[tokio::test]
async fn test_empty_directory() {
    let temp_dir = TempDir::new().unwrap();

    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);
    let stats = manager.load_all().await.unwrap();

    assert_eq!(stats.loaded, 0);
    assert_eq!(stats.failed, 0);
}

#[tokio::test]
async fn test_subdirectories_ignored() {
    let temp_dir = TempDir::new().unwrap();
    let sub_dir = temp_dir.path().join("subdir");
    std::fs::create_dir(&sub_dir).unwrap();

    let rule_file = sub_dir.join("nested.json");
    let rule = serde_json::json!({
        "id": "nested",
        "name": "Nested Rule",
        "version": "1.0.0",
        "severity": "Medium",
        "tags": []
    });
    std::fs::write(&rule_file, rule.to_string()).unwrap();

    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);
    let stats = manager.load_all().await.unwrap();

    // Should ignore files in subdirectories
    assert_eq!(stats.loaded, 0);
}

#[tokio::test]
async fn test_corrupt_yaml_file() {
    let temp_dir = TempDir::new().unwrap();
    let rule_file = temp_dir.path().join("corrupt.yaml");
    std::fs::write(&rule_file, "not: valid: yaml: [").unwrap();

    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);
    let stats = manager.load_all().await.unwrap();

    assert_eq!(stats.failed, 1);
}

#[tokio::test]
async fn test_eql_file_without_extension() {
    let temp_dir = TempDir::new().unwrap();
    let rule_file = temp_dir.path().join("no_ext_eql");
    std::fs::write(&rule_file, "process where true").unwrap();

    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);
    let stats = manager.load_all().await.unwrap();

    // Should skip files without proper extension
    assert_eq!(stats.loaded, 0);
}

// =============================================================================
// Helper Functions
// =============================================================================

fn create_test_rule(id: &str, name: &str) -> Rule {
    Rule {
        metadata: RuleMetadata {
            id: id.to_string(),
            name: name.to_string(),
            description: None,
            version: "1.0.0".to_string(),
            author: None,
            tags: vec![],
            severity: Severity::Medium,
        },
        definition: RuleDefinition::Eql("process where true".to_string()),
    }
}
