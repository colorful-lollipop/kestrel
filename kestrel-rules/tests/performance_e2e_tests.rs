//! Performance and End-to-End Tests for Rules Module
//!
//! 规则模块的性能测试和端到端测试

use kestrel_rules::*;
use std::path::PathBuf;
use std::time::Instant;
use tempfile::TempDir;

// =============================================================================
// Rule Loading Performance Tests
// =============================================================================

#[tokio::test]
async fn test_rule_loading_performance() {
    let temp_dir = TempDir::new().unwrap();
    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);

    // Create test JSON rules
    for i in 0..100 {
        let rule_file = temp_dir.path().join(format!("rule_{}.json", i));
        let rule = serde_json::json!({
            "id": format!("perf_rule_{}", i),
            "name": format!("Performance Test Rule {}", i),
            "version": "1.0.0",
            "severity": "Medium",
            "tags": ["test", "performance"]
        });
        std::fs::write(&rule_file, rule.to_string()).unwrap();
    }

    let start = Instant::now();
    let stats = manager.load_all().await.unwrap();
    let elapsed = start.elapsed();

    let ops_per_sec = stats.loaded as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Rule loading: {} rules in {:?} ({:.0} rules/sec)",
        stats.loaded, elapsed, ops_per_sec
    );

    assert_eq!(stats.loaded, 100);
    assert_eq!(stats.failed, 0);
}

#[tokio::test]
async fn test_rule_loading_scaling() {
    let rule_counts = vec![10, 50, 100, 200];

    for count in rule_counts {
        let temp_dir = TempDir::new().unwrap();
        let config = RuleManagerConfig {
            rules_dir: temp_dir.path().to_path_buf(),
            watch_enabled: false,
            max_concurrent_loads: 4,
        };

        // Create test rules
        for i in 0..count {
            let rule_file = temp_dir.path().join(format!("rule_{}.json", i));
            let rule = serde_json::json!({
                "id": format!("scale_rule_{}_{}", count, i),
                "name": format!("Scale Rule {}", i),
                "version": "1.0.0",
                "severity": "Low",
                "tags": []
            });
            std::fs::write(&rule_file, rule.to_string()).unwrap();
        }

        let manager = RuleManager::new(config);

        let start = Instant::now();
        let stats = manager.load_all().await.unwrap();
        let elapsed = start.elapsed();

        let ops_per_sec = stats.loaded as f64 / elapsed.as_secs_f64();

        println!(
            "✅ Rule loading scale ({} rules): {:?} ({:.0} rules/sec)",
            count, elapsed, ops_per_sec
        );

        assert_eq!(stats.loaded, count);
    }
}

// =============================================================================
// Rule Compilation Performance Tests
// =============================================================================

#[test]
fn test_compilation_manager_creation() {
    let start = Instant::now();
    let _manager = CompilationManager::new();
    let elapsed = start.elapsed();

    println!("✅ Compilation manager creation: {:?}", elapsed);
}

#[test]
fn test_ir_rule_creation_performance() {
    let rule_count = 500;
    let start = Instant::now();

    for i in 0..rule_count {
        let _ir_rule = IrRule {
            metadata: RuleMetadata {
                id: format!("ir_rule_{}", i),
                name: format!("IR Rule {}", i),
                description: Some("Test compilation".to_string()),
                version: "1.0.0".to_string(),
                author: Some("Test".to_string()),
                tags: vec!["test".to_string()],
                severity: Severity::Medium,
            },
            rule_type: IrRuleType::SingleEvent {
                predicate: IrPredicate {
                    id: format!("pred_{}", i),
                    event_type: "process".to_string(),
                    condition: IrCondition::FieldEq {
                        field: "process.name".to_string(),
                        value: "bash".to_string(),
                    },
                },
            },
            required_fields: vec![1, 2, 3],
        };
    }

    let elapsed = start.elapsed();
    let ops_per_sec = rule_count as f64 / elapsed.as_secs_f64();

    println!(
        "✅ IR rule creation: {} rules in {:?} ({:.0} rules/sec)",
        rule_count, elapsed, ops_per_sec
    );
}

// =============================================================================
// Memory Usage Tests
// =============================================================================

#[test]
fn test_rule_memory_footprint() {
    use std::mem::size_of;

    let rule_size = size_of::<Rule>();
    let metadata_size = size_of::<RuleMetadata>();
    let compiled_rule_size = size_of::<CompiledRule>();

    println!("✅ Memory footprint:");
    println!("   Rule struct: {} bytes", rule_size);
    println!("   RuleMetadata: {} bytes", metadata_size);
    println!("   CompiledRule: {} bytes", compiled_rule_size);

    // Estimate memory for different rule counts
    let counts = vec![100, 500, 1000, 5000];
    for count in counts {
        let estimated_kb = (count * (rule_size + compiled_rule_size)) / 1024;
        println!("   {} rules: ~{} KB", count, estimated_kb);
    }
}

// =============================================================================
// End-to-End Integration Tests
// =============================================================================

#[tokio::test]
async fn test_complete_rule_lifecycle() {
    let temp_dir = TempDir::new().unwrap();
    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);

    // Phase 1: Create rules
    for i in 0..50 {
        let rule_file = temp_dir.path().join(format!("lifecycle_rule_{}.json", i));
        let rule = serde_json::json!({
            "id": format!("lifecycle_rule_{}", i),
            "name": format!("Lifecycle Rule {}", i),
            "version": "1.0.0",
            "severity": "Medium",
            "tags": ["lifecycle", "test"]
        });
        std::fs::write(&rule_file, rule.to_string()).unwrap();
    }

    // Phase 2: Load all rules
    let load_start = Instant::now();
    let stats = manager.load_all().await.unwrap();
    let load_time = load_start.elapsed();

    assert_eq!(stats.loaded, 50);

    // Phase 3: List rules
    let list_start = Instant::now();
    let rules = manager.list_rules().await;
    let list_time = list_start.elapsed();

    assert_eq!(rules.len(), 50);

    // Phase 4: Get specific rule
    let get_start = Instant::now();
    let rule = manager.get_rule("lifecycle_rule_25").await;
    let get_time = get_start.elapsed();

    assert!(rule.is_some());
    assert_eq!(rule.unwrap().metadata.id, "lifecycle_rule_25");

    // Phase 5: Verify rule count
    let count = manager.rule_count().await;
    assert_eq!(count, 50);

    println!("✅ Complete rule lifecycle (50 rules):");
    println!("   Load: {:?}", load_time);
    println!("   List: {:?}", list_time);
    println!("   Get: {:?}", get_time);
}

#[tokio::test]
async fn test_mixed_format_rule_loading() {
    let temp_dir = TempDir::new().unwrap();
    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);

    // Create JSON rules
    for i in 0..20 {
        let rule_file = temp_dir.path().join(format!("json_rule_{}.json", i));
        let rule = serde_json::json!({
            "id": format!("json_rule_{}", i),
            "name": format!("JSON Rule {}", i),
            "version": "1.0.0",
            "severity": "Low",
            "tags": ["json"]
        });
        std::fs::write(&rule_file, rule.to_string()).unwrap();
    }

    // Create YAML rules
    for i in 0..20 {
        let rule_file = temp_dir.path().join(format!("yaml_rule_{}.yaml", i));
        let rule = serde_yaml::to_string(&serde_json::json!({
            "id": format!("yaml_rule_{}", i),
            "name": format!("YAML Rule {}", i),
            "version": "1.0.0",
            "severity": "Medium",
            "tags": ["yaml"]
        }))
        .unwrap();
        std::fs::write(&rule_file, rule).unwrap();
    }

    // Create EQL rules
    for i in 0..10 {
        let rule_file = temp_dir.path().join(format!("eql_rule_{}.eql", i));
        std::fs::write(&rule_file, "process where process.name == \"bash\"").unwrap();
    }

    let start = Instant::now();
    let stats = manager.load_all().await.unwrap();
    let elapsed = start.elapsed();

    println!("✅ Mixed format loading:");
    println!("   Loaded: {} rules", stats.loaded);
    println!("   Failed: {} rules", stats.failed);
    println!("   Time: {:?}", elapsed);

    assert!(stats.loaded >= 40, "Should load at least JSON and EQL rules");
}

#[tokio::test]
async fn test_empty_directory_handling() {
    let temp_dir = TempDir::new().unwrap();
    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);

    let start = Instant::now();
    let stats = manager.load_all().await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(stats.loaded, 0);
    assert_eq!(stats.failed, 0);

    println!("✅ Empty directory handling: {:?}", elapsed);
}

#[tokio::test]
async fn test_nonexistent_directory_handling() {
    let config = RuleManagerConfig {
        rules_dir: PathBuf::from("/nonexistent/path/to/rules"),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);

    let start = Instant::now();
    let stats = manager.load_all().await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(stats.loaded, 0);
    assert_eq!(stats.failed, 0);

    println!("✅ Nonexistent directory handling: {:?}", elapsed);
}

// =============================================================================
// Error Handling Tests
// =============================================================================

#[tokio::test]
async fn test_invalid_json_handling() {
    let temp_dir = TempDir::new().unwrap();
    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);

    // Create valid rule
    let valid_file = temp_dir.path().join("valid_rule.json");
    std::fs::write(&valid_file, r#"{"id": "valid", "name": "Valid Rule", "version": "1.0.0", "severity": "Medium", "tags": []}"#).unwrap();

    // Create invalid JSON rule
    let invalid_file = temp_dir.path().join("invalid_rule.json");
    std::fs::write(&invalid_file, "{invalid json}").unwrap();

    let stats = manager.load_all().await.unwrap();

    assert_eq!(stats.loaded, 1);
    assert_eq!(stats.failed, 1);

    println!("✅ Invalid JSON handling: {} loaded, {} failed", stats.loaded, stats.failed);
}

// =============================================================================
// Concurrency Tests
// =============================================================================

#[tokio::test]
async fn test_concurrent_rule_access() {
    let temp_dir = TempDir::new().unwrap();
    let config = RuleManagerConfig {
        rules_dir: temp_dir.path().to_path_buf(),
        watch_enabled: false,
        max_concurrent_loads: 4,
    };

    let manager = RuleManager::new(config);

    // Create test rules
    for i in 0..100 {
        let rule_file = temp_dir.path().join(format!("concurrent_rule_{}.json", i));
        let rule = serde_json::json!({
            "id": format!("concurrent_rule_{}", i),
            "name": format!("Concurrent Rule {}", i),
            "version": "1.0.0",
            "severity": "Medium",
            "tags": []
        });
        std::fs::write(&rule_file, rule.to_string()).unwrap();
    }

    manager.load_all().await.unwrap();

    // Concurrent reads
    let manager = std::sync::Arc::new(manager);
    let mut handles = vec![];

    for i in 0..10 {
        let m = std::sync::Arc::clone(&manager);
        let handle = tokio::spawn(async move {
            for j in 0..10 {
                let rule_id = format!("concurrent_rule_{}", (i * 10 + j) % 100);
                let _ = m.get_rule(&rule_id).await;
            }
        });
        handles.push(handle);
    }

    let start = Instant::now();
    for handle in handles {
        handle.await.unwrap();
    }
    let elapsed = start.elapsed();

    println!("✅ Concurrent rule access (100 accesses): {:?}", elapsed);
}
