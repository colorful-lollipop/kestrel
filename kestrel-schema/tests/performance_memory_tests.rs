//! Performance and Memory Tests for Schema Module
//!
//! 性能测试和内存使用测试

use kestrel_schema::*;
use std::time::Instant;

// =============================================================================
// Performance Tests: Schema Registry Operations
// =============================================================================

#[test]
fn test_schema_registry_field_registration_performance() {
    let registry = SchemaRegistry::new();
    let count = 10000;

    let start = Instant::now();
    for i in 0..count {
        let def = FieldDef {
            path: format!("field_{}", i),
            data_type: FieldDataType::String,
            description: Some(format!("Field {}", i)),
        };
        let _ = registry.register_field(def);
    }
    let elapsed = start.elapsed();

    let ops_per_sec = count as f64 / elapsed.as_secs_f64();
    println!(
        "✅ Field registration: {} fields in {:?} ({:.0} ops/sec)",
        count, elapsed, ops_per_sec
    );

    assert!(ops_per_sec > 1000.0, "Field registration too slow: {:.0} ops/sec", ops_per_sec);
}

#[test]
fn test_schema_registry_field_lookup_performance() {
    let registry = SchemaRegistry::new();
    let count = 10000;

    // Register fields first
    for i in 0..count {
        let def = FieldDef {
            path: format!("field_{}", i),
            data_type: FieldDataType::String,
            description: None,
        };
        let _ = registry.register_field(def).unwrap();
    }

    // Measure lookup performance
    let start = Instant::now();
    for i in 0..count {
        let _ = registry.get_field_id(&format!("field_{}", i));
    }
    let elapsed = start.elapsed();

    let ops_per_sec = count as f64 / elapsed.as_secs_f64();
    println!(
        "✅ Field lookup: {} lookups in {:?} ({:.0} ops/sec)",
        count, elapsed, ops_per_sec
    );

    assert!(ops_per_sec > 10000.0, "Field lookup too slow: {:.0} ops/sec", ops_per_sec);
}

#[test]
fn test_schema_registry_concurrent_access_performance() {
    use std::sync::Arc;
    use std::thread;

    let registry = Arc::new(SchemaRegistry::new());
    let num_threads = 8;
    let ops_per_thread = 1000;

    let start = Instant::now();

    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let reg = Arc::clone(&registry);
            thread::spawn(move || {
                for i in 0..ops_per_thread {
                    let def = FieldDef {
                        path: format!("thread_{}_field_{}", thread_id, i),
                        data_type: FieldDataType::I64,
                        description: None,
                    };
                    let _ = reg.register_field(def);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    let elapsed = start.elapsed();
    let total_ops = num_threads * ops_per_thread;
    let ops_per_sec = total_ops as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Concurrent field registration: {} ops across {} threads in {:?} ({:.0} ops/sec)",
        total_ops, num_threads, elapsed, ops_per_sec
    );
}

// =============================================================================
// Memory Usage Tests
// =============================================================================

#[test]
fn test_typed_value_memory_overhead() {
    use std::mem::size_of;

    let bool_size = size_of::<TypedValue>();
    let string_size = size_of::<TypedValue>() + size_of::<String>();

    println!("✅ TypedValue memory overhead:");
    println!("   Bool: {} bytes", bool_size);
    println!("   String (empty): {} bytes", string_size);

    // Verify reasonable sizes
    assert!(bool_size <= 32, "TypedValue too large: {} bytes", bool_size);
}

#[test]
fn test_schema_registry_memory_scaling() {
    let _registry = SchemaRegistry::new();
    let field_counts = vec![100, 1000, 10000];

    for count in field_counts {
        let reg = SchemaRegistry::new();

        for i in 0..count {
            let def = FieldDef {
                path: format!("process.thread.module.field_{}", i),
                data_type: match i % 5 {
                    0 => FieldDataType::I64,
                    1 => FieldDataType::U64,
                    2 => FieldDataType::String,
                    3 => FieldDataType::Bool,
                    _ => FieldDataType::F64,
                },
                description: if i % 10 == 0 {
                    Some(format!("Description for field {}", i))
                } else {
                    None
                },
            };
            let _ = reg.register_field(def).unwrap();
        }

        let fields = reg.list_fields();
        assert_eq!(fields.len(), count);

        println!("✅ Memory scaling: {} fields registered", count);
    }
}

// =============================================================================
// Stress Tests
// =============================================================================

#[test]
fn test_severity_comparison_performance() {
    let iterations = 1_000_000;
    let start = Instant::now();

    for i in 0..iterations {
        let s1 = match i % 5 {
            0 => Severity::Informational,
            1 => Severity::Low,
            2 => Severity::Medium,
            3 => Severity::High,
            _ => Severity::Critical,
        };
        let s2 = match (i + 1) % 5 {
            0 => Severity::Informational,
            1 => Severity::Low,
            2 => Severity::Medium,
            3 => Severity::High,
            _ => Severity::Critical,
        };
        let _ = s1 < s2;
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    println!(
        "✅ Severity comparison: {} ops in {:?} ({:.0} ops/sec)",
        iterations, elapsed, ops_per_sec
    );

    assert!(ops_per_sec > 10_000_000.0, "Severity comparison too slow");
}

#[test]
fn test_typed_value_creation_performance() {
    let iterations = 100_000;
    let start = Instant::now();

    for i in 0..iterations {
        let _values: Vec<TypedValue> = vec![
            TypedValue::I64(i as i64),
            TypedValue::U64(i as u64),
            TypedValue::Bool(i % 2 == 0),
            TypedValue::String(format!("value_{}", i).into()),
        ];
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    println!(
        "✅ TypedValue creation: {} iterations in {:?} ({:.0} ops/sec)",
        iterations, elapsed, ops_per_sec
    );
}

#[test]
fn test_eval_result_creation_performance() {
    let iterations = 500_000;
    let start = Instant::now();

    for i in 0..iterations {
        let result = if i % 3 == 0 {
            EvalResult::matched()
        } else if i % 3 == 1 {
            EvalResult::not_matched()
        } else {
            EvalResult::error("test error")
        };
        drop(result);
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    println!(
        "✅ EvalResult creation: {} ops in {:?} ({:.0} ops/sec)",
        iterations, elapsed, ops_per_sec
    );
}

// =============================================================================
// End-to-End Integration Tests
// =============================================================================

#[test]
fn test_complete_schema_workflow() {
    let registry = SchemaRegistry::new();

    // Register event types
    let process_exec = registry
        .register_event_type(EventTypeDef {
            name: "process_exec".to_string(),
            description: Some("Process execution event".to_string()),
            parent: None,
        })
        .unwrap();

    let file_open = registry
        .register_event_type(EventTypeDef {
            name: "file_open".to_string(),
            description: Some("File open event".to_string()),
            parent: None,
        })
        .unwrap();

    // Register fields
    let pid = registry
        .register_field(FieldDef {
            path: "process.pid".to_string(),
            data_type: FieldDataType::I64,
            description: Some("Process ID".to_string()),
        })
        .unwrap();

    let exe = registry
        .register_field(FieldDef {
            path: "process.executable".to_string(),
            data_type: FieldDataType::String,
            description: Some("Process executable path".to_string()),
        })
        .unwrap();

    let filename = registry
        .register_field(FieldDef {
            path: "file.name".to_string(),
            data_type: FieldDataType::String,
            description: Some("File name".to_string()),
        })
        .unwrap();

    // Verify lookups
    assert_eq!(registry.get_event_type_id("process_exec"), Some(process_exec));
    assert_eq!(registry.get_event_type_id("file_open"), Some(file_open));
    assert_eq!(registry.get_field_id("process.pid"), Some(pid));
    assert_eq!(registry.get_field_id("process.executable"), Some(exe));
    assert_eq!(registry.get_field_id("file.name"), Some(filename));

    // Verify field definitions
    let pid_field = registry.get_field(pid).unwrap();
    assert_eq!(pid_field.path, "process.pid");
    assert_eq!(pid_field.data_type, FieldDataType::I64);

    // List all
    let fields = registry.list_fields();
    assert_eq!(fields.len(), 3);

    let event_types = registry.list_event_types();
    assert_eq!(event_types.len(), 2);

    println!(
        "✅ Complete schema workflow: {} fields, {} event types",
        fields.len(),
        event_types.len()
    );
}

#[test]
fn test_rule_metadata_e2e() {
    let metadata = RuleMetadata::new("malware_detection", "Malware Detection Rule")
        .with_severity("critical")
        .with_author("Security Team")
        .with_description("Detects known malware patterns")
        .with_tags(vec![
            "malware".to_string(),
            "detection".to_string(),
            "critical".to_string(),
        ]);

    let capabilities = RuleCapabilities::detection();
    let manifest = RuleManifest::new(metadata.clone()).with_capabilities(capabilities);

    assert_eq!(manifest.metadata.rule_id, "malware_detection");
    assert_eq!(manifest.metadata.severity, "critical");
    assert!(manifest.capabilities.requires_alert);
    assert!(!manifest.capabilities.supports_inline);

    println!("✅ Rule metadata E2E: {} created successfully", manifest.metadata.rule_name);
}

#[test]
fn test_typed_value_formatting() {
    let values = vec![
        TypedValue::Bool(true),
        TypedValue::I64(-42),
        TypedValue::U64(42),
        TypedValue::F64(std::f64::consts::PI),
        TypedValue::String("test string".into()),
    ];

    for value in values {
        let debug_str = format!("{:?}", value);
        assert!(!debug_str.is_empty(), "Debug format should not be empty");
    }

    println!("✅ TypedValue formatting: all variants format correctly");
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_field_registration_duplicate_handling() {
    let registry = SchemaRegistry::new();

    let def = FieldDef {
        path: "test.field".to_string(),
        data_type: FieldDataType::String,
        description: None,
    };

    let id1 = registry.register_field(def.clone()).unwrap();
    let result = registry.register_field(def);

    assert!(result.is_err(), "Should fail on duplicate field registration");

    // Verify original field still exists
    assert_eq!(registry.get_field_id("test.field"), Some(id1));
}

#[test]
fn test_long_field_path_performance() {
    let registry = SchemaRegistry::new();
    let long_path = "a".repeat(1000);

    let def = FieldDef {
        path: long_path.clone(),
        data_type: FieldDataType::String,
        description: None,
    };

    let start = Instant::now();
    let id = registry.register_field(def).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(registry.get_field_id(&long_path), Some(id));

    println!("✅ Long field path ({} chars) registered in {:?}", long_path.len(), elapsed);
}

#[test]
fn test_many_event_types_performance() {
    let registry = SchemaRegistry::new();
    let count = 1000;

    let start = Instant::now();
    for i in 0..count {
        let def = EventTypeDef {
            name: format!("event_type_{}", i),
            description: Some(format!("Event type {}", i)),
            parent: if i > 0 { Some(i as u16) } else { None },
        };
        let _ = registry.register_event_type(def).unwrap();
    }
    let elapsed = start.elapsed();

    let event_types = registry.list_event_types();
    assert_eq!(event_types.len(), count);

    println!("✅ Registered {} event types in {:?}", count, elapsed);
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

    println!("✅ RuntimeCapabilities default values verified");
}

#[test]
fn test_severity_all_comparisons() {
    let severities = [
        Severity::Informational,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    for i in 0..severities.len() {
        for j in i + 1..severities.len() {
            assert!(
                severities[i] < severities[j],
                "{:?} should be less than {:?}",
                severities[i],
                severities[j]
            );
        }
    }

    println!("✅ All severity level comparisons verified");
}
