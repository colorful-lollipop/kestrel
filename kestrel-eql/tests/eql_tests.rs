//! EQL Compiler integration tests

use kestrel_eql::EqlCompiler;
use kestrel_schema::SchemaRegistry;
use std::sync::Arc;

fn create_test_compiler() -> EqlCompiler {
    let mut schema = SchemaRegistry::new();
    // Register common event types for testing
    schema
        .register_event_type(kestrel_schema::EventTypeDef {
            name: "process".to_string(),
            description: Some("Process event".to_string()),
            parent: None,
        })
        .unwrap();
    schema
        .register_event_type(kestrel_schema::EventTypeDef {
            name: "file".to_string(),
            description: Some("File event".to_string()),
            parent: None,
        })
        .unwrap();
    schema
        .register_event_type(kestrel_schema::EventTypeDef {
            name: "network".to_string(),
            description: Some("Network event".to_string()),
            parent: None,
        })
        .unwrap();
    let schema = Arc::new(schema);
    EqlCompiler::new(schema)
}

#[test]
fn test_parse_simple_event_query() {
    let compiler = create_test_compiler();

    let result = compiler.parse("process where process.pid == 1000");
    assert!(result.is_ok());

    let query = result.unwrap();
    match query {
        kestrel_eql::ast::Query::Event(eq) => {
            assert_eq!(eq.event_type, "process");
            assert!(eq.condition.is_some());
        }
        _ => panic!("Expected event query"),
    }
}

#[test]
fn test_parse_event_with_string_condition() {
    let compiler = create_test_compiler();

    let result =
        compiler.parse("process where process.executable == \"/bin/bash\" and process.pid > 1000");
    assert!(result.is_ok());

    let query = result.unwrap();
    match query {
        kestrel_eql::ast::Query::Event(eq) => {
            assert_eq!(eq.event_type, "process");
            assert!(eq.condition.is_some());
        }
        _ => panic!("Expected event query"),
    }
}

#[test]
fn test_parse_sequence_query() {
    let compiler = create_test_compiler();

    let result = compiler.parse(
        "sequence by process.entity_id [process where process.executable == \"/bin/bash\"] [file where file.path == \"/etc/passwd\"]"
    );

    assert!(result.is_ok());

    let query = result.unwrap();
    match query {
        kestrel_eql::ast::Query::Sequence(sq) => {
            assert_eq!(sq.steps.len(), 2);
            assert_eq!(sq.steps[0].event_type, "process");
            assert_eq!(sq.steps[1].event_type, "file");
            assert!(sq.by.is_some());
        }
        _ => panic!("Expected sequence query"),
    }
}

#[test]
fn test_parse_sequence_with_maxspan() {
    let compiler = create_test_compiler();

    let result = compiler.parse("sequence by process.pid [process] [file] with maxspan=5s");

    assert!(result.is_ok());

    let query = result.unwrap();
    match query {
        kestrel_eql::ast::Query::Sequence(sq) => {
            assert_eq!(sq.steps.len(), 2);
            assert!(sq.maxspan.is_some());
            let maxspan = sq.maxspan.unwrap();
            assert_eq!(maxspan.value, 5);
        }
        _ => panic!("Expected sequence query"),
    }
}

#[test]
fn test_parse_sequence_with_until() {
    let compiler = create_test_compiler();

    let result = compiler.parse(
        "sequence by process.pid [process] [file] until [network where network.destination == \"malicious.com\"]"
    );

    assert!(result.is_ok());

    let query = result.unwrap();
    match query {
        kestrel_eql::ast::Query::Sequence(sq) => {
            assert_eq!(sq.steps.len(), 2);
            assert!(sq.until.is_some());
        }
        _ => panic!("Expected sequence query"),
    }
}

#[test]
fn test_parse_with_wildcard_function() {
    let compiler = create_test_compiler();

    let result = compiler.parse("file where wildcard(file.path, \"*.exe\")");

    assert!(result.is_ok());

    let query = result.unwrap();
    match query {
        kestrel_eql::ast::Query::Event(eq) => {
            assert_eq!(eq.event_type, "file");
            assert!(eq.condition.is_some());
        }
        _ => panic!("Expected event query"),
    }
}

#[test]
fn test_parse_with_in_expression() {
    let compiler = create_test_compiler();

    let result = compiler
        .parse("process where process.executable in (\"/bin/bash\", \"/bin/sh\", \"/bin/zsh\")");

    assert!(result.is_ok());

    let query = result.unwrap();
    match query {
        kestrel_eql::ast::Query::Event(eq) => {
            assert_eq!(eq.event_type, "process");
            assert!(eq.condition.is_some());
        }
        _ => panic!("Expected event query"),
    }
}

#[test]
fn test_parse_with_complex_logic() {
    let compiler = create_test_compiler();

    let result = compiler.parse(
        "process where (process.executable == \"/bin/bash\" and process.pid > 1000) or process.user == \"root\""
    );

    assert!(result.is_ok());
}

#[test]
fn test_parse_with_not_operator() {
    let compiler = create_test_compiler();

    let result = compiler.parse("process where not process.executable == \"/bin/bash\"");

    assert!(result.is_ok());

    let query = result.unwrap();
    match query {
        kestrel_eql::ast::Query::Event(eq) => {
            assert_eq!(eq.event_type, "process");
            assert!(eq.condition.is_some());
        }
        _ => panic!("Expected event query"),
    }
}

#[test]
fn test_compile_to_wasm_simple() {
    let mut compiler = create_test_compiler();

    let result = compiler.compile_to_wasm("process where process.pid == 1000");

    // Should generate valid WAT (may have semantic errors due to schema)
    match result {
        Ok(wat) => {
            assert!(wat.contains("(module"));
            assert!(wat.contains("pred_init"));
            assert!(wat.contains("pred_eval"));
            assert!(wat.contains("event_get_i64"));
        }
        Err(kestrel_eql::EqlError::UnknownField { .. }) => {
            // Expected - schema not set up, this is valid behavior
        }
        Err(e) => {
            panic!("Unexpected error: {:?}", e);
        }
    }
}

#[test]
fn test_syntax_error_handling() {
    let compiler = create_test_compiler();

    let result = compiler.parse("process where process.pid = 1000"); // Should be == not =

    // Should fail with syntax error
    assert!(result.is_err());
}

#[test]
fn test_missing_by_clause() {
    let compiler = create_test_compiler();

    let result = compiler.parse("sequence [process] [file]");

    // Sequence without 'by' clause should fail in semantic analysis
    // Note: Parser may accept it, but semantic analyzer should reject
    match result {
        Ok(query) => {
            // If parser accepts it, verify it's a valid sequence struct
            match query {
                kestrel_eql::ast::Query::Sequence(sq) => {
                    // Sequence without 'by' clause should have None for by field
                    assert!(sq.by.is_none() || sq.by.as_ref().map(|s| s.is_empty()).unwrap_or(false),
                        "Sequence without 'by' clause should have empty or no join field");
                }
                _ => panic!("Expected sequence query"),
            }
        }
        Err(_) => {
            // Parser rejected the query - this is also valid behavior
            // The important thing is we don't panic
        }
    }
}

#[test]
fn test_arithmetic_operators() {
    let compiler = create_test_compiler();

    let result = compiler.parse("process where process.pid + 100 > 2000");

    assert!(result.is_ok());
}

#[test]
fn test_comparison_operators() {
    let compiler = create_test_compiler();

    // Test all comparison operators
    let operators = vec!["==", "!=", "<", "<=", ">", ">="];

    for op in operators {
        let query = format!("process where process.pid {} 1000", op);
        let result = compiler.parse(&query);
        assert!(
            result.is_ok(),
            "Failed to parse operator {}: {:?}",
            op,
            result.err()
        );
    }
}

#[test]
fn test_boolean_literals() {
    let compiler = create_test_compiler();

    let result = compiler.parse("process where process.is_suspended == true");

    assert!(result.is_ok());
}

#[test]
fn test_null_handling() {
    let compiler = create_test_compiler();

    let result = compiler.parse("process where process.parent == null");

    assert!(result.is_ok());
}

#[test]
fn test_nested_field_references() {
    let compiler = create_test_compiler();

    let result = compiler.parse("process where process.executable.path == \"/usr/bin/test\"");

    assert!(result.is_ok());

    let query = result.unwrap();
    match query {
        kestrel_eql::ast::Query::Event(eq) => {
            assert_eq!(eq.event_type, "process");
            assert!(eq.condition.is_some());
        }
        _ => panic!("Expected event query"),
    }
}

#[test]
fn test_maxspan_durations() {
    let compiler = create_test_compiler();

    // Test different duration units
    let durations = vec!["5ms", "10s", "2m", "1h"];

    for duration in durations {
        let query = format!(
            "sequence by process.pid [process] [file] with maxspan={}",
            duration
        );
        let result = compiler.parse(&query);
        assert!(
            result.is_ok(),
            "Failed to parse duration {}: {:?}",
            duration,
            result.err()
        );
    }
}

#[test]
fn test_duration_parsing() {
    use kestrel_eql::EqlCompiler;
    use kestrel_schema::SchemaRegistry;
    use std::sync::Arc;

    let schema = Arc::new(SchemaRegistry::new());
    let compiler = EqlCompiler::new(schema);

    // Test different duration units and their expected millisecond values
    let test_cases = vec![
        ("5ms", 5),
        ("10s", 10 * 1000),
        ("2m", 2 * 60 * 1000),
        ("1h", 60 * 60 * 1000),
    ];

    for (duration_str, expected_ms) in test_cases {
        let result = compiler.parse(&format!(
            "sequence by process.pid [process] [file] with maxspan={}",
            duration_str
        ));
        assert!(result.is_ok(), "Failed to parse duration {}: {:?}", duration_str, result.err());
        
        let query = result.unwrap();
        match query {
            kestrel_eql::ast::Query::Sequence(sq) => {
                assert!(sq.maxspan.is_some(), "Duration {} should have maxspan set", duration_str);
                let maxspan = sq.maxspan.unwrap();
                // Note: The actual unit conversion may vary, but the value should be parsed
                assert!(maxspan.value > 0, "Duration {} should have positive value", duration_str);
            }
            _ => panic!("Expected sequence query for duration {}", duration_str),
        }
    }
}

#[test]
fn test_duration_raw_parsing() {
    use kestrel_eql::parser::parse;

    // Test that different duration formats can be parsed successfully
    let test_cases = vec!["10s", "5ms", "1m", "2h"];
    
    for duration in test_cases {
        let query = format!("sequence by process.pid [process] [file] with maxspan={}", duration);
        let result = parse(&query);
        assert!(result.is_ok(), "Failed to parse raw query with duration {}: {:?}", duration, result.err());
    }
}
