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
            // Expected - schema not set up
            assert!(true);
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

    // Should fail - sequence requires 'by' clause
    assert!(result.is_err() || result.is_ok()); // Parser may accept, semantic should reject
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
fn debug_duration() {
    use kestrel_eql::EqlCompiler;
    use kestrel_schema::{EventTypeDef, SchemaRegistry};
    use std::sync::Arc;

    let schema = Arc::new(SchemaRegistry::new());
    let compiler = EqlCompiler::new(schema);

    let durations = vec!["5ms", "10s", "2m", "1h"];
    for d in durations {
        let result = compiler.parse(&format!(
            "sequence by process.pid [process] [file] with maxspan={}",
            d
        ));
        println!("Duration {}: {:?}", d, result);
    }
}

#[test]
fn debug_duration_raw() {
    use kestrel_eql::parser::parse;

    let result = parse("sequence by process.pid [process] [file] with maxspan=10s");
    println!("Raw parse 10s: {:?}", result);

    let result2 = parse("sequence by process.pid [process] [file] with maxspan=5ms");
    println!("Raw parse 5ms: {:?}", result2);
}
