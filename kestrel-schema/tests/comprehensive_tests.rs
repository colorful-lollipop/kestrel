//! Comprehensive Schema Tests
use kestrel_schema::{RuleMetadata, SchemaRegistry, Severity, TypedValue};

#[test]
fn test_schema_creation() {
    let _schema = SchemaRegistry::new();
}

#[test]
fn test_typed_value_equality() {
    assert_eq!(TypedValue::Bool(true), TypedValue::Bool(true));
    assert_eq!(TypedValue::I64(-42), TypedValue::I64(-42));
    assert_eq!(TypedValue::U64(42), TypedValue::U64(42));
    assert_eq!(TypedValue::String("test".into()), TypedValue::String("test".into()));
}

#[test]
fn test_typed_value_inequality() {
    assert_ne!(TypedValue::Bool(true), TypedValue::Bool(false));
    assert_ne!(TypedValue::I64(42), TypedValue::I64(-42));
    assert_ne!(TypedValue::String("a".into()), TypedValue::String("b".into()));
}

#[test]
fn test_typed_value_variants() {
    let _ = TypedValue::Bool(true);
    let _ = TypedValue::I64(-1);
    let _ = TypedValue::U64(1);
    let _ = TypedValue::F64(1.0);
    let _ = TypedValue::String("test".into());
}

#[test]
fn test_typed_value_clone() {
    let value = TypedValue::String("test".into());
    let cloned = value.clone();
    assert_eq!(value, cloned);
}

#[test]
fn test_severity_ordering() {
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
fn test_rule_metadata_creation() {
    let metadata = RuleMetadata::new("rule1", "Test Rule");
    assert_eq!(metadata.rule_id, "rule1");
    assert_eq!(metadata.rule_name, "Test Rule");
}

#[test]
fn test_rule_metadata_with_severity() {
    let metadata = RuleMetadata::new("rule1", "Test Rule").with_severity("high");
    assert_eq!(metadata.severity, "high");
}

#[test]
fn test_rule_metadata_with_description() {
    let metadata = RuleMetadata::new("rule1", "Test Rule").with_description("Test description");
    assert_eq!(metadata.description, Some("Test description".to_string()));
}

#[test]
fn test_rule_metadata_with_author() {
    let metadata = RuleMetadata::new("rule1", "Test Rule").with_author("Test Author");
    assert_eq!(metadata.author, Some("Test Author".to_string()));
}

#[test]
fn test_rule_metadata_with_tags() {
    let metadata = RuleMetadata::new("rule1", "Test Rule")
        .with_tags(vec!["tag1".to_string(), "tag2".to_string()]);
    assert_eq!(metadata.tags, vec!["tag1", "tag2"]);
}

#[test]
fn test_severity_default() {
    let default = Severity::default();
    assert_eq!(default, Severity::Medium);
}

#[test]
fn test_typed_value_debug() {
    let value = TypedValue::String("test".into());
    let debug = format!("{:?}", value);
    assert!(debug.contains("test"));
}

#[test]
fn test_rule_metadata_default() {
    let metadata = RuleMetadata::new("rule1", "Test Rule");
    assert_eq!(metadata.rule_version, "1.0.0");
    assert_eq!(metadata.schema_version, "1.0");
}
