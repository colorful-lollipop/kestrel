//! Comprehensive Event Tests
//!
//! Event结构体综合测试

use kestrel_event::Event;
use kestrel_schema::{SchemaRegistry, TypedValue};

// =============================================================================
// Test 1-50: 基础事件创建
// =============================================================================

#[test]
fn test_event_creation_minimal() {
    let event = Event::builder()
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(1)
        .build()
        .unwrap();

    assert_eq!(event.event_type_id, 1);
    assert_eq!(event.ts_mono_ns, 1000);
    assert_eq!(event.entity_key, 1);
}

#[test]
fn test_event_creation_with_fields() {
    let schema = SchemaRegistry::new();
    let field_id = schema
        .register_field(kestrel_schema::FieldDef {
            path: "test.field".to_string(),
            data_type: kestrel_schema::FieldDataType::String,
            description: None,
        })
        .unwrap();

    let event = Event::builder()
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(1)
        .field(field_id, TypedValue::String("test".into()))
        .build()
        .unwrap();

    assert_eq!(event.get_field(field_id), Some(&TypedValue::String("test".into())));
}

#[test]
fn test_event_max_event_id() {
    let event = Event::builder()
        .event_id(u64::MAX)
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(1)
        .build()
        .unwrap();

    assert_eq!(event.event_id, u64::MAX);
}

#[test]
fn test_event_zero_timestamps() {
    let event = Event::builder()
        .event_type(1)
        .ts_mono(0)
        .ts_wall(0)
        .entity_key(1)
        .build()
        .unwrap();

    assert_eq!(event.ts_mono_ns, 0);
    assert_eq!(event.ts_wall_ns, 0);
}

#[test]
fn test_event_entity_key_boundaries() {
    let keys = [0u128, 1, u64::MAX as u128, u128::MAX];

    for key in keys {
        let event = Event::builder()
            .event_type(1)
            .ts_mono(1000)
            .ts_wall(1000)
            .entity_key(key)
            .build()
            .unwrap();

        assert_eq!(event.entity_key, key);
    }
}
