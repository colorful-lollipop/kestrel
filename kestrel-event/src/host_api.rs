//! Shared host API functions for rule runtimes
//!
//! These functions provide the business logic for host API calls,
//! independent of the specific runtime (Wasm, Lua, etc.).

use crate::Event;
use kestrel_schema::{FieldId, TypedValue};

/// Get an i64 field from an event
pub fn event_get_i64(event: &Event, field_id: FieldId) -> i64 {
    match event.get_field(field_id) {
        Some(TypedValue::I64(v)) => *v,
        Some(TypedValue::U64(v)) => {
            if *v >= i64::MAX as u64 {
                i64::MAX
            } else {
                *v as i64
            }
        },
        _ => 0,
    }
}

/// Get a u64 field from an event
pub fn event_get_u64(event: &Event, field_id: FieldId) -> u64 {
    match event.get_field(field_id) {
        Some(TypedValue::U64(v)) => *v,
        Some(TypedValue::I64(v)) => {
            if *v < 0 {
                0
            } else {
                *v as u64
            }
        },
        _ => 0,
    }
}

/// Get a string field from an event
pub fn event_get_string(event: &Event, field_id: FieldId) -> String {
    match event.get_field(field_id) {
        Some(TypedValue::String(s)) => s.to_string(),
        _ => String::new(),
    }
}

/// Get a bool field from an event
pub fn event_get_bool(event: &Event, field_id: FieldId) -> bool {
    match event.get_field(field_id) {
        Some(TypedValue::Bool(b)) => *b,
        Some(TypedValue::I64(v)) => *v != 0,
        Some(TypedValue::U64(v)) => *v != 0,
        _ => false,
    }
}
