//! Shared host API functions for rule runtimes
//!
//! These functions provide the business logic for host API calls,
//! independent of the specific runtime (Wasm, Lua, etc.).

use ahash::AHashMap;
use glob::Pattern;
use kestrel_schema::{AlertRecord, FieldId, GlobId, RegexId, RuleMetadata, TypedValue};
use parking_lot::{Mutex, RwLock};
use regex::Regex;

use crate::Event;

/// Shared host API v1 for runtime integrations (Wasm, Lua, etc.)
pub trait HostApiV1 {
    /// Get i64 field from event by FieldId
    fn event_get_i64(&self, field_id: u32) -> Option<i64>;

    /// Get u64 field from event by FieldId
    fn event_get_u64(&self, field_id: u32) -> Option<u64>;

    /// Get string field from event by FieldId
    fn event_get_str(&self, field_id: u32) -> Option<&str>;

    /// Get bool field from event by FieldId
    fn event_get_bool(&self, field_id: u32) -> Option<bool>;

    /// Check if cached regex pattern matches text
    fn re_match(&self, pattern_id: u32, text: &str) -> bool;

    /// Check if cached glob pattern matches text
    fn glob_match(&self, pattern_id: u32, text: &str) -> bool;

    /// Emit an alert
    fn alert_emit(&self, event_handle: u32) -> i32;
}

/// Concrete context implementing [`HostApiV1`] for use during predicate evaluation.
pub struct HostApiContext<'a> {
    /// The event being evaluated, if any.
    pub event: Option<&'a Event>,
    /// Cache of compiled regex patterns.
    pub regex_cache: &'a RwLock<AHashMap<RegexId, Regex>>,
    /// Cache of compiled glob patterns.
    pub glob_cache: &'a RwLock<AHashMap<GlobId, Pattern>>,
    /// Alert buffer.
    pub alerts: &'a Mutex<Vec<AlertRecord>>,
    /// Rule metadata for alert construction.
    pub rule_metadata: Option<&'a RuleMetadata>,
}

impl<'a> HostApiContext<'a> {
    /// Create a new host API context.
    pub fn new(
        event: Option<&'a Event>,
        regex_cache: &'a RwLock<AHashMap<RegexId, Regex>>,
        glob_cache: &'a RwLock<AHashMap<GlobId, Pattern>>,
        alerts: &'a Mutex<Vec<AlertRecord>>,
        rule_metadata: Option<&'a RuleMetadata>,
    ) -> Self {
        Self {
            event,
            regex_cache,
            glob_cache,
            alerts,
            rule_metadata,
        }
    }
}

impl<'a> HostApiV1 for HostApiContext<'a> {
    fn event_get_i64(&self, field_id: u32) -> Option<i64> {
        let event = self.event?;
        match event.get_field(field_id) {
            Some(TypedValue::I64(v)) => Some(*v),
            Some(TypedValue::U64(v)) => {
                if *v > i64::MAX as u64 {
                    Some(i64::MAX)
                } else {
                    Some(*v as i64)
                }
            },
            Some(TypedValue::Bool(v)) => Some(if *v { 1 } else { 0 }),
            _ => None,
        }
    }

    fn event_get_u64(&self, field_id: u32) -> Option<u64> {
        let event = self.event?;
        match event.get_field(field_id) {
            Some(TypedValue::U64(v)) => Some(*v),
            Some(TypedValue::I64(v)) => {
                if *v < 0 {
                    Some(0)
                } else {
                    Some(*v as u64)
                }
            },
            Some(TypedValue::Bool(v)) => Some(if *v { 1 } else { 0 }),
            _ => None,
        }
    }

    fn event_get_str(&self, field_id: u32) -> Option<&str> {
        let event = self.event?;
        match event.get_field(field_id) {
            Some(TypedValue::String(s)) => Some(s.as_ref()),
            _ => None,
        }
    }

    fn event_get_bool(&self, field_id: u32) -> Option<bool> {
        let event = self.event?;
        match event.get_field(field_id) {
            Some(TypedValue::Bool(v)) => Some(*v),
            Some(TypedValue::I64(v)) => Some(*v != 0),
            Some(TypedValue::U64(v)) => Some(*v != 0),
            _ => None,
        }
    }

    fn re_match(&self, pattern_id: u32, text: &str) -> bool {
        let cache = self.regex_cache.read();
        cache.get(&pattern_id).map_or(false, |re| re.is_match(text))
    }

    fn glob_match(&self, pattern_id: u32, text: &str) -> bool {
        let cache = self.glob_cache.read();
        cache
            .get(&pattern_id)
            .map_or(false, |pattern| pattern.matches(text))
    }

    fn alert_emit(&self, event_handle: u32) -> i32 {
        let event = match self.event {
            Some(e) => e,
            None => return -1,
        };

        let mut fields = AHashMap::new();
        for (field_id, value) in &event.fields {
            fields.insert(format!("field_{}", field_id), value.clone());
        }

        let alert = match self.rule_metadata {
            Some(meta) => AlertRecord {
                rule_id: meta.rule_id.clone(),
                severity: meta.severity.clone(),
                title: meta.rule_name.clone(),
                description: meta.description.clone(),
                event_handles: vec![event_handle],
                fields,
            },
            None => AlertRecord {
                rule_id: "unknown".to_string(),
                severity: "medium".to_string(),
                title: "Alert".to_string(),
                description: None,
                event_handles: vec![event_handle],
                fields,
            },
        };

        self.alerts.lock().push(alert);
        0
    }
}

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
