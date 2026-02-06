//! Kestrel Event Schema
//!
//! This module defines the type system and schema for events in the Kestrel detection engine.
//! Events are strongly typed with field IDs for performance and reproducibility.

use ahash::AHashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Field identifier (u32 for fast lookup)
pub type FieldId = u32;

/// Event type identifier
pub type EventTypeId = u16;

/// Entity key for grouping events (e.g., by process, session, container)
pub type EntityKey = u128;

/// Timestamp in nanoseconds (monotonic)
pub type TimestampMono = u64;

/// Timestamp in nanoseconds (wall clock)
pub type TimestampWall = u64;

/// Event handle for Host API
pub type EventHandle = u32;

/// Regex ID (pre-compiled regex handle)
pub type RegexId = u32;

/// Glob ID (pre-compiled glob handle)
pub type GlobId = u32;

// ============================================================================
// Common Types - Extracted from runtime crates to eliminate duplication
// ============================================================================

/// Severity levels for alerts and rules
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Informational => write!(f, "Informational"),
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Medium
    }
}

/// Rule metadata - shared between all rule types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    /// Unique rule identifier
    pub rule_id: String,
    /// Rule name
    pub rule_name: String,
    /// Rule version
    pub rule_version: String,
    /// Rule author
    pub author: Option<String>,
    /// Rule description
    pub description: Option<String>,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Severity level
    pub severity: String,
    /// Schema version
    pub schema_version: String,
}

impl RuleMetadata {
    /// Create a new rule metadata with default values
    pub fn new(rule_id: impl Into<String>, rule_name: impl Into<String>) -> Self {
        Self {
            rule_id: rule_id.into(),
            rule_name: rule_name.into(),
            rule_version: "1.0.0".to_string(),
            author: None,
            description: None,
            tags: Vec::new(),
            severity: "medium".to_string(),
            schema_version: "1.0".to_string(),
        }
    }

    /// Set the severity
    pub fn with_severity(mut self, severity: impl Into<String>) -> Self {
        self.severity = severity.into();
        self
    }

    /// Set the description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the author
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    /// Add tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

/// Rule capabilities - defines what a rule can do
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCapabilities {
    /// Supports inline execution
    pub supports_inline: bool,
    /// Requires alert capability
    pub requires_alert: bool,
    /// Requires block capability
    pub requires_block: bool,
    /// Maximum span for sequence rules
    pub max_span_ms: Option<u64>,
}

impl Default for RuleCapabilities {
    fn default() -> Self {
        Self {
            supports_inline: false,
            requires_alert: true,
            requires_block: false,
            max_span_ms: None,
        }
    }
}

impl RuleCapabilities {
    /// Create default capabilities for a detection rule
    pub fn detection() -> Self {
        Self {
            supports_inline: false,
            requires_alert: true,
            requires_block: false,
            max_span_ms: None,
        }
    }

    /// Create capabilities for inline blocking rule
    pub fn inline_blocking() -> Self {
        Self {
            supports_inline: true,
            requires_alert: true,
            requires_block: true,
            max_span_ms: None,
        }
    }
}

/// Rule package manifest - used for loading rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleManifest {
    /// Manifest format version
    pub format_version: String,
    /// Rule metadata
    pub metadata: RuleMetadata,
    /// Rule capabilities
    pub capabilities: RuleCapabilities,
}

impl RuleManifest {
    /// Create a new manifest with the given metadata
    pub fn new(metadata: RuleMetadata) -> Self {
        Self {
            format_version: "1.0".to_string(),
            metadata,
            capabilities: RuleCapabilities::default(),
        }
    }

    /// Set capabilities
    pub fn with_capabilities(mut self, capabilities: RuleCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }
}

/// Runtime type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuntimeType {
    /// WebAssembly runtime
    Wasm,
    /// Lua/LuaJIT runtime
    Lua,
    /// Native runtime (for built-in predicates)
    Native,
}

impl std::fmt::Display for RuntimeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeType::Wasm => write!(f, "wasm"),
            RuntimeType::Lua => write!(f, "lua"),
            RuntimeType::Native => write!(f, "native"),
        }
    }
}

/// Runtime capabilities - what features a runtime supports
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RuntimeCapabilities {
    /// Supports regex matching
    pub regex: bool,
    /// Supports glob pattern matching
    pub glob: bool,
    /// Supports string manipulation functions
    pub string_ops: bool,
    /// Supports mathematical operations
    pub math_ops: bool,
    /// Maximum memory per evaluation (in MB)
    pub max_memory_mb: usize,
    /// Maximum execution time per evaluation (in ms)
    pub max_execution_time_ms: u64,
}

impl Default for RuntimeCapabilities {
    fn default() -> Self {
        Self {
            regex: true,
            glob: true,
            string_ops: true,
            math_ops: true,
            max_memory_mb: 128,
            max_execution_time_ms: 100,
        }
    }
}

/// Common runtime configuration trait
pub trait RuntimeConfig: Clone + Send + Sync {
    /// Get maximum memory in MB
    fn max_memory_mb(&self) -> usize;
    /// Get maximum execution time in milliseconds
    fn max_execution_time_ms(&self) -> u64;
    /// Get instruction/fuel limit if applicable
    fn instruction_limit(&self) -> Option<u64>;
}

/// Evaluation result from a runtime - unified across all runtimes
#[derive(Debug, Clone)]
pub struct EvalResult {
    /// Whether the predicate matched
    pub matched: bool,
    /// Optional error message
    pub error: Option<String>,
    /// Captured field values
    pub captured_fields: AHashMap<String, TypedValue>,
}

impl EvalResult {
    /// Create a successful match result
    pub fn matched() -> Self {
        Self {
            matched: true,
            error: None,
            captured_fields: AHashMap::new(),
        }
    }

    /// Create a non-match result
    pub fn not_matched() -> Self {
        Self {
            matched: false,
            error: None,
            captured_fields: AHashMap::new(),
        }
    }

    /// Create an error result
    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            matched: false,
            error: Some(msg.into()),
            captured_fields: AHashMap::new(),
        }
    }

    /// Add a captured field
    pub fn with_capture(mut self, key: impl Into<String>, value: TypedValue) -> Self {
        self.captured_fields.insert(key.into(), value);
        self
    }
}

/// Alert record for Host API - unified structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRecord {
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub event_handles: Vec<EventHandle>,
    pub fields: AHashMap<String, TypedValue>,
}

// ============================================================================
// Schema Registry
// ============================================================================

/// Schema registry that maintains field definitions and type information
/// 
/// Uses DashMap for concurrent access without locking, providing better
/// performance under high concurrency.
#[derive(Debug)]
pub struct SchemaRegistry {
    /// Field ID to definition mapping
    fields: dashmap::DashMap<FieldId, FieldDef>,
    /// Field path to ID mapping for fast lookups
    field_paths: dashmap::DashMap<String, FieldId>,
    /// Event type definitions
    event_types: dashmap::DashMap<EventTypeId, EventTypeDef>,
    /// Event type name to ID mapping
    event_type_names: dashmap::DashMap<String, EventTypeId>,
    /// Next available field ID
    next_field_id: std::sync::atomic::AtomicU32,
    /// Next available event type ID
    next_event_type_id: std::sync::atomic::AtomicU16,
}

impl Clone for SchemaRegistry {
    fn clone(&self) -> Self {
        // Clone all data from DashMaps to new ones
        Self {
            fields: self.fields.clone(),
            field_paths: self.field_paths.clone(),
            event_types: self.event_types.clone(),
            event_type_names: self.event_type_names.clone(),
            next_field_id: std::sync::atomic::AtomicU32::new(
                self.next_field_id.load(std::sync::atomic::Ordering::SeqCst)
            ),
            next_event_type_id: std::sync::atomic::AtomicU16::new(
                self.next_event_type_id.load(std::sync::atomic::Ordering::SeqCst)
            ),
        }
    }
}

impl Default for SchemaRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SchemaRegistry {
    /// Create a new schema registry
    pub fn new() -> Self {
        Self {
            fields: dashmap::DashMap::new(),
            field_paths: dashmap::DashMap::new(),
            event_types: dashmap::DashMap::new(),
            event_type_names: dashmap::DashMap::new(),
            next_field_id: std::sync::atomic::AtomicU32::new(1),
            next_event_type_id: std::sync::atomic::AtomicU16::new(1),
        }
    }

    /// Register a field definition and return its ID
    pub fn register_field(&self, def: FieldDef) -> Result<FieldId, SchemaError> {
        // Check if field already exists
        if self.field_paths.contains_key(&def.path) {
            return Err(SchemaError::FieldAlreadyExists(def.path));
        }

        // Get next ID atomically
        let id = self.next_field_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        // Insert into both maps
        self.field_paths.insert(def.path.clone(), id);
        self.fields.insert(id, def);

        Ok(id)
    }

    /// Register an event type definition
    pub fn register_event_type(&self, def: EventTypeDef) -> Result<EventTypeId, SchemaError> {
        // Check if event type already exists
        if self.event_type_names.contains_key(&def.name) {
            return Err(SchemaError::EventTypeAlreadyExists(def.name));
        }

        // Get next ID atomically
        let id = self.next_event_type_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        // Insert into both maps
        self.event_type_names.insert(def.name.clone(), id);
        self.event_types.insert(id, def);

        Ok(id)
    }

    /// Get event type ID by name
    pub fn get_event_type_id(&self, name: &str) -> Option<EventTypeId> {
        self.event_type_names.get(name).map(|v| *v.value())
    }

    /// Get field definition by ID
    pub fn get_field(&self, id: FieldId) -> Option<FieldDef> {
        self.fields.get(&id).map(|v| v.value().clone())
    }

    /// Get field ID by path
    pub fn get_field_id(&self, path: &str) -> Option<FieldId> {
        self.field_paths.get(path).map(|v| *v.value())
    }

    /// Get event type definition by ID
    pub fn get_event_type(&self, id: EventTypeId) -> Option<EventTypeDef> {
        self.event_types.get(&id).map(|v| v.value().clone())
    }

    /// List all registered fields
    pub fn list_fields(&self) -> Vec<(FieldId, FieldDef)> {
        self.fields
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect()
    }

    /// List all registered event types
    pub fn list_event_types(&self) -> Vec<(EventTypeId, EventTypeDef)> {
        self.event_types
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect()
    }
}

/// Field definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDef {
    /// Unique field path (e.g., "process.executable")
    pub path: String,
    /// Field data type
    pub data_type: FieldDataType,
    /// Optional description
    pub description: Option<String>,
}

/// Field data types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldDataType {
    /// Signed integer
    I64,
    /// Unsigned integer
    U64,
    /// String
    String,
    /// Boolean
    Bool,
    /// Floating point
    F64,
    /// Byte array
    Bytes,
    /// Array
    Array,
}

/// Event type definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventTypeDef {
    /// Event type name (e.g., "process_exec", "file_open")
    pub name: String,
    /// Optional description
    pub description: Option<String>,
    /// Optional parent event type
    pub parent: Option<EventTypeId>,
}

/// Typed field value
#[derive(Debug, Clone, PartialEq)]
pub enum TypedValue {
    I64(i64),
    U64(u64),
    F64(f64),
    Bool(bool),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<TypedValue>),
    Null,
}

// Implement custom serialization for TypedValue
impl serde::Serialize for TypedValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            TypedValue::I64(v) => serializer.serialize_newtype_variant("TypedValue", 0, "I64", v),
            TypedValue::U64(v) => serializer.serialize_newtype_variant("TypedValue", 1, "U64", v),
            TypedValue::F64(v) => serializer.serialize_newtype_variant("TypedValue", 2, "F64", v),
            TypedValue::Bool(v) => serializer.serialize_newtype_variant("TypedValue", 3, "Bool", v),
            TypedValue::String(v) => {
                serializer.serialize_newtype_variant("TypedValue", 4, "String", v)
            }
            TypedValue::Bytes(v) => {
                serializer.serialize_newtype_variant("TypedValue", 5, "Bytes", v)
            }
            TypedValue::Array(v) => {
                serializer.serialize_newtype_variant("TypedValue", 6, "Array", v)
            }
            TypedValue::Null => serializer.serialize_unit_variant("TypedValue", 7, "Null"),
        }
    }
}

impl<'de> serde::Deserialize<'de> for TypedValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::VariantAccess;

        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            I64,
            U64,
            F64,
            Bool,
            String,
            Bytes,
            Array,
            Null,
        }

        struct TypedValueVisitor;

        impl<'de> serde::de::Visitor<'de> for TypedValueVisitor {
            type Value = TypedValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a TypedValue variant")
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::EnumAccess<'de>,
            {
                match data.variant::<Field>()? {
                    (Field::I64, v) => v.newtype_variant().map(TypedValue::I64),
                    (Field::U64, v) => v.newtype_variant().map(TypedValue::U64),
                    (Field::F64, v) => v.newtype_variant().map(TypedValue::F64),
                    (Field::Bool, v) => v.newtype_variant().map(TypedValue::Bool),
                    (Field::String, v) => v.newtype_variant().map(TypedValue::String),
                    (Field::Bytes, v) => v.newtype_variant().map(TypedValue::Bytes),
                    (Field::Array, v) => v.newtype_variant().map(TypedValue::Array),
                    (Field::Null, v) => {
                        v.unit_variant()?;
                        Ok(TypedValue::Null)
                    }
                }
            }
        }

        deserializer.deserialize_enum(
            "TypedValue",
            &[
                "i64", "u64", "f64", "bool", "string", "bytes", "array", "null",
            ],
            TypedValueVisitor,
        )
    }
}

impl TypedValue {
    /// Get as i64 if possible
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            TypedValue::I64(v) => Some(*v),
            TypedValue::U64(v) => i64::try_from(*v).ok(),
            _ => None,
        }
    }

    /// Get as u64 if possible
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            TypedValue::U64(v) => Some(*v),
            TypedValue::I64(v) => u64::try_from(*v).ok(),
            _ => None,
        }
    }

    /// Get as string if possible
    pub fn as_str(&self) -> Option<&str> {
        match self {
            TypedValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get as bool if possible
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            TypedValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Get as f64 if possible
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            TypedValue::F64(v) => Some(*v),
            TypedValue::I64(v) => Some(*v as f64),
            TypedValue::U64(v) => Some(*v as f64),
            _ => None,
        }
    }

    /// Check if value is null
    pub fn is_null(&self) -> bool {
        matches!(self, TypedValue::Null)
    }
}

/// Schema errors
#[derive(Debug, Error)]
pub enum SchemaError {
    #[error("Field already exists: {0}")]
    FieldAlreadyExists(String),

    #[error("Event type already exists: {0}")]
    EventTypeAlreadyExists(String),

    #[error("Field not found: {0}")]
    FieldNotFound(String),

    #[error("Event type not found: {0}")]
    EventTypeNotFound(String),

    #[error("Type mismatch: expected {expected}, got {actual}")]
    TypeMismatch { expected: String, actual: String },

    #[error("Lock error: {0}")]
    LockError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_field() {
        let registry = SchemaRegistry::new();
        let field = FieldDef {
            path: "process.executable".to_string(),
            data_type: FieldDataType::String,
            description: Some("Process executable path".to_string()),
        };

        let id = registry.register_field(field).unwrap();
        assert_eq!(id, 1);

        let retrieved = registry.get_field(id).unwrap();
        assert_eq!(retrieved.path, "process.executable");
        assert_eq!(retrieved.data_type, FieldDataType::String);
    }

    #[test]
    fn test_field_path_lookup() {
        let registry = SchemaRegistry::new();
        let field = FieldDef {
            path: "process.pid".to_string(),
            data_type: FieldDataType::U64,
            description: None,
        };

        registry.register_field(field).unwrap();
        let id = registry.get_field_id("process.pid").unwrap();
        assert_eq!(id, 1);
    }

    #[test]
    fn test_duplicate_field() {
        let registry = SchemaRegistry::new();
        let field = FieldDef {
            path: "process.name".to_string(),
            data_type: FieldDataType::String,
            description: None,
        };

        registry.register_field(field.clone()).unwrap();
        let result = registry.register_field(field);
        assert!(matches!(result, Err(SchemaError::FieldAlreadyExists(_))));
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Critical.to_string(), "Critical");
        assert_eq!(Severity::High.to_string(), "High");
        assert_eq!(Severity::Medium.to_string(), "Medium");
        assert_eq!(Severity::Low.to_string(), "Low");
        assert_eq!(Severity::Informational.to_string(), "Informational");
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Informational);
    }

    #[test]
    fn test_rule_metadata_builder() {
        let meta = RuleMetadata::new("rule-001", "Test Rule")
            .with_severity("high")
            .with_description("A test rule")
            .with_author("Test Author");

        assert_eq!(meta.rule_id, "rule-001");
        assert_eq!(meta.rule_name, "Test Rule");
        assert_eq!(meta.severity, "high");
        assert_eq!(meta.description, Some("A test rule".to_string()));
        assert_eq!(meta.author, Some("Test Author".to_string()));
    }

    #[test]
    fn test_eval_result() {
        let matched = EvalResult::matched();
        assert!(matched.matched);
        assert!(matched.error.is_none());

        let not_matched = EvalResult::not_matched();
        assert!(!not_matched.matched);

        let error = EvalResult::error("test error");
        assert!(!error.matched);
        assert_eq!(error.error, Some("test error".to_string()));

        let with_capture = EvalResult::matched()
            .with_capture("field1", TypedValue::I64(42));
        assert_eq!(with_capture.captured_fields.get("field1"), Some(&TypedValue::I64(42)));
    }
}
