//! Kestrel Event Schema
//!
//! This module defines the type system and schema for events in the Kestrel detection engine.
//! Events are strongly typed with field IDs for performance and reproducibility.

use ahash::AHashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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

/// Schema registry that maintains field definitions and type information
#[derive(Debug, Clone)]
pub struct SchemaRegistry {
    /// Field ID to definition mapping
    fields: Arc<AHashMap<FieldId, FieldDef>>,
    /// Field path to ID mapping for fast lookups
    field_paths: Arc<AHashMap<String, FieldId>>,
    /// Event type definitions
    event_types: Arc<AHashMap<EventTypeId, EventTypeDef>>,
    /// Event type name to ID mapping
    event_type_names: Arc<AHashMap<String, EventTypeId>>,
    /// Next available field ID
    next_field_id: FieldId,
    /// Next available event type ID
    next_event_type_id: EventTypeId,
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
            fields: Arc::new(AHashMap::default()),
            field_paths: Arc::new(AHashMap::default()),
            event_types: Arc::new(AHashMap::default()),
            event_type_names: Arc::new(AHashMap::default()),
            next_field_id: 1,
            next_event_type_id: 1,
        }
    }

    /// Register a field definition and return its ID
    pub fn register_field(&mut self, def: FieldDef) -> Result<FieldId, SchemaError> {
        if self.field_paths.contains_key(&def.path) {
            return Err(SchemaError::FieldAlreadyExists(def.path));
        }

        let id = self.next_field_id;
        self.next_field_id += 1;

        let mut fields = (*self.fields).clone();
        fields.insert(id, def.clone());

        let mut paths = (*self.field_paths).clone();
        paths.insert(def.path.clone(), id);

        self.fields = Arc::new(fields);
        self.field_paths = Arc::new(paths);

        Ok(id)
    }

    /// Register an event type definition
    pub fn register_event_type(&mut self, def: EventTypeDef) -> Result<EventTypeId, SchemaError> {
        if self.event_type_names.contains_key(&def.name) {
            return Err(SchemaError::EventTypeAlreadyExists(def.name));
        }

        let id = self.next_event_type_id;
        self.next_event_type_id += 1;

        let mut types = (*self.event_types).clone();
        types.insert(id, def.clone());

        let mut names = (*self.event_type_names).clone();
        names.insert(def.name.clone(), id);

        self.event_types = Arc::new(types);
        self.event_type_names = Arc::new(names);

        Ok(id)
    }

    /// Get event type ID by name
    pub fn get_event_type_id(&self, name: &str) -> Option<EventTypeId> {
        self.event_type_names.get(name).copied()
    }

    /// Get field definition by ID
    pub fn get_field(&self, id: FieldId) -> Option<&FieldDef> {
        self.fields.get(&id)
    }

    /// Get field ID by path
    pub fn get_field_id(&self, path: &str) -> Option<FieldId> {
        self.field_paths.get(path).copied()
    }

    /// Get event type definition by ID
    pub fn get_event_type(&self, id: EventTypeId) -> Option<&EventTypeDef> {
        self.event_types.get(&id)
    }

    /// List all registered fields
    pub fn list_fields(&self) -> Vec<(FieldId, &FieldDef)> {
        self.fields.iter().map(|(id, def)| (*id, def)).collect()
    }

    /// List all registered event types
    pub fn list_event_types(&self) -> Vec<(EventTypeId, &EventTypeDef)> {
        self.event_types
            .iter()
            .map(|(id, def)| (*id, def))
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_field() {
        let mut registry = SchemaRegistry::new();
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
        let mut registry = SchemaRegistry::new();
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
        let mut registry = SchemaRegistry::new();
        let field = FieldDef {
            path: "process.name".to_string(),
            data_type: FieldDataType::String,
            description: None,
        };

        registry.register_field(field.clone()).unwrap();
        let result = registry.register_field(field);
        assert!(matches!(result, Err(SchemaError::FieldAlreadyExists(_))));
    }
}
