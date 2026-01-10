//! Error types for EQL compiler

use std::io;
use thiserror::Error;

/// EQL compiler error type
#[derive(Error, Debug)]
pub enum EqlError {
    /// Syntax error during parsing
    #[error("Syntax error at {location}: {message}")]
    SyntaxError { location: String, message: String },

    /// Semantic error (type checking, field resolution)
    #[error("Semantic error: {message}")]
    SemanticError { message: String },

    /// Type mismatch
    #[error("Type mismatch: expected {expected}, found {found}")]
    TypeMismatch {
        expected: String,
        found: String,
        location: String,
    },

    /// Unknown field
    #[error("Unknown field: {field_path}")]
    UnknownField {
        field_path: String,
        location: String,
    },

    /// Unknown event type
    #[error("Unknown event type: {event_type}")]
    UnknownEventType { event_type: String },

    /// Code generation error
    #[error("Code generation error: {message}")]
    CodegenError { message: String },

    /// IR validation error
    #[error("IR validation error: {message}")]
    IrError { message: String },
}

impl From<io::Error> for EqlError {
    fn from(err: io::Error) -> Self {
        EqlError::CodegenError {
            message: err.to_string(),
        }
    }
}

/// Result type for EQL operations
pub type Result<T> = std::result::Result<T, EqlError>;

impl EqlError {
    pub fn syntax(location: impl Into<String>, message: impl Into<String>) -> Self {
        EqlError::SyntaxError {
            location: location.into(),
            message: message.into(),
        }
    }

    pub fn semantic(message: impl Into<String>) -> Self {
        EqlError::SemanticError {
            message: message.into(),
        }
    }

    pub fn type_mismatch(
        expected: impl Into<String>,
        found: impl Into<String>,
        location: impl Into<String>,
    ) -> Self {
        EqlError::TypeMismatch {
            expected: expected.into(),
            found: found.into(),
            location: location.into(),
        }
    }

    pub fn unknown_field(field_path: impl Into<String>, location: impl Into<String>) -> Self {
        EqlError::UnknownField {
            field_path: field_path.into(),
            location: location.into(),
        }
    }
}
