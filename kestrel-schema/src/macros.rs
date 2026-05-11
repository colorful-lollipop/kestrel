//! Shared macros for the Kestrel project

/// Map a Result's error to a string-wrapped variant
///
/// Usage: `map_err_string!(result, ErrorType::Variant)`
#[macro_export]
macro_rules! map_err_string {
    ($result:expr, $variant:path) => {
        $result.map_err(|e| $variant(e.to_string()))
    };
}

/// Map a Result's error to a string-wrapped variant with context
///
/// Usage: `map_err_string_ctx!(result, ErrorType::Variant, "context")`
#[macro_export]
macro_rules! map_err_string_ctx {
    ($result:expr, $variant:path, $ctx:expr) => {
        $result.map_err(|e| $variant(format!("{}: {}", $ctx, e)))
    };
}
