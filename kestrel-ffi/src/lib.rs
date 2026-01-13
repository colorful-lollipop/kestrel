//! Kestrel C FFI Layer
//!
//! This crate provides C-compatible FFI bindings for Kestrel detection engine.
//!
//! ## Safety
//!
//! The FFI layer maintains these safety guarantees:
//! - All pointers are validated before use
//! - Returned pointers must be freed by the caller
//! - All functions are thread-safe
//! - No panic across FFI boundary

use std::os::raw::c_char;

mod engine;
mod error;
mod event;
mod metrics;
mod types;

pub use error::KestrelError;
pub use types::*;

// Version information
pub const KESTREL_VERSION_MAJOR: u32 = 0;
pub const KESTREL_VERSION_MINOR: u32 = 2;
pub const KESTREL_VERSION_PATCH: u32 = 0;
pub const KESTREL_VERSION: &[u8] = b"0.2.0\0";

/// Get Kestrel version string
#[no_mangle]
pub extern "C" fn kestrel_version() -> *const c_char {
    KESTREL_VERSION.as_ptr() as *const c_char
}

/// Get last error message
///
/// # Safety
/// Caller must ensure the string is not modified and is used before
/// the next FFI call that might set an error.
#[no_mangle]
pub extern "C" fn kestrel_last_error() -> *const c_char {
    engine::get_last_error().unwrap_or(std::ptr::null())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let version_ptr = unsafe { std::ffi::CStr::from_ptr(kestrel_version()) };
        let version = version_ptr.to_str().unwrap();
        assert_eq!(version, "0.2.0");
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(KestrelError::Ok as i32, 0);
        assert_eq!(KestrelError::Unknown as i32, -1);
        assert_eq!(KestrelError::InvalidArg as i32, -2);
    }
}
