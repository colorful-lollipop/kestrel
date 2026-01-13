//! Error types for FFI layer

use std::ffi::CString;
use std::sync::RwLock;

/// Error codes for C API
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KestrelError {
    Ok = 0,
    Unknown = -1,
    InvalidArg = -2,
    NoMem = -3,
    NotFound = -4,
    AlreadyExists = -5,
    Parse = -6,
    Runtime = -7,
}

impl From<anyhow::Error> for KestrelError {
    fn from(_err: anyhow::Error) -> Self {
        KestrelError::Runtime
    }
}

/// Thread-local error message storage
thread_local! {
    static LAST_ERROR: RwLock<Option<CString>> = RwLock::new(None);
}

/// Set last error message
pub fn set_last_error(msg: &str) {
    LAST_ERROR.with(|error| {
        let mut error = error.write().unwrap();
        if let Ok(cstr) = CString::new(msg) {
            *error = Some(cstr);
        }
    });
}

/// Get last error message as pointer
pub fn get_last_error() -> Option<*const std::os::raw::c_char> {
    LAST_ERROR.with(|error| {
        let error = error.read().unwrap();
        error.as_ref().map(|cstr| cstr.as_ptr())
    })
}
