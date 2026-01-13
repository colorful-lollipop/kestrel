//! Event processing FFI implementation
//!
//! Provides C-compatible API for processing events and retrieving alerts

use std::ffi::CString;
use std::os::raw::c_char;

use crate::error::KestrelError;
use crate::types::*;

/// Internal alert representation
#[repr(C)]
pub struct AlertWrapper {
    rule_id: String,
    timestamp_ns: u64,
    severity: String,
}

/// Process an event through the engine
///
/// # Safety
/// - `engine` must be a valid pointer
/// - `event` must be a valid pointer
/// - `out_alerts` must be a valid pointer for output
/// - `out_alert_count` must be a valid pointer for output
///
/// # Note
/// This is a simplified MVP implementation that returns empty alerts.
/// Full implementation requires integration with kestrel-engine.
#[no_mangle]
pub unsafe extern "C" fn kestrel_engine_process_event(
    engine: *mut kestrel_engine_t,
    event: *const kestrel_event_data_t,
    out_alerts: *mut *mut *mut kestrel_alert_t,
    out_alert_count: *mut usize,
) -> KestrelError {
    if engine.is_null() || event.is_null() || out_alerts.is_null() || out_alert_count.is_null() {
        return KestrelError::InvalidArg;
    }

    let _event = &*event;
    let _wrapper = &mut *(engine as *mut crate::engine::EngineWrapper);

    // TODO: Full implementation requires:
    // 1. Convert kestrel_event_data_t to kestrel_event::Event
    // 2. Call engine.process_event()
    // 3. Convert alerts to kestrel_alert_t wrappers

    // For MVP, return empty alerts
    *out_alert_count = 0;
    *out_alerts = std::ptr::null_mut();

    KestrelError::Ok
}

/// Free alerts array
///
/// # Safety
/// - `alerts` must be a valid pointer or NULL
/// - `count` must match the number of alerts
#[no_mangle]
pub unsafe extern "C" fn kestrel_alerts_free(
    alerts: *mut *mut kestrel_alert_t,
    count: usize,
) {
    if alerts.is_null() {
        return;
    }

    let alerts_slice = std::slice::from_raw_parts_mut(alerts, count);
    for alert_ptr in alerts_slice {
        if !alert_ptr.is_null() {
            let _ = Box::from_raw(*alert_ptr as *mut AlertWrapper);
        }
    }

    // Free the array itself
    let _ = Box::from_raw(alerts);
}

/// Get rule ID from alert
///
/// # Safety
/// - `alert` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn kestrel_alert_get_rule_id(
    alert: *const kestrel_alert_t,
) -> *const c_char {
    if alert.is_null() {
        return std::ptr::null();
    }

    let alert_wrapper = &*(alert as *const AlertWrapper);

    // Create a C string (leaked for static lifetime)
    match CString::new(alert_wrapper.rule_id.as_str()) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => std::ptr::null(),
    }
}

/// Get timestamp from alert
///
/// # Safety
/// - `alert` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn kestrel_alert_get_timestamp_ns(
    alert: *const kestrel_alert_t,
) -> u64 {
    if alert.is_null() {
        return 0;
    }

    let alert_wrapper = &*(alert as *const AlertWrapper);
    alert_wrapper.timestamp_ns
}

/// Get severity from alert
///
/// # Safety
/// - `alert` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn kestrel_alert_get_severity(
    alert: *const kestrel_alert_t,
) -> *const c_char {
    if alert.is_null() {
        return std::ptr::null();
    }

    let alert_wrapper = &*(alert as *const AlertWrapper);

    // Create a C string (leaked for static lifetime)
    match CString::new(alert_wrapper.severity.as_str()) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => std::ptr::null(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_wrapper_size() {
        // Verify opaque handle works
        assert_eq!(std::mem::size_of::<kestrel_alert_t>(), 0);
    }
}
