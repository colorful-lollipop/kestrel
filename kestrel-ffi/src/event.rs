//! Event processing FFI implementation
//!
//! Provides C-compatible API for processing events and retrieving alerts

use std::ffi::CString;
use std::os::raw::c_char;
use std::slice;

use crate::error::KestrelError;
use crate::types::*;
use kestrel_event::{Event, EventBuilder};
use kestrel_schema::TypedValue;

/// Internal alert representation
pub struct AlertWrapper {
    rule_id: String,
    rule_name: String,
    sequence_id: String,
    timestamp_ns: u64,
    entity_key: u128,
}

/// Convert kestrel_value_t to TypedValue
unsafe fn convert_value(value: &kestrel_value_t) -> Option<TypedValue> {
    // Try different types - strings need special handling
    // For now, we'll support basic types
    Some(TypedValue::U64(value.u64))
}

/// Convert kestrel_event_data_t to Event
unsafe fn convert_event(event_data: &kestrel_event_data_t) -> Option<Event> {
    let mut builder = EventBuilder::default()
        .event_id(event_data.event_id)
        .event_type(event_data.event_type)
        .ts_mono(event_data.ts_mono_ns)
        .ts_wall(event_data.ts_wall_ns)
        .entity_key(event_data.entity_key);

    // Convert fields
    let fields_slice = slice::from_raw_parts(event_data.fields, event_data.field_count as usize);
    for field in fields_slice {
        let typed_value = match convert_value(&field.value) {
            Some(v) => v,
            None => continue,
        };
        builder = builder.field(field.field_id, typed_value);
    }

    match builder.build() {
        Ok(event) => Some(event),
        Err(_) => None,
    }
}

/// Process an event through the engine
///
/// # Safety
/// - `engine` must be a valid pointer
/// - `event` must be a valid pointer
/// - `out_alerts` must be a valid pointer for output
/// - `out_alert_count` must be a valid pointer for output
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

    let event_data = &*event;
    let wrapper = &mut *(engine as *mut crate::engine::EngineWrapper);

    // Convert kestrel_event_data_t to Event
    let kestrel_event = match convert_event(event_data) {
        Some(e) => e,
        None => {
            // Conversion failed, return empty alerts
            *out_alert_count = 0;
            *out_alerts = std::ptr::null_mut();
            return KestrelError::InvalidArg;
        }
    };

    // Process event through engine
    let sequence_alerts = match wrapper.engine.process_event(&kestrel_event) {
        Ok(alerts) => alerts,
        Err(_) => {
            // Processing failed, return empty alerts
            *out_alert_count = 0;
            *out_alerts = std::ptr::null_mut();
            return KestrelError::Unknown;
        }
    };

    // Convert SequenceAlert to AlertWrapper
    let alert_wrappers: Vec<Box<AlertWrapper>> = sequence_alerts
        .into_iter()
        .map(|alert| {
            Box::new(AlertWrapper {
                rule_id: alert.rule_id,
                rule_name: alert.rule_name,
                sequence_id: alert.sequence_id,
                timestamp_ns: alert.timestamp_ns,
                entity_key: alert.entity_key,
            })
        })
        .collect();

    // Create output array
    let alert_count = alert_wrappers.len();
    if alert_count == 0 {
        *out_alert_count = 0;
        *out_alerts = std::ptr::null_mut();
        return KestrelError::Ok;
    }

    // Convert to C array
    let alert_ptrs: Vec<*mut kestrel_alert_t> = alert_wrappers
        .into_iter()
        .map(|wrapper| Box::into_raw(wrapper) as *mut kestrel_alert_t)
        .collect();

    let boxed_alerts = alert_ptrs.into_boxed_slice();
    *out_alert_count = alert_count;
    *out_alerts = Box::into_raw(boxed_alerts) as *mut *mut kestrel_alert_t;

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

/// Get rule name from alert
///
/// # Safety
/// - `alert` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn kestrel_alert_get_rule_name(
    alert: *const kestrel_alert_t,
) -> *const c_char {
    if alert.is_null() {
        return std::ptr::null();
    }

    let alert_wrapper = &*(alert as *const AlertWrapper);

    // Create a C string (leaked for static lifetime)
    match CString::new(alert_wrapper.rule_name.as_str()) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => std::ptr::null(),
    }
}

/// Get sequence ID from alert
///
/// # Safety
/// - `alert` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn kestrel_alert_get_sequence_id(
    alert: *const kestrel_alert_t,
) -> *const c_char {
    if alert.is_null() {
        return std::ptr::null();
    }

    let alert_wrapper = &*(alert as *const AlertWrapper);

    // Create a C string (leaked for static lifetime)
    match CString::new(alert_wrapper.sequence_id.as_str()) {
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

/// Get entity key from alert
///
/// # Safety
/// - `alert` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn kestrel_alert_get_entity_key(
    alert: *const kestrel_alert_t,
) -> u128 {
    if alert.is_null() {
        return 0;
    }

    let alert_wrapper = &*(alert as *const AlertWrapper);
    alert_wrapper.entity_key
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
