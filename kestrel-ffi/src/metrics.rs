//! Metrics FFI implementation
//!
//! Provides C-compatible API for retrieving engine metrics

use crate::error::KestrelError;
use crate::types::*;

/// Internal metrics wrapper
pub struct MetricsWrapper {
    events_processed: u64,
    alerts_generated: u64,
}

/// Get engine metrics
///
/// # Safety
/// - `engine` must be a valid pointer
/// - `out_metrics` must be a valid pointer for output
///
/// # Note
/// This is a simplified MVP implementation.
/// Full implementation requires integration with kestrel-engine.
#[no_mangle]
pub unsafe extern "C" fn kestrel_engine_get_metrics(
    engine: *mut kestrel_engine_t,
    out_metrics: *mut *mut kestrel_metrics_t,
) -> KestrelError {
    if engine.is_null() || out_metrics.is_null() {
        return KestrelError::InvalidArg;
    }

    let _wrapper = &*(engine as *mut crate::engine::EngineWrapper);

    // TODO: Full implementation requires:
    // 1. Get actual metrics from engine
    // 2. Convert to MetricsWrapper

    // For MVP, return zeroed metrics
    let wrapper = Box::new(MetricsWrapper {
        events_processed: 0,
        alerts_generated: 0,
    });
    let metrics_ptr = Box::into_raw(wrapper) as *mut kestrel_metrics_t;
    *out_metrics = metrics_ptr;

    KestrelError::Ok
}

/// Get events processed count from metrics
///
/// # Safety
/// - `metrics` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn kestrel_metrics_get_events_processed(
    metrics: *const kestrel_metrics_t,
) -> u64 {
    if metrics.is_null() {
        return 0;
    }

    let wrapper = &*(metrics as *const MetricsWrapper);
    wrapper.events_processed
}

/// Get alerts generated count from metrics
///
/// # Safety
/// - `metrics` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn kestrel_metrics_get_alerts_generated(
    metrics: *const kestrel_metrics_t,
) -> u64 {
    if metrics.is_null() {
        return 0;
    }

    let wrapper = &*(metrics as *const MetricsWrapper);
    wrapper.alerts_generated
}

/// Free metrics
///
/// # Safety
/// - `metrics` must be a valid pointer or NULL
#[no_mangle]
pub unsafe extern "C" fn kestrel_metrics_free(metrics: *mut kestrel_metrics_t) {
    if metrics.is_null() {
        return;
    }
    let _ = Box::from_raw(metrics as *mut MetricsWrapper);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_wrapper_size() {
        // Verify opaque handle works
        assert_eq!(std::mem::size_of::<kestrel_metrics_t>(), 0);
    }
}
