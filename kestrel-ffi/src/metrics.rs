//! Metrics FFI implementation
//!
//! Provides C-compatible API for retrieving engine metrics

use crate::error::KestrelError;
use crate::types::*;

/// Internal metrics wrapper
pub struct MetricsWrapper {
    events_processed: u64,
    alerts_generated: u64,
    nfa_sequence_count: usize,
    dfa_cache_count: usize,
    dfa_memory_usage: usize,
    hot_sequence_count: usize,
    total_rules_tracked: usize,
}

/// Get engine metrics
///
/// # Safety
/// - `engine` must be a valid pointer
/// - `out_metrics` must be a valid pointer for output
#[no_mangle]
pub unsafe extern "C" fn kestrel_engine_get_metrics(
    engine: *mut kestrel_engine_t,
    out_metrics: *mut *mut kestrel_metrics_t,
) -> KestrelError {
    if engine.is_null() || out_metrics.is_null() {
        return KestrelError::InvalidArg;
    }

    let wrapper = &*(engine as *mut crate::engine::EngineWrapper);

    // Get actual statistics from engine
    let stats = wrapper.engine.stats();

    // Create metrics wrapper with actual data
    let wrapper = Box::new(MetricsWrapper {
        events_processed: 0, // Would need to track this in the engine
        alerts_generated: 0, // Would need to track this in the engine
        nfa_sequence_count: stats.nfa_sequence_count,
        dfa_cache_count: stats.dfa_cache_count,
        dfa_memory_usage: stats.dfa_memory_usage,
        hot_sequence_count: stats.hot_sequence_count,
        total_rules_tracked: stats.total_rules_tracked,
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

/// Get NFA sequence count from metrics
///
/// # Safety
/// - `metrics` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn kestrel_metrics_get_nfa_sequence_count(
    metrics: *const kestrel_metrics_t,
) -> usize {
    if metrics.is_null() {
        return 0;
    }

    let wrapper = &*(metrics as *const MetricsWrapper);
    wrapper.nfa_sequence_count
}

/// Get DFA cache count from metrics
///
/// # Safety
/// - `metrics` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn kestrel_metrics_get_dfa_cache_count(
    metrics: *const kestrel_metrics_t,
) -> usize {
    if metrics.is_null() {
        return 0;
    }

    let wrapper = &*(metrics as *const MetricsWrapper);
    wrapper.dfa_cache_count
}

/// Get DFA memory usage from metrics
///
/// # Safety
/// - `metrics` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn kestrel_metrics_get_dfa_memory_usage(
    metrics: *const kestrel_metrics_t,
) -> usize {
    if metrics.is_null() {
        return 0;
    }

    let wrapper = &*(metrics as *const MetricsWrapper);
    wrapper.dfa_memory_usage
}

/// Get hot sequence count from metrics
///
/// # Safety
/// - `metrics` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn kestrel_metrics_get_hot_sequence_count(
    metrics: *const kestrel_metrics_t,
) -> usize {
    if metrics.is_null() {
        return 0;
    }

    let wrapper = &*(metrics as *const MetricsWrapper);
    wrapper.hot_sequence_count
}

/// Get total rules tracked from metrics
///
/// # Safety
/// - `metrics` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn kestrel_metrics_get_total_rules_tracked(
    metrics: *const kestrel_metrics_t,
) -> usize {
    if metrics.is_null() {
        return 0;
    }

    let wrapper = &*(metrics as *const MetricsWrapper);
    wrapper.total_rules_tracked
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
