//! Engine FFI implementation
//!
//! Provides C-compatible API for Kestrel detection engine

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::Arc;
use std::collections::HashMap;
use parking_lot::RwLock;

use crate::error::KestrelError;
use crate::types::*;

use kestrel_hybrid_engine::{HybridEngine, HybridEngineConfig, RuleStrategy};
use kestrel_nfa::{CompiledSequence, NfaEngineConfig, PredicateEvaluator};

/// Mock evaluator for MVP
struct MockEvaluator;

impl PredicateEvaluator for MockEvaluator {
    fn evaluate(&self, _predicate_id: &str, _event: &kestrel_event::Event) -> kestrel_nfa::NfaResult<bool> {
        Ok(true) // For MVP, accept all predicates
    }

    fn get_required_fields(&self, _predicate_id: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
        Ok(Vec::new()) // For MVP, no required fields
    }

    fn has_predicate(&self, _predicate_id: &str) -> bool {
        true // For MVP, always has predicate
    }
}

/// Internal engine wrapper with actual hybrid engine
pub struct EngineWrapper {
    pub config: kestrel_config_t,
    pub engine: HybridEngine,
    pub loaded_sequences: RwLock<HashMap<String, String>>, // rule_id -> sequence_id mapping
}

// Thread-local storage for last error message
thread_local! {
    static LAST_ERROR: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);
}

/// Get last error message as pointer
pub fn get_last_error() -> Option<*const c_char> {
    LAST_ERROR.with(|error| {
        let error = error.read().unwrap();
        error.as_ref().and_then(|msg| CString::new(msg.as_str()).ok()).map(|cstr| cstr.as_ptr() as *const c_char)
    })
}

/// Create a new Kestrel engine
///
/// # Safety
/// - `config` must be a valid pointer or NULL
/// - `out_engine` must be a valid pointer for output
#[no_mangle]
pub unsafe extern "C" fn kestrel_engine_new(
    config: *const kestrel_config_t,
    out_engine: *mut *mut kestrel_engine_t,
) -> KestrelError {
    if out_engine.is_null() {
        return KestrelError::InvalidArg;
    }

    let config = if config.is_null() {
        kestrel_config_t::default()
    } else {
        *config
    };

    // Create hybrid engine configuration
    let hybrid_config = HybridEngineConfig::default();

    // Create predicate evaluator
    let evaluator = Arc::new(MockEvaluator);

    // Create hybrid engine
    let engine = match HybridEngine::new(hybrid_config, evaluator) {
        Ok(e) => e,
        Err(_) => return KestrelError::Unknown,
    };

    // Create engine wrapper
    let wrapper = Box::new(EngineWrapper {
        config,
        engine,
        loaded_sequences: RwLock::new(HashMap::new()),
    });
    let engine_ptr = Box::into_raw(wrapper) as *mut kestrel_engine_t;
    *out_engine = engine_ptr;

    KestrelError::Ok
}

/// Free a Kestrel engine
///
/// # Safety
/// - `engine` must be a valid pointer created by `kestrel_engine_new` or NULL
#[no_mangle]
pub unsafe extern "C" fn kestrel_engine_free(engine: *mut kestrel_engine_t) {
    if engine.is_null() {
        return;
    }
    let _ = Box::from_raw(engine as *mut EngineWrapper);
}

/// Load a rule into the engine
///
/// # Safety
/// - `engine` must be a valid pointer
/// - `rule_id` must be a valid null-terminated string
/// - `rule_definition` must be a valid null-terminated string
#[no_mangle]
pub unsafe extern "C" fn kestrel_engine_load_rule(
    engine: *mut kestrel_engine_t,
    rule_id: *const c_char,
    rule_definition: *const c_char,
    _error_msg: *mut *const c_char,
) -> KestrelError {
    if engine.is_null() || rule_id.is_null() || rule_definition.is_null() {
        return KestrelError::InvalidArg;
    }

    let _wrapper = &mut *(engine as *mut EngineWrapper);

    let rule_id_str = match CStr::from_ptr(rule_id).to_str() {
        Ok(s) => s,
        Err(_) => return KestrelError::InvalidArg,
    };

    let rule_def_str = match CStr::from_ptr(rule_definition).to_str() {
        Ok(s) => s,
        Err(_) => return KestrelError::InvalidArg,
    };

    // For now, just log the rule (actual rule loading to be implemented)
    tracing::info!(
        rule_id = rule_id_str,
        rule = rule_def_str,
        "Rule load requested"
    );

    KestrelError::Ok
}

/// Unload a rule from the engine
///
/// # Safety
/// - `engine` must be a valid pointer
/// - `rule_id` must be a valid null-terminated string
#[no_mangle]
pub unsafe extern "C" fn kestrel_engine_unload_rule(
    engine: *mut kestrel_engine_t,
    rule_id: *const c_char,
) -> KestrelError {
    if engine.is_null() || rule_id.is_null() {
        return KestrelError::InvalidArg;
    }

    let wrapper = &mut *(engine as *mut EngineWrapper);
    let rule_id_str = match CStr::from_ptr(rule_id).to_str() {
        Ok(s) => s,
        Err(_) => return KestrelError::InvalidArg,
    };

    // Remove from loaded sequences mapping
    let sequence_id = wrapper.loaded_sequences.write().remove(rule_id_str);

    if let Some(seq_id) = sequence_id {
        tracing::info!(
            rule_id = rule_id_str,
            sequence_id = seq_id,
            "Rule unloaded"
        );
        KestrelError::Ok
    } else {
        tracing::warn!(rule_id = rule_id_str, "Rule not found");
        KestrelError::Unknown
    }
}

/// Unload all rules from the engine
///
/// # Safety
/// - `engine` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn kestrel_engine_unload_all_rules(
    engine: *mut kestrel_engine_t,
) -> KestrelError {
    if engine.is_null() {
        return KestrelError::InvalidArg;
    }

    let wrapper = &mut *(engine as *mut EngineWrapper);

    // Clear all loaded sequences
    let sequences = wrapper.loaded_sequences.write();
    let count = sequences.len();
    wrapper.loaded_sequences.write().clear();

    tracing::info!(count = count, "All rules unloaded");

    KestrelError::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let mut engine_ptr: *mut kestrel_engine_t = std::ptr::null_mut();
        let config = kestrel_config_t::default();

        let result = unsafe { kestrel_engine_new(&config, &mut engine_ptr) };
        assert_eq!(result as i32, KestrelError::Ok as i32);
        assert!(!engine_ptr.is_null());

        unsafe { kestrel_engine_free(engine_ptr) };
    }

    #[test]
    fn test_engine_null_config() {
        let mut engine_ptr: *mut kestrel_engine_t = std::ptr::null_mut();

        let result = unsafe { kestrel_engine_new(std::ptr::null(), &mut engine_ptr) };
        assert_eq!(result as i32, KestrelError::Ok as i32);
        assert!(!engine_ptr.is_null());

        unsafe { kestrel_engine_free(engine_ptr) };
    }

    #[test]
    fn test_engine_free_null() {
        // Should not crash
        unsafe { kestrel_engine_free(std::ptr::null_mut()) };
    }

    #[test]
    fn test_invalid_args() {
        let mut engine_ptr: *mut kestrel_engine_t = std::ptr::null_mut();
        let config = kestrel_config_t::default();

        // NULL out_engine
        let result = unsafe { kestrel_engine_new(&config, std::ptr::null_mut()) };
        assert_eq!(result as i32, KestrelError::InvalidArg as i32);

        // Create engine first for other tests
        unsafe { kestrel_engine_new(&config, &mut engine_ptr) };

        // NULL engine
        let result = unsafe { kestrel_engine_unload_rule(std::ptr::null_mut(), std::ptr::null()) };
        assert_eq!(result as i32, KestrelError::InvalidArg as i32);

        unsafe { kestrel_engine_free(engine_ptr) };
    }
}
