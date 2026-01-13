//! C-compatible type definitions


/// Engine configuration
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct kestrel_config_t {
    pub event_bus_size: u32,
    pub worker_threads: u32,
    pub batch_size: u32,
    pub enable_metrics: bool,
    pub enable_tracing: bool,
}

impl Default for kestrel_config_t {
    fn default() -> Self {
        Self {
            event_bus_size: 10000,
            worker_threads: 4,
            batch_size: 100,
            enable_metrics: true,
            enable_tracing: false,
        }
    }
}

/// Opaque handle for Kestrel engine
#[repr(C)]
pub struct kestrel_engine_t {
    _private: [u8; 0],
}

/// Opaque handle for Kestrel event
#[repr(C)]
pub struct kestrel_event_t {
    _private: [u8; 0],
}

/// Opaque handle for Kestrel rule
#[repr(C)]
pub struct kestrel_rule_t {
    _private: [u8; 0],
}

/// Opaque handle for Kestrel alert
#[repr(C)]
pub struct kestrel_alert_t {
    _private: [u8; 0],
}

/// Opaque handle for Kestrel metrics
#[repr(C)]
pub struct kestrel_metrics_t {
    _private: [u8; 0],
}

/// Typed value for event fields
#[repr(C)]
#[derive(Clone, Copy)]
pub union kestrel_value_t {
    pub i64: i64,
    pub u64: u64,
    pub f64: f64,
    pub boolean: bool,
    pub string: kestrel_string_t,
    pub bytes: kestrel_bytes_t,
}

/// String representation
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct kestrel_string_t {
    pub data: *const u8,
    pub len: usize,
}

/// Bytes representation
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct kestrel_bytes_t {
    pub data: *const u8,
    pub len: usize,
}

/// Event field
#[repr(C)]
#[derive(Clone, Copy)]
pub struct kestrel_field_t {
    pub field_id: u32,
    pub value: kestrel_value_t,
}

/// Event structure (non-opaque version for FFI input)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct kestrel_event_data_t {
    pub event_id: u64,
    pub event_type: u16,
    pub ts_mono_ns: u64,
    pub ts_wall_ns: u64,
    pub entity_key: u128,
    pub field_count: u32,
    pub fields: *const kestrel_field_t,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_size() {
        assert_eq!(std::mem::size_of::<kestrel_config_t>(), 16);
        assert_eq!(std::mem::size_of::<kestrel_config_t>(), 16);
    }

    #[test]
    fn test_config_default() {
        let config = kestrel_config_t::default();
        assert_eq!(config.event_bus_size, 10000);
        assert_eq!(config.worker_threads, 4);
    }

    #[test]
    fn test_event_data_size() {
        // Verify layout (u128 requires 16-byte alignment, causing padding)
        assert_eq!(std::mem::size_of::<kestrel_event_data_t>(), 64);
    }
}
