//! C header file for Kestrel FFI
//!
//! This header defines the C-compatible API for Kestrel detection engine.

#ifndef KESTREL_H
#define KESTREL_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Version information
#define KESTREL_VERSION_MAJOR 0
#define KESTREL_VERSION_MINOR 2
#define KESTREL_VERSION_PATCH 0

// Error codes
typedef enum {
    KESTREL_OK = 0,
    KESTREL_ERROR_UNKNOWN = -1,
    KESTREL_ERROR_INVALID_ARG = -2,
    KESTREL_ERROR_NOMEM = -3,
    KESTREL_ERROR_NOT_FOUND = -4,
    KESTREL_ERROR_ALREADY_EXISTS = -5,
    KESTREL_ERROR_PARSE = -6,
    KESTREL_ERROR_RUNTIME = -7,
} kestrel_error_t;

// Opaque handle types
typedef struct kestrel_engine kestrel_engine_t;
typedef struct kestrel_event kestrel_event_t;
typedef struct kestrel_rule kestrel_rule_t;
typedef struct kestrel_alert kestrel_alert_t;
typedef struct kestrel_metrics kestrel_metrics_t;

// Configuration
typedef struct {
    uint32_t event_bus_size;
    uint32_t worker_threads;
    uint32_t batch_size;
    bool enable_metrics;
    bool enable_tracing;
} kestrel_config_t;

// Typed value for event fields
typedef union {
    int64_t i64;
    uint64_t u64;
    double f64;
    bool boolean;
    struct {
        const uint8_t* data;
        size_t len;
    } string;
    struct {
        const uint8_t* data;
        size_t len;
    } bytes;
} kestrel_value_t;

// Event field
typedef struct {
    uint32_t field_id;
    kestrel_value_t value;
} kestrel_field_t;

// Event structure (non-opaque for input)
typedef struct {
    uint64_t event_id;
    uint16_t event_type;
    uint64_t ts_mono_ns;
    uint64_t ts_wall_ns;
    unsigned __int128 entity_key;
    uint32_t field_count;
    const kestrel_field_t* fields;
} kestrel_event_data_t;

// Version
const char* kestrel_version(void);

// Error handling
const char* kestrel_last_error(void);

// Engine lifecycle
kestrel_error_t kestrel_engine_new(
    const kestrel_config_t* config,
    kestrel_engine_t** out_engine
);

void kestrel_engine_free(kestrel_engine_t* engine);

// Rule management
kestrel_error_t kestrel_engine_load_rule(
    kestrel_engine_t* engine,
    const char* rule_id,
    const char* rule_definition,
    const char** error_msg
);

kestrel_error_t kestrel_engine_unload_rule(
    kestrel_engine_t* engine,
    const char* rule_id
);

kestrel_error_t kestrel_engine_unload_all_rules(
    kestrel_engine_t* engine
);

// Event processing
kestrel_error_t kestrel_engine_process_event(
    kestrel_engine_t* engine,
    const kestrel_event_data_t* event,
    kestrel_alert_t*** out_alerts,
    size_t* out_alert_count
);

void kestrel_alerts_free(
    kestrel_alert_t** alerts,
    size_t count
);

// Alert queries
const char* kestrel_alert_get_rule_id(
    const kestrel_alert_t* alert
);

uint64_t kestrel_alert_get_timestamp_ns(
    const kestrel_alert_t* alert
);

const char* kestrel_alert_get_severity(
    const kestrel_alert_t* alert
);

// Metrics
kestrel_error_t kestrel_engine_get_metrics(
    kestrel_engine_t* engine,
    kestrel_metrics_t** out_metrics
);

uint64_t kestrel_metrics_get_events_processed(
    const kestrel_metrics_t* metrics
);

uint64_t kestrel_metrics_get_alerts_generated(
    const kestrel_metrics_t* metrics
);

void kestrel_metrics_free(kestrel_metrics_t* metrics);

#ifdef __cplusplus
}
#endif

#endif // KESTREL_H
