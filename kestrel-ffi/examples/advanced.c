//! Advanced C example demonstrating Kestrel FFI event processing and metrics

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "../include/kestrel.h"

int main(void) {
    printf("Kestrel FFI Advanced Example\n");
    printf("============================\n\n");

    // Get version
    printf("Version: %s\n\n", kestrel_version());

    // Create engine with default config
    kestrel_config_t config = {
        .event_bus_size = 10000,
        .worker_threads = 4,
        .batch_size = 100,
        .enable_metrics = true,
        .enable_tracing = false,
    };

    kestrel_engine_t* engine = NULL;
    kestrel_error_t err = kestrel_engine_new(&config, &engine);
    if (err != KESTREL_OK) {
        fprintf(stderr, "Failed to create engine: %d\n", err);
        return 1;
    }
    printf("Engine created successfully\n");

    // Load a rule
    const char* rule_id = "detect_suspicious_exec";
    const char* rule_definition = "event_type = 1 AND process_name = 'malware'";
    const char* error_msg = NULL;

    err = kestrel_engine_load_rule(engine, rule_id, rule_definition, &error_msg);
    if (err != KESTREL_OK) {
        fprintf(stderr, "Failed to load rule: %d\n", err);
        if (error_msg) {
            fprintf(stderr, "Error: %s\n", error_msg);
        }
        kestrel_engine_free(engine);
        return 1;
    }
    printf("Rule '%s' loaded successfully\n", rule_id);

    // Create an event
    kestrel_value_t proc_name_value = {
        .string = {.data = (const uint8_t*)"malware", .len = 7}
    };

    kestrel_field_t fields[] = {
        {.field_id = 100, .value = proc_name_value}
    };

    kestrel_event_data_t event = {
        .event_id = 12345,
        .event_type = 1,
        .ts_mono_ns = 1234567890000000ULL,
        .ts_wall_ns = 1234567890000000ULL,
        .entity_key = 0,
        .field_count = 1,
        .fields = fields,
    };

    printf("\nProcessing event...\n");
    printf("  Event ID: %lu\n", event.event_id);
    printf("  Event Type: %u\n", event.event_type);
    printf("  Fields: %u\n", event.field_count);

    // Process the event
    kestrel_alert_t** alerts = NULL;
    size_t alert_count = 0;

    err = kestrel_engine_process_event(engine, &event, &alerts, &alert_count);
    if (err != KESTREL_OK) {
        fprintf(stderr, "Failed to process event: %d\n", err);
        kestrel_engine_unload_rule(engine, rule_id);
        kestrel_engine_free(engine);
        return 1;
    }
    printf("Event processed successfully\n");
    printf("Alerts generated: %zu\n", alert_count);

    // Check alerts (MVP returns 0 alerts)
    if (alert_count > 0) {
        for (size_t i = 0; i < alert_count; i++) {
            const char* rule = kestrel_alert_get_rule_id(alerts[i]);
            uint64_t timestamp = kestrel_alert_get_timestamp_ns(alerts[i]);
            const char* severity = kestrel_alert_get_severity(alerts[i]);

            printf("\nAlert %zu:\n", i);
            printf("  Rule: %s\n", rule ? rule : "null");
            printf("  Timestamp: %lu ns\n", timestamp);
            printf("  Severity: %s\n", severity ? severity : "null");
        }

        kestrel_alerts_free(alerts, alert_count);
    }

    // Get metrics
    kestrel_metrics_t* metrics = NULL;
    err = kestrel_engine_get_metrics(engine, &metrics);
    if (err != KESTREL_OK) {
        fprintf(stderr, "Failed to get metrics: %d\n", err);
        kestrel_engine_unload_rule(engine, rule_id);
        kestrel_engine_free(engine);
        return 1;
    }

    printf("\nMetrics:\n");
    printf("  Events Processed: %lu\n", kestrel_metrics_get_events_processed(metrics));
    printf("  Alerts Generated: %lu\n", kestrel_metrics_get_alerts_generated(metrics));

    kestrel_metrics_free(metrics);

    // Cleanup
    kestrel_engine_unload_rule(engine, rule_id);
    kestrel_engine_free(engine);
    printf("\nEngine freed successfully\n");

    printf("\nAdvanced example completed successfully!\n");
    return 0;
}
