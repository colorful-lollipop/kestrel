//! Simple C example demonstrating Kestrel FFI API usage

#include <stdio.h>
#include <stdlib.h>
#include "../include/kestrel.h"

int main(void) {
    printf("Kestrel FFI Example\n");
    printf("===================\n\n");

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

    // Load a simple rule
    const char* rule_id = "test_rule_1";
    const char* rule_definition = "event_type = 'exec' AND process_name = 'bash'";
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

    // Unload the rule
    err = kestrel_engine_unload_rule(engine, rule_id);
    if (err != KESTREL_OK) {
        fprintf(stderr, "Failed to unload rule: %d\n", err);
        kestrel_engine_free(engine);
        return 1;
    }
    printf("Rule '%s' unloaded successfully\n", rule_id);

    // Free the engine
    kestrel_engine_free(engine);
    printf("Engine freed successfully\n\n");

    printf("Example completed successfully!\n");
    return 0;
}
