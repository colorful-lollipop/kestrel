//! End-to-End Integration Test
//!
//! Tests the complete detection pipeline with real event streams

use kestrel_event::Event;
use kestrel_nfa::{
    CompiledSequence, NfaEngine, NfaEngineConfig, NfaSequence, PredicateEvaluator, SeqStep,
};
use kestrel_schema::{FieldDataType, FieldDef, SchemaRegistry};
use std::sync::Arc;

// Simple predicate evaluator that matches everything
struct TestPredicateEvaluator;

impl PredicateEvaluator for TestPredicateEvaluator {
    fn evaluate(&self, _id: &str, _e: &Event) -> kestrel_nfa::NfaResult<bool> {
        Ok(true) // Match everything for this test
    }

    fn get_required_fields(&self, _id: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
        Ok(vec![])
    }

    fn has_predicate(&self, _id: &str) -> bool {
        true
    }
}

// -----------------------------------------------------------------------------
// Real-world Scenario: Linux Privilege Escalation Detection
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_linux_privilege_escalation() {
    // Setup schema with real fields
    let mut schema = SchemaRegistry::new();

    let pid_field = schema
        .register_field(FieldDef {
            path: "process.pid".to_string(),
            data_type: FieldDataType::U64,
            description: Some("Process ID".to_string()),
        })
        .unwrap();

    let name_field = schema
        .register_field(FieldDef {
            path: "process.name".to_string(),
            data_type: FieldDataType::String,
            description: Some("Process name".to_string()),
        })
        .unwrap();

    let path_field = schema
        .register_field(FieldDef {
            path: "file.path".to_string(),
            data_type: FieldDataType::String,
            description: Some("File path".to_string()),
        })
        .unwrap();

    let schema = Arc::new(schema);

    // Create NFA engine with test evaluator
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestPredicateEvaluator);
    let mut nfa = NfaEngine::new(NfaEngineConfig::default(), evaluator);

    // Create privilege escalation detection sequence
    // This simulates: sudo → chmod → /etc/shadow access
    let sequence = CompiledSequence {
        id: "linux-priv-esc".to_string(),
        sequence: NfaSequence::new(
            "linux-priv-esc".to_string(),
            pid_field, // Group by PID
            vec![
                SeqStep::new(0, "sudo".to_string(), 1), // Event type 1: process
                SeqStep::new(1, "chmod".to_string(), 1), // Event type 1: process
                SeqStep::new(2, "shadow_access".to_string(), 3), // Event type 3: file
            ],
            Some(5000), // 5 second maxspan
            None,
        ),
        rule_id: "detect-priv-esc".to_string(),
        rule_name: "Linux Privilege Escalation Detection".to_string(),
    };

    nfa.load_sequence(sequence)
        .expect("Failed to load sequence");

    // Simulate real attack timeline
    let attacker_pid: u128 = 54321;
    let base_time_ns = 1_700_000_000_000_000_000u64;

    println!("\n{}", "=".repeat(60));
    println!("Testing Linux Privilege Escalation Detection");
    println!("{}\n", "=".repeat(60));

    // Step 1: Attacker runs sudo
    let event1 = Event::builder()
        .event_id(1)
        .event_type(1) // PROCESS_EXEC
        .ts_mono(base_time_ns)
        .ts_wall(base_time_ns)
        .entity_key(attacker_pid)
        .field(pid_field, kestrel_schema::TypedValue::U64(54321))
        .field(
            name_field,
            kestrel_schema::TypedValue::String("sudo".to_string()),
        )
        .build()
        .unwrap();

    let alerts1 = nfa.process_event(&event1).unwrap();
    println!("Event 1: sudo execution (PID 54321)");
    println!("  Timestamp: {} ns", event1.ts_mono_ns);
    println!("  Process: sudo");
    println!("  → Alerts: {}", alerts1.len());
    assert!(alerts1.is_empty(), "Should not alert after first event");
    println!("  ✓ No alert (expected)\n");

    // Step 2: Attacker runs chmod (after 1 second)
    let event2 = Event::builder()
        .event_id(2)
        .event_type(1) // PROCESS_EXEC
        .ts_mono(base_time_ns + 1_000_000_000) // +1s
        .ts_wall(base_time_ns + 1_000_000_000)
        .entity_key(attacker_pid)
        .field(pid_field, kestrel_schema::TypedValue::U64(54321))
        .field(
            name_field,
            kestrel_schema::TypedValue::String("chmod".to_string()),
        )
        .build()
        .unwrap();

    let alerts2 = nfa.process_event(&event2).unwrap();
    println!("Event 2: chmod execution (PID 54321, +1s)");
    println!("  Timestamp: {} ns", event2.ts_mono_ns);
    println!("  Process: chmod");
    println!("  → Alerts: {}", alerts2.len());
    assert!(alerts2.is_empty(), "Should not alert after second event");
    println!("  ✓ No alert (expected)\n");

    // Step 3: Attacker accesses /etc/shadow (after 3 more seconds)
    let event3 = Event::builder()
        .event_id(3)
        .event_type(3) // FILE_OPEN
        .ts_mono(base_time_ns + 4_000_000_000) // +4s total
        .ts_wall(base_time_ns + 4_000_000_000)
        .entity_key(attacker_pid)
        .field(pid_field, kestrel_schema::TypedValue::U64(54321))
        .field(
            path_field,
            kestrel_schema::TypedValue::String("/etc/shadow".to_string()),
        )
        .build()
        .unwrap();

    let alerts3 = nfa.process_event(&event3).unwrap();
    println!("Event 3: /etc/shadow access (PID 54321, +4s)");
    println!("  Timestamp: {} ns", event3.ts_mono_ns);
    println!("  File: /etc/shadow");
    println!("  → Alerts: {}", alerts3.len());

    // Should trigger alert now
    assert_eq!(alerts3.len(), 1, "Should alert after completing sequence");
    let alert = &alerts3[0];

    println!("\n  🚨 ALERT TRIGGERED!");
    println!("     Rule ID: {}", alert.rule_id);
    println!("     Rule Name: {}", alert.rule_name);
    println!("     Entity (PID): {}", alert.entity_key);
    println!("     Events in sequence: {}", alert.events.len());

    println!("\n  Event Sequence:");
    for (i, event) in alert.events.iter().enumerate() {
        let pid = event.get_field(pid_field).and_then(|v| {
            if let kestrel_schema::TypedValue::U64(pid) = v {
                Some(pid.to_string())
            } else {
                None
            }
        });
        println!(
            "     {}. Event ID: {}, Type: {}, PID: {:?}",
            i + 1,
            event.event_id,
            event.event_type_id,
            pid
        );
    }

    // Verify alert content
    assert_eq!(alert.events.len(), 3, "Alert should contain all 3 events");
    assert_eq!(alert.entity_key, attacker_pid);
    assert_eq!(alert.rule_id, "linux-priv-esc");

    println!("\n{}", "=".repeat(60));
    println!("✅ Test PASSED: Linux Privilege Escalation Detection");
    println!("{}\n", "=".repeat(60));
}

// -----------------------------------------------------------------------------
// Test Scenario: Ransomware Pattern Detection
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_ransomware_detection() {
    let mut schema = SchemaRegistry::new();

    let pid_field = schema
        .register_field(FieldDef {
            path: "process.pid".to_string(),
            data_type: FieldDataType::U64,
            description: Some("Process ID".to_string()),
        })
        .unwrap();

    let name_field = schema
        .register_field(FieldDef {
            path: "process.name".to_string(),
            data_type: FieldDataType::String,
            description: Some("Process name".to_string()),
        })
        .unwrap();

    let path_field = schema
        .register_field(FieldDef {
            path: "file.path".to_string(),
            data_type: FieldDataType::String,
            description: Some("File path".to_string()),
        })
        .unwrap();

    let schema = Arc::new(schema);
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestPredicateEvaluator);
    let mut nfa = NfaEngine::new(NfaEngineConfig::default(), evaluator);

    // Ransomware pattern: document → encryption → backup deletion
    let sequence = CompiledSequence {
        id: "ransomware-1".to_string(),
        sequence: NfaSequence::new(
            "ransomware-1".to_string(),
            pid_field,
            vec![
                SeqStep::new(0, "doc_access".to_string(), 3), // file access
                SeqStep::new(1, "powershell".to_string(), 1), // powershell
                SeqStep::new(2, "vssadmin".to_string(), 1),   // vssadmin (delete backups)
                SeqStep::new(3, "encrypted".to_string(), 3),  // encrypted file
            ],
            Some(30000), // 30 second maxspan
            None,
        ),
        rule_id: "detect-ransomware".to_string(),
        rule_name: "Ransomware Behavior Detection".to_string(),
    };

    nfa.load_sequence(sequence)
        .expect("Failed to load sequence");

    let victim_pid: u128 = 99999;
    let base_time_ns = 1_700_000_000_000_000_000u64;

    println!("\n{}", "=".repeat(60));
    println!("Testing Ransomware Pattern Detection");
    println!("{}\n", "=".repeat(60));

    // Attack sequence
    let events = vec![
        Event::builder()
            .event_id(1)
            .event_type(3)
            .ts_mono(base_time_ns)
            .ts_wall(base_time_ns)
            .entity_key(victim_pid)
            .field(pid_field, kestrel_schema::TypedValue::U64(99999))
            .field(
                path_field,
                kestrel_schema::TypedValue::String("C:\\Documents\\important.docx".to_string()),
            )
            .build()
            .unwrap(),
        Event::builder()
            .event_id(2)
            .event_type(1)
            .ts_mono(base_time_ns + 5_000_000_000) // +5s
            .ts_wall(base_time_ns + 5_000_000_000)
            .entity_key(victim_pid)
            .field(pid_field, kestrel_schema::TypedValue::U64(99999))
            .field(
                name_field,
                kestrel_schema::TypedValue::String("powershell.exe".to_string()),
            )
            .build()
            .unwrap(),
        Event::builder()
            .event_id(3)
            .event_type(1)
            .ts_mono(base_time_ns + 10_000_000_000) // +10s
            .ts_wall(base_time_ns + 10_000_000_000)
            .entity_key(victim_pid)
            .field(pid_field, kestrel_schema::TypedValue::U64(99999))
            .field(
                name_field,
                kestrel_schema::TypedValue::String("vssadmin.exe".to_string()),
            )
            .build()
            .unwrap(),
        Event::builder()
            .event_id(4)
            .event_type(3)
            .ts_mono(base_time_ns + 25_000_000_000) // +25s
            .ts_wall(base_time_ns + 25_000_000_000)
            .entity_key(victim_pid)
            .field(pid_field, kestrel_schema::TypedValue::U64(99999))
            .field(
                path_field,
                kestrel_schema::TypedValue::String(
                    "C:\\Documents\\important.docx.encrypted".to_string(),
                ),
            )
            .build()
            .unwrap(),
    ];

    // Process attack sequence
    let mut final_alerts = Vec::new();
    for (i, event) in events.iter().enumerate() {
        let alerts = nfa.process_event(event).unwrap();
        println!(
            "Event {}: type={}, alerts={}",
            i + 1,
            event.event_type_id,
            alerts.len()
        );

        if !alerts.is_empty() {
            final_alerts = alerts;
        }
    }

    assert_eq!(final_alerts.len(), 1, "Should detect ransomware pattern");
    let alert = &final_alerts[0];

    println!("\n  🚨 RANSOMWARE DETECTED!");
    println!("     Events in sequence: {}", alert.events.len());
    println!(
        "     Time window: {} ns",
        alert.events.last().unwrap().ts_mono_ns - alert.events.first().unwrap().ts_mono_ns
    );

    assert_eq!(alert.events.len(), 4);

    println!("\n{}", "=".repeat(60));
    println!("✅ Test PASSED: Ransomware Detection");
    println!("{}\n", "=".repeat(60));
}

// -----------------------------------------------------------------------------
// Test Scenario: Entity Isolation (No False Positives)
// -----------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_entity_isolation() {
    let mut schema = SchemaRegistry::new();

    let pid_field = schema
        .register_field(FieldDef {
            path: "process.pid".to_string(),
            data_type: FieldDataType::U64,
            description: Some("Process ID".to_string()),
        })
        .unwrap();

    let name_field = schema
        .register_field(FieldDef {
            path: "process.name".to_string(),
            data_type: FieldDataType::String,
            description: Some("Process name".to_string()),
        })
        .unwrap();

    let schema = Arc::new(schema);
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestPredicateEvaluator);
    let mut nfa = NfaEngine::new(NfaEngineConfig::default(), evaluator);

    // Load the same privilege escalation sequence
    let sequence = CompiledSequence {
        id: "linux-priv-esc".to_string(),
        sequence: NfaSequence::new(
            "linux-priv-esc".to_string(),
            pid_field,
            vec![
                SeqStep::new(0, "sudo".to_string(), 1),
                SeqStep::new(1, "chmod".to_string(), 1),
                SeqStep::new(2, "shadow_access".to_string(), 3),
            ],
            Some(5000),
            None,
        ),
        rule_id: "detect-priv-esc".to_string(),
        rule_name: "Linux Privilege Escalation Detection".to_string(),
    };

    nfa.load_sequence(sequence)
        .expect("Failed to load sequence");

    let base_time_ns = 1_700_000_000_000_000_000u64;

    println!("\n{}", "=".repeat(60));
    println!("Testing Entity Isolation (No False Positives)");
    println!("{}\n", "=".repeat(60));

    // Process 1: sudo (PID 11111)
    let event1 = Event::builder()
        .event_id(1)
        .event_type(1)
        .ts_mono(base_time_ns)
        .ts_wall(base_time_ns)
        .entity_key(11111)
        .field(pid_field, kestrel_schema::TypedValue::U64(11111))
        .field(
            name_field,
            kestrel_schema::TypedValue::String("sudo".to_string()),
        )
        .build()
        .unwrap();

    nfa.process_event(&event1).unwrap();
    println!("✓ Event 1: sudo (PID 11111)");

    // Process 2: chmod (PID 22222 - DIFFERENT ENTITY)
    let event2 = Event::builder()
        .event_id(2)
        .event_type(1)
        .ts_mono(base_time_ns + 1_000_000_000)
        .ts_wall(base_time_ns + 1_000_000_000)
        .entity_key(22222)
        .field(pid_field, kestrel_schema::TypedValue::U64(22222))
        .field(
            name_field,
            kestrel_schema::TypedValue::String("chmod".to_string()),
        )
        .build()
        .unwrap();

    nfa.process_event(&event2).unwrap();
    println!("✓ Event 2: chmod (PID 22222)");

    // Process 2: /etc/shadow access (PID 22222)
    let event3 = Event::builder()
        .event_id(3)
        .event_type(3)
        .ts_mono(base_time_ns + 4_000_000_000)
        .ts_wall(base_time_ns + 4_000_000_000)
        .entity_key(22222)
        .field(pid_field, kestrel_schema::TypedValue::U64(22222))
        .build()
        .unwrap();

    let alerts = nfa.process_event(&event3).unwrap();
    println!("✓ Event 3: /etc/shadow (PID 22222)");

    // Should NOT alert because events are from different entities
    assert_eq!(
        alerts.len(),
        0,
        "Should NOT alert - events from different PIDs"
    );

    println!("\n  ✅ No false positive - correctly isolated by entity");
    println!("\n{}", "=".repeat(60));
    println!("✅ Test PASSED: Entity Isolation");
    println!("{}\n", "=".repeat(60));
}
