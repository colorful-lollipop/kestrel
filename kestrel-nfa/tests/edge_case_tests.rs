//! Edge Case Tests for NFA Module
//!
//! NFA模块的边界条件测试

use kestrel_event::Event;
use kestrel_nfa::*;
use std::sync::Arc;

struct TestEvaluator;

#[async_trait::async_trait]
impl PredicateEvaluator for TestEvaluator {
    async fn evaluate(&self, _predicate_id: &str, _event: &Event) -> NfaResult<bool> {
        Ok(true)
    }

    fn get_required_fields(&self, _predicate_id: &str) -> NfaResult<Vec<u32>> {
        Ok(Vec::new())
    }

    fn has_predicate(&self, _predicate_id: &str) -> bool {
        true
    }
}

fn create_engine() -> NfaEngine {
    let config = NfaEngineConfig {
        max_evaluations_per_sec: 0,
        max_eval_time_ns: 0,
        ..Default::default()
    };
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestEvaluator);
    NfaEngine::new(config, evaluator)
}

fn create_sequence(id: &str, steps: Vec<(u16, &str)>, maxspan: Option<u64>) -> CompiledSequence {
    let seq_steps: Vec<_> = steps
        .iter()
        .enumerate()
        .map(|(i, (event_type, pred_id))| SeqStep::new(i as u16, pred_id.to_string(), *event_type))
        .collect();

    let sequence = NfaSequence::new(id.to_string(), 100, seq_steps, maxspan, None);

    CompiledSequence {
        id: id.to_string(),
        sequence,
        rule_id: format!("rule-{}", id),
        rule_name: format!("Test Rule {}", id),
    }
}

fn create_event(event_type: u16, ts_ns: u64, entity_key: u128) -> Event {
    Event::builder()
        .event_type(event_type)
        .ts_mono(ts_ns)
        .ts_wall(ts_ns)
        .entity_key(entity_key)
        .build()
        .unwrap()
}

// =============================================================================
// Empty and Minimal Tests (1-10)
// =============================================================================

#[test]
fn test_empty_sequence() {
    let mut engine = create_engine();
    let seq = create_sequence("empty", vec![], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(1, 1_000_000, 1);
    let alerts = engine.process_event_blocking(&event).unwrap();

    // Empty sequence should match immediately or not at all
    println!("Empty sequence produced {} alerts", alerts.len());
}

#[test]
fn test_single_step_sequence() {
    let mut engine = create_engine();
    let seq = create_sequence("single", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(1, 1_000_000, 1);
    let alerts = engine.process_event_blocking(&event).unwrap();

    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_single_step_wrong_event_type() {
    let mut engine = create_engine();
    let seq = create_sequence("single-wrong", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(2, 1_000_000, 1); // Different event type
    let alerts = engine.process_event_blocking(&event).unwrap();

    assert!(alerts.is_empty());
}

#[test]
fn test_two_step_minimum() {
    let mut engine = create_engine();
    let seq = create_sequence("two-step", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    engine
        .process_event_blocking(&create_event(1, 1_000_000, 1))
        .unwrap();
    let alerts = engine
        .process_event_blocking(&create_event(2, 2_000_000, 1))
        .unwrap();

    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_no_sequences_loaded() {
    let mut engine = create_engine();

    let event = create_event(1, 1_000_000, 1);
    let alerts = engine.process_event_blocking(&event).unwrap();

    assert!(alerts.is_empty());
}

// =============================================================================
// Timestamp Boundary Tests (11-25)
// =============================================================================

#[test]
fn test_zero_timestamp() {
    let mut engine = create_engine();
    let seq = create_sequence("zero-ts", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(1, 0, 1);
    let alerts = engine.process_event_blocking(&event).unwrap();

    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_very_large_timestamp() {
    let mut engine = create_engine();
    let seq = create_sequence("large-ts", vec![(1, "p1"), (2, "p2")], Some(u64::MAX));
    engine.load_sequence(seq).unwrap();

    let event1 = create_event(1, u64::MAX / 2, 1);
    engine.process_event_blocking(&event1).unwrap();

    let event2 = create_event(2, u64::MAX / 2 + 1_000_000, 1);
    let alerts = engine.process_event_blocking(&event2).unwrap();

    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_maxspan_exact_match() {
    let mut engine = create_engine();
    let seq = create_sequence("exact-maxspan", vec![(1, "p1"), (2, "p2")], Some(1000));
    engine.load_sequence(seq).unwrap();

    let event1 = create_event(1, 0, 1);
    engine.process_event_blocking(&event1).unwrap();

    // Exactly at maxspan boundary (1000ms = 1,000,000,000 ns)
    let event2 = create_event(2, 1_000_000_000, 1);
    let alerts = engine.process_event_blocking(&event2).unwrap();

    // Should match (exactly at boundary)
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_maxspan_just_over() {
    let mut engine = create_engine();
    let seq = create_sequence("over-maxspan", vec![(1, "p1"), (2, "p2")], Some(100));
    engine.load_sequence(seq).unwrap();

    let event1 = create_event(1, 0, 1);
    engine.process_event_blocking(&event1).unwrap();

    // Just over maxspan (100ms = 100,000,000 ns)
    let event2 = create_event(2, 100_000_001, 1);
    let alerts = engine.process_event_blocking(&event2).unwrap();

    // Should not match (just over boundary)
    assert!(alerts.is_empty());
}

#[test]
fn test_negative_time_elapsed() {
    let mut engine = create_engine();
    let seq = create_sequence("negative-time", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    let event1 = create_event(1, 2_000_000, 1);
    engine.process_event_blocking(&event1).unwrap();

    // Second event has earlier timestamp (out of order)
    let event2 = create_event(2, 1_000_000, 1);
    let alerts = engine.process_event_blocking(&event2).unwrap();

    // Should handle gracefully
    println!("Out-of-order events produced {} alerts", alerts.len());
}

#[test]
fn test_very_short_maxspan() {
    let mut engine = create_engine();
    let seq = create_sequence("short-maxspan", vec![(1, "p1"), (2, "p2")], Some(1));
    engine.load_sequence(seq).unwrap();

    let event1 = create_event(1, 0, 1);
    engine.process_event_blocking(&event1).unwrap();

    // Even 1ms later exceeds maxspan
    let event2 = create_event(2, 2_000_000, 1); // 2ms later
    let alerts = engine.process_event_blocking(&event2).unwrap();

    assert!(alerts.is_empty());
}

#[test]
fn test_very_long_maxspan() {
    let mut engine = create_engine();
    let seq = create_sequence("long-maxspan", vec![(1, "p1"), (2, "p2")], Some(3_600_000)); // 1 hour
    engine.load_sequence(seq).unwrap();

    let event1 = create_event(1, 0, 1);
    engine.process_event_blocking(&event1).unwrap();

    // 30 minutes later
    let event2 = create_event(2, 1_800_000_000_000, 1); // 30 min in ns
    let alerts = engine.process_event_blocking(&event2).unwrap();

    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_events_at_same_timestamp() {
    let mut engine = create_engine();
    let seq = create_sequence("same-ts", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    let event1 = create_event(1, 1_000_000, 1);
    engine.process_event_blocking(&event1).unwrap();

    let event2 = create_event(2, 1_000_000, 1); // Same timestamp
    let alerts = engine.process_event_blocking(&event2).unwrap();

    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_timestamp_overflow_protection() {
    let mut engine = create_engine();
    let seq = create_sequence("overflow", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    let event1 = create_event(1, u64::MAX - 1_000_000, 1);
    engine.process_event_blocking(&event1).unwrap();

    // This would overflow if not handled properly
    let event2 = create_event(2, u64::MAX, 1);
    let alerts = engine.process_event_blocking(&event2).unwrap();

    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_microsecond_precision() {
    let mut engine = create_engine();
    let seq = create_sequence("micro-precision", vec![(1, "p1"), (2, "p2")], Some(1));
    engine.load_sequence(seq).unwrap();

    // Events 500 microseconds apart
    let event1 = create_event(1, 1_000_000, 1);
    engine.process_event_blocking(&event1).unwrap();

    let event2 = create_event(2, 1_500_000, 1); // 500 us later
    let alerts = engine.process_event_blocking(&event2).unwrap();

    // Should match (within 1ms maxspan)
    assert_eq!(alerts.len(), 1);
}

// =============================================================================
// Entity Key Boundary Tests (26-35)
// =============================================================================

#[test]
fn test_entity_key_zero() {
    let mut engine = create_engine();
    let seq = create_sequence("entity-zero", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    let event1 = create_event(1, 1_000_000, 0);
    engine.process_event_blocking(&event1).unwrap();

    let event2 = create_event(2, 2_000_000, 0);
    let alerts = engine.process_event_blocking(&event2).unwrap();

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].entity_key, 0);
}

#[test]
fn test_entity_key_max() {
    let mut engine = create_engine();
    let seq = create_sequence("entity-max", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    let event1 = create_event(1, 1_000_000, u128::MAX);
    engine.process_event_blocking(&event1).unwrap();

    let event2 = create_event(2, 2_000_000, u128::MAX);
    let alerts = engine.process_event_blocking(&event2).unwrap();

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].entity_key, u128::MAX);
}

#[test]
fn test_many_entities() {
    let mut engine = create_engine();
    let seq = create_sequence("many-entities", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    // Create partial matches for 1000 entities
    for i in 0..1000 {
        let event = create_event(1, 1_000_000, i as u128);
        engine.process_event_blocking(&event).unwrap();
    }

    // Complete all sequences
    let mut alert_count = 0;
    for i in 0..1000 {
        let event = create_event(2, 2_000_000, i as u128);
        let alerts = engine.process_event_blocking(&event).unwrap();
        alert_count += alerts.len();
    }

    assert_eq!(alert_count, 1000);
}

#[test]
fn test_entity_isolation() {
    let mut engine = create_engine();
    let seq = create_sequence("entity-isolation", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    // Entity 1: step 1
    engine
        .process_event_blocking(&create_event(1, 1_000_000, 1))
        .unwrap();

    // Entity 2: step 2 (should not match with entity 1)
    let alerts = engine
        .process_event_blocking(&create_event(2, 2_000_000, 2))
        .unwrap();
    assert!(alerts.is_empty());

    // Entity 1: step 2 (should complete)
    let alerts = engine
        .process_event_blocking(&create_event(2, 3_000_000, 1))
        .unwrap();
    assert_eq!(alerts.len(), 1);
}

// =============================================================================
// Event Type Edge Cases (36-45)
// =============================================================================

#[test]
fn test_event_type_zero() {
    let mut engine = create_engine();
    let seq = create_sequence("type-zero", vec![(0, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(0, 1_000_000, 1);
    let alerts = engine.process_event_blocking(&event).unwrap();

    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_event_type_max() {
    let mut engine = create_engine();
    let seq = create_sequence("type-max", vec![(u16::MAX, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(u16::MAX, 1_000_000, 1);
    let alerts = engine.process_event_blocking(&event).unwrap();

    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_many_event_types() {
    let mut engine = create_engine();

    // Create sequences for 100 different event types
    for i in 0..100 {
        let seq = create_sequence(&format!("type-seq-{}", i), vec![(i as u16, "p")], None);
        engine.load_sequence(seq).unwrap();
    }

    // Process one event of each type
    for i in 0..100 {
        let event = create_event(i as u16, i as u64 * 1_000_000, i as u128);
        let alerts = engine.process_event_blocking(&event).unwrap();
        assert_eq!(alerts.len(), 1, "Event type {} should match", i);
    }
}

// =============================================================================
// State Management Edge Cases (46-55)
// =============================================================================

#[test]
fn test_unload_nonexistent_sequence() {
    let mut engine = create_engine();

    let result = engine.unload_sequence("nonexistent");
    assert!(result.is_ok());
    assert!(!result.unwrap()); // Returns false if not found
}

#[test]
fn test_reload_same_sequence() {
    let mut engine = create_engine();
    let seq = create_sequence("reload", vec![(1, "p1")], None);

    engine.load_sequence(seq.clone()).unwrap();
    engine.load_sequence(seq).unwrap(); // Load again

    // Should have only one sequence
    assert_eq!(engine.sequence_count(), 1);
}

#[test]
fn test_sequence_count() {
    let mut engine = create_engine();

    assert_eq!(engine.sequence_count(), 0);

    for i in 0..10 {
        let seq = create_sequence(&format!("count-{}", i), vec![(1, "p")], None);
        engine.load_sequence(seq).unwrap();
        assert_eq!(engine.sequence_count(), i + 1);
    }
}

#[test]
fn test_tick_with_no_sequences() {
    let mut engine = create_engine();

    // Should not panic
    engine.tick(1_000_000_000);
}

#[test]
fn test_tick_with_expired_matches() {
    let mut engine = create_engine();
    let seq = create_sequence("tick-expire", vec![(1, "p1"), (2, "p2")], Some(100));
    engine.load_sequence(seq).unwrap();

    // Create partial match
    engine.process_event_blocking(&create_event(1, 0, 1)).unwrap();

    // Tick to trigger cleanup
    engine.tick(200_000_000); // 200ms later

    // Try to complete - should not match (expired)
    let alerts = engine
        .process_event_blocking(&create_event(2, 200_000_000, 1))
        .unwrap();
    assert!(alerts.is_empty());
}

// =============================================================================
// Error Handling Tests (56-65)
// =============================================================================

#[test]
fn test_malformed_sequence_id() {
    let mut engine = create_engine();
    let seq = create_sequence("", vec![(1, "p1")], None);

    // Empty ID should still work
    let result = engine.load_sequence(seq);
    assert!(result.is_ok());
}

#[test]
fn test_very_long_sequence_id() {
    let mut engine = create_engine();
    let long_id = "a".repeat(1000);
    let seq = create_sequence(&long_id, vec![(1, "p1")], None);

    let result = engine.load_sequence(seq);
    assert!(result.is_ok());
}

#[test]
fn test_special_characters_in_id() {
    let mut engine = create_engine();
    let special_ids = vec!["test-rule_1", "test.rule.2", "test:rule:3", "test/rule/4"];

    for id in special_ids {
        let seq = create_sequence(id, vec![(1, "p")], None);
        let result = engine.load_sequence(seq);
        assert!(result.is_ok(), "Failed for ID: {}", id);
    }
}

// =============================================================================
// Unicode and Special Character Tests (66-75)
// =============================================================================

#[test]
fn test_unicode_in_predicate_id() {
    let mut engine = create_engine();
    let seq = create_sequence("unicode", vec![(1, "进程名称检查")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(1, 1_000_000, 1);
    let alerts = engine.process_event_blocking(&event).unwrap();

    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_unicode_in_sequence_id() {
    let mut engine = create_engine();
    let seq = create_sequence("序列测试", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    assert_eq!(engine.sequence_count(), 1);
}

// =============================================================================
// Performance Edge Cases (76-85)
// =============================================================================

#[test]
fn test_rapid_event_burst() {
    let mut engine = create_engine();
    let seq = create_sequence("burst", vec![(1, "p1"), (2, "p2")], Some(1000));
    engine.load_sequence(seq).unwrap();

    // Send 1000 events rapidly
    for i in 0..1000 {
        let event_type = if i % 2 == 0 { 1 } else { 2 };
        let _ = engine.process_event_blocking(&create_event(event_type, i as u64 * 1000, (i % 100) as u128));
    }

    // Should complete without panic
}

#[test]
fn test_alternating_events_same_entity() {
    let mut engine = create_engine();
    let seq = create_sequence("alternating", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    let entity = 12345u128;

    // Alternating events for same entity
    for i in 0..10 {
        let event_type = if i % 2 == 0 { 1 } else { 2 };
        let _ = engine.process_event_blocking(&create_event(event_type, i as u64 * 1_000_000, entity));
    }

    // Should handle gracefully
}

#[test]
fn test_single_entity_many_sequences() {
    let mut engine = create_engine();

    // Load 50 sequences
    for i in 0..50 {
        let seq = create_sequence(
            &format!("multi-seq-{}", i),
            vec![(1, &format!("p{}", i)), (2, &format!("q{}", i))],
            Some(10000),
        );
        engine.load_sequence(seq).unwrap();
    }

    // Single entity triggers all sequences
    let entity = 999u128;
    engine
        .process_event_blocking(&create_event(1, 1_000_000, entity))
        .unwrap();

    let alerts = engine
        .process_event_blocking(&create_event(2, 2_000_000, entity))
        .unwrap();

    // Should have alerts from multiple sequences
    println!("Single entity triggered {} alerts", alerts.len());
}

// =============================================================================
// Deterministic Tests (86-95)
// =============================================================================

#[test]
fn test_deterministic_processing() {
    let mut engine1 = create_engine();
    let mut engine2 = create_engine();

    let seq = create_sequence("deterministic", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine1.load_sequence(seq.clone()).unwrap();
    engine2.load_sequence(seq).unwrap();

    // Process same events in same order
    let events = vec![create_event(1, 1_000_000, 1), create_event(2, 2_000_000, 1)];

    let mut alerts1 = vec![];
    for event in &events {
        alerts1.extend(engine1.process_event_blocking(event).unwrap());
    }

    let mut alerts2 = vec![];
    for event in &events {
        alerts2.extend(engine2.process_event_blocking(event).unwrap());
    }

    assert_eq!(alerts1.len(), alerts2.len());
}

#[test]
fn test_reproducible_results() {
    for run in 0..5 {
        let mut engine = create_engine();
        let seq = create_sequence(&format!("run-{}", run), vec![(1, "p1"), (2, "p2")], Some(5000));
        engine.load_sequence(seq).unwrap();

        let alerts = engine
            .process_event_blocking(&create_event(1, 1_000_000, 1))
            .unwrap();
        assert!(alerts.is_empty(), "First event should not alert");

        let alerts = engine
            .process_event_blocking(&create_event(2, 2_000_000, 1))
            .unwrap();
        assert_eq!(alerts.len(), 1, "Second event should alert");
    }
}

// =============================================================================
// Miscellaneous Edge Cases (96-100)
// =============================================================================

#[test]
fn test_load_unload_load_cycle() {
    let mut engine = create_engine();
    let seq_id = "cycle-test";

    for _i in 0..10 {
        let seq = create_sequence(seq_id, vec![(1, "p1")], None);
        engine.load_sequence(seq).unwrap();
        assert_eq!(engine.sequence_count(), 1);

        let removed = engine.unload_sequence(seq_id).unwrap();
        assert!(removed);
        assert_eq!(engine.sequence_count(), 0);
    }
}

#[test]
fn test_all_entity_keys() {
    let mut engine = create_engine();
    let seq = create_sequence("all-keys", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    // Test various entity key patterns
    let keys = vec![
        0u128,
        1u128,
        0xFFFFFFFFFFFFFFFFu128,                 // 64-bit max
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128, // 128-bit max
    ];

    for key in keys {
        let alerts = engine
            .process_event_blocking(&create_event(1, 1_000_000, key))
            .unwrap();
        assert_eq!(alerts.len(), 1, "Failed for key: {}", key);
    }
}

#[test]
fn test_event_with_all_fields() {
    let mut engine = create_engine();
    let seq = create_sequence("full-event", vec![(1, "p1")], None);
    engine.load_sequence(seq).unwrap();

    let event = Event::builder()
        .event_id(1)
        .event_type(1)
        .ts_mono(1_000_000)
        .ts_wall(2_000_000)
        .entity_key(12345)
        .field(1, kestrel_schema::TypedValue::I64(42))
        .field(2, kestrel_schema::TypedValue::String("test".into()))
        .field(3, kestrel_schema::TypedValue::Bool(true))
        .build()
        .unwrap();

    let alerts = engine.process_event_blocking(&event).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_sequence_with_until_clause() {
    // Test sequences with until condition
    let mut engine = create_engine();
    let seq = create_sequence("with-until", vec![(1, "p1"), (2, "p2")], Some(5000));
    engine.load_sequence(seq).unwrap();

    // This test would require until clause support
    // For now, just verify it loads correctly
    assert_eq!(engine.sequence_count(), 1);
}

#[test]
fn test_engine_statistics() {
    let mut engine = create_engine();

    // Initial state
    assert_eq!(engine.sequence_count(), 0);

    // Add sequences
    for i in 0..5 {
        let seq = create_sequence(&format!("stats-{}", i), vec![(1, "p")], None);
        engine.load_sequence(seq).unwrap();
    }

    assert_eq!(engine.sequence_count(), 5);

    // Process events
    for i in 0..100 {
        let _ = engine.process_event_blocking(&create_event(1, i as u64 * 1_000_000, (i % 10) as u128));
    }

    // Verify engine still functional
    assert_eq!(engine.sequence_count(), 5);
}
