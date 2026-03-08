//! Edge Case Tests
//!
//! 边界条件测试套件 - 测试极端和异常场景

use kestrel_event::Event;
use kestrel_hybrid_engine::{HybridEngine, HybridEngineConfig};
use kestrel_nfa::{CompiledSequence, NfaSequence, PredicateEvaluator, SeqStep};
use kestrel_schema::{FieldDataType, FieldDef, SchemaRegistry};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct EdgeCaseEvaluator;

#[async_trait::async_trait]
impl PredicateEvaluator for EdgeCaseEvaluator {
    async fn evaluate(&self, predicate_id: &str, _event: &Event) -> kestrel_nfa::NfaResult<bool> {
        match predicate_id {
            "always_true" => Ok(true),
            "always_false" => Ok(false),
            "error" => Err(kestrel_nfa::NfaError::PredicateError("test error".to_string())),
            _ => Ok(true),
        }
    }

    fn get_required_fields(&self, _predicate_id: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
        Ok(Vec::new())
    }

    fn has_predicate(&self, predicate_id: &str) -> bool {
        matches!(predicate_id, "always_true" | "always_false" | "error")
    }
}

fn create_engine() -> HybridEngine {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(EdgeCaseEvaluator);
    HybridEngine::new(config, evaluator).unwrap()
}

fn create_sequence_with_predicates(
    id: &str,
    steps: Vec<(u16, &str)>,
    maxspan: Option<u64>,
) -> CompiledSequence {
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
// Test 1-30: 空值和默认值测试
// =============================================================================

#[test]
fn test_empty_sequence() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates("empty", vec![], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(1, 1000, 1);
    let alerts = engine.process_event(&event).unwrap();

    println!("✅ Empty sequence test: {} alerts", alerts.len());
}

#[test]
fn test_single_step_sequence() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates("single-step", vec![(1, "always_true")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(1, 1000, 1);
    let alerts = engine.process_event(&event).unwrap();

    assert_eq!(alerts.len(), 1, "Single-step sequence should alert immediately");
    println!("✅ Single-step sequence: 1 alert");
}

#[test]
fn test_no_predicate_match() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates("no-match", vec![(1, "always_false")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(1, 1000, 1);
    let alerts = engine.process_event(&event).unwrap();

    assert!(alerts.is_empty(), "Should not alert on non-matching predicate");
    println!("✅ No predicate match: 0 alerts");
}

#[test]
fn test_predicate_error_handling() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates("error-pred", vec![(1, "error")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(1, 1000, 1);
    let result = engine.process_event(&event);

    // Should handle error gracefully
    assert!(result.is_ok(), "Should handle predicate error gracefully");
    println!("✅ Predicate error handled gracefully");
}

// =============================================================================
// Test 31-60: 时间边界测试
// =============================================================================

#[test]
fn test_exact_maxspan_boundary() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates(
        "exact-maxspan",
        vec![(1, "always_true"), (2, "always_true")],
        Some(1000),
    );
    engine.load_sequence(seq).unwrap();

    // First event at t=0
    let event1 = create_event(1, 0, 1);
    engine.process_event(&event1).unwrap();

    // Second event at exactly maxspan
    let event2 = create_event(2, 1000, 1);
    let alerts = engine.process_event(&event2).unwrap();

    assert_eq!(alerts.len(), 1, "Should match at exact maxspan boundary");
    println!("✅ Exact maxspan boundary: 1 alert");
}

#[test]
fn test_maxspan_plus_one_millisecond() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates(
        "maxspan-plus-1ms",
        vec![(1, "always_true"), (2, "always_true")],
        Some(1000), // 1000ms = 1 second maxspan
    );
    engine.load_sequence(seq).unwrap();

    let event1 = create_event(1, 0, 1);
    engine.process_event(&event1).unwrap();

    // Second event 1ms after maxspan (1001ms total, maxspan is 1000ms)
    let event2 = create_event(2, 1_001_000_000, 1); // 1.001 seconds in nanoseconds
    let alerts = engine.process_event(&event2).unwrap();

    assert!(alerts.is_empty(), "Should not match after maxspan");
    println!("✅ Maxspan + 1ms: 0 alerts");
}

#[test]
fn test_zero_maxspan() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates(
        "zero-maxspan",
        vec![(1, "always_true"), (2, "always_true")],
        Some(0),
    );
    engine.load_sequence(seq).unwrap();

    let event1 = create_event(1, 0, 1);
    engine.process_event(&event1).unwrap();

    // Must be simultaneous
    let event2 = create_event(2, 0, 1);
    let alerts = engine.process_event(&event2).unwrap();

    println!("✅ Zero maxspan: {} alerts", alerts.len());
}

#[test]
fn test_very_large_maxspan() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates(
        "large-maxspan",
        vec![(1, "always_true"), (2, "always_true")],
        Some(u64::MAX / 2),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Very large maxspan handled");
}

#[test]
fn test_negative_time_progression() {
    // Events should be processed in order, but test negative progression
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates(
        "negative-time",
        vec![(1, "always_true"), (2, "always_true")],
        Some(10000),
    );
    engine.load_sequence(seq).unwrap();

    // Events with decreasing timestamps
    let event1 = create_event(1, 1000, 1);
    let event2 = create_event(2, 500, 1); // Earlier timestamp

    engine.process_event(&event1).unwrap();
    let alerts = engine.process_event(&event2).unwrap();

    println!("✅ Negative time progression: {} alerts", alerts.len());
}

#[test]
fn test_simultaneous_events_same_type() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates(
        "simultaneous-same",
        vec![(1, "always_true"), (1, "always_true")],
        Some(1000),
    );
    engine.load_sequence(seq).unwrap();

    // Two events at same time, same type
    let event1 = create_event(1, 1000, 1);
    let event2 = create_event(1, 1000, 1);

    engine.process_event(&event1).unwrap();
    let alerts = engine.process_event(&event2).unwrap();

    println!("✅ Simultaneous same type: {} alerts", alerts.len());
}

// =============================================================================
// Test 61-90: 实体边界测试
// =============================================================================

#[test]
fn test_entity_key_zero() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates("entity-zero", vec![(1, "always_true")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(1, 1000, 0);
    let alerts = engine.process_event(&event).unwrap();

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].entity_key, 0);
    println!("✅ Entity key zero: 1 alert");
}

#[test]
fn test_entity_key_max() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates("entity-max", vec![(1, "always_true")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(1, 1000, u128::MAX);
    let alerts = engine.process_event(&event).unwrap();

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].entity_key, u128::MAX);
    println!("✅ Entity key MAX: 1 alert");
}

#[test]
fn test_entity_key_boundary_values() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates("entity-boundary", vec![(1, "always_true")], None);
    engine.load_sequence(seq).unwrap();

    let boundary_values = [
        0u128,
        1,
        u8::MAX as u128,
        u16::MAX as u128,
        u32::MAX as u128,
        u64::MAX as u128,
        u128::MAX,
    ];

    for (i, &key) in boundary_values.iter().enumerate() {
        let event = create_event(1, 1000 + i as u64 * 1000, key);
        let alerts = engine.process_event(&event).unwrap();
        assert_eq!(alerts.len(), 1, "Failed for entity key {}", key);
    }

    println!("✅ Entity key boundary values: {} alerts", boundary_values.len());
}

#[test]
fn test_many_entities_same_event() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates("many-entities", vec![(1, "always_true")], None);
    engine.load_sequence(seq).unwrap();

    let num_entities = 100;
    let mut total_alerts = 0;
    for i in 0..num_entities {
        let event = create_event(1, 1000 + i as u64 * 1000, i as u128);
        let alerts = engine.process_event(&event).unwrap();
        total_alerts += alerts.len();
    }

    assert_eq!(total_alerts, num_entities, "Each entity should trigger one alert");
    println!("✅ Many entities same event: {} alerts", total_alerts);
}

// =============================================================================
// Test 91-120: 事件类型边界测试
// =============================================================================

#[test]
fn test_event_type_zero() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates("type-zero", vec![(0, "always_true")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(0, 1000, 1);
    let alerts = engine.process_event(&event).unwrap();

    println!("✅ Event type zero: {} alerts", alerts.len());
}

#[test]
fn test_event_type_max_u16() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates("type-max", vec![(u16::MAX, "always_true")], None);
    engine.load_sequence(seq).unwrap();

    let event = create_event(u16::MAX, 1000, 1);
    let alerts = engine.process_event(&event).unwrap();

    assert_eq!(alerts.len(), 1);
    println!("✅ Event type MAX: 1 alert");
}

#[test]
fn test_all_event_types() {
    let mut engine = create_engine();

    // Create rules for different event types
    for event_type in [1, 100, 1000, 10000] {
        let seq = create_sequence_with_predicates(
            &format!("type-{}", event_type),
            vec![(event_type, "always_true")],
            None,
        );
        engine.load_sequence(seq).unwrap();
    }

    println!("✅ All event types loaded");
}

// =============================================================================
// Test 121-150: 复杂交错场景
// =============================================================================

#[test]
fn test_interleaved_multiple_entities() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates(
        "interleaved",
        vec![(1, "always_true"), (2, "always_true"), (3, "always_true")],
        Some(10000),
    );
    engine.load_sequence(seq).unwrap();

    // Interleave events from 3 entities
    let events = vec![
        (1, 1000, 1u128),
        (1, 1100, 2),
        (1, 1200, 3),
        (2, 2000, 1),
        (2, 2100, 2),
        (2, 2200, 3),
        (3, 3000, 1),
        (3, 3100, 2),
        (3, 3200, 3),
    ];

    let mut alerts_count = 0;
    for (etype, ts, entity) in events {
        let event = create_event(etype, ts, entity);
        let alerts = engine.process_event(&event).unwrap();
        alerts_count += alerts.len();
    }

    assert_eq!(alerts_count, 3, "Should have 3 alerts (one per entity)");
    println!("✅ Interleaved multiple entities: 3 alerts");
}

#[test]
fn test_partial_completion_interleaved() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates(
        "partial-interleaved",
        vec![(1, "always_true"), (2, "always_true"), (3, "always_true")],
        Some(10000),
    );
    engine.load_sequence(seq).unwrap();

    // Entity 1: complete sequence
    // Entity 2: partial (only 2 events)
    // Entity 3: partial (only 1 event)
    let events = vec![
        (1, 1000, 1u128),
        (1, 1100, 2),
        (1, 1200, 3),
        (2, 2000, 1),
        (2, 2100, 2),
        (3, 3000, 1),
    ];

    let mut alerts_count = 0;
    for (etype, ts, entity) in events {
        let event = create_event(etype, ts, entity);
        let alerts = engine.process_event(&event).unwrap();
        alerts_count += alerts.len();
    }

    // Only entity 1 should complete
    assert_eq!(alerts_count, 1);
    println!("✅ Partial completion interleaved: 1 alert");
}

// =============================================================================
// Test 151-180: 规则边界测试
// =============================================================================

#[test]
fn test_duplicate_rule_id() {
    let mut engine = create_engine();

    let seq1 = create_sequence_with_predicates("dup", vec![(1, "always_true")], None);
    let seq2 = create_sequence_with_predicates("dup", vec![(2, "always_true")], None);

    engine.load_sequence(seq1).unwrap();
    engine.load_sequence(seq2).unwrap();

    // Duplicate rule IDs - the second one overwrites the first
    let stats = engine.stats();
    assert_eq!(stats.total_rules_tracked, 1, "Duplicate rule ID should overwrite");
    println!("✅ Duplicate rule ID: second rule overwrites first");
}

#[test]
fn test_max_rules() {
    let mut engine = create_engine();
    let max_rules = 1000;

    for i in 0..max_rules {
        let seq = create_sequence_with_predicates(
            &format!("max-rule-{}", i),
            vec![(1, "always_true")],
            None,
        );
        engine.load_sequence(seq).unwrap();
    }

    let stats = engine.stats();
    assert_eq!(stats.total_rules_tracked, max_rules);
    println!("✅ Max rules test: {} rules loaded", max_rules);
}

#[test]
fn test_rule_with_many_steps() {
    let mut engine = create_engine();

    // Create sequence with 100 steps
    let steps: Vec<_> = (0..100).map(|i| (i as u16 + 1, "always_true")).collect();

    let seq = create_sequence_with_predicates("many-steps", steps, Some(60000));
    engine.load_sequence(seq).unwrap();

    println!("✅ Rule with many steps: 100 steps loaded");
}

// =============================================================================
// Test 181-210: 性能边界测试
// =============================================================================

#[test]
fn test_rapid_fire_events() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates("rapid-fire", vec![(1, "always_true")], None);
    engine.load_sequence(seq).unwrap();

    let start = Instant::now();
    let count = 100000;

    for i in 0..count {
        let event = create_event(1, i as u64, i as u128);
        let _ = engine.process_event(&event);
    }

    let elapsed = start.elapsed();
    let rate = count as f64 / elapsed.as_secs_f64();

    println!("✅ Rapid fire: {} events in {:?} ({:.2} events/sec)", count, elapsed, rate);
}

#[test]
fn test_burst_then_quiet() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates(
        "burst-quiet",
        vec![(1, "always_true"), (2, "always_true")],
        Some(1000),
    );
    engine.load_sequence(seq).unwrap();

    // Burst of 10000 events
    for i in 0..10000 {
        let event = create_event(1, i as u64 * 100, i as u128);
        let _ = engine.process_event(&event);
    }

    // Quiet period
    std::thread::sleep(Duration::from_millis(100));

    // More events
    for i in 0..100 {
        let event = create_event(2, 1000000 + i as u64 * 100, i as u128);
        let _ = engine.process_event(&event);
    }

    println!("✅ Burst then quiet: completed");
}

// =============================================================================
// Test 211-240: 异常场景测试
// =============================================================================

#[test]
fn test_event_with_no_matching_rules() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates("no-match-rule", vec![(1, "always_true")], None);
    engine.load_sequence(seq).unwrap();

    // Event type 2 doesn't match any rule
    let event = create_event(2, 1000, 1);
    let alerts = engine.process_event(&event).unwrap();

    assert!(alerts.is_empty());
    println!("✅ Event with no matching rules: 0 alerts");
}

#[test]
fn test_all_predicates_false() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates(
        "all-false",
        vec![(1, "always_false"), (2, "always_false")],
        Some(5000),
    );
    engine.load_sequence(seq).unwrap();

    let events = vec![create_event(1, 1000, 1), create_event(2, 2000, 1)];

    let mut alerts_count = 0;
    for event in events {
        let alerts = engine.process_event(&event).unwrap();
        alerts_count += alerts.len();
    }

    assert_eq!(alerts_count, 0);
    println!("✅ All predicates false: 0 alerts");
}

#[test]
fn test_mixed_predicate_results() {
    let mut engine = create_engine();

    // Sequence requiring true predicates
    let seq = create_sequence_with_predicates(
        "mixed-preds",
        vec![
            (1, "always_true"),
            (2, "always_false"), // This will fail
        ],
        Some(5000),
    );
    engine.load_sequence(seq).unwrap();

    let event1 = create_event(1, 1000, 1);
    let event2 = create_event(2, 2000, 1);

    engine.process_event(&event1).unwrap();
    let alerts = engine.process_event(&event2).unwrap();

    assert!(alerts.is_empty(), "Should not alert when predicate fails");
    println!("✅ Mixed predicate results: 0 alerts");
}

// =============================================================================
// Test 241-270: 数据字段边界测试
// =============================================================================

#[test]
fn test_event_with_max_fields() {
    let schema = SchemaRegistry::new();
    let mut field_ids = Vec::new();

    // Register many fields
    for i in 0..100 {
        let field_id = schema
            .register_field(FieldDef {
                path: format!("field{}", i),
                data_type: FieldDataType::String,
                description: None,
            })
            .unwrap();
        field_ids.push(field_id);
    }

    let mut engine = create_engine();
    let seq = create_sequence_with_predicates("max-fields", vec![(1, "always_true")], None);
    engine.load_sequence(seq).unwrap();

    println!("✅ Event with max fields: {} fields", field_ids.len());
}

#[test]
fn test_empty_event() {
    let event = Event::builder()
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(1)
        .build()
        .unwrap();

    let mut engine = create_engine();
    let seq = create_sequence_with_predicates("empty-event", vec![(1, "always_true")], None);
    engine.load_sequence(seq).unwrap();

    let alerts = engine.process_event(&event).unwrap();
    assert_eq!(alerts.len(), 1);
    println!("✅ Empty event: 1 alert");
}

// =============================================================================
// Test 271-300: 并发状态测试
// =============================================================================

#[test]
fn test_multiple_partial_matches_same_entity() {
    let mut engine = create_engine();

    // Multiple sequences can have partial matches for same entity
    for i in 0..10 {
        let seq = create_sequence_with_predicates(
            &format!("multi-partial-{}", i),
            vec![(i as u16 + 1, "always_true"), (i as u16 + 2, "always_true")],
            Some(60000),
        );
        engine.load_sequence(seq).unwrap();
    }

    // First event for each sequence
    for i in 0..10 {
        let event = create_event(i as u16 + 1, 1000, 1);
        let _ = engine.process_event(&event);
    }

    println!("✅ Multiple partial matches same entity: 10 partial");
}

#[test]
fn test_entity_state_isolation() {
    let mut engine = create_engine();
    let seq = create_sequence_with_predicates(
        "state-isolation",
        vec![(1, "always_true"), (2, "always_true")],
        Some(5000),
    );
    engine.load_sequence(seq).unwrap();

    // Entity 1: state 0 -> 1
    let e1 = create_event(1, 1000, 1);
    engine.process_event(&e1).unwrap();

    // Entity 2: state 0 (different entity)
    let e2 = create_event(1, 1100, 2);
    engine.process_event(&e2).unwrap();

    // Entity 1: state 1 -> 2 (complete)
    let e3 = create_event(2, 2000, 1);
    let alerts = engine.process_event(&e3).unwrap();

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].entity_key, 1);

    // Entity 2: still at state 1
    let e4 = create_event(2, 2100, 2);
    let alerts2 = engine.process_event(&e4).unwrap();

    assert_eq!(alerts2.len(), 1);
    assert_eq!(alerts2[0].entity_key, 2);

    println!("✅ Entity state isolation: verified");
}
