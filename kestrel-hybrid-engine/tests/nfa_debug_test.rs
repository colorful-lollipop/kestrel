//! NFA Engine Debug Test
//!
//! 最小化测试来调试NFA引擎的告警生成

use kestrel_hybrid_engine::{HybridEngine, HybridEngineConfig};
use kestrel_nfa::{CompiledSequence, NfaSequence, PredicateEvaluator, SeqStep};
use std::sync::Arc;

// Simple evaluator that always returns true
struct SimpleEvaluator;

impl PredicateEvaluator for SimpleEvaluator {
    fn evaluate(&self, predicate_id: &str, event: &kestrel_event::Event) -> kestrel_nfa::NfaResult<bool> {
        println!("  [Evaluator] Checking predicate: {}", predicate_id);
        println!("    Event type: {}", event.event_type_id);
        println!("    Entity key: {}", event.entity_key);
        Ok(true)
    }

    fn get_required_fields(&self, _predicate_id: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
        Ok(vec![])
    }

    fn has_predicate(&self, predicate_id: &str) -> bool {
        !predicate_id.is_empty()
    }
}

#[test]
fn debug_single_step_sequence() {
    println!("\n=== Debug Single Step Sequence ===");

    // 1. Create engine
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(SimpleEvaluator);
    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    // 2. Create single-step sequence (just detect event type 1)
    // NOTE: state_id starts from 0!
    // SeqStep::new(state_id, predicate_id, event_type_id)
    let seq_steps = vec![
        SeqStep::new(0, "pred1".to_string(), 1),
    ];

    let sequence = NfaSequence::new(
        "single-step".to_string(),
        100,  // by_field_id
        seq_steps,
        None,  // maxspan
        None,  // until_step
    );

    let compiled = CompiledSequence {
        id: "single-step".to_string(),
        sequence,
        rule_id: "rule-001".to_string(),
        rule_name: "Single Step Rule".to_string(),
    };

    println!("\n[Setup] Loading sequence...");
    engine.load_sequence(compiled).unwrap();
    println!("[Setup] Sequence loaded successfully");

    // 3. Create event
    let event = kestrel_event::Event::builder()
        .event_id(1)
        .event_type(1)  // This should match our sequence
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(12345)
        .build()
        .unwrap();

    println!("\n[Process] Processing event:");
    println!("  Event ID: {}", event.event_id);
    println!("  Event type: {}", event.event_type_id);
    println!("  Entity key: {}", event.entity_key);

    // 4. Process event
    let alerts = engine.process_event(&event).unwrap();

    println!("\n[Result] Alerts generated: {}", alerts.len());
    for (i, alert) in alerts.iter().enumerate() {
        println!("  Alert {}:", i);
        println!("    Rule ID: {}", alert.rule_id);
        println!("    Sequence ID: {}", alert.sequence_id);
        println!("    Entity key: {}", alert.entity_key);
        println!("    Events in sequence: {}", alert.events.len());
    }

    // Verify
    if alerts.len() > 0 {
        println!("\n✅ SUCCESS: Single-step sequence works!");
    } else {
        println!("\n❌ FAILED: No alerts generated for single-step sequence");
        println!("   This indicates a core NFA engine issue");
        panic!("Single-step sequence should generate at least one alert");
    }
}

#[test]
fn debug_two_step_sequence() {
    println!("\n=== Debug Two Step Sequence ===");

    // 1. Create engine
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(SimpleEvaluator);
    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    // 2. Create two-step sequence
    // NOTE: state_id starts from 0!
    // SeqStep::new(state_id, predicate_id, event_type_id)
    let seq_steps = vec![
        SeqStep::new(0, "pred1".to_string(), 1),
        SeqStep::new(1, "pred2".to_string(), 2),
    ];

    let sequence = NfaSequence::new(
        "two-step".to_string(),
        100,
        seq_steps,
        Some(10000),  // 10 second maxspan
        None,
    );

    let compiled = CompiledSequence {
        id: "two-step".to_string(),
        sequence,
        rule_id: "rule-002".to_string(),
        rule_name: "Two Step Rule".to_string(),
    };

    println!("\n[Setup] Loading two-step sequence...");
    engine.load_sequence(compiled).unwrap();

    // 3. Create two events with same entity key
    let event1 = kestrel_event::Event::builder()
        .event_id(1)
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(12345)
        .build()
        .unwrap();

    let event2 = kestrel_event::Event::builder()
        .event_id(2)
        .event_type(2)
        .ts_mono(2000)
        .ts_wall(2000)
        .entity_key(12345)  // Same entity key!
        .build()
        .unwrap();

    println!("\n[Process] Processing event 1 (type=1, key=12345)...");
    let alerts1 = engine.process_event(&event1).unwrap();
    println!("  Alerts after event 1: {}", alerts1.len());

    println!("\n[Process] Processing event 2 (type=2, key=12345)...");
    let alerts2 = engine.process_event(&event2).unwrap();
    println!("  Alerts after event 2: {}", alerts2.len());

    println!("\n[Result] Total alerts: {}", alerts2.len());
    for (i, alert) in alerts2.iter().enumerate() {
        println!("  Alert {}:", i);
        println!("    Sequence ID: {}", alert.sequence_id);
        println!("    Events matched: {}", alert.events.len());
    }

    if alerts2.len() > 0 {
        println!("\n✅ SUCCESS: Two-step sequence works!");
    } else {
        println!("\n❌ FAILED: No alerts for two-step sequence");
        println!("   Events have same entity key but sequence didn't match");
    }
}

#[test]
fn debug_different_entity_keys() {
    println!("\n=== Debug Different Entity Keys ===");

    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(SimpleEvaluator);
    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    // Two-step sequence
    // NOTE: state_id starts from 0!
    // SeqStep::new(state_id, predicate_id, event_type_id)
    let seq_steps = vec![
        SeqStep::new(0, "pred1".to_string(), 1),
        SeqStep::new(1, "pred2".to_string(), 2),
    ];

    let sequence = NfaSequence::new(
        "two-step-diff".to_string(),
        100,
        seq_steps,
        Some(10000),
        None,
    );

    let compiled = CompiledSequence {
        id: "two-step-diff".to_string(),
        sequence,
        rule_id: "rule-003".to_string(),
        rule_name: "Different Entity Rule".to_string(),
    };

    engine.load_sequence(compiled).unwrap();

    // Events with DIFFERENT entity keys (should NOT match)
    let event1 = kestrel_event::Event::builder()
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(11111)  // Different key
        .build()
        .unwrap();

    let event2 = kestrel_event::Event::builder()
        .event_type(2)
        .ts_mono(2000)
        .ts_wall(2000)
        .entity_key(22222)  // Different key
        .build()
        .unwrap();

    println!("\n[Process] Processing events with different entity keys...");
    engine.process_event(&event1).unwrap();
    let alerts = engine.process_event(&event2).unwrap();

    println!("  Alerts: {}", alerts.len());

    if alerts.len() == 0 {
        println!("\n✅ SUCCESS: Correctly no alert for different entity keys");
    } else {
        println!("\n❌ FAILED: Generated alert for different entity keys (should not match)");
    }
}
