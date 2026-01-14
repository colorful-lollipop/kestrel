//! Debug test for multi-step sequences

use kestrel_hybrid_engine::{HybridEngine, HybridEngineConfig};
use kestrel_nfa::{CompiledSequence, NfaSequence, PredicateEvaluator, SeqStep};
use kestrel_event::Event;
use std::sync::Arc;

struct SimpleEvaluator;

impl PredicateEvaluator for SimpleEvaluator {
    fn evaluate(&self, predicate_id: &str, event: &Event) -> kestrel_nfa::NfaResult<bool> {
        println!("    [Evaluator] predicate={}, event_type={}, entity_key={}",
                 predicate_id, event.event_type_id, event.entity_key);
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
fn debug_four_step_sequence() {
    println!("\n=== Debug Four Step Sequence ===");

    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(SimpleEvaluator);
    let mut engine = HybridEngine::new(config, evaluator).unwrap();

    // Create 4-step sequence (like PowerShell scenario)
    // state_id: 0, 1, 2, 3
    // event_type: 1, 3, 4, 6
    let seq_steps = vec![
        SeqStep::new(0, "pred1".to_string(), 1),  // event_type 1, state_id 0
        SeqStep::new(1, "pred2".to_string(), 3),  // event_type 3, state_id 1
        SeqStep::new(2, "pred3".to_string(), 4),  // event_type 4, state_id 2
        SeqStep::new(3, "pred4".to_string(), 6),  // event_type 6, state_id 3
    ];

    let sequence = NfaSequence::new(
        "four-step".to_string(),
        100,
        seq_steps,
        Some(10000),  // 10 second maxspan
        None,
    );

    let compiled = CompiledSequence {
        id: "four-step".to_string(),
        sequence,
        rule_id: "rule-004".to_string(),
        rule_name: "Four Step Rule".to_string(),
    };

    println!("\n[Setup] Loading 4-step sequence...");
    engine.load_sequence(compiled).unwrap();
    println!("[Setup] Sequence loaded successfully");

    // Check the loaded sequence
    let strategy = engine.get_rule_strategy("four-step");
    println!("[Setup] Strategy: {:?}", strategy);

    // All events with SAME entity key
    println!("\n[Process] Processing events (all with entity_key=9999)...");

    // Event 1: type=1 (should match step 0)
    let event1 = Event::builder()
        .event_id(1)
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(9999)
        .build()
        .unwrap();

    println!("\n  Event 1: type={}, key={}", event1.event_type_id, event1.entity_key);
    let alerts1 = engine.process_event(&event1).unwrap();
    println!("  Alerts: {}", alerts1.len());

    // Event 2: type=3 (should match step 1)
    let event2 = Event::builder()
        .event_id(2)
        .event_type(3)
        .ts_mono(2000)
        .ts_wall(2000)
        .entity_key(9999)
        .build()
        .unwrap();

    println!("\n  Event 2: type={}, key={}", event2.event_type_id, event2.entity_key);
    let alerts2 = engine.process_event(&event2).unwrap();
    println!("  Alerts: {}", alerts2.len());

    // Event 3: type=4 (should match step 2)
    let event3 = Event::builder()
        .event_id(3)
        .event_type(4)
        .ts_mono(3000)
        .ts_wall(3000)
        .entity_key(9999)
        .build()
        .unwrap();

    println!("\n  Event 3: type={}, key={}", event3.event_type_id, event3.entity_key);
    let alerts3 = engine.process_event(&event3).unwrap();
    println!("  Alerts: {}", alerts3.len());

    // Event 4: type=6 (should match step 3 - COMPLETE!)
    let event4 = Event::builder()
        .event_id(4)
        .event_type(6)
        .ts_mono(4000)
        .ts_wall(4000)
        .entity_key(9999)
        .build()
        .unwrap();

    println!("\n  Event 4: type={}, key={}", event4.event_type_id, event4.entity_key);
    let alerts4 = engine.process_event(&event4).unwrap();
    println!("  Alerts: {}", alerts4.len());

    println!("\n[Result] Total alerts after all events: {}", alerts4.len());

    if alerts4.len() > 0 {
        println!("\n✅ SUCCESS: Four-step sequence works!");
        for (i, alert) in alerts4.iter().enumerate() {
            println!("  Alert {}:", i);
            println!("    Sequence ID: {}", alert.sequence_id);
            println!("    Events matched: {}", alert.events.len());
            println!("    Entity key: {}", alert.entity_key);
        }
    } else {
        println!("\n❌ FAILED: No alerts for 4-step sequence");
        println!("   Events have same entity key and correct types");
        println!("   Expected: 1 alert after 4 events");
        println!("   Got: 0 alerts");
        panic!("Four-step sequence should generate alert");
    }
}
