//! Comprehensive End-to-End Test Suite
//!
//! 完整的端到端测试套件，验证NFA引擎的各种场景

use kestrel_hybrid_engine::{HybridEngine, HybridEngineConfig};
use kestrel_nfa::{CompiledSequence, NfaSequence, PredicateEvaluator, SeqStep};
use kestrel_event::Event;
use std::sync::Arc;

struct SimpleEvaluator;

impl PredicateEvaluator for SimpleEvaluator {
    fn evaluate(&self, _predicate_id: &str, _event: &Event) -> kestrel_nfa::NfaResult<bool> {
        Ok(true)
    }

    fn get_required_fields(&self, _predicate_id: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
        Ok(vec![])
    }

    fn has_predicate(&self, predicate_id: &str) -> bool {
        !predicate_id.is_empty()
    }
}

fn create_engine() -> HybridEngine {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(SimpleEvaluator);
    HybridEngine::new(config, evaluator).unwrap()
}

/// 创建测试序列：SeqStep::new(state_id, predicate_id, event_type_id)
fn create_sequence(id: &str, steps: Vec<(u16, &str, u16)>, maxspan: Option<u64>) -> CompiledSequence {
    let seq_steps: Vec<_> = steps
        .iter()
        .map(|(state_id, pred_id, event_type)| {
            SeqStep::new(*state_id, pred_id.to_string(), *event_type)
        })
        .collect();

    let sequence = NfaSequence::new(
        id.to_string(),
        100,
        seq_steps,
        maxspan,
        None,
    );

    CompiledSequence {
        id: id.to_string(),
        sequence,
        rule_id: format!("rule-{}", id),
        rule_name: format!("Test Rule {}", id),
    }
}

#[test]
fn test_two_step_sequence() {
    let mut engine = create_engine();

    // 2步序列：event_type 1 -> event_type 2
    let sequence = create_sequence(
        "two-step",
        vec![(0, "p1", 1), (1, "p2", 2)],
        Some(5000),
    );

    engine.load_sequence(sequence).unwrap();

    // 事件1：type=1
    let event1 = Event::builder()
        .event_type(1)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(123)
        .build()
        .unwrap();

    let alerts1 = engine.process_event(&event1).unwrap();
    assert_eq!(alerts1.len(), 0, "First event should not generate alert yet");

    // 事件2：type=2 (相同entity_key)
    let event2 = Event::builder()
        .event_type(2)
        .ts_mono(2000)
        .ts_wall(2000)
        .entity_key(123)
        .build()
        .unwrap();

    let alerts2 = engine.process_event(&event2).unwrap();
    assert_eq!(alerts2.len(), 1, "Second event should complete the sequence");
    assert_eq!(alerts2[0].events.len(), 2);

    println!("✅ Two-step sequence: 1 alert with 2 events");
}

#[test]
fn test_three_step_sequence() {
    let mut engine = create_engine();

    // 3步序列
    let sequence = create_sequence(
        "three-step",
        vec![(0, "p1", 1), (1, "p2", 2), (2, "p3", 3)],
        Some(10000),
    );

    engine.load_sequence(sequence).unwrap();

    let e1 = Event::builder().event_type(1).ts_mono(1000).ts_wall(1000).entity_key(456).build().unwrap();
    let e2 = Event::builder().event_type(2).ts_mono(2000).ts_wall(2000).entity_key(456).build().unwrap();
    let e3 = Event::builder().event_type(3).ts_mono(3000).ts_wall(3000).entity_key(456).build().unwrap();

    engine.process_event(&e1).unwrap();
    engine.process_event(&e2).unwrap();
    let alerts = engine.process_event(&e3).unwrap();

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].events.len(), 3);

    println!("✅ Three-step sequence: 1 alert with 3 events");
}

#[test]
fn test_four_step_sequence() {
    let mut engine = create_engine();

    // 4步序列：模拟PowerShell场景
    let sequence = create_sequence(
        "powershell",
        vec![(0, "p1", 1), (1, "p2", 3), (2, "p3", 4), (3, "p4", 6)],
        Some(10000),
    );

    engine.load_sequence(sequence).unwrap();

    let e1 = Event::builder().event_type(1).ts_mono(1000).ts_wall(1000).entity_key(789).build().unwrap();
    let e2 = Event::builder().event_type(3).ts_mono(2000).ts_wall(2000).entity_key(789).build().unwrap();
    let e3 = Event::builder().event_type(4).ts_mono(3000).ts_wall(3000).entity_key(789).build().unwrap();
    let e4 = Event::builder().event_type(6).ts_mono(4000).ts_wall(4000).entity_key(789).build().unwrap();

    engine.process_event(&e1).unwrap();
    engine.process_event(&e2).unwrap();
    engine.process_event(&e3).unwrap();
    let alerts = engine.process_event(&e4).unwrap();

    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].events.len(), 4);

    println!("✅ Four-step sequence: 1 alert with 4 events");
}

#[test]
fn test_different_entities_separate_matches() {
    let mut engine = create_engine();

    // 2步序列
    let sequence = create_sequence(
        "multi-entity",
        vec![(0, "p1", 1), (1, "p2", 2)],
        Some(5000),
    );

    engine.load_sequence(sequence).unwrap();

    // 实体A的两个事件
    let e1a = Event::builder().event_type(1).ts_mono(1000).ts_wall(1000).entity_key(111).build().unwrap();
    let e2a = Event::builder().event_type(2).ts_mono(2000).ts_wall(2000).entity_key(111).build().unwrap();

    // 实体B的两个事件
    let e1b = Event::builder().event_type(1).ts_mono(3000).ts_wall(3000).entity_key(222).build().unwrap();
    let e2b = Event::builder().event_type(2).ts_mono(4000).ts_wall(4000).entity_key(222).build().unwrap();

    engine.process_event(&e1a).unwrap();
    let alerts_a = engine.process_event(&e2a).unwrap();

    engine.process_event(&e1b).unwrap();
    let alerts_b = engine.process_event(&e2b).unwrap();

    assert_eq!(alerts_a.len(), 1, "Entity A should generate alert");
    assert_eq!(alerts_b.len(), 1, "Entity B should generate alert");
    assert_eq!(alerts_a[0].entity_key, 111);
    assert_eq!(alerts_b[0].entity_key, 222);

    println!("✅ Different entities: 2 separate alerts");
}

#[test]
fn test_maxspan_timeout() {
    let mut engine = create_engine();

    // 2步序列，maxspan=100ms
    let sequence = create_sequence(
        "maxspan-test",
        vec![(0, "p1", 1), (1, "p2", 2)],
        Some(100), // 100ms
    );

    engine.load_sequence(sequence).unwrap();

    let e1 = Event::builder().event_type(1).ts_mono(1_000_000_000).ts_wall(1_000_000_000).entity_key(999).build().unwrap();

    // 第二个事件在500ms后（超过maxspan）
    let e2 = Event::builder().event_type(2).ts_mono(1_500_000_000).ts_wall(1_500_000_000).entity_key(999).build().unwrap();

    engine.process_event(&e1).unwrap();
    let alerts = engine.process_event(&e2).unwrap();

    assert_eq!(alerts.len(), 0, "Should timeout and not generate alert");

    println!("✅ Maxspan timeout: correctly expired partial match");
}

#[test]
fn test_performance_1000_events() {
    let mut engine = create_engine();

    // 单步序列
    let sequence = create_sequence(
        "perf-test",
        vec![(0, "p1", 1)],
        None,
    );

    engine.load_sequence(sequence).unwrap();

    let start = std::time::Instant::now();
    let mut total_alerts = 0;

    for i in 0..1000 {
        let event = Event::builder()
            .event_id(i)
            .event_type(1)
            .ts_mono(i * 1000)
            .ts_wall(i * 1000)
            .entity_key(i as u128)
            .build()
            .unwrap();

        let alerts = engine.process_event(&event).unwrap();
        total_alerts += alerts.len();
    }

    let elapsed = start.elapsed();
    let throughput = 1000.0 / elapsed.as_secs_f64();

    assert_eq!(total_alerts, 1000, "Should generate alert for each event");

    println!("✅ Performance test:");
    println!("   1000 events processed");
    println!("   Throughput: {:.2} events/sec", throughput);
    println!("   Latency: {:.2} µs/event", elapsed.as_micros() as f64 / 1000.0);

    // 验证性能要求
    assert!(throughput > 1000.0, "Throughput too low");
}

#[test]
fn test_multiple_rules_same_event() {
    let mut engine = create_engine();

    // 加载3个不同的单步规则
    let seq1 = create_sequence("rule1", vec![(0, "p1", 1)], None);
    let seq2 = create_sequence("rule2", vec![(0, "p2", 1)], None);
    let seq3 = create_sequence("rule3", vec![(0, "p3", 2)], None);

    engine.load_sequence(seq1).unwrap();
    engine.load_sequence(seq2).unwrap();
    engine.load_sequence(seq3).unwrap();

    // 事件type=1应该匹配rule1和rule2
    let event1 = Event::builder().event_type(1).ts_mono(1000).ts_wall(1000).entity_key(1).build().unwrap();
    let alerts1 = engine.process_event(&event1).unwrap();

    // 事件type=2应该匹配rule3
    let event2 = Event::builder().event_type(2).ts_mono(2000).ts_wall(2000).entity_key(1).build().unwrap();
    let alerts2 = engine.process_event(&event2).unwrap();

    assert_eq!(alerts1.len(), 2, "Event type 1 should match 2 rules");
    assert_eq!(alerts2.len(), 1, "Event type 2 should match 1 rule");

    println!("✅ Multiple rules: 2 alerts for first event, 1 for second");
}

#[test]
fn test_interleaved_sequences() {
    let mut engine = create_engine();

    // 两个不同的序列
    let seq_a = create_sequence("seq-a", vec![(0, "pa1", 1), (1, "pa2", 2)], Some(5000));
    let seq_b = create_sequence("seq-b", vec![(0, "pb1", 3), (1, "pb2", 4)], Some(5000));

    engine.load_sequence(seq_a).unwrap();
    engine.load_sequence(seq_b).unwrap();

    // 交错事件：type=1 (seq-a step 0), type=3 (seq-b step 0), type=2 (seq-a step 1), type=4 (seq-b step 1)
    let e1 = Event::builder().event_type(1).ts_mono(1000).ts_wall(1000).entity_key(777).build().unwrap();
    let e2 = Event::builder().event_type(3).ts_mono(2000).ts_wall(2000).entity_key(777).build().unwrap();
    let e3 = Event::builder().event_type(2).ts_mono(3000).ts_wall(3000).entity_key(777).build().unwrap();
    let e4 = Event::builder().event_type(4).ts_mono(4000).ts_wall(4000).entity_key(777).build().unwrap();

    engine.process_event(&e1).unwrap();
    engine.process_event(&e2).unwrap();
    let alerts3 = engine.process_event(&e3).unwrap(); // 完成seq-a
    let alerts4 = engine.process_event(&e4).unwrap(); // 完成seq-b

    assert_eq!(alerts3.len(), 1, "Should complete sequence A");
    assert_eq!(alerts4.len(), 1, "Should complete sequence B");

    println!("✅ Interleaved sequences: both sequences completed correctly");
}
