use kestrel_event::Event;
use kestrel_nfa::{
    CompiledSequence, NfaEngine, NfaEngineConfig, NfaSequence, PredicateEvaluator, SeqStep,
};
use kestrel_schema::SchemaRegistry;
use std::sync::Arc;

struct TestPredicateEvaluator;

impl PredicateEvaluator for TestPredicateEvaluator {
    fn evaluate(&self, _id: &str, _e: &Event) -> kestrel_nfa::NfaResult<bool> {
        Ok(true)
    }
    fn get_required_fields(&self, _id: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
        Ok(vec![])
    }
    fn has_predicate(&self, _id: &str) -> bool {
        true
    }
}

#[tokio::test]
async fn test_process_injection_sequence() {
    let schema = Arc::new(SchemaRegistry::new());
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestPredicateEvaluator);
    let mut nfa = NfaEngine::new(NfaEngineConfig::default(), evaluator);

    let sequence = CompiledSequence {
        id: "process-injection".to_string(),
        sequence: NfaSequence::new(
            "process-injection".to_string(),
            100,
            vec![
                SeqStep::new(0, "suspicious-exec".to_string(), 1001),
                SeqStep::new(1, "virtualalloc".to_string(), 1002),
                SeqStep::new(2, "loadlibrary".to_string(), 1003),
            ],
            Some(10000),
            None,
        ),
        rule_id: "detect-process-injection".to_string(),
        rule_name: "Detect Process Injection".to_string(),
    };
    nfa.load_sequence(sequence).unwrap();

    let entity: u128 = 12345;
    let base_time = 1_000_000_000u64;

    let e1 = Event::builder()
        .event_type(1001)
        .ts_mono(base_time)
        .ts_wall(base_time)
        .entity_key(entity)
        .build()
        .unwrap();
    assert!(nfa.process_event(&e1).unwrap().is_empty());

    let e2 = Event::builder()
        .event_type(1002)
        .ts_mono(base_time + 500_000_000)
        .ts_wall(base_time + 500_000_000)
        .entity_key(entity)
        .build()
        .unwrap();
    assert!(nfa.process_event(&e2).unwrap().is_empty());

    let e3 = Event::builder()
        .event_type(1003)
        .ts_mono(base_time + 1_000_000_000)
        .ts_wall(base_time + 1_000_000_000)
        .entity_key(entity)
        .build()
        .unwrap();
    let alerts = nfa.process_event(&e3).unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "process-injection");
}

#[tokio::test]
async fn test_file_exfiltration_sequence() {
    let schema = Arc::new(SchemaRegistry::new());
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestPredicateEvaluator);
    let mut nfa = NfaEngine::new(NfaEngineConfig::default(), evaluator);

    let sequence = CompiledSequence {
        id: "file-exfil".to_string(),
        sequence: NfaSequence::new(
            "file-exfil".to_string(),
            200,
            vec![
                SeqStep::new(0, "collect-files".to_string(), 2001),
                SeqStep::new(1, "archive".to_string(), 2002),
                SeqStep::new(2, "transfer".to_string(), 2003),
            ],
            Some(30000),
            None,
        ),
        rule_id: "detect-exfil".to_string(),
        rule_name: "Detect File Exfiltration".to_string(),
    };
    nfa.load_sequence(sequence).unwrap();

    let entity: u128 = 0xDEADBEEF;
    let base_time = 1_000_000_000u64;

    for (i, event_type) in [2001, 2002, 2003].iter().enumerate() {
        let e = Event::builder()
            .event_type(*event_type)
            .ts_mono(base_time + (i as u64 * 10_000_000))
            .ts_wall(base_time + (i as u64 * 10_000_000))
            .entity_key(entity)
            .build()
            .unwrap();
        if i < 2 {
            assert!(
                nfa.process_event(&e).unwrap().is_empty(),
                "Step {} should be partial match",
                i + 1
            );
        } else {
            let alerts = nfa.process_event(&e).unwrap();
            assert_eq!(alerts.len(), 1, "Step {} should complete sequence", i + 1);
        }
    }
}

#[tokio::test]
async fn test_c2_beaconing_pattern() {
    let schema = Arc::new(SchemaRegistry::new());
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestPredicateEvaluator);
    let mut nfa = NfaEngine::new(NfaEngineConfig::default(), evaluator);

    let sequence = CompiledSequence {
        id: "c2-beacon".to_string(),
        sequence: NfaSequence::new(
            "c2-beacon".to_string(),
            300,
            vec![
                SeqStep::new(0, "beacon".to_string(), 3001),
                SeqStep::new(1, "beacon".to_string(), 3001),
                SeqStep::new(2, "beacon".to_string(), 3001),
                SeqStep::new(3, "beacon".to_string(), 3001),
                SeqStep::new(4, "beacon".to_string(), 3001),
            ],
            Some(60000),
            None,
        ),
        rule_id: "detect-c2".to_string(),
        rule_name: "Detect C2 Beaconing".to_string(),
    };
    nfa.load_sequence(sequence).unwrap();

    let entity: u128 = 0xC0FFEE;
    let base_time = 1_000_000_000u64;

    for i in 0..5 {
        let e = Event::builder()
            .event_type(3001)
            .ts_mono(base_time + (i as u64 * 5_000_000_000))
            .ts_wall(base_time + (i as u64 * 5_000_000_000))
            .entity_key(entity)
            .build()
            .unwrap();

        if i < 4 {
            assert!(
                nfa.process_event(&e).unwrap().is_empty(),
                "Beacon {} should be partial",
                i + 1
            );
        } else {
            let alerts = nfa.process_event(&e).unwrap();
            assert_eq!(alerts.len(), 1, "5th beacon should complete pattern");
        }
    }
}

#[tokio::test]
async fn test_maxspan_enforcement() {
    let schema = Arc::new(SchemaRegistry::new());
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestPredicateEvaluator);
    let mut nfa = NfaEngine::new(NfaEngineConfig::default(), evaluator);

    let sequence = CompiledSequence {
        id: "timed-attack".to_string(),
        sequence: NfaSequence::new(
            "timed-attack".to_string(),
            400,
            vec![
                SeqStep::new(0, "step1".to_string(), 4001),
                SeqStep::new(1, "step2".to_string(), 4002),
            ],
            Some(5000),
            None,
        ),
        rule_id: "detect-timed".to_string(),
        rule_name: "Detect Timed Attack".to_string(),
    };
    nfa.load_sequence(sequence).unwrap();

    let entity: u128 = 0xDEAD;

    let e1 = Event::builder()
        .event_type(4001)
        .ts_mono(1_000_000_000)
        .ts_wall(1_000_000_000)
        .entity_key(entity)
        .build()
        .unwrap();
    assert!(nfa.process_event(&e1).unwrap().is_empty());

    let e2 = Event::builder()
        .event_type(4002)
        .ts_mono(11_000_000_000) // 11 seconds (10 second gap > 5s maxspan)
        .ts_wall(11_000_000_000)
        .entity_key(entity)
        .build()
        .unwrap();
    let alerts = nfa.process_event(&e2).unwrap();
    assert!(
        alerts.is_empty(),
        "Should not match - 10s exceeds 5s maxspan"
    );
}

#[tokio::test]
async fn test_entity_isolation() {
    let schema = Arc::new(SchemaRegistry::new());
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestPredicateEvaluator);
    let mut nfa = NfaEngine::new(NfaEngineConfig::default(), evaluator);

    let sequence = CompiledSequence {
        id: "multi-entity".to_string(),
        sequence: NfaSequence::new(
            "multi-entity".to_string(),
            500,
            vec![
                SeqStep::new(0, "step1".to_string(), 5001),
                SeqStep::new(1, "step2".to_string(), 5002),
            ],
            Some(10000),
            None,
        ),
        rule_id: "detect-multi".to_string(),
        rule_name: "Detect Multi-Entity Pattern".to_string(),
    };
    nfa.load_sequence(sequence).unwrap();

    let e1a = Event::builder()
        .event_type(5001)
        .ts_mono(1000)
        .ts_wall(1000)
        .entity_key(0xAAAA)
        .build()
        .unwrap();
    let e1b = Event::builder()
        .event_type(5001)
        .ts_mono(1100)
        .ts_wall(1100)
        .entity_key(0xBBBB)
        .build()
        .unwrap();
    assert!(nfa.process_event(&e1a).unwrap().is_empty());
    assert!(nfa.process_event(&e1b).unwrap().is_empty());

    let e2a = Event::builder()
        .event_type(5002)
        .ts_mono(2000)
        .ts_wall(2000)
        .entity_key(0xAAAA)
        .build()
        .unwrap();
    let alerts = nfa.process_event(&e2a).unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].entity_key, 0xAAAA);

    let e2b = Event::builder()
        .event_type(5002)
        .ts_mono(2100)
        .ts_wall(2100)
        .entity_key(0xBBBB)
        .build()
        .unwrap();
    let alerts = nfa.process_event(&e2b).unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].entity_key, 0xBBBB);
}

#[tokio::test]
async fn test_multiple_sequences_different_entities() {
    let schema = Arc::new(SchemaRegistry::new());
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestPredicateEvaluator);
    let mut nfa = NfaEngine::new(NfaEngineConfig::default(), evaluator);

    let sequence = CompiledSequence {
        id: "attack-chain".to_string(),
        sequence: NfaSequence::new(
            "attack-chain".to_string(),
            600,
            vec![
                SeqStep::new(0, "initial-access".to_string(), 6001),
                SeqStep::new(1, "execution".to_string(), 6002),
                SeqStep::new(2, "persistence".to_string(), 6003),
            ],
            Some(30000),
            None,
        ),
        rule_id: "detect-attack-chain".to_string(),
        rule_name: "Detect Attack Chain".to_string(),
    };
    nfa.load_sequence(sequence).unwrap();

    let entity1: u128 = 0x1111;
    let entity2: u128 = 0x2222;
    let base_time = 1_000_000_000u64;

    let e1 = Event::builder()
        .event_type(6001)
        .ts_mono(base_time)
        .ts_wall(base_time)
        .entity_key(entity1)
        .build()
        .unwrap();
    let e2 = Event::builder()
        .event_type(6001)
        .ts_mono(base_time + 1000)
        .ts_wall(base_time + 1000)
        .entity_key(entity2)
        .build()
        .unwrap();
    nfa.process_event(&e1).unwrap();
    nfa.process_event(&e2).unwrap();

    let e3 = Event::builder()
        .event_type(6002)
        .ts_mono(base_time + 2000)
        .ts_wall(base_time + 2000)
        .entity_key(entity1)
        .build()
        .unwrap();
    nfa.process_event(&e3).unwrap();

    let e4 = Event::builder()
        .event_type(6002)
        .ts_mono(base_time + 2100)
        .ts_wall(base_time + 2100)
        .entity_key(entity2)
        .build()
        .unwrap();
    nfa.process_event(&e4).unwrap();

    let e5 = Event::builder()
        .event_type(6003)
        .ts_mono(base_time + 3000)
        .ts_wall(base_time + 3000)
        .entity_key(entity1)
        .build()
        .unwrap();
    let alerts1 = nfa.process_event(&e5).unwrap();
    assert_eq!(alerts1.len(), 1);
    assert_eq!(alerts1[0].entity_key, entity1);

    let e6 = Event::builder()
        .event_type(6003)
        .ts_mono(base_time + 3100)
        .ts_wall(base_time + 3100)
        .entity_key(entity2)
        .build()
        .unwrap();
    let alerts2 = nfa.process_event(&e6).unwrap();
    assert_eq!(alerts2.len(), 1);
    assert_eq!(alerts2[0].entity_key, entity2);
}
