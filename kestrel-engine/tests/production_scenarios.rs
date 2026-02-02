//! Production-Grade Security Scenarios Tests
use kestrel_nfa::{NfaEngine, NfaEngineConfig, PredicateEvaluator, NfaResult, NfaSequence, SeqStep, CompiledSequence};
use kestrel_event::Event;
use std::sync::Arc;

struct TestPredicateEvaluator {
    predicates: std::collections::HashMap<String, Box<dyn Fn(&Event) -> bool + Send + Sync>>,
}

impl TestPredicateEvaluator {
    fn new() -> Self {
        Self { predicates: std::collections::HashMap::new() }
    }
    fn register<F>(&mut self, id: &str, func: F)
    where F: Fn(&Event) -> bool + Send + Sync + 'static {
        self.predicates.insert(id.to_string(), Box::new(func));
    }
}

impl PredicateEvaluator for TestPredicateEvaluator {
    fn evaluate(&self, predicate_id: &str, event: &Event) -> NfaResult<bool> {
        Ok(self.predicates.get(predicate_id).map(|f| f(event)).unwrap_or(false))
    }
    fn get_required_fields(&self, _predicate_id: &str) -> NfaResult<Vec<u32>> { Ok(vec![]) }
    fn has_predicate(&self, predicate_id: &str) -> bool { self.predicates.contains_key(predicate_id) }
}

fn create_test_event(event_type_id: u16, ts_ns: u64, entity_key: u128) -> Event {
    Event::builder()
        .event_type(event_type_id)
        .ts_mono(ts_ns)
        .ts_wall(ts_ns)
        .entity_key(entity_key)
        .build()
        .expect("Failed to build test event")
}

#[test]
fn test_ransomware_attack_detection() {
    let config = NfaEngineConfig::default();
    let mut evaluator = TestPredicateEvaluator::new();
    evaluator.register("suspicious_exec", |e| e.event_type_id == 1001);
    evaluator.register("file_encryption", |e| e.event_type_id == 1002);
    evaluator.register("ransom_note", |e| e.event_type_id == 1003);

    let mut engine = NfaEngine::new(config, Arc::new(evaluator));
    let sequence = NfaSequence::new(
        "ransomware_detection".to_string(), 1,
        vec![
            SeqStep::new(0, "suspicious_exec".to_string(), 1001),
            SeqStep::new(1, "file_encryption".to_string(), 1002),
            SeqStep::new(2, "file_encryption".to_string(), 1002),
            SeqStep::new(3, "ransom_note".to_string(), 1003),
        ],
        Some(60000), None,
    );
    let compiled = CompiledSequence {
        id: "ransomware_detection".to_string(),
        sequence, rule_id: "rule-ransomware-001".to_string(),
        rule_name: "Ransomware Attack Detection".to_string(),
    };
    engine.load_sequence(compiled).unwrap();

    let entity_key: u128 = 0x123456789abcdef;
    let base_time = 1_000_000_000;

    let event1 = create_test_event(1001, base_time, entity_key);
    assert!(engine.process_event(&event1).unwrap().is_empty());

    let event2 = create_test_event(1002, base_time + 1_000_000, entity_key);
    assert!(engine.process_event(&event2).unwrap().is_empty());

    let event3 = create_test_event(1002, base_time + 2_000_000, entity_key);
    assert!(engine.process_event(&event3).unwrap().is_empty());

    let event4 = create_test_event(1003, base_time + 3_000_000, entity_key);
    let alerts = engine.process_event(&event4).unwrap();
    
    assert_eq!(alerts.len(), 1, "Should detect ransomware attack!");
    assert_eq!(alerts[0].sequence_id, "ransomware_detection");
}

#[test]
fn test_apt_lateral_movement_detection() {
    let config = NfaEngineConfig::default();
    let mut evaluator = TestPredicateEvaluator::new();
    evaluator.register("phishing_exec", |e| e.event_type_id == 2001);
    evaluator.register("credential_dump", |e| e.event_type_id == 2002);
    evaluator.register("wmi_exec", |e| e.event_type_id == 2003);
    evaluator.register("dc_access", |e| e.event_type_id == 2004);

    let mut engine = NfaEngine::new(config, Arc::new(evaluator));
    let sequence = NfaSequence::new(
        "apt_lateral_movement".to_string(), 1,
        vec![
            SeqStep::new(0, "phishing_exec".to_string(), 2001),
            SeqStep::new(1, "credential_dump".to_string(), 2002),
            SeqStep::new(2, "wmi_exec".to_string(), 2003),
            SeqStep::new(3, "dc_access".to_string(), 2004),
        ],
        Some(300_000), None,
    );
    let compiled = CompiledSequence {
        id: "apt_lateral_movement".to_string(),
        sequence, rule_id: "rule-apt-001".to_string(),
        rule_name: "APT Lateral Movement Detection".to_string(),
    };
    engine.load_sequence(compiled).unwrap();

    let entity_key: u128 = 0xdeadbeef;
    let base_time = 2_000_000_000;

    assert!(engine.process_event(&create_test_event(2001, base_time, entity_key)).unwrap().is_empty());
    assert!(engine.process_event(&create_test_event(2002, base_time + 30_000_000, entity_key)).unwrap().is_empty());
    assert!(engine.process_event(&create_test_event(2003, base_time + 60_000_000, entity_key)).unwrap().is_empty());
    
    let alerts = engine.process_event(&create_test_event(2004, base_time + 90_000_000, entity_key)).unwrap();
    assert_eq!(alerts.len(), 1, "Should detect APT lateral movement!");
}

#[test]
fn test_insider_data_exfiltration() {
    let config = NfaEngineConfig::default();
    let mut evaluator = TestPredicateEvaluator::new();
    evaluator.register("db_access", |e| e.event_type_id == 3001);
    evaluator.register("large_query", |e| e.event_type_id == 3002);
    evaluator.register("file_archive", |e| e.event_type_id == 3003);
    evaluator.register("external_upload", |e| e.event_type_id == 3004);

    let mut engine = NfaEngine::new(config, Arc::new(evaluator));
    let sequence = NfaSequence::new(
        "insider_exfiltration".to_string(), 1,
        vec![
            SeqStep::new(0, "db_access".to_string(), 3001),
            SeqStep::new(1, "large_query".to_string(), 3002),
            SeqStep::new(2, "file_archive".to_string(), 3003),
            SeqStep::new(3, "external_upload".to_string(), 3004),
        ],
        Some(600_000), None,
    );
    let compiled = CompiledSequence {
        id: "insider_exfiltration".to_string(),
        sequence, rule_id: "rule-insider-001".to_string(),
        rule_name: "Insider Data Exfiltration".to_string(),
    };
    engine.load_sequence(compiled).unwrap();

    let entity_key: u128 = 0xcafebabe;
    let base_time = 3_000_000_000;

    assert!(engine.process_event(&create_test_event(3001, base_time, entity_key)).unwrap().is_empty());
    assert!(engine.process_event(&create_test_event(3002, base_time + 120_000_000, entity_key)).unwrap().is_empty());
    assert!(engine.process_event(&create_test_event(3003, base_time + 180_000_000, entity_key)).unwrap().is_empty());
    
    let alerts = engine.process_event(&create_test_event(3004, base_time + 300_000_000, entity_key)).unwrap();
    assert_eq!(alerts.len(), 1, "Should detect insider exfiltration!");
}

#[test]
fn test_supply_chain_attack() {
    let config = NfaEngineConfig::default();
    let mut evaluator = TestPredicateEvaluator::new();
    evaluator.register("build_access", |e| e.event_type_id == 4001);
    evaluator.register("code_modify", |e| e.event_type_id == 4002);
    evaluator.register("signed_build", |e| e.event_type_id == 4003);
    evaluator.register("backdoor_callback", |e| e.event_type_id == 4004);

    let mut engine = NfaEngine::new(config, Arc::new(evaluator));
    let sequence = NfaSequence::new(
        "supply_chain_attack".to_string(), 1,
        vec![
            SeqStep::new(0, "build_access".to_string(), 4001),
            SeqStep::new(1, "code_modify".to_string(), 4002),
            SeqStep::new(2, "signed_build".to_string(), 4003),
            SeqStep::new(3, "backdoor_callback".to_string(), 4004),
        ],
        Some(3_600_000), None,
    );
    let compiled = CompiledSequence {
        id: "supply_chain_attack".to_string(),
        sequence, rule_id: "rule-supplychain-001".to_string(),
        rule_name: "Supply Chain Attack Detection".to_string(),
    };
    engine.load_sequence(compiled).unwrap();

    let entity_key: u128 = 0x11111111;
    let base_time = 4_000_000_000;

    assert!(engine.process_event(&create_test_event(4001, base_time, entity_key)).unwrap().is_empty());
    assert!(engine.process_event(&create_test_event(4002, base_time + 600_000_000, entity_key)).unwrap().is_empty());
    assert!(engine.process_event(&create_test_event(4003, base_time + 1_800_000_000, entity_key)).unwrap().is_empty());
    
    let alerts = engine.process_event(&create_test_event(4004, base_time + 2_400_000_000, entity_key)).unwrap();
    assert_eq!(alerts.len(), 1, "Should detect supply chain attack!");
}

#[test]
fn test_cryptomining_detection() {
    let config = NfaEngineConfig::default();
    let mut evaluator = TestPredicateEvaluator::new();
    evaluator.register("suspicious_download", |e| e.event_type_id == 5001);
    evaluator.register("cpu_spike", |e| e.event_type_id == 5002);
    evaluator.register("stratum_conn", |e| e.event_type_id == 5003);
    evaluator.register("mining_process", |e| e.event_type_id == 5004);

    let mut engine = NfaEngine::new(config, Arc::new(evaluator));
    let sequence = NfaSequence::new(
        "cryptomining_detection".to_string(), 1,
        vec![
            SeqStep::new(0, "suspicious_download".to_string(), 5001),
            SeqStep::new(1, "cpu_spike".to_string(), 5002),
            SeqStep::new(2, "stratum_conn".to_string(), 5003),
            SeqStep::new(3, "mining_process".to_string(), 5004),
        ],
        Some(120_000), None,
    );
    let compiled = CompiledSequence {
        id: "cryptomining_detection".to_string(),
        sequence, rule_id: "rule-crypto-001".to_string(),
        rule_name: "Cryptomining Malware Detection".to_string(),
    };
    engine.load_sequence(compiled).unwrap();

    let entity_key: u128 = 0x99999999;
    let base_time = 5_000_000_000;

    assert!(engine.process_event(&create_test_event(5001, base_time, entity_key)).unwrap().is_empty());
    assert!(engine.process_event(&create_test_event(5002, base_time + 10_000_000, entity_key)).unwrap().is_empty());
    assert!(engine.process_event(&create_test_event(5003, base_time + 20_000_000, entity_key)).unwrap().is_empty());
    
    let alerts = engine.process_event(&create_test_event(5004, base_time + 30_000_000, entity_key)).unwrap();
    assert_eq!(alerts.len(), 1, "Should detect cryptomining!");
}

#[test]
fn test_multi_stage_web_attack() {
    let config = NfaEngineConfig::default();
    let mut evaluator = TestPredicateEvaluator::new();
    evaluator.register("sql_injection", |e| e.event_type_id == 6001);
    evaluator.register("privilege_escalation", |e| e.event_type_id == 6002);
    evaluator.register("web_shell", |e| e.event_type_id == 6003);
    evaluator.register("data_breach", |e| e.event_type_id == 6004);

    let mut engine = NfaEngine::new(config, Arc::new(evaluator));
    let sequence = NfaSequence::new(
        "web_attack_chain".to_string(), 1,
        vec![
            SeqStep::new(0, "sql_injection".to_string(), 6001),
            SeqStep::new(1, "privilege_escalation".to_string(), 6002),
            SeqStep::new(2, "web_shell".to_string(), 6003),
            SeqStep::new(3, "data_breach".to_string(), 6004),
        ],
        Some(180_000), None,
    );
    let compiled = CompiledSequence {
        id: "web_attack_chain".to_string(),
        sequence, rule_id: "rule-web-001".to_string(),
        rule_name: "Multi-Stage Web Attack".to_string(),
    };
    engine.load_sequence(compiled).unwrap();

    let entity_key: u128 = 0xabcdef01;
    let base_time = 6_000_000_000;

    assert!(engine.process_event(&create_test_event(6001, base_time, entity_key)).unwrap().is_empty());
    assert!(engine.process_event(&create_test_event(6002, base_time + 30_000_000, entity_key)).unwrap().is_empty());
    assert!(engine.process_event(&create_test_event(6003, base_time + 60_000_000, entity_key)).unwrap().is_empty());
    
    let alerts = engine.process_event(&create_test_event(6004, base_time + 90_000_000, entity_key)).unwrap();
    assert_eq!(alerts.len(), 1, "Should detect multi-stage web attack!");
}
