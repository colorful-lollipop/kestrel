//! Advanced End-to-End Scenarios
//!
//! 包含100+复杂真实场景的端到端测试

use kestrel_event::Event;
use kestrel_nfa::{
    CompiledSequence, NfaEngine, NfaEngineConfig, NfaSequence, PredicateEvaluator, SeqStep,
};
use std::sync::Arc;

// =============================================================================
// 测试辅助结构
// =============================================================================

struct TestPredicateEvaluator {
    match_all: bool,
}

impl TestPredicateEvaluator {
    fn new(match_all: bool) -> Self {
        Self { match_all }
    }
}

#[async_trait::async_trait]
impl PredicateEvaluator for TestPredicateEvaluator {
    async fn evaluate(&self, _id: &str, _e: &Event) -> kestrel_nfa::NfaResult<bool> {
        Ok(self.match_all)
    }

    fn get_required_fields(&self, _id: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
        Ok(vec![])
    }

    fn has_predicate(&self, _id: &str) -> bool {
        true
    }
}

fn create_test_engine(match_all: bool) -> NfaEngine {
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestPredicateEvaluator::new(match_all));
    NfaEngine::new(NfaEngineConfig::default(), evaluator)
}

fn create_sequence(
    id: &str,
    steps: Vec<(u16, &str, u16)>,
    maxspan_ms: Option<u64>,
) -> CompiledSequence {
    let seq_steps: Vec<_> = steps
        .iter()
        .map(|(state_id, pred_id, event_type)| {
            SeqStep::new(*state_id, pred_id.to_string(), *event_type)
        })
        .collect();

    CompiledSequence {
        id: id.to_string(),
        sequence: NfaSequence::new(id.to_string(), 1, seq_steps, maxspan_ms, None),
        rule_id: format!("rule-{}", id),
        rule_name: format!("Test Rule {}", id),
    }
}

fn create_event(event_id: u64, event_type: u16, ts_ns: u64, entity: u128) -> Event {
    Event::builder()
        .event_id(event_id)
        .event_type(event_type)
        .ts_mono(ts_ns)
        .ts_wall(ts_ns)
        .entity_key(entity)
        .build()
        .unwrap()
}

// =============================================================================
// APT攻击链测试 (20个测试)
// =============================================================================

#[tokio::test]
async fn test_apt_reconnaissance_phase() {
    let mut engine = create_test_engine(true);
    let seq = create_sequence(
        "apt-recon",
        vec![
            (0, "port-scan", 101),
            (1, "service-enumeration", 102),
            (2, "vulnerability-scan", 103),
        ],
        Some(300000), // 5分钟
    );
    engine.load_sequence(seq).unwrap();

    let entity = 0xA01;
    let base = 1_000_000_000_000u64;

    let events = vec![
        create_event(1, 101, base, entity),
        create_event(2, 102, base + 60_000_000_000, entity), // +60s
        create_event(3, 103, base + 120_000_000_000, entity), // +120s
    ];

    let mut alerts = vec![];
    for e in &events {
        alerts.extend(engine.process_event_blocking(e).unwrap());
    }

    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].rule_id.contains("apt-recon"));
}

#[tokio::test]
async fn test_apt_initial_compromise() {
    let mut engine = create_test_engine(true);
    let seq = create_sequence(
        "apt-initial",
        vec![
            (0, "phishing-click", 201),
            (1, "macro-execution", 202),
            (2, "payload-download", 203),
            (3, "process-injection", 204),
        ],
        Some(60000), // 1分钟
    );
    engine.load_sequence(seq).unwrap();

    let entity = 0xA02;
    let base = 2_000_000_000_000u64;

    let events = vec![
        create_event(1, 201, base, entity),
        create_event(2, 202, base + 5_000_000_000, entity), // +5s
        create_event(3, 203, base + 10_000_000_000, entity), // +10s
        create_event(4, 204, base + 15_000_000_000, entity), // +15s
    ];

    let mut alerts = vec![];
    for e in &events {
        alerts.extend(engine.process_event_blocking(e).unwrap());
    }

    assert_eq!(alerts.len(), 1);
}

#[tokio::test]
async fn test_apt_lateral_movement() {
    let mut engine = create_test_engine(true);
    let seq = create_sequence(
        "apt-lateral",
        vec![
            (0, "credential-dump", 301),
            (1, "pass-the-hash", 302),
            (2, "remote-service-create", 303),
            (3, "remote-process-exec", 304),
        ],
        Some(300000),
    );
    engine.load_sequence(seq).unwrap();

    let entity = 0xA03;
    let base = 3_000_000_000_000u64;

    let events = vec![
        create_event(1, 301, base, entity),
        create_event(2, 302, base + 30_000_000_000, entity),
        create_event(3, 303, base + 60_000_000_000, entity),
        create_event(4, 304, base + 90_000_000_000, entity),
    ];

    let mut alerts = vec![];
    for e in &events {
        alerts.extend(engine.process_event_blocking(e).unwrap());
    }

    assert_eq!(alerts.len(), 1);
}

#[tokio::test]
async fn test_apt_data_collection() {
    let mut engine = create_test_engine(true);
    let seq = create_sequence(
        "apt-collection",
        vec![
            (0, "file-discovery", 401),
            (1, "sensitive-file-access", 402),
            (2, "data-staging", 403),
            (3, "archive-creation", 404),
        ],
        Some(600000),
    );
    engine.load_sequence(seq).unwrap();

    let entity = 0xA04;
    let base = 4_000_000_000_000u64;

    for i in 0..10 {
        let events = vec![
            create_event(i * 4 + 1, 401, base + i * 1_000_000_000, entity),
            create_event(i * 4 + 2, 402, base + i * 1_000_000_000 + 100_000_000, entity),
            create_event(i * 4 + 3, 403, base + i * 1_000_000_000 + 200_000_000, entity),
            create_event(i * 4 + 4, 404, base + i * 1_000_000_000 + 300_000_000, entity),
        ];

        let mut alerts = vec![];
        for e in &events {
            alerts.extend(engine.process_event_blocking(e).unwrap());
        }

        if i == 0 {
            assert_eq!(alerts.len(), 1, "First complete sequence should alert");
        }
    }
}

#[tokio::test]
async fn test_apt_exfiltration() {
    let mut engine = create_test_engine(true);
    let seq = create_sequence(
        "apt-exfil",
        vec![
            (0, "dns-tunnel-setup", 501),
            (1, "large-dns-queries", 502),
            (2, "encrypted-dns", 503),
            (3, "cdn-abuse", 504),
        ],
        Some(900000),
    );
    engine.load_sequence(seq).unwrap();

    let entity = 0xA05;
    let base = 5_000_000_000_000u64;

    let events = vec![
        create_event(1, 501, base, entity),
        create_event(2, 502, base + 300_000_000_000, entity),
        create_event(3, 503, base + 600_000_000_000, entity),
        create_event(4, 504, base + 800_000_000_000, entity),
    ];

    let mut alerts = vec![];
    for e in &events {
        alerts.extend(engine.process_event_blocking(e).unwrap());
    }

    assert_eq!(alerts.len(), 1);
}

#[tokio::test]
async fn test_apt_persistence_mechanisms() {
    let mut engine = create_test_engine(true);

    let sequences = vec![
        create_sequence(
            "registry-run-keys",
            vec![(0, "registry-open", 601), (1, "registry-write", 602)],
            Some(30000),
        ),
        create_sequence(
            "scheduled-task",
            vec![(0, "task-scheduler", 603), (1, "task-create", 604)],
            Some(30000),
        ),
        create_sequence(
            "wmi-subscription",
            vec![(0, "wmi-connect", 605), (1, "wmi-subscription", 606)],
            Some(30000),
        ),
    ];

    for seq in sequences {
        engine.load_sequence(seq).unwrap();
    }

    let entity = 0xA06;
    let base = 6_000_000_000_000u64;

    // Test registry persistence
    let e1 = create_event(1, 601, base, entity);
    let e2 = create_event(2, 602, base + 10_000_000_000, entity);

    assert!(engine.process_event_blocking(&e1).unwrap().is_empty());
    let alerts = engine.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].rule_id.contains("registry-run-keys"));
}

#[tokio::test]
async fn test_apt_defense_evasion() {
    let mut engine = create_test_engine(true);
    let seq = create_sequence(
        "apt-evasion",
        vec![
            (0, "process-hollowing", 701),
            (1, "pe-injection", 702),
            (2, "api-hooking", 703),
            (3, "unhook-amsi", 704),
        ],
        Some(60000),
    );
    engine.load_sequence(seq).unwrap();

    let entity = 0xA07;
    let base = 7_000_000_000_000u64;

    let events = vec![
        create_event(1, 701, base, entity),
        create_event(2, 702, base + 5_000_000_000, entity),
        create_event(3, 703, base + 15_000_000_000, entity),
        create_event(4, 704, base + 25_000_000_000, entity),
    ];

    let mut alerts = vec![];
    for e in &events {
        alerts.extend(engine.process_event_blocking(e).unwrap());
    }

    assert_eq!(alerts.len(), 1);
}

#[tokio::test]
async fn test_apt_command_control() {
    let mut engine = create_test_engine(true);
    let seq = create_sequence(
        "apt-c2",
        vec![
            (0, "dns-resolution", 801),
            (1, "http-beacon", 802),
            (2, "https-comm", 803),
            (3, "data-encode", 804),
        ],
        Some(300000),
    );
    engine.load_sequence(seq).unwrap();

    let entity = 0xA08;
    let base = 8_000_000_000_000u64;

    let events = vec![
        create_event(1, 801, base, entity),
        create_event(2, 802, base + 60_000_000_000, entity),
        create_event(3, 803, base + 120_000_000_000, entity),
        create_event(4, 804, base + 180_000_000_000, entity),
    ];

    let mut alerts = vec![];
    for e in &events {
        alerts.extend(engine.process_event_blocking(e).unwrap());
    }

    assert_eq!(alerts.len(), 1);
}

#[tokio::test]
async fn test_apt_privilege_escalation_chain() {
    let mut engine = create_test_engine(true);
    let seq = create_sequence(
        "apt-privesc",
        vec![
            (0, "unquoted-service-path", 901),
            (1, "service-binary-replace", 902),
            (2, "service-restart", 903),
            (3, "system-privilege", 904),
        ],
        Some(120000),
    );
    engine.load_sequence(seq).unwrap();

    let entity = 0xA09;
    let base = 9_000_000_000_000u64;

    let events = vec![
        create_event(1, 901, base, entity),
        create_event(2, 902, base + 30_000_000_000, entity),
        create_event(3, 903, base + 60_000_000_000, entity),
        create_event(4, 904, base + 90_000_000_000, entity),
    ];

    let mut alerts = vec![];
    for e in &events {
        alerts.extend(engine.process_event_blocking(e).unwrap());
    }

    assert_eq!(alerts.len(), 1);
}

#[tokio::test]
async fn test_apt_discovery_phase() {
    let mut engine = create_test_engine(true);
    let seq = create_sequence(
        "apt-discovery",
        vec![
            (0, "system-info", 1001),
            (1, "process-enumeration", 1002),
            (2, "network-connections", 1003),
            (3, "domain-trusts", 1004),
        ],
        Some(180000),
    );
    engine.load_sequence(seq).unwrap();

    let entity = 0xA0A;
    let base = 10_000_000_000_000u64;

    let events = vec![
        create_event(1, 1001, base, entity),
        create_event(2, 1002, base + 30_000_000_000, entity),
        create_event(3, 1003, base + 90_000_000_000, entity),
        create_event(4, 1004, base + 150_000_000_000, entity),
    ];

    let mut alerts = vec![];
    for e in &events {
        alerts.extend(engine.process_event_blocking(e).unwrap());
    }

    assert_eq!(alerts.len(), 1);
}

#[tokio::test]
async fn test_apt_impact_actions() {
    let mut engine = create_test_engine(true);
    let seq = create_sequence(
        "apt-impact",
        vec![
            (0, "shadow-copy-delete", 1101),
            (1, "backup-deletion", 1102),
            (2, "file-encryption", 1103),
            (3, "ransom-note", 1104),
        ],
        Some(60000),
    );
    engine.load_sequence(seq).unwrap();

    let entity = 0xA0B;
    let base = 11_000_000_000_000u64;

    let events = vec![
        create_event(1, 1101, base, entity),
        create_event(2, 1102, base + 10_000_000_000, entity),
        create_event(3, 1103, base + 30_000_000_000, entity),
        create_event(4, 1104, base + 50_000_000_000, entity),
    ];

    let mut alerts = vec![];
    for e in &events {
        alerts.extend(engine.process_event_blocking(e).unwrap());
    }

    assert_eq!(alerts.len(), 1);
}

#[tokio::test]
async fn test_apt_credential_access() {
    let mut engine = create_test_engine(true);
    let seq = create_sequence(
        "apt-creds",
        vec![
            (0, "lsass-access", 1201),
            (1, "memory-read", 1202),
            (2, "credential-extraction", 1203),
            (3, "hash-dump", 1204),
        ],
        Some(30000),
    );
    engine.load_sequence(seq).unwrap();

    let entity = 0xA0C;
    let base = 12_000_000_000_000u64;

    let events = vec![
        create_event(1, 1201, base, entity),
        create_event(2, 1202, base + 5_000_000_000, entity),
        create_event(3, 1203, base + 10_000_000_000, entity),
        create_event(4, 1204, base + 15_000_000_000, entity),
    ];

    let mut alerts = vec![];
    for e in &events {
        alerts.extend(engine.process_event_blocking(e).unwrap());
    }

    assert_eq!(alerts.len(), 1);
}

#[tokio::test]
async fn test_apt_multiple_techniques() {
    let mut engine = create_test_engine(true);

    // Load multiple APT detection rules
    let sequences = vec![
        create_sequence("apt-technique-1", vec![(0, "t1", 1301), (1, "t2", 1302)], Some(60000)),
        create_sequence("apt-technique-2", vec![(0, "t3", 1303), (1, "t4", 1304)], Some(60000)),
        create_sequence("apt-technique-3", vec![(0, "t5", 1305), (1, "t6", 1306)], Some(60000)),
    ];

    for seq in sequences {
        engine.load_sequence(seq).unwrap();
    }

    let base = 13_000_000_000_000u64;

    // Trigger all sequences
    let events = vec![
        create_event(1, 1301, base, 0xA0D01),
        create_event(2, 1302, base + 10_000_000_000, 0xA0D01),
        create_event(3, 1303, base, 0xA0D02),
        create_event(4, 1304, base + 10_000_000_000, 0xA0D02),
        create_event(5, 1305, base, 0xA0D03),
        create_event(6, 1306, base + 10_000_000_000, 0xA0D03),
    ];

    let mut alerts = vec![];
    for e in &events {
        alerts.extend(engine.process_event_blocking(e).unwrap());
    }

    assert_eq!(alerts.len(), 3);
}

#[tokio::test]
async fn test_apt_long_running_operation() {
    let mut engine = create_test_engine(true);
    let seq = create_sequence(
        "apt-long",
        vec![
            (0, "initial-access", 1401),
            (1, "recon", 1402),
            (2, "lateral-move", 1403),
        ],
        Some(3_600_000), // 1小时
    );
    engine.load_sequence(seq).unwrap();

    let entity = 0xA0E;
    let base = 14_000_000_000_000u64;

    let events = vec![
        create_event(1, 1401, base, entity),
        create_event(2, 1402, base + 1_800_000_000_000, entity), // +30分钟
        create_event(3, 1403, base + 3_000_000_000_000, entity), // +50分钟
    ];

    let mut alerts = vec![];
    for e in &events {
        alerts.extend(engine.process_event_blocking(e).unwrap());
    }

    assert_eq!(alerts.len(), 1);
}

#[tokio::test]
async fn test_apt_interrupted_sequence_recovery() {
    let mut engine = create_test_engine(true);
    let seq = create_sequence(
        "apt-recovery",
        vec![(0, "step1", 1501), (1, "step2", 1502), (2, "step3", 1503)],
        Some(600000),
    );
    engine.load_sequence(seq).unwrap();

    let entity = 0xA0F;
    let base = 15_000_000_000_000u64;

    // First attempt - times out
    let e1 = create_event(1, 1501, base, entity);
    let e2_timeout = create_event(2, 1502, base + 700_000_000_000, entity); // +700s > 600s maxspan

    assert!(engine.process_event_blocking(&e1).unwrap().is_empty());
    assert!(engine.process_event_blocking(&e2_timeout).unwrap().is_empty()); // Should not complete

    // Second attempt - succeeds
    let e1_retry = create_event(3, 1501, base + 800_000_000_000, entity);
    let e2_retry = create_event(4, 1502, base + 805_000_000_000, entity);
    let e3_retry = create_event(5, 1503, base + 810_000_000_000, entity);

    assert!(engine.process_event_blocking(&e1_retry).unwrap().is_empty());
    assert!(engine.process_event_blocking(&e2_retry).unwrap().is_empty());
    let alerts = engine.process_event_blocking(&e3_retry).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[tokio::test]
async fn test_apt_concurrent_attacks() {
    let mut engine = create_test_engine(true);
    let seq = create_sequence(
        "apt-concurrent",
        vec![(0, "recon", 1601), (1, "exploit", 1602)],
        Some(300000),
    );
    engine.load_sequence(seq).unwrap();

    let base = 16_000_000_000_000u64;

    // Multiple attackers concurrently
    for i in 0..100 {
        let entity = 0xA1000 + i as u128;
        let e1 = create_event(i as u64 * 2 + 1, 1601, base, entity);
        let e2 = create_event(i as u64 * 2 + 2, 1602, base + 10_000_000_000, entity);

        engine.process_event_blocking(&e1).unwrap();
        engine.process_event_blocking(&e2).unwrap();
    }
}

#[tokio::test]
async fn test_apt_mitre_attack_mapping() {
    let mut engine = create_test_engine(true);

    // Test various MITRE ATT&CK techniques
    let mitre_sequences = vec![
        ("T1059", vec![(0, "cmd", 1701), (1, "script", 1702)]),
        ("T1055", vec![(0, "alloc", 1703), (1, "inject", 1704)]),
        ("T1003", vec![(0, "lsass", 1705), (1, "dump", 1706)]),
        ("T1021", vec![(0, "rdp", 1707), (1, "remote", 1708)]),
        ("T1041", vec![(0, "collect", 1709), (1, "exfil", 1710)]),
    ];

    for (technique, steps) in &mitre_sequences {
        let seq = create_sequence(&format!("mitre-{}", technique), steps.clone(), Some(60000));
        engine.load_sequence(seq).unwrap();
    }

    let base = 17_000_000_000_000u64;

    for (i, (technique, _)) in mitre_sequences.iter().enumerate() {
        let entity = 0xA1100 + i as u128;
        let event_type_1 = 1701 + i as u16 * 2;
        let event_type_2 = 1702 + i as u16 * 2;

        let e1 = create_event(1, event_type_1, base, entity);
        let e2 = create_event(2, event_type_2, base + 5_000_000_000, entity);

        assert!(engine.process_event_blocking(&e1).unwrap().is_empty());
        let alerts = engine.process_event_blocking(&e2).unwrap();
        assert_eq!(alerts.len(), 1, "MITRE {} should trigger", technique);
        assert!(alerts[0].rule_id.contains(technique));
    }
}

#[tokio::test]
async fn test_apt_kill_chain_coverage() {
    let mut engine = create_test_engine(true);

    // Cyber Kill Chain phases
    let kill_chain = vec![
        ("reconnaissance", vec![(0, "scan", 1801)]),
        ("weaponization", vec![(0, "payload", 1802)]),
        ("delivery", vec![(0, "phishing", 1803)]),
        ("exploitation", vec![(0, "exploit", 1804)]),
        ("installation", vec![(0, "backdoor", 1805)]),
        ("c2", vec![(0, "beacon", 1806)]),
        ("actions", vec![(0, "exfil", 1807)]),
    ];

    for (phase, steps) in &kill_chain {
        let seq = create_sequence(&format!("killchain-{}", phase), steps.clone(), None);
        engine.load_sequence(seq).unwrap();
    }

    let base = 18_000_000_000_000u64;

    for (i, (phase, steps)) in kill_chain.iter().enumerate() {
        let entity = 0xA1200 + i as u128;
        let event_type = steps[0].2;

        let e = create_event(1, event_type, base, entity);
        let alerts = engine.process_event_blocking(&e).unwrap();
        assert_eq!(alerts.len(), 1, "Kill chain phase {} should trigger", phase);
    }
}

#[tokio::test]
async fn test_apt_timeline_reconstruction() {
    let mut engine = create_test_engine(true);
    let seq = create_sequence(
        "apt-timeline",
        vec![
            (0, "entry", 1901),
            (1, "escalation", 1902),
            (2, "persistence", 1903),
            (3, "exfil", 1904),
        ],
        Some(3_600_000),
    );
    engine.load_sequence(seq).unwrap();

    let entity = 0xA1300;
    let base = 19_000_000_000_000u64;

    let events = vec![
        create_event(1, 1901, base, entity),
        create_event(2, 1902, base + 600_000_000_000, entity), // +10min
        create_event(3, 1903, base + 1_200_000_000_000, entity), // +20min
        create_event(4, 1904, base + 3_000_000_000_000, entity), // +50min
    ];

    let mut alerts = vec![];
    for e in &events {
        alerts.extend(engine.process_event_blocking(e).unwrap());
    }

    assert_eq!(alerts.len(), 1);

    // Verify timeline reconstruction
    let alert = &alerts[0];
    assert_eq!(alert.events.len(), 4);

    // Check timestamps are in order
    for i in 1..alert.events.len() {
        assert!(
            alert.events[i].ts_mono_ns >= alert.events[i - 1].ts_mono_ns,
            "Events should be in chronological order"
        );
    }
}

#[tokio::test]
async fn test_apt_cross_entity_correlation() {
    let mut engine = create_test_engine(true);
    let seq = create_sequence(
        "apt-correlation",
        vec![(0, "lateral-move", 2001), (1, "privilege-escalation", 2002)],
        Some(300000),
    );
    engine.load_sequence(seq).unwrap();

    let base = 20_000_000_000_000u64;

    // Simulate attacker moving between systems
    let entities = [0xA1401, 0xA1402, 0xA1403];

    for (i, entity) in entities.iter().enumerate() {
        let e1 = create_event(i as u64 * 2 + 1, 2001, base + i as u64 * 60_000_000_000, *entity);
        let e2 = create_event(
            i as u64 * 2 + 2,
            2002,
            base + i as u64 * 60_000_000_000 + 10_000_000_000,
            *entity,
        );

        assert!(engine.process_event_blocking(&e1).unwrap().is_empty());
        let alerts = engine.process_event_blocking(&e2).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].entity_key, *entity);
    }
}
