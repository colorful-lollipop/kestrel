//! Threat Hunting Tests
//!
//! 威胁狩猎场景测试 - 检测高级持续性威胁(APT)和隐蔽攻击

use kestrel_event::Event;
use kestrel_nfa::{
    CompiledSequence, NfaEngine, NfaEngineConfig, NfaSequence, PredicateEvaluator, SeqStep,
};
use std::sync::Arc;

struct TestPredicateEvaluator;

#[async_trait::async_trait]
impl PredicateEvaluator for TestPredicateEvaluator {
    async fn evaluate(&self, _id: &str, _e: &Event) -> kestrel_nfa::NfaResult<bool> {
        Ok(true)
    }
    fn get_required_fields(&self, _id: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
        Ok(vec![])
    }
    fn has_predicate(&self, _id: &str) -> bool {
        true
    }
}

fn create_hunting_engine() -> NfaEngine {
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestPredicateEvaluator);
    NfaEngine::new(NfaEngineConfig::default(), evaluator)
}

fn create_hunting_event(event_type: u16, entity: u128, timestamp_ns: u64) -> Event {
    Event::builder()
        .event_type(event_type)
        .ts_mono(timestamp_ns)
        .ts_wall(timestamp_ns)
        .entity_key(entity)
        .build()
        .unwrap()
}

// =============================================================================
// Living Off The Land (LOTL) 攻击检测
// =============================================================================

#[test]
fn test_lotl_powershell_encode_command() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "lotl-powershell".to_string(),
        sequence: NfaSequence::new(
            "lotl-powershell".to_string(),
            100,
            vec![
                SeqStep::new(0, "powershell-start".to_string(), 1001),
                SeqStep::new(1, "encoded-command".to_string(), 1002),
            ],
            Some(30000),
            None,
        ),
        rule_id: "lotl-detect".to_string(),
        rule_name: "LOTL PowerShell Encoded".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA001u128;
    let base = 1_000_000_000u64;

    let e1 = create_hunting_event(1001, entity, base);
    assert!(nfa.process_event_blocking(Arc::new(e1.clone())).unwrap().is_empty());

    let e2 = create_hunting_event(1002, entity, base + 10_000_000);
    let alerts = nfa.process_event_blocking(Arc::new(e2.clone())).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_lotl_certutil_download() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "lotl-certutil".to_string(),
        sequence: NfaSequence::new(
            "lotl-certutil".to_string(),
            101,
            vec![
                SeqStep::new(0, "certutil-exec".to_string(), 1003),
                SeqStep::new(1, "urlcache-download".to_string(), 1004),
            ],
            Some(60000),
            None,
        ),
        rule_id: "lotl-certutil-detect".to_string(),
        rule_name: "LOTL CertUtil Download".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA002u128;
    let base = 2_000_000_000u64;

    let e1 = create_hunting_event(1003, entity, base);
    let e2 = create_hunting_event(1004, entity, base + 50_000_000);

    assert!(nfa.process_event_blocking(Arc::new(e1.clone())).unwrap().is_empty());
    assert_eq!(nfa.process_event_blocking(Arc::new(e2.clone())).unwrap().len(), 1);
}

#[test]
fn test_lotl_mshta_javascript() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "lotl-mshta".to_string(),
        sequence: NfaSequence::new(
            "lotl-mshta".to_string(),
            102,
            vec![
                SeqStep::new(0, "mshta-start".to_string(), 1005),
                SeqStep::new(1, "javascript-exec".to_string(), 1006),
            ],
            Some(30000),
            None,
        ),
        rule_id: "lotl-mshta-detect".to_string(),
        rule_name: "LOTL MSHTA JavaScript".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA003u128;
    let base = 3_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1005, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1006, entity, base + 100_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_lotl_rundll32_suspicious_export() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "lotl-rundll32".to_string(),
        sequence: NfaSequence::new(
            "lotl-rundll32".to_string(),
            103,
            vec![
                SeqStep::new(0, "rundll32-start".to_string(), 1007),
                SeqStep::new(1, "suspicious-export".to_string(), 1008),
            ],
            Some(20000),
            None,
        ),
        rule_id: "lotl-rundll32-detect".to_string(),
        rule_name: "LOTL RunDLL32 Suspicious".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA004u128;
    let base = 4_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1007, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1008, entity, base + 50_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_lotl_regsvr32_scrobj() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "lotl-regsvr32".to_string(),
        sequence: NfaSequence::new(
            "lotl-regsvr32".to_string(),
            104,
            vec![
                SeqStep::new(0, "regsvr32-start".to_string(), 1009),
                SeqStep::new(1, "scrobj-script".to_string(), 1010),
            ],
            Some(30000),
            None,
        ),
        rule_id: "lotl-regsvr32-detect".to_string(),
        rule_name: "LOTL RegSvr32 Scrobj".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA005u128;
    let base = 5_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1009, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1010, entity, base + 50_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_lotl_wmic_process_creation() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "lotl-wmic".to_string(),
        sequence: NfaSequence::new(
            "lotl-wmic".to_string(),
            105,
            vec![
                SeqStep::new(0, "wmic-start".to_string(), 1011),
                SeqStep::new(1, "process-create".to_string(), 1012),
            ],
            Some(60000),
            None,
        ),
        rule_id: "lotl-wmic-detect".to_string(),
        rule_name: "LOTL WMIC Process Create".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA006u128;
    let base = 6_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1011, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1012, entity, base + 100_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_lotl_cscript_wscript_execution() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "lotl-cscript".to_string(),
        sequence: NfaSequence::new(
            "lotl-cscript".to_string(),
            106,
            vec![
                SeqStep::new(0, "cscript-start".to_string(), 1013),
                SeqStep::new(1, "vbs-execution".to_string(), 1014),
            ],
            Some(30000),
            None,
        ),
        rule_id: "lotl-cscript-detect".to_string(),
        rule_name: "LOTL CScript Execution".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA007u128;
    let base = 7_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1013, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1014, entity, base + 50_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

// =============================================================================
// 凭证访问和窃取检测
// =============================================================================

#[test]
fn test_credential_mimikatz_execution() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "cred-mimikatz".to_string(),
        sequence: NfaSequence::new(
            "cred-mimikatz".to_string(),
            110,
            vec![
                SeqStep::new(0, "mimikatz-exec".to_string(), 1015),
                SeqStep::new(1, "sekurlsa-logonpasswords".to_string(), 1016),
            ],
            Some(10000),
            None,
        ),
        rule_id: "cred-mimikatz-detect".to_string(),
        rule_name: "Credential Mimikatz".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA010u128;
    let base = 10_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1015, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1016, entity, base + 5_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_credential_lsass_access() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "cred-lsass".to_string(),
        sequence: NfaSequence::new(
            "cred-lsass".to_string(),
            111,
            vec![
                SeqStep::new(0, "lsass-target".to_string(), 1017),
                SeqStep::new(1, "openprocess-call".to_string(), 1018),
            ],
            Some(5000),
            None,
        ),
        rule_id: "cred-lsass-detect".to_string(),
        rule_name: "Credential LSASS Access".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA011u128;
    let base = 11_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1017, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1018, entity, base + 1_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_credential_sam_database_access() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "cred-sam".to_string(),
        sequence: NfaSequence::new(
            "cred-sam".to_string(),
            112,
            vec![
                SeqStep::new(0, "reg-sam-access".to_string(), 1019),
                SeqStep::new(1, "sam-export".to_string(), 1020),
            ],
            Some(10000),
            None,
        ),
        rule_id: "cred-sam-detect".to_string(),
        rule_name: "Credential SAM Access".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA012u128;
    let base = 12_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1019, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1020, entity, base + 50_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_credential_ntds_dit_extraction() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "cred-ntds".to_string(),
        sequence: NfaSequence::new(
            "cred-ntds".to_string(),
            113,
            vec![
                SeqStep::new(0, "ntdsutil-start".to_string(), 1021),
                SeqStep::new(1, "ac-ntds".to_string(), 1022),
                SeqStep::new(2, "ifm-create".to_string(), 1023),
            ],
            Some(300000),
            None,
        ),
        rule_id: "cred-ntds-detect".to_string(),
        rule_name: "Credential NTDS Extraction".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA013u128;
    let base = 13_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1021, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1022, entity, base + 100_000_000).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1023, entity, base + 200_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_credential_kerberoasting() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "cred-kerberoast".to_string(),
        sequence: NfaSequence::new(
            "cred-kerberoast".to_string(),
            114,
            vec![
                SeqStep::new(0, "kerberoast-start".to_string(), 1024),
                SeqStep::new(1, "tgs-req-spn".to_string(), 1025),
                SeqStep::new(2, "rc4-hmac-ticket".to_string(), 1026),
            ],
            Some(60000),
            None,
        ),
        rule_id: "cred-kerberoast-detect".to_string(),
        rule_name: "Credential Kerberoasting".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA014u128;
    let base = 14_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1024, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1025, entity, base + 500_000_000).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1026, entity, base + 1_000_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

// =============================================================================
// 权限维持和持久化检测
// =============================================================================

#[test]
fn test_persistence_registry_run_keys() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "persist-runkeys".to_string(),
        sequence: NfaSequence::new(
            "persist-runkeys".to_string(),
            120,
            vec![
                SeqStep::new(0, "reg-start".to_string(), 1027),
                SeqStep::new(1, "run-key-add".to_string(), 1028),
            ],
            Some(30000),
            None,
        ),
        rule_id: "persist-runkeys-detect".to_string(),
        rule_name: "Persistence Run Keys".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA020u128;
    let base = 20_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1027, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1028, entity, base + 50_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_persistence_scheduled_task_creation() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "persist-schtask".to_string(),
        sequence: NfaSequence::new(
            "persist-schtask".to_string(),
            121,
            vec![
                SeqStep::new(0, "schtasks-start".to_string(), 1029),
                SeqStep::new(1, "task-create".to_string(), 1030),
            ],
            Some(60000),
            None,
        ),
        rule_id: "persist-schtask-detect".to_string(),
        rule_name: "Persistence Scheduled Task".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA021u128;
    let base = 21_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1029, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1030, entity, base + 100_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_persistence_wmi_event_subscription() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "persist-wmi".to_string(),
        sequence: NfaSequence::new(
            "persist-wmi".to_string(),
            122,
            vec![
                SeqStep::new(0, "wmi-namespace".to_string(), 1031),
                SeqStep::new(1, "eventfilter-create".to_string(), 1032),
            ],
            Some(60000),
            None,
        ),
        rule_id: "persist-wmi-detect".to_string(),
        rule_name: "Persistence WMI Subscription".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA022u128;
    let base = 22_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1031, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1032, entity, base + 100_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_persistence_service_creation() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "persist-service".to_string(),
        sequence: NfaSequence::new(
            "persist-service".to_string(),
            123,
            vec![
                SeqStep::new(0, "sc-start".to_string(), 1033),
                SeqStep::new(1, "service-create".to_string(), 1034),
            ],
            Some(60000),
            None,
        ),
        rule_id: "persist-service-detect".to_string(),
        rule_name: "Persistence Service Create".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA023u128;
    let base = 23_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1033, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1034, entity, base + 100_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_persistence_dll_search_order_hijacking() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "persist-dll-hijack".to_string(),
        sequence: NfaSequence::new(
            "persist-dll-hijack".to_string(),
            124,
            vec![
                SeqStep::new(0, "legit-app-start".to_string(), 1035),
                SeqStep::new(1, "dll-side-load".to_string(), 1036),
            ],
            Some(30000),
            None,
        ),
        rule_id: "persist-dll-hijack-detect".to_string(),
        rule_name: "Persistence DLL Hijacking".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA024u128;
    let base = 24_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1035, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1036, entity, base + 100_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

// =============================================================================
// 横向移动检测
// =============================================================================

#[test]
fn test_lateral_psexec_usage() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "lat-psexec".to_string(),
        sequence: NfaSequence::new(
            "lat-psexec".to_string(),
            130,
            vec![
                SeqStep::new(0, "psexec-start".to_string(), 1037),
                SeqStep::new(1, "remote-exec".to_string(), 1038),
            ],
            Some(60000),
            None,
        ),
        rule_id: "lat-psexec-detect".to_string(),
        rule_name: "Lateral PsExec".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA030u128;
    let base = 30_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1037, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1038, entity, base + 100_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_lateral_wmi_exec() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "lat-wmi".to_string(),
        sequence: NfaSequence::new(
            "lat-wmi".to_string(),
            131,
            vec![
                SeqStep::new(0, "wmi-exec-start".to_string(), 1039),
                SeqStep::new(1, "remote-process-create".to_string(), 1040),
            ],
            Some(60000),
            None,
        ),
        rule_id: "lat-wmi-detect".to_string(),
        rule_name: "Lateral WMI Exec".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA031u128;
    let base = 31_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1039, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1040, entity, base + 100_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_lateral_winrm_remote_execution() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "lat-winrm".to_string(),
        sequence: NfaSequence::new(
            "lat-winrm".to_string(),
            132,
            vec![
                SeqStep::new(0, "winrs-start".to_string(), 1041),
                SeqStep::new(1, "remote-cmd-exec".to_string(), 1042),
            ],
            Some(60000),
            None,
        ),
        rule_id: "lat-winrm-detect".to_string(),
        rule_name: "Lateral WinRM".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA032u128;
    let base = 32_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1041, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1042, entity, base + 100_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_lateral_remote_scheduled_task() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "lat-remote-schtask".to_string(),
        sequence: NfaSequence::new(
            "lat-remote-schtask".to_string(),
            133,
            vec![
                SeqStep::new(0, "schtasks-remote".to_string(), 1043),
                SeqStep::new(1, "remote-task-create".to_string(), 1044),
            ],
            Some(120000),
            None,
        ),
        rule_id: "lat-remote-schtask-detect".to_string(),
        rule_name: "Lateral Remote SchTask".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA033u128;
    let base = 33_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1043, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1044, entity, base + 100_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_lateral_smb_admin_share() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "lat-smb-admin".to_string(),
        sequence: NfaSequence::new(
            "lat-smb-admin".to_string(),
            134,
            vec![
                SeqStep::new(0, "smb-admin-connect".to_string(), 1045),
                SeqStep::new(1, "file-copy-admin".to_string(), 1046),
            ],
            Some(60000),
            None,
        ),
        rule_id: "lat-smb-admin-detect".to_string(),
        rule_name: "Lateral SMB Admin".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA034u128;
    let base = 34_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1045, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1046, entity, base + 100_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

// =============================================================================
// 防御规避检测
// =============================================================================

#[test]
fn test_evasion_process_hollowing() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "evasion-hollow".to_string(),
        sequence: NfaSequence::new(
            "evasion-hollow".to_string(),
            140,
            vec![
                SeqStep::new(0, "createprocess-suspended".to_string(), 1047),
                SeqStep::new(1, "ntunmapview".to_string(), 1048),
                SeqStep::new(2, "virtualallocex-rwx".to_string(), 1049),
                SeqStep::new(3, "writeprocessmemory".to_string(), 1050),
            ],
            Some(10000),
            None,
        ),
        rule_id: "evasion-hollow-detect".to_string(),
        rule_name: "Evasion Process Hollowing".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA040u128;
    let base = 40_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1047, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1048, entity, base + 100_000_000).clone()))
            .unwrap()
            .is_empty()
    );
    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1049, entity, base + 200_000_000).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1050, entity, base + 300_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_evasion_process_doppelganging() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "evasion-doppel".to_string(),
        sequence: NfaSequence::new(
            "evasion-doppel".to_string(),
            141,
            vec![
                SeqStep::new(0, "ntcreatetransaction".to_string(), 1051),
                SeqStep::new(1, "createfiletransacted".to_string(), 1052),
                SeqStep::new(2, "rollbacktransaction".to_string(), 1053),
            ],
            Some(30000),
            None,
        ),
        rule_id: "evasion-doppel-detect".to_string(),
        rule_name: "Evasion Doppelganging".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA041u128;
    let base = 41_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1051, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1052, entity, base + 100_000_000).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1053, entity, base + 200_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_evasion_amsi_bypass() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "evasion-amsi".to_string(),
        sequence: NfaSequence::new(
            "evasion-amsi".to_string(),
            142,
            vec![
                SeqStep::new(0, "virtualprotect".to_string(), 1054),
                SeqStep::new(1, "amsi-dll-access".to_string(), 1055),
                SeqStep::new(2, "amsiscanbuffer-patch".to_string(), 1056),
            ],
            Some(30000),
            None,
        ),
        rule_id: "evasion-amsi-detect".to_string(),
        rule_name: "Evasion AMSI Bypass".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA042u128;
    let base = 42_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1054, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1055, entity, base + 100_000_000).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1056, entity, base + 200_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_evasion_etw_tampering() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "evasion-etw".to_string(),
        sequence: NfaSequence::new(
            "evasion-etw".to_string(),
            143,
            vec![
                SeqStep::new(0, "nttracecontrol".to_string(), 1057),
                SeqStep::new(1, "eventunregister".to_string(), 1058),
            ],
            Some(10000),
            None,
        ),
        rule_id: "evasion-etw-detect".to_string(),
        rule_name: "Evasion ETW Tampering".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA043u128;
    let base = 43_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1057, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1058, entity, base + 100_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_evasion_sxsppl_bypass() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "evasion-sxs".to_string(),
        sequence: NfaSequence::new(
            "evasion-sxs".to_string(),
            144,
            vec![
                SeqStep::new(0, "sxs-dll-load".to_string(), 1059),
                SeqStep::new(1, "sxsprobing-bypass".to_string(), 1060),
            ],
            Some(30000),
            None,
        ),
        rule_id: "evasion-sxs-detect".to_string(),
        rule_name: "Evasion SxS Bypass".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA044u128;
    let base = 44_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1059, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1060, entity, base + 100_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

// =============================================================================
// 数据窃取和渗出检测
// =============================================================================

#[test]
fn test_exfil_compression_archive() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "exfil-archive".to_string(),
        sequence: NfaSequence::new(
            "exfil-archive".to_string(),
            150,
            vec![
                SeqStep::new(0, "7z-start".to_string(), 1061),
                SeqStep::new(1, "archive-create".to_string(), 1062),
            ],
            Some(60000),
            None,
        ),
        rule_id: "exfil-archive-detect".to_string(),
        rule_name: "Exfiltration Archive".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA050u128;
    let base = 50_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1061, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1062, entity, base + 100_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_exfil_cloud_storage_upload() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "exfil-cloud".to_string(),
        sequence: NfaSequence::new(
            "exfil-cloud".to_string(),
            151,
            vec![
                SeqStep::new(0, "rclone-start".to_string(), 1063),
                SeqStep::new(1, "cloud-upload".to_string(), 1064),
            ],
            Some(120000),
            None,
        ),
        rule_id: "exfil-cloud-detect".to_string(),
        rule_name: "Exfiltration Cloud Storage".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA051u128;
    let base = 51_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1063, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1064, entity, base + 100_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_exfil_dns_tunneling() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "exfil-dns".to_string(),
        sequence: NfaSequence::new(
            "exfil-dns".to_string(),
            152,
            vec![
                SeqStep::new(0, "nslookup-start".to_string(), 1065),
                SeqStep::new(1, "dns-query-long".to_string(), 1066),
            ],
            Some(60000),
            None,
        ),
        rule_id: "exfil-dns-detect".to_string(),
        rule_name: "Exfiltration DNS Tunnel".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA052u128;
    let base = 52_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1065, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1066, entity, base + 50_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_exfil_https_c2_beacon() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "exfil-beacon".to_string(),
        sequence: NfaSequence::new(
            "exfil-beacon".to_string(),
            153,
            vec![
                SeqStep::new(0, "svchost-suspect".to_string(), 1067),
                SeqStep::new(1, "https-post".to_string(), 1068),
            ],
            Some(300000),
            None,
        ),
        rule_id: "exfil-beacon-detect".to_string(),
        rule_name: "Exfiltration C2 Beacon".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA053u128;
    let base = 53_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1067, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1068, entity, base + 300_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_exfil_smtp_data_transfer() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "exfil-smtp".to_string(),
        sequence: NfaSequence::new(
            "exfil-smtp".to_string(),
            154,
            vec![
                SeqStep::new(0, "powershell-email".to_string(), 1069),
                SeqStep::new(1, "send-mailmessage".to_string(), 1070),
            ],
            Some(60000),
            None,
        ),
        rule_id: "exfil-smtp-detect".to_string(),
        rule_name: "Exfiltration SMTP".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA054u128;
    let base = 54_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1069, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1070, entity, base + 100_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

// =============================================================================
// 异常行为检测
// =============================================================================

#[test]
fn test_anomaly_unusual_process_parent() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "anomaly-parent".to_string(),
        sequence: NfaSequence::new(
            "anomaly-parent".to_string(),
            160,
            vec![
                SeqStep::new(0, "office-parent".to_string(), 1071),
                SeqStep::new(1, "suspicious-child".to_string(), 1072),
            ],
            Some(600000),
            None,
        ),
        rule_id: "anomaly-parent-detect".to_string(),
        rule_name: "Anomaly Process Parent".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA060u128;
    let base = 60_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1071, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1072, entity, base + 500_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_anomaly_unusual_network_connection() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "anomaly-network".to_string(),
        sequence: NfaSequence::new(
            "anomaly-network".to_string(),
            161,
            vec![
                SeqStep::new(0, "notepad-network".to_string(), 1073),
                SeqStep::new(1, "external-connect".to_string(), 1074),
            ],
            Some(60000),
            None,
        ),
        rule_id: "anomaly-network-detect".to_string(),
        rule_name: "Anomaly Network Connection".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA061u128;
    let base = 61_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1073, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1074, entity, base + 100_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_anomaly_mass_file_deletion() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "anomaly-mass-delete".to_string(),
        sequence: NfaSequence::new(
            "anomaly-mass-delete".to_string(),
            163,
            vec![
                SeqStep::new(0, "delete-start".to_string(), 1077),
                SeqStep::new(1, "rapid-deletion".to_string(), 1078),
                SeqStep::new(2, "high-frequency-delete".to_string(), 1079),
            ],
            Some(30000),
            None,
        ),
        rule_id: "anomaly-mass-delete-detect".to_string(),
        rule_name: "Anomaly Mass File Deletion".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA063u128;
    let base = 63_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1077, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1078, entity, base + 500_000).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1079, entity, base + 1_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_anomaly_privilege_escalation_attempt() {
    let mut nfa = create_hunting_engine();

    let seq = CompiledSequence {
        id: "anomaly-privesc".to_string(),
        sequence: NfaSequence::new(
            "anomaly-privesc".to_string(),
            164,
            vec![
                SeqStep::new(0, "whoami-priv".to_string(), 1080),
                SeqStep::new(1, "net-localgroup".to_string(), 1081),
                SeqStep::new(2, "runas-admin".to_string(), 1082),
            ],
            Some(60000),
            None,
        ),
        rule_id: "anomaly-privesc-detect".to_string(),
        rule_name: "Anomaly Privilege Escalation".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xA064u128;
    let base = 64_000_000_000u64;

    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1080, entity, base).clone()))
            .unwrap()
            .is_empty()
    );
    assert!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1081, entity, base + 100_000_000).clone()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(create_hunting_event(1082, entity, base + 200_000_000).clone()))
            .unwrap()
            .len(),
        1
    );
}
