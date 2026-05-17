//! File Integrity Monitoring Tests
//!
//! 文件完整性监控场景测试 - 检测关键系统文件变更

use kestrel_event::Event;
use kestrel_nfa::{
    CompiledSequence, NfaEngine, NfaEngineConfig, NfaSequence, PredicateEvaluator, SeqStep,
};
use std::sync::Arc;

struct TestPredicateEvaluator;

#[async_trait::async_trait]
impl PredicateEvaluator for TestPredicateEvaluator {
    async fn evaluate(&self, _id: &str, _e: &Event) -> kestrel_event::PredicateResult<bool> {
        Ok(true)
    }
    fn get_required_fields(&self, _id: &str) -> kestrel_event::PredicateResult<Vec<u32>> {
        Ok(vec![])
    }
    fn has_predicate(&self, _id: &str) -> bool {
        true
    }
}

fn create_fim_engine() -> NfaEngine {
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestPredicateEvaluator);
    NfaEngine::new(NfaEngineConfig::default(), evaluator)
}

fn create_fim_event(event_type: u16, entity: u128, timestamp_ns: u64) -> Event {
    Event::builder()
        .event_type(event_type)
        .ts_mono(timestamp_ns)
        .ts_wall(timestamp_ns)
        .entity_key(entity)
        .build()
        .unwrap()
}

// =============================================================================
// 系统文件完整性检测
// =============================================================================

#[test]
fn test_fim_etc_passwd_modification() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-passwd".to_string(),
        sequence: NfaSequence::new(
            "fim-passwd".to_string(),
            400,
            vec![SeqStep::new(0, "passwd-modify".to_string(), 40001)],
            Some(30000),
            None,
        ),
        rule_id: "fim-passwd-detect".to_string(),
        rule_name: "FIM /etc/passwd Modify".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40001, 0xE001u128, 1_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_fim_etc_shadow_modification() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-shadow".to_string(),
        sequence: NfaSequence::new(
            "fim-shadow".to_string(),
            401,
            vec![SeqStep::new(0, "shadow-modify".to_string(), 40002)],
            Some(30000),
            None,
        ),
        rule_id: "fim-shadow-detect".to_string(),
        rule_name: "FIM /etc/shadow Modify".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40002, 0xE002u128, 2_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_fim_sudoers_modification() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-sudoers".to_string(),
        sequence: NfaSequence::new(
            "fim-sudoers".to_string(),
            402,
            vec![SeqStep::new(0, "sudoers-modify".to_string(), 40003)],
            Some(30000),
            None,
        ),
        rule_id: "fim-sudoers-detect".to_string(),
        rule_name: "FIM Sudoers Modify".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40003, 0xE003u128, 3_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_fim_ssh_config_modification() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-ssh".to_string(),
        sequence: NfaSequence::new(
            "fim-ssh".to_string(),
            403,
            vec![SeqStep::new(0, "ssh-config-modify".to_string(), 40004)],
            Some(30000),
            None,
        ),
        rule_id: "fim-ssh-detect".to_string(),
        rule_name: "FIM SSH Config Modify".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40004, 0xE004u128, 4_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_fim_crontab_modification() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-crontab".to_string(),
        sequence: NfaSequence::new(
            "fim-crontab".to_string(),
            404,
            vec![SeqStep::new(0, "crontab-modify".to_string(), 40005)],
            Some(30000),
            None,
        ),
        rule_id: "fim-crontab-detect".to_string(),
        rule_name: "FIM Crontab Modify".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40005, 0xE005u128, 5_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_fim_systemd_service_modification() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-systemd".to_string(),
        sequence: NfaSequence::new(
            "fim-systemd".to_string(),
            405,
            vec![SeqStep::new(0, "systemd-service-create".to_string(), 40006)],
            Some(30000),
            None,
        ),
        rule_id: "fim-systemd-detect".to_string(),
        rule_name: "FIM Systemd Service Modify".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40006, 0xE006u128, 6_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_fim_kernel_module_modification() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-kernel".to_string(),
        sequence: NfaSequence::new(
            "fim-kernel".to_string(),
            406,
            vec![SeqStep::new(0, "kernel-module-modify".to_string(), 40007)],
            Some(30000),
            None,
        ),
        rule_id: "fim-kernel-detect".to_string(),
        rule_name: "FIM Kernel Module Modify".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40007, 0xE007u128, 7_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_fim_ld_preload_modification() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-ldpreload".to_string(),
        sequence: NfaSequence::new(
            "fim-ldpreload".to_string(),
            407,
            vec![SeqStep::new(0, "ld-preload-create".to_string(), 40008)],
            Some(30000),
            None,
        ),
        rule_id: "fim-ldpreload-detect".to_string(),
        rule_name: "FIM LD_PRELOAD Create".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40008, 0xE008u128, 8_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

// =============================================================================
// 应用程序完整性检测
// =============================================================================

#[test]
fn test_fim_web_root_modification() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-webroot".to_string(),
        sequence: NfaSequence::new(
            "fim-webroot".to_string(),
            410,
            vec![SeqStep::new(0, "webroot-modify".to_string(), 40009)],
            Some(30000),
            None,
        ),
        rule_id: "fim-webroot-detect".to_string(),
        rule_name: "FIM Web Root Modify".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40009, 0xE010u128, 10_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_fim_application_binary_modification() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-binary".to_string(),
        sequence: NfaSequence::new(
            "fim-binary".to_string(),
            411,
            vec![SeqStep::new(0, "binary-modify".to_string(), 40010)],
            Some(30000),
            None,
        ),
        rule_id: "fim-binary-detect".to_string(),
        rule_name: "FIM Binary Modify".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40010, 0xE011u128, 11_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_fim_library_injection() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-lib-inject".to_string(),
        sequence: NfaSequence::new(
            "fim-lib-inject".to_string(),
            412,
            vec![SeqStep::new(0, "suspicious-lib-create".to_string(), 40011)],
            Some(30000),
            None,
        ),
        rule_id: "fim-lib-detect".to_string(),
        rule_name: "FIM Library Injection".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40011, 0xE012u128, 12_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_fim_configuration_file_change() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-config".to_string(),
        sequence: NfaSequence::new(
            "fim-config".to_string(),
            413,
            vec![SeqStep::new(0, "config-file-modify".to_string(), 40012)],
            Some(30000),
            None,
        ),
        rule_id: "fim-config-detect".to_string(),
        rule_name: "FIM Config File Modify".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40012, 0xE013u128, 13_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_fim_database_file_access() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-database".to_string(),
        sequence: NfaSequence::new(
            "fim-database".to_string(),
            414,
            vec![SeqStep::new(0, "database-file-read".to_string(), 40013)],
            Some(30000),
            None,
        ),
        rule_id: "fim-database-detect".to_string(),
        rule_name: "FIM Database File Access".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40013, 0xE014u128, 14_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

// =============================================================================
// 日志文件完整性检测
// =============================================================================

#[test]
fn test_fim_auth_log_deletion() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-authlog".to_string(),
        sequence: NfaSequence::new(
            "fim-authlog".to_string(),
            420,
            vec![SeqStep::new(0, "auth-log-delete".to_string(), 40014)],
            Some(30000),
            None,
        ),
        rule_id: "fim-authlog-detect".to_string(),
        rule_name: "FIM Auth Log Delete".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40014, 0xE020u128, 20_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_fim_syslog_modification() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-syslog".to_string(),
        sequence: NfaSequence::new(
            "fim-syslog".to_string(),
            421,
            vec![SeqStep::new(0, "syslog-modify".to_string(), 40015)],
            Some(30000),
            None,
        ),
        rule_id: "fim-syslog-detect".to_string(),
        rule_name: "FIM Syslog Modify".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40015, 0xE021u128, 21_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_fim_audit_log_tampering() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-audit".to_string(),
        sequence: NfaSequence::new(
            "fim-audit".to_string(),
            422,
            vec![SeqStep::new(0, "audit-log-truncate".to_string(), 40016)],
            Some(30000),
            None,
        ),
        rule_id: "fim-audit-detect".to_string(),
        rule_name: "FIM Audit Log Truncate".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40016, 0xE022u128, 22_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_fim_wtmp_utmp_modification() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-wtmp".to_string(),
        sequence: NfaSequence::new(
            "fim-wtmp".to_string(),
            423,
            vec![SeqStep::new(0, "wtmp-modify".to_string(), 40017)],
            Some(30000),
            None,
        ),
        rule_id: "fim-wtmp-detect".to_string(),
        rule_name: "FIM Wtmp Modify".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40017, 0xE023u128, 23_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

// =============================================================================
// 启动和初始化文件检测
// =============================================================================

#[test]
fn test_fim_initd_script_modification() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-initd".to_string(),
        sequence: NfaSequence::new(
            "fim-initd".to_string(),
            430,
            vec![SeqStep::new(0, "initd-script-create".to_string(), 40018)],
            Some(30000),
            None,
        ),
        rule_id: "fim-initd-detect".to_string(),
        rule_name: "FIM Init.d Script Create".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40018, 0xE030u128, 30_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_fim_rc_local_modification() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-rc-local".to_string(),
        sequence: NfaSequence::new(
            "fim-rc-local".to_string(),
            431,
            vec![SeqStep::new(0, "rc-local-modify".to_string(), 40019)],
            Some(30000),
            None,
        ),
        rule_id: "fim-rc-local-detect".to_string(),
        rule_name: "FIM rc.local Modify".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40019, 0xE031u128, 31_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_fim_profile_modification() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-profile".to_string(),
        sequence: NfaSequence::new(
            "fim-profile".to_string(),
            432,
            vec![SeqStep::new(0, "profile-modify".to_string(), 40020)],
            Some(30000),
            None,
        ),
        rule_id: "fim-profile-detect".to_string(),
        rule_name: "FIM Profile Modify".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40020, 0xE032u128, 32_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_fim_bashrc_modification() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-bashrc".to_string(),
        sequence: NfaSequence::new(
            "fim-bashrc".to_string(),
            433,
            vec![SeqStep::new(0, "bashrc-modify".to_string(), 40021)],
            Some(30000),
            None,
        ),
        rule_id: "fim-bashrc-detect".to_string(),
        rule_name: "FIM .bashrc Modify".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40021, 0xE033u128, 33_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

// =============================================================================
// 批量文件变更检测
// =============================================================================

#[test]
fn test_fim_mass_file_deletion() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-mass-delete".to_string(),
        sequence: NfaSequence::new(
            "fim-mass-delete".to_string(),
            440,
            vec![
                SeqStep::new(0, "file-delete-start".to_string(), 40022),
                SeqStep::new(1, "rapid-file-delete".to_string(), 40023),
            ],
            Some(30000),
            None,
        ),
        rule_id: "fim-mass-delete-detect".to_string(),
        rule_name: "FIM Mass File Delete".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40022, 0xE040u128, 40_000_000_000u64).clone()
        ))
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40023, 0xE040u128, 40_010_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_fim_mass_file_encryption() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-mass-encrypt".to_string(),
        sequence: NfaSequence::new(
            "fim-mass-encrypt".to_string(),
            441,
            vec![
                SeqStep::new(0, "encrypted-file-create".to_string(), 40024),
                SeqStep::new(1, "rapid-encrypt-pattern".to_string(), 40025),
            ],
            Some(30000),
            None,
        ),
        rule_id: "fim-mass-encrypt-detect".to_string(),
        rule_name: "FIM Mass File Encrypt".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40024, 0xE041u128, 41_000_000_000u64).clone()
        ))
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40025, 0xE041u128, 41_005_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_fim_extension_change_pattern() {
    let mut nfa = create_fim_engine();
    let seq = CompiledSequence {
        id: "fim-ext-change".to_string(),
        sequence: NfaSequence::new(
            "fim-ext-change".to_string(),
            442,
            vec![
                SeqStep::new(0, "file-rename-start".to_string(), 40026),
                SeqStep::new(1, "extension-change".to_string(), 40027),
            ],
            Some(30000),
            None,
        ),
        rule_id: "fim-ext-change-detect".to_string(),
        rule_name: "FIM Extension Change".to_string(),
    };
    nfa.load_sequence(seq).unwrap();
    assert!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40026, 0xE042u128, 42_000_000_000u64).clone()
        ))
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_fim_event(40027, 0xE042u128, 42_010_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}
