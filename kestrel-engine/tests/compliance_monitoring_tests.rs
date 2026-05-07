//! Compliance Monitoring Tests
//!
//! 合规性监控场景测试 - 检测法规遵从性和安全策略违规

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

fn create_compliance_engine() -> NfaEngine {
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestPredicateEvaluator);
    NfaEngine::new(NfaEngineConfig::default(), evaluator)
}

fn create_compliance_event(
    event_type: u16,
    entity: u128,
    timestamp_ns: u64,
    category: &str,
    action: &str,
    user: &str,
) -> Event {
    Event::builder()
        .event_type(event_type)
        .ts_mono(timestamp_ns)
        .ts_wall(timestamp_ns)
        .entity_key(entity)
        .field(1, kestrel_schema::TypedValue::String(category.to_string().into()))
        .field(2, kestrel_schema::TypedValue::String(action.to_string().into()))
        .field(3, kestrel_schema::TypedValue::String(user.to_string().into()))
        .build()
        .unwrap()
}

// =============================================================================
// PCI DSS 合规检测
// =============================================================================

#[test]
fn test_pci_dss_unencrypted_card_data() {
    // 检测未加密的卡数据
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "pci-unencrypted-card".to_string(),
        sequence: NfaSequence::new(
            "pci-unencrypted-card".to_string(),
            200,
            vec![
                SeqStep::new(0, "card-data-access".to_string(), 20001),
                SeqStep::new(1, "unencrypted-storage".to_string(), 20002),
            ],
            Some(60000),
            None,
        ),
        rule_id: "pci-unencrypted-detect".to_string(),
        rule_name: "PCI DSS Unencrypted Card Data".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC001u128;
    let base_time = 1_000_000_000u64;

    let e1 = create_compliance_event(
        20001,
        entity,
        base_time,
        "PCI",
        "FileAccess",
        "4111111111111111.txt",
    );
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20002,
        entity,
        base_time + 10_000_000,
        "PCI",
        "Unencrypted",
        "card_data",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_pci_dss_database_encryption_check() {
    // 检测数据库加密状态
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "pci-db-encryption".to_string(),
        sequence: NfaSequence::new(
            "pci-db-encryption".to_string(),
            201,
            vec![
                SeqStep::new(0, "db-config-check".to_string(), 20003),
                SeqStep::new(1, "tde-disabled".to_string(), 20004),
            ],
            Some(30000),
            None,
        ),
        rule_id: "pci-db-encryption-detect".to_string(),
        rule_name: "PCI DSS Database Encryption".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC002u128;
    let base_time = 2_000_000_000u64;

    let e1 = create_compliance_event(20003, entity, base_time, "PCI", "DatabaseConfig", "check");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20004,
        entity,
        base_time + 5_000_000,
        "PCI",
        "TDE_Disabled",
        "violation",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_pci_dss_audit_log_retention() {
    // 检测审计日志保留
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "pci-log-retention".to_string(),
        sequence: NfaSequence::new(
            "pci-log-retention".to_string(),
            202,
            vec![
                SeqStep::new(0, "log-retention-check".to_string(), 20005),
                SeqStep::new(1, "retention-violation".to_string(), 20006),
            ],
            Some(30000),
            None,
        ),
        rule_id: "pci-log-retention-detect".to_string(),
        rule_name: "PCI DSS Log Retention".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC003u128;
    let base_time = 3_000_000_000u64;

    let e1 = create_compliance_event(20005, entity, base_time, "PCI", "LogRetention", "check");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20006,
        entity,
        base_time + 5_000_000,
        "PCI",
        "7_days",
        "insufficient",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_pci_dss_network_segmentation() {
    // 检测网络分段违规
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "pci-network-seg".to_string(),
        sequence: NfaSequence::new(
            "pci-network-seg".to_string(),
            203,
            vec![
                SeqStep::new(0, "network-access-attempt".to_string(), 20007),
                SeqStep::new(1, "cross-segment-access".to_string(), 20008),
            ],
            Some(30000),
            None,
        ),
        rule_id: "pci-network-seg-detect".to_string(),
        rule_name: "PCI DSS Network Segmentation".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC004u128;
    let base_time = 4_000_000_000u64;

    let e1 = create_compliance_event(20007, entity, base_time, "PCI", "NetworkAccess", "attempt");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20008,
        entity,
        base_time + 5_000_000,
        "PCI",
        "cross_segment",
        "violation",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_pci_dss_admin_access_monitoring() {
    // 检测管理员访问监控
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "pci-admin-access".to_string(),
        sequence: NfaSequence::new(
            "pci-admin-access".to_string(),
            204,
            vec![
                SeqStep::new(0, "admin-login-attempt".to_string(), 20009),
                SeqStep::new(1, "privileged-access".to_string(), 20010),
            ],
            Some(60000),
            None,
        ),
        rule_id: "pci-admin-access-detect".to_string(),
        rule_name: "PCI DSS Admin Access".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC005u128;
    let base_time = 5_000_000_000u64;

    let e1 = create_compliance_event(20009, entity, base_time, "PCI", "AdminLogin", "root");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20010,
        entity,
        base_time + 10_000_000,
        "PCI",
        "Privileged",
        "access_granted",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

// =============================================================================
// GDPR 合规检测
// =============================================================================

#[test]
fn test_gdpr_pii_exposure() {
    // 检测PII数据暴露
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "gdpr-pii-exposure".to_string(),
        sequence: NfaSequence::new(
            "gdpr-pii-exposure".to_string(),
            210,
            vec![
                SeqStep::new(0, "pii-access".to_string(), 20011),
                SeqStep::new(1, "unauthorized-export".to_string(), 20012),
            ],
            Some(60000),
            None,
        ),
        rule_id: "gdpr-pii-detect".to_string(),
        rule_name: "GDPR PII Exposure".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC010u128;
    let base_time = 10_000_000_000u64;

    let e1 = create_compliance_event(20011, entity, base_time, "GDPR", "DataAccess", "pii");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20012,
        entity,
        base_time + 10_000_000,
        "GDPR",
        "DataExport",
        "email_list.csv",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_gdpr_data_subject_access_request() {
    // 检测数据主体访问请求
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "gdpr-dsar".to_string(),
        sequence: NfaSequence::new(
            "gdpr-dsar".to_string(),
            211,
            vec![
                SeqStep::new(0, "dsar-received".to_string(), 20013),
                SeqStep::new(1, "dsar-overdue".to_string(), 20014),
            ],
            Some(2592000000u64), // 30 days in ms
            None,
        ),
        rule_id: "gdpr-dsar-detect".to_string(),
        rule_name: "GDPR DSAR Overdue".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC011u128;
    let base_time = 11_000_000_000u64;

    let e1 = create_compliance_event(20013, entity, base_time, "GDPR", "DSAR", "received");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20014,
        entity,
        base_time + 2_592_000_000_000u64,
        "GDPR",
        "DSAR",
        "overdue_30_days",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_gdpr_cross_border_transfer() {
    // 检测跨境数据传输
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "gdpr-cross-border".to_string(),
        sequence: NfaSequence::new(
            "gdpr-cross-border".to_string(),
            212,
            vec![
                SeqStep::new(0, "data-transfer-init".to_string(), 20015),
                SeqStep::new(1, "non-adequate-destination".to_string(), 20016),
            ],
            Some(60000),
            None,
        ),
        rule_id: "gdpr-cross-border-detect".to_string(),
        rule_name: "GDPR Cross Border Transfer".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC012u128;
    let base_time = 12_000_000_000u64;

    let e1 = create_compliance_event(20015, entity, base_time, "GDPR", "DataTransfer", "initiated");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20016,
        entity,
        base_time + 10_000_000,
        "GDPR",
        "DataTransfer",
        "non_adequate_country",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_gdpr_consent_management() {
    // 检测同意管理违规
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "gdpr-consent".to_string(),
        sequence: NfaSequence::new(
            "gdpr-consent".to_string(),
            213,
            vec![
                SeqStep::new(0, "consent-withdrawn".to_string(), 20017),
                SeqStep::new(1, "data-processed-anyway".to_string(), 20018),
            ],
            Some(86400000u64), // 24 hours in ms
            None,
        ),
        rule_id: "gdpr-consent-detect".to_string(),
        rule_name: "GDPR Consent Violation".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC013u128;
    let base_time = 13_000_000_000u64;

    let e1 = create_compliance_event(20017, entity, base_time, "GDPR", "Consent", "withdrawn");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20018,
        entity,
        base_time + 100_000_000,
        "GDPR",
        "Consent",
        "withdrawn_but_processed",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_gdpr_data_retention_expiry() {
    // 检测数据保留期限
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "gdpr-retention".to_string(),
        sequence: NfaSequence::new(
            "gdpr-retention".to_string(),
            214,
            vec![
                SeqStep::new(0, "retention-check".to_string(), 20019),
                SeqStep::new(1, "retention-exceeded".to_string(), 20020),
            ],
            Some(30000),
            None,
        ),
        rule_id: "gdpr-retention-detect".to_string(),
        rule_name: "GDPR Data Retention".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC014u128;
    let base_time = 14_000_000_000u64;

    let e1 = create_compliance_event(20019, entity, base_time, "GDPR", "DataRetention", "check");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20020,
        entity,
        base_time + 5_000_000,
        "GDPR",
        "DataRetention",
        "exceeded_7_years",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

// =============================================================================
// HIPAA 合规检测
// =============================================================================

#[test]
fn test_hipaa_phi_access_log() {
    // 检测PHI访问日志
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "hipaa-phi-access".to_string(),
        sequence: NfaSequence::new(
            "hipaa-phi-access".to_string(),
            220,
            vec![
                SeqStep::new(0, "phi-access-attempt".to_string(), 20021),
                SeqStep::new(1, "unauthorized-phi-access".to_string(), 20022),
            ],
            Some(30000),
            None,
        ),
        rule_id: "hipaa-phi-detect".to_string(),
        rule_name: "HIPAA PHI Access".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC020u128;
    let base_time = 20_000_000_000u64;

    let e1 = create_compliance_event(20021, entity, base_time, "HIPAA", "PHIAccess", "attempt");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20022,
        entity,
        base_time + 5_000_000,
        "HIPAA",
        "PHIAccess",
        "unauthorized_user",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_hipaa_minimum_necessary_violation() {
    // 检测最小必要原则违规
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "hipaa-min-necessary".to_string(),
        sequence: NfaSequence::new(
            "hipaa-min-necessary".to_string(),
            221,
            vec![
                SeqStep::new(0, "bulk-access-request".to_string(), 20023),
                SeqStep::new(1, "all-patients-access".to_string(), 20024),
            ],
            Some(60000),
            None,
        ),
        rule_id: "hipaa-min-necessary-detect".to_string(),
        rule_name: "HIPAA Minimum Necessary".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC021u128;
    let base_time = 21_000_000_000u64;

    let e1 = create_compliance_event(20023, entity, base_time, "HIPAA", "BulkAccess", "request");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20024,
        entity,
        base_time + 10_000_000,
        "HIPAA",
        "BulkAccess",
        "all_patients",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_hipaa_emergency_access_break_glass() {
    // 检测紧急访问 (Break Glass)
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "hipaa-breakglass".to_string(),
        sequence: NfaSequence::new(
            "hipaa-breakglass".to_string(),
            222,
            vec![
                SeqStep::new(0, "emergency-access-attempt".to_string(), 20025),
                SeqStep::new(1, "unauthorized-breakglass".to_string(), 20026),
            ],
            Some(30000),
            None,
        ),
        rule_id: "hipaa-breakglass-detect".to_string(),
        rule_name: "HIPAA Break Glass".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC022u128;
    let base_time = 22_000_000_000u64;

    let e1 = create_compliance_event(20025, entity, base_time, "HIPAA", "BreakGlass", "attempt");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20026,
        entity,
        base_time + 5_000_000,
        "HIPAA",
        "BreakGlass",
        "unauthorized",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_hipaa_workstation_security() {
    // 检测工作站安全
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "hipaa-workstation".to_string(),
        sequence: NfaSequence::new(
            "hipaa-workstation".to_string(),
            223,
            vec![
                SeqStep::new(0, "workstation-unattended".to_string(), 20027),
                SeqStep::new(1, "session-unlocked".to_string(), 20028),
            ],
            Some(300000u64), // 5 minutes
            None,
        ),
        rule_id: "hipaa-workstation-detect".to_string(),
        rule_name: "HIPAA Workstation Security".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC023u128;
    let base_time = 23_000_000_000u64;

    let e1 =
        create_compliance_event(20027, entity, base_time, "HIPAA", "Workstation", "unattended");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20028,
        entity,
        base_time + 60_000_000,
        "HIPAA",
        "Workstation",
        "unattended_unlocked",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

// =============================================================================
// SOX 合规检测
// =============================================================================

#[test]
fn test_sox_financial_data_modification() {
    // 检测财务数据修改
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "sox-financial-mod".to_string(),
        sequence: NfaSequence::new(
            "sox-financial-mod".to_string(),
            230,
            vec![
                SeqStep::new(0, "financial-record-access".to_string(), 20029),
                SeqStep::new(1, "post-close-modification".to_string(), 20030),
            ],
            Some(60000),
            None,
        ),
        rule_id: "sox-financial-mod-detect".to_string(),
        rule_name: "SOX Financial Data Modification".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC030u128;
    let base_time = 30_000_000_000u64;

    let e1 = create_compliance_event(20029, entity, base_time, "SOX", "FinancialRecord", "access");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20030,
        entity,
        base_time + 10_000_000,
        "SOX",
        "FinancialRecord",
        "modified_post_close",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_sox_segregation_of_duties() {
    // 检测职责分离违规
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "sox-sod".to_string(),
        sequence: NfaSequence::new(
            "sox-sod".to_string(),
            231,
            vec![
                SeqStep::new(0, "conflicting-role-assigned".to_string(), 20031),
                SeqStep::new(1, "sod-violation-executed".to_string(), 20032),
            ],
            Some(300000u64), // 5 minutes
            None,
        ),
        rule_id: "sox-sod-detect".to_string(),
        rule_name: "SOX Segregation of Duties".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC031u128;
    let base_time = 31_000_000_000u64;

    let e1 =
        create_compliance_event(20031, entity, base_time, "SOX", "ConflictingRole", "assigned");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20032,
        entity,
        base_time + 60_000_000,
        "SOX",
        "ConflictingRole",
        "approve_and_record",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_sox_change_management() {
    // 检测变更管理
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "sox-change-mgmt".to_string(),
        sequence: NfaSequence::new(
            "sox-change-mgmt".to_string(),
            232,
            vec![
                SeqStep::new(0, "unauthorized-change-attempt".to_string(), 20033),
                SeqStep::new(1, "production-modification".to_string(), 20034),
            ],
            Some(60000),
            None,
        ),
        rule_id: "sox-change-mgmt-detect".to_string(),
        rule_name: "SOX Change Management".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC032u128;
    let base_time = 32_000_000_000u64;

    let e1 =
        create_compliance_event(20033, entity, base_time, "SOX", "UnauthorizedChange", "attempt");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20034,
        entity,
        base_time + 10_000_000,
        "SOX",
        "UnauthorizedChange",
        "production_system",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

// =============================================================================
// NIST 框架合规检测
// =============================================================================

#[test]
fn test_nist_identify_asset_management() {
    // 检测资产管理
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "nist-asset-mgmt".to_string(),
        sequence: NfaSequence::new(
            "nist-asset-mgmt".to_string(),
            240,
            vec![
                SeqStep::new(0, "unknown-device-detected".to_string(), 20035),
                SeqStep::new(1, "unauthorized-device-connected".to_string(), 20036),
            ],
            Some(60000),
            None,
        ),
        rule_id: "nist-asset-mgmt-detect".to_string(),
        rule_name: "NIST Asset Management".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC040u128;
    let base_time = 40_000_000_000u64;

    let e1 = create_compliance_event(20035, entity, base_time, "NIST", "UnknownAsset", "detected");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20036,
        entity,
        base_time + 10_000_000,
        "NIST",
        "UnknownAsset",
        "unauthorized_device",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_nist_protect_access_control() {
    // 检测访问控制
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "nist-access-ctrl".to_string(),
        sequence: NfaSequence::new(
            "nist-access-ctrl".to_string(),
            241,
            vec![
                SeqStep::new(0, "default-credential-usage".to_string(), 20037),
                SeqStep::new(1, "admin-access-granted".to_string(), 20038),
            ],
            Some(30000),
            None,
        ),
        rule_id: "nist-access-ctrl-detect".to_string(),
        rule_name: "NIST Access Control".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC041u128;
    let base_time = 41_000_000_000u64;

    let e1 =
        create_compliance_event(20037, entity, base_time, "NIST", "DefaultCredentials", "attempt");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20038,
        entity,
        base_time + 5_000_000,
        "NIST",
        "DefaultCredentials",
        "admin/admin",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_nist_detect_anomaly_events() {
    // 检测异常事件
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "nist-anomaly".to_string(),
        sequence: NfaSequence::new(
            "nist-anomaly".to_string(),
            242,
            vec![
                SeqStep::new(0, "baseline-deviation".to_string(), 20039),
                SeqStep::new(1, "anomaly-confirmed".to_string(), 20040),
            ],
            Some(300000u64), // 5 minutes
            None,
        ),
        rule_id: "nist-anomaly-detect".to_string(),
        rule_name: "NIST Anomaly Detection".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC042u128;
    let base_time = 42_000_000_000u64;

    let e1 = create_compliance_event(20039, entity, base_time, "NIST", "Anomaly", "detected");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20040,
        entity,
        base_time + 60_000_000,
        "NIST",
        "Anomaly",
        "unusual_login_pattern",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_nist_respond_incident_handling() {
    // 检测事件响应
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "nist-incident".to_string(),
        sequence: NfaSequence::new(
            "nist-incident".to_string(),
            243,
            vec![
                SeqStep::new(0, "incident-reported".to_string(), 20041),
                SeqStep::new(1, "response-time-exceeded".to_string(), 20042),
            ],
            Some(3600000u64), // 1 hour
            None,
        ),
        rule_id: "nist-incident-detect".to_string(),
        rule_name: "NIST Incident Response".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC043u128;
    let base_time = 43_000_000_000u64;

    let e1 = create_compliance_event(20041, entity, base_time, "NIST", "Incident", "reported");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20042,
        entity,
        base_time + 3_600_000_000u64,
        "NIST",
        "Incident",
        "response_time_exceeded",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_nist_recover_backup_restoration() {
    // 检测备份恢复
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "nist-backup".to_string(),
        sequence: NfaSequence::new(
            "nist-backup".to_string(),
            244,
            vec![
                SeqStep::new(0, "backup-check".to_string(), 20043),
                SeqStep::new(1, "backup-failure".to_string(), 20044),
            ],
            Some(30000),
            None,
        ),
        rule_id: "nist-backup-detect".to_string(),
        rule_name: "NIST Backup Recovery".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC044u128;
    let base_time = 44_000_000_000u64;

    let e1 = create_compliance_event(20043, entity, base_time, "NIST", "BackupFailure", "check");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20044,
        entity,
        base_time + 10_000_000,
        "NIST",
        "BackupFailure",
        "72_hours_no_backup",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

// =============================================================================
// ISO 27001 合规检测
// =============================================================================

#[test]
fn test_iso27001_policy_violation() {
    // 检测策略违规
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "iso27001-policy".to_string(),
        sequence: NfaSequence::new(
            "iso27001-policy".to_string(),
            250,
            vec![
                SeqStep::new(0, "policy-check".to_string(), 20045),
                SeqStep::new(1, "policy-violation".to_string(), 20046),
            ],
            Some(30000),
            None,
        ),
        rule_id: "iso27001-policy-detect".to_string(),
        rule_name: "ISO27001 Policy Violation".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC050u128;
    let base_time = 50_000_000_000u64;

    let e1 =
        create_compliance_event(20045, entity, base_time, "ISO27001", "PolicyViolation", "check");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20046,
        entity,
        base_time + 5_000_000,
        "ISO27001",
        "PolicyViolation",
        "data_classification",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_iso27001_cryptographic_controls() {
    // 检测加密控制
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "iso27001-crypto".to_string(),
        sequence: NfaSequence::new(
            "iso27001-crypto".to_string(),
            251,
            vec![
                SeqStep::new(0, "crypto-check".to_string(), 20047),
                SeqStep::new(1, "weak-crypto-detected".to_string(), 20048),
            ],
            Some(30000),
            None,
        ),
        rule_id: "iso27001-crypto-detect".to_string(),
        rule_name: "ISO27001 Cryptographic Controls".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC051u128;
    let base_time = 51_000_000_000u64;

    let e1 =
        create_compliance_event(20047, entity, base_time, "ISO27001", "WeakEncryption", "check");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20048,
        entity,
        base_time + 5_000_000,
        "ISO27001",
        "WeakEncryption",
        "MD5_RSA_1024",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_iso27001_supplier_relationships() {
    // 检测供应商关系
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "iso27001-supplier".to_string(),
        sequence: NfaSequence::new(
            "iso27001-supplier".to_string(),
            252,
            vec![
                SeqStep::new(0, "supplier-risk-check".to_string(), 20049),
                SeqStep::new(1, "supplier-contract-expired".to_string(), 20050),
            ],
            Some(86400000u64), // 24 hours
            None,
        ),
        rule_id: "iso27001-supplier-detect".to_string(),
        rule_name: "ISO27001 Supplier Relationships".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC052u128;
    let base_time = 52_000_000_000u64;

    let e1 =
        create_compliance_event(20049, entity, base_time, "ISO27001", "ThirdPartyRisk", "check");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20050,
        entity,
        base_time + 100_000_000,
        "ISO27001",
        "ThirdPartyRisk",
        "expired_contract",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

// =============================================================================
// 通用安全策略检测
// =============================================================================

#[test]
fn test_policy_password_complexity() {
    // 检测密码复杂度策略
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "policy-password".to_string(),
        sequence: NfaSequence::new(
            "policy-password".to_string(),
            260,
            vec![
                SeqStep::new(0, "password-change-attempt".to_string(), 20051),
                SeqStep::new(1, "weak-password-set".to_string(), 20052),
            ],
            Some(30000),
            None,
        ),
        rule_id: "policy-password-detect".to_string(),
        rule_name: "Policy Password Complexity".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC060u128;
    let base_time = 60_000_000_000u64;

    let e1 = create_compliance_event(20051, entity, base_time, "Policy", "WeakPassword", "attempt");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20052,
        entity,
        base_time + 5_000_000,
        "Policy",
        "WeakPassword",
        "password123",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_policy_privileged_account_review() {
    // 检测特权账户审查
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "policy-priv-acct".to_string(),
        sequence: NfaSequence::new(
            "policy-priv-acct".to_string(),
            261,
            vec![
                SeqStep::new(0, "account-review-due".to_string(), 20053),
                SeqStep::new(1, "stale-account-found".to_string(), 20054),
            ],
            Some(7776000000u64), // 90 days
            None,
        ),
        rule_id: "policy-priv-acct-detect".to_string(),
        rule_name: "Policy Privileged Account Review".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC061u128;
    let base_time = 61_000_000_000u64;

    let e1 =
        create_compliance_event(20053, entity, base_time, "Policy", "StaleAccount", "review_due");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20054,
        entity,
        base_time + 7_776_000_000_000u64,
        "Policy",
        "StaleAccount",
        "90_days_unused",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_policy_data_classification() {
    // 检测数据分类策略
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "policy-data-class".to_string(),
        sequence: NfaSequence::new(
            "policy-data-class".to_string(),
            262,
            vec![
                SeqStep::new(0, "classification-check".to_string(), 20055),
                SeqStep::new(1, "misclassification-found".to_string(), 20056),
            ],
            Some(30000),
            None,
        ),
        rule_id: "policy-data-class-detect".to_string(),
        rule_name: "Policy Data Classification".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC062u128;
    let base_time = 62_000_000_000u64;

    let e1 =
        create_compliance_event(20055, entity, base_time, "Policy", "MisclassifiedData", "check");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20056,
        entity,
        base_time + 5_000_000,
        "Policy",
        "MisclassifiedData",
        "confidential_in_public",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_policy_patch_management() {
    // 检测补丁管理
    let mut nfa = create_compliance_engine();

    let seq = CompiledSequence {
        id: "policy-patch".to_string(),
        sequence: NfaSequence::new(
            "policy-patch".to_string(),
            263,
            vec![
                SeqStep::new(0, "patch-scan-initiated".to_string(), 20057),
                SeqStep::new(1, "critical-patch-missing".to_string(), 20058),
            ],
            Some(2592000000u64), // 30 days
            None,
        ),
        rule_id: "policy-patch-detect".to_string(),
        rule_name: "Policy Patch Management".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let entity = 0xC063u128;
    let base_time = 63_000_000_000u64;

    let e1 = create_compliance_event(20057, entity, base_time, "Policy", "MissingPatch", "scan");
    assert!(nfa.process_event_blocking(&e1).unwrap().is_empty());

    let e2 = create_compliance_event(
        20058,
        entity,
        base_time + 2_592_000_000_000u64,
        "Policy",
        "MissingPatch",
        "critical_30_days",
    );
    let alerts = nfa.process_event_blocking(&e2).unwrap();
    assert_eq!(alerts.len(), 1);
}
