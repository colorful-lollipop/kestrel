//! Cloud Security Tests
//!
//! 云安全检测场景测试 - 检测云环境中的安全威胁和错误配置

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

fn create_cloud_engine() -> NfaEngine {
    let evaluator: Arc<dyn PredicateEvaluator> = Arc::new(TestPredicateEvaluator);
    NfaEngine::new(NfaEngineConfig::default(), evaluator)
}

fn create_cloud_event(event_type: u16, entity: u128, timestamp_ns: u64) -> Event {
    Event::builder()
        .event_type(event_type)
        .ts_mono(timestamp_ns)
        .ts_wall(timestamp_ns)
        .entity_key(entity)
        .build()
        .unwrap()
}

// =============================================================================
// AWS 安全检测
// =============================================================================

#[test]
fn test_aws_root_account_usage() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "aws-root".to_string(),
        sequence: NfaSequence::new(
            "aws-root".to_string(),
            200,
            vec![SeqStep::new(0, "console-login".to_string(), 20001)],
            Some(60000),
            None,
        ),
        rule_id: "aws-root-detect".to_string(),
        rule_name: "AWS Root Account Usage".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    let alerts = nfa
        .process_event_blocking(Arc::new(
            create_cloud_event(20001, 0xB001u128, 1_000_000_000u64).clone(),
        ))
        .unwrap();
    assert_eq!(alerts.len(), 1);
}

#[test]
fn test_aws_iam_policy_change() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "aws-iam-policy".to_string(),
        sequence: NfaSequence::new(
            "aws-iam-policy".to_string(),
            201,
            vec![SeqStep::new(0, "put-user-policy".to_string(), 20002)],
            Some(30000),
            None,
        ),
        rule_id: "aws-iam-detect".to_string(),
        rule_name: "AWS IAM Policy Change".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20002, 0xB002u128, 2_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_aws_s3_bucket_public_access() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "aws-s3-public".to_string(),
        sequence: NfaSequence::new(
            "aws-s3-public".to_string(),
            202,
            vec![
                SeqStep::new(0, "put-bucket-acl".to_string(), 20003),
                SeqStep::new(1, "public-access".to_string(), 20004),
            ],
            Some(60000),
            None,
        ),
        rule_id: "aws-s3-detect".to_string(),
        rule_name: "AWS S3 Public Access".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20003, 0xB003u128, 3_000_000_000u64).clone()
        ))
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20004, 0xB003u128, 3_100_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_aws_security_group_egress() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "aws-sg-egress".to_string(),
        sequence: NfaSequence::new(
            "aws-sg-egress".to_string(),
            203,
            vec![SeqStep::new(0, "authorize-egress".to_string(), 20005)],
            Some(30000),
            None,
        ),
        rule_id: "aws-sg-detect".to_string(),
        rule_name: "AWS Security Group Egress".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20005, 0xB004u128, 4_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_aws_cloudtrail_disabled() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "aws-cloudtrail-stop".to_string(),
        sequence: NfaSequence::new(
            "aws-cloudtrail-stop".to_string(),
            204,
            vec![SeqStep::new(0, "stop-logging".to_string(), 20006)],
            Some(30000),
            None,
        ),
        rule_id: "aws-cloudtrail-detect".to_string(),
        rule_name: "AWS CloudTrail Stopped".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20006, 0xB005u128, 5_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_aws_kms_key_deletion() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "aws-kms-delete".to_string(),
        sequence: NfaSequence::new(
            "aws-kms-delete".to_string(),
            205,
            vec![SeqStep::new(0, "schedule-key-deletion".to_string(), 20007)],
            Some(30000),
            None,
        ),
        rule_id: "aws-kms-detect".to_string(),
        rule_name: "AWS KMS Key Deletion".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20007, 0xB006u128, 6_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_aws_ec2_user_data_modification() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "aws-ec2-userdata".to_string(),
        sequence: NfaSequence::new(
            "aws-ec2-userdata".to_string(),
            206,
            vec![SeqStep::new(
                0,
                "modify-instance-attribute".to_string(),
                20008,
            )],
            Some(30000),
            None,
        ),
        rule_id: "aws-ec2-detect".to_string(),
        rule_name: "AWS EC2 UserData Modify".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20008, 0xB007u128, 7_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_aws_guardduty_disabled() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "aws-guardduty-delete".to_string(),
        sequence: NfaSequence::new(
            "aws-guardduty-delete".to_string(),
            207,
            vec![SeqStep::new(0, "delete-detector".to_string(), 20009)],
            Some(30000),
            None,
        ),
        rule_id: "aws-guardduty-detect".to_string(),
        rule_name: "AWS GuardDuty Disabled".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20009, 0xB008u128, 8_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

// =============================================================================
// Azure 安全检测
// =============================================================================

#[test]
fn test_azure_rbac_role_assignment() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "azure-rbac".to_string(),
        sequence: NfaSequence::new(
            "azure-rbac".to_string(),
            210,
            vec![SeqStep::new(0, "create-role-assignment".to_string(), 20010)],
            Some(60000),
            None,
        ),
        rule_id: "azure-rbac-detect".to_string(),
        rule_name: "Azure RBAC Assignment".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20010, 0xB010u128, 10_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_azure_key_vault_access() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "azure-keyvault".to_string(),
        sequence: NfaSequence::new(
            "azure-keyvault".to_string(),
            211,
            vec![SeqStep::new(0, "secret-get".to_string(), 20011)],
            Some(30000),
            None,
        ),
        rule_id: "azure-keyvault-detect".to_string(),
        rule_name: "Azure KeyVault Access".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20011, 0xB011u128, 11_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_azure_storage_account_key_regeneration() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "azure-storage-key".to_string(),
        sequence: NfaSequence::new(
            "azure-storage-key".to_string(),
            212,
            vec![SeqStep::new(0, "regenerate-storage-key".to_string(), 20012)],
            Some(30000),
            None,
        ),
        rule_id: "azure-storage-detect".to_string(),
        rule_name: "Azure Storage Key Regen".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20012, 0xB012u128, 12_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_azure_network_security_group_change() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "azure-nsg-change".to_string(),
        sequence: NfaSequence::new(
            "azure-nsg-change".to_string(),
            213,
            vec![SeqStep::new(0, "security-rule-update".to_string(), 20013)],
            Some(30000),
            None,
        ),
        rule_id: "azure-nsg-detect".to_string(),
        rule_name: "Azure NSG Change".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20013, 0xB013u128, 13_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_azure_conditional_access_disabled() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "azure-ca-delete".to_string(),
        sequence: NfaSequence::new(
            "azure-ca-delete".to_string(),
            214,
            vec![SeqStep::new(0, "delete-ca-policy".to_string(), 20014)],
            Some(30000),
            None,
        ),
        rule_id: "azure-ca-detect".to_string(),
        rule_name: "Azure CA Policy Deleted".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20014, 0xB014u128, 14_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_azure_mfa_disabled() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "azure-mfa-disable".to_string(),
        sequence: NfaSequence::new(
            "azure-mfa-disable".to_string(),
            215,
            vec![SeqStep::new(0, "disable-mfa".to_string(), 20015)],
            Some(30000),
            None,
        ),
        rule_id: "azure-mfa-detect".to_string(),
        rule_name: "Azure MFA Disabled".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20015, 0xB015u128, 15_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

// =============================================================================
// GCP 安全检测
// =============================================================================

#[test]
fn test_gcp_service_account_key_creation() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "gcp-sa-key".to_string(),
        sequence: NfaSequence::new(
            "gcp-sa-key".to_string(),
            220,
            vec![SeqStep::new(0, "create-sa-key".to_string(), 20016)],
            Some(60000),
            None,
        ),
        rule_id: "gcp-sa-detect".to_string(),
        rule_name: "GCP SA Key Create".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20016, 0xB020u128, 20_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_gcp_iam_policy_binding() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "gcp-iam-binding".to_string(),
        sequence: NfaSequence::new(
            "gcp-iam-binding".to_string(),
            221,
            vec![SeqStep::new(0, "set-iam-policy".to_string(), 20017)],
            Some(30000),
            None,
        ),
        rule_id: "gcp-iam-detect".to_string(),
        rule_name: "GCP IAM Policy Binding".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20017, 0xB021u128, 21_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_gcp_storage_bucket_public() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "gcp-bucket-public".to_string(),
        sequence: NfaSequence::new(
            "gcp-bucket-public".to_string(),
            222,
            vec![SeqStep::new(0, "set-bucket-iam".to_string(), 20018)],
            Some(30000),
            None,
        ),
        rule_id: "gcp-bucket-detect".to_string(),
        rule_name: "GCP Bucket Public".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20018, 0xB022u128, 22_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_gcp_cloud_audit_logs_disabled() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "gcp-audit-delete".to_string(),
        sequence: NfaSequence::new(
            "gcp-audit-delete".to_string(),
            223,
            vec![SeqStep::new(0, "delete-sink".to_string(), 20019)],
            Some(30000),
            None,
        ),
        rule_id: "gcp-audit-detect".to_string(),
        rule_name: "GCP Audit Sink Deleted".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20019, 0xB023u128, 23_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_gcp_compute_firewall_rule_change() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "gcp-firewall-patch".to_string(),
        sequence: NfaSequence::new(
            "gcp-firewall-patch".to_string(),
            224,
            vec![SeqStep::new(0, "patch-firewall".to_string(), 20020)],
            Some(30000),
            None,
        ),
        rule_id: "gcp-firewall-detect".to_string(),
        rule_name: "GCP Firewall Patched".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20020, 0xB024u128, 24_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

// =============================================================================
// 容器安全检测
// =============================================================================

#[test]
fn test_container_privileged_mode() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "k8s-privileged".to_string(),
        sequence: NfaSequence::new(
            "k8s-privileged".to_string(),
            230,
            vec![SeqStep::new(0, "create-privileged-pod".to_string(), 20021)],
            Some(30000),
            None,
        ),
        rule_id: "k8s-priv-detect".to_string(),
        rule_name: "K8s Privileged Pod".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20021, 0xB030u128, 30_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_container_host_namespace() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "k8s-hostns".to_string(),
        sequence: NfaSequence::new(
            "k8s-hostns".to_string(),
            231,
            vec![SeqStep::new(0, "host-network-true".to_string(), 20022)],
            Some(30000),
            None,
        ),
        rule_id: "k8s-hostns-detect".to_string(),
        rule_name: "K8s Host Namespace".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20022, 0xB031u128, 31_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_container_sensitive_mount() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "k8s-sensitive-mount".to_string(),
        sequence: NfaSequence::new(
            "k8s-sensitive-mount".to_string(),
            232,
            vec![SeqStep::new(0, "hostpath-sensitive".to_string(), 20023)],
            Some(30000),
            None,
        ),
        rule_id: "k8s-mount-detect".to_string(),
        rule_name: "K8s Sensitive Mount".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20023, 0xB032u128, 32_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_container_image_pull_policy() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "k8s-image-policy".to_string(),
        sequence: NfaSequence::new(
            "k8s-image-policy".to_string(),
            233,
            vec![
                SeqStep::new(0, "pull-policy-never".to_string(), 20024),
                SeqStep::new(1, "external-image".to_string(), 20025),
            ],
            Some(60000),
            None,
        ),
        rule_id: "k8s-image-detect".to_string(),
        rule_name: "K8s Image Policy".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20024, 0xB033u128, 33_000_000_000u64).clone()
        ))
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20025, 0xB033u128, 33_100_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_container_runtime_escape() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "container-escape".to_string(),
        sequence: NfaSequence::new(
            "container-escape".to_string(),
            234,
            vec![SeqStep::new(0, "runc-exploit".to_string(), 20026)],
            Some(30000),
            None,
        ),
        rule_id: "container-escape-detect".to_string(),
        rule_name: "Container Runtime Escape".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20026, 0xB034u128, 34_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

// =============================================================================
// 无服务器安全检测
// =============================================================================

#[test]
fn test_lambda_environment_exfil() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "lambda-env-exfil".to_string(),
        sequence: NfaSequence::new(
            "lambda-env-exfil".to_string(),
            240,
            vec![SeqStep::new(0, "lambda-getenv".to_string(), 20027)],
            Some(30000),
            None,
        ),
        rule_id: "lambda-env-detect".to_string(),
        rule_name: "Lambda Env Exfil".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20027, 0xB040u128, 40_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_lambda_policy_privilege_escalation() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "lambda-privesc".to_string(),
        sequence: NfaSequence::new(
            "lambda-privesc".to_string(),
            241,
            vec![SeqStep::new(0, "lambda-add-permission".to_string(), 20028)],
            Some(30000),
            None,
        ),
        rule_id: "lambda-privesc-detect".to_string(),
        rule_name: "Lambda Privilege Escalation".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20028, 0xB041u128, 41_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_function_url_unauthorized_access() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "lambda-url-public".to_string(),
        sequence: NfaSequence::new(
            "lambda-url-public".to_string(),
            242,
            vec![SeqStep::new(0, "function-url-none".to_string(), 20029)],
            Some(30000),
            None,
        ),
        rule_id: "lambda-url-detect".to_string(),
        rule_name: "Lambda URL Public".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20029, 0xB042u128, 42_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

// =============================================================================
// 多租户和隔离违规检测
// =============================================================================

#[test]
fn test_cross_tenant_access_attempt() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "cross-tenant".to_string(),
        sequence: NfaSequence::new(
            "cross-tenant".to_string(),
            250,
            vec![SeqStep::new(0, "cross-tenant-access".to_string(), 20030)],
            Some(30000),
            None,
        ),
        rule_id: "cross-tenant-detect".to_string(),
        rule_name: "Cross Tenant Access".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20030, 0xB050u128, 50_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_resource_quota_abuse() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "quota-abuse".to_string(),
        sequence: NfaSequence::new(
            "quota-abuse".to_string(),
            251,
            vec![
                SeqStep::new(0, "instance-create-start".to_string(), 20031),
                SeqStep::new(1, "rapid-instances".to_string(), 20032),
            ],
            Some(60000),
            None,
        ),
        rule_id: "quota-abuse-detect".to_string(),
        rule_name: "Resource Quota Abuse".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20031, 0xB051u128, 51_000_000_000u64).clone()
        ))
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20032, 0xB051u128, 51_100_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

// =============================================================================
// 云数据泄露检测
// =============================================================================

#[test]
fn test_cloud_data_download_anomaly() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "data-download-anomaly".to_string(),
        sequence: NfaSequence::new(
            "data-download-anomaly".to_string(),
            260,
            vec![
                SeqStep::new(0, "large-get-object".to_string(), 20033),
                SeqStep::new(1, "increasing-download".to_string(), 20034),
            ],
            Some(300000),
            None,
        ),
        rule_id: "data-download-detect".to_string(),
        rule_name: "Data Download Anomaly".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20033, 0xB060u128, 60_000_000_000u64).clone()
        ))
        .unwrap()
        .is_empty()
    );
    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20034, 0xB060u128, 60_300_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_snapshot_export_unauthorized() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "snapshot-export".to_string(),
        sequence: NfaSequence::new(
            "snapshot-export".to_string(),
            261,
            vec![SeqStep::new(
                0,
                "modify-snapshot-attribute".to_string(),
                20035,
            )],
            Some(30000),
            None,
        ),
        rule_id: "snapshot-export-detect".to_string(),
        rule_name: "Snapshot Export Unauthorized".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20035, 0xB061u128, 61_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}

#[test]
fn test_database_public_snapshot() {
    let mut nfa = create_cloud_engine();
    let seq = CompiledSequence {
        id: "db-public-snapshot".to_string(),
        sequence: NfaSequence::new(
            "db-public-snapshot".to_string(),
            262,
            vec![SeqStep::new(
                0,
                "create-db-snapshot-public".to_string(),
                20036,
            )],
            Some(30000),
            None,
        ),
        rule_id: "db-snapshot-detect".to_string(),
        rule_name: "DB Public Snapshot".to_string(),
    };
    nfa.load_sequence(seq).unwrap();

    assert_eq!(
        nfa.process_event_blocking(Arc::new(
            create_cloud_event(20036, 0xB062u128, 62_000_000_000u64).clone()
        ))
        .unwrap()
        .len(),
        1
    );
}
