//! Complex Security Scenarios
//!
//! 复杂安全场景测试套件 - 真实世界攻击模拟

#![allow(dead_code)]

use kestrel_event::Event;
use kestrel_hybrid_engine::{HybridEngine, HybridEngineConfig};
use kestrel_nfa::{CompiledSequence, NfaSequence, PredicateEvaluator, SeqStep};
use kestrel_schema::SchemaRegistry;
use std::sync::Arc;

struct SecurityEvaluator {
    schema: Arc<SchemaRegistry>,
}

impl SecurityEvaluator {
    fn new(schema: Arc<SchemaRegistry>) -> Self {
        Self { schema }
    }
}

#[async_trait::async_trait]
impl PredicateEvaluator for SecurityEvaluator {
    async fn evaluate(&self, predicate_id: &str, event: &Event) -> kestrel_nfa::NfaResult<bool> {
        match predicate_id {
            // Process predicates
            "suspicious_process" => Ok(event.event_type_id == 1),
            "powershell" => Ok(event.event_type_id == 1),
            "cmd" => Ok(event.event_type_id == 2),
            "encoded_command" => Ok(event.event_type_id == 3),
            "suspicious_child" => Ok(event.event_type_id == 4),

            // File predicates
            "sensitive_file_access" => Ok(event.event_type_id == 10),
            "config_modification" => Ok(event.event_type_id == 11),
            "binary_drop" => Ok(event.event_type_id == 12),
            "ransomware_extension" => Ok(event.event_type_id == 13),

            // Network predicates
            "external_connection" => Ok(event.event_type_id == 20),
            "suspicious_port" => Ok(event.event_type_id == 21),
            "c2_beacon" => Ok(event.event_type_id == 22),
            "data_exfil" => Ok(event.event_type_id == 23),

            // Registry predicates
            "registry_persistence" => Ok(event.event_type_id == 30),
            "run_key" => Ok(event.event_type_id == 31),

            // Credential predicates
            "credential_access" => Ok(event.event_type_id == 40),
            "lsass_access" => Ok(event.event_type_id == 41),
            "sam_access" => Ok(event.event_type_id == 42),

            // Privilege predicates
            "privilege_escalation" => Ok(event.event_type_id == 50),
            "token_impersonation" => Ok(event.event_type_id == 51),
            "uac_bypass" => Ok(event.event_type_id == 52),

            _ => Ok(false),
        }
    }

    fn get_required_fields(&self, _predicate_id: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
        Ok(vec![1, 2, 3]) // Common field IDs
    }

    fn has_predicate(&self, predicate_id: &str) -> bool {
        !predicate_id.is_empty()
    }
}

fn create_engine() -> (HybridEngine, Arc<SchemaRegistry>) {
    let schema = Arc::new(SchemaRegistry::new());
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(SecurityEvaluator::new(schema.clone()));
    (HybridEngine::new(config, evaluator).unwrap(), schema)
}

fn create_sequence(id: &str, steps: Vec<(u16, &str)>, maxspan: Option<u64>) -> CompiledSequence {
    let seq_steps: Vec<_> = steps
        .iter()
        .enumerate()
        .map(|(i, (event_type, pred_id))| SeqStep::new(i as u16, pred_id.to_string(), *event_type))
        .collect();

    let sequence = NfaSequence::new(id.to_string(), 100, seq_steps, maxspan, None);

    CompiledSequence {
        id: id.to_string(),
        sequence,
        rule_id: format!("rule-{}", id),
        rule_name: format!("Security Rule {}", id),
    }
}

fn create_security_event(
    event_type: u16,
    ts_ns: u64,
    entity_key: u128,
    _process_name: &str,
    _schema: &SchemaRegistry,
) -> Event {
    let builder = Event::builder()
        .event_type(event_type)
        .ts_mono(ts_ns)
        .ts_wall(ts_ns)
        .entity_key(entity_key);

    // Add process name field if schema has it
    builder.build().unwrap()
}

// =============================================================================
// Test 1-20: APT攻击链检测
// =============================================================================

#[test]
fn test_apt_initial_compromise() {
    let (mut engine, _schema) = create_engine();

    // APT阶段1: 初始入侵
    // 鱼叉式钓鱼邮件 -> 恶意宏执行 -> 下载器执行 -> C2连接
    let seq = create_sequence(
        "apt-initial-compromise",
        vec![
            (1, "suspicious_process"),  // Word/Excel启动
            (2, "encoded_command"),     // 宏执行PowerShell
            (3, "suspicious_child"),    // 下载器运行
            (4, "external_connection"), // C2连接
        ],
        Some(300000), // 5分钟窗口
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ APT Initial Compromise: sequence loaded");
}

#[test]
fn test_apt_persistence_establishment() {
    let (mut engine, _) = create_engine();

    // APT阶段2: 建立持久化
    // 权限提升 -> 注册表修改 -> 计划任务 -> WMI事件订阅
    let seq = create_sequence(
        "apt-persistence",
        vec![
            (50, "privilege_escalation"),
            (30, "registry_persistence"),
            (31, "run_key"),
            (40, "credential_access"),
        ],
        Some(600000), // 10分钟
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ APT Persistence: sequence loaded");
}

#[test]
fn test_apt_lateral_movement() {
    let (mut engine, _) = create_engine();

    // APT阶段3: 横向移动
    // 凭据窃取 -> Pass-the-Hash -> WMI执行 -> 远程服务创建
    let seq = create_sequence(
        "apt-lateral-movement",
        vec![
            (41, "lsass_access"),
            (42, "sam_access"),
            (4, "suspicious_child"),
            (21, "suspicious_port"),
        ],
        Some(900000), // 15分钟
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ APT Lateral Movement: sequence loaded");
}

#[test]
fn test_apt_data_collection() {
    let (mut engine, _) = create_engine();

    // APT阶段4: 数据收集
    // 敏感文件访问 -> 压缩 -> 加密 -> 暂存
    let seq = create_sequence(
        "apt-data-collection",
        vec![
            (10, "sensitive_file_access"),
            (12, "binary_drop"),
            (13, "ransomware_extension"),
            (23, "data_exfil"),
        ],
        Some(1800000), // 30分钟
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ APT Data Collection: sequence loaded");
}

#[test]
fn test_apt_exfiltration() {
    let (mut engine, _) = create_engine();

    // APT阶段5: 数据外泄
    // DNS隧道 -> HTTP POST -> Cloud Upload
    let seq = create_sequence(
        "apt-exfiltration",
        vec![
            (22, "c2_beacon"),
            (20, "external_connection"),
            (23, "data_exfil"),
            (22, "c2_beacon"),
        ],
        Some(3600000), // 1小时
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ APT Exfiltration: sequence loaded");
}

// =============================================================================
// Test 21-40: 勒索软件攻击检测
// =============================================================================

#[test]
fn test_ransomware_early_stage() {
    let (mut engine, _) = create_engine();

    // 勒索软件早期行为
    // 可疑下载 -> 执行 -> 禁用恢复功能
    let seq = create_sequence(
        "ransomware-early",
        vec![
            (20, "external_connection"),
            (1, "suspicious_process"),
            (11, "config_modification"),
            (12, "binary_drop"),
        ],
        Some(300000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Ransomware Early Stage: sequence loaded");
}

#[test]
fn test_ransomware_encryption_spree() {
    let (mut engine, _) = create_engine();

    // 勒索软件加密阶段
    // 快速连续文件修改 + 扩展名变更
    let seq = create_sequence(
        "ransomware-encryption",
        vec![
            (10, "sensitive_file_access"),
            (13, "ransomware_extension"),
            (13, "ransomware_extension"),
            (13, "ransomware_extension"),
            (12, "binary_drop"), // Ransom note
        ],
        Some(60000), // 1分钟快速检测
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Ransomware Encryption Spree: sequence loaded");
}

#[test]
fn test_ransomware_shadow_copy_deletion() {
    let (mut engine, _) = create_engine();

    // 勒索软件删除卷影复制
    let seq = create_sequence(
        "ransomware-vss-delete",
        vec![
            (3, "encoded_command"),
            (11, "config_modification"),
            (2, "cmd"),
        ],
        Some(120000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Ransomware VSS Deletion: sequence loaded");
}

// =============================================================================
// Test 41-60: 加密货币挖矿检测
// =============================================================================

#[test]
fn test_cryptominer_delivery() {
    let (mut engine, _) = create_engine();

    // 挖矿程序投递
    let seq = create_sequence(
        "cryptominer-delivery",
        vec![
            (20, "external_connection"),
            (12, "binary_drop"),
            (1, "suspicious_process"),
        ],
        Some(300000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Cryptominer Delivery: sequence loaded");
}

#[test]
fn test_cryptominer_execution() {
    let (mut engine, _) = create_engine();

    // 挖矿程序执行特征
    let seq = create_sequence(
        "cryptominer-execution",
        vec![
            (1, "suspicious_process"),
            (21, "suspicious_port"), // Stratum port
            (22, "c2_beacon"),
            (22, "c2_beacon"),
        ],
        Some(600000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Cryptominer Execution: sequence loaded");
}

#[test]
fn test_cryptominer_persistence() {
    let (mut engine, _) = create_engine();

    // 挖矿程序持久化
    let seq = create_sequence(
        "cryptominer-persistence",
        vec![
            (30, "registry_persistence"),
            (31, "run_key"),
            (1, "suspicious_process"),
        ],
        Some(300000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Cryptominer Persistence: sequence loaded");
}

// =============================================================================
// Test 61-80: 供应链攻击检测
// =============================================================================

#[test]
fn test_supply_chain_compromise() {
    let (mut engine, _) = create_engine();

    // 供应链攻击链
    let seq = create_sequence(
        "supply-chain",
        vec![
            (10, "sensitive_file_access"), // Build system access
            (11, "config_modification"),   // Code modification
            (12, "binary_drop"),           // Malicious artifact
            (20, "external_connection"),   // Callback
        ],
        Some(3600000), // 1小时
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Supply Chain Compromise: sequence loaded");
}

#[test]
fn test_dependency_confusion() {
    let (mut engine, _) = create_engine();

    // 依赖混淆攻击
    let seq = create_sequence(
        "dependency-confusion",
        vec![
            (20, "external_connection"),
            (12, "binary_drop"),
            (1, "suspicious_process"),
            (4, "suspicious_child"),
        ],
        Some(600000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Dependency Confusion: sequence loaded");
}

// =============================================================================
// Test 81-100: 内部威胁检测
// =============================================================================

#[test]
fn test_insider_data_access() {
    let (mut engine, _) = create_engine();

    // 内部人员异常数据访问
    let seq = create_sequence(
        "insider-data-access",
        vec![
            (10, "sensitive_file_access"),
            (10, "sensitive_file_access"),
            (10, "sensitive_file_access"),
            (23, "data_exfil"),
        ],
        Some(1800000), // 30分钟
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Insider Data Access: sequence loaded");
}

#[test]
fn test_insider_privilege_abuse() {
    let (mut engine, _) = create_engine();

    // 内部人员权限滥用
    let seq = create_sequence(
        "insider-privilege-abuse",
        vec![
            (50, "privilege_escalation"),
            (10, "sensitive_file_access"),
            (41, "lsass_access"),
        ],
        Some(900000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Insider Privilege Abuse: sequence loaded");
}

#[test]
fn test_insider_after_hours() {
    let (mut engine, _) = create_engine();

    // 非工作时间异常活动
    let seq = create_sequence(
        "insider-after-hours",
        vec![
            (1, "suspicious_process"),
            (10, "sensitive_file_access"),
            (23, "data_exfil"),
        ],
        Some(3600000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Insider After Hours: sequence loaded");
}

// =============================================================================
// Test 101-120: Web攻击检测
// =============================================================================

#[test]
fn test_web_shell_upload() {
    let (mut engine, _) = create_engine();

    // Web Shell上传
    let seq = create_sequence(
        "web-shell-upload",
        vec![
            (20, "external_connection"), // Web request
            (12, "binary_drop"),         // File upload
            (1, "suspicious_process"),   // Web server spawning process
        ],
        Some(300000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Web Shell Upload: sequence loaded");
}

#[test]
fn test_sql_injection_to_rce() {
    let (mut engine, _) = create_engine();

    // SQL注入到RCE
    let seq = create_sequence(
        "sqli-to-rce",
        vec![
            (20, "external_connection"),
            (20, "external_connection"),
            (11, "config_modification"),
            (1, "suspicious_process"),
        ],
        Some(600000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ SQLi to RCE: sequence loaded");
}

#[test]
fn test_deserialization_attack() {
    let (mut engine, _) = create_engine();

    // 反序列化攻击
    let seq = create_sequence(
        "deserialization-attack",
        vec![
            (20, "external_connection"),
            (4, "suspicious_child"),
            (50, "privilege_escalation"),
        ],
        Some(300000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Deserialization Attack: sequence loaded");
}

// =============================================================================
// Test 121-140: 容器安全检测
// =============================================================================

#[test]
fn test_container_escape() {
    let (mut engine, _) = create_engine();

    // 容器逃逸
    let seq = create_sequence(
        "container-escape",
        vec![
            (50, "privilege_escalation"),
            (10, "sensitive_file_access"), // /proc, /sys access
            (11, "config_modification"),
            (1, "suspicious_process"),
        ],
        Some(300000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Container Escape: sequence loaded");
}

#[test]
fn test_kubernetes_attack() {
    let (mut engine, _) = create_engine();

    // Kubernetes攻击链
    let seq = create_sequence(
        "k8s-attack",
        vec![
            (20, "external_connection"), // API Server access
            (41, "lsass_access"),        // Service account token
            (50, "privilege_escalation"),
            (4, "suspicious_child"),
        ],
        Some(600000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Kubernetes Attack: sequence loaded");
}

// =============================================================================
// Test 141-160: 云环境攻击检测
// =============================================================================

#[test]
fn test_cloud_credential_theft() {
    let (mut engine, _) = create_engine();

    // 云凭证窃取
    let seq = create_sequence(
        "cloud-credential-theft",
        vec![
            (10, "sensitive_file_access"), // ~/.aws/credentials
            (10, "sensitive_file_access"),
            (20, "external_connection"),
            (23, "data_exfil"),
        ],
        Some(900000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Cloud Credential Theft: sequence loaded");
}

#[test]
fn test_cloud_metadata_exploit() {
    let (mut engine, _) = create_engine();

    // 云元数据服务利用
    let seq = create_sequence(
        "cloud-metadata-exploit",
        vec![
            (20, "external_connection"), // 169.254.169.254
            (40, "credential_access"),
            (50, "privilege_escalation"),
        ],
        Some(300000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Cloud Metadata Exploit: sequence loaded");
}

// =============================================================================
// Test 161-200: 多阶段组合攻击
// =============================================================================

#[test]
fn test_multi_stage_attack_1() {
    let (mut engine, _) = create_engine();

    // 复杂多阶段攻击
    let seq = create_sequence(
        "multi-stage-1",
        vec![
            (1, "suspicious_process"),
            (20, "external_connection"),
            (50, "privilege_escalation"),
            (41, "lsass_access"),
            (4, "suspicious_child"),
            (23, "data_exfil"),
        ],
        Some(3600000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Multi-Stage Attack 1: sequence loaded");
}

#[test]
fn test_multi_stage_attack_2() {
    let (mut engine, _) = create_engine();

    let seq = create_sequence(
        "multi-stage-2",
        vec![
            (3, "encoded_command"),
            (30, "registry_persistence"),
            (31, "run_key"),
            (22, "c2_beacon"),
            (12, "binary_drop"),
        ],
        Some(1800000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Multi-Stage Attack 2: sequence loaded");
}

#[test]
fn test_multi_stage_attack_3() {
    let (mut engine, _) = create_engine();

    let seq = create_sequence(
        "multi-stage-3",
        vec![
            (52, "uac_bypass"),
            (51, "token_impersonation"),
            (41, "lsass_access"),
            (21, "suspicious_port"),
            (4, "suspicious_child"),
        ],
        Some(900000),
    );
    engine.load_sequence(seq).unwrap();

    println!("✅ Multi-Stage Attack 3: sequence loaded");
}

#[test]
fn test_concurrent_attacks() {
    let (mut engine, _) = create_engine();

    // 同时加载多个攻击检测规则
    let attack_types = vec![
        ("ransomware", vec![(1, "suspicious_process"), (13, "ransomware_extension")]),
        ("cryptominer", vec![(1, "suspicious_process"), (22, "c2_beacon")]),
        (
            "apt",
            vec![
                (1, "suspicious_process"),
                (4, "suspicious_child"),
                (23, "data_exfil"),
            ],
        ),
        ("webshell", vec![(20, "external_connection"), (12, "binary_drop")]),
    ];

    for (name, steps) in attack_types {
        let seq = create_sequence(&format!("concurrent-{}", name), steps, Some(600000));
        engine.load_sequence(seq).unwrap();
    }

    let stats = engine.stats();
    assert_eq!(stats.total_rules_tracked, 4);
    println!("✅ Concurrent Attacks: 4 rules loaded");
}

#[test]
fn test_attack_variant_detection() {
    let (mut engine, _) = create_engine();

    // 同一攻击的不同变体
    let variants = [
        vec![(1, "suspicious_process"), (3, "encoded_command")],
        vec![(1, "suspicious_process"), (2, "cmd")],
        vec![(1, "suspicious_process"), (1, "suspicious_process")],
    ];

    for (i, steps) in variants.iter().enumerate() {
        let seq = create_sequence(&format!("variant-{}", i), steps.clone(), Some(300000));
        engine.load_sequence(seq).unwrap();
    }

    println!("✅ Attack Variant Detection: {} variants loaded", variants.len());
}
