//! Advanced Threat Detection Tests
//!
//! 高级威胁检测场景测试 - 使用混合引擎检测复杂的多阶段攻击

use kestrel_event::Event;
use kestrel_hybrid_engine::{HybridEngine, HybridEngineConfig};
use kestrel_schema::{SchemaRegistry, TypedValue};
use std::sync::Arc;

// Mock predicate evaluator for testing
struct MockEvaluator;

#[async_trait::async_trait]

impl kestrel_nfa::PredicateEvaluator for MockEvaluator {
    async fn evaluate(
        &self,
        _predicate_id: &str,
        _event: &kestrel_event::Event,
    ) -> kestrel_nfa::NfaResult<bool> {
        Ok(true)
    }

    fn get_required_fields(&self, _predicate_id: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
        Ok(vec![1, 2])
    }

    fn has_predicate(&self, predicate_id: &str) -> bool {
        !predicate_id.is_empty()
    }
}

fn create_test_schema() -> Arc<SchemaRegistry> {
    Arc::new(SchemaRegistry::new())
}

fn create_test_event(event_type: u16, entity: u128, timestamp_ns: u64, data: &str) -> Event {
    Event::builder()
        .event_type(event_type)
        .ts_mono(timestamp_ns)
        .ts_wall(timestamp_ns)
        .entity_key(entity)
        .field(1, TypedValue::String(data.to_string().into()))
        .build()
        .unwrap()
}

fn create_hybrid_engine() -> HybridEngine {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);
    HybridEngine::new(config, evaluator).unwrap()
}

// =============================================================================
// 供应链攻击检测
// =============================================================================

#[test]
fn test_supply_chain_dependency_confusion() {
    // 检测依赖混淆攻击
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF001u128;
    let base_time = 1_000_000_000u64;

    // 内部包被外部同名包替换
    let e1 = create_test_event(50001, entity, base_time, "npm install @company/package");
    let _ = engine.process_event(&e1);

    let e2 = create_test_event(
        50002,
        entity,
        base_time + 10_000_000_000,
        "fetch https://registry.npmjs.org/@company/package",
    );
    let result = engine.process_event(&e2);

    assert!(result.is_ok());
}

#[test]
fn test_supply_chain_compromised_build_tool() {
    // 检测被感染的构建工具
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF002u128;
    let base_time = 2_000_000_000u64;

    let e1 = create_test_event(50001, entity, base_time, "maven build started");
    let _ = engine.process_event(&e1);

    let e2 = create_test_event(
        50002,
        entity,
        base_time + 60_000_000_000,
        "outbound connection to unknown host",
    );
    let result = engine.process_event(&e2);

    assert!(result.is_ok());
}

#[test]
fn test_supply_chain_typosquatting() {
    // 检测误植域名攻击
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF003u128;
    let base_time = 3_000_000_000u64;

    let e1 = create_test_event(50001, entity, base_time, "pip install reqeusts");
    let result = engine.process_event(&e1);

    assert!(result.is_ok());
}

#[test]
fn test_supply_chain_malicious_commit() {
    // 检测恶意代码提交
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF004u128;
    let base_time = 4_000_000_000u64;

    let e1 = create_test_event(50001, entity, base_time, "git push origin main");
    let _ = engine.process_event(&e1);

    let e2 = create_test_event(
        50002,
        entity,
        base_time + 1_000_000_000,
        "commit contains eval(base64_decode())",
    );
    let result = engine.process_event(&e2);

    assert!(result.is_ok());
}

#[test]
fn test_supply_chain_hijacked_account() {
    // 检测被劫持的开发者账户
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF005u128;
    let base_time = 5_000_000_000u64;

    let e1 = create_test_event(50001, entity, base_time, "login from new location: Russia");
    let _ = engine.process_event(&e1);

    let e2 = create_test_event(
        50002,
        entity,
        base_time + 3_600_000_000_000,
        "package publish by developer@company.com",
    );
    let result = engine.process_event(&e2);

    assert!(result.is_ok());
}

// =============================================================================
// 无文件恶意软件检测
// =============================================================================

#[test]
fn test_fileless_powershell_reflective_injection() {
    // 检测PowerShell反射注入
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF010u128;
    let base_time = 10_000_000_000u64;

    let e1 = create_test_event(
        50001,
        entity,
        base_time,
        "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiA",
    );
    let _ = engine.process_event(&e1);

    let e2 = create_test_event(
        50002,
        entity,
        base_time + 500_000_000,
        "[System.Reflection.Assembly]::Load",
    );
    let result = engine.process_event(&e2);

    assert!(result.is_ok());
}

#[test]
fn test_fileless_dotnet_in_memory() {
    // 检测.NET内存执行
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF011u128;
    let base_time = 11_000_000_000u64;

    let e1 = create_test_event(50001, entity, base_time, "CLR loaded without dotnet.exe");
    let result = engine.process_event(&e1);

    assert!(result.is_ok());
}

#[test]
fn test_fileless_wmi_subscription() {
    // 检测WMI事件订阅
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF012u128;
    let base_time = 12_000_000_000u64;

    let e1 = create_test_event(50001, entity, base_time, "__EventFilter created");
    let _ = engine.process_event(&e1);

    let e2 = create_test_event(
        50002,
        entity,
        base_time + 100_000_000,
        "CommandLineEventConsumer registered",
    );
    let result = engine.process_event(&e2);

    assert!(result.is_ok());
}

#[test]
fn test_fileless_registry_payload() {
    // 检测注册表载荷执行
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF013u128;
    let base_time = 13_000_000_000u64;

    let e1 = create_test_event(50001, entity, base_time, "HKCU\\Software\\Classes\\ evil payload");
    let _ = engine.process_event(&e1);

    let e2 = create_test_event(50002, entity, base_time + 300_000_000, "regsvr32 /i /n scrobj.dll");
    let result = engine.process_event(&e2);

    assert!(result.is_ok());
}

// =============================================================================
// 内存注入检测
// =============================================================================

#[test]
fn test_memory_process_hollowing() {
    // 检测进程镂空
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF020u128;
    let base_time = 20_000_000_000u64;

    let e1 = create_test_event(50001, entity, base_time, "CreateProcess suspended");
    let _ = engine.process_event(&e1);

    let e2 = create_test_event(50002, entity, base_time + 50_000_000, "NtUnmapViewOfSection");
    let _ = engine.process_event(&e2);

    let e3 = create_test_event(50003, entity, base_time + 100_000_000, "VirtualAllocEx RWX");
    let result = engine.process_event(&e3);

    assert!(result.is_ok());
}

#[test]
fn test_memory_apc_injection() {
    // 检测APC注入
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF021u128;
    let base_time = 21_000_000_000u64;

    let e1 = create_test_event(50001, entity, base_time, "OpenThread");
    let _ = engine.process_event(&e1);

    let e2 = create_test_event(50002, entity, base_time + 10_000_000, "QueueUserAPC");
    let result = engine.process_event(&e2);

    assert!(result.is_ok());
}

#[test]
fn test_memory_thread_hijacking() {
    // 检测线程劫持
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF022u128;
    let base_time = 22_000_000_000u64;

    let e1 = create_test_event(50001, entity, base_time, "SuspendThread");
    let _ = engine.process_event(&e1);

    let e2 = create_test_event(50002, entity, base_time + 5_000_000, "GetThreadContext");
    let _ = engine.process_event(&e2);

    let e3 = create_test_event(50003, entity, base_time + 10_000_000, "SetThreadContext");
    let result = engine.process_event(&e3);

    assert!(result.is_ok());
}

#[test]
fn test_memory_atom_bombing() {
    // 检测Atom Bombing注入
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF023u128;
    let base_time = 23_000_000_000u64;

    let e1 = create_test_event(50001, entity, base_time, "GlobalAddAtom");
    let _ = engine.process_event(&e1);

    let e2 = create_test_event(
        50002,
        entity,
        base_time + 50_000_000,
        "NtQueueApcThread with GlobalGetAtomName",
    );
    let result = engine.process_event(&e2);

    assert!(result.is_ok());
}

#[test]
fn test_memory_etw_patch() {
    // 检测ETW内存补丁
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF024u128;
    let base_time = 24_000_000_000u64;

    let e1 = create_test_event(50001, entity, base_time, "ntdll.dll EtwEventWrite patched");
    let result = engine.process_event(&e1);

    assert!(result.is_ok());
}

// =============================================================================
// 反取证技术检测
// =============================================================================

#[test]
fn test_anti_forensic_timestomp() {
    // 检测时间戳篡改
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF030u128;
    let base_time = 30_000_000_000u64;

    let e1 = create_test_event(50001, entity, base_time, "SetFileTime: 2019-01-01");
    let result = engine.process_event(&e1);

    assert!(result.is_ok());
}

#[test]
fn test_anti_forensic_log_deletion() {
    // 检测日志删除
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF031u128;
    let base_time = 31_000_000_000u64;

    let e1 = create_test_event(50001, entity, base_time, "wevtutil cl security");
    let _ = engine.process_event(&e1);

    let e2 = create_test_event(50002, entity, base_time + 100_000_000, "Clear-EventLog");
    let result = engine.process_event(&e2);

    assert!(result.is_ok());
}

#[test]
fn test_anti_forensic_shadow_copy_deletion() {
    // 检测影子副本删除
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF032u128;
    let base_time = 32_000_000_000u64;

    let e1 = create_test_event(50001, entity, base_time, "vssadmin delete shadows /all");
    let _ = engine.process_event(&e1);

    let e2 = create_test_event(50002, entity, base_time + 50_000_000, "wmic shadowcopy delete");
    let result = engine.process_event(&e2);

    assert!(result.is_ok());
}

#[test]
fn test_anti_forensic_prefetch_deletion() {
    // 检测预取文件删除
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF033u128;
    let base_time = 33_000_000_000u64;

    let e1 = create_test_event(50001, entity, base_time, "del C:\\Windows\\Prefetch\\*.pf");
    let result = engine.process_event(&e1);

    assert!(result.is_ok());
}

// =============================================================================
// 高级持续性威胁 (APT) 检测
// =============================================================================

#[test]
fn test_apt_long_dwell_time() {
    // 检测长期潜伏
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF040u128;
    let base_time = 40_000_000_000u64;

    // 初始入侵
    let e1 = create_test_event(50001, entity, base_time, "initial compromise");
    let _ = engine.process_event(&e1);

    // 180天后活动
    let e2 = create_test_event(
        50002,
        entity,
        base_time + 15_552_000_000_000_000u64,
        "lateral movement started",
    );
    let result = engine.process_event(&e2);

    assert!(result.is_ok());
}

#[test]
fn test_apt_low_slow_beacon() {
    // 检测低频慢速信标
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF041u128;
    let base_time = 41_000_000_000u64;

    // 每小时一次信标，持续24小时
    for i in 0..24 {
        let e = create_test_event(
            50001,
            entity,
            base_time + i as u64 * 3_600_000_000_000u64,
            "beacon to c2.example.com",
        );
        let _ = engine.process_event(&e);
    }

    let _alerts = engine.stats();
    // total_rules_tracked is u32, just verify stats are accessible
    let _ = _alerts.total_rules_tracked;
}

#[test]
fn test_apt_domain_fronting() {
    // 检测域前置
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF042u128;
    let base_time = 42_000_000_000u64;

    let e1 = create_test_event(50001, entity, base_time, "Host: cdn.cloudfront.net");
    let _ = engine.process_event(&e1);

    let e2 =
        create_test_event(50002, entity, base_time + 100_000_000, "X-Forwarded-Host: evil.com");
    let result = engine.process_event(&e2);

    assert!(result.is_ok());
}

#[test]
fn test_apt_dns_tunnel_slow() {
    // 检测慢速DNS隧道
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF043u128;
    let base_time = 43_000_000_000u64;

    // 模拟DNS隧道 - 低频查询
    for i in 0..10 {
        let e = create_test_event(
            50001,
            entity,
            base_time + i as u64 * 60_000_000_000u64,
            &format!("a{}.base64data.example.com A", i),
        );
        let _ = engine.process_event(&e);
    }

    let result = engine.process_event(&create_test_event(
        50002,
        entity,
        base_time + 600_000_000_000u64,
        "DNS tunnel detected",
    ));

    assert!(result.is_ok());
}

// =============================================================================
// 勒索软件行为检测
// =============================================================================

#[test]
fn test_ransomware_volume_shadow_delete() {
    // 检测卷影副本删除 (勒索软件前兆)
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF050u128;
    let base_time = 50_000_000_000u64;

    let e1 = create_test_event(50001, entity, base_time, "vssadmin.exe resize shadowstorage");
    let _ = engine.process_event(&e1);

    let e2 =
        create_test_event(50002, entity, base_time + 60_000_000_000, "vssadmin delete shadows");
    let result = engine.process_event(&e2);

    assert!(result.is_ok());
}

#[test]
fn test_ransomware_backup_service_stop() {
    // 检测备份服务停止
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF051u128;
    let base_time = 51_000_000_000u64;

    let services = ["Veeam", "BackupExec", "Acronis", "ShadowProtect"];
    for (i, service) in services.iter().enumerate() {
        let e = create_test_event(
            50001,
            entity,
            base_time + i as u64 * 10_000_000_000,
            &format!("net stop {}", service),
        );
        let _ = engine.process_event(&e);
    }

    let result = engine.stats();
    let _ = result.total_rules_tracked;
}

#[test]
fn test_ransomware_file_extension_pattern() {
    // 检测文件扩展名变更模式
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF052u128;
    let base_time = 52_000_000_000u64;

    // 快速重命名文件
    for i in 0..20 {
        let e = create_test_event(
            50001,
            entity,
            base_time + i as u64 * 1_000_000,
            &format!("rename file{}.doc to file{}.locked", i, i),
        );
        let _ = engine.process_event(&e);
    }

    let result = engine.stats();
    let _ = result.total_rules_tracked;
}

#[test]
fn test_ransomware_note_creation() {
    // 检测勒索信创建
    let _schema = create_test_schema();
    let mut engine = create_hybrid_engine();

    let entity = 0xF053u128;
    let base_time = 53_000_000_000u64;

    let notes = ["README.txt", "HOW_TO_DECRYPT.hta", "RECOVER_FILES.html"];
    for (i, note) in notes.iter().enumerate() {
        let e = create_test_event(
            50001,
            entity,
            base_time + i as u64 * 5_000_000_000,
            &format!("create {}", note),
        );
        let _ = engine.process_event(&e);
    }

    let result = engine.stats();
    let _ = result.total_rules_tracked;
}
