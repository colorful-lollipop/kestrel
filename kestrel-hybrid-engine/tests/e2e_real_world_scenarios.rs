//! End-to-End Real-World Scenario Tests
//!
//! 测试真实场景的事件检测，验证Kestrel引擎能否正确识别威胁

use kestrel_hybrid_engine::{HybridEngine, HybridEngineConfig, RuleStrategy};
use kestrel_nfa::{
    CompiledSequence, NfaEngineConfig, NfaSequence, PredicateEvaluator, SeqStep,
};
use std::sync::Arc;
use std::time::Instant;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// 包含在examples中的事件模拟器
mod event_simulator {
    use kestrel_event::{Event, EventBuilder};
    use kestrel_schema::TypedValue;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    pub struct EventSimulator {
        next_event_id: u64,
        base_timestamp: u64,
        current_entity_key: Option<u128>, // 当前场景的entity_key
    }

    impl EventSimulator {
        pub fn new() -> Self {
            Self {
                next_event_id: 1,
                base_timestamp: 1_000_000_000_000,
                current_entity_key: None,
            }
        }

        fn next_id(&mut self) -> u64 {
            let id = self.next_event_id;
            self.next_event_id += 1;
            id
        }

        fn next_timestamp(&mut self) -> u64 {
            let ts = self.base_timestamp;
            self.base_timestamp += 1_000_000; // +1ms
            ts
        }

        // 开始新场景，设置entity_key
        fn start_scenario(&mut self, entity_key: u128) {
            self.current_entity_key = Some(entity_key);
        }

        // 获取当前场景的entity_key
        fn get_entity_key(&self) -> u128 {
            self.current_entity_key.unwrap_or(0)
        }

        pub fn process_start(&mut self, pid: u32, _ppid: u32, name: &str, _cmdline: &str) -> Event {
            EventBuilder::default()
                .event_id(self.next_id())
                .event_type(1)
                .ts_mono(self.next_timestamp())
                .ts_wall(self.base_timestamp)
                .entity_key(self.get_entity_key())
                .field(1, TypedValue::U64(pid as u64))
                .field(3, TypedValue::String(name.to_string()))
                .build()
                .unwrap()
        }

        pub fn file_create(&mut self, pid: u32, path: &str) -> Event {
            EventBuilder::default()
                .event_id(self.next_id())
                .event_type(3)
                .ts_mono(self.next_timestamp())
                .ts_wall(self.base_timestamp)
                .entity_key(self.get_entity_key())
                .field(1, TypedValue::U64(pid as u64))
                .field(10, TypedValue::String(path.to_string()))
                .build()
                .unwrap()
        }

        pub fn file_modify(&mut self, pid: u32, path: &str) -> Event {
            EventBuilder::default()
                .event_id(self.next_id())
                .event_type(4)
                .ts_mono(self.next_timestamp())
                .ts_wall(self.base_timestamp)
                .entity_key(self.get_entity_key())
                .field(1, TypedValue::U64(pid as u64))
                .field(10, TypedValue::String(path.to_string()))
                .build()
                .unwrap()
        }

        pub fn network_connect(&mut self, pid: u32, dest_ip: &str, dest_port: u16) -> Event {
            EventBuilder::default()
                .event_id(self.next_id())
                .event_type(6)
                .ts_mono(self.next_timestamp())
                .ts_wall(self.base_timestamp)
                .entity_key(self.get_entity_key())
                .field(1, TypedValue::U64(pid as u64))
                .field(20, TypedValue::String(dest_ip.to_string()))
                .build()
                .unwrap()
        }

        // 场景1: 可疑PowerShell执行
        pub fn scenario_powershell_suspicious(&mut self) -> Vec<Event> {
            self.start_scenario(1234); // 设置场景entity_key
            let mut events = Vec::new();
            events.push(self.process_start(1234, 100, "powershell.exe", "ps -c xyz"));
            events.push(self.file_create(1234, "/tmp/script.ps1"));
            events.push(self.file_modify(1234, "/tmp/script.ps1"));
            events.push(self.network_connect(1234, "192.168.1.100", 4444));
            events
        }

        // 场景2: 文件篡改
        pub fn scenario_file_tampering(&mut self) -> Vec<Event> {
            self.start_scenario(5678); // 设置场景entity_key
            let mut events = Vec::new();
            events.push(self.process_start(5678, 100, "vim", "vim /etc/passwd"));
            events.push(self.file_create(5678, "/etc/passwd"));
            events.push(self.file_modify(5678, "/etc/passwd"));
            events.push(self.file_modify(5678, "/etc/passwd"));
            events
        }

        // 场景3: 正常进程（不应告警）
        pub fn scenario_normal(&mut self) -> Vec<Event> {
            self.start_scenario(9999); // 设置场景entity_key
            let mut events = Vec::new();
            events.push(self.process_start(9999, 100, "bash", "bash"));
            events
        }
    }

    impl Default for EventSimulator {
        fn default() -> Self {
            Self::new()
        }
    }
}

/// Mock evaluator for testing
struct MockEvaluator;

impl PredicateEvaluator for MockEvaluator {
    fn evaluate(&self, _predicate_id: &str, _event: &kestrel_event::Event) -> kestrel_nfa::NfaResult<bool> {
        Ok(true)
    }

    fn get_required_fields(&self, _predicate_id: &str) -> kestrel_nfa::NfaResult<Vec<u32>> {
        Ok(Vec::new())
    }

    fn has_predicate(&self, _predicate_id: &str) -> bool {
        true
    }
}

/// 创建测试用的混合引擎
fn create_test_engine() -> HybridEngine {
    let config = HybridEngineConfig::default();
    let evaluator = Arc::new(MockEvaluator);
    HybridEngine::new(config, evaluator).unwrap()
}

/// 创建简单的测试序列
fn create_test_sequence(id: &str, steps: Vec<(u16, &str)>, maxspan: Option<u64>) -> CompiledSequence {
    let seq_steps: Vec<_> = steps
        .iter()
        .enumerate()
        .map(|(i, (event_type, pred_id))| {
            // state_id starts from 0!
            // SeqStep::new(state_id, predicate_id, event_type_id)
            SeqStep::new(i as u16, pred_id.to_string(), *event_type)
        })
        .collect();

    let sequence = NfaSequence::new(
        id.to_string(),
        100, // by_field_id
        seq_steps,
        maxspan,
        None, // until_step
    );

    CompiledSequence {
        id: id.to_string(),
        sequence,
        rule_id: format!("rule-{}", id),
        rule_name: format!("Test Rule {}", id),
    }
}

#[test]
fn test_scenario_powershell_suspicious() {
    let mut engine = create_test_engine();
    let mut simulator = event_simulator::EventSimulator::new();

    // 创建规则：单步 - 检测任何进程启动
    let simple_sequence = create_test_sequence(
        "process-start",
        vec![(1, "p1")],
        None,
    );

    engine.load_sequence(simple_sequence).unwrap();
    // engine.build_ac_matcher().unwrap(); // Optional for NFA-based testing

    // 生成事件
    let events = simulator.scenario_powershell_suspicious();

    // 处理事件并收集告警
    let mut all_alerts = Vec::new();
    for event in &events {
        match engine.process_event(event) {
            Ok(alerts) => all_alerts.extend(alerts),
            Err(e) => panic!("Failed to process event: {}", e),
        }
    }

    // 验证：应该生成1个告警（第一个事件匹配）
    println!("Total alerts: {}", all_alerts.len());
    for (i, alert) in all_alerts.iter().enumerate() {
        println!("Alert {}: rule={}, sequence={}", i, alert.rule_id, alert.sequence_id);
    }

    assert!(all_alerts.len() >= 1, "Expected at least 1 alert, got {}", all_alerts.len());

    let alert = &all_alerts[0];
    assert_eq!(alert.rule_id, "process-start");

    println!("✅ PowerShell suspicious scenario detected!");
    println!("   Rule: {}", alert.rule_name);
    println!("   Sequence: {}", alert.sequence_id);
    println!("   Total alerts: {}", all_alerts.len());
}

#[test]
fn test_scenario_file_tampering() {
    let mut engine = create_test_engine();
    let mut simulator = event_simulator::EventSimulator::new();

    // 创建规则：进程启动 -> 文件创建 -> 多次文件修改
    let sequence = create_test_sequence(
        "file-tampering",
        vec![(1, "p1"), (3, "p2"), (4, "p3"), (4, "p4")],
        Some(10000), // 10秒内完成
    );

    engine.load_sequence(sequence).unwrap();
    // engine.build_ac_matcher().unwrap(); // Optional for NFA-based testing

    // 生成事件
    let events = simulator.scenario_file_tampering();

    // 处理事件
    let mut all_alerts = Vec::new();
    for event in &events {
        match engine.process_event(event) {
            Ok(alerts) => all_alerts.extend(alerts),
            Err(e) => panic!("Failed to process event: {}", e),
        }
    }

    // 验证：应该生成1个告警
    assert_eq!(
        all_alerts.len(),
        1,
        "Expected 1 alert for file tampering, got {}",
        all_alerts.len()
    );

    let alert = &all_alerts[0];
    assert_eq!(alert.rule_id, "file-tampering");
    assert_eq!(alert.sequence_id, "file-tampering");

    println!("✅ File tampering scenario detected!");
    println!("   Rule: {}", alert.rule_name);
    println!("   Events in sequence: {}", alert.events.len());
}

#[test]
fn test_scenario_normal_process_no_alert() {
    let mut engine = create_test_engine();
    let mut simulator = event_simulator::EventSimulator::new();

    // 创建规则：需要4步才能触发
    let sequence = create_test_sequence(
        "multi-step",
        vec![(1, "p1"), (3, "p2"), (4, "p3"), (6, "p4")],
        Some(5000),
    );

    engine.load_sequence(sequence).unwrap();
    // engine.build_ac_matcher().unwrap(); // Optional for NFA-based testing

    // 生成正常事件（只有1个）
    let events = simulator.scenario_normal();

    // 处理事件
    let mut all_alerts = Vec::new();
    for event in &events {
        match engine.process_event(event) {
            Ok(alerts) => all_alerts.extend(alerts),
            Err(e) => panic!("Failed to process event: {}", e),
        }
    }

    // 验证：不应该生成告警
    assert_eq!(
        all_alerts.len(),
        0,
        "Expected 0 alerts for normal process, got {}",
        all_alerts.len()
    );

    println!("✅ Normal process correctly ignored (no false positives)");
}

#[test]
fn test_multiple_scenarios_mixed() {
    let mut engine = create_test_engine();
    let mut simulator = event_simulator::EventSimulator::new();

    // 加载多个规则
    let seq1 = create_test_sequence(
        "powershell-suspicious",
        vec![(1, "p1"), (3, "p2"), (4, "p3"), (6, "p4")],
        Some(5000),
    );

    let seq2 = create_test_sequence(
        "file-tampering",
        vec![(1, "p1"), (3, "p2"), (4, "p3"), (4, "p4")],
        Some(10000),
    );

    engine.load_sequence(seq1).unwrap();
    engine.load_sequence(seq2).unwrap();
    // engine.build_ac_matcher().unwrap(); // Optional for NFA-based testing

    // 混合处理多个场景
    let mut all_events = Vec::new();
    all_events.extend(simulator.scenario_powershell_suspicious());
    all_events.extend(simulator.scenario_normal()); // 正常事件，不应告警
    all_events.extend(simulator.scenario_file_tampering());

    // 处理所有事件
    let mut all_alerts = Vec::new();
    for event in &all_events {
        match engine.process_event(event) {
            Ok(alerts) => all_alerts.extend(alerts),
            Err(e) => panic!("Failed to process event: {}", e),
        }
    }

    // 验证：应该有2个告警（1个PowerShell + 1个文件篡改）
    assert_eq!(
        all_alerts.len(),
        2,
        "Expected 2 alerts, got {}",
        all_alerts.len()
    );

    // 验证告警类型
    let rule_ids: Vec<_> = all_alerts.iter().map(|a| a.rule_id.as_str()).collect();
    assert!(rule_ids.contains(&"powershell-suspicious"));
    assert!(rule_ids.contains(&"file-tampering"));

    println!("✅ Mixed scenarios handled correctly!");
    println!("   Total alerts: {}", all_alerts.len());
    println!("   Rules triggered: {:?}", rule_ids);
}

#[test]
fn test_performance_realistic_load() {
    let mut engine = create_test_engine();
    let mut simulator = event_simulator::EventSimulator::new();

    // 加载10个规则
    for i in 0..10 {
        let seq = create_test_sequence(
            &format!("rule-{}", i),
            vec![(1, "p1"), (3, "p2"), (4, "p3")],
            Some(5000),
        );
        engine.load_sequence(seq).unwrap();
    }
    // engine.build_ac_matcher().unwrap(); // Optional for NFA-based testing

    // 生成1000个事件
    let mut events = Vec::new();
    for i in 0..1000 {
        events.extend(simulator.scenario_normal());
        if i % 100 == 0 {
            events.extend(simulator.scenario_powershell_suspicious());
        }
    }

    // 测量处理时间
    let start = Instant::now();
    let mut total_alerts = 0;
    for event in &events {
        match engine.process_event(event) {
            Ok(alerts) => total_alerts += alerts.len(),
            Err(_) => continue,
        }
    }
    let elapsed = start.elapsed();

    let throughput = events.len() as f64 / elapsed.as_secs_f64();
    let avg_latency = elapsed.as_micros() as f64 / events.len() as f64;

    println!("✅ Performance test completed:");
    println!("   Total events: {}", events.len());
    println!("   Total alerts: {}", total_alerts);
    println!("   Throughput: {:.2} events/sec", throughput);
    println!("   Avg latency: {:.2} µs/event", avg_latency);
    println!("   Total time: {:?}", elapsed);

    // 验证性能要求
    assert!(throughput > 1000.0, "Throughput too low: {:.2} events/sec", throughput);
    assert!(avg_latency < 1000.0, "Latency too high: {:.2} µs", avg_latency);
}

#[test]
fn test_strategy_selection() {
    let engine = create_test_engine();

    // 创建简单规则
    let simple_seq = create_test_sequence("simple", vec![(1, "p1")], None);

    // 创建复杂规则
    let complex_seq = create_test_sequence(
        "complex",
        vec![
            (1, "p1"),
            (2, "p2"),
            (3, "p3"),
            (4, "p4"),
            (5, "p5"),
            (6, "p6"),
            (7, "p7"),
        ],
        Some(10000),
    );

    let mut engine_with_rules = engine;
    engine_with_rules.load_sequence(simple_seq).unwrap();
    engine_with_rules.load_sequence(complex_seq).unwrap();
    // engine_with_rules.build_ac_matcher().unwrap(); // Optional for NFA-based testing

    // 检查策略分配
    let stats = engine_with_rules.stats();
    println!("✅ Strategy selection test:");
    println!("   Total rules: {}", stats.total_rules_tracked);
    println!("   NFA sequences: {}", stats.nfa_sequence_count);

    assert!(stats.total_rules_tracked >= 2);
}
