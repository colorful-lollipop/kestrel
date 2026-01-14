# Kestrel端到端测试指南

**创建日期**: 2026-01-14
**版本**: 0.2.0

---

## 概述

本指南介绍如何使用Kestrel进行端到端测试，包括：
1. 使用事件模拟器生成测试事件
2. 创建检测规则
3. 处理事件并收集告警
4. 验证检测结果

---

## 架构组件

### 1. EventSimulator（事件模拟器）

位置: `examples/event_simulator.rs`

事件模拟器用于生成各种系统事件，包括：
- **进程事件**: `process_start()`, `process_exit()`
- **文件事件**: `file_create()`, `file_modify()`, `file_delete()`
- **网络事件**: `network_connect()`, `network_accept()`

### 2. HybridEngine（混合引擎）

位置: `kestrel-hybrid-engine/src/engine.rs`

混合引擎是核心处理组件，负责：
- 加载检测规则
- 根据规则复杂度选择最优策略（AC-DFA、Lazy DFA、NFA）
- 处理事件流
- 生成告警

### 3. Event（事件模型）

位置: `kestrel-event/src/lib.rs`

事件包含以下关键字段：
- `event_id`: 唯一标识符
- `event_type_id`: 事件类型（进程、文件、网络等）
- `ts_mono_ns`: 单调时间戳（用于排序）
- `ts_wall_ns`: 墙钟时间戳（用于显示）
- `entity_key`: 实体键（用于分组，如PID）
- `fields`: 事件字段（键值对）

---

## 使用示例

### 基础用法

```rust
use kestrel_hybrid_engine::{HybridEngine, HybridEngineConfig};
use kestrel_nfa::{CompiledSequence, NfaSequence, SeqStep, PredicateEvaluator};
use std::sync::Arc;

// 1. 创建Mock评估器
struct MockEvaluator;
impl PredicateEvaluator for MockEvaluator {
    fn evaluate(&self, _pred: &str, _event: &Event) -> NfaResult<bool> {
        Ok(true)  // 接受所有谓词
    }

    fn get_required_fields(&self, _pred: &str) -> NfaResult<Vec<u32>> {
        Ok(vec![])
    }

    fn has_predicate(&self, _pred: &str) -> bool {
        true
    }
}

// 2. 创建引擎
let config = HybridEngineConfig::default();
let evaluator = Arc::new(MockEvaluator);
let mut engine = HybridEngine::new(config, evaluator).unwrap();

// 3. 创建检测序列
let seq_steps = vec![
    SeqStep::new(1, "pred1".to_string(), 1),  // 事件类型1
    SeqStep::new(3, "pred2".to_string(), 2),  // 事件类型3
];

let sequence = NfaSequence::new(
    "my-sequence".to_string(),
    100,  // by_field_id
    seq_steps,
    Some(5000),  // maxspan (5秒)
    None,        // until_step
);

let compiled = CompiledSequence {
    id: "my-sequence".to_string(),
    sequence,
    rule_id: "rule-001".to_string(),
    rule_name: "My Detection Rule".to_string(),
};

// 4. 加载序列
engine.load_sequence(compiled).unwrap();

// 5. 处理事件
let event = Event::builder()
    .event_type(1)
    .ts_mono(1000)
    .ts_wall(1000)
    .entity_key(12345)
    .build()
    .unwrap();

match engine.process_event(&event) {
    Ok(alerts) => {
        for alert in alerts {
            println!("Alert: {} - {}", alert.rule_id, alert.sequence_id);
        }
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

### 使用事件模拟器

```rust
// 创建模拟器
let mut sim = EventSimulator::new();

// 生成可疑PowerShell场景
let events = sim.scenario_powershell_suspicious();

// 处理所有事件
for event in &events {
    let alerts = engine.process_event(event)?;
    for alert in alerts {
        println!("Detected: {}", alert.rule_name);
    }
}
```

---

## 真实场景示例

### 场景1: 可疑PowerShell执行

**威胁特征**:
1. PowerShell进程启动
2. 创建脚本文件
3. 修改脚本文件
4. 连接到可疑IP

**检测规则**:
```rust
let sequence = create_test_sequence(
    "powershell-suspicious",
    vec![(1, "p1"), (3, "p2"), (4, "p3"), (6, "p4")],
    Some(5000),  // 5秒内完成
);
```

### 场景2: 文件篡改

**威胁特征**:
1. 编辑器进程启动
2. 打开敏感文件
3. 多次修改文件

**检测规则**:
```rust
let sequence = create_test_sequence(
    "file-tampering",
    vec![(1, "p1"), (3, "p2"), (4, "p3"), (4, "p4")],
    Some(10000),  // 10秒内完成
);
```

---

## 测试框架

### 测试文件位置

- **事件模拟器**: `examples/event_simulator.rs`
- **端到端测试**: `kestrel-hybrid-engine/tests/e2e_real_world_scenarios.rs`
- **集成测试**: `kestrel-hybrid-engine/tests/integration_test.rs`
- **现有E2E测试**: `kestrel-hybrid-engine/tests/e2e_test.rs`

### 运行测试

```bash
# 运行所有端到端测试
cargo test -p kestrel-hybrid-engine --test e2e_real_world_scenarios

# 运行特定测试
cargo test -p kestrel-hybrid-engine --test e2e_real_world_scenarios test_scenario_powershell_suspicious

# 显示输出
cargo test -p kestrel-hybrid-engine --test e2e_real_world_scenarios -- --nocapture
```

---

## 当前实现状态

### ✅ 已完成

1. **事件模拟器**
   - 支持进程、文件、网络事件生成
   - 预定义场景（PowerShell、文件篡改等）
   - 自动时间戳和entity_key管理

2. **测试框架**
   - 完整的端到端测试套件
   - 6个测试场景
   - 性能基准测试

3. **C FFI接口**
   - 完整的C兼容API
   - 事件处理、规则加载/卸载
   - 统计信息获取

4. **文档**
   - 本使用指南
   - 代码注释完整

### ⚠️ 需要进一步调试

**NFA引擎告警生成**:
- 当前测试中，事件处理不产生告警
- 可能原因：
  1. NFA状态机需要完整的事件序列才能触发
  2. Entity key匹配逻辑需要验证
  3. 谓词评估器实现可能需要完善

**建议**:
- 使用调试日志跟踪NFA状态转换
- 验证entity key的正确性
- 检查maxspan时间窗口逻辑

### 📊 测试结果

```
running 6 tests
✅ test_strategy_selection ... ok
✅ test_scenario_normal_process_no_alert ... ok
✅ test_performance_realistic_load ... ok
⚠️ test_scenario_powershell_suspicious ... FAILED (需要调试)
⚠️ test_scenario_file_tampering ... FAILED (需要调试)
⚠️ test_multiple_scenarios_mixed ... FAILED (需要调试)
```

**性能测试结果**:
- 总事件数: 1,040
- 吞吐量: 8,959 events/sec
- 平均延迟: 111.62 µs/event
- 总时间: 116ms

---

## 下一步工作

### 短期

1. **调试NFA告警生成**
   - 添加详细日志
   - 验证状态转换逻辑
   - 确认entity key匹配

2. **完善测试场景**
   - 添加更多真实场景
   - 增加边界情况测试
   - 添加压力测试

### 中期

1. **真实规则集成**
   - 从EQL规则编译到NFA序列
   - 支持复杂谓词评估
   - 添加正则表达式和glob匹配

2. **性能优化**
   - AC-DFA优化
   - Lazy DFA热spot检测
   - 并行事件处理

### 长期

1. **生产部署**
   - 持久化规则存储
   - 分布式处理
   - 实时监控和告警

2. **扩展功能**
   - 机器学习增强
   - 自适应阈值
   - 异常检测

---

## 参考资料

- **Phase D报告**: `docs/phase_d_final_summary.md`
- **复杂规则测试报告**: `docs/complex_rules_test_report.md`
- **NFA引擎文档**: `kestrel-nfa/README.md`
- **事件模型文档**: `kestrel-event/README.md`

---

## 贡献指南

欢迎贡献！请遵循以下步骤：

1. Fork项目
2. 创建功能分支
3. 编写测试
4. 提交Pull Request

---

**文档版本**: 1.0
**最后更新**: 2026-01-14
**维护者**: Kestrel Team
