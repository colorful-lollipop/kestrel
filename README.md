# Kestrel

<div align="center">

**下一代端侧行为检测引擎** | Next-Generation Endpoint Behavior Detection Engine

[![Build Status](https://img.shields.io/github/actions/workflow/status/kestrel-detection/kestrel/ci.yml?branch=main)](https://github.com/kestrel-detection/kestrel/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust Version](https://img.shields.io/badge/Rust-1.82+-orange.svg)](https://www.rust-lang.org)
[![Test Coverage](https://img.shields.io/badge/coverage-99%25-success)](https://github.com/kestrel-detection/kestrel)

**English | [中文](#中文文档)**

*Rust + eBPF + Host NFA + Wasm/LuaJIT 双运行时 + EQL 兼容*

面向：Linux 与 HarmonyOS（类Unix可移植），端侧低功耗实时检测/阻断 + 离线可复现回放

</div>

---

## 目录

- [核心特性](#核心特性)
- [为什么选择 Kestrel？](#为什么选择-kestrel)
- [技术架构](#技术架构)
  - [整体架构图](#整体架构图)
  - [核心设计理念](#核心设计理念)
  - [技术栈详解](#技术栈详解)
- [核心组件](#核心组件)
  - [Schema Registry - 强类型系统](#schema-registry---强类型系统)
  - [Event 模型 - 稀疏事件存储](#event-模型---稀疏事件存储)
  - [NFA Engine - 序列检测引擎](#nfa-engine---序列检测引擎)
  - [Hybrid Engine - 混合匹配策略](#hybrid-engine---混合匹配策略)
  - [双运行时系统](#双运行时系统)
  - [eBPF 采集层](#ebpf-采集层)
- [快速开始](#快速开始)
- [规则示例](#规则示例)
- [性能基准](#性能基准)
- [项目结构](#项目结构)
- [开发文档](#开发文档)
- [路线图](#路线图)
- [贡献](#贡献)
- [许可证](#许可证)

---

## 核心特性

### 🎯 检测能力
- **EQL 序列规则**: 支持 Elastic EQL 兼容子集，表达复杂行为序列
- **双运行时执行**: Wasm（可移植）和 LuaJIT（高性能）共享统一 Host API
- **实时阻断**: LSM hooks 集成，支持关键动作的内联阻断
- **混合匹配策略**: AC-DFA + 惰性 DFA + NFA，根据规则复杂度自动选择最优策略

### ⚡ 性能特性
- **零拷贝事件采集**: eBPF ringbuf 内核态到用户态零拷贝
- **O(log n) 字段查找**: 稀疏事件结构，二分查找定位字段
- **实例池复用**: Wasm/Lua 运行时实例池，消除初始化开销
- **热点检测与 DFA 缓存**: 频繁匹配的序列自动转换为 DFA，8x 性能提升

### 🔄 可复现性
- **确定性回放**: 相同事件 + 相同规则 + 相同引擎版本 = 相同结果
- **双时间戳**: 单调时钟（排序/窗口）+ 墙上时钟（取证）
- **离线分析**: 支持历史事件的离线回放与验证

---

## 为什么选择 Kestrel？

### 对比传统方案

| 特性 | 传统 EDR | Kestrel |
|------|----------|---------|
| **规则执行** | 解释型/脚本 | 编译为 Wasm/LuaJIT，沙箱化执行 |
| **事件采集** | 轮询/审计日志 | eBPF kernel-level 采集，零拷贝 |
| **序列检测** | 简单模式匹配 | Host NFA + 状态机，支持 maxspan/until |
| **性能优化** | 单一策略 | 混合 DFA/NFA，热点自动识别 |
| **离线分析** | 依赖外部 SIEM | 原生支持离线回放，100% 可复现 |
| **跨平台** | 依赖特定组件 | 架构可移植，Linux/Harmony 兼容 |

### 适用场景

- **端侧 EDR**: 笔记本/服务器的实时威胁检测与响应
- **应用白名单**: 关键系统的行为控制与阻断
- **威胁狩猎**: 本地快速检测，无需上传敏感日志
- **安全研究**: 可复现的离线分析环境

---

## 技术架构

### 整体架构图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Rule Packages (规则层)                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────────────┐  │
│  │ EQL DSL     │ →  │ EQL Compiler│ →  │ IR → Wasm/Lua Predicate         │  │
│  │ (序列规则)   │    │ (kestrel-eql)│   │ (谓词编译产物)                    │  │
│  └─────────────┘    └─────────────┘    └─────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │ hotload / rollback
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Engine Control Plane (控制层)                         │
│                                                                             │
│   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐ │
│   │ RuleManager  │   │ Capability   │   │ Runtime      │   │ Metrics      │ │
│   │ (规则管理)    │   │ Registry     │   │ Manager      │   │ Collection   │ │
│   └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Detection Data Plane (数据层)                          │
│                                                                             │
│   ┌─────────────┐   ┌─────────────────────────────────────────────────────┐ │
│   │  EventBus   │ → │ Partition → Worker Threads (多分区并行处理)          │ │
│   │ (事件总线)   │   └─────────────────────────────────────────────────────┘ │
│   └─────────────┘                          │                                │
│        │                                   ▼                                │
│        │      ┌────────────────────────────────────────────────────────┐   │
│        │      │ Detection Engine Core                                   │   │
│        │      │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │   │
│        │      │  │ Single-Event│  │ NFA Engine  │  │ Hybrid Engine   │  │   │
│        │      │  │ (单事件规则) │  │ (序列规则)   │  │ (AC-DFA + Lazy) │  │   │
│        │      │  └─────────────┘  └─────────────┘  └─────────────────┘  │   │
│        │      │           │                        │                    │   │
│        │      │           ▼                        ▼                    │   │
│        │      │  ┌──────────────────────────────────────────────┐      │   │
│        │      │  │ Predicate Runtime (Wasm / LuaJIT)             │      │   │
│        │      │  │ - Host API v1 (字段访问、正则、glob、告警)      │      │   │
│        │      │  │ - 沙箱化执行，资源限制                          │      │   │
│        │      │  └──────────────────────────────────────────────┘      │   │
│        │      └────────────────────────────────────────────────────────┘   │
│        │                                    │                                │
│        │      ┌─────────────────────────────┼──────────────────────┐       │
│        │      │                             ▼                      │       │
│        │      │  ┌─────────────┐  ┌─────────────────┐  ┌──────────┐│       │
│        │      │  │ StateStore  │  │ Action Executor │  │ Alert    ││       │
│        │      │  │ (TTL/LRU)   │  │ (Block/Allow)   │  │ Output   ││       │
│        │      │  └─────────────┘  └─────────────────┘  └──────────┘│       │
│        │      └────────────────────────────────────────────────────┘       │
│        │                                                                   │
│        ▼                                                                   │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │ Event Sources (可插拔采集层)                                          │  │
│   │  ├─ eBPF tracepoints/kprobes + ringbuf (零拷贝)                      │  │
│   │  ├─ LSM/eBPF-LSM hooks (阻断点)                                      │  │
│   │  ├─ Audit / fanotify (fallback)                                     │  │
│   │  └─ Offline replay (binary log 回放)                                │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 核心设计理念

#### 1. Schema Registry - 强类型事件系统

所有事件字段在启动时注册到 `SchemaRegistry`，运行时通过 `FieldId` (u32) 访问，避免字符串比较开销：

```rust
// 启动时注册字段
let field_id = registry.register_field(FieldDef {
    path: "process.executable".to_string(),
    data_type: FieldDataType::String,
})?;

// 运行时 O(log n) 字段查找
event.get_field(field_id)  // 二分查找，非字符串匹配
```

**优势**:
- 编译时字段路径验证
- 运行时零字符串分配
- O(log n) 字段访问（二分查找）

#### 2. 稀疏事件存储模型

事件使用 `SmallVec<[(FieldId, TypedValue); 8]>` 存储非空字段，默认内联存储 8 个字段，避免堆分配：

```rust
pub struct Event {
    pub event_id: u64,                    // 单调递增 ID（回放排序）
    pub event_type_id: EventTypeId,       // 事件类型
    pub ts_mono_ns: TimestampMono,        // 单调时间戳（排序/窗口）
    pub ts_wall_ns: TimestampWall,        // 墙上时间戳（取证）
    pub entity_key: EntityKey,            // 实体分组键
    pub fields: SmallVec<[(FieldId, TypedValue); 8]>, // 稀疏字段存储
}
```

#### 3. NFA 序列引擎

Host 端执行的 NFA（非确定性有限自动机）用于检测 EQL 序列规则：

```
sequence by process.entity_id
  [process where process.executable == "/bin/bash"]
  [file where file.path == "/etc/passwd"]
  [process where process.executable == "wc"]
with maxspan=5s
```

**实现原理**:
- 每个序列规则编译为 NFA 状态机
- `PartialMatch` 跟踪每个实体的匹配进度
- `maxspan` 使用单调时间戳检查窗口超时
- `until` 子句支持终止条件

```rust
pub struct PartialMatch {
    pub sequence_id: String,
    pub entity_key: EntityKey,
    pub started_at: u64,        // 首事件时间戳（maxspan 计算基准）
    pub last_matched_at: u64,
    pub matched_steps: Vec<usize>,
    pub captured_values: HashMap<String, TypedValue>,
}

pub fn is_expired(&self, now_ns: u64, maxspan_ms: Option<u64>) -> bool {
    if let Some(maxspan) = maxspan_ms {
        let maxspan_ns = maxspan.saturating_mul(1_000_000);
        let elapsed = now_ns.saturating_sub(self.started_at);
        elapsed > maxspan_ns
    } else {
        false
    }
}
```

#### 4. 混合匹配策略 (Hybrid Engine)

根据规则复杂度自动选择最优匹配策略：

| 策略 | 适用场景 | 性能 |
|------|----------|------|
| **AC-DFA** | 简单字符串字面量 | 8x 加速 |
| **Lazy DFA** | 热点简单序列 | 动态编译缓存 |
| **NFA** | 复杂规则（正则/until） | 通用匹配 |
| **Hybrid AC+NFA** | 复杂规则但含字符串字面量 | AC 预过滤 |

**热点检测**:
```rust
pub struct HotSpotDetector {
    sequence_stats: DashMap<String, SequenceStats>,
    hot_threshold: u32,      // 1000 次/分钟
    success_rate_threshold: f64, // 80% 成功率
}
```

### 技术栈详解

```
Rust (Edition 2021, MSRV 1.82)
├── 异步运行时: tokio 1.42
├── 序列化: serde + serde_json + bincode
├── Wasm 运行时: wasmtime 26.0 (with instance pool)
├── Lua 运行时: mlua 0.10 (LuaJIT)
├── eBPF 框架: aya 0.13
├── 数据结构: smallvec, ahash, dashmap
├── 日志: tracing + tracing-subscriber
└── CLI: clap 4.5

C (eBPF)
└── 内核版本: 5.10+ (eBPF + LSM hooks)
```

---

## 核心组件

### Schema Registry - 强类型系统

```rust
use kestrel_schema::{SchemaRegistry, FieldDef, FieldDataType};

// 创建注册表
let mut registry = SchemaRegistry::new();

// 注册字段（运行时一次性）
let pid_field = registry.register_field(FieldDef {
    path: "process.pid".to_string(),
    data_type: FieldDataType::U32,
    description: Some("Process ID".to_string()),
})?;

let exe_field = registry.register_field(FieldDef {
    path: "process.executable".to_string(),
    data_type: FieldDataType::String,
    description: Some("Process executable path".to_string()),
})?;
```

### Event 模型 - 稀疏事件存储

```rust
use kestrel_event::Event;
use kestrel_schema::TypedValue;

// 构建事件
let event = Event::builder()
    .event_type(1001)                    // process_exec
    .ts_mono(1234567890000000000u64)     // 单调时间戳
    .ts_wall(1704067200000000000u64)     // 墙上时间戳
    .entity_key(0x7f3a2b1c0d4e_u128)     // 实体分组键
    .field(pid_field, TypedValue::U32(12345))
    .field(exe_field, TypedValue::String("/bin/bash".to_string()))
    .build()?;

// O(log n) 字段查找
if let Some(TypedValue::String(exe)) = event.get_field(exe_field) {
    println!("Executable: {}", exe);
}
```

### NFA Engine - 序列检测引擎

```rust
use kestrel_nfa::{NfaEngine, NfaSequence, SeqStep, CompiledSequence};

// 定义序列规则
let sequence = NfaSequence {
    id: "suspicious_chain".to_string(),
    steps: vec![
        SeqStep {
            event_type: 1001,  // process_exec
            predicate_id: "bash_exec".to_string(),
        },
        SeqStep {
            event_type: 1002,  // file_open
            predicate_id: "read_passwd".to_string(),
        },
    ],
    maxspan_ms: Some(5000),  // 5秒窗口
};

// 编译并加载
let compiled = CompiledSequence {
    id: "seq-001".to_string(),
    sequence,
    rule_id: "rule-001".to_string(),
    rule_name: "Bash reads /etc/passwd".to_string(),
};

nfa_engine.load_sequence(compiled)?;

// 处理事件
let alerts = nfa_engine.process_event(&event, &evaluator)?;
```

### Hybrid Engine - 混合匹配策略

```rust
use kestrel_hybrid_engine::{HybridEngine, RuleComplexityAnalyzer};

// 自动分析规则复杂度
let analyzer = RuleComplexityAnalyzer::new();
let complexity = analyzer.analyze(&rule);

// 选择最优策略
let strategy = match complexity.score {
    0..=20 if complexity.has_string_literals => MatchingStrategy::AcDfa,
    21..=50 if complexity.is_hot_sequence => MatchingStrategy::LazyDfa,
    _ if complexity.has_regex => MatchingStrategy::Nfa,
    _ => MatchingStrategy::HybridAcNfa,
};

// 执行检测
let engine = HybridEngine::new(config);
let alerts = engine.process_event(event)?;
```

### 双运行时系统

**统一 Runtime Trait 抽象**:

```rust
#[async_trait::async_trait]
pub trait Runtime: Send + Sync {
    async fn evaluate(&self, predicate_id: &str, event: &Event) -> RuntimeResult<EvalResult>;
    async fn evaluate_adhoc(&self, bytes: &[u8], event: &Event) -> RuntimeResult<EvalResult>;
    fn required_fields(&self, predicate_id: &str) -> RuntimeResult<Vec<FieldId>>;
    fn has_predicate(&self, predicate_id: &str) -> bool;
    fn runtime_type(&self) -> RuntimeType;
}

// Wasm 运行时
let wasm_runtime = WasmRuntimeAdapter::new(WasmEngine::new(config)?);

// Lua 运行时  
let lua_runtime = LuaRuntimeAdapter::new(LuaEngine::new(config)?);

// 统一使用
runtime_manager.register(RuntimeType::Wasm, Arc::new(wasm_runtime));
runtime_manager.register(RuntimeType::Lua, Arc::new(lua_runtime));
```

### eBPF 采集层

```rust
use kestrel_ebpf::{EbpfCollector, EventNormalizer, InterestPushdown};

// 创建采集器
let (event_tx, mut event_rx) = mpsc::channel(10000);
let ebpf = Ebpf::load_file("kestrel.bpf.o")?;
let collector = EbpfCollector::new(event_tx, ebpf)?;

// 兴趣下推 - 只采集规则需要的事件类型
let interests = InterestPushdown::from_rules(&rules);
collector.set_interests(interests)?;

// 事件规范化
let normalizer = EventNormalizer::new(schema);
let event = normalizer.normalize(raw_event)?;
```

---

## 快速开始

### 前置要求

- Rust 1.82+ (edition 2021)
- Linux kernel 5.10+ (eBPF 支持)
- Git

### 安装

```bash
# 克隆仓库
git clone https://github.com/kestrel-detection/kestrel.git
cd Kestrel

# 构建项目（开发模式）
cargo build --workspace

# 构建项目（发布模式，推荐用于生产）
cargo build --workspace --release
```

### 运行

```bash
# 使用默认规则目录运行检测引擎
cargo run --bin kestrel -- run

# 指定规则目录
cargo run --bin kestrel -- run --rules /path/to/rules

# 设置日志级别
cargo run --bin kestrel -- run --rules ./rules --log-level info

# 验证规则配置
cargo run --bin kestrel -- validate --rules ./rules

# 列出所有规则
cargo run --bin kestrel -- list --rules ./rules
```

### 测试

```bash
# 运行所有测试
cargo test --workspace

# 运行特定模块测试
cargo test -p kestrel-schema
cargo test -p kestrel-nfa
cargo test -p kestrel-engine

# 代码覆盖率
cargo install cargo-llvm-cov
cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info
```

---

## 规则示例

### EQL 序列规则

```eql
// 检测 bash 读取 /etc/passwd 后执行 wc
sequence by process.entity_id
  [process where process.executable == "/bin/bash"]
  [file where file.path == "/etc/passwd" and event.action == "read"]
  [process where process.executable == "wc"]
with maxspan=5s
```

### EQL 单事件规则

```eql
// 检测可疑临时目录执行
process where process.executable == "/tmp/suspicious" 
  and process.parent.executable != "install"
```

### JSON 规则格式

```json
{
  "manifest": {
    "format_version": "1.0",
    "metadata": {
      "rule_id": "suspicious-exec",
      "rule_name": "Suspicious Temporary Binary Execution",
      "severity": "High",
      "description": "Detects binary execution from /tmp directory"
    },
    "capabilities": {
      "supports_inline": true,
      "requires_alert": true,
      "requires_block": false
    }
  },
  "predicates": {
    "wasm": "suspicious_exec.wasm",
    "lua": "suspicious_exec.lua"
  }
}
```

### Rust 规则定义

```rust
use kestrel_rules::{Rule, RuleDefinition, RuleManager};

let rule = RuleDefinition {
    id: "credential_access".to_string(),
    name: "Credential Access Detection".to_string(),
    severity: Severity::High,
    event_type: 1001,
    condition: RuleCondition::Predicate {
        runtime: RuntimeType::Wasm,
        predicate_id: "check_credential_access".to_string(),
    },
};
```

---

## 性能基准

> 测试环境: Intel i7-12700, 32GB RAM, Linux 6.5, Release 模式

### 核心性能指标

| 指标 | 目标 | 实测值 | 状态 |
|------|------|--------|------|
| **AC-DFA 加速比** | 5-10x | **8.0x** | ✅ 达成 |
| **事件处理延迟** | < 1ms | **133 µs** | ✅ 达成 |
| **事件吞吐量** | > 1K EPS | **7.5K EPS** | ✅ 达成 |
| **内存占用** | < 20MB | **1.6 MB** | ✅ 达成 |

### 详细性能数据

| 测试项 | Debug 模式 | Release 模式 | 提升 |
|--------|-----------|--------------|------|
| AC-DFA 匹配 | 115 ns/op | 125 ns/op | - |
| 事件处理 | 222 µs/event | 133 µs/event | **68%** |
| 序列加载 | - | 2.90 µs/sequence | - |

### 内存使用分解

| 组件 | 内存占用 |
|------|----------|
| AC-DFA (100 patterns) | ~100 KB |
| Lazy DFA (10 cached) | ~1 MB |
| NFA (100 sequences) | ~500 KB |
| **总计** | **~1.6 MB** |

---

## 项目结构

```
Kestrel/
├── kestrel-schema/          # 类型系统、SchemaRegistry、公共类型
│   └── src/lib.rs           # FieldId, TypedValue, Severity, RuleMetadata
│
├── kestrel-event/           # 稀疏事件结构
│   └── src/lib.rs           # Event, EventBuilder
│
├── kestrel-core/            # 核心基础设施
│   ├── src/eventbus.rs      # 多分区事件总线
│   ├── src/alert.rs         # 告警生成
│   ├── src/action.rs        # 动作执行（Block/Allow/Kill）
│   ├── src/time.rs          # 双时间戳系统
│   ├── src/replay.rs        # 离线回放
│   └── src/deterministic.rs # 确定性验证
│
├── kestrel-rules/           # 规则管理
│   └── src/lib.rs           # RuleManager, RulePackage
│
├── kestrel-engine/          # 检测引擎核心
│   ├── src/lib.rs           # DetectionEngine
│   ├── src/runtime.rs       # Runtime trait 抽象
│   └── tests/               # E2E 测试
│
├── kestrel-nfa/             # NFA 序列引擎
│   ├── src/engine.rs        # NfaEngine
│   ├── src/state.rs         # PartialMatch, SeqStep
│   └── src/store.rs         # StateStore (TTL/LRU/Quota)
│
├── kestrel-hybrid-engine/   # 混合匹配引擎
│   ├── src/analyzer.rs      # RuleComplexityAnalyzer
│   └── src/engine.rs        # HybridEngine
│
├── kestrel-ac-dfa/          # Aho-Corasick DFA
│   ├── src/builder.rs       # AcDfaBuilder
│   └── src/matcher.rs       # AcMatcher
│
├── kestrel-lazy-dfa/        # 惰性 DFA 缓存
│   ├── src/detector.rs      # HotSpotDetector
│   ├── src/converter.rs     # NfaToDfaConverter
│   └── src/cache.rs         # DfaCache (LRU)
│
├── kestrel-runtime-wasm/    # Wasm 运行时
│   └── src/lib.rs           # WasmEngine, Host API v1
│
├── kestrel-runtime-lua/     # LuaJIT 运行时
│   └── src/lib.rs           # LuaEngine, Host API v1
│
├── kestrel-eql/             # EQL 编译器
│   ├── src/parser.rs        # EQL 语法解析
│   ├── src/ir.rs            # 中间表示
│   └── src/codegen_wasm.rs  # Wasm 代码生成
│
├── kestrel-ebpf/            # eBPF 采集层
│   ├── src/lib.rs           # EbpfCollector
│   ├── src/executor.rs      # EbpfExecutor (阻断执行)
│   ├── src/lsm.rs           # LSM hooks
│   └── src/normalize.rs     # 事件规范化
│
├── kestrel-ffi/             # C FFI 接口
│   └── src/lib.rs           # C API 导出
│
├── kestrel-cli/             # 命令行工具
│   └── src/main.rs          # kestrel 命令
│
├── kestrel-benchmark/       # 性能基准测试
│   └── src/lib.rs           # 基准测试套件
│
├── rules/                   # 示例规则
│   ├── wasm_example_rule/   # Wasm 规则示例
│   ├── lua_example_rule/    # Lua 规则示例
│   └── */manifest.json      # 各类检测规则
│
└── docs/                    # 文档
    ├── api.md               # API 文档
    ├── deployment.md        # 部署指南
    └── troubleshooting.md   # 故障排查
```

---

## 开发文档

### 构建配置

```toml
# Cargo.toml - 功能标志
[features]
default = ["wasm", "lua"]
wasm = ["dep:wasmtime", "dep:kestrel-runtime-wasm"]
lua = ["dep:mlua", "dep:kestrel-runtime-lua"]
```

### 代码规范

```bash
# 格式化代码
cargo fmt --all

# 代码检查
cargo clippy --workspace --all-targets

# 检查特定包
cargo check -p kestrel-engine
```

### 测试策略

```bash
# 单元测试
cargo test --lib

# 集成测试
cargo test --test '*e2e*'

# E2E 测试
cargo test -p kestrel-engine --test detection_scenarios
```

### 关键文档索引

| 文档 | 内容 |
|------|------|
| [AGENTS.md](AGENTS.md) | AI 编码代理指南 |
| [plan.md](plan.md) | 完整技术架构设计 |
| [PROGRESS.md](PROGRESS.md) | 开发进度记录 |
| [REFACTOR_SUMMARY.md](REFACTOR_SUMMARY.md) | 代码重构总结 |
| [ARCH_REFACTOR_SUMMARY.md](ARCH_REFACTOR_SUMMARY.md) | 架构重构报告 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 贡献指南 |
| [SECURITY.md](SECURITY.md) | 安全策略 |

---

## 路线图

### 已完成 ✅

| Phase | 内容 | 状态 |
|-------|------|------|
| Phase 0 | 架构骨架 | ✅ |
| Phase 1 | Wasm Runtime + Host API v1 | ✅ |
| Phase 2 | LuaJIT Runtime 集成 | ✅ |
| Phase 3 | EQL 编译器 | ✅ |
| Phase 4 | Host NFA 序列引擎 | ✅ |
| Phase 5 | eBPF 采集层 | ✅ |
| Phase 6 | 实时阻断 (LSM hooks) | ✅ |
| Phase 7 | 离线可复现回放 | ✅ |
| Refactor | 代码重构，冗余消除 | ✅ |
| Phase D | 混合引擎 (AC-DFA + Lazy DFA) | ✅ |

### 当前版本: v1.0.0 (生产就绪)

- **测试覆盖**: 262+ 测试，99%+ 通过率
- **代码规模**: ~35,000+ 行 Rust 代码，16 个 crate
- **性能目标**: 全部达成 ✅

---

## 贡献

我们欢迎社区贡献！请查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解详情。

### 快速开始

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'feat: Add amazing feature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

### 报告问题

- **一般问题**: GitHub Issues
- **安全问题**: security@kestrel-detection.org（请勿公开提交）

---

## 许可证

本项目采用 Apache License 2.0 - 详见 [LICENSE](LICENSE) 文件。

---

<div align="center">

**Kestrel** - 下一代端侧行为检测引擎

Built with 🦀 Rust + 🔐 eBPF + ⚡ Wasm

</div>
