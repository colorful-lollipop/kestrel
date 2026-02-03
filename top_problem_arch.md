# Kestrel 项目架构设计问题深度分析

> **分析范围**: 18个crate的整体架构设计、模块划分、数据流、依赖关系、设计模式
> 
> **分析深度**: 架构层、流程层、设计模式层（超越代码细节）
> 
> **分析日期**: 2026-02-03

---

## 架构总览与分层问题

### 当前架构分层

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Platform Layer                                │
│  kestrel-ebpf (eBPF收集)  │  kestrel-ffi (FFI)  │  kestrel-cli    │
├─────────────────────────────────────────────────────────────────────┤
│                        Runtime Layer                                 │
│  kestrel-runtime-wasm  │  kestrel-runtime-lua  │  kestrel-eql     │
├─────────────────────────────────────────────────────────────────────┤
│                        Engine Layer                                  │
│           kestrel-engine (检测引擎)  │  kestrel-nfa (NFA引擎)       │
├─────────────────────────────────────────────────────────────────────┤
│                        Core Layer                                    │
│  kestrel-core (EventBus, Alert, Action)  │  kestrel-rules           │
├─────────────────────────────────────────────────────────────────────┤
│                      Foundation Layer                                │
│         kestrel-schema (类型系统)  │  kestrel-event (事件结构)      │
└─────────────────────────────────────────────────────────────────────┘
```

### 问题 1: 层间依赖方向错误（架构核心问题）

**严重程度**: 🔴 Critical

#### 问题描述

架构的分层意图良好，但实际代码中存在大量**逆向依赖**，导致：

1. **Engine层依赖Runtime实现细节**
   - `DetectionEngine` 直接导入 `kestrel_runtime_wasm::WasmEngine`
   - 这应该是通过 trait abstraction 隐藏的实现细节

2. **Core层包含Engine概念**
   - `kestrel-core` 定义了 `ActionType::Block`、`ActionType::Kill`
   - 这些是业务策略，不应该属于核心服务层

3. **Platform层泄露到Engine层**
   - eBPF的事件类型定义在 `kestrel-ebpf` 但被Engine直接使用

#### 问题代码示例

```rust
// kestrel-engine/src/lib.rs:22-23
// ❌ Engine层不应该直接依赖Runtime实现
#[cfg(feature = "wasm")]
use kestrel_runtime_wasm::{WasmConfig, WasmEngine};

// kestrel-core/src/action.rs:17-27
// ❌ Core层定义了业务策略
pub enum ActionType {
    Block,      // 业务策略
    Allow,      // 业务策略
    Kill,       // 业务策略 - 不应该在这里
    Quarantine, // 业务策略 - 不应该在这里
    Alert,      // 业务策略 - 不应该在这里
}
```

#### 影响

1. **测试困难**: Engine测试必须包含完整的Wasm运行时
2. **扩展困难**: 无法在不修改Engine的情况下添加新的运行时
3. **耦合严重**: 任何Runtime的变更都可能影响Engine
4. **违反依赖倒置**: 高层模块应该依赖抽象，而不是实现

#### 架构重构建议

```
// 正确的依赖方向

┌─────────────────────────────────────────────────────┐
│                    Engine Layer                      │
│                                                    │
│  DetectionEngine                                    │
│    ├── trait Runtime: Send + Sync                   │  ← 抽象
│    │   ├── fn eval(&self, rule, event)              │
│    │   └── fn compile(&self, rule)                  │
│    ├── trait PredicateEvaluator: Send + Sync        │  ← 抽象
│    │   ├── fn evaluate(&self, predicate, event)     │
│    │   └── fn get_required_fields(&self, predicate) │
│                                                    │
└─────────────────────────────────────────────────────┘
                          ↑
                          │ 依赖抽象
                          │
┌─────────────────────────────────────────────────────┐
│                   Runtime Layer                      │
│                                                    │
│  struct WasmRuntime impl Runtime                    │  ← 实现
│  struct LuaRuntime impl Runtime                     │  ← 实现
│                                                    │
└─────────────────────────────────────────────────────┘
```

---

## 问题 2: EventBus 设计的架构缺陷

**严重程度**: 🟠 High

### 问题描述

EventBus 是系统的核心消息总线，但其设计存在几个关键问题：

#### 2.1 分区设计不完整

```rust
// kestrel-core/src/eventbus.rs:56-62
fn get_partition(&self, event: &Event) -> usize {
    if self.partition_count == 1 {
        return 0;
    }
    let key = event.entity_key;
    (key % self.partition_count as u128) as usize  // ❌ 简单取模
}
```

**问题**:
- 仅使用 `entity_key` 的低 bits 进行分区
- 没有考虑 `event_type` 作为二级分区键
- 分区策略固定，无法动态调整
- 没有分区再平衡机制

#### 2.2 消费者模型不清晰

```rust
// kestrel-core/src/eventbus.rs:223-238
pub fn subscribe(&self) -> mpsc::Receiver<Vec<Event>> {
    let (tx, rx) = mpsc::channel(100);
    if let Some(subscriber_tx) = &self.subscriber_tx {
        // ... 已废弃的逻辑
    }
    rx
}
```

**问题**:
- `subscribe()` 方法返回 `Receiver`，但生产者（EventBus）如何知道有新的消费者？
- 只有一个 `subscriber_tx`，这意味着只能有一个消费者
- 多消费者场景没有设计

#### 2.3 Backpressure 策略不一致

```rust
// 三种publish方法，策略不同
pub async fn publish(&self, event: Event) -> Result<(), PublishError> { ... }
pub async fn publish_with_backpressure(&self, event: Event) -> Result<(), PublishError> { ... }
pub fn try_publish(&self, event: Event) -> Result<(), PublishError> { ... }
```

**问题**:
- 同一接口有三种语义，消费者无法预知会使用哪种
- `PublishError::Closed` 和 `PublishError::Full` 含义模糊
- 消费者无法区分"队列满"和"生产者关闭"

#### 2.4 批量处理设计问题

```rust
// kestrel-core/src/eventbus.rs:264
tokio::select! {
    result = receiver.recv_many(&mut batch, batch_size) => {
        // 批量大小固定，没有动态调整
```

**问题**:
- 批量大小固定，无法根据负载动态调整
- 没有批处理延迟配置（是否应该等待更多事件？）
- 批处理失败后的事件丢失没有处理

### 影响

1. **吞吐量瓶颈**: 简单取模分区可能导致热点
2. **扩展性差**: 无法增加分区而不重启
3. **消费者饥饿**: 一个慢消费者可能拖慢整个分区
4. **一致性风险**: 批量处理可能在故障时丢失事件

### 架构重构建议

```rust
// 新的EventBus设计

pub trait EventBus: Send + Sync {
    /// 发布单个事件
    async fn publish(&self, event: Event) -> Result<(), PublishError>;
    
    /// 订阅事件流
    fn subscribe(&self, config: SubscriptionConfig) -> Box<dyn EventSubscription>;
    
    /// 获取分区数量
    fn partition_count(&self) -> usize;
    
    /// 添加分区（动态扩展）
    async fn add_partition(&self) -> Result<(), Error>;
}

pub struct SubscriptionConfig {
    /// 消费哪些分区
    pub partitions: Option<Vec<usize>>,
    
    /// 消费哪些事件类型
    pub event_types: Option<Vec<EventTypeId>>,
    
    /// 消费者组ID（用于负载均衡）
    pub consumer_group: String,
    
    /// 批处理配置
    pub batch_config: BatchConfig,
}

pub enum BackpressureStrategy {
    Drop,           // 丢弃新事件
    Block,          // 阻塞生产者
    FailFast,       // 立即返回错误
    ShedLoad,       // 负载 shed
}
```

---

## 问题 3: NFA 引擎的状态管理架构问题

**严重程度**: 🟠 High

### 问题描述

NFA引擎负责序列检测，其状态管理架构存在几个关键问题：

#### 3.1 状态存储使用 `RwLock` 保护可变状态

```rust
// kestrel-nfa/src/engine.rs:64-85
pub struct NfaEngine {
    sequences: AHashMap<String, NfaSequence>,
    event_type_index: HashMap<u16, Vec<String>>,
    predicate_evaluator: Arc<dyn PredicateEvaluator>,
    state_store: StateStore,
    metrics: Arc<RwLock<NfaMetrics>>,
    config: NfaEngineConfig,
    budget_tracker: RwLock<AHashMap<String, (u64, u64, u64)>>,
}
```

**问题**:
- `process_event` 需要 `&mut self`（因为要修改 `budget_tracker`）
- 这意味着 NFAEngine 不是 `Sync` 的，无法在多线程间共享
- 每次调用都要获取锁，性能开销大

#### 3.2 事件类型索引设计

```rust
// kestrel-nfa/src/engine.rs:69
event_type_index: HashMap<u16, Vec<String>>,  // ❌ 每个事件可能有多个序列
```

**问题**:
- 使用 `Vec<String>` 存储序列ID，而不是直接存储序列引用
- 每次处理事件都要克隆这个Vec
- 没有考虑使用更高效的数据结构（如 `Vec<Arc<Sequence>>`）

#### 3.3 预算追踪的时间基准

```rust
// kestrel-nfa/src/engine.rs:156
let now_ns = std::time::Instant::now().elapsed().as_nanos() as u64;
let window_ns = 1_000_000_000;
```

**问题**:
- 使用 `Instant::now()`，这是单调时钟，不是事件时间
- 预算应该在事件时间窗口内追踪，而不是挂钟时间
- 如果引擎重启，预算追踪会重置（可能有问题，也可能没问题）

#### 3.4 状态存储的锁竞争

```rust
// kestrel-nfa/src/engine.rs:253-278
ALERTS_BUF.with(|buf| {
    let mut alerts = buf.borrow_mut();
    alerts.clear();
    
    for seq_id in &relevant_sequence_ids {
        // 每个序列都要获取metrics锁
        if let Some(seq_metrics) = self.metrics.read().get_sequence_metrics_arc(seq_id) {
            seq_metrics.record_event_relaxed();
        }
        
        // 每个序列都要克隆
        if let Some(seq) = self.sequences.get(seq_id).cloned() {  // ❌ clone
            // ...
        }
    }
});
```

**问题**:
- 循环内多次获取锁
- `self.sequences.get(seq_id).cloned()` 会克隆整个序列
- 线程局部缓冲区只在单线程有效

### 影响

1. **性能瓶颈**: 锁竞争严重，无法充分利用多核
2. **内存浪费**: 频繁克隆序列对象
3. **时间语义混乱**: 预算追踪使用挂钟时间，而非事件时间

### 架构重构建议

```rust
// 新的NFA引擎设计

pub struct NfaEngine {
    // 使用Arc共享不可变数据
    sequences: Arc<SequenceStore>,      // 不可变，可共享
    state_store: Arc<StateStore>,       // 内部有锁，外部可共享
    config: Arc<NfaConfig>,
    metrics: Arc<NfaMetrics>,
    
    // 工作器池
    workers: Vec<NfaWorker>,
}

pub struct SequenceStore {
    // 使用索引+Arc避免克隆
    by_id: AHashMap<SequenceId, Arc<NfaSequence>>,
    by_event_type: AHashMap<EventTypeId, Vec<SequenceId>>,
}

pub struct NfaWorker {
    id: usize,
    sequences: Arc<SequenceStore>,
    state: WorkerLocalState,  // 每个工作器本地状态
    metrics: Arc<NfaMetrics>,
}

// Engine可以安全地在多线程间共享
impl<N: NfaEngine + Sync> Sync for N {}
```

---

## 问题 4: 运行时抽象的架构缺失

**严重程度**: 🟠 High

### 问题描述

系统支持 Wasm 和 Lua 两种运行时，但没有统一的架构抽象：

#### 4.1 PredicateEvaluator Trait 定义不完整

```rust
// kestrel-nfa/src/lib.rs:51-60
pub trait PredicateEvaluator: Send + Sync {
    fn evaluate(&self, predicate_id: &str, event: &Event) -> NfaResult<bool>;
    fn get_required_fields(&self, predicate_id: &str) -> NfaResult<Vec<u32>>;
    fn has_predicate(&self, predicate_id: &str) -> bool;
}
```

**问题**:
- 没有 `init()` 方法来初始化运行时状态
- 没有 `cleanup()` 方法来释放资源
- 没有配置接口
- 错误处理不统一

#### 4.2 Wasm 和 Lua 运行时并行存在但架构不统一

```rust
// kestrel-runtime-wasm/src/lib.rs:102-114
pub struct WasmEngine {
    pub engine: Engine,
    pub linker: Linker<WasmContext>,
    pub config: WasmConfig,
    pub schema: Arc<SchemaRegistry>,
    pub modules: Arc<RwLock<HashMap<String, CompiledModule>>>,
    pub instance_pool: Arc<RwLock<HashMap<String, InstancePool>>>,
    pub regex_cache: Arc<RwLock<HashMap<RegexId, regex::Regex>>>,
    pub glob_cache: Arc<RwLock<HashMap<GlobId, glob::Pattern>>>,
    // ...
}

// kestrel-runtime-lua/src/lib.rs (类似的结构)
```

**问题**:
- 两个引擎有类似的结构（modules, instance_pool, regex_cache, glob_cache）
- 但没有共享的 trait 或 trait object
- 无法在运行时动态切换运行时

#### 4.3 运行时配置不统一

```rust
// Wasm配置
pub struct WasmConfig {
    pub max_memory_mb: usize,
    pub max_execution_time_ms: u64,
    pub pool_size: usize,
    pub enable_fuel: bool,
    pub fuel_per_eval: u64,
}

// Lua配置 (如果有的话) - 可能完全不同
```

**问题**:
- 两个运行时的配置项不同，无法统一配置界面
- 没有运行时能力探测（运行时是否支持某功能）
- 没有优雅降级策略

### 影响

1. **扩展困难**: 添加新的运行时（如 JS）需要大量修改
2. **配置复杂**: 每个运行时有不同的配置方式
3. **测试复杂**: 无法用 Mock Runtime 进行测试

### 架构重构建议

```rust
// 统一运行时抽象

pub trait Runtime: Send + Sync {
    type Config: RuntimeConfig;
    type Error: std::error::Error;
    
    /// 创建运行时实例
    fn new(config: Self::Config, schema: Arc<SchemaRegistry>) -> Result<Self, Self::Error>;
    
    /// 初始化运行时（加载规则等）
    async fn init(&mut self) -> Result<(), Self::Error>;
    
    /// 编译规则
    async fn compile_rule(&self, rule_id: &str, rule: &Rule) 
        -> Result<CompiledPredicate, Self::Error>;
    
    /// 评估谓词
    async fn evaluate(&self, predicate: &CompiledPredicate, event: &Event) 
        -> Result<bool, Self::Error>;
    
    /// 获取所需的字段
    fn required_fields(&self, predicate: &CompiledPredicate) -> Vec<FieldId>;
    
    /// 清理资源
    async fn cleanup(&mut self) -> Result<(), Self::Error>;
}

pub trait RuntimeConfig: Default + Clone {
    /// 验证配置
    fn validate(&self) -> Result<(), ConfigError>;
    
    /// 获取默认资源配置
    fn default_resource_limits(&self) -> ResourceLimits;
}

// 使用方式
let runtime: Box<dyn Runtime> = match config.runtime_type {
    RuntimeType::Wasm => Box::new(WasmRuntime::new(wasm_config, schema)?),
    RuntimeType::Lua => Box::new(LuaRuntime::new(lua_config, schema)?),
};
```

---

## 问题 5: 规则生命周期的架构问题

**严重程度**: 🟡 Medium

### 问题描述

规则管理存在几个架构问题：

#### 5.1 规则定义分散

```rust
// kestrel-rules/src/lib.rs:86-92
pub struct Rule {
    pub metadata: RuleMetadata,
    pub definition: RuleDefinition,
    pub enabled: bool,
}

pub enum RuleDefinition {
    Eql(String),
    Wasm(Vec<u8>),
    Lua(String),
}
```

**问题**:
- `RuleDefinition` 包含了所有可能的规则类型
- 任何新的规则类型都需要修改这个 enum
- 违反了开闭原则

#### 5.2 规则编译耦合在 Engine 中

```rust
// kestrel-engine/src/lib.rs:276
pub async fn compile_single_event_rule(&self, rule: &Rule) -> Result<(), EngineError> {
    // EQL编译逻辑在这里
    // Wasm编译逻辑在这里
    // Lua编译逻辑在这里
}
```

**问题**:
- Engine 承担了规则编译的职责
- 规则编译应该由 RuleManager 或专门的 Compiler 处理
- Engine 应该只负责执行，不应该知道规则如何编译

#### 5.3 规则热重载设计缺失

```rust
// kestrel-rules/src/lib.rs:21-25
pub struct RuleManagerConfig {
    pub rules_dir: PathBuf,
    pub watch_enabled: bool,  // 只有开关，没有策略
    pub max_concurrent_loads: usize,
}
```

**问题**:
- `watch_enabled` 只是一个开关
- 没有规则版本管理
- 没有规则更新策略（原子更新、渐进式更新）
- 没有规则回滚机制

### 影响

1. **维护困难**: 规则类型增加需要修改多处代码
2. **更新风险**: 热重载可能造成规则状态不一致
3. **无法回滚**: 更新失败后没有回滚机制

### 架构重构建议

```rust
// 规则架构重构

// 1. 规则类型使用 trait
pub trait RuleDefinition: Send + Sync {
    fn rule_type(&self) -> RuleType;
    fn metadata(&self) -> &RuleMetadata;
    fn validate(&self, schema: &SchemaRegistry) -> Result<(), ValidationError>;
    fn compile(&self, compiler: &dyn RuleCompiler) -> Result<CompiledRule, CompilationError>;
}

// 2. 规则编译器 trait
pub trait RuleCompiler: Send + Sync {
    fn compile_event_rule(&self, rule: &EventRuleDefinition) -> Result<CompiledEventRule, Error>;
    fn compile_sequence_rule(&self, rule: &SequenceRuleDefinition) -> Result<CompiledSequenceRule, Error>;
}

// 3. 规则生命周期管理
pub struct RuleLifecycleManager {
    store: Arc<RuleStore>,
    compiler: Arc<dyn RuleCompiler>,
    validator: Arc<dyn RuleValidator>,
    change_notifier: Arc<ChangeNotifier>,
    
    // 版本管理
    versions: AHashMap<RuleId, RuleVersion>,
    
    // 更新策略
    update_strategy: UpdateStrategy,
}

pub enum UpdateStrategy {
    Atomic,      // 原子更新
    Gradual,     // 渐进式更新
    Canaries,    // 金丝雀发布
}
```

---

## 问题 6: 平台层与引擎层的耦合问题

**严重程度**: 🟡 Medium

### 问题描述

#### 6.1 eBPF 事件类型硬编码

```rust
// kestrel-ebpf/src/lib.rs:31-40
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EbpfEventType {
    ProcessExec,
    ProcessExit,
    FileOpen,
    FileRename,
    FileUnlink,
    NetworkConnect,
    NetworkSend,
}
```

**问题**:
- eBPF 收集的事件类型是固定的
- 引擎需要知道这些具体的类型才能处理
- 没有事件类型的注册机制

#### 6.2 事件归一化职责不清

```rust
// kestrel-ebpf/src/lib.rs:213
let normalizer = normalize::EventNormalizer::new(schema);
```

**问题**:
- EventNormalizer 在 eBPF collector 中
- 但其他事件源（replay, test）也需要归一化
- 归一化逻辑被绑定在 eBPF collector 上

#### 6.3 平台能力探测缺失

```rust
// eBPF收集器启动时
pub async fn load(&mut self) -> Result<(), EbpfError> {
    let mut programs = ProgramManager::new(self.ebpf.clone());
    programs.attach_process_programs()?;  // 如果不支持呢？
    programs.attach_file_programs()?;
    programs.attach_network_programs()?;
    // ...
}
```

**问题**:
- 没有检测平台是否支持特定的eBPF程序类型
- 直接尝试attach，失败才处理
- 缺乏优雅降级

### 影响

1. **可移植性差**: 难以支持其他平台（macOS, Windows）
2. **缺乏灵活性**: 事件类型固定，无法动态扩展
3. **鲁棒性差**: 平台不支持时直接失败

---

## 问题 7: 错误处理架构不统一

**严重程度**: 🟡 Medium

### 问题描述

#### 7.1 错误类型混用

```rust
// 不同模块使用不同的错误库
use thiserror::Error;           // kestrel-schema, kestrel-nfa
use anyhow::Result;             // kestrel-rules
use Result<_, String>           // 一些地方用简单类型
```

**问题**:
- 没有统一的错误类型
- `thiserror` 和 `anyhow` 混用
- 错误传播路径不清晰

#### 7.2 错误处理策略不明确

```rust
// kestrel-engine/src/lib.rs:447-488
if let Some(ref mut nfa_engine) = self.nfa_engine {
    match nfa_engine.process_event(event) {
        Ok(sequence_alerts) => { /* ... */ }
        Err(e) => {
            error!(error = %e, "NFA engine error");
            // ❌ 错误被吞掉，调用者不知道
        }
    }
}
```

**问题**:
- NFA错误只记录日志，不返回给调用者
- Engine 无法区分"没有告警"和"处理出错"
- 告警可能丢失而不自知

#### 7.3 缺乏错误边界

```rust
// 整个eval_event没有错误边界
pub async fn eval_event(&mut self, event: &Event) -> Result<Vec<Alert>, EngineError> {
    // NFA错误 → 被吞掉
    // Wasm运行时错误 → 返回错误
    // 单事件规则错误 → ?
}
```

**问题**:
- 不同组件的错误处理策略不一致
- 没有统一的错误分类
- 难以实现告警抑制或降级

### 影响

1. **调试困难**: 错误信息不完整
2. **可靠性差**: 错误可能导致静默失败
3. **运维困难**: 难以监控引擎健康状态

---

## 问题 8: 性能架构问题

**严重程度**: 🟡 Medium

### 问题描述

#### 8.1 内存分配策略

```rust
// 每次处理事件都分配新的Vec
let mut alerts = Vec::new();

// 每次克隆序列
if let Some(seq) = self.sequences.get(seq_id).cloned() {
```

**问题**:
- 没有对象池
- 没有预分配
- 频繁的堆分配

#### 8.2 锁的粒度问题

```rust
// 多层锁
pub struct NfaEngine {
    sequences: AHashMap<String, NfaSequence>,    // 无锁
    event_type_index: HashMap<u16, Vec<String>>,  // 无锁
    predicate_evaluator: Arc<dyn PredicateEvaluator>,  // 无锁
    state_store: StateStore,                       // 内部有锁
    metrics: Arc<RwLock<NfaMetrics>>,              // RwLock
    config: NfaEngineConfig,                       // 无锁
    budget_tracker: RwLock<AHashMap<String, (u64, u64, u64)>>,  // RwLock
}
```

**问题**:
- `budget_tracker` 使用 `RwLock`，但更新频繁
- 多个组件各自有锁，锁的顺序可能造成死锁
- 没有使用 lock-free 数据结构

#### 8.3 序列化开销

```rust
// 事件→JSON→告警
let context = serde_json::json!({
    "sequence_id": seq_alert.sequence_id,
    "entity_key": seq_alert.entity_key,
    "captures": seq_alert.captures,
});
```

**问题**:
- 大量使用 `serde_json`
- 事件在发送过程中被序列化
- 没有考虑 binary format

### 影响

1. **吞吐量受限**: 内存分配和锁竞争是瓶颈
2. **延迟增加**: 序列化开销大
3. **资源利用低**: 没有充分利用现代CPU

---

## 问题 9: 可观测性架构缺失

**严重程度**: 🟡 Medium

### 问题描述

#### 9.1 指标系统分散

```rust
// 每个模块都有自己的metrics
pub struct EventBusMetrics { ... }
pub struct NfaMetrics { ... }
pub struct PoolMetrics { ... }
```

**问题**:
- 没有统一的指标接口
- 指标格式不统一
- 难以聚合和展示

#### 9.2 追踪（Tracing）不完整

```rust
#[tracing::instrument(skip(self, event), fields(event_id = %event.ts_mono_ns, event_type_id = event.event_type_id))]
pub async fn eval_event(&mut self, event: &Event) -> Result<Vec<Alert>, EngineError> {
```

**问题**:
- 只有部分关键路径有 tracing
- span 的层级关系不清晰
- 没有结构化的追踪输出

#### 9.3 健康检查缺失

```rust
// 没有健康检查接口
pub struct DetectionEngine {
    // ...
}
```

**问题**:
- 无法判断引擎是否健康
- 无法获取引擎内部状态
- 无法进行主动探测

### 影响

1. **可观测性差**: 难以了解系统运行状态
2. **调试困难**: 问题定位需要大量日志分析
3. **运维困难**: 无法自动化健康检查

---

## 问题 10: 扩展性架构设计缺失

**严重程度**: 🟡 Medium

### 问题描述

#### 10.1 插件系统缺失

```rust
// 当前：所有功能都是内置的
pub struct DetectionEngine {
    // 只有内置的运行时
    #[cfg(feature = "wasm")]
    wasm_engine: Option<Arc<WasmEngine>>,
    // 没有插件槽位
}
```

**问题**:
- 无法动态添加新的事件源
- 无法动态添加新的动作类型
- 无法动态添加新的检测引擎

#### 10.2 分布式支持缺失

```rust
// 当前：单节点设计
pub struct DetectionEngine {
    // 所有状态都在本地
    nfa_engine: Option<NfaEngine>,
    single_event_rules: Arc<tokio::sync::RwLock<Vec<SingleEventRule>>>,
}
```

**问题**:
- 状态无法跨节点共享
- 无法水平扩展
- 无法进行分布式检测

#### 10.3 配置动态更新缺失

```rust
// 当前：配置在创建时固定
pub struct DetectionEngine {
    config: EngineConfig,  // 不可变
}
```

**问题**:
- 无法动态调整配置
- 配置更新需要重启
- 无法实现 A/B 测试

### 影响

1. **扩展性差**: 难以添加新功能
2. **无法规模化**: 只能单节点运行
3. **运维不灵活**: 配置更新需要重启

---

## 架构问题总结与优先级

### 问题严重程度汇总

| 优先级 | 问题 | 分类 | 影响范围 |
|-------|------|------|---------|
| P0 | 层间依赖方向错误 | 架构设计 | 整个系统 |
| P1 | EventBus 设计缺陷 | 架构设计 | 事件流 |
| P2 | NFA 状态管理问题 | 架构设计 | 检测性能 |
| P3 | 运行时抽象缺失 | 架构设计 | 扩展性 |
| P4 | 规则生命周期问题 | 架构设计 | 可维护性 |
| P5 | 平台层耦合 | 架构设计 | 可移植性 |
| P6 | 错误处理不统一 | 架构设计 | 可靠性 |
| P7 | 性能架构问题 | 架构设计 | 性能 |
| P8 | 可观测性缺失 | 架构设计 | 运维 |
| P9 | 扩展性缺失 | 架构设计 | 长期发展 |

### 建议重构路线图

```
Phase 1 (2-4周): 架构基础重构
├── 统一运行时抽象 (Runtime trait)
├── 修复EventBus分区和backpressure
├── 统一错误处理 (统一Error类型)
└── 分离Engine层和Runtime层

Phase 2 (4-8周): 核心架构改进
├── NFA引擎无锁化重构
├── 规则生命周期管理重构
├── 引入对象池和预分配
└── 统一可观测性接口

Phase 3 (8-12周): 扩展性增强
├── 插件系统设计
├── 分布式状态管理
├── 动态配置更新
└── 多平台抽象层
```

---

## 附录：架构决策记录

### AD-001: 事件分区策略

| 项目 | 内容 |
|-----|------|
| 决策 | 使用 entity_key 取模进行分区 |
| 状态 | 已实现，但有缺陷 |
| 问题 | 热点问题，无法动态调整 |
| 建议 | 改为一致性哈希，支持动态分区 |

### AD-002: 运行时选择

| 项目 | 内容 |
|-----|------|
| 决策 | 使用 feature flag 选择运行时 |
| 状态 | 已实现 |
| 问题 | 运行时在编译时固定，无法运行时切换 |
| 建议 | 引入 trait object，支持运行时选择 |

### AD-003: 规则编译位置

| 项目 | 内容 |
|-----|------|
| 决策 | 在 Engine 中编译规则 |
| 状态 | 已实现 |
| 问题 | 职责不清，耦合严重 |
| 建议 | 移入 RuleManager 或独立的 Compiler |

### AD-004: 错误处理策略

| 项目 | 内容 |
|-----|------|
| 决策 | 各模块自行定义错误类型 |
| 状态 | 已实现 |
| 问题 | 不一致，难以调试 |
| 建议 | 统一使用 thiserror，定义统一的 Error trait |
---

# 问题 5: 规则生命周期架构问题 - 详细设计规划

## 5.1 现状分析

### 当前架构问题

| 问题 | 描述 | 影响 |
|------|------|------|
| **RuleDefinition是enum** | 添加新规则类型需修改enum和所有匹配分支 | 违反开闭原则 |
| **编译职责耦合** | Engine负责EQL→Wasm编译，职责不清 | 测试困难，维护困难 |
| **热重载缺失** | 只有watch开关，无版本管理、原子更新、回滚 | 更新风险高 |
| **状态管理缺失** | 规则更新时已匹配的序列状态如何处理？ | 状态不一致 |

## 5.2 详细设计方案

### 5.2.1 规则定义重构 (RuleDefinition Trait)

```rust
// 文件: kestrel-rules/src/definition.rs

/// 规则类型标识
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RuleType {
    Event { event_type: String },
    Sequence { sequence_id: String },
    Custom(&'static str),  // 插件规则类型
}

/// 规则定义 trait - 所有规则类型必须实现
pub trait RuleDefinition: Send + Sync + 'static {
    fn rule_type(&self) -> RuleType;
    fn metadata(&self) -> &RuleMetadata;
    fn validate(&self, schema: &SchemaRegistry) -> Result<(), ValidationError>;
    fn required_fields(&self) -> Vec<FieldId>;
    fn entity_grouping(&self) -> EntityGrouping;
    fn max_time_window_ns(&self) -> Option<u64>;
}

/// 实体分组策略
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityGrouping {
    None,
    ByField(FieldId),
    ByProcess,
    BySession,
    ByUser,
}

/// 验证错误
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Field not found in schema: {field}")]
    FieldNotFound { field: String },
    #[error("Type mismatch for field {field}: expected {expected}, got {actual}")]
    TypeMismatch { field: String, expected: String, actual: String },
    #[error("Invalid predicate: {reason}")]
    InvalidPredicate { reason: String },
    #[error("Missing required field: {field}")]
    MissingRequiredField { field: String },
    #[error("Rule validation failed: {reason}")]
    Generic { reason: String },
}

// EQL 规则定义
#[derive(Debug, Clone)]
pub struct EqlRuleDefinition {
    pub metadata: RuleMetadata,
    pub eql: String,
    pub parsed_ast: Option<ast::RuleNode>,
}

impl RuleDefinition for EqlRuleDefinition {
    fn rule_type(&self) -> RuleType {
        self.parsed_ast
            .as_ref()
            .map(|ast| ast.rule_type())
            .unwrap_or(RuleType::Event { event_type: "unknown".to_string() })
    }
    
    fn metadata(&self) -> &RuleMetadata { &self.metadata }
    
    fn validate(&self, schema: &SchemaRegistry) -> Result<(), ValidationError> {
        let ast = parser::parse_rule(&self.eql)
            .map_err(|e| ValidationError::Generic { reason: e })?;
        for field in ast.required_fields() {
            if schema.get_field_id(&field).is_none() {
                return Err(ValidationError::FieldNotFound { field });
            }
        }
        self.parsed_ast.replace(ast);
        Ok(())
    }
    
    fn required_fields(&self) -> Vec<FieldId> {
        self.parsed_ast.as_ref().map(|a| a.required_fields()).unwrap_or_default()
    }
    
    fn entity_grouping(&self) -> EntityGrouping {
        self.parsed_ast.as_ref().map(|a| a.entity_grouping()).unwrap_or(EntityGrouping::ByProcess)
    }
    
    fn max_time_window_ns(&self) -> Option<u64> {
        self.parsed_ast.as_ref().and_then(|a| a.max_time_window())
    }
}

// Wasm 规则定义
#[derive(Debug, Clone)]
pub struct WasmRuleDefinition {
    pub metadata: RuleMetadata,
    pub wasm_bytes: Vec<u8>,
    pub required_fields: Vec<FieldId>,
    pub entity_grouping: EntityGrouping,
    pub max_window_ns: Option<u64>,
}

impl RuleDefinition for WasmRuleDefinition {
    fn rule_type(&self) -> RuleType {
        RuleType::Event { event_type: "wasm".to_string() }
    }
    
    fn metadata(&self) -> &RuleMetadata { &self.metadata }
    
    fn validate(&self, _schema: &SchemaRegistry) -> Result<(), ValidationError> {
        if self.wasm_bytes.len() < 8 {
            return Err(ValidationError::Generic { reason: "Invalid Wasm bytecode: too short".to_string() });
        }
        if &self.wasm_bytes[0..4] != b"\0asm" {
            return Err(ValidationError::Generic { reason: "Invalid Wasm magic number".to_string() });
        }
        Ok(())
    }
    
    fn required_fields(&self) -> Vec<FieldId> { self.required_fields.clone() }
    fn entity_grouping(&self) -> EntityGrouping { self.entity_grouping }
    fn max_time_window_ns(&self) -> Option<u64> { self.max_window_ns }
}
```

### 5.2.2 规则编译架构 (RuleCompiler Trait)

```rust
// 文件: kestrel-rules/src/compiler.rs

pub trait RuleCompiler: Send + Sync + 'static {
    fn compile_event_rule(&self, rule: &dyn RuleDefinition) -> Result<CompiledEventRule, CompilationError>;
    fn compile_sequence_rule(&self, rule: &dyn RuleDefinition) -> Result<CompiledSequenceRule, CompilationError>;
    fn capabilities(&self) -> CompilerCapabilities;
}

#[derive(Debug, Clone, Default)]
pub struct CompilerCapabilities {
    pub supported_rule_types: Vec<&'static str>,
    pub max_predicate_complexity: usize,
    pub supports_regex: bool,
    pub supports_glob: bool,
    pub supports_aggregation: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum CompilationError {
    #[error("Validation failed: {reason}")]
    Validation { reason: String },
    #[error("Codegen failed: {reason}")]
    Codegen { reason: String },
    #[error("Compilation timeout")]
    Timeout,
    #[error("Resource limit exceeded: {limit}")]
    ResourceLimit { limit: String },
}

#[derive(Debug, Clone)]
pub struct CompiledEventRule {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub event_type: EventTypeId,
    pub predicate: CompiledPredicate,
    pub required_fields: Vec<FieldId>,
    pub description: Option<String>,
    pub blockable: bool,
    pub action_type: Option<ActionType>,
}

#[derive(Debug, Clone)]
pub enum CompiledPredicate {
    Wasm { wasm_bytes: Vec<u8>, required_fields: Vec<FieldId> },
    Lua { script: String, required_fields: Vec<FieldId> },
    Native { conditions: Vec<PredicateCondition> },
}

pub struct EqlCompiler {
    schema: Arc<SchemaRegistry>,
    capabilities: CompilerCapabilities,
}

impl EqlCompiler {
    pub fn new(schema: Arc<SchemaRegistry>) -> Self {
        Self {
            schema,
            capabilities: CompilerCapabilities {
                supported_rule_types: vec!["event", "sequence"],
                max_predicate_complexity: 100,
                supports_regex: true,
                supports_glob: true,
                supports_aggregation: false,
            },
        }
    }
}

impl RuleCompiler for EqlCompiler {
    fn compile_event_rule(&self, rule: &dyn RuleDefinition) -> Result<CompiledEventRule, CompilationError> {
        let eql_rule = rule.as_any().downcast_ref::<EqlRuleDefinition>()
            .ok_or_else(|| CompilationError::Validation { reason: "Rule is not an EQL rule".to_string() })?;
        
        let ast = parser::parse_event_rule(&eql_rule.eql)
            .map_err(|e| CompilationError::Codegen { reason: e })?;
        
        let ir = self.compile_to_ir(&ast)?;
        let wasm_bytes = self.compile_to_wasm(&ir)?;
        
        Ok(CompiledEventRule {
            rule_id: eql_rule.metadata.id.clone(),
            rule_name: eql_rule.metadata.name.clone(),
            severity: convert_severity(eql_rule.metadata.severity),
            event_type: self.schema.get_event_type_id(&ast.event_type())
                .ok_or_else(|| CompilationError::Validation { reason: format!("Unknown event type: {}", ast.event_type()) })?,
            predicate: CompiledPredicate::Wasm { wasm_bytes, required_fields: rule.required_fields() },
            required_fields: rule.required_fields(),
            description: eql_rule.metadata.description.clone(),
            blockable: false,
            action_type: None,
        })
    }
    
    fn compile_sequence_rule(&self, rule: &dyn RuleDefinition) -> Result<CompiledSequenceRule, CompilationError> {
        todo!()
    }
    
    fn capabilities(&self) -> CompilerCapabilities { self.capabilities.clone() }
}
```

### 5.2.3 规则生命周期管理 (RuleLifecycleManager)

```rust
// 文件: kestrel-rules/src/lifecycle.rs

pub struct RuleLifecycleManager {
    store: Arc<RuleStore>,
    compiler: Arc<dyn RuleCompiler>,
    validator: Arc<dyn RuleValidator>,
    change_notifier: Arc<ChangeNotifier>,
    versions: Arc<RwLock<AHashMap<RuleId, RuleVersion>>>,
    update_strategy: UpdateStrategy,
    pending_activation: Arc<RwLock<HashSet<RuleId>>>,
}

struct RuleStore {
    definitions: Arc<RwLock<AHashMap<RuleId, Arc<dyn RuleDefinition>>>>,
    compiled: Arc<RwLock<AHashMap<RuleId, CompiledRule>>>,
    enabled: Arc<RwLock<AHashMap<RuleId, bool>>>,
}

#[derive(Debug, Clone)]
pub struct RuleVersion {
    pub version: u64,
    pub content_hash: [u8; 32],
    pub created_at: TimestampMono,
    pub created_by: String,
    pub description: String,
    pub status: VersionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionStatus {
    Active,
    Pending,
    Deprecated,
    Archived,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateStrategy {
    Atomic,
    Gradual { canary_ratio: f64, observation_window_ms: u64 },
    Canary { canary_count: usize, error_rate_threshold: f64 },
}

impl RuleLifecycleManager {
    pub fn new(
        store: Arc<RuleStore>,
        compiler: Arc<dyn RuleCompiler>,
        validator: Arc<dyn RuleValidator>,
        change_notifier: Arc<ChangeNotifier>,
        config: LifecycleConfig,
    ) -> Self {
        Self {
            store,
            compiler,
            validator,
            change_notifier,
            versions: Arc::new(RwLock::new(AHashMap::new())),
            update_strategy: config.update_strategy,
            pending_activation: Arc::new(RwLock::new(HashSet::new())),
        }
    }
    
    pub async fn add_rule(&self, rule: Arc<dyn RuleDefinition>) -> Result<RuleId, LifecycleError> {
        let rule_id = rule.metadata().id.clone();
        
        self.validator.validate(&rule).await
            .map_err(LifecycleError::ValidationFailed)?;
        
        let content_hash = self.compute_hash(&rule);
        
        let version = RuleVersion {
            version: 1,
            content_hash,
            created_at: now_mono_ns(),
            created_by: "system".to_string(),
            description: format!("Initial version of rule {}", rule_id),
            status: VersionStatus::Pending,
        };
        
        {
            let mut definitions = self.store.definitions.write().await;
            definitions.insert(rule_id.clone(), rule);
        }
        
        {
            let mut versions = self.versions.write();
            versions.insert(rule_id.clone(), version);
        }
        
        self.activate_rule(&rule_id, None).await?;
        
        self.change_notifier.notify(RuleChange::Added {
            rule_id: rule_id.clone(),
            version: 1,
        }).await;
        
        Ok(rule_id)
    }
    
    pub async fn update_rule(&self, rule_id: &RuleId, new_rule: Arc<dyn RuleDefinition>) -> Result<u64, LifecycleError> {
        {
            let definitions = self.store.definitions.read().await;
            if !definitions.contains_key(rule_id) {
                return Err(LifecycleError::RuleNotFound(rule_id.to_string()));
            }
        }
        
        self.validator.validate(&new_rule).await
            .map_err(LifecycleError::ValidationFailed)?;
        
        let content_hash = self.compute_hash(&new_rule);
        
        let old_version = {
            let versions = self.versions.read();
            versions.get(rule_id).map(|v| v.version).unwrap_or(0)
        };
        
        let new_version = old_version + 1;
        let version = RuleVersion {
            version: new_version,
            content_hash,
            created_at: now_mono_ns(),
            created_by: "system".to_string(),
            description: format!("Update from version {}", old_version),
            status: VersionStatus::Pending,
        };
        
        {
            let mut definitions = self.store.definitions.write().await;
            definitions.insert(rule_id.to_string(), new_rule);
        }
        
        {
            let mut versions = self.versions.write();
            versions.insert(rule_id.to_string(), version);
        }
        
        self.activate_rule(rule_id, Some(old_version)).await?;
        
        self.change_notifier.notify(RuleChange::Modified {
            rule_id: rule_id.to_string(),
            old_version,
            new_version,
        }).await;
        
        Ok(new_version)
    }
    
    async fn activate_rule(&self, rule_id: &RuleId, old_version: Option<u64>) -> Result<(), LifecycleError> {
        match self.update_strategy {
            UpdateStrategy::Atomic => {
                self.do_activate(rule_id).await?;
            }
            UpdateStrategy::Gradual { .. } => {
                self.schedule_gradual_activation(rule_id).await?;
            }
            UpdateStrategy::Canary { .. } => {
                self.schedule_canary_activation(rule_id).await?;
            }
        }
        
        {
            let mut versions = self.versions.write();
            if let Some(v) = versions.get_mut(rule_id) {
                v.status = VersionStatus::Active;
            }
        }
        
        Ok(())
    }
    
    async fn do_activate(&self, rule_id: &RuleId) -> Result<(), LifecycleError> {
        let rule_def = {
            let definitions = self.store.definitions.read().await;
            definitions.get(rule_id)
                .ok_or_else(|| LifecycleError::RuleNotFound(rule_id.to_string()))?
                .clone()
        };
        
        let compiled = match rule_def.rule_type() {
            RuleType::Event { .. } => {
                CompiledRule::Event(self.compiler.compile_event_rule(&*rule_def)?)
            }
            RuleType::Sequence { .. } => {
                CompiledRule::Sequence(self.compiler.compile_sequence_rule(&*rule_def)?)
            }
            _ => return Err(LifecycleError::UnsupportedRuleType),
        };
        
        {
            let mut compiled_map = self.store.compiled.write().await;
            compiled_map.insert(rule_id.to_string(), compiled);
        }
        
        {
            let mut enabled = self.store.enabled.write().await;
            enabled.insert(rule_id.to_string(), true);
        }
        
        Ok(())
    }
    
    pub async fn remove_rule(&self, rule_id: &RuleId) -> Result<(), LifecycleError> {
        {
            let mut versions = self.versions.write();
            if let Some(v) = versions.get_mut(rule_id) {
                v.status = VersionStatus::Archived;
            }
        }
        
        {
            let mut enabled = self.store.enabled.write().await;
            enabled.insert(rule_id.to_string(), false);
        }
        
        {
            let mut compiled = self.store.compiled.write().await;
            compiled.remove(rule_id);
        }
        
        self.change_notifier.notify(RuleChange::Removed {
            rule_id: rule_id.to_string(),
            version: 0,
        }).await;
        
        Ok(())
    }
    
    fn compute_hash(&self, rule: &dyn RuleDefinition) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(rule.metadata().id.as_bytes());
        hasher.update(rule.metadata().name.as_bytes());
        *hasher.finalize().as_bytes()
    }
}

#[derive(Debug, Clone)]
pub struct LifecycleConfig {
    pub update_strategy: UpdateStrategy,
    pub max_versions_per_rule: u32,
    pub validation_timeout_ms: u64,
    pub compilation_timeout_ms: u64,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            update_strategy: UpdateStrategy::Atomic,
            max_versions_per_rule: 10,
            validation_timeout_ms: 5000,
            compilation_timeout_ms: 10000,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("Rule not found: {0}")]
    RuleNotFound(String),
    #[error("Rule validation failed: {0:?}")]
    ValidationFailed(Vec<ValidationError>),
    #[error("Compilation failed: {0}")]
    CompilationFailed(String),
    #[error("Unsupported rule type")]
    UnsupportedRuleType,
    #[error("Update conflict: rule was modified")]
    UpdateConflict,
}
```

### 5.2.4 变更通知器 (ChangeNotifier)

```rust
// 文件: kestrel-rules/src/change_notifier.rs

pub struct ChangeNotifier {
    tx: mpsc::Sender<RuleChangeEvent>,
    subscribers: Arc<RwLock<Vec<mpsc::Sender<RuleChangeEvent>>>>,
    history: Arc<RwLock<Vec<RuleChangeEvent>>>,
    max_history: usize,
}

#[derive(Debug, Clone)]
pub struct RuleChangeEvent {
    pub change: RuleChange,
    pub timestamp: TimestampMono,
    pub sequence_number: u64,
}

pub enum RuleChange {
    Added { rule_id: RuleId, version: u64 },
    Modified { rule_id: RuleId, old_version: u64, new_version: u64 },
    Removed { rule_id: RuleId, version: u64 },
    Enabled { rule_id: RuleId },
    Disabled { rule_id: RuleId },
}

impl ChangeNotifier {
    pub fn new(buffer_size: usize, max_history: usize) -> Self {
        let (tx, _rx) = mpsc::channel(buffer_size);
        Self {
            tx,
            subscribers: Arc::new(RwLock::new(Vec::new())),
            history: Arc::new(RwLock::new(Vec::new())),
            max_history,
        }
    }
    
    pub async fn notify(&self, change: RuleChange) {
        let event = RuleChangeEvent {
            change,
            timestamp: now_mono_ns(),
            sequence_number: self.next_sequence(),
        };
        
        let _ = self.tx.send(event.clone()).await;
        
        {
            let subscribers = self.subscribers.read().await;
            for tx in subscribers.iter() {
                let _ = tx.send(event.clone()).await;
            }
        }
        
        {
            let mut history = self.history.write().await;
            history.push(event);
            if history.len() > self.max_history {
                history.remove(0);
            }
        }
    }
    
    pub async fn subscribe(&self) -> mpsc::Receiver<RuleChangeEvent> {
        let (tx, rx) = mpsc::channel(100);
        {
            let mut subscribers = self.subscribers.write().await;
            subscribers.push(tx);
        }
        rx
    }
    
    pub async fn history(&self, since: Option<u64>) -> Vec<RuleChangeEvent> {
        let history = self.history.read().await;
        match since {
            Some(seq) => history.iter().filter(|e| e.sequence_number > seq).cloned().collect(),
            None => history.clone(),
        }
    }
    
    fn next_sequence(&self) -> u64 {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::SeqCst)
    }
}
```

## 5.3 修改计划

### 阶段 1: 规则定义重构 (Week 1)
| 任务 | 文件 | 修改内容 |
|------|------|---------|
| 定义RuleDefinition trait | `kestrel-rules/src/definition.rs` | 新建文件 |
| 实现EqlRuleDefinition | `kestrel-rules/src/eql_definition.rs` | 新建文件 |
| 实现WasmRuleDefinition | `kestrel-rules/src/wasm_definition.rs` | 新建文件 |

### 阶段 2: 规则编译架构 (Week 2)
| 任务 | 文件 | 修改内容 |
|------|------|---------|
| 定义RuleCompiler trait | `kestrel-rules/src/compiler.rs` | 新建文件 |
| 实现EqlCompiler | `kestrel-rules/src/eql_compiler.rs` | 重构 |
| 定义CompiledRule结构 | `kestrel-rules/src/compiled.rs` | 新建文件 |

### 阶段 3: 规则生命周期管理 (Week 3)
| 任务 | 文件 | 修改内容 |
|------|------|---------|
| 实现RuleLifecycleManager | `kestrel-rules/src/lifecycle.rs` | 新建文件 |
| 实现ChangeNotifier | `kestrel-rules/src/change_notifier.rs` | 新建文件 |
| 修改RuleManager | `kestrel-rules/src/lib.rs` | 集成新组件 |

### 阶段 4: 集成测试 (Week 4)
| 任务 | 文件 | 修改内容 |
|------|------|---------|
| 编写单元测试 | `kestrel-rules/tests/lifecycle.rs` | 新建测试文件 |
| 编写集成测试 | `kestrel-rules/tests/e2e.rs` | 新建测试文件 |

---

# 问题 6: 错误处理架构不统一 - 详细设计规划

## 6.1 现状分析

| 模块 | 错误处理方式 | 问题 |
|------|-------------|------|
| kestrel-schema | thiserror | 良好 |
| kestrel-event | thiserror | 良好 |
| kestrel-nfa | thiserror + NfaResult | 良好 |
| kestrel-engine | thiserror + EngineError | 良好 |
| kestrel-rules | anyhow::Result | 与其他模块不一致 |
| kestrel-runtime-wasm | ? + unwrap混合 | 不好 |
| kestrel-core | thiserror混合 | 中等 |

## 6.2 详细设计方案

### 6.2.1 统一错误类型定义

```rust
// 文件: kestrel-errors/src/lib.rs

#[derive(Debug, Error)]
#[error(transparent)]
pub struct KestrelError {
    kind: ErrorKind,
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
    context: ErrorContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    Schema,
    Event,
    EventBus,
    RuleManager,
    Engine,
    NfaEngine,
    Predicate,
    WasmRuntime,
    LuaRuntime,
    EqlCompilation,
    EbpfCollector,
    LsmHook,
    Ffi,
    Io,
    Config,
    Permission,
    Timeout,
    ResourceExhausted,
    InvalidState,
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct ErrorContext {
    pub rule_id: Option<String>,
    pub event_id: Option<u64>,
    pub entity_key: Option<u128>,
    pub component: Option<String>,
    pub operation: Option<String>,
    pub attributes: AHashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl KestrelError {
    pub fn new(kind: ErrorKind, message: impl Into<String>, source: Option<impl std::error::Error + Send + Sync>) -> Self {
        Self {
            kind,
            message: message.into(),
            source: source.map(|e| Box::new(e) as _),
            context: ErrorContext::default(),
            #[cfg(debug_assertions)]
            backtrace: Backtrace::capture(),
        }
    }
    
    pub fn with_context(mut self, context: ErrorContext) -> Self {
        self.context = context;
        self
    }
    
    pub fn with_rule_id(mut self, rule_id: impl Into<String>) -> Self {
        self.context.rule_id = Some(rule_id.into());
        self
    }
    
    pub fn with_event_id(mut self, event_id: u64) -> Self {
        self.context.event_id = Some(event_id);
        self
    }
    
    pub fn with_component(mut self, component: impl Into<String>) -> Self {
        self.context.component = Some(component.into());
        self
    }
    
    pub fn kind(&self) -> ErrorKind { self.kind.clone() }
    pub fn message(&self) -> &str { &self.message }
    
    pub fn severity(&self) -> ErrorSeverity {
        match self.kind {
            ErrorKind::Schema | ErrorKind::Event => ErrorSeverity::Warning,
            ErrorKind::EventBus | ErrorKind::RuleManager => ErrorSeverity::Error,
            ErrorKind::Engine | ErrorKind::NfaEngine | ErrorKind::Predicate => ErrorSeverity::Error,
            ErrorKind::WasmRuntime | ErrorKind::LuaRuntime | ErrorKind::EqlCompilation => ErrorSeverity::Warning,
            ErrorKind::EbpfCollector | ErrorKind::LsmHook => ErrorSeverity::Error,
            ErrorKind::Ffi => ErrorSeverity::Critical,
            ErrorKind::Io | ErrorKind::Config => ErrorSeverity::Error,
            ErrorKind::Permission => ErrorSeverity::Warning,
            ErrorKind::Timeout | ErrorKind::ResourceExhausted => ErrorSeverity::Error,
            ErrorKind::InvalidState => ErrorSeverity::Error,
            ErrorKind::Unknown => ErrorSeverity::Critical,
        }
    }
    
    pub fn is_transient(&self) -> bool {
        matches!(self.kind, ErrorKind::Timeout | ErrorKind::ResourceExhausted | ErrorKind::EventBus)
    }
    
    pub fn is_fatal(&self) -> bool {
        matches!(self.kind, ErrorKind::Permission | ErrorKind::Ffi | ErrorKind::InvalidState)
    }
}

#[macro_export]
macro_rules! kestrel_err {
    ($kind:expr, $($arg:tt)*) => {
        KestrelError::new($kind, format!($($arg)*), None)
    };
}

#[macro_export]
macro_rules! kestrel_err_from {
    ($kind:expr, $source:expr) => {
        KestrelError::new($kind, format!("{}", $source), Some($source))
    };
}

pub type Result<T> = std::result::Result<T, KestrelError>;
```

### 6.2.2 错误处理策略模式

```rust
// 文件: kestrel-errors/src/handler.rs

pub trait ErrorHandler: Send + Sync {
    fn handle(&self, error: &KestrelError) -> ErrorAction;
    fn name(&self) -> &'static str;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorAction {
    LogAndContinue,
    LogAndReturn,
    LogAndPanic,
    Degrade { fallback: FallbackStrategy },
    Retry { max_attempts: u32, delay_ms: u64 },
    Suppress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackStrategy {
    DefaultValue,
    CachedValue,
    Skip,
    AlternativeRuntime,
    Custom(&'static str),
}

pub struct ErrorHandlerChain {
    handlers: Vec<Arc<dyn ErrorHandler>>,
}

impl ErrorHandlerChain {
    pub fn new() -> Self {
        Self { handlers: Vec::new() }
    }
    
    pub fn add(&mut self, handler: Arc<dyn ErrorHandler>) {
        self.handlers.push(handler);
    }
    
    pub fn handle(&self, error: &KestrelError) -> Vec<ErrorAction> {
        self.handlers.iter().map(|h| h.handle(error)).collect()
    }
}

pub struct DefaultErrorHandler;

impl ErrorHandler for DefaultErrorHandler {
    fn handle(&self, error: &KestrelError) -> ErrorAction {
        match error.severity() {
            ErrorSeverity::Info => ErrorAction::LogAndContinue,
            ErrorSeverity::Warning => ErrorAction::LogAndContinue,
            ErrorSeverity::Error => ErrorAction::LogAndReturn,
            ErrorSeverity::Critical => ErrorAction::LogAndPanic,
        }
    }
    
    fn name(&self) -> &'static str { "default" }
}

pub struct ErrorBoundary {
    error_count: AtomicU64,
    success_count: AtomicU64,
    threshold: u64,
    recovery_timeout_ms: u64,
    state: AtomicU8,
    last_error_time: AtomicU64,
}

const CLOSED: u8 = 0;
const OPEN: u8 = 1;
const HALF_OPEN: u8 = 2;

impl ErrorBoundary {
    pub fn new(threshold: u64, recovery_timeout_ms: u64) -> Self {
        Self {
            error_count: AtomicU64::new(0),
            success_count: AtomicU64::new(0),
            threshold,
            recovery_timeout_ms,
            state: AtomicU8::new(CLOSED),
            last_error_time: AtomicU64::new(0),
        }
    }
    
    pub fn call<F, T, E>(&self, f: F) -> Result<T, ErrorBoundaryError>
    where
        F: FnOnce() -> Result<T, E>,
        E: Into<KestrelError>,
    {
        let state = self.state.load(Ordering::SeqCst);
        
        if state == OPEN {
            let last_error = self.last_error_time.load(Ordering::SeqCst);
            let now = now_ms();
            if now - last_error > self.recovery_timeout_ms {
                if self.state.compare_exchange(OPEN, HALF_OPEN, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                    // 继续执行
                } else {
                    return Err(ErrorBoundaryError::Open);
                }
            } else {
                return Err(ErrorBoundaryError::Open);
            }
        }
        
        match f() {
            Ok(result) => {
                self.success_count.fetch_add(1, Ordering::SeqCst);
                if state == HALF_OPEN {
                    self.state.store(CLOSED, Ordering::SeqCst);
                    self.error_count.store(0, Ordering::SeqCst);
                }
                Ok(result)
            }
            Err(e) => {
                let error = e.into();
                self.error_count.fetch_add(1, Ordering::SeqCst);
                self.last_error_time.store(now_ms(), Ordering::SeqCst);
                
                if self.error_count.load(Ordering::SeqCst) >= self.threshold {
                    self.state.store(OPEN, Ordering::SeqCst);
                }
                
                Err(ErrorBoundaryError::Tripped(error))
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ErrorBoundaryError {
    #[error("Circuit breaker is open")]
    Open,
    #[error("Circuit breaker was tripped: {0}")]
    Tripped(KestrelError),
}
```

### 6.2.3 错误转换

```rust
// 文件: kestrel-errors/src/convert.rs

pub trait IntoKestrelError {
    fn into_kestrel_error(self, kind: ErrorKind) -> KestrelError;
}

impl<T: std::error::Error + Send + Sync> IntoKestrelError for T {
    fn into_kestrel_error(self, kind: ErrorKind) -> KestrelError {
        KestrelError::new(kind, format!("{}", self), Some(self))
    }
}

impl From<kestrel_schema::SchemaError> for KestrelError {
    fn from(e: kestrel_schema::SchemaError) -> Self {
        KestrelError::new(ErrorKind::Schema, format!("{}", e), Some(e))
    }
}

impl From<kestrel_nfa::NfaError> for KestrelError {
    fn from(e: kestrel_nfa::NfaError) -> Self {
        KestrelError::new(ErrorKind::NfaEngine, format!("{}", e), Some(e))
    }
}

impl From<kestrel_engine::EngineError> for KestrelError {
    fn from(e: kestrel_engine::EngineError) -> Self {
        KestrelError::new(ErrorKind::Engine, format!("{}", e), Some(e))
    }
}

impl From<anyhow::Error> for KestrelError {
    fn from(e: anyhow::Error) -> Self {
        KestrelError::new(ErrorKind::Unknown, format!("{}", e), None)
    }
}

impl From<std::io::Error> for KestrelError {
    fn from(e: std::io::Error) -> Self {
        let kind = match e.kind() {
            std::io::ErrorKind::NotFound => ErrorKind::Io,
            std::io::ErrorKind::PermissionDenied => ErrorKind::Permission,
            _ => ErrorKind::Io,
        };
        KestrelError::new(kind, format!("{}", e), Some(e))
    }
}
```

## 6.3 修改计划

### 阶段 1: 统一错误类型 (Week 1)
| 任务 | 文件 | 修改内容 |
|------|------|---------|
| 创建 kestrel-errors crate | `kestrel-errors/Cargo.toml` | 新建crate |
| 定义统一错误类型 | `kestrel-errors/src/lib.rs` | 新建文件 |
| 定义错误处理策略 | `kestrel-errors/src/handler.rs` | 新建文件 |
| 定义错误转换 | `kestrel-errors/src/convert.rs` | 新建文件 |

### 阶段 2: 替换现有错误类型 (Week 2)
| 任务 | 文件 | 修改内容 |
|------|------|---------|
| 更新 kestrel-schema | `kestrel-schema/src/error.rs` | 实现 IntoKestrelError |
| 更新 kestrel-nfa | `kestrel-nfa/src/error.rs` | 实现 IntoKestrelError |
| 更新 kestrel-engine | `kestrel-engine/src/error.rs` | 实现 IntoKestrelError |
| 更新 kestrel-rules | `kestrel-rules/src/error.rs` | 从 anyhow 迁移到 thiserror |

### 阶段 3: 集成错误处理 (Week 3)
| 任务 | 文件 | 修改内容 |
|------|------|---------|
| 修复 eval_event 错误处理 | `kestrel-engine/src/lib.rs` | 返回错误而非吞掉 |
| 添加错误边界 | `kestrel-engine/src/engine.rs` | 使用 ErrorBoundary |
| 添加错误处理链 | `kestrel-core/src/bus.rs` | 使用 ErrorHandlerChain |

---

# 问题 8: 性能架构问题 - 详细设计规划

## 8.1 性能指标目标

| 指标 | 当前 | 目标 | 提升 |
|------|------|------|------|
| 事件处理延迟 (P99) | ~100μs | <10μs | 10x |
| 吞吐量 | 10K events/sec | 100K events/sec | 10x |
| 内存使用 | ~500MB | <200MB | 2.5x |

## 8.2 详细设计方案

### 8.2.1 对象池

```rust
// 文件: kestrel-core/src/pool.rs

pub struct ObjectPool<T: Send + Sync + 'static> {
    items: Arc<RwLock<Vec<T>>>,
    max_size: usize,
    factory: Arc<dyn Fn() -> T + Send + Sync>,
}

impl<T: Clone + Send + Sync> ObjectPool<T> {
    pub fn new(max_size: usize, factory: impl Fn() -> T + Send + Sync + 'static) -> Self {
        Self {
            items: Arc::new(RwLock::new(Vec::with_capacity(max_size))),
            max_size,
            factory: Arc::new(factory),
        }
    }
    
    pub fn acquire(&self) -> PooledObject<T> {
        {
            let mut items = self.items.write();
            if let Some(item) = items.pop() {
                return PooledObject { pool: self.clone(), item: Some(item) };
            }
        }
        
        let item = (self.factory)();
        PooledObject { pool: self.clone(), item: Some(item) }
    }
    
    fn release(&self, item: T) {
        let mut items = self.items.write();
        if items.len() < self.max_size {
            items.push(item);
        }
    }
}

pub struct PooledObject<T: Send + Sync> {
    pool: ObjectPool<T>,
    item: Option<T>,
}

impl<T: Send + Sync> PooledObject<T> {
    pub fn as_mut(&mut self) -> &mut T {
        self.item.as_mut().expect("PooledObject was taken")
    }
}

impl<T: Send + Sync> Drop for PooledObject<T> {
    fn drop(&mut self) {
        if let Some(item) = self.item.take() {
            self.pool.release(item);
        }
    }
}

pub type AlertPool = ObjectPool<Vec<Alert>>;
pub type SequenceMatchPool = ObjectPool<Vec<SequenceMatch>>;

impl AlertPool {
    pub fn new() -> Self {
        Self::new(1000, || Vec::with_capacity(16))
    }
}

impl SequenceMatchPool {
    pub fn new() -> Self {
        Self::new(1000, || Vec::with_capacity(4))
    }
}
```

### 8.2.2 无锁数据结构

```rust
// 文件: kestrel-nfa/src/budget.rs

pub struct LockFreeBudgetTracker {
    budgets: AHashMap<String, Arc<BudgetEntry>>,
    window_ns: u64,
    window_start: AtomicU64,
    total_evaluations: AtomicU64,
    total_time_ns: AtomicU64,
}

struct BudgetEntry {
    count: AtomicU64,
    time_ns: AtomicU64,
    window_start: AtomicU64,
}

impl LockFreeBudgetTracker {
    pub fn new(window_ns: u64) -> Self {
        let now = now_ns();
        Self {
            budgets: AHashMap::new(),
            window_ns,
            window_start: AtomicU64::new(now),
            total_evaluations: AtomicU64::new(0),
            total_time_ns: AtomicU64::new(0),
        }
    }
    
    pub fn check_and_update(&self, sequence_id: &str, eval_time_ns: u64) -> bool {
        let now = now_ns();
        
        loop {
            let current_start = self.window_start.load(Ordering::SeqCst);
            if now - current_start < self.window_ns {
                break;
            }
            if self.window_start.compare_exchange_weak(
                current_start, now, Ordering::SeqCst, Ordering::SeqCst
            ).is_ok() {
                self.total_evaluations.store(0, Ordering::SeqCst);
                self.total_time_ns.store(0, Ordering::SeqCst);
                break;
            }
        }
        
        let entry = self.budgets
            .entry(sequence_id.to_string())
            .or_insert_with(|| Arc::new(BudgetEntry {
                count: AtomicU64::new(0),
                time_ns: AtomicU64::new(0),
                window_start: AtomicU64::new(self.window_start.load(Ordering::SeqCst)),
            }))
            .clone();
        
        loop {
            let entry_start = entry.window_start.load(Ordering::SeqCst);
            if now - entry_start < self.window_ns {
                break;
            }
            if entry.window_start.compare_exchange_weak(
                entry_start, now, Ordering::SeqCst, Ordering::SeqCst
            ).is_ok() {
                entry.count.store(0, Ordering::SeqCst);
                entry.time_ns.store(0, Ordering::SeqCst);
                break;
            }
        }
        
        let new_count = entry.count.fetch_add(1, Ordering::SeqCst) + 1;
        entry.time_ns.fetch_add(eval_time_ns, Ordering::SeqCst);
        
        self.total_evaluations.fetch_add(1, Ordering::SeqCst);
        self.total_time_ns.fetch_add(eval_time_ns, Ordering::SeqCst);
        
        new_count <= 100_000
    }
    
    pub fn stats(&self) -> BudgetStats {
        BudgetStats {
            total_evaluations: self.total_evaluations.load(Ordering::SeqCst),
            total_time_ns: self.total_time_ns.load(Ordering::SeqCst),
            window_ns: self.window_ns,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BudgetStats {
    pub total_evaluations: u64,
    pub total_time_ns: u64,
    pub window_ns: u64,
}
```

### 8.2.3 二进制序列化

```rust
// 文件: kestrel-core/src/serdes.rs

use bincode::{Encode, Decode};

#[derive(Encode, Decode, Debug, Clone)]
pub struct BinaryAlert {
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: u8,
    pub title: String,
    pub description: Option<String>,
    pub timestamp_ns: u64,
    pub events: Vec<BinaryEventEvidence>,
    pub context_len: u32,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct BinaryEventEvidence {
    pub event_type_id: u16,
    pub timestamp_ns: u64,
    pub field_count: u8,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct BinaryBatch {
    pub version: u8,
    pub event_count: u32,
    pub events: Vec<BinaryEvent>,
    pub checksum: u32,
}

impl BinaryBatch {
    pub fn serialize(events: &[Event]) -> Vec<u8> {
        let binary_events: Vec<BinaryEvent> = events.iter().map(|e| BinaryEvent::from(e)).collect();
        
        let batch = BinaryBatch {
            version: 1,
            event_count: binary_events.len() as u32,
            events: binary_events,
            checksum: 0,
        };
        
        let mut bytes = bincode::encode_to_vec(&batch, bincode::config::standard())
            .expect("Failed to serialize batch");
        
        let checksum = crc32::crc32(&bytes);
        let checksum_bytes = checksum.to_le_bytes();
        bytes[bytes.len()-4..].copy_from_slice(&checksum_bytes);
        
        bytes
    }
    
    pub fn deserialize(data: &[u8]) -> Result<Vec<Event>, DeserializationError> {
        let stored_checksum = u32::from_le_bytes(data[data.len()-4..].try_into().unwrap());
        let data_without_checksum = &data[..data.len()-4];
        let computed_checksum = crc32::crc32(data_without_checksum);
        
        if stored_checksum != computed_checksum {
            return Err(DeserializationError::ChecksumMismatch);
        }
        
        let (batch, _): (BinaryBatch, _) = bincode::decode_from_slice(data, bincode::config::standard())
            .map_err(|e| DeserializationError::DecodeError(e.to_string()))?;
        
        batch.events.iter().map(|e| Event::try_from(e)).collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeserializationError {
    #[error("Checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: u32, actual: u32 },
    #[error("Decode error: {0}")]
    DecodeError(String),
    #[error("Invalid event data")]
    InvalidData,
}
```

## 8.3 修改计划

### 阶段 1: 对象池 (Week 1)
| 任务 | 文件 | 修改内容 |
|------|------|---------|
| 创建 ObjectPool | `kestrel-core/src/pool.rs` | 新建通用对象池 |
| 实现 AlertPool | `kestrel-core/src/pool.rs` | 告警专用池 |
| 集成到 Engine | `kestrel-engine/src/engine.rs` | 使用对象池 |

### 阶段 2: 无锁数据结构 (Week 2)
| 任务 | 文件 | 修改内容 |
|------|------|---------|
| 实现 LockFreeBudgetTracker | `kestrel-nfa/src/budget.rs` | 新建无锁预算追踪 |
| 替换现有实现 | `kestrel-nfa/src/engine.rs` | 使用无锁版本 |

### 阶段 3: 二进制序列化 (Week 3)
| 任务 | 文件 | 修改内容 |
|------|------|---------|
| 实现 BinaryAlert | `kestrel-core/src/serdes.rs` | 新建二进制序列化 |
| 添加 bincode 依赖 | `kestrel-core/Cargo.toml` | 添加依赖 |

---

# 问题 9: 可观测性架构缺失 - 详细设计规划

## 9.1 详细设计方案

### 9.2.1 统一指标系统

```rust
// 文件: kestrel-telemetry/src/metrics.rs

pub struct MetricsRegistry {
    counters: AHashMap<&'static str, AtomicU64>,
    gauges: AHashMap<&'static str, AtomicU64>,
    histograms: AHashMap<&'static str, HistogramData>,
    timers: AHashMap<&'static str, TimerData>,
    labels: AHashMap<String, String>,
}

struct HistogramData {
    buckets: Vec<AtomicU64>,
    total: AtomicU64,
}

struct TimerData {
    buckets: Vec<AtomicU64>,
    total: AtomicU64,
    count: AtomicU64,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            counters: AHashMap::new(),
            gauges: AHashMap::new(),
            histograms: AHashMap::new(),
            timers: AHashMap::new(),
            labels: AHashMap::new(),
        }
    }
    
    pub fn counter_inc(&self, name: &str, delta: u64) {
        if let Some(counter) = self.counters.get(name) {
            counter.fetch_add(delta, Ordering::Relaxed);
        }
    }
    
    pub fn gauge_set(&self, name: &str, value: f64) {
        if let Some(gauge) = self.gauges.get(name) {
            gauge.store(value as u64, Ordering::Relaxed);
        }
    }
    
    pub fn histogram_observe(&self, name: &str, value: u64) {
        if let Some(hist) = self.histograms.get(name) {
            for (i, bucket) in hist.buckets.iter().enumerate() {
                if value <= (i as u64) * 1000 {
                    bucket.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
            hist.total.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    pub fn timer_record(&self, name: &str, duration: std::time::Duration) {
        if let Some(timer) = self.timers.get(name) {
            let micros = duration.as_micros() as u64;
            for (i, bucket) in timer.buckets.iter().enumerate() {
                if micros <= (i as u64) * 1000 {
                    bucket.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
            timer.total.fetch_add(micros, Ordering::Relaxed);
            timer.count.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    pub fn export_prometheus(&self) -> String {
        let mut output = String::new();
        for (name, counter) in &self.counters {
            output.push_str(&format!("# TYPE {} counter\n", name));
            output.push_str(&format!("{} {}\n", name, counter.load(Ordering::Relaxed)));
        }
        for (name, gauge) in &self.gauges {
            output.push_str(&format!("# TYPE {} gauge\n", name));
            output.push_str(&format!("{} {}\n", name, gauge.load(Ordering::Relaxed)));
        }
        output
    }
}

pub mod metric_names {
    pub const EVENT_BUS_EVENTS_RECEIVED: &str = "kestrel_eventbus_events_received_total";
    pub const EVENT_BUS_EVENTS_PROCESSED: &str = "kestrel_eventbus_events_processed_total";
    pub const ENGINE_ALERTS_GENERATED: &str = "kestrel_engine_alerts_generated_total";
    pub const NFA_EVENTS_PROCESSED: &str = "kestrel_nfa_events_processed_total";
    pub const RUNTIME_PREDICATE_EVALS: &str = "kestrel_runtime_predicate_evaluations_total";
}
```

### 9.2.2 分布式追踪

```rust
// 文件: kestrel-telemetry/src/tracing.rs

pub struct TracingManager {
    tracer: Option<opentelemetry::sdk::trace::Tracer>,
    propagator: Box<dyn opentelemetry::propagation::TextMapPropagator + Send + Sync>,
    config: TracingConfig,
}

impl TracingManager {
    pub fn new(config: TracingConfig) -> Self {
        Self {
            tracer: None,
            propagator: Box::new(opentelemetry::propagation::TraceContextPropagator::new()),
            config,
        }
    }
    
    pub fn init(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let sampler = opentelemetry::sdk::trace::Sampler::TraceIdRatioBased(self.config.sample_rate);
        let exporter = opentelemetry_stdout::SpanExporter::default();
        
        let tracer = opentelemetry::sdk::trace::TracerProvider::builder()
            .with_simple_exporter(exporter)
            .with_config(opentelemetry::sdk::trace::Config { sampler, ..Default::default() })
            .build();
        
        opentelemetry::global::set_tracer_provider(tracer);
        self.tracer = Some(opentelemetry::global::tracer(self.config.service_name.as_str()));
        
        Ok(())
    }
}

#[tracing::instrument(skip(event, engine), fields(event_id = %event.ts_mono_ns))]
pub async fn trace_eval_event(
    engine: &DetectionEngine,
    event: &Event,
) -> Result<Vec<Alert>, EngineError> {
    let start = std::time::Instant::now();
    
    tracing::info!(
        event_type_id = event.event_type_id,
        entity_key = event.entity_key,
        "Starting event evaluation"
    );
    
    let result = engine.eval_event(event).await;
    
    match &result {
        Ok(alerts) => {
            tracing::info!(
                alerts_generated = alerts.len(),
                duration_ms = start.elapsed().as_millis(),
                "Event evaluation completed"
            );
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                duration_ms = start.elapsed().as_millis(),
                "Event evaluation failed"
            );
        }
    }
    
    result
}
```

### 9.2.3 健康检查接口

```rust
// 文件: kestrel-telemetry/src/health.rs

pub struct HealthRegistry {
    components: Arc<RwLock<AHashMap<String, ComponentHealth>>>,
    checkers: Arc<RwLock<AHashMap<String, Box<dyn HealthChecker>>>>,
    last_check: Arc<RwLock<std::time::Instant>>,
    check_interval: std::time::Duration,
}

impl HealthRegistry {
    pub fn new(check_interval: std::time::Duration) -> Self {
        Self {
            components: Arc::new(RwLock::new(AHashMap::new())),
            checkers: Arc::new(RwLock::new(AHashMap::new())),
            last_check: Arc::new(RwLock::new(std::time::Instant::now())),
            check_interval,
        }
    }
    
    pub async fn check(&self) -> HealthCheckResult {
        let checkers = self.checkers.read().await;
        let mut components = self.components.write().await;
        
        let mut unhealthy_reasons = Vec::new();
        let mut details = AHashMap::new();
        
        for (name, checker) in checkers.iter() {
            let result = checker.check().await;
            
            let status = match &result {
                CheckResult::Healthy => ComponentStatus::Up,
                CheckResult::Unhealthy(_) => {
                    unhealthy_reasons.push(UnhealthyReason::ComponentCrashed { component: name.to_string() });
                    ComponentStatus::Down
                }
                CheckResult::Degraded(_) => ComponentStatus::Up,
                CheckResult::Unknown => ComponentStatus::Unknown,
            };
            
            details.insert(name.to_string(), ComponentHealth {
                name: name.to_string(),
                status,
                last_check: std::time::Instant::now(),
                latency: None,
                message: result.message(),
                metrics: AHashMap::new(),
            });
        }
        
        let status = if !unhealthy_reasons.is_empty() {
            HealthStatus::Unhealthy(unhealthy_reasons)
        } else {
            HealthStatus::Healthy
        };
        
        HealthCheckResult {
            status,
            timestamp: std::time::Instant::now(),
            details,
            uptime: std::time::Duration::from_secs(0),
        }
    }
}

pub struct EngineHealthChecker {
    engine: Arc<DetectionEngine>,
}

#[async_trait::async_trait]
impl HealthChecker for EngineHealthChecker {
    async fn check(&self) -> CheckResult {
        let stats = self.engine.stats().await;
        
        if stats.rule_count == 0 {
            return CheckResult::Degraded(DegradedReason::PartialOutage { component: "rules".to_string() });
        }
        
        if stats.errors_count > 100 {
            return CheckResult::Degraded(DegradedReason::HighErrorRate {
                component: "engine".to_string(),
                errors: stats.errors_count,
                total: stats.events_processed,
            });
        }
        
        CheckResult::Healthy
    }
}

pub async fn health_handler(registry: Arc<HealthRegistry>) -> impl warp::Reply {
    let result = registry.check().await;
    
    let status_code = match result.status {
        HealthStatus::Healthy => warp::http::StatusCode::OK,
        HealthStatus::Degraded(_) => warp::http::StatusCode::OK,
        HealthStatus::Unhealthy(_) => warp::http::StatusCode::SERVICE_UNAVAILABLE,
    };
    
    warp::reply::with_status(warp::reply::json(&result), status_code)
}
```

## 9.3 修改计划

### 阶段 1: 创建遥测 crate (Week 1)
| 任务 | 文件 | 修改内容 |
|------|------|---------|
| 创建 kestrel-telemetry | `kestrel-telemetry/Cargo.toml` | 新建 crate |
| 实现 MetricsRegistry | `kestrel-telemetry/src/metrics.rs` | 新建统一指标系统 |

### 阶段 2: 集成指标系统 (Week 2)
| 任务 | 文件 | 修改内容 |
|------|------|---------|
| 更新 EventBus | `kestrel-core/src/eventbus.rs` | 使用 MetricsRegistry |
| 更新 Engine | `kestrel-engine/src/engine.rs` | 使用 MetricsRegistry |
| 更新 NFA | `kestrel-nfa/src/engine.rs` | 使用 MetricsRegistry |

### 阶段 3: 健康检查 (Week 3)
| 任务 | 文件 | 修改内容 |
|------|------|---------|
| 实现 HealthRegistry | `kestrel-telemetry/src/health.rs` | 新建健康检查系统 |
| 添加 HTTP 端点 | `kestrel-cli/src/main.rs` | 添加 /health 端点 |

---

# 问题 10: 扩展性架构设计缺失 - 详细设计规划

## 10.1 详细设计方案

### 10.2.1 插件系统

```rust
// 文件: kestrel-plugin/src/lib.rs

pub trait Plugin: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn init(&mut self, context: &PluginContext) -> Result<(), PluginError>;
    fn capabilities(&self) -> Vec<PluginCapability>;
    fn shutdown(&mut self);
}

pub enum PluginCapability {
    EventSource { name: &'static str, factory: fn(Arc<SchemaRegistry>) -> Box<dyn EventSource> },
    ActionExecutor { name: &'static str, factory: fn() -> Box<dyn ActionExecutor> },
    PredicateEvaluator { name: &'static str, factory: fn() -> Box<dyn PredicateEvaluator> },
    OutputHandler { name: &'static str, factory: fn() -> Box<dyn OutputHandler> },
    RuleCompiler { name: &'static str, priority: u32, factory: fn(Arc<SchemaRegistry>) -> Box<dyn RuleCompiler> },
}

pub struct PluginContext {
    pub schema: Arc<SchemaRegistry>,
    pub event_bus: Arc<dyn EventBus + Send + Sync>,
    pub config: Arc<dyn ConfigProvider>,
    pub metrics: Arc<MetricsRegistry>,
}

pub struct PluginManager {
    plugins: Arc<RwLock<AHashMap<String, LoadedPlugin>>>,
    plugin_path: std::path::PathBuf,
    context: PluginContext,
    capabilities: Arc<RwLock<AHashMap<PluginCapability, String>>>,
}

struct LoadedPlugin {
    name: &'static str,
    version: &'static str,
    library: libloading::Library,
    instance: Box<dyn Plugin>,
}

impl PluginManager {
    pub async fn load_plugin(&self, name: &str) -> Result<(), PluginError> {
        let path = self.plugin_path.join(format!("lib{}.so", name));
        
        let library = unsafe {
            libloading::Library::new(&path)
                .map_err(|e| PluginError::LoadFailed(e.to_string()))?
        };
        
        let factory: Symbol<fn() -> *mut Box<dyn Plugin>> = unsafe {
            library.get(b"_kestrel_create_plugin\0")
                .map_err(|e| PluginError::InvalidFormat(e.to_string()))?
        };
        
        let plugin_ptr = unsafe { factory() };
        let mut plugin = unsafe { Box::from_raw(plugin_ptr) };
        
        plugin.init(&self.context).map_err(|e| PluginError::InitFailed(e.to_string()))?;
        
        let plugin_name = plugin.name();
        for capability in plugin.capabilities() {
            let mut caps = self.capabilities.write();
            caps.insert(capability, plugin_name.to_string());
        }
        
        let mut plugins = self.plugins.write();
        plugins.insert(plugin_name.to_string(), LoadedPlugin {
            name: plugin.name(),
            version: plugin.version(),
            library,
            instance: plugin,
        });
        
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("Failed to load plugin: {0}")]
    LoadFailed(String),
    #[error("Invalid plugin format: {0}")]
    InvalidFormat(String),
    #[error("Plugin init failed: {0}")]
    InitFailed(String),
    #[error("Plugin not found: {0}")]
    NotFound(String),
    #[error("Plugin already loaded: {0}")]
    AlreadyLoaded(String),
}
```

### 10.2.2 分布式状态管理

```rust
// 文件: kestrel-distrib/src/lib.rs

pub trait DistributedStateStore: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StateError>;
    async fn set(&self, key: &str, value: &[u8], ttl: Option<std::time::Duration>) -> Result<(), StateError>;
    async fn delete(&self, key: &str) -> Result<(), StateError>;
    async fn compare_and_set(&self, key: &str, expected: &[u8], new_value: &[u8]) -> Result<bool, StateError>;
    async fn watch(&self, key: &str) -> mpsc::Receiver<WatchEvent>;
}

pub enum WatchEvent {
    Put(Vec<u8>),
    Delete,
}

pub struct DistributedSequenceState {
    store: Arc<dyn DistributedStateStore>,
    key_prefix: String,
    sequence_id: String,
}

impl DistributedSequenceState {
    fn make_key(&self, entity_key: u128, step: usize) -> String {
        format!("{}/sequences/{}/entity_{}/step_{}", self.key_prefix, self.sequence_id, entity_key, step)
    }
    
    pub async fn get_partial_match(&self, entity_key: u128, step: usize) -> Result<Option<PartialMatchState>, StateError> {
        let key = self.make_key(entity_key, step);
        let data = self.store.get(&key).await?;
        data.map(|d| PartialMatchState::deserialize(&d)).transpose().map_err(StateError::Deserialize)
    }
    
    pub async fn set_partial_match(&self, entity_key: u128, step: usize, state: &PartialMatchState, ttl: std::time::Duration) -> Result<(), StateError> {
        let key = self.make_key(entity_key, step);
        let data = state.serialize();
        self.store.set(&key, &data, Some(ttl)).await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialMatchState {
    pub sequence_id: String,
    pub entity_key: u128,
    pub current_step: usize,
    pub started_at: u64,
    pub expires_at: u64,
    pub captures: AHashMap<String, TypedValue>,
    pub event_ids: Vec<u64>,
}

impl PartialMatchState {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::encode_to_vec(self, bincode::config::standard()).expect("Failed to serialize")
    }
    
    pub fn deserialize(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::decode_from_slice(data, bincode::config::standard()).map(|(s, _)| s)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Serialization error: {0}")]
    Serialize(String),
    #[error("Deserialization error: {0}")]
    Deserialize(bincode::Error),
    #[error("Timeout")]
    Timeout,
    #[error("Conflict")]
    Conflict,
}
```

### 10.2.3 动态配置更新

```rust
// 文件: kestrel-config/src/dynamic.rs

pub trait DynamicConfig: Send + Sync + 'static {
    type Config: serde::Serialize + for<'de> serde::Deserialize<'de> + Default;
    fn config(&self) -> &Self::Config;
    async fn update(&self, new_config: Self::Config) -> Result<(), ConfigError>;
    fn subscribe(&self) -> tokio::sync::watch::Receiver<Self::Config>;
}

pub struct ConfigManager {
    configs: Arc<RwLock<AHashMap<String, Arc<dyn DynamicConfig>>>>,
    sources: Arc<RwLock<Vec<ConfigSource>>>,
    update_tx: tokio::sync::watch::Sender<ConfigUpdate>,
}

#[derive(Debug, Clone)]
pub enum ConfigSource {
    File { path: std::path::PathBuf, poll_interval: std::time::Duration },
    Http { url: String, poll_interval: std::time::Duration },
    Etcd { key: String, endpoints: Vec<String> },
}

#[derive(Debug, Clone)]
pub struct ConfigUpdate {
    pub config_name: String,
    pub timestamp: u64,
    pub source: ConfigSource,
}

impl ConfigManager {
    pub fn new() -> Self {
        Self {
            configs: Arc::new(RwLock::new(AHashMap::new())),
            sources: Arc::new(RwLock::new(Vec::new())),
            update_tx: tokio::sync::watch::channel(ConfigUpdate {
                config_name: "".to_string(),
                timestamp: now_mono_ns(),
                source: ConfigSource::File { path: std::path::PathBuf::from("config.toml"), poll_interval: std::time::Duration::from_secs(30) },
            }).0,
        }
    }
    
    pub fn register<C: DynamicConfig>(&self, name: String, config: Arc<C>) {
        let mut configs = self.configs.write();
        configs.insert(name, config);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EngineDynamicConfig {
    pub max_concurrent_evaluations: usize,
    pub budget_check_interval_ms: u64,
    pub auto_load_new_rules: bool,
    pub alert_batch_size: usize,
    pub alert_batch_timeout_ms: u64,
}

#[async_trait::async_trait]
impl DynamicConfig for EngineDynamicConfig {
    type Config = EngineDynamicConfig;
    
    fn config(&self) -> &Self::Config { self }
    
    async fn update(&self, new_config: Self::Config) -> Result<(), ConfigError> {
        if new_config.max_concurrent_evaluations == 0 {
            return Err(ConfigError::Validation("max_concurrent_evaluations must be > 0".to_string()));
        }
        Ok(())
    }
    
    fn subscribe(&self) -> tokio::sync::watch::Receiver<Self::Config> {
        let (tx, rx) = tokio::sync::watch::channel(self.clone());
        tx
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Load error: {0}")]
    Load(String),
    #[error("Parse error: {0}")]
    Parse(String),
}
```

## 10.3 修改计划

### 阶段 1: 插件系统 (Week 1-2)
| 任务 | 文件 | 修改内容 |
|------|------|---------|
| 创建 kestrel-plugin | `kestrel-plugin/Cargo.toml` | 新建 crate |
| 定义 Plugin trait | `kestrel-plugin/src/lib.rs` | 新建文件 |
| 实现 PluginManager | `kestrel-plugin/src/manager.rs` | 新建文件 |

### 阶段 2: 分布式支持 (Week 3-4)
| 任务 | 文件 | 修改内容 |
|------|------|---------|
| 创建 kestrel-distrib | `kestrel-distrib/Cargo.toml` | 新建 crate |
| 实现 DistributedStateStore | `kestrel-distrib/src/store.rs` | 新建文件 |
| 添加 Redis/etcd 支持 | `kestrel-distrib/Cargo.toml` | 添加依赖 |

### 阶段 3: 动态配置 (Week 5)
| 任务 | 文件 | 修改内容 |
|------|------|---------|
| 创建 kestrel-config | `kestrel-config/Cargo.toml` | 新建 crate |
| 实现 ConfigManager | `kestrel-config/src/manager.rs` | 新建文件 |
| 集成到 Engine | `kestrel-engine/src/engine.rs` | 使用动态配置 |

---

## 总结

本文档为问题 5、6、8、9、10 提供了详细的设计规划和修改方案：

| 问题 | 主题 | 主要改动 | 预计工期 |
|------|------|---------|---------|
| **#5** | 规则生命周期 | RuleDefinition trait、RuleCompiler trait、RuleLifecycleManager、版本管理 | 4周 |
| **#6** | 错误处理 | 统一错误类型 KestrelError、ErrorHandler 链、ErrorBoundary | 3周 |
| **#8** | 性能架构 | ObjectPool、LockFreeBudgetTracker、二进制序列化 | 3周 |
| **#9** | 可观测性 | MetricsRegistry、TracingManager、HealthRegistry | 3周 |
| **#10** | 扩展性 | PluginManager、DistributedStateStore、ConfigManager | 5周 |

每个问题都包含：
1. **详细设计方案** - 完整的 Rust 代码示例
2. **修改计划** - 分阶段实施计划
3. **迁移策略** - 向后兼容方案
