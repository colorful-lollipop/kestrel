# Kestrel 代码重构分析与计划

## 一、已识别的冗余问题

### 1. **严重冗余 - 重复的 Runtime 结构** (P0)

**位置**: `kestrel-runtime-wasm` 和 `kestrel-runtime-lua`

**重复内容**:
| 结构 | Wasm 位置 | Lua 位置 | 解决方案 |
|------|-----------|----------|---------|
| `EvalResult` | wasm/lib.rs:287 | lua/lib.rs:101 | 提取到公共 trait |
| `RuleMetadata` | wasm/lib.rs:125 | lua/lib.rs:109 | 提取到 kestrel-rules |
| `RuleManifest` | wasm/lib.rs:138 | lua/lib.rs:122 | 提取到 kestrel-rules |
| `RuleCapabilities` | wasm/lib.rs:146 | lua/lib.rs:129 | 提取到 kestrel-rules |
| `AlertRecord` | wasm/host_api.rs:43 | lua/host_api.rs:37 | 提取到 kestrel-core |
| `EventHandle/RegexId/GlobId` | wasm/host_api.rs:34-40 | lua/host_api.rs:28-34 | 提取到 kestrel-schema |

**影响**: 约 200+ 行重复代码，修改需要同步多处

---

### 2. **重复的错误类型定义** (P1)

**现有错误类型**:
- `WasmRuntimeError` (wasm) - 7 个变体
- `LuaRuntimeError` (lua) - 8 个变体
- `CompilationError` (rules) - 5 个变体
- `NfaError` (nfa) - 5 个变体
- `RuntimeError` (engine) - 5 个变体

**重复变体**:
- `CompilationError` / `LoadError` / `CompilationFailed`
- `ExecutionError` / `ExecutionError`
- `Timeout` / `OutOfFuel`
- `InvalidFieldId` / `InvalidEventHandle`

**解决方案**: 使用错误类型转换和 thiserror 的 `#[from]` 属性

---

### 3. **重复的 Severity 定义** (P1)

**位置**:
- `kestrel-rules/src/lib.rs:69` 
- `kestrel-core/src/alert.rs:45`

**问题**: 完全相同的枚举，应该统一到一个地方

---

### 4. **重复的 Metrics 模式** (P1)

**重复模式** (出现在 metrics.rs, wasm/lib.rs 等):
```rust
// Peak value update pattern - 重复 6+ 次
loop {
    let peak = self.peak_value.load(Ordering::Relaxed);
    if value <= peak { break; }
    if self.peak_value.compare_exchange_weak(...).is_ok() { break; }
}
```

**解决方案**: 提取到通用的 `AtomicPeak` 结构

---

### 5. **重复的证据结构** (P2)

**位置**:
- `ActionEvidence` (action.rs:146)
- `EventEvidence` (alert.rs:54)

**差异**: 只有字段名略有不同，含义相同

---

### 6. **重复的 Runtime 配置** (P2)

**结构**:
- `WasmConfig`: max_memory_mb, max_execution_time_ms, fuel_per_eval
- `LuaConfig`: max_memory_mb, max_execution_time_ms, instruction_limit

---

## 二、设计模式应用

### 1. **Strategy Pattern (策略模式)** - 已部分应用 ✅

**当前实现**: `Partitioner` trait 在 eventbus.rs

**应该扩展**:
- `Runtime` trait 应该完全隐藏 Wasm/Lua 差异
- `ActionExecutor` trait 已经是好的实践

### 2. **Template Method Pattern (模板方法模式)**

**适用场景**:
- `ActionExecutor` 的各个实现有大量重复的执行流程
- Runtime Adapters 的 `load_predicate` 方法

### 3. **Builder Pattern (建造者模式)** - 已应用 ✅

**当前实现**: `EventBuilder` 在 event.rs

**应该统一**: 所有配置结构都使用 Builder 模式

### 4. **Factory Pattern (工厂模式)**

**适用场景**:
- Runtime 实例的创建
- ActionExecutor 的创建
- 编译器的创建

### 5. **Adapter Pattern (适配器模式)** - 已应用 ✅

**当前实现**: `WasmRuntimeAdapter`, `LuaRuntimeAdapter`

---

## 三、重构计划

### Phase 1: 提取公共类型 (P0)

1. **创建 `kestrel-common` crate** (或扩展到 kestrel-schema)
   - 移动 `RuleMetadata`, `RuleManifest`, `RuleCapabilities`
   - 移动 `EvalResult`
   - 移动 `Severity`
   - 移动 `EventHandle`, `RegexId`, `GlobId`

2. **统一 Runtime 相关类型**
   - 创建 `RuntimeConfig` trait
   - 提取公共配置字段

### Phase 2: 统一错误处理 (P1)

1. **创建错误转换层**
   - 使用 `thiserror` 的 `#[from]` 属性
   - 保留特定错误类型的同时提供统一接口

2. **错误分类**:
   - `ConfigError` - 配置错误
   - `CompilationError` - 编译错误
   - `ExecutionError` - 执行错误
   - `ValidationError` - 验证错误

### Phase 3: 提取通用 Metrics 工具 (P1)

1. **创建 `AtomicPeak` 结构**
   ```rust
   pub struct AtomicPeak {
       value: AtomicU64,
   }
   impl AtomicPeak {
       pub fn update(&self, new_value: u64) -> bool;
       pub fn load(&self) -> u64;
   }
   ```

2. **创建 `MetricsRecorder` trait**
   - 统一 metrics 记录接口

### Phase 4: 代码生成/宏简化 (P2)

1. **派生宏**: `#[derive(Builder)]`
2. **派生宏**: `#[derive(Metrics)]`

---

## 四、预期收益

| 指标 | 当前 | 预期 | 收益 |
|-----|------|------|------|
| 重复代码行数 | ~800 | ~200 | -75% |
| 需要同步修改的位置 | 5+ | 1 | -80% |
| 新增类型数量 | 50+ | 30- | -40% |
| 错误类型数量 | 35+ | 15- | -57% |
| 测试代码重复 | 30% | 10% | -67% |

---

## 五、风险评估

### 低风险
- 纯结构移动，不改变逻辑
- 类型别名保持向后兼容

### 中风险
- 错误类型转换需要测试覆盖
- 需要更新下游依赖

### 缓解措施
1. 逐步重构，每次一个模块
2. 保持类型别名用于向后兼容
3. 完整测试覆盖
4. 文档更新
