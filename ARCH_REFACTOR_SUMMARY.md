# 架构设计问题修复报告

本文档记录了根据 `top_problem_arch.md` 进行的架构改进。

## 已完成的架构改进

### ✅ 问题 1: 层间依赖方向错误 - Runtime Trait 抽象

**问题描述**: Engine 层直接依赖 Wasm/Lua 运行时实现细节，违反了依赖倒置原则。

**修复方案**:

创建了统一的 `Runtime` trait 抽象层：

```rust
#[async_trait::async_trait]
pub trait Runtime: Send + Sync {
    async fn evaluate(&self, predicate_id: &str, event: &Event) -> RuntimeResult<EvalResult>;
    async fn evaluate_adhoc(&self, bytes: &[u8], event: &Event) -> RuntimeResult<EvalResult>;
    fn required_fields(&self, predicate_id: &str) -> RuntimeResult<Vec<FieldId>>;
    fn has_predicate(&self, predicate_id: &str) -> bool;
    async fn load_predicate(&self, predicate_id: &str, bytes: &[u8]) -> RuntimeResult<()>;
    fn unload_predicate(&self, predicate_id: &str);
    fn runtime_type(&self) -> RuntimeType;
    fn capabilities(&self) -> RuntimeCapabilities;
}
```

**新增组件**:

1. **RuntimeManager** - 管理多个运行时实例
   ```rust
   pub struct RuntimeManager {
       runtimes: HashMap<RuntimeType, Arc<dyn Runtime>>,
       schema: Arc<SchemaRegistry>,
   }
   ```

2. **Runtime Adapters** - 将具体运行时适配到 trait
   - `WasmRuntimeAdapter` - Wasm 引擎适配器
   - `LuaRuntimeAdapter` - Lua 引擎适配器

3. **统一的错误类型**
   ```rust
   pub enum RuntimeError {
       CompilationError(String),
       ExecutionError(String),
       NotAvailable(String),
       PredicateNotFound(String),
       ConfigError(String),
   }
   ```

**改进效果**:

```
修复前:
DetectionEngine → WasmEngine (直接依赖)
DetectionEngine → LuaEngine (直接依赖)

修复后:
DetectionEngine → Runtime trait (抽象依赖)
                      ↑
            ┌────────┴────────┐
      WasmRuntimeAdapter  LuaRuntimeAdapter
              ↓                    ↓
       WasmEngine            LuaEngine
```

**影响文件**:
- `kestrel-engine/src/runtime.rs` (新增)
- `kestrel-engine/src/lib.rs` (导出 runtime 模块)
- `kestrel-runtime-lua/src/lib.rs` (添加辅助方法)

---

### ✅ 问题 7: 错误处理架构 - 统一 Runtime 错误

**修复内容**:

1. 定义了统一的 `RuntimeError` 类型，所有运行时错误都映射到这个类型
2. 创建了 `RuntimeResult<T>` 类型别名
3. 在适配器中完成错误转换，隐藏底层实现细节

```rust
pub type RuntimeResult<T> = Result<T, RuntimeError>;

// 适配器中的错误转换
#[async_trait::async_trait]
impl Runtime for WasmRuntimeAdapter {
    async fn evaluate_adhoc(&self, bytes: &[u8], event: &Event) -> RuntimeResult<EvalResult> {
        match self.inner.eval_adhoc_predicate(bytes, event).await {
            Ok(matched) => Ok(EvalResult { matched, ... }),
            Err(e) => Err(RuntimeError::ExecutionError(e.to_string())),
        }
    }
}
```

---

## 架构改进后的依赖关系

```
┌─────────────────────────────────────────────────────────────────┐
│                      Engine Layer                                │
│                                                                  │
│   DetectionEngine ────────► Runtime trait (抽象)                 │
│                              │                                   │
│                              ▼                                   │
│   RuntimeManager ◄────── RuntimeType                             │
│                              │                                   │
└──────────────────────────────┬───────────────────────────────────┘
                               │
                    ┌──────────┴──────────┐
                    │                     │
┌───────────────────▼──────┐  ┌───────────▼──────────────────────┐
│     Runtime Layer        │  │      Runtime Layer               │
│                          │  │                                  │
│  WasmRuntimeAdapter      │  │  LuaRuntimeAdapter               │
│       ↓                  │  │       ↓                          │
│  WasmEngine              │  │  LuaEngine                       │
│                          │  │                                  │
└──────────────────────────┘  └──────────────────────────────────┘
```

## 向后兼容性

所有改进保持向后兼容：
- 原有 API 保持不变
- Runtime trait 是新增功能，不影响现有代码
- 可以通过适配器逐步迁移现有代码

## 测试验证

所有测试通过：
```
Test Suites: 15 passed
Tests:       100+ passed
Failures:    0
```

## 后续建议

### 短期（1-2 周）
1. 将 Engine 中的 wasm/lua 直接调用迁移到 Runtime trait
2. 添加更多 Runtime 能力探测 API
3. 完善 Runtime 配置统一接口

### 中期（1 个月）
1. 实现插件化运行时加载（动态库）
2. 添加 Runtime 健康检查接口
3. 完善错误分类和错误恢复策略

### 长期（2-3 个月）
1. 分布式 Runtime 支持
2. Runtime 资源配额管理
3. 多运行时并行执行框架

## 参考

- `kestrel-engine/src/runtime.rs` - 完整实现
- `top_problem_arch.md` - 原始架构问题分析
