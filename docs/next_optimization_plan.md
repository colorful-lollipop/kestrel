# Kestrel 下一阶段优化方向分析

**日期**: 2026-03-07
**基于**: 全量代码审查 + 测试分析 + 热路径审计 + eBPF 采集层审查

---

## 一、当前状态总结

| 维度 | 状态 |
|------|------|
| 测试 | 1,203 个测试全部通过，0 失败，1 ignored |
| 编译 | 全 workspace 编译成功，存在若干 unused warnings |
| Clippy | **clippy.toml 配置损坏**，3 个无效 key 导致无法运行 |
| eBPF 采集 | 3/7 事件类型已实现（ProcessExec, FileOpen, NetworkConnect） |
| LSM 阻断 | 框架完成，内核侧仅 in-memory stub，无真实阻断 |
| 场景验证 | 4 个攻击场景已定义，受限于缺失事件类型 |

---

## 二、发现的问题（按优先级排序）

### P0: 基础设施问题（必须先修）

#### 1. clippy.toml 配置损坏
clippy 完全无法运行，CI 形同虚设。

**无效配置项**:
- `missing-docs-in-private-items` → 应为 `missing-docs-in-crate-items`
- `suppress-lint-ignore-strings` → 不存在的配置项
- `macro-max-params-stack-size` → 不存在的配置项

**影响**: 所有 `cargo clippy` 命令失败，代码质量门禁失效。
**修复成本**: 小（删除/修正 3 行）

#### 2. 编译警告清理
多个 crate 存在 unused 警告:

| Crate | 警告 |
|-------|------|
| kestrel-runtime-lua | unused field `rule_id`, `init_func` |
| kestrel-hybrid-engine | unused field `schema` |
| kestrel-ebpf | 5 个 unused fields/variables |
| kestrel-ffi | unused `set_last_error()`, `get_last_error()`, field `config` |
| kestrel-benchmark | unused function `run_throughput_benchmarks()`, unnecessary mut |

**影响**: 降低代码质量信号，掩盖真正的问题。

---

### P1: 运行时热路径性能瓶颈（核心竞争力）

#### 3. NFA Engine 全局 Mutex 序列化（CRITICAL）
**位置**: `kestrel-engine/src/lib.rs:801,820`

```rust
nfa_engine: &Arc<Mutex<Option<NfaEngine>>>,
// 每个事件都要获取这个锁
let mut guard = nfa_engine.lock().await;
```

**问题**: 所有事件的 NFA 处理被单一 Mutex 串行化，无论有多少 worker 线程，NFA 吞吐量上限 = 单线程。
**影响**: 这是整个系统的最大瓶颈，直接决定 EPS 上限。

#### 4. Budget Tracker Write Lock 在每次谓词评估时获取（CRITICAL）
**位置**: `kestrel-nfa/src/engine.rs:159,457-461`

```rust
let mut tracker = self.budget_tracker.write(); // 每次谓词评估
```

**问题**: 每个谓词评估都获取 write lock，数百个谓词/事件 → 严重竞争。
**建议**: 改为 AtomicU64 计数器 + 周期性窗口检查。

#### 5. PredicateEvaluator 同步接口阻塞异步运行时（CRITICAL）
**位置**: `kestrel-runtime-wasm/src/lib.rs:994-1005`

```rust
tokio::task::block_in_place(|| {
    tokio::runtime::Handle::current().block_on(async {
        engine.eval_loaded_predicate(rule_id, predicate_index, event).await
    })
})
```

**问题**: PredicateEvaluator trait 是同步的，但 Wasm 引擎是异步的，导致 block_in_place 调用。在 NFA 热路径中，每个 step 评估都会阻塞 tokio worker thread。
**建议**: 将 PredicateEvaluator trait 改为 async，或提供同步 Wasm 评估路径。

#### 6. SingleEventRule 每事件全量 Clone（CRITICAL）
**位置**: `kestrel-engine/src/lib.rs:722`

```rust
let single_event_rules_snapshot = { single_event_rules.read().await.clone() };
```

**问题**: 每个 batch 中的每个事件都 clone 整个规则列表。O(M×B) 次 clone，M=规则数，B=batch 大小。
**建议**: Arc 包装规则快照，batch 级别获取一次即可。

#### 7. NFA 事件处理中多次 Event Clone（HIGH）
**位置**: `kestrel-nfa/src/engine.rs:265,342,365`

**问题**: 每个事件在 NFA 处理中被 clone 3+ 次（序列查找、partial match 创建、advance 推进）。Event 包含 AHashMap<u32, TypedValue>，clone 成本高。
**建议**: 传递 &Event 引用，仅在需要存储 capture 时 clone 必要字段。

#### 8. Glob 匹配中的 block_in_place（HIGH）
**位置**: `kestrel-runtime-wasm/src/lib.rs:582-584`

```rust
let cache_guard = tokio::task::block_in_place(|| {
    tokio::runtime::Handle::current().block_on(cache.read())
});
```

**问题**: Wasm host API 中 glob 匹配使用 block_on，阻塞 tokio worker。
**对比**: regex 匹配使用 try_read()（正确做法）。

#### 9. NFA Metrics RwLock 在每个事件上多次获取（HIGH）
**位置**: `kestrel-nfa/src/engine.rs:243,259`

**问题**: 每个事件触发多次 `self.metrics.read()` 获取。Metrics 应该是无锁的（纯 Atomic）。

#### 10. Wasm Instance Pool 过小 + 双重锁（MEDIUM）
**位置**: `kestrel-runtime-wasm/src/lib.rs:814-824`

**问题**: 默认 4 个实例，Semaphore + Mutex 双重获取。高并发下成为瓶颈。

#### 11. Regex/Glob 缓存无上限（MEDIUM）
**位置**: `kestrel-runtime-wasm/src/lib.rs:91-92,902-912`

**问题**: 缓存无 LRU/大小限制，长时间运行可能 OOM。

---

### P2: eBPF 采集层补齐

#### 12. 缺失关键事件类型

| 事件类型 | 状态 | 影响 |
|----------|------|------|
| ProcessExit | 未实现 | 进程生命周期不完整，无法做 exit_code 关联 |
| FileRename | 未实现 | 勒索软件检测场景失效 |
| FileUnlink | 未实现 | 文件删除行为不可见 |
| NetworkSend | 未实现 | 数据外泄检测受限 |

**影响**: 4 个攻击场景中的 ransomware 场景无法完整验证。

#### 13. 字段规范化不完整

缺失字段:
- 文件: mode, permissions, size, owner, group
- 网络: source_port, protocol, direction, IPv6
- 进程: parent_executable, environment_vars

#### 14. LSM 阻断仅为 Stub
**位置**: `kestrel-ebpf/src/lsm.rs`

**现状**: 决策引擎完整，但 LSM attach 仅 log 不执行真实阻断。需要通过 aya 真正 attach 到内核 LSM hooks。

---

### P3: 测试覆盖缺口

#### 15. 关键 crate 无测试

| Crate | 测试文件数 | 风险 |
|-------|-----------|------|
| kestrel-cli | 0 | CLI 子命令逻辑无验证 |
| kestrel-ffi | 0 | C ABI 兼容性无保证 |
| kestrel-runtime-lua | 0 | Lua 运行时功能无验证 |
| kestrel-ac-dfa | 0 | AC-DFA 实现无独立测试 |

#### 16. 未完成的 TODO

| 位置 | 内容 |
|------|------|
| `kestrel-runtime-wasm/src/lib.rs:1009` | Implement field tracking for Wasm predicates |
| `kestrel-eql/src/codegen_wasm.rs:1105` | Implement proper array iteration via Host API |
| `kestrel-eql/src/codegen_wasm.rs:1117` | Iterate over array elements |

---

## 三、推荐优化路线

### Phase N1: 基础修复（1-2 天）
> 目标: 恢复代码质量门禁，清理噪音

1. 修复 clippy.toml 3 个无效配置项
2. 运行 `cargo clippy --workspace` 修复所有 warnings
3. 清理编译 unused warnings
4. 验证 CI pipeline 可通过

### Phase N2: 热路径去锁化（1-2 周）
> 目标: 解除 NFA 串行化瓶颈，预期 3-5x EPS 提升

**按优先级排序:**

1. **NFA Engine 去 Mutex**:
   - 方案 A: NFA Engine 改为 per-partition 独立实例（每个 EventBus partition 一个 NFA）
   - 方案 B: NFA Engine 内部改为 sharded state（按 entity_key 分片）
   - 推荐方案 A，与 EventBus partition 天然对齐

2. **PredicateEvaluator async 化**:
   - 将 trait 改为 async fn evaluate()
   - 消除 Wasm 路径中的 block_in_place

3. **Budget Tracker 改 Atomic**:
   - RwLock → AtomicU64 计数器
   - 窗口重置用 compare_exchange

4. **规则快照 Arc 化**:
   - SingleEventRule Vec 用 Arc<Vec> 包装
   - batch 级别获取一次快照

5. **Event 引用传递**:
   - NFA process_event 接受 &Event
   - 仅在 capture 时 clone 必要字段

6. **Metrics 去锁**:
   - 将 RwLock<NfaMetrics> 改为 Arc<NfaMetrics>（内部全 Atomic）
   - 去掉 metrics 访问的 read() 调用

### Phase N3: eBPF 事件补齐（2-3 周）
> 目标: 覆盖 4 大攻击场景的全部事件类型

1. 实现 ProcessExit 采集（tracepoint: sched_process_exit）
2. 实现 FileRename 采集（LSM: path_rename 或 kprobe: vfs_rename）
3. 实现 FileUnlink 采集（LSM: path_unlink 或 kprobe: vfs_unlink）
4. 补齐 normalize.rs 对应字段
5. 验证 ransomware 场景端到端

### Phase N4: 测试加固 + Battle Lab 闭环（2-3 周）
> 目标: 规则开发 → 场景验证 → 回放复现 完整闭环

1. 为 kestrel-cli 添加集成测试
2. 为 kestrel-ffi 添加 C 集成测试
3. 为 kestrel-runtime-lua 添加功能测试
4. 完善 kestrel-lab 场景执行器
5. 4 个攻击场景全部可跑通 + 断言通过
6. 实现 EQL codegen 的 array iteration TODO

---

## 四、预期收益

| 优化 | 预期收益 |
|------|---------|
| NFA 去 Mutex + per-partition | EPS 提升 3-5x（当前瓶颈在锁） |
| PredicateEvaluator async 化 | Wasm 谓词不再阻塞 worker |
| Event 引用传递 | 内存分配降低 50%+（NFA 路径） |
| Budget Tracker Atomic | 谓词评估不再串行 |
| 规则快照 Arc 化 | 每 batch 减少 O(M×B) clone |
| eBPF 事件补齐 | 4 个攻击场景可完整验证 |
| clippy 修复 | 代码质量门禁恢复 |

---

## 五、风险与注意事项

1. **NFA 去 Mutex 改动面大**: 需要保证 per-partition NFA 的状态隔离正确性，特别是跨 entity 的序列（目前按 entity_key 分组，天然隔离）
2. **PredicateEvaluator async 化**: 会影响所有实现方（Wasm/Lua/测试 mock），是一个 breaking change
3. **eBPF hooks 需要内核权限**: FileRename/FileUnlink 的 hook 点选择要考虑内核版本兼容性
4. **LSM 真实阻断**: 从 stub 到真实阻断是一个安全敏感的改动，建议先做 detect-only 验证
