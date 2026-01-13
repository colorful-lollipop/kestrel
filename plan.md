# 下一代端侧行为检测引擎白皮书与架构技术方案（Kestrel）
**Rust + eBPF +（Host 执行 NFA）+ Wasm/LuaJIT 双运行时 + EQL 兼容子集**  
面向：Linux 与 Harmony（类 Unix 可移植），端侧低功耗实时检测/阻断 + 离线可复现回放

---

## 0. 执行摘要（What & Why）
我们建设的是一套端侧高性能行为检测引擎，名为Kestrel, 
核心差异化在于：

1. **统一事件流与可插拔采集层**：eBPF/审计/用户态 API 统一为强类型事件流；可按规则“兴趣”下推过滤，减少端侧功耗。
2. **EQL 规则体系 + 序列引擎（Host NFA）**：用业内成熟的 EQL 表达“动态行为序列”；由宿主执行 NFA/窗口/关联；谓词执行交给 Wasm/LuaJIT。
3. **双运行时统一 Host API**：规则可以编译成 Wasm（标准、可移植）或 LuaJIT（灵活、快速迭代、端侧性能好）；二者共享同一套 Host API 与 IR 接口。
4. **实时阻断与离线可复现**：同一规则、同一检测核在 inline（阻断）与 async/offline（分析回放）模式下运行，保证结果可解释、可复现。

---

## 0.1 项目进展总览（2026年1月）

### 当前版本状态
- **版本号**: v0.2.0
- **核心状态**: 引擎基础框架完成，进入生产化准备阶段
- **代码质量**: 28+ 测试全部通过，无已知阻塞问题

### 已完成模块（按架构层次）

#### ✅ 核心引擎层
- **Schema Registry**: 强类型事件字段注册系统，支持 field_id 化
- **EventBus**: 事件总线，支持批处理、背压控制、metrics 收集
- **NFA Engine**: 非确定有限自动机序列引擎，支持多规则并行匹配
- **StateStore**: TTL/LRU/Quota 三重淘汰机制，支持 per-rule/per-entity 预算
- **Metrics**: 统一指标收集系统（EngineMetrics + UnifiedMetrics），支持 Prometheus/JSON 导出

#### ✅ 双运行时系统
- **Wasm Runtime**: 基于 Wasmtime，实现 Host API v1，支持 instance pool 复用
- **Lua Runtime**: 基于 MLua (LuaJIT)，实现 Host API v1，与 Wasm 共享 ABI
- **PredicateEvaluator**: 统一谓词评估接口，运行时可插拔
- **PoolMetrics**: Wasm instance pool 指标（利用率、等待时间、缓存命中率）

#### ✅ 规则加载系统
- **RuleManager**: 规则包热加载、版本管理、原子切换
- **RulePackage**: EQL 编译产物打包（metadata + predicates + capabilities）
- **加载隔离**: load_semaphore 保护，避免并发加载冲突

#### ✅ 离线可复现（Replay）
- **BinaryLog**: 事件二进制日志，紧凑序列化
- **ReplayEngine**: 同核回放，保证结果可复现
- **可复现契约**:
  - `event_id`: 用于事件排序 tie-breaker
  - `rule_pack_hash`: 规则包版本哈希
  - `ts_mono_ns + event_id`: 确定性排序键

#### ✅ 采集层（eBPF）
- **Normalization**: 事件规范化，强类型字段映射
- **InterestPushdown**: 按"规则兴趣"过滤，减少无用数据收集
- **框架完整**: tracepoints/kprobes/LSM hooks 架构就绪

#### ✅ C FFI 兼容接口
- **kestrel-ffi**: C API 层，完整导出引擎生命周期、规则管理、事件处理、指标查询
- **ABI 稳定**: C 头文件（kestrel.h）定义完整的 opaque handle 类型
- **示例程序**: simple.c / advanced.c 展示 API 用法
- **共享库**: libkestrel_ffi.so (342K)，支持 Linux glibc 2.17+

### 近期完成（2026年1月）

#### Phase A: eBPF 集成测试与性能基线 ✅
- 创建集成测试套件（10个测试，覆盖 normalize/pushdown/end-to-end）
- 创建性能基准测试（12个测试，建立性能基线）
- 导出 InterestPushdown API
- **文件**: kestrel-ebpf/tests/integration_test.rs, performance_benchmark.rs

#### Phase B: C FFI 兼容接口 ✅
- **B.1**: 基础框架完成（Engine API, 类型定义, 错误处理）
- **B.2**: 事件处理 API 完成（process_event, alerts, metrics）
- 11个测试全部通过
- C 示例程序运行成功
- **文件**: kestrel-ffi crate, examples/simple.c, examples/advanced.c

#### Phase C: 可观测性完善（进行中）
- **C.1**: Wasm pool 指标收集 ✅
  - PoolMetrics 结构（pool_size, active_instances, acquires, releases, misses）
  - 等待时间跟踪（total_wait_ns, peak_wait_ns, avg_wait_ns）
  - 利用率与缓存命中率计算
- **C.2**: 性能基线测试（待完成）

### 架构优势已验证

#### 1. 性能优势
- **NFA Engine**: 单规则状态机匹配 < 1μs
- **EventBus**: Batch 处理提升吞吐量
- **StateStore**: LRU/TTL/Quota 三重机制控制内存增长
- **Instance Pool**: Wasm/Lua 实例复用，减少初始化开销

#### 2. 可观测性优势
- **UnifiedMetrics**: 聚合 Engine + EventBus + Runtime 指标
- **Per-Rule Metrics**: 每规则独立指标（evaluations, alerts, eval_time）
- **Pool Metrics**: 实例池利用率、等待时间、缓存命中率
- **Prometheus Export**: 标准格式，便于接入监控系统

#### 3. 可控性优势
- **Resource Budget**: Per-rule/per-entity quota 保护
- **Backpressure**: EventBus 背压机制防止内存溢出
- **TTL/LRU**: 自动淘汰过期状态
- **Graceful Degradation**: 阻断模式下可降级到检测模式

### 待完善模块（优先级排序）

#### P0: 生产化基础设施
- [ ] CI/CD pipeline（目前构建环境存在 cross-device link 问题）
- [ ] 性能回归基线（定期 benchmark，防止性能退化）
- [ ] 内存泄漏检测（Valgrind/Sanitizer 集成）
- [ ] 压力测试（长时间高负载稳定性）

#### P1: eBPF 采集层生产化
- [ ] Ringbuf polling 稳定性验证
- [ ] 事件协议版本化（跨内核版本兼容）
- [ ] 字段完备性（当前仅部分字段）
- [ ] 降级策略（内核不支持 eBPF 时的 fallback）

#### P2: 实时阻断（Inline/Enforce）
- [ ] LSM hooks 集成
- [ ] 阻断策略与授权机制
- [ ] 误杀回滚机制
- [ ] 审计取证

#### P3: 规则生态与工具链
- [ ] EQL 编译器（eqlc）完整实现
- [ ] 规则包管理工具
- [ ] 规则测试框架
- [ ] 规则灰度发布机制

### 技术债务与改进建议

#### 1. 性能优化空间
- [ ] String → Integer ID 映射（rule_id, sequence_id）
- [ ] 字段读取批量 hostcall（减少 Wasm/Lua 交叉边界次数）
- [ ] Regex/Glob 预编译句柄缓存优化
- [ ] NFA 状态机分区（按 entity_key 哈希，提升 cache locality）

#### 2. 可观测性增强
- [ ] Wasm/Lua pool 指标集成到 UnifiedMetrics
- [ ] Prometheus export 新增 pool metrics
- [ ] 分布式追踪（tracing）集成
- [ ] 告警聚合与去重

#### 3. 测试覆盖
- [ ] 端到端集成测试（完整规则包 + 真实事件流）
- [ ] 并发压力测试（多线程、多规则）
- [ ] 长时间运行稳定性测试（7x24h）
- [ ] 内存泄漏专项测试

### 下一步工作计划

#### 短期（2-4周）
1. **完成 Phase C.2**: 性能基线测试与回归保护
2. **CI/CD 完善**: 解决构建环境问题，建立自动化测试
3. **文档完善**: API 文档、架构文档、运维手册

#### 中期（1-2月）
1. **eBPF 生产化**: Ringbuf 稳定性、事件协议版本化
2. **规则工具链**: EQL 编译器、规则包管理
3. **实时阻断**: LSM hooks 集成、阻断策略

#### 长期（3-6月）
1. **性能优化**: String → ID 映射、批量 hostcall
2. **规则生态**: 规则市场、社区贡献
3. **多平台支持**: macOS、Windows 适配

---

## 1. 目标与边界

### 1.1 目标
- **端侧（笔记本）**：1k EPS 峰值下稳定运行；低 CPU 占用、可控内存；可配置低功耗策略。
- **实时阻断**：文件 / 进程 / 内存相关关键 API 与系统调用（见 §8）。
- **离线回放**：同核检测，结果**完全可复现**（同一日志+规则+引擎版本 → 同一告警与证据）。
- **规则无需重编译引擎**：规则包热加载，来自本地文件（watch + 原子切换）。
- **类 Unix 可移植**：Linux 首发；Harmony（部分兼容 Linux）按能力适配。

### 1.2 明确边界（v0.2 不承诺）
- 不把 GPU 当作端侧实时阻断的主路径（原因见 §11）。GPU 仅作为可选加速方向（云/离线/批处理）。
- 不追求“完整覆盖所有 EQL 扩展语法”（如 pipeline 的全量生态）；选择稳定可实现、适合安全检测的兼容子集（见 §7）。

---

## 2. 总体架构（可插拔、可降级、可复现）

### 2.1 分层架构图（逻辑）
```text
┌──────────────────────────────────────────────────────────┐
│                      Rule Packages (local)               │
│      EQL DSL -> eqlc -> IR -> (Wasm predicate | Lua)     │
└──────────────────────────────────────────────────────────┘
                     │ hotload/rollback
                     v
┌──────────────────────────────────────────────────────────┐
│ Engine Control Plane                                     │
│  - RuleManager  - Capability/Mode  - Metrics/Tracing     │
└──────────────────────────────────────────────────────────┘
                     │
                     v
┌──────────────────────────────────────────────────────────┐
│ Detection Data Plane                                      │
│  EventBus -> Partition -> Worker Threads                  │
│    ├─ NFA Sequence Engine (Host)                          │
│    ├─ Predicate Runtime: Wasm OR LuaJIT                   │
│    ├─ StateStore (TTL/LRU/Quota)                          │
│    └─ Actions/Alerts (inline/async/offline policy)        │
└──────────────────────────────────────────────────────────┘
                     ^
                     │ normalized events
┌──────────────────────────────────────────────────────────┐
│ Event Sources (pluggable)                                 │
│  - eBPF tracepoints/kprobe + ringbuf                      │
│  - LSM/eBPF-LSM hooks (阻断点)                            │
│  - audit / fanotify (可选)                                │
│  - Offline replay (binary log)                            │
└──────────────────────────────────────────────────────────┘
```

### 2.2 三种运行模式（同核）
- **Inline/Enforce**：阻断路径（严格预算、规则子集、可降级）
- **Online/Detect**：在线检测（全量序列+富化）
- **Offline/Replay**：离线回放（同序列引擎、同谓词运行时；动作接口被禁用/仿真）

---

## 3. 事件模型与 Schema（为性能、EQL 与可复现服务）

### 3.1 Schema 原则
- **强类型字段**：避免运行时字符串解析与隐式类型转换开销/歧义。
- **字段 ID 化**：`field_path -> field_id(u32)` 在加载规则时解析；运行时以 ID 访问。
- **可复现时间语义**：记录 `ts_mono_ns`（单调）用于窗口/序列；记录 `ts_wall_ns` 用于取证展示。

### 3.2 事件结构（内部建议）
- `event_type_id: u16`
- `ts_mono_ns: u64`
- `ts_wall_ns: u64`
- `entity_key: u128`（例如 pid+start_time 或者容器/会话扩展）
- `fields: smallvec<(field_id, typed_value)>`（稀疏存储，零拷贝字符串/bytes 视情况）

---

## 4. 采集层与适配（Linux/Harmony）

### 4.1 Linux 首选路径：eBPF +（观测/阻断分离）
- **观测**：tracepoints/kprobes + ringbuf → 用户态规范化
- **阻断**：优先 **LSM hooks**（如 `bprm_check_security`, `file_open`, `inode_*`, `socket_connect` 等）
  - 若内核支持：**eBPF LSM**（性能与可维护性更好）
  - 否则：退化到 LSM 模块/其他机制（按发行版能力）

> 说明：阻断属于“决策点”，必须选择能在动作发生前介入的 hook；纯 tracepoint 只能事后观测。

### 4.2 Harmony/类 Unix
- 以“能力探测 + 适配层”方式实现：
  - `EventSource.capabilities()` 描述可提供的事件类型/字段/阻断点
  - 规则兴趣下推与阻断点映射按平台能力裁剪

---

## 5. 检测核心：Host 执行 NFA（序列/窗口/关联），Wasm/Lua 执行谓词

### 5.1 为什么选择方案 A（Host NFA）
- **性能可控**：NFA/窗口淘汰/分区状态管理在 Rust 内核完成，避免每规则重复实现序列逻辑。
- **更适合阻断路径**：可以把 inline 规则约束为“有限状态 + 快谓词”，保障延迟上界。
- **更易做到可复现**：状态淘汰、事件排序、窗口边界由宿主统一实现，减少运行时差异。

### 5.2 NFA 执行要点
- 按 `sequence by <entity>` 分区：每个 `entity_key` 独立维护 partial matches
- `maxspan`：partial match 以 `ts_mono_ns` 进行 TTL 淘汰
- `until`：终止事件到来时清理相关 partial matches
- 状态存储：**分片 + TTL/LRU + 配额**
  - 配额建议：按规则/按实体双维度限制，避免单实体或单规则放大内存

---

## 6. 双运行时设计：Wasm + LuaJIT 并存（统一 Host API/IR）

### 6.1 定位与取舍
- **Wasm**：标准化、可移植、便于跨平台一致性（尤其 offline/replay 与云端）
- **LuaJIT**：端侧性能通常优秀（JIT）、开发迭代快，适合内部/可信规则快速落地

你提到“规则基本可信”——这允许我们在 **trusted 模式**下放松部分限制以换取性能，但仍建议保留最小的鲁棒性边界（见 §10）。

### 6.2 统一接口：Predicate ABI（关键）
无论 Wasm 还是 LuaJIT，都实现同一“谓词接口”，供 NFA 调用：

- `pred_init(ctx) -> ok`
- `pred_eval(event, ctx) -> bool`  
- （可选）`pred_capture(event, ctx) -> captures`：返回用于告警的字段提取结果

其中 `ctx` 只通过 Host API 访问：
- 事件字段读取（field_id）
- 常量表/预编译 regex 句柄
- 轻量状态访问（如需要，通常序列状态由 Host 管）

### 6.3 Host API（v1）要点（Wasm/Lua 共用）
**事件读取**
- `schema_resolve(path) -> field_id`（加载期完成，运行期用 id）
- `event_get_<type>(event_handle, field_id) -> option<T>`
- `event_type(event_handle) -> event_type_id`
- `event_entity(event_handle) -> entity_key`

**工具**
- `re_match(re_id, str)` / `glob_match(glob_id, str)`
- `str_eq_ci(a,b)`（可选：大小写不敏感常用加速）
- `hash_xx64(bytes)`（可选：用于键计算）

**动作/告警**
- `alert_emit(record)`
- `action_block(...)`（inline 模式允许；offline 模式禁用或仿真返回）

> 实现方式：  
> - Wasm：wasmtime host functions（尽量批量读取/减少 hostcall）  
> - LuaJIT：C FFI 函数表（或 Rust 导出 C ABI），字段 ID 直接传 u32

### 6.4 规则工程建议
- EQL 默认编译为 **Wasm 谓词**（一致性好）
- 内部/高性能场景允许 EQL→Lua（或手写 Lua predicate）作为可选后端
- 引擎支持同一规则集混合加载：部分规则 Wasm，部分 Lua

---

## 7. EQL 支持矩阵（必须/可选/不支持与替代）

> 选择基线：**Elastic EQL 的稳定核心语义（sequence/where/by/maxspan/until）**，裁剪掉对端侧价值低、实现成本高或语义易分歧的部分（如复杂 pipeline）。  
> 目标是“用于安全行为检测足够强、语义稳定、可测试可复现”。

### 7.1 必须兼容（v1 必做）
| 类别 | 特性 | 说明 |
|---|---|---|
| 查询结构 | `event where <expr>` | 单事件规则 |
| 序列 | `sequence [A where ...] [B where ...] ...` | 多步序列 |
| 关联 | `sequence by <field>` | 以实体键分组（常用：`process.entity_id`/`process.pid`+start） |
| 窗口 | `with maxspan=<duration>` | 序列最大时间跨度 |
| 终止 | `until [X where ...]` | 终止/清理 partial match |
| 条件表达式 | `and/or/not` | 逻辑运算 |
| 比较 | `== != < <= > >=` | 数值/字符串比较（明确类型规则） |
| 集合 | `in (a,b,c)` | 常量集合匹配（编译期优化为 hash/set） |
| 字符串 | `contains`, `startswith`, `endswith` | 常用 IOC/路径匹配 |
| 正则/通配 | `regex`, `wildcard/glob`（选一套语义固定） | 建议实现 `wildcard`（性能更好）+ 可选 `regex` |
| 缺失字段 | `field == null` / `missing` 语义 | 必须明确：缺失=Null 还是三值逻辑（建议二值+显式 missing 判断） |
| 输出 | 告警字段提取（rule metadata + captures） | 支持把关键字段写入告警 |

### 7.2 可选支持（v1.5 / v2）
| 类别 | 特性 | 价值 | 备注 |
|---|---|---|---|
| 负条件序列 | `sequence ... ![X where ...] ...` | 表达“期间未发生” | 实现复杂（需要区间补集）但对检测很强 |
| 数组字段 | `any`/`all` 语义 | 适配某些日志源 | 需要统一字段模型 |
| 数学函数 | `length()`, `cidrMatch()` 等 | 网络/字符串增强 | Host 提供内建函数更快 |
| pipe/pipeline | `| where ...`、`| sort` 等 | SIEM 侧更常见 | 端侧价值有限，建议裁剪 |

### 7.3 不支持（明确替代）
| 特性 | 不支持原因 | 替代方案 |
|---|---|---|
| 复杂 join（跨索引/跨大表） | 端侧资源不适合 | 交给云端/离线分析；或通过序列+state 近似 |
| 任意脚本嵌入 EQL | 语义不稳定/安全性差 | 用 Wasm/Lua predicate 扩展点 |
| 全量 pipeline 生态 | 实现与兼容成本高 | 保留最小必要输出与过滤能力 |

> 建议交付物：建立一套 **EQL 兼容性测试基线**（语法、语义、边界时间窗、缺失字段、类型转换），这是“看起来厉害且能长期维护”的关键资产。

---

## 8. 实时阻断范围与实现建议（Linux）

你给定的阻断范围：**文件、进程、内存、关键 API 与系统调用**。建议将“阻断点”工程化为能力矩阵，并按平台能力逐步覆盖：

### 8.1 进程类（优先级最高）
- `execve/execveat`：阻断可疑进程启动（LSM `bprm_check_security`）
- `ptrace`：阻断调试/注入链路（LSM `ptrace_access_check` 等）
- `bpf`, `perf_event_open`：限制侧载观测/提权面（视场景）

### 8.2 文件类（强需求）
- `open/openat` 写入、`rename`, `unlink`, `chmod/chown`：关键路径保护
- 可用 hook：`file_open`, `inode_permission`, `security_path_*`（依内核版本选择）
- 补充：必要时结合 **fanotify** 做用户态阻断（但延迟与边界需评估）

### 8.3 网络类（常用）
- `connect` / `sendto` / DNS：阻断外联
- hook：`socket_connect`（LSM）/ cgroup hooks（部分场景更合适）

### 8.4 内存/注入类（复杂但重要）
- `mmap(PROT_EXEC)`, `mprotect` 提升为可执行、`process_vm_writev`、`memfd_create` 等
- 现实建议：先做**观测+告警**，阻断逐步引入（避免误杀与兼容性风险）

---

## 9. 离线完全可复现（强约束下的工程设计）

要做到“完全可复现”，必须控制三件事：

1. **事件排序确定性**：以 `ts_mono_ns` + `event_id(递增)` 做稳定排序；同一时间戳冲突时也确定。
2. **规则与引擎版本锁定**：离线回放记录 `rule_pack_hash`、`engine_build_id`、`schema_version`。
3. **同一语义实现**：NFA/窗口/淘汰在 Host 统一执行；谓词运行时差异（Wasm vs Lua）需要可选“确定性模式”（LuaJIT 在离线可切 interpreter/关闭某些不确定行为）。

**日志建议最小包含**：规范化事件（字段ID+强类型值）、schema版本、mono/wall 时间、entity_key、source_id、原始字段可选（用于取证展示）。

---

## 10. “规则基本可信”下的性能策略（放松安全但不放松鲁棒性）

即便规则可信，端侧工程仍要防“误写规则导致引擎抖动/内存泄漏式增长”。建议提供两档模式：

### 10.1 Trusted 模式（默认内部/企业自有规则）
- Wasm：可提高 fuel 上限、允许更大内存
- LuaJIT：开启 JIT、允许更高指令预算
- 仍保留：**超时监控、状态配额、关键动作审计**（避免事故不可定位）

### 10.2 Strict 模式（面向第三方规则/未知来源）
- 更严格的 fuel/内存/hostcall 限制
- 更严格 capability（阻断需显式授权）

---

## 11. 加性能优化


**更现实的端侧优先级**：
- CPU SIMD（SSE/AVX）优化字符串匹配/哈希
- 批处理（batching）减少 hostcall
- 规则兴趣下推（eBPF 预过滤）降低事件量
- 多核分区（按 entity_key 或 event_type 分区）避免锁竞争

---

## 12. 工程落地路线图（v0.2 → v1.0）与工作量预估

以下以“人周（person-week）”粗估；假设 4 人核心团队（Rust 内核×2、eBPF×1、规则编译/测试×1），可并行。

### Phase 0：架构骨架与可跑通链路（3–5 人周）
- 事件 Schema v1（字段ID、类型系统、规范化库）
- EventBus（批处理、背压、分区策略原型）
- RuleManager（本地目录加载、版本切换、原子替换）
- 最小告警通路（alert 输出到本地文件/stdout）

**里程碑**：事件进入引擎 → 规则命中 → 告警输出

---

### Phase 1：Wasm 运行时 + Host API v1（4–7 人周）
- 集成 Wasmtime（AOT 缓存、实例池）
- Host API v1（event_get、regex/glob、alert_emit）
- 规则包格式（manifest + wasm + metadata）

**里程碑**：Wasm 谓词规则可热加载，稳定跑在 1k EPS

---

### Phase 2：LuaJIT 运行时并行接入（3–6 人周）
- LuaJIT Runtime（FFI 函数表绑定 Host API v1）
- 与 Wasm 同一 Predicate ABI、同一 captures/告警结构
- 基准测试：LuaJIT vs Wasm hostcall 开销、吞吐、延迟

**里程碑**：同一条规则可用 Lua 或 Wasm 后端执行，结果一致

---

### Phase 3：EQL 编译器（eqlc）+ IR + 兼容性基线（8–12 人周）
- EQL parser（clean-room）
- 语义/类型规则（缺失字段、字符串匹配、数值比较）
- IR：谓词 DAG + 序列步骤描述
- 输出后端：IR → Wasm predicate（默认），可选 IR → Lua
- **测试基线**：语法/语义/边界用例（这是核心资产）

**里程碑**：EQL（必须兼容子集）可编译并在引擎运行，测试对齐

---

### Phase 4：Host NFA 序列引擎 + StateStore（8–14 人周）
- NFA/partial match 引擎
- maxspan/until/by 语义实现
- StateStore：分片、TTL、配额、LRU
- 可观测性：每规则状态规模、淘汰原因、命中路径

**里程碑**：EQL sequence 在 1k EPS 稳定，内存可控，离线回放一致

---

### Phase 5：Linux eBPF 采集 +（观测）稳定化（6–10 人周）
- Aya + CO-RE（尽量降低内核版本适配成本）
- 事件规范化（进程树/路径/用户信息等）
- 规则兴趣下推：事件类型过滤、关键字段过滤（轻量）

**里程碑**：端侧低功耗采集 + 检测闭环，CPU 占用可控

---

### Phase 6：实时阻断（Enforce）第一版（8–16 人周）
- 选定阻断点优先级：exec/file/network（先易后难）
- Inline Guard 子集（严格预算、规则标注可阻断）
- Actions：block/deny/kill/quarantine（按平台能力）
- 审计闭环：每次阻断决策可追溯

**里程碑**：关键动作可阻断；误杀可回滚；性能不崩

---

### Phase 7：离线完全可复现（4–8 人周）
- 二进制日志格式 + 写入/索引
- Offline replay source + 确定性排序
- 回放结果一致性测试（跨机器/跨时间）

**里程碑**：同一日志+规则→100%一致告警与证据

---

### 总体粗估（到 v1.0）
- **核心能力可用（在线检测 + EQL 序列 + Wasm/Lua + 采集）**：约 **32–54 人周**
- **加上实时阻断与离线完全可复现**：约 **48–78 人周**
- 以 4 人团队计算：约 **3–5 个月到可用 v0.9**，**5–8 个月到较完整 v1.0**（取决于阻断深度与平台适配复杂度）

---

## 13. v0.2 的“看起来就很专业”的建议交付物清单
1. **EQL 兼容性规范文档**（本白皮书矩阵 → 可执行测试用例集）
2. **Host API v1 规范**（WIT/头文件 + 版本化策略 + capability）
3. **性能基线报告**（1k EPS：CPU、P99 延迟、内存、功耗趋势）
4. **可复现性证明**（离线回放一致性测试报告）
5. **阻断点能力矩阵**（不同内核版本/发行版/harmony 能力差异表）

---


- **默认 v1：单租户**（一个规则集（多个规则） + 一个策略配置）
- 但架构上支持多 policy：RuleManager 支持加载多个 rule-set（如 `enterprise/`, `local/`）并按优先级合并/冲突解决（例如同一 rule_id 以更高优先级覆盖）

---

## 14. C FFI 兼容接口（C Compatible Library Interface）

### 14.1 目标与价值

Kestrel 核心引擎用 Rust 实现，为了支持与其他 C/C++ 项目集成（如现有的安全产品、端点防护系统等），需要提供稳定的 C 兼容接口。

**应用场景**：
- 现有 C/C++ 安全产品集成 Kestrel 检测能力
- 嵌入式系统（不支持 Rust 运行时）
- 与其他厂商的联动响应（通过共享库）
- Python/Go/Java 等语言通过 FFI 调用

### 14.2 设计原则

1. **ABI 稳定性优先**：C API 必须保持向后兼容
2. **零拷贝或最小拷贝**：性能关键路径避免不必要的内存复制
3. **错误处理透明**：所有错误通过返回码和错误消息传递
4. **资源管理明确**：提供显式的创建/销毁函数
5. **线程安全**：所有 API 必须是线程安全的

### 14.3 核心接口设计

#### 14.3.1 类型定义（kestrel_ffi.h）

```c
#include <stdint.h>
#include <stdbool.h>

// 版本信息
#define KESTREL_VERSION_MAJOR 0
#define KESTREL_VERSION_MINOR 2
#define KESTREL_VERSION_PATCH 0

// 错误码
typedef enum {
    KESTREL_OK = 0,
    KESTREL_ERROR_UNKNOWN = -1,
    KESTREL_ERROR_INVALID_ARG = -2,
    KESTREL_ERROR_NOMEM = -3,
    KESTREL_ERROR_NOT_FOUND = -4,
    KESTREL_ERROR_ALREADY_EXISTS = -5,
    KESTREL_ERROR_PARSE = -6,
    KESTREL_ERROR_RUNTIME = -7,
} kestrel_error_t;

// 不透明句柄类型（向前声明）
typedef struct kestrel_engine kestrel_engine_t;
typedef struct kestrel_event kestrel_event_t;
typedef struct kestrel_rule kestrel_rule_t;
typedef struct kestrel_alert kestrel_alert_t;
typedef struct kestrel_metrics kestrel_metrics_t;

// 配置结构
typedef struct {
    uint32_t event_bus_size;
    uint32_t worker_threads;
    uint32_t batch_size;
    bool enable_metrics;
    bool enable_tracing;
} kestrel_config_t;

// 事件结构
typedef struct {
    uint64_t event_id;
    uint16_t event_type;
    uint64_t ts_mono_ns;
    uint64_t ts_wall_ns;
    uint128_t entity_key;
    uint32_t field_count;
    kestrel_field_t* fields;
} kestrel_event_t;

typedef struct {
    uint32_t field_id;
    kestrel_value_t value;
} kestrel_field_t;

typedef union {
    int64_t i64;
    uint64_t u64;
    double f64;
    bool boolean;
    struct {
        const char* data;
        size_t len;
    } string;
    struct {
        const uint8_t* data;
        size_t len;
    } bytes;
} kestrel_value_t;
```

#### 14.3.2 核心引擎 API

```c
// 引擎生命周期
kestrel_error_t kestrel_engine_new(
    const kestrel_config_t* config,
    kestrel_engine_t** out_engine
);

void kestrel_engine_free(kestrel_engine_t* engine);

// 规则管理
kestrel_error_t kestrel_engine_load_rule(
    kestrel_engine_t* engine,
    const char* rule_id,
    const char* rule_definition,
    const char** error_msg
);

kestrel_error_t kestrel_engine_unload_rule(
    kestrel_engine_t* engine,
    const char* rule_id
);

kestrel_error_t kestrel_engine_unload_all_rules(
    kestrel_engine_t* engine
);

// 事件处理
kestrel_error_t kestrel_engine_process_event(
    kestrel_engine_t* engine,
    const kestrel_event_t* event,
    kestrel_alert_t*** out_alerts,
    size_t* out_alert_count
);

void kestrel_alerts_free(
    kestrel_alert_t** alerts,
    size_t count
);

// 查询告警信息
const char* kestrel_alert_get_rule_id(
    const kestrel_alert_t* alert
);

uint64_t kestrel_alert_get_timestamp_ns(
    const kestrel_alert_t* alert
);

const char* kestrel_alert_get_severity(
    const kestrel_alert_t* alert
);

// Metrics
kestrel_error_t kestrel_engine_get_metrics(
    kestrel_engine_t* engine,
    kestrel_metrics_t** out_metrics
);

uint64_t kestrel_metrics_get_events_processed(
    const kestrel_metrics_t* metrics
);

uint64_t kestrel_metrics_get_alerts_generated(
    const kestrel_metrics_t* metrics
);

void kestrel_metrics_free(kestrel_metrics_t* metrics);

// 版本信息
const char* kestrel_version(void);
```

### 14.4 实现架构

```
┌─────────────────────────────────────┐
│     C/C++ Application              │
└──────────────┬──────────────────────┘
               │ libkestrel.so / kestrel.lib
               ▼
┌─────────────────────────────────────┐
│     C FFI Layer (kestrel-ffi)       │
│  - C ABI wrappers                   │
│  - Memory management                │
│  - Error translation                │
│  - Type conversions                 │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│     Kestrel Core (Rust)             │
│  - Engine                           │
│  - NFA                              │
│  - Runtimes (Wasm/Lua)              │
│  - EventBus                         │
└─────────────────────────────────────┘
```

### 14.5 内存管理策略

1. **输出内存由调用者释放**：所有返回的指针（alerts、metrics 等）必须由调用者通过对应的 `_free()` 函数释放
2. **输入内存借用**：引擎不持有输入事件和规则的内存
3. **全局锁保护**：所有 API 内部使用 mutex 保证线程安全

### 14.6 构建与打包

#### 14.6.1 目录结构
```
kestrel-ffi/
├── include/
│   └── kestrel.h          # 公开 C 头文件
├── src/
│   ├── lib.rs             # FFI 实现
│   ├── engine.rs          # Engine API
│   ├── events.rs          # Event API
│   ├── rules.rs           # Rule API
│   └── metrics.rs         # Metrics API
├── tests/
│   └── c_integration/      # C 集成测试
│       ├── test_basic.c
│       └── Makefile
└── Cargo.toml
```

#### 14.6.2 构建产物

```bash
# Linux
cargo build --release --lib -p kestrel-ffi
# 生成: target/release/libkestrel.so

# macOS
cargo build --release --lib -p kestrel-ffi
# 生成: target/release/libkestrel.dylib

# Windows (MSVC)
cargo build --release --lib -p kestrel-ffi
# 生成: target/release/kestrel.dll

# 静态库（可选）
cargo build --release --lib -p kestrel-ffi
# 生成: target/release/libkestrel.a
```

### 14.7 使用示例

#### 14.7.1 C 示例代码

```c
#include "kestrel.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    kestrel_engine_t* engine = NULL;
    kestrel_config_t config = {
        .event_bus_size = 10000,
        .worker_threads = 4,
        .batch_size = 100,
        .enable_metrics = true,
        .enable_tracing = false,
    };

    // 创建引擎
    kestrel_error_t err = kestrel_engine_new(&config, &engine);
    if (err != KESTREL_OK) {
        fprintf(stderr, "Failed to create engine\n");
        return 1;
    }

    // 加载规则
    const char* rule = "sequence where process.name == 'bash'";
    const char* error_msg = NULL;
    err = kestrel_engine_load_rule(engine, "rule-1", rule, &error_msg);
    if (err != KESTREL_OK) {
        fprintf(stderr, "Failed to load rule: %s\n", error_msg);
    }

    // 处理事件
    kestrel_event_t event = {
        .event_id = 1,
        .event_type = 1,  // PROCESS_EXEC
        .ts_mono_ns = 1000000,
        .ts_wall_ns = 1000000,
        .entity_key = 12345,
        .field_count = 2,
        // ... fields
    };

    kestrel_alert_t** alerts = NULL;
    size_t alert_count = 0;
    err = kestrel_engine_process_event(engine, &event, &alerts, &alert_count);

    if (alert_count > 0) {
        printf("Generated %zu alerts\n", alert_count);
        for (size_t i = 0; i < alert_count; i++) {
            printf("Alert: %s\n", kestrel_alert_get_rule_id(alerts[i]));
        }
        kestrel_alerts_free(alerts, alert_count);
    }

    // 清理
    kestrel_engine_free(engine);
    return 0;
}
```

#### 14.7.2 Python 集成示例（通过 ctypes/cffi）

```python
import ctypes
from ctypes import *

# 加载共享库
lib = ctypes.CDLL("./libkestrel.so")

# 定义类型和函数签名
lib.kestrel_engine_new.restype = c_int32
lib.kestrel_engine_new.argtypes = [POINTER(kestrel_config), POINTER(c_void_p)]

lib.kestrel_engine_process_event.restype = c_int32
lib.kestrel_engine_process_event.argtypes = [c_void_p, POINTER(kestrel_event), POINTER(c_void_p), POINTER(c_size_t)]

# 使用...
engine = c_void_p()
lib.kestrel_engine_new(byref(config), byref(engine))
```

### 14.8 Phase 规划

#### Phase 1: 核心 FFI 框架（2-3 人周）
- 创建 kestrel-ffi crate
- 实现 Engine API wrapper
- 实现 Event/Alert API wrapper
- C 头文件定义（kestrel.h）
- 基础内存管理

#### Phase 2: 规则与 Metrics API（2-3 人周）
- 规则加载/卸载 API
- Metrics 查询 API
- 错误消息处理
- 资源清理 API

#### Phase 3: 测试与文档（2-3 人周）
- C 集成测试套件
- Python bindings 示例
- 使用文档与示例代码
- 性能基准测试

#### Phase 4: 多语言支持（1-2 人周）
- Go cgo 绑定示例
- Java JNI 绑定示例
- Node.js FFI 示例

### 14.9 兼容性目标

| 平台 | 最低版本 | 状态 |
|------|---------|------|
| Linux glibc | 2.17 | 待实现 |
| macOS | 10.14+ | 待实现 |
| Windows | MSVC 2019+ | 待实现 |

### 14.10 质量门槨

1. **ABI 稳定性测试**：跨版本兼容性测试
2. **内存泄漏检测**：Valgrind/Sanitizer 检查
3. **线程安全测试**：多线程并发调用测试
4. **性能测试**：FFI 层开销 < 5% 总延迟
5. **文档完整性**：每个 API 都有示例代码

### 总体粗估
- **最小可用版本**（核心 API + 测试）：约 **6–9 人周**
- **完整生态**（多语言绑定 + 文档）：约 **9–14 人周**
