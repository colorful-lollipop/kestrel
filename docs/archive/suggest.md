# Kestrel 中期审视报告（Phase 0 → Phase 5）

本报告以“是否能达成项目目的（端侧实时检测/阻断 + 离线完全可复现）”为准绳，对当前仓库从 Phase 0/1 到现阶段（Phase 5 进行中）的所有核心代码进行技术审视，并给出修改建议与后续开发优先级。

## 0. 总体结论（可达成性）

### 0.1 成功概率判断
- **在线检测（Detect）**：成功概率高。Schema/Event 模型、EQL AST/IR、NFA/StateStore 已经形成闭环的“内部逻辑基础”。
- **实时阻断（Enforce）**：成功概率中等偏高，但强依赖后续对“阻断规则子集、预算、能力矩阵”的工程化约束。
- **离线可复现（Replay）**：成功概率中等。当前架构方向正确，但缺少“确定性契约”的落地（event_id、版本锁定、日志格式）。若拖到 Phase 7 再补，会引发接口返工。

### 0.2 当前最影响项目成败的 P0 问题
1. **`kestrel-engine` 未打通规则执行链路**：`DetectionEngine::eval_event` 仍返回空告警，导致 Phase 0-4 的成果无法端到端验收。
2. **EQL→Wasm codegen 与 runtime ABI 不一致**：`kestrel-eql` 的 `codegen_wasm` 当前生成的导出/类型语义存在明显缺口，难以与 `kestrel-runtime-wasm` 形成可运行闭环。
3. **eBPF 采集层仍是骨架**：`kestrel-ebpf` 尚未提供任何真实内核事件闭环；没有“最小可用事件面”，后续性能/语义/字段完备性都无法验证。

---

## 1. Phase 0（架构骨架）审视

### 1.1 `kestrel-schema`
优点：
- 类型别名清晰：`FieldId=u32`、`EventTypeId=u16`、`EntityKey=u128` 与 plan.md 方向一致。
- `SchemaRegistry` 使用 `Arc<AHashMap<..>>` 的 copy-on-write 结构，具备“读多写少”的性能潜力。

问题与风险：
- `TypedValue` 手写 serde 实现存在**明显的协议不一致风险**：`serialize_newtype_variant("TypedValue", 0, "I64", v)` 这类实现，配套 `deserialize_enum` 却使用了 `&["i64", "u64", ...]` 的 variant 名称列表，且内部 `Field` 是 `I64/U64/...`。这非常容易导致 JSON/YAML/跨运行时序列化不兼容。
- `SchemaRegistry` 的 `get_field_id(path)` 依赖运行时字符串查找；如果在 hot path（如 eBPF normalize）频繁调用，会产生不必要开销。

建议：
- [P0] 统一 `TypedValue` 的 serde 方案：建议使用 `#[derive(Serialize, Deserialize)]` + `#[serde(tag = "t", content = "v")]` 或者固定 `"I64"/"U64"/...` 的 variant 名称，确保 round-trip 与跨语言一致。
- [P1] 为高频字段提供初始化期缓存：例如 normalizer 初始化时把 `process.pid` 等常用 `FieldId` 缓存下来，避免事件级字符串查找。

### 1.2 `kestrel-event`
优点：
- `Event` 与 plan.md 定义基本对齐：稀疏字段存储（SmallVec）、`EntityKey`、双时间戳。

问题与风险：
- `Event::get_field` 是 O(n) 扫描；在 EPS 提升或字段变多时会成为可见开销。
- 缺少 `event_id`，而 plan.md 对“离线完全可复现”明确要求“稳定排序：ts_mono_ns + event_id”。

建议：
- [P1] `fields` 存储可演进为“按 FieldId 排序的 SmallVec + 二分查找”，兼顾小规模内联与更低常数。
- [P1] 引入 `event_id: u64`（单调递增，作为 tie-breaker），从 Phase 5 就开始落地，避免 Phase 7 大规模改接口。

### 1.3 `kestrel-core`（EventBus / Alert）
优点：
- EventBus 有 batching 轮廓与 metrics 原型；AlertOutput 支持 stdout/file，便于本地验证。

问题与风险：
- `EventBusConfig.partitions` 目前未实现真正分区：仅启动一个 worker，且 `worker_tx` 是 dummy channel。
- `BackpressureConfig` 定义完整但未实装；对端侧“低功耗/低延迟/可控内存”的关键承诺还缺工程支撑。
- `Alert::Severity` 与 `kestrel_rules::Severity` 重复定义，后续会出现映射/序列化不一致。

建议：
- [P1] 实现真正的 partitions：按 `entity_key`（或 event_type）哈希分发到多 worker，才能支撑 NFA 并行与锁竞争控制。
- [P1] 实装 backpressure：至少提供 drop/block 两种策略 + 计数器（dropped/backpressure），为 enforce 模式做准备。
- [P2] Severity 合并到单一来源（建议以 `kestrel-core` 为准，rules 复用）。

---

## 2. Phase 1/2（Wasm/Lua 运行时）审视

### 2.1 `kestrel-runtime-wasm`
优点：
- 明确了 Host API v1 的概念域（event_get、regex/glob、alert_emit、capabilities）。
- Wasmtime 配置、fuel 计量、实例池/AOT 缓存等性能思路正确。

问题与风险：
- Host API 的 ABI 目前仍缺“单一事实来源”（例如 WIT/头文件）。`kestrel-eql` codegen 直接写死导入名/签名，极易 drift。
- AOT 缓存默认写 `./cache/wasm`，在某些运行环境（只读/跨设备）会导致构建/运行失败；需要可配置并有降级策略。

建议：
- [P0] 抽出 Host API v1 规范文件（WIT 或 rust `trait`+导出名常量），由 eqlc/runtime/engine 统一引用。
- [P1] AOT cache 的写入路径与启用策略：默认可关闭或落在明确可写目录，并有失败降级。

### 2.2 `kestrel-runtime-lua`
优点：
- 与 Wasm 类似的 manifest/capabilities 结构，有利于双运行时统一。

问题与风险：
- 目前 `eval()` 仅调用 `pred_eval()` 且不传 event/ctx（注释也写“for now, pass no event, just return true”），这与 NFA/Engine 的需求不匹配。
- `enable_jit` 只是配置项，没有明确“离线确定性模式”。

建议：
- [P0] 对齐 Predicate ABI：Lua 的 `pred_eval(event_handle, ctx)` 与 Wasm 统一，Host API 提供字段读取/工具函数。
- [P2] 离线回放引入确定性开关：至少支持关闭 JIT + 指令/时间限制，作为一致性验收路径。

---

## 3. Phase 3/4（EQL 编译器 / NFA 引擎）审视

### 3.1 `kestrel-eql`
优点：
- AST/semantic/IR 分层清晰；`IrPredicate.required_fields/regex/globs` 为 pushdown 与预编译缓存提供了接口基础。

问题与风险（高）：
- `codegen_wasm.rs` 仍处于原型状态：
  - 对每个 predicate 都导出同名 `pred_eval`（循环里反复写 `(export "pred_eval")`），在 Wasm 模块中这是**不合法/不可用**的。
  - `LoadField` 一律调用 `event_get_i64`，无法正确表达 `u64/string/bool`。
  - string literal、`pred_capture`、regex/glob id 常量表都还是 TODO。

建议：
- [P0] 修正 codegen 的导出策略：
  - 要么导出 `pred_eval_main`/`pred_eval_step1`…并由 runtime 按名字调用；
  - 要么只导出一个 `pred_eval(predicate_id, event_handle)` 的 dispatcher（但需要将 predicate_id 变成可传入的数值/索引）。
- [P0] 与 runtime 统一 typed getter ABI（i64/u64/string/bytes/bool），并定义 string ABI（ptr/len 或 host 返回 handle）。
- [P1] `IrCapture` 落地：至少能把关键字段写入告警，用于验收“可解释性”。

### 3.2 `kestrel-nfa`
优点：
- StateStore 具备 TTL/LRU/quota 的工程形态，且有 metrics；这是端侧可控内存的核心资产。

问题与风险：
- `NfaEngine::process_event` 为了绕过借用问题会 clone `sequence_ids`，并对 `NfaSequence` 做 clone；在高 EPS + 多规则下可能形成明显开销。
- shard 计算使用 `(entity_key as usize) % num_shards`，对 u128 的低位敏感；如果 entity_key 的低位分布不好，可能导致热点 shard。

建议：
- [P1] shard 选择改为对 `entity_key` 做哈希（ahash）再取模。
- [P1] sequence_id 由 String 改为更轻量的 `SequenceId(u32)`（对外仍可映射到 rule_id），减少热路径分配/clone。

---

## 4. Phase 5（eBPF 采集层）审视

### 4.1 当前状态
- `kestrel-ebpf` 已具备 collector/normalizer/pushdown/program manager 的结构，但核心能力仍是占位：
  - `EbpfCollector::load_ebpf()` 直接返回 `LoadError("not yet implemented")`
  - `ProgramManager` 的 attach/detach 全是 TODO
  - `build.rs` 未编译任何 BPF 源码

### 4.2 主要问题与风险
- `RawEbpfEvent.entity_key: u64` 与全局契约（`EntityKey=u128`）不一致，后续容器/会话/进程 start_time 组合键会受限。
- `EventNormalizer` 事件类型与字段访问使用大量运行时字符串查找 + 魔法数字 event_type(1..7)，容易造成跨模块语义漂移。
- `InterestPushdown` 使用 `HashMap/Vec/String` 等用户态友好结构，但不可直接映射到 BPF map / verifier 友好模型；若目标是“下推到内核过滤”，需要从一开始就按 eBPF 可落地的数据结构设计。

### 4.3 建议（Phase 5 的最小验收闭环）
- [P0] 先实现 1 个真实事件闭环（建议 exec）：tracepoint/kprobe + ringbuf/perfbuf → 用户态 normalize → EventBus → Engine。
- [P0] pushdown v1 只做 event_type bitset（BPF map），这是收益最大且最容易通过 verifier 的下推。
- [P1] raw payload 协议引入 `version:u16`，优先用 fixed-size 字段（comm[16], filename[256] 等）快速闭环，稳定后再做变长协议。

---

## 5. 跨阶段一致性问题（会导致返工的“接口契约”）

### 5.1 规则执行链路缺口（当前最大阻塞）
`kestrel-engine/src/lib.rs` 的 `eval_event()` 仍为空实现：
- RuleManager 仅负责加载规则文本/元数据，但没有把规则编译为 IR/Wasm/Lua predicate 并注入 runtime。
- NFA 引擎与 runtime 的连接缺少最终 orchestrator。

建议（P0）：
- 在 `DetectionEngine` 内实现最小可用链路：
  - 单事件规则：predicate match → AlertOutput
  - 序列规则：event → NFA → SequenceAlert → AlertOutput
- 同步定义“Rule → Interests”接口（event types/field ids），用于：
  - eBPF pushdown
  - Engine 路由（按 event_type_id 选规则）

### 5.2 构建/测试可用性
当前环境中 `cargo test --workspace` 出现 `Invalid cross-device link (os error 18)` 的构建问题（与工作区/target 写入方式有关）。这会影响持续集成与“中期验收可跑”。

建议：
- [P0] 在 README/AGENT 中补充可复现的构建 workaround（例如指定 `CARGO_TARGET_DIR` 到同一文件系统，或关闭某些缓存/硬链接行为）。

---

## 6. 建议的短期任务清单（按优先级）

- [P0] 打通 `kestrel-engine` 规则执行闭环（单事件 + 序列），让 Phase 0-4 的成果可验收。
- [P0] 修复 `kestrel-eql` Wasm codegen 的导出与 typed getter/字符串/捕获逻辑，使其可与 `kestrel-runtime-wasm` 实际运行。
- [P0] Phase 5 落地 1 个真实 eBPF 事件闭环（exec），pushdown v1 先做 event_type。
- [P1] EventBus partitions/backpressure 实装，为 NFA 并行与 enforce 预算做准备。
- [P1] 引入 `event_id` + 最小二进制事件日志原型，为 Phase 7 复现铺路。
- [P2] Lua 确定性模式与双运行时一致性测试（同规则同事件流 → 同告警）。

