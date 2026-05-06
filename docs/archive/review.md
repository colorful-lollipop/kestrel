# Kestrel 项目评审与 2.0 规划建议

本文档基于 `plan.md` 的目标/架构设想，以及当前仓库代码与文档（`README.md`、`PLANNING.md`、`PROGRESS.md`、`suggest.md` 等）对 Kestrel 的完成度、差距与后续 2.0 演进路径做一次“面向生产可用”的评审。

## 1. 总体结论（现状 vs 目标）

### 1.1 当前完成度（按能力链路拆解）

- **规则执行链路（Engine ← Rules ← Runtime）**：
  - Wasm/EQL/NFA/Engine 的基础模块已形成闭环雏形；`PROGRESS.md` 显示 Phase 5/5.5 的核心修复已完成。
  - 但整体仍更像“可跑的研发内核”，距离“生产可用引擎”差一套系统化质量门槛与配套设施（可观测性、压测、回归基线、发布与回滚、数据面 SLO）。

- **采集层（eBPF）**：
  - 具备 crate 级结构与 normalize/pushdown 的方向，但 **真实可用的内核闭环**、ringbuf polling、attach 生命周期、字段/事件稳定协议、以及跨内核版本能力矩阵仍是最大缺口。

- **离线可复现（Replay/Deterministic）**：
  - 代码层已出现 replay/deterministic/一致性比较的雏形，这是正确方向。
  - 但“可复现性契约”尚未工程化成：日志格式版本化、规则包哈希、引擎 build id、事件排序 tie-breaker（`event_id`）等完整闭环。

- **实时阻断（Inline/Enforce）**：
  - 架构与 `plan.md` 方向正确（LSM 优先、规则子集、预算与降级）。
  - 但生产级阻断需要“能力矩阵 + 策略/授权 + 误杀回滚 + 审计取证”，这些配套在代码与文档侧还不完整。

### 1.2 一句话判断

- **你们已经具备“端侧行为检测引擎的核心骨架”**（schema/event、EQL→IR、NFA、Wasm/Lua runtime、engine 组织）；
- **离商业顶级引擎的差距主要不在单点算法**，而在“端到端工程化”——采集稳定性、语义一致性、资源预算/隔离、观测与回归基线、规则生态/工具链、与生产运维能力。

## 2. 关键风险与阻塞项（优先级排序）

### P0：构建/测试环境存在系统性阻塞（生产化第一步）

在本环境中执行 `cargo test --workspace` 触发 `Invalid cross-device link (os error 18)`，导致无法稳定完成全量构建测试。这会直接阻断 CI 与质量门槛。

建议：
- 明确并固化一套可复现的构建方案（容器化/CI runner/固定 target 目录策略），并在 `docs/troubleshooting.md` 增补该问题的标准 workaround。
- 生产化视角下，把“可重复构建 + 可重复测试”作为第一质量门槛（否则后续性能/算法优化都无法验证）。

### P0：eBPF 真实闭环与协议稳定性

- ringbuf/perfbuf polling、BPF 程序 attach、事件协议版本化、字段完备性与兼容性，是端侧引擎能否“低功耗 + 高性能 + 可部署”的决定性因素。
- 当前 `kestrel-ebpf` 编译提示 clang 失败（环境依赖），也说明 eBPF 相关链路需要更强的工程化（依赖检测、降级策略、最小可用事件面）。

### P1：数据面资源预算（CPU/内存/延迟）需要“可证明”而非“预期”

你们已有 EventBus batching、NFA StateStore（TTL/LRU/quota）、runtime fuel 等机制的方向，但缺少：
- per-rule / per-tenant / per-entity 的预算与隔离策略（避免单规则拖垮全局）。
- P99 延迟与尾部放大治理（尤其是 sequence + 字符串匹配/regex）。

### P1：一致性与可复现契约还需“前置工程化”

离线可复现不是 Phase 7 才做的功能，而是从 Phase 5/6 开始就要固化的契约：
- 事件排序：`ts_mono_ns + event_id`。
- 版本锁定：`rule_pack_hash`、`schema_version`、`engine_build_id`。
- 运行时差异：LuaJIT/Wasm 的确定性模式与一致性测试基线。

## 3. 架构与算法层的优化建议（面向 2.0）

### 3.1 引擎数据面：从“可用实现”走向“可控系统”

建议将 data plane 收敛成 4 个可独立压测/替换的模块：

1) **采集与规范化（Sources + Normalizer）**
- 目标：尽可能早地“减少数据量、减少字符串、减少分配”。
- 2.0 建议：在 normalize 阶段把常用字段 FieldId 缓存为结构体成员（避免运行时反复 `register/get_field_id`）。

2) **路由与分区（Router/Partitioner）**
- 目标：把事件按 `entity_key`（或 event_type）稳定分区，最大化 cache locality，减少锁。
- 2.0 建议：分区键对 `u128 entity_key` 做哈希再取模，避免低位偏置导致热点 shard。

3) **序列状态机（Host NFA + StateStore）**
- 目标：状态增长受控、淘汰可解释、按规则/实体双维度配额。
- 2.0 建议：将 sequence_id/rule_id 从 `String` 热路径逐步收敛为整数 ID（加载期映射），减少 clone/分配。

4) **谓词执行（Wasm/Lua Predicate ABI）**
- 目标：hostcall 次数最少、字段读取批量化、字符串处理可控。
- 2.0 建议：为谓词引擎增加“批量字段读取”hostcall（一次取多个 FieldId）与“预编译 matcher 句柄”（regex/glob/contains）。

### 3.2 算法侧：商业顶级行为检测引擎的“隐藏护城河”

多数顶级引擎差异不在 NFA 本身，而在以下“算法+工程结合点”：

- **实体建模与上下文富化**：
  - 进程实体：`pid + start_time`、父子链、exec 链、会话/容器维度。
  - 文件实体：路径规范化、inode、挂载命名空间、软硬链接语义。
  - 网络实体：连接五元组、DNS/HTTP 语义、证书指纹。

- **事件语义稳定性**：同一个行为在不同内核/发行版/容器环境下如何映射成一致事件（这决定规则可移植性）。

- **抑噪与相关性（alert correlation）**：
  - 顶级引擎会把“单点命中”提升为“行为故事线”：聚合、去重、分数、阶段。
  - 需要 engine 支持：rule group、证据链、跨告警关联键。

- **规则生命周期与灰度**：
  - 规则热加载只是开始；更关键的是灰度发布、分组启用、回滚、统计反馈（命中率/误报/成本）。

## 4. 性能/低功耗/低内存：端侧可部署的工程路线

### 4.1 端侧性能的三层优化顺序（建议坚持）

1) **减少事件量**：兴趣下推（event_type bitset、字段级过滤、简单比较）优先于任何用户态优化。
2) **减少每事件成本**：字段 ID、零拷贝字符串、批处理、减少 hostcall。
3) **并行与隔离**：分区 worker + backpressure + 配额，控制尾延迟。

### 4.2 需要补齐的关键“预算机制”

- **CPU 预算**：per-rule 统计 `eval_count / eval_time`，达到阈值自动降级（关闭 regex、降低采样、转离线）。
- **内存预算**：StateStore 的 per-rule/per-entity quotas + 可观测的淘汰原因。
- **延迟预算**：Inline 模式强制“规则子集 + 超时 fail-open/fail-closed 策略可配置”。

### 4.3 生产可用必备：可观测性（Observability）

至少要做到：
- metrics：EPS、drop/backpressure、NFA 活跃状态、每规则耗时分布、Wasm/Lua 实例池、ringbuf backlog。
- tracing：rule_id、sequence_id、partition_id、action decision trace。
- profiling：提供可选的 `pprof`/`perf` 指南（端侧常用）。

## 5. 文档与工具链：从“能用”到“能规模化用”

### 5.1 必须沉淀为“长期资产”的文档

- **EQL 兼容性规范 + 可执行测试集**（你们在 `plan.md` 和 `suggest.md` 已强调，这是顶级项目的核心资产）。
- **Predicate ABI 规范**：Wasm/Lua 共享的 Host API/ABI（建议提供 WIT 或单一 Rust 规范源），避免 codegen/runtime drift。
- **事件 Schema 版本化策略**：字段新增/弃用、事件类型演进、跨平台能力矩阵。

### 5.2 配套设施（商业顶级引擎常见但开源项目容易缺）

- 规则开发工具：lint/formatter、语义检查、成本估计（复杂度、预计 hostcall/regex 次数）。
- 回归与兼容：一套“黄金事件流/黄金告警”基线，保证升级不破坏语义。
- 发布与回滚：规则包签名/哈希、引擎版本标识、A/B 或灰度开关。

## 6. 测试与质量门槛建议（如何保证生产可用）

### 6.1 测试分层（建议 2.0 完整引入）

1) **语义测试（最重要）**
- EQL 语义基线：缺失字段、类型比较、边界 maxspan/until、同 ts 排序。
- 同规则在 Wasm 与 Lua 上结果一致（在“确定性模式”下）。

2) **数据面压测**
- 固定事件流回放：测吞吐、P99、内存上界、状态淘汰。
- 故障注入：ringbuf backlog、规则热加载、异常规则（超时/崩溃）。

3) **eBPF 集成测试（可在 CI 的 privileged runner 做）**
- 最小闭环：exec/file/network 各 1 个事件，从 kernel → user → alert。
- 能力探测与降级：缺 kernel feature 时的行为（不崩溃、有告警/日志）。

4) **生产演练**
- 误杀回滚演练：阻断策略切换、规则撤回、旁路模式。
- 离线复现演练：同日志同规则同版本 → 告警完全一致。

### 6.2 质量门槛（Release Gate）建议

对齐 `PLANNING.md` 的 Quality Gates，并补齐“端侧生产”必须项：
- `cargo test --workspace`、`cargo clippy --workspace --all-targets`、`cargo fmt --check`。
- 基准：吞吐、P99、内存上界（带回归阈值）。
- 安全：规则包签名/校验、运行时资源限制（fuel/内存/hostcall）可配置。
- 可观测性：核心 metrics/traces 默认开启（可配置）。

## 7. 2.0 演进规划（建议里程碑）

### 2.0.1（1–3 周）：打通生产化基础
- 解决构建/CI 的系统性问题（`Invalid cross-device link`）。
- 固化 Host API/Predicate ABI 单一规范源（避免 drift）。
- 明确 schema 版本与 event_id 排序契约（为 replay 铺路）。

### 2.0.2（3–6 周）：eBPF 最小可用闭环 + 兴趣下推 v1
- exec 事件完整闭环（kprobe/tracepoint + ringbuf + normalize）。
- pushdown v1：event_type bitset（BPF map）。
- 端侧资源基线报告（1k EPS：CPU、P99、内存、功耗趋势）。

### 2.0.3（6–10 周）：数据面可控与可观测
- EventBus 分区策略、backpressure 策略可配置并可观测。
- NFA StateStore 配额与淘汰原因指标完善。
- Wasm instance pool 与 hostcall 批量化，形成可复现性能基线。

### 2.0.4（10–16 周）：Inline/Enforce 第一版（谨慎上线）
- 阻断能力矩阵（exec/file/network）+ 策略授权 + 审计闭环。
- Inline 规则子集与 fail-open/fail-closed 可配置。
- 误杀回滚与旁路模式（enforce ↔ detect）

### 2.0.5（并行长期）：规则生态与一致性资产
- EQL 兼容性测试集持续扩充。
- 规则开发工具链（lint/成本估计/样例库）。
- 黄金事件流/黄金告警回归资产。

---

## 8. 附：与“商业顶级行为检测引擎”的差距清单（便于对标）

- **采集覆盖与稳定性**：跨内核/发行版/容器的语义一致性与能力矩阵（顶级引擎核心壁垒）。
- **端侧资源治理**：严格预算、隔离、降级、尾延迟控制（决定可部署性）。
- **规则工程化**：灰度、回滚、统计反馈、规则质量与成本工具。
- **可观测性与运维**：指标/追踪/诊断工具链完善，支持大规模终端运行。
- **取证与故事线**：证据链、关联分析、告警聚合与上下文富化。

