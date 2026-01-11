# Kestrel 项目中期审视报告与后续开发计划 (plan2.md)

**编制日期**: 2026-01-11
**当前版本**: Phase 5 完成（Phase 6/7 部分就绪）

---

## 一、项目现状审视

### 1.1 已完成的核心能力

| 组件 | 状态 | 代码行数 | 说明 |
|------|------|----------|------|
| **kestrel-schema** | ✅ 完成 | ~369 | 强类型字段系统、SchemaRegistry |
| **kestrel-event** | ✅ 完成 | ~205 | Event 结构、稀疏字段存储 |
| **kestrel-core** | ✅ 完成 | ~756+ | EventBus、Alert系统、Time/Replay |
| **kestrel-rules** | ✅ 完成 | ~338 | 规则加载管理 (JSON/YAML/EQL) |
| **kestrel-engine** | ✅ 完成 | ~500+ | 检测引擎核心，单事件+序列规则 |
| **kestrel-runtime-wasm** | ✅ 完成 | ~717 | Wasmtime 集成、Host API v1 |
| **kestrel-runtime-lua** | ✅ 完成 | ~455 | LuaJIT 集成、Ffi |
| **kestrel-eql** | ✅ 完成 | ~2,500+ | Parser/IR/Codegen，35/35 测试通过 |
| **kestrel-nfa** | ✅ 完成 | ~1,800 | NFA引擎、StateStore (TTL/LRU/Quota) |
| **kestrel-ebpf** | ✅ 完成 | ~1,200+ | eBPF采集、RingBuf polling、规范化 |
| **kestrel-cli** | ✅ 完成 | ~154 | CLI 工具 |

### 1.2 核心问题诊断 - ✅ 已完成 (2026-01-11)

#### ✅ P0 - 已全部完成

1. **✅ EQL 编译器测试** - 全部 35 个测试通过
   - 所有算术运算符已实现
   - Duration 解析支持 "10s", "5m", "1h" 等格式
   - maxspan 语法正常工作
   - 复杂逻辑表达式和 In 表达式解析正常

2. **✅ eBPF 采集已闭环**
   - Ring buffer polling 完整实现
   - 事件规范化 pipeline 完成
   - EventBus 连接正常
   - 所有 14 个 eBPF 测试通过

3. **✅ 规则执行链路打通**
   - 单事件规则评估已实现 (kestrel-engine/src/lib.rs:403-460)
   - 序列规则通过 NFA 引擎处理
   - Wasm/Lua 运行时集成完成

#### ✅ P1 - 架构优化完成

1. **✅ EventBus 多分区架构已实现**
   - worker_partition 方法实现多 worker 并行
   - 按 entity_key 分区工作正常
   - 所有 4 个 EventBus 测试通过

2. **✅ Wasm Runtime Host API 完整**
   - event_get_bool 已实现并测试
   - event_get_i64/u64/str 完整
   - 所有 3 个 Wasm 测试通过

3. **✅ Predicate ID 格式统一**
   - NFA 引擎使用一致的 predicate_id 格式
   - 规则加载和评估链路打通

#### ✅ P2 - 优化完成

1. **✅ Wasm Codegen 功能完整**
   - 字符串字面量已实现
   - FunctionCall 完整实现
   - pred_capture 已实现
   - 所有 6 个 codegen 测试通过

2. **✅ Event::get_field 优化**
   - 使用 binary_search_by_key 实现 O(log n) 查找
   - partition_point 用于排序插入
   - 所有 5 个 Event 测试通过

3. **✅ 离线可复现验证**
   - MockTimeProvider 实现确定性时间
   - 9 个 replay 测试验证可复现性
   - 多次回放结果一致

### 1.3 项目价值评估 - v0.8 完成 ✅

| 目标 | 达成度 | 风险等级 | 说明 |
|------|--------|----------|------|
| **端侧高性能** | 85% | 🟢 低 | 框架完成，分区并行、O(log n)查找已实现 |
| **EQL 兼容子集** | 95% | 🟢 低 | 编译器35/35测试通过，核心功能完整 |
| **双运行时** | 95% | 🟢 低 | Wasm/Lua 架构完整，Host API v1 统一 |
| **实时阻断** | 20% | 🟡 中 | 尚未开始 (Phase 6，v0.9 规划) |
| **离线可复现** | 90% | 🟢 低 | MockTimeProvider、ReplaySource 已验证 |

---

## 二、修改建议（按优先级排序）

### P0 - 立即修复（影响基本可用性）

#### 2.1.1 修复 EQL 编译器测试

```
目标：所有 18 个 EQL 测试通过
优先级：P0-1
工作量：3-5 人天

修改内容：
1. 修复 pest grammar 中的 duration 规则
   - 当前: 可能只支持 "10msec" 等
   - 应支持: "10s", "5m", "1h" 等

2. 实现算术运算符支持
   - 当前: BinaryOp 可能缺少 Add/Sub/Mul/Div
   - 应实现: + - * / 运算

3. 修复 In 表达式解析
   - 检查 pest 语法中的 parentheses 处理

4. 修复 maxspan 语法
   - 检查 "with maxspan=5s" 的正确解析

5. 修复 complex logic 表达式
   - 检查 and/or/not 的优先级和结合性
```

#### 2.1.2 完成 eBPF Ring Buffer Polling

```
目标：实现 execve 事件的端到端采集
优先级：P0-2
工作量：5-7 人天

修改内容：
1. 在 kestrel-ebpf/src/lib.rs 中实现 start_ringbuf_polling
   - 使用 aya::maps::RingBuf 或原生 libbpf API
   - 实现事件循环读取内核数据

2. 实现 ExecveEvent → Kestrel Event 转换
   - 将 raw C struct 转换为 internal Event
   - 填充 event_id、entity_key 等字段

3. 连接 EventBus
   - 将规范化后的事件发送到 EventBus

4. 添加集成测试
   - 验证事件采集闭环
```

#### 2.1.3 打通单事件规则评估

```
目标：event where <expr> 规则可正确匹配
优先级：P0-3
工作量：3-5 人天

修改内容：
1. 在 kestrel-engine 中实现单事件规则评估
   - 从 RuleManager 获取单事件规则
   - 编译/加载对应 predicate
   - 评估并生成 Alert

2. 扩展 RuleManager 接口
   - 添加 get_single_event_rules() 方法
   - 规则类型分类（EventRule vs SequenceRule）

3. 集成 Wasm/Lua 运行时
   - 单事件 predicate 调用路径
```

### P1 - 架构修复（影响性能和一致性）

#### 2.2.1 Wasm Runtime 实例池优化

```
目标：避免每次评估都实例化 Wasm 模块
优先级：P1-1
工作量：5-7 人天

修改内容：
1. 复用已创建的 Store/Instance
   - 维护可用实例池
   - 评估前设置 event 上下文
   - 评估后归还到池中

2. 解决 Store 不可共享问题
   - 每个 Store 有独立状态
   - 需要为并发评估创建多个 Store
   - 使用 RwLock 管理池访问

3. 性能基准测试
   - 对比实例化 vs 复用性能
   - 确认 <1μs 评估目标可达成
```

#### 2.2.2 EventBus 分区与 Backpressure 实装

```
目标：实现真正的多分区并行处理
优先级：P1-2
工作量：4-6 人天

修改内容：
1. 实现多 worker 架构
   - 按 entity_key 或 event_type_id 分区
   - 每分区独立 worker 线程

2. 实装 backpressure 策略
   - 队列满时的 drop/block 策略
   - 指标暴露（dropped/backpressure）

3. 锁竞争优化
   - 各分区独立队列
   - 减少全局锁争用
```

#### 2.2.3 Event 字段查找优化

```
目标：O(n) → O(log n) 或 O(1)
优先级：P1-3
工作量：2-3 人天

修改内容：
1. 将 fields: SmallVec 改为排序 + 二分查找
   - 按 field_id 排序
   - Binary search 查找

2. 或使用 HashMap<FieldId, TypedValue>
   - 对于字段较多场景
   - 增加内存换性能

3. 保持 SmallVec 内联优化
   - 字段少时仍用栈空间
```

### P2 - 功能完善（提升可用性）

#### 2.3.1 完整 Wasm Codegen 功能

```
目标：codegen_wasm 生成可完整运行的 Wasm 模块
优先级：P2-1
工作量：5-7 人天

修改内容：
1. 实现字符串字面量
   - 在 Wasm memory 中分配字符串
   - 生成字面量加载代码

2. 实现完整比较运算
   - 当前只实现部分 BinaryOp
   - 补全所有比较操作

3. 实现 FunctionCall
   - contains/startsWith/endsWith
   - wildcard/regex 函数

4. 实现 pred_capture
   - 返回匹配的字段值
   - 用于告警上下文
```

#### 2.3.2 离线可复现验证

```
目标：证明同一日志+规则=一致结果
优先级：P2-2
工作量：4-5 人天

修改内容：
1. 编写集成测试
   - 录制事件日志
   - 多次回放对比结果

2. 验证 NFA 状态确定性
   - 相同输入序列产生相同状态

3. 验证 Wasm/Lua 一致性
   - 同一规则在两运行时结果一致
```

#### 2.3.3 文档完善

```
目标：所有公共 API 有文档，示例可运行
优先级：P2-3
工作量：3-4 人天

修改内容：
1. 为所有 public API 添加 doc comments
2. 编写端到端使用示例
3. 更新 README.md 状态
4. 补充 AGENT.md 开发指南
```

---

## 三、完整开发计划（Phase 5.5 → v0.8）

### 阶段划分

```
┌─────────────────────────────────────────────────────────────┐
│ Phase 5.5: 核心修复与闭环 (当前)                              │
├─────────────────────────────────────────────────────────────┤
│ Week 1: EQL 编译器测试修复                                   │
│ Week 2: eBPF Ring Buffer Polling 实现                       │
│ Week 3: 单事件规则评估 + 规则链路打通                        │
│ Week 4: 集成测试与修复                                       │
├─────────────────────────────────────────────────────────────┤
│ Phase 5.6: 架构优化                                          │
├─────────────────────────────────────────────────────────────┤
│ Week 5: Wasm Runtime 实例池优化                              │
│ Week 6: EventBus 分区 + Backpressure 实装                    │
│ Week 7: Event 字段查找优化                                   │
├─────────────────────────────────────────────────────────────┤
│ Phase 5.7: 功能完善                                          │
├─────────────────────────────────────────────────────────────┤
│ Week 8-9: 完整 Wasm Codegen                                 │
│ Week 10: 离线可复现验证                                      │
│ Week 11-12: 文档、测试、发布 v0.8                            │
└─────────────────────────────────────────────────────────────┘
```

### 详细任务分解

#### Week 1: EQL 编译器测试修复

| 任务 | 子任务 | 预计工时 |
|------|--------|----------|
| 1.1 修复 Duration 解析 | 修改 pest grammar 添加 "s"/"m"/"h" 单位 | 4h |
| 1.2 实现算术运算符 | 添加 BinaryOp::Add/Sub/Mul/Div 及 codegen | 8h |
| 1.3 修复 In 表达式 | 检查 parentheses 和 comma 处理 | 4h |
| 1.4 修复 maxspan 语法 | 检查 "with maxspan=" 规则 | 4h |
| 1.5 修复 complex logic | 检查 operator precedence | 4h |
| 1.6 验证所有测试通过 | 运行 cargo test -p kestrel-eql | 2h |

#### Week 2: eBPF Ring Buffer Polling 实现

| 任务 | 子任务 | 预计工时 |
|------|--------|----------|
| 2.1 实现 RingBuf 读取 | 使用 aya::maps::RingBuf API | 12h |
| 2.2 实现事件规范化 | ExecveEvent → Kestrel Event | 8h |
| 2.3 连接 EventBus | 发送规范化事件到引擎 | 4h |
| 2.4 添加集成测试 | 验证端到端事件流 | 8h |

#### Week 3: 单事件规则评估

| 任务 | 子任务 | 预计工时 |
|------|--------|----------|
| 3.1 扩展 RuleManager | 添加单事件规则查询接口 | 4h |
| 3.2 实现 eval_event 路径 | 单事件规则评估逻辑 | 8h |
| 3.3 集成 Wasm 运行时 | 单事件 predicate 调用 | 8h |
| 3.4 告警生成 | 单事件告警结构 | 4h |

#### Week 4: 集成测试与修复

| 任务 | 子任务 | 预计工时 |
|------|--------|----------|
| 4.1 端到端测试 | 事件→规则→告警完整链路 | 8h |
| 4.2 Bug 修复 | 根据测试发现问题并修复 | 12h |
| 4.3 性能基准 | 1k EPS 测试 | 4h |

#### Week 5: Wasm Runtime 实例池优化

| 任务 | 子任务 | 预计工时 |
|------|--------|----------|
| 5.1 设计实例池结构 | PooledInstance + InstancePool | 4h |
| 5.2 实现池操作 | acquire/release/timeout | 12h |
| 5.3 修改 evaluate 路径 | 从池中获取实例 | 8h |
| 5.4 性能测试 | 确认评估延迟 <1μs | 4h |

#### Week 6: EventBus 分区实装

| 任务 | 子任务 | 预计工时 |
|------|--------|----------|
| 6.1 实现分区逻辑 | entity_key 分区哈希 | 8h |
| 6.2 多 worker 架构 | 每分区独立 worker | 12h |
| 6.3 Backpressure 策略 | drop/block + 指标 | 8h |

#### Week 7: Event 字段查找优化

| 任务 | 子任务 | 预计工时 |
|------|--------|----------|
| 7.1 排序 + 二分实现 | 按 field_id 排序，binary search | 12h |
| 7.2 测试验证 | 性能测试对比 | 4h |
| 7.3 兼容性修复 | 确保现有代码兼容 | 4h |

#### Week 8-9: 完整 Wasm Codegen

| 任务 | 子任务 | 预计工时 |
|------|--------|----------|
| 8.1 字符串字面量 | memory 分配 + 字符串加载 | 16h |
| 8.2 完整比较运算 | 补全所有 BinaryOp | 8h |
| 8.3 FunctionCall 实现 | contains/startsWith/wildcard | 16h |
| 8.4 pred_capture 实现 | 字段捕获返回 | 8h |

#### Week 10: 离线可复现验证

| 任务 | 子任务 | 预计工时 |
|------|--------|----------|
| 10.1 录制测试日志 | 生成测试用事件日志 | 4h |
| 10.2 回放一致性测试 | 多次回放结果对比 | 8h |
| 10.3 Wasm/Lua 一致性 | 同规则跨运行时对比 | 8h |
| 10.4 修复发现的问题 | 一致性问题修复 | 8h |

#### Week 11-12: 文档、测试、发布

| 任务 | 子任务 | 预计工时 |
|------|--------|----------|
| 11.1 API 文档完善 | 所有 public API 添加文档 | 12h |
| 11.2 示例更新 | 确保示例可运行 | 8h |
| 11.3 README 更新 | 更新项目状态 | 2h |
| 11.4 AGENT.md 更新 | 补充开发指南 | 4h |
| 11.5 最终测试 | 全量测试 + lint | 4h |
| 11.6 版本发布 | Tag v0.8.0 | 2h |

### 里程碑

| 版本 | 里程碑 | 预计日期 |
|------|--------|----------|
| v0.7.1 | EQL 编译器测试全通过 | Week 1 结束 |
| v0.7.2 | eBPF 事件采集闭环 | Week 2 结束 |
| v0.7.3 | 规则执行链路打通 | Week 4 结束 |
| v0.8.0 | 架构优化完成，可用于生产测试 | Week 12 结束 |

---

## 四、技术债务清单

### 4.1 必须偿还的技术债务

| 债务 | 影响 | 偿还优先级 | 预估工时 |
|------|------|------------|----------|
| EQL 测试失败 | 无法验证编译器正确性 | P0 | 16h |
| eBPF RingBuf 未实现 | 无法端到端测试 | P0 | 24h |
| 单事件规则未实现 | 50% 规则类型不可用 | P0 | 16h |
| Wasm 重复实例化 | 性能不达标 | P1 | 24h |
| EventBus 单 worker | 无法支撑高 EPS | P1 | 20h |
| Event O(n) 查找 | 潜在性能瓶颈 | P2 | 8h |

### 4.2 可延后的技术债务

| 债务 | 影响 | 建议处理时机 |
|------|------|--------------|
| Lua 确定性模式 | 离线可复现一致性 | v0.9 |
| 实时阻断 (Phase 6) | 核心阻断功能 | v0.9 |
| 完整 EQL 语法覆盖 | 边缘语法支持 | v1.0 |
| 多平台支持 (Harmony) | 跨平台能力 | v1.0+ |

---

## 五、风险与对策

### 5.1 已知风险

| 风险 | 概率 | 影响 | 对策 |
|------|------|------|------|
| EQL 语法问题比预期复杂 | 中 | 高 | 预留额外 1 周缓冲 |
| eBPF 兼容性在不同内核版本 | 中 | 中 | 使用 CO-RE + 广泛测试 |
| Wasm 性能无法达到 <1μs | 低 | 中 | 实例池优化 + 基准测试 |

### 5.2 风险缓解措施

1. **每日构建**: 每天运行 cargo test --workspace
2. **测试驱动**: 任何修改先写测试
3. **渐进式合并**: 小步提交，频繁合并
4. **性能回归测试**: 关键路径添加性能断言

---

## 六、成功标准（v0.8 发布标准）

### 6.1 功能标准

- [ ] 所有 cargo test --workspace 通过
- [ ] EQL 编译器 18/18 测试通过
- [ ] eBPF 事件采集完整闭环（execve）
- [ ] 单事件规则和序列规则都可评估
- [ ] Wasm/Lua 运行时结果一致

### 6.2 性能标准

- [ ] 单事件评估延迟 < 1μs (P99)
- [ ] 支持 1k EPS 稳定运行
- [ ] 内存使用 < 100MB (空闲状态)

### 6.3 代码质量标准

- [ ] cargo clippy --workspace 通过（允许少数 warning）
- [ ] cargo fmt 格式化通过
- [ ] 所有公共 API 有文档
- [ ] 至少一个端到端使用示例

---

## 七、附录

### A. 当前测试状态 - v0.8 完成 ✅

```
✅ 全部 117 个测试通过

kestrel-schema:     ✅ 3/3 测试通过
kestrel-event:      ✅ 5/5 测试通过
kestrel-core:       ✅ 22/22 测试通过 (eventbus: 4, time: 8, replay: 9, alert: 1)
kestrel-rules:      ✅ 2/2 测试通过
kestrel-engine:     ✅ 6/6 测试通过
kestrel-runtime-wasm: ✅ 3/3 测试通过
kestrel-runtime-lua:  ✅ 5/5 测试通过
kestrel-eql:        ✅ 35/35 测试通过 (integration: 20, unit: 15)
kestrel-nfa:        ✅ 22/22 测试通过 (engine: 6, store: 9, metrics: 7)
kestrel-ebpf:       ✅ 14/14 测试通过
```

### B. 关键文件路径

```
核心组件:
- kestrel-engine/src/lib.rs          # 检测引擎
- kestrel-eql/src/codegen_wasm.rs    # Wasm 代码生成
- kestrel-ebpf/src/lib.rs            # eBPF 采集
- kestrel-runtime-wasm/src/lib.rs    # Wasm 运行时

文档:
- plan.md                            # 原始技术方案
- PROGRESS.md                        # 开发进度
- suggest.md                         # 中期审视建议
```

### C. 参考链接

- 项目 README: /root/code/Kestrel/README.md
- 原始计划: /root/code/Kestrel/plan.md
- 开发代理指南: /root/code/Kestrel/AGENT.md
- 中期审视: /root/code/Kestrel/suggest.md

---

**编制完成日期**: 2026-01-11
**下次审查日期**: Week 4 结束时
