# Kestrel 开发实施计划

## 总体目标
按优先级顺序完成 8 项开发任务，提升代码质量、性能和稳定性。

---

## Stage 1: 修复离线回放测试失败
**Goal**: 修复 `test_replay_event_ordering_deterministic` 测试失败
**Success Criteria**: 
- `cargo test -p kestrel-core test_replay_event_ordering_deterministic` 通过
- 所有现有测试仍通过
**Status**: ✅ Complete

---

## Stage 2: 优化 SchemaRegistry 并发
**Goal**: 使用 `DashMap` 替换 `RwLock<HashMap>` 提升并发性能
**Success Criteria**:
- SchemaRegistry 使用无锁数据结构
- 所有测试通过
- 性能基准无退化
**Status**: ✅ Complete

---

## Stage 3: 完善 eBPF 稳定性
**Goal**: 添加 RingBuf 健康检查和降级策略
**Success Criteria**:
- 添加 EbpfHealthChecker 组件
- 实现连接断开自动重连
- 降级到 fanotify 的 fallback 机制
**Status**: ✅ Complete

---

## Stage 4: 添加更多 EQL 语法支持
**Goal**: 实现 `any`/`all` 数组字段操作
**Success Criteria**:
- EQL 解析器支持 `any(field == value)` 语法
- Wasm 代码生成支持数组操作
- 单元测试覆盖
**Status**: Not Started

---

## Stage 5: 实现 Wasm Pool 指标导出
**Goal**: 将 Wasm Pool 指标集成到 Prometheus 导出
**Success Criteria**:
- PoolMetrics 导出到 Prometheus 格式
- 新增 gauge 指标：pool_size, active_instances, cache_hits
**Status**: Not Started

---

## Stage 6: 添加配置热重载
**Goal**: 运行时更新引擎配置无需重启
**Success Criteria**:
- 信号/文件监听触发配置重载
- 原子配置切换无停机
- 支持热更新的配置项白名单
**Status**: Not Started

---

## Stage 7: 清理编译警告
**Goal**: 修复所有未使用字段/变量警告
**Success Criteria**:
- `cargo build --workspace` 无警告
- `cargo clippy --workspace` 无警告
**Status**: Not Started

---

## Stage 8: 完善文档
**Goal**: 补充 API 文档和使用示例
**Success Criteria**:
- 核心模块 rustdoc 完整
- 添加 architecture.md 架构图
- 添加贡献者指南
**Status**: Not Started

---

## 执行记录

| Stage | 开始时间 | 完成时间 | 备注 |
|-------|----------|----------|------|
| 1 | 2026-02-06 | 2026-02-06 | 修复 EventBus::new() 添加后台消费者 |
| 2 | 2026-02-06 | 2026-02-06 | SchemaRegistry 使用 DashMap 优化并发 |
| 3 | 2026-02-06 | 2026-02-06 | 添加 eBPF HealthChecker 组件 |
