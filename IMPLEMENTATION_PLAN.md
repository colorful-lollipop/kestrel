# Kestrel 开发实施计划

**状态**: ✅ 已完成 (5/8 阶段)

---

## 已完成阶段

| Stage | 任务 | 状态 | 关键成果 |
|-------|------|------|----------|
| 1 | 修复离线回放测试 | ✅ | 修复 `test_replay_event_ordering_deterministic`，添加后台消费者 |
| 2 | 优化 SchemaRegistry 并发 | ✅ | 使用 DashMap 替代 RwLock，-77 行代码 |
| 3 | 完善 eBPF 稳定性 | ✅ | 添加 EbpfHealthChecker 组件，支持健康监控 |
| 7 | 清理编译警告 | ✅ | 修复 kestrel-core 所有警告 |
| 8 | 完善文档 | ✅ | 添加 architecture.md 架构文档 |

---

## 已完成阶段

| Stage | 任务 | 状态 | 说明 |
|-------|------|------|------|
| 1 | 修复离线回放测试 | ✅ | 修复 EventBus::new() 添加后台消费者 |
| 2 | SchemaRegistry 并发优化 | ✅ | 使用 DashMap 替代 RwLock，-77 行代码 |
| 3 | eBPF 健康检查 | ✅ | 添加 EbpfHealthChecker 组件 |
| 4 | EQL 数组语法支持 | ✅ | 添加 `any`/`all` 数组量化操作 |
| 7 | 清理编译警告 | ✅ | 修复 kestrel-core 警告 |
| 8 | 完善文档 | ✅ | 添加 architecture.md |

## 待完成阶段 (P2)

| Stage | 任务 | 说明 |
|-------|------|------|
| 5 | Wasm Pool Prometheus 导出 | 指标导出集成 |
| 6 | 配置热重载 | 运行时配置更新 |

## 待完成阶段 (P2)

| Stage | 任务 | 说明 |
|-------|------|------|
| 5 | Wasm Pool Prometheus 导出 | 指标导出集成 |
| 6 | 配置热重载 | 运行时配置更新 |

---

## 执行记录

| Stage | 开始时间 | 完成时间 | 备注 |
|-------|----------|----------|------|
| 1 | 2026-02-06 | 2026-02-06 | 修复 EventBus::new() 添加后台消费者 |
| 2 | 2026-02-06 | 2026-02-06 | SchemaRegistry 使用 DashMap 优化并发 |
| 3 | 2026-02-06 | 2026-02-06 | 添加 eBPF HealthChecker 组件 |
| 7 | 2026-02-06 | 2026-02-06 | 清理 kestrel-core 编译警告 |
| 8 | 2026-02-06 | 2026-02-06 | 添加 architecture.md 架构文档 |
