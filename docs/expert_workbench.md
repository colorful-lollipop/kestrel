# Kestrel Expert Workbench 设计方案

> 目标：为安全专家、规则工程师、运营人员和研究人员提供一套高效的 GUI / 工作台体系，用于规则开发、回放验证、场景测试、设备观察与策略治理。  
> 最后更新：2026-03-06

---

## 1. 为什么必须有 Expert Workbench

如果 Kestrel 只停留在 CLI + 文档层面，那么：
- 规则开发成本高
- 误报排查慢
- 场景验证不连续
- 运营团队无法快速理解引擎状态
- AI / replay / battle-lab 价值无法充分释放

因此，GUI 不是“锦上添花”，而是**产品化效率放大器**。

---

## 2. 用户角色

### 2.1 规则工程师
关注：
- 规则是否正确
- 规则字段是否真实可用
- 规则成本是否合理
- 场景回放是否命中预期

### 2.2 安全研究员
关注：
- 场景复现
- 样本行为链
- replay 时间线
- 相似恶意样本
- AI 异常分数

### 2.3 安全运营 / SOC 分析师
关注：
- 告警优先级
- 告警聚类
- 设备健康
- 策略发布状态
- 回滚与灰度

### 2.4 平台管理员
关注：
- 设备接入
- 策略版本
- 控制平面状态
- 指标、资源、容量

---

## 3. 总体组件划分

```text
Expert Workbench
├── Device Center
├── Policy Center
├── Rule Studio
├── Replay Lab
├── Battle Lab Console
├── Threat Console
└── Metrics & Profiling
```

---

## 4. Device Center

### 核心能力
- 设备注册与发现
- 设备能力画像
- 设备分组 / 标签管理
- 设备健康状态
- Agent / collector / runtime version 查看

### 关键视图
- 设备总览表
- 设备详情页
- 能力矩阵页
- 健康状态页

### 关键字段
- 设备 ID
- hostname
- OS / kernel
- agent version
- collector capability
- Wasm/Lua runtime capability
- current policy version
- last heartbeat
- current resource usage

---

## 5. Policy Center

### 核心能力
- 策略创建 / 编辑 / 发布 / 回滚
- 规则包版本管理
- 灰度发布编排
- 部署范围选择（租户 / 分组 / 能力 / 环境）

### 关键视图
- Policy 列表
- Policy 版本 diff
- 灰度发布面板
- 回滚历史

### 关键操作
- 创建新版本
- dry-run 验证
- 按设备组灰度
- 回滚到稳定版本
- 查看端侧 ACK / NACK

---

## 6. Rule Studio

### 核心能力
- EQL / Lua / Wasm metadata 编辑
- 字段浏览器
- 语法与 capability 校验
- rule profile（规则成本分析）
- AI 候选建议

### 编辑器能力
- 自动补全字段
- 事件类别提示
- capability 检查
- schema 可用性验证
- 规则版本历史

### Rule Profiling 视图
- 规则平均耗时
- P95 / P99
- 命中率
- 访问字段数
- 是否命中 Wasm runtime
- regex / glob 代价

### AI 辅助能力
- 推荐字段
- 推荐条件
- 推荐 maxspan
- 推荐 by clause
- 展示最相似恶意样本

---

## 7. Replay Lab

### 核心能力
- 导入 replay log
- 选择规则包版本与模型版本
- 重放并比较结果
- 查看命中 / 未命中 / anomaly score
- 输出 replay 报告

### 关键视图
- 时间线回放视图
- 规则命中对照视图
- 告警对比视图
- 性能对比视图

### 核心问题回答能力
- 为什么命中了？
- 为什么没命中？
- 不同规则版本结果有何变化？
- 不同模型版本 anomaly score 有何变化？

---

## 8. Battle Lab Console

### 核心能力
- 选择场景
- 启动隔离环境
- 执行攻击脚本
- 采集 live 遥测
- 归档 replay log
- 对照 expected alerts

### 第一版支持的场景
- reverse shell
- credential access
- suspicious outbound connect
- batch file operations
- ransomware early-stage patterns

### 输出结果
- 场景执行状态
- live 事件摘要
- replay log 链接
- 规则命中摘要
- 漏报 / 误报摘要
- 资源消耗摘要

---

## 9. Threat Console

### 核心能力
- 告警检索
- 告警聚类
- 相似攻击链检索
- 设备上下文查看
- 证据时间线查看

### AI 联动能力
- anomaly score
- nearest malicious baseline
- nearest benign baseline
- cluster / family suggestion

### 专家分析体验
告警详情页应至少同时展示：
- 原始规则命中信息
- 事件证据
- 实体时间线
- AI 风险增强结果
- 设备状态
- 当前策略版本

---

## 10. Metrics & Profiling

### 核心能力
- 端侧资源指标
- 引擎吞吐与 drop
- NFA 状态规模
- Wasm runtime pool 利用率
- 规则级别耗时 / 命中率 / 代价
- replay 任务指标
- battle-lab 场景指标

### 最关键面板
- Engine health dashboard
- Rule cost dashboard
- Collector health dashboard
- Replay validation dashboard
- Rollout / rollback dashboard

---

## 11. Battle Lab 与 GUI 的关系

Battle Lab 不应只是脚本目录，而应在 GUI 中成为一等能力：
- 从 GUI 选择场景
- 执行场景
- 自动保存 replay log
- 自动与 expected alerts 做 diff
- 直接跳到 Rule Studio 调整规则
- 再回放验证

这会形成完整飞轮：

```text
场景执行 -> 采集日志 -> 回放验证 -> 规则修改 -> 再验证 -> 发布灰度
```

---

## 12. AI 在 GUI 中的最佳位置

### 12.1 Rule Studio 中
- 规则建议
- 字段建议
- 条件建议
- 成本风险提示

### 12.2 Replay Lab 中
- replay 样本 anomaly score
- 相似样本列表
- top contributing features

### 12.3 Threat Console 中
- 告警排序
- 相似攻击链
- 家族聚类

---

## 13. 最小可行 GUI 路线

### Milestone GUI-1
先不做复杂前端，只定义 API 和页面骨架：
- Device Center
- Rule Studio
- Replay Lab

### Milestone GUI-2
接入 Battle Lab 与 Rule Profiling：
- 场景执行
- replay 对比
- rule cost 面板

### Milestone GUI-3
接入 AI：
- anomaly / similarity
- 规则建议
- 告警排序增强

### Milestone GUI-4
接入完整云控：
- Policy Center
- 灰度发布
- 回滚管理

---

## 14. 最重要的产品原则

1. **GUI 服务专家，而不是取代专家**
2. **所有 GUI 结论都必须能回到 replay / 日志 / 规则证据**
3. **所有 AI 增强都必须可解释**
4. **Rule Studio / Replay Lab / Battle Lab 必须形成闭环，而不是孤立页面**
5. **端侧约束优先于前端体验幻想：所有设计必须回到“对端侧资源是否友好”**

---

## 15. 总结

Kestrel 的 Expert Workbench 不只是一个“管理页面”，而应成为以下三类工作的统一平台：
- 规则工程
- 攻防验证
- 安全运营

它与 AI、Replay、Battle Lab、Control Plane 的组合，决定了 Kestrel 是否能从“优秀引擎”真正成长为“完整安全产品平台”。
