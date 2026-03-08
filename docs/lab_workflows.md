# Kestrel Lab Workflows

> 目的：把 `scenarios/`、Battle Lab、Replay、Rule Studio、Control Plane、Expert Workbench 串成一套可执行的产品迭代工作流。  
> 适用对象：规则工程师、安全研究员、SOC、平台运营、产品研发。  
> 最后更新：2026-03-06

---

## 1. 为什么需要统一工作流

Kestrel 已经具备以下关键能力：
- 端侧引擎与 collector
- replay / deterministic verification
- 场景资产目录
- Control Plane 设计
- AI / Expert Workbench 设计

但如果这些能力没有统一工作流，团队就会回到碎片化状态：
- 场景有人写，但没有标准 replay 验证
- 规则有人写，但不知道如何进入灰度
- GUI 有设计，但不知道该消费哪些资产
- 运营能看告警，但无法追溯到场景和规则来源

因此，必须建立一条统一链路：

```text
Scenario -> Live/Replay -> Rule Tuning -> Validation -> Rollout -> GUI Ops -> Feedback
```

这条链路就是 Kestrel 的“产品迭代飞轮”。

---

## 2. 总体闭环

```text
场景资产（scenarios/）
    ↓
Battle Lab 执行 / Replay 回放
    ↓
引擎检测结果 + 性能结果 + 异常分数
    ↓
规则调优 / 策略修正 / AI 辅助分析
    ↓
灰度发布 / 端侧 ACK / 回滚控制
    ↓
GUI 观察与运维分析
    ↓
误报 / 漏报 / 资源问题回流到场景与规则
```

这个闭环要求：
- 每个阶段都有明确输入输出
- 每个输出都能进入下一阶段
- 任一线上问题都能尽量回溯到 replay / scenario 层

---

## 3. Workflow A：Scenario 驱动开发

适合：
- 新检测规则开发
- 新 collector 字段验证
- 行为链验证
- 首次接入新威胁场景

### 3.1 输入
- `scenarios/<scenario>/scenario.yaml`
- `scenarios/<scenario>/attack.sh`
- `scenarios/<scenario>/expected_alerts.json`

### 3.2 执行步骤
1. 选择一个场景（例如 `reverse_shell`）
2. 在 Battle Lab 中执行受控脚本
3. 使用 Kestrel collector + engine 采集 live 遥测
4. 保存 replay log
5. 对比 `expected_alerts.json`
6. 输出：
   - 规则命中情况
   - 缺失字段
   - 资源消耗
   - 误报 / 漏报

### 3.3 产出
- replay log
- 规则迭代建议
- collector 字段缺口记录
- 场景结果摘要

### 3.4 退出条件
一个场景达到可用标准时，至少满足：
- 预期规则命中
- 未出现高噪音误报
- replay 可复现
- 资源成本在可接受范围内

---

## 4. Workflow B：Replay 驱动规则调优

适合：
- 误报排查
- 漏报排查
- 性能回归
- 规则版本对比

### 4.1 输入
- replay log
- 当前规则包版本
- 候选新规则包版本

### 4.2 执行步骤
1. 使用 CLI replay 或未来 Replay Lab 导入日志
2. 在同一日志上跑多个规则版本
3. 记录：
   - 命中差异
   - 漏报差异
   - 性能差异
   - 规则 cost 变化
4. 在 Rule Studio 中修改规则
5. 重新 replay，直到达到预期

### 4.3 关键比较维度
- 规则命中是否符合预期
- 告警数量是否明显过多
- 单规则平均耗时 / P99
- Wasm / Lua 运行时代价
- 是否引入新的高风险误报

### 4.4 产出
- 新的规则版本候选
- replay 报告
- 误报 / 漏报备注
- 场景回归结论

---

## 5. Workflow C：Rule Studio 调试工作流

适合：
- 安全专家快速试写规则
- 研究员验证字段和条件
- 规则性能优化

### 5.1 规则开发最小循环
```text
选场景 → 看字段 → 写规则 → replay → 看命中 → 调规则 → 再 replay
```

### 5.2 Rule Studio 应该能直接消费的资产
- `scenario.yaml`
- replay log
- 当前 schema / capability 信息
- Rule profiling 结果
- AI 推荐字段 / 条件

### 5.3 UI 最小支持
- 字段浏览器
- capability 检查
- 规则编辑器
- replay 执行按钮
- 告警对比面板
- rule cost profiler

### 5.4 关键输出
- 规则草案
- 规则版本 diff
- replay 成功结果
- 规则成本快照

---

## 6. Workflow D：灰度发布与回滚

适合：
- 规则从实验室走向生产
- 新 collector 能力上线
- 新 AI 模型 / anomaly 策略上线

### 6.1 输入
- 已通过 replay / 场景验证的规则包版本
- 目标设备组
- rollout plan

### 6.2 推荐发布阶段
1. internal
2. canary
3. limited
4. detect-full
5. prevent-canary
6. prevent-broad

### 6.3 每一阶段必须观察的指标
- 命中率变化
- 误报率变化
- CPU / memory 增量
- 事件 drop rate
- collector 健康状态
- ACK / NACK 比例
- rollback 触发条件

### 6.4 自动回滚触发条件建议
- ACK 失败率超过阈值
- CPU / memory 占用异常增加
- 误报率显著升高
- collector 启动失败率异常
- 阻断成功率异常下降

### 6.5 产出
- rollout report
- rollback record
- 设备组影响摘要
- 策略稳定性结论

---

## 7. Workflow E：GUI / Expert Workbench 运维流

适合：
- SOC 日常分析
- 平台运营
- 规则团队 / 研究团队协同

### 7.1 Device Center
输入：
- 端侧 heartbeat
- capability 报告
- 当前策略版本

输出：
- 设备健康图
- 设备能力画像
- 问题设备列表

### 7.2 Policy Center
输入：
- policy / policy version
- rollout records
- ACK / rollback data

输出：
- 当前发布状态
- 灰度进度
- 回滚历史

### 7.3 Replay Lab
输入：
- replay log
- 规则版本
- AI 模型版本（未来）

输出：
- 时间线
- 命中/未命中对比
- anomaly score 对比
- 规则 cost 对比

### 7.4 Threat Console
输入：
- 告警流
- 设备上下文
- 相似攻击链 / anomaly score（未来）

输出：
- 告警排序
- 时间线
- 证据与关联实体
- 处置建议

---

## 8. AI 与 Battle Lab / Replay 的协同方式

AI 不直接替代引擎实时判决，而是服务于：
- 场景分析
- replay 结果增强
- 告警重排序
- 规则建议

### 8.1 数据进入 AI 的路径
```text
Battle Lab / Live Telemetry
    ↓
Replay Log / Feature Extraction
    ↓
Embedding / Anomaly / Similarity
    ↓
Rule Studio / Replay Lab / Threat Console
```

### 8.2 AI 在工作流中的作用
- 在 Replay Lab 中给 anomaly score
- 在 Rule Studio 中给字段/条件建议
- 在 Threat Console 中给相似行为簇
- 在 Battle Lab 中帮助识别“规则未覆盖但高风险”的场景

### 8.3 不建议的做法
- 不要让 AI 直接成为端侧实时阻断唯一依据
- 不要让 AI 先于 replay / scenario 体系落地
- 不要先做复杂模型，再补产品闭环

---

## 9. 推荐的落地顺序

### Stage 1：Engine + Replay 可用
- CLI replay
- replay 报告
- 规则验证闭环

### Stage 2：Battle Lab 最小版
- 场景目录
- 场景执行器
- replay log 归档
- expected alert 断言

### Stage 3：Control Plane 最小版
- 设备注册
- capability 上报
- policy version
- rollout / rollback

### Stage 4：Expert Workbench 最小版
- Rule Studio
- Replay Lab
- Device Center
- Policy Center

### Stage 5：AI 增强版
- feature extraction
- anomaly score
- similarity retrieval
- rule recommendation

---

## 10. 面向研发团队的使用建议

### 检测研发
优先使用：
- `scenarios/`
- Battle Lab
- replay
- Rule Studio

### 平台研发
优先使用：
- Control Plane 对象模型
- rollout / rollback 设计
- device / capability 流程

### 研究与运营
优先使用：
- Replay Lab
- Threat Console
- anomaly / similarity 结果

---

## 11. 近期可执行任务清单

1. 完成 `kestrel-lab` 最小执行器
2. 给场景运行产出标准化 summary / replay 报告
3. 让 replay 结果可导出给 GUI / Rule Studio 使用
4. 定义 Control Plane Rust 数据模型草案
5. 增加更多 first-party scenarios
6. 增加 Rule profiling 输出与规则成本视图

---

## 12. 一句话总结

Kestrel 的产品飞轮不应只是：

```text
写规则 -> 上线
```

而应是：

```text
写场景 -> 采行为 -> replay -> 调规则 -> 灰度 -> GUI观察 -> 反馈回场景
```

只有这样，Battle Lab、Replay、Control Plane、GUI、AI 才会成为一个真正协同的安全产品体系。
