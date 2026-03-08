# Kestrel AI / 向量增强架构设计

> 目标：在不破坏端侧实时、可解释、低资源约束的前提下，引入 AI / 向量能力，提升未知威胁发现、相似行为检索、告警排序与规则迭代效率。  
> 最后更新：2026-03-06

---

## 1. 设计原则

Kestrel 的 AI 能力必须遵守以下原则：

1. **AI 不替代引擎主干**
   - eBPF / EventBus / RuleManager / NFA / Wasm / Lua 仍然是实时检测主链路
   - AI 是增强层，不是第一性执行层

2. **实时判决优先走规则 / 状态机**
   - 低延迟阻断仍依赖 EQL / NFA / 明确策略
   - AI 先承担“异常发现 / 相似检索 / 风险排序 / 规则建议”职责

3. **端侧轻、云侧重**
   - 端侧做轻量特征聚合和必要摘要
   - 云侧做 embedding、ANN 检索、异常评分、聚类与训练

4. **必须可回放、可验证、可解释**
   - 所有 AI 结果都要能绑定 replay 日志、场景、规则版本、模型版本
   - 必须能回答“为什么它是异常的”

---

## 2. AI 能力在产品中的位置

### 2.1 异常检测（Anomaly Detection）
针对单设备、单实体、单容器的行为窗口计算异常分数。

适用：
- 规则未覆盖的新变种
- 低频异常执行链
- 正常基线之外的进程/文件/网络组合

### 2.2 相似行为检索（Similarity Retrieval）
把历史恶意样本、已验证攻击链、规则命中事件流编码成 embedding，构建向量索引。

适用：
- 新样本与历史恶意链做相似检索
- 告警归类
- 快速发现“已知家族的未知变体”

### 2.3 风险重排序（Risk Re-ranking）
对已命中的规则告警做二次增强排序。

考虑因素：
- 行为 embedding 距离
- 设备画像
- 规则历史精度
- 实体上下文
- 近期相似攻击样本密度

### 2.4 规则建议（Rule Suggestion）
从场景日志 / replay 结果中总结高区分度字段、序列结构、时间窗口与候选条件，辅助安全专家写 EQL / Lua / Wasm 规则。

### 2.5 行为聚类（Behavior Clustering）
按设备、进程、容器、用户会话对行为进行聚类与离群分析。

适用：
- 横向发现异常集群
- 挖掘长期潜伏行为
- 构造场景资产与正常基线库

---

## 3. 分层架构

```text
┌──────────────────────────────────────────────────────────────┐
│                      Expert Workbench / GUI                  │
│  Replay Lab | Rule Studio | Threat Console | AI Insights    │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                    Cloud AI / Analytics Layer                │
│  Embedding | ANN Retrieval | Anomaly | Clustering | Ranking  │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                 Feature / Replay / Battle Lab Layer          │
│  Replay logs | Scenario assets | Feature vectors | Labels    │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                     Endpoint Runtime Layer                   │
│  eBPF | EventBus | NFA | Wasm/Lua | Rule Engine | Metrics    │
└──────────────────────────────────────────────────────────────┘
```

---

## 4. 端侧特征层（Endpoint Feature Layer）

### 4.1 目标
端侧不直接跑重模型，而是输出资源可控、可缓存、可上传的行为摘要。

### 4.2 特征来源
来自现有 Kestrel 事件：
- `process.*`
- `file.*`
- `network.*`
- `*.operation`
- `entity_key`
- `ts_mono_ns`

### 4.3 聚合维度
推荐至少支持：
- 按 `process.entity_id`
- 按 `entity_key`
- 按容器 / 会话 / 主机
- 按时间窗口：5s / 30s / 5m

### 4.4 第一版推荐特征

#### Process 特征
- `proc_exec_count`
- `unique_process_name_count`
- `shell_spawn_count`
- `suspicious_parent_child_pairs`
- `rare_executable_count`

#### File 特征
- `file_open_sensitive_count`
- `file_rename_count`
- `file_unlink_count`
- `unique_inode_count`
- `high_value_file_touch_count`

#### Network 特征
- `net_connect_count`
- `unique_dest_ip_count`
- `unique_dest_port_count`
- `external_connect_count`
- `rare_port_connect_count`

#### Sequence 特征
- `shell_after_network`
- `sensitive_file_after_exec`
- `burst_file_ops_after_process_exec`
- `repeated_connect_after_exec`

#### Resource / Context 特征
- 时间密度
- 事件熵
- 行为窗口长度
- 命中的规则数
- 是否处于 collector 降级模式

### 4.5 推荐模块
建议新增：
- `kestrel-feature`

职责：
- 从 `Event` 做轻量特征提取
- 维护窗口聚合
- 输出 `FeatureVector` / `FeatureSummary`
- 支持端侧本地缓存与上传

---

## 5. 云侧 Embedding / Anomaly / Retrieval 层

### 5.1 Embedding 层
建议新增：
- `kestrel-embedding`

输入：
- `FeatureVector`
- 事件序列窗口
- 场景 replay 日志

输出：
- `Embedding(Vec<f32>)`
- `EmbeddingMetadata`

### 5.2 Anomaly 层
建议新增：
- `kestrel-anomaly`

第一版模型建议：
- Isolation Forest
- One-Class baseline
- Autoencoder

输出：
- `anomaly_score`
- `feature_attribution`
- `baseline_distance`

### 5.3 Retrieval 层
建议新增：
- `kestrel-vector-store`

职责：
- 存 benign / suspicious / malicious embeddings
- 相似检索
- 聚类与近邻解释

第一版不必自研复杂索引，可从：
- brute-force baseline
- HNSW 风格内存索引
开始。

---

## 6. 数据模型建议

### 6.1 Feature Summary
```text
FeatureSummary {
  entity_scope,
  window_start,
  window_end,
  counters,
  sequence_markers,
  environment_context,
  engine_metrics_snapshot,
}
```

### 6.2 Embedding Record
```text
EmbeddingRecord {
  embedding_id,
  embedding_version,
  source_type,        // replay / battle_lab / live_sample
  label,              // benign / suspicious / malicious
  scenario_id,
  rule_pack_hash,
  feature_summary,
  embedding,
}
```

### 6.3 Anomaly Result
```text
AnomalyResult {
  entity_scope,
  model_version,
  anomaly_score,
  nearest_benign,
  nearest_malicious,
  top_features,
}
```

---

## 7. Battle Lab 联动方式

AI 最核心的训练和验证燃料来自 Battle Lab 与 Replay。

### 7.1 Battle Lab 产出
每次战场场景执行应至少产出：
- replay log
- 场景标签
- 预期告警
- 运行时 metrics
- 资源占用摘要
- 特征摘要

### 7.2 标准资产目录建议
```text
scenarios/
  reverse_shell/
    scenario.yaml
    attack.sh
    expected_alerts.json
    labels.json
    notes.md
```

### 7.3 训练与验证闭环
1. 执行 battle-lab 场景
2. 生成 replay 日志
3. 回放验证规则结果
4. 提取特征向量
5. 生成 embedding
6. 写入向量样本库
7. 用于：
   - anomaly 评估
   - similarity 检索
   - 规则建议

---

## 8. GUI / Expert Workbench 分层

AI 与 GUI 必须联动，而不是彼此孤立。

### 8.1 Rule Studio
- EQL / Lua / Wasm 编辑器
- 字段浏览器
- capability 预检
- 规则资源成本预估
- AI 建议：候选条件、候选窗口、候选字段

### 8.2 Replay Lab
- 导入 replay log
- 选择规则包 / 模型版本
- 查看命中 / 漏报 / anomaly score
- 查看最相似恶意样本与 benign baseline

### 8.3 Threat Console
- 告警检索
- 时间线
- 行为相似聚类
- 风险重排序结果
- 规则命中 + AI 风险并列展示

### 8.4 Metrics / Profiling 面板
- 每规则耗时
- Wasm runtime pool 利用率
- EventBus drop / backpressure
- 特征提取成本
- anomaly / retrieval 请求耗时

---

## 9. 产品落地建议：先做什么，不做什么

### 9.1 第一阶段要做
- `Replay + Feature Extraction`
- `Battle Lab + Scenario Assets`
- `Embedding baseline`
- `Anomaly score`
- `Similarity retrieval`

### 9.2 第一阶段不要做
- 端侧大模型实时推理
- AI 直接驱动阻断
- 每事件 embedding
- 高资源图模型实时执行

### 9.3 最现实的第一版 AI 形态
- 端侧：特征聚合 + 可选轻量 anomaly pre-score
- 云侧：embedding / retrieval / anomaly / clustering
- GUI：Replay Lab + Rule Studio 的 AI 辅助面板

---

## 10. 推荐迭代路线

### Phase AI-0
- 先实现 `FeatureSummary`
- 只做 replay 场景数据资产沉淀
- 不引入模型推理

### Phase AI-1
- 轻量 anomaly score
- 向量化 benign / malicious baseline
- 基础 similarity retrieval

### Phase AI-2
- 规则建议
- 告警重排序
- 场景聚类 / 行为家族发现

### Phase AI-3
- GUI 深度联动
- 面向安全专家的规则调试/回放/对比工作流
- 云控策略与 AI 结果联动

---

## 11. 与现有 Kestrel 架构的关系

Kestrel 当前最适合的 AI 架构定位是：

- **规则 / NFA**：负责实时、解释、阻断
- **AI / 向量**：负责异常发现、相似检索、风险增强、规则建议
- **Replay / Battle Lab**：负责训练、验证、迭代
- **GUI / Control Plane**：负责专家效率与运营闭环

这意味着 AI 不是“附加玩具功能”，而是未来 Kestrel 从“高性能检测引擎”成长为“完整安全产品平台”的关键增强层。
