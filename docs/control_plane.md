# Kestrel Control Plane 最小设计

## 1. 目标
Kestrel Control Plane 负责把端侧引擎从“单机检测程序”提升为“可运营的安全产品”。

最小版本的目标不是一次性做完多租户安全平台，而是先完成以下闭环：

1. **设备注册与能力感知**
2. **策略版本管理**
3. **灰度下发与回滚**
4. **端侧 ACK / NACK / 健康回传**
5. **策略效果与资源指标可观测**

该设计与 `plan.md` 中第 16 节保持一致，并优先服务于：
- Kestrel agent / engine 的大规模端侧部署
- 检测策略和阻断策略的安全发布
- replay / battle lab / Rule Studio 的后续集成

---

## 2. 设计原则

### 2.1 云边职责分离
**端侧负责：**
- 实时采集
- 实时检测 / 阻断
- 本地资源治理
- 本地审计与短期缓存

**云侧负责：**
- 设备管理
- 策略与版本治理
- 灰度、回滚、审批
- 规则效果分析
- 运营与可视化

### 2.2 策略必须版本化
策略不是文件目录，而是产品级对象：
- 有版本
- 有签名
- 有目标设备范围
- 有 required capabilities
- 有回滚语义

### 2.3 端侧必须可降级
Control Plane 下发的策略不应该假设所有设备能力一致。策略需要支持：
- capability 检查
- dry-run / detect-only 模式
- 局部禁用不支持的功能
- 失败自动回滚

### 2.4 先做最小可运营版本
第一阶段不追求：
- 复杂多租户计费
- 超大规模跨地域联邦控制面
- 实时大数据分析平台

第一阶段只做：
- 设备
- 策略
- 版本
- 灰度
- 回滚
- 指标

---

## 3. 组件视图

```text
+---------------------------------------------------------------+
|                    Kestrel Control Plane                      |
|                                                               |
|  +------------------+   +------------------+                  |
|  | Device Service   |   | Policy Service   |                  |
|  +------------------+   +------------------+                  |
|  | Inventory        |   | Policy CRUD      |                  |
|  | Heartbeat        |   | Versioning        |                  |
|  | Capability Sync  |   | Signing           |                  |
|  | Grouping/Tags    |   | Validation        |                  |
|  +------------------+   +------------------+                  |
|                                                               |
|  +------------------+   +------------------+                  |
|  | Rollout Service  |   | Telemetry Service|                  |
|  +------------------+   +------------------+                  |
|  | Stage rollout    |   | Agent metrics     |                 |
|  | ACK/NACK         |   | Rule metrics      |                 |
|  | Rollback         |   | Health summary    |                 |
|  +------------------+   +------------------+                  |
|                                                               |
|  +---------------------------------------------------------+  |
|  | GUI / Expert Workbench (future)                        |  |
|  | Policy Center / Device Center / Rule Studio / Replay   |  |
|  +---------------------------------------------------------+  |
+---------------------------------------------------------------+
                 ^                                |
                 | control / config / tasks       | telemetry / audit
                 |                                v
+---------------------------------------------------------------+
|                    Endpoint Agent / Kestrel                    |
|  collector + engine + runtimes + local store + replay logs    |
+---------------------------------------------------------------+
```

---

## 4. 核心对象模型

### 4.1 Device
表示一个受管端点实例。

#### 字段建议
- `device_id`: 全局唯一 ID
- `tenant_id`: 所属租户
- `hostname`
- `os_type`
- `os_version`
- `kernel_version`
- `agent_version`
- `status`: `online | offline | degraded | quarantined | error`
- `last_seen_at`
- `labels`: 环境、地域、业务、风险标签
- `group_ids`

#### 关键价值
- 是所有灰度、下发、回滚的目标对象
- 是后续 Device Center 的主索引对象

### 4.2 Capability
表示设备当前具备的执行/采集能力。

#### 字段建议
- `device_id`
- `supports_ebpf`
- `supports_lsm`
- `supports_live_process_exec`
- `supports_live_file_open`
- `supports_live_network_connect`
- `supports_wasm_runtime`
- `supports_lua_runtime`
- `supports_inline_enforcement`
- `supports_replay`
- `collector_profile_version`
- `runtime_profile_version`
- `updated_at`

#### 关键价值
- 用于下发前预检
- 用于灰度目标过滤
- 用于策略兼容性分析

### 4.3 Policy
表示逻辑上的策略实体。

#### 字段建议
- `policy_id`
- `tenant_id`
- `name`
- `description`
- `category`: `detect | prevent | audit | diagnostics`
- `current_version`
- `status`: `draft | active | paused | archived`
- `created_by`
- `created_at`
- `updated_at`

#### 关键价值
- 为多个版本提供稳定逻辑锚点
- 支持 GUI 中的策略生命周期管理

### 4.4 PolicyVersion
表示一次具体可下发的策略版本。

#### 字段建议
- `policy_id`
- `policy_version`
- `rule_pack_hash`
- `agent_min_version`
- `required_capabilities`
- `execution_mode`: `detect | inline | offline`
- `resource_profile`
- `signature`
- `approval_state`: `draft | review | approved | rejected`
- `changelog`
- `created_by`
- `created_at`

#### 关键价值
- 是真正下发到设备的版本对象
- 支持安全审批、审计、回滚和对比

### 4.5 RolloutPlan
表示一个策略版本的发布计划。

#### 字段建议
- `rollout_id`
- `policy_id`
- `policy_version`
- `target_scope`
- `strategy`: `all_at_once | staged | canary | capability_filtered`
- `stage_definitions`
- `success_criteria`
- `rollback_policy`
- `status`: `planned | running | paused | completed | rolled_back | failed`
- `started_at`
- `completed_at`

#### 关键价值
- 让灰度成为第一等公民
- 支持按设备组/租户/capability 发布

### 4.6 RollbackRecord
表示一次回滚事件。

#### 字段建议
- `rollback_id`
- `rollout_id`
- `from_policy_version`
- `to_policy_version`
- `reason`
- `trigger_type`: `manual | automatic | health_guard`
- `triggered_by`
- `created_at`

#### 关键价值
- 审计
- 运营追踪
- 后续事故分析

### 4.7 AgentHeartbeat
表示端侧周期性状态上报。

#### 字段建议
- `device_id`
- `timestamp`
- `status`
- `active_policy_version`
- `active_rule_pack_hash`
- `cpu_pct`
- `memory_mb`
- `events_per_sec`
- `events_dropped`
- `alerts_generated`
- `health_flags`

#### 关键价值
- 设备在线判断
- 运行态性能与健康监控
- 灰度成功率判定

### 4.8 PolicyAck
表示端侧对策略版本的确认结果。

#### 字段建议
- `device_id`
- `policy_id`
- `policy_version`
- `result`: `ack | nack | partial_ack`
- `reason`
- `unsupported_capabilities`
- `timestamp`

#### 关键价值
- 保证发布可追踪
- 支持 capability 不满足时的部分生效

---

## 5. 最小 API 草图

### 5.1 Device API

#### `POST /api/v1/devices/register`
用途：首次注册设备。

请求体示例：
```json
{
  "hostname": "db-prod-01",
  "os_type": "linux",
  "os_version": "ubuntu-24.04",
  "kernel_version": "6.8.0",
  "agent_version": "0.1.0"
}
```

响应体示例：
```json
{
  "device_id": "dev_123",
  "token": "signed-bootstrap-token",
  "assigned_tenant_id": "tenant_default"
}
```

#### `POST /api/v1/devices/{device_id}/heartbeat`
用途：设备定期回传健康状态、资源指标、当前生效策略。

#### `POST /api/v1/devices/{device_id}/capabilities`
用途：上报能力画像。

#### `GET /api/v1/devices`
用途：按标签、状态、版本筛选设备。

### 5.2 Policy API

#### `POST /api/v1/policies`
创建逻辑策略对象。

#### `POST /api/v1/policies/{policy_id}/versions`
创建新版本。

#### `GET /api/v1/policies/{policy_id}/versions/{version}`
获取具体版本。

#### `POST /api/v1/policies/{policy_id}/versions/{version}/approve`
审批通过一个版本。

### 5.3 Rollout API

#### `POST /api/v1/rollouts`
创建灰度发布计划。

请求体示例：
```json
{
  "policy_id": "policy_detect_linux",
  "policy_version": 12,
  "strategy": "staged",
  "target_scope": {
    "labels": ["prod", "linux"],
    "max_devices": 500
  },
  "stage_definitions": [
    {"name": "internal", "percent": 1},
    {"name": "canary", "percent": 5},
    {"name": "broad", "percent": 25},
    {"name": "full", "percent": 100}
  ]
}
```

#### `POST /api/v1/rollouts/{rollout_id}/pause`
暂停灰度。

#### `POST /api/v1/rollouts/{rollout_id}/resume`
恢复灰度。

#### `POST /api/v1/rollouts/{rollout_id}/rollback`
执行回滚。

### 5.4 Agent Pull API

#### `GET /api/v1/agents/{device_id}/desired-state`
用途：端侧拉取当前希望生效的配置。

响应体建议包含：
- 目标 `policy_id`
- 目标 `policy_version`
- 配置校验 hash
- 执行模式
- 回退版本
- 必需 capability

#### `POST /api/v1/agents/{device_id}/acks`
用途：端侧确认配置是否接收并成功应用。

### 5.5 Telemetry API

#### `POST /api/v1/telemetry/metrics`
上报 agent 指标。

#### `POST /api/v1/telemetry/alerts`
上报告警摘要或批量告警。

#### `POST /api/v1/telemetry/replay-metadata`
上报 replay 结果摘要与验证元信息。

---

## 6. 灰度策略建议

### 6.1 建议灰度阶段
1. **internal**：安全团队自有设备
2. **canary**：1%–5% 低风险设备
3. **limited**：10%–25% 目标群组
4. **detect-full**：检测模式全量
5. **prevent-canary**：阻断模式小流量
6. **prevent-broad**：阻断模式扩大

### 6.2 灰度判定条件
建议至少观察：
- agent 崩溃率
- CPU / memory 增量
- 事件 drop rate
- alerts 激增情况
- ack 成功率
- replay 验证通过率

### 6.3 自动回滚条件
最小自动回滚策略建议：
- `ack_success_rate < threshold`
- `collector_start_failure_rate > threshold`
- `cpu_pct_delta > threshold`
- `memory_mb_delta > threshold`
- `events_dropped > threshold`

---

## 7. 端侧下发模型

### 7.1 端侧推荐采用 Pull 模式
不建议全靠云侧主动 push。

推荐：
- 云侧维护 desired state
- 端侧 heartbeat 后拉取 desired state
- 端侧执行本地预检
- 成功后 ACK，失败后 NACK

优点：
- 更适合大规模端侧
- 更适合弱网络环境
- 更容易做幂等与重试

### 7.2 下发前预检
端侧必须做：
- agent 版本检查
- capability 检查
- 规则包签名校验
- 本地资源限制预估
- 是否允许 inline / detect-only 切换

### 7.3 原子切换
端侧切换策略时推荐采用：
- 下载到 staging 区
- 校验签名与 hash
- 本地 dry-run / compile
- 成功后原子切换
- 保留 previous stable version

---

## 8. 与 Battle Lab / Replay / Rule Studio 的关系
Control Plane 不是孤立存在，而是未来这几个系统的协调中心：

### 与 Battle Lab
- 下发场景
- 收集战场 replay 结果
- 记录场景与规则版本关系

### 与 Replay Lab
- 选择策略版本进行 replay
- 对比不同版本结果差异
- 管理 replay 资产元数据

### 与 Rule Studio
- 编辑规则后提交新版本
- 触发编译、预检、审批、灰度
- 关联场景验证结果与性能摘要

---

## 9. 最小实施建议

### 第一阶段（现在应该做）
- 先把对象模型稳定下来
- 不急着做完整 GUI
- 先做：
  - Device / Capability / Policy / PolicyVersion / Rollout / Rollback 数据模型
  - 最小 REST API 草图
  - desired-state / ack 协议

### 第二阶段
- 做最小 Control Plane 服务：
  - 设备注册
  - 心跳
  - 能力上报
  - 策略版本查询
  - 灰度下发

### 第三阶段
- 再进入 GUI 工作台：
  - Policy Center
  - Device Center
  - Rule Studio
  - Replay Lab

---

## 10. 推荐下一步
如果继续按产品路线前进，建议紧接着做：

1. 在仓库内补一份 **控制平面 Rust 数据模型草案**
2. 再补一份 **Battle Lab 编排器设计**
3. 然后定义 **Rule Studio / Replay Lab 所需 API 契约**

这样后续无论先做 CLI、Lab、还是 GUI，都不会跑偏。
