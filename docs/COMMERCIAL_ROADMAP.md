# Kestrel 商用化路线图

> 打造世界顶级的开源 EDR 引擎

---

## 愿景

成为**开源 EDR 领域的事实标准**，在性能、功能、易用性三个维度全面超越商业产品。

---

## 阶段规划

### 🚀 Phase 1: 生产就绪强化 (2026 Q1)

**目标**: 稳固现有功能，修复已知问题，达到企业部署标准

#### 核心任务

| 优先级 | 任务 | 工作量 | 负责人 |
|--------|------|--------|--------|
| P0 | NFA P99 延迟优化 (<10µs) | 1周 | 引擎团队 |
| P0 | eBPF 实际内核程序开发 | 2周 | 平台团队 |
| P0 | 完整 CI/CD 流水线 | 1周 | DevOps |
| P1 | 代码警告清理 | 3天 | 全团队 |
| P1 | 性能基准自动化 | 1周 | QA |
| P1 | 安全审计 & 漏洞扫描 | 1周 | 安全团队 |

#### 交付物

- [ ] 所有测试 100% 通过 (0 警告)
- [ ] 实际 eBPF 程序 (execve, open, connect)
- [ ] 自动化性能回归测试
- [ ] 安全审计报告
- [ ] v1.1.0 发布

#### 成功指标

```
✅ 测试通过率: 100% (262/262)
✅ 代码覆盖率: >80%
✅ 性能回归: 自动化检测 >10% 性能下降
✅ CVE 数量: 0 高危, 0 中危
```

---

### 🏗️ Phase 2: 企业级功能 (2026 Q2)

**目标**: 添加企业部署必需的管理和集成能力

#### 核心任务

| 模块 | 功能 | 描述 |
|------|------|------|
| **Web UI** | 管理界面 | React/Vue 现代化 Web 控制台 |
| | 实时监控 | 事件流、告警、指标可视化 |
| | 规则编辑器 | EQL 语法高亮、实时验证 |
| | 资产管理 | 终端资产发现和清单 |
| **API** | REST API | 完整的 HTTP API (OpenAPI 3.0) |
| | GraphQL | 灵活的数据查询接口 |
| | WebSocket | 实时事件推送 |
| **集成** | SIEM 连接器 | Splunk, Elastic, QRadar, Sentinel |
| | SOAR 集成 | Phantom, XSOAR, Tines |
| | 威胁情报 | MISP, TAXII, OTX 集成 |

#### Web UI 功能清单

```
Dashboard (仪表盘)
├── 实时事件流
├── 告警趋势图表
├── 系统健康状态
├── 规则命中率
└── 性能指标

Alerts (告警管理)
├── 告警列表 (筛选、排序)
├── 告警详情
├── 告警抑制
├── 导出/分享
└── 批量处理

Rules (规则管理)
├── 规则列表
├── 规则编辑器
├── 版本控制
├── 规则测试
├── 性能分析
└── 导入/导出

Assets (资产管理)
├── 终端列表
├── 资产详情
├── 标签管理
├── 分组管理
└── 健康状态

Configuration (配置)
├── 引擎配置
├── 集成配置
├── 用户管理
├── 权限设置
└── 审计日志
```

#### 技术栈

```
Frontend:
- React 18 + TypeScript
- Ant Design / Material-UI
- ECharts / D3.js
- WebSocket client

Backend API:
- Axum / Actix-web
- utoipa (OpenAPI)
- async-graphql
- JWT auth
```

---

### 🌐 Phase 3: 分布式与高可用 (2026 Q3)

**目标**: 支持大规模分布式部署

#### 架构设计

```
┌─────────────────────────────────────────────────────────────────┐
│                        控制平面                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │ API Gateway │  │   Web UI    │  │    Rule Distribution    │ │
│  └──────┬──────┘  └─────────────┘  └─────────────────────────┘ │
└─────────┼───────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                        数据平面                                  │
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │  Agent Node  │◄──►│  Agent Node  │◄──►│  Agent Node  │      │
│  │  (Region A)  │    │  (Region B)  │    │  (Region C)  │      │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘      │
│         │                   │                   │              │
│         └───────────────────┼───────────────────┘              │
│                             ▼                                  │
│                    ┌─────────────────┐                         │
│                    │  Message Queue  │                         │
│                    │  (Kafka/Pulsar) │                         │
│                    └────────┬────────┘                         │
│                             │                                  │
│         ┌───────────────────┼───────────────────┐              │
│         ▼                   ▼                   ▼              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │  Analyzer    │    │  Analyzer    │    │  Analyzer    │      │
│  │  (Primary)   │◄──►│  (Secondary) │    │  (Read)      │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### 核心功能

| 功能 | 描述 | 技术方案 |
|------|------|----------|
| 分布式 Agent | 跨区域部署 | gRPC + mTLS |
| 配置同步 | 规则/配置自动分发 | Raft / etcd |
| 数据聚合 | 多节点数据汇总 | Kafka / Pulsar |
| 高可用 | 主备自动切换 | Kubernetes Operator |
| 负载均衡 | 智能流量分配 | Envoy / Istio |

#### 部署模式

```yaml
# Kubernetes 部署示例
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kestrel-analyzer
spec:
  replicas: 3
  selector:
    matchLabels:
      app: kestrel-analyzer
  template:
    spec:
      containers:
      - name: analyzer
        image: kestrel/analyzer:v2.0
        resources:
          requests:
            memory: "4Gi"
            cpu: "2"
          limits:
            memory: "8Gi"
            cpu: "4"
        env:
        - name: KESTREL_MODE
          value: "distributed"
        - name: KESTREL_CLUSTER_PEERS
          value: "kestrel-0:9090,kestrel-1:9090,kestrel-2:9090"
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kestrel-agent
spec:
  template:
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: agent
        image: kestrel/agent:v2.0
        securityContext:
          privileged: true
        volumeMounts:
        - name: sys-kernel
          mountPath: /sys/kernel
        - name: bpf-fs
          mountPath: /sys/fs/bpf
```

---

### 🤖 Phase 4: 智能化与自动化 (2026 Q4)

**目标**: 引入 AI/ML 能力，实现智能威胁检测

#### AI 功能模块

```
Machine Learning Stack:
├── 异常检测引擎
│   ├── 用户行为基线 (UEBA)
│   ├── 进程行为基线
│   ├── 网络流量基线
│   └── 文件访问基线
│
├── 威胁检测模型
│   ├── 勒索软件检测
│   ├── 挖矿木马检测
│   ├── C2 通信检测
│   └── 横向移动检测
│
├── 智能告警
│   ├── 误报过滤
│   ├── 告警聚合
│   ├── 优先级排序
│   └── 上下文增强
│
└── 预测性分析
    ├── 攻击路径预测
    ├── 资产风险评分
    └── 威胁趋势预测
```

#### 技术实现

```rust
// Rust + ONNX Runtime 集成
use ort::{Environment, Session, Value};

pub struct AnomalyDetector {
    model: Session,
    baseline: BehaviorBaseline,
}

impl AnomalyDetector {
    pub fn detect(&self, event: &Event) -> AnomalyScore {
        let features = self.extract_features(event);
        let input = Value::from_array(features).unwrap();
        let outputs = self.model.run(vec![input]).unwrap();
        
        AnomalyScore {
            value: outputs[0].extract(),
            threshold: self.baseline.threshold(),
            confidence: outputs[1].extract(),
        }
    }
}
```

#### 模型训练流程

```python
# Python ML Pipeline
from kestrel_ml import FeatureExtractor, ModelTrainer

# 1. 特征提取
extractor = FeatureExtractor()
features = extractor.transform(events_df)

# 2. 模型训练
trainer = ModelTrainer(
    model_type='isolation_forest',
    contamination=0.01
)
model = trainer.fit(features)

# 3. 导出 ONNX
model.export_onnx('anomaly_detector.onnx')

# 4. 规则集成
rule = f'''
process where
    ml.anomaly_score > 0.8
    and process.executable != $TRUSTED_PROCESSES
'''
```

---

### 🌍 Phase 5: 生态建设 (2027+)

**目标**: 建立完整的开源生态系统

#### 规则市场

```
Kestrel Hub (规则市场)
├── 官方规则库
│   ├── MITRE ATT&CK 覆盖
│   ├── 勒索软件专项
│   ├── APT 组织追踪
│   └── 行业合规 (PCI-DSS, HIPAA, GDPR)
│
├── 社区规则
│   ├── 社区贡献
│   ├── 评分系统
│   └── 版本管理
│
└── 商业规则
    ├── 威胁情报厂商
    ├── MSSP 定制
    └── 订阅服务
```

#### 多平台支持

| 平台 | 优先级 | 状态 |
|------|--------|------|
| Linux (x86_64) | P0 | ✅ 已完成 |
| Linux (ARM64) | P1 | 🚧 进行中 |
| Windows | P1 | 📋 规划中 |
| macOS | P2 | 📋 规划中 |
| 容器/K8s | P1 | 🚧 进行中 |
| 嵌入式/IoT | P2 | 📋 规划中 |

#### 开发者生态

```
Developer Tools:
├── SDK
│   ├── Rust SDK (原生)
│   ├── Python SDK
│   ├── Go SDK
│   └── JavaScript SDK
│
├── CLI 工具
│   ├── kestrel-cli (已有)
│   ├── rule-dev (规则开发)
│   ├── log-converter (日志转换)
│   └── benchmark (性能测试)
│
├── IDE 插件
│   ├── VS Code EQL 插件
│   ├── IntelliJ 插件
│   └── Vim/Neovim 插件
│
└── 集成示例
    ├── SIEM 集成示例
    ├── SOAR Playbook
    ├── Terraform 模块
    └── Ansible Role
```

---

## 里程碑时间表

```
2026 Q1  [Phase 1]  ████████████████████  生产就绪 v1.1
         - eBPF 内核程序
         - 性能优化
         - 安全审计

2026 Q2  [Phase 2]  ████████████████████  企业功能 v2.0
         - Web UI
         - REST API
         - SIEM/SOAR 集成

2026 Q3  [Phase 3]  ████████████████████  分布式 v2.5
         - K8s Operator
         - 多区域部署
         - 高可用架构

2026 Q4  [Phase 4]  ████████████████████  智能化 v3.0
         - ML 异常检测
         - UEBA
         - 自动化响应

2027+    [Phase 5]  ████████████████████  生态完善 v4.0
         - 规则市场
         - Windows 支持
         - 开发者生态
```

---

## 竞争分析

### 与商业产品对比

| 维度 | Kestrel (2027) | CrowdStrike | SentinelOne | Elastic |
|------|----------------|-------------|-------------|---------|
| **性能** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **检测能力** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **易用性** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| **成本** | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐⭐ |
| **开源** | ✅ | ❌ | ❌ | ❌ |
| **可控性** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |

### 差异化优势

```
Kestrel 核心差异化:

1. 极致性能
   - 单节点 15K+ EPS
   - <100µs P99 延迟
   - 内存占用 <1MB

2. 完全可控
   - 源码开放
   - 无供应商锁定
   - 自主可控部署

3. 成本优势
   - 0 许可证费用
   - 灵活部署
   - 社区支持

4. 技术领先
   - Rust + eBPF
   - Wasm/Lua 双运行时
   - AI/ML 原生集成
```

---

## 成功指标

### 技术指标

```
2026 目标:
├── 性能
│   ├── 吞吐量: >15K EPS (单节点)
│   ├── P99 延迟: <100µs
│   └── 内存: <50MB (空闲)
│
├── 可靠性
│   ├── 可用性: 99.99%
│   ├── 数据丢失率: 0%
│   └── 误报率: <1%
│
└── 规模
    ├── 支持终端数: 100,000+
    ├── 规则数: 10,000+
    └── 事件存储: PB 级
```

### 社区指标

```
2026 目标:
├── GitHub Stars: 10,000+
├── 贡献者: 100+
├── 企业用户: 50+
├── 规则包下载: 100,000+
└── 文档访问量: 1M+
```

---

## 资源需求

### 人力资源

| 角色 | Phase 1 | Phase 2 | Phase 3 | Phase 4 | Phase 5 |
|------|---------|---------|---------|---------|---------|
| Rust 核心开发 | 2 | 2 | 3 | 3 | 3 |
| 前端开发 | 0 | 2 | 2 | 2 | 2 |
| eBPF 开发 | 1 | 1 | 2 | 2 | 2 |
| ML 工程师 | 0 | 0 | 1 | 2 | 2 |
| DevOps | 1 | 1 | 2 | 2 | 2 |
| 技术文档 | 1 | 1 | 1 | 1 | 2 |
| 社区运营 | 0 | 1 | 1 | 1 | 2 |
| **总计** | **5** | **8** | **12** | **15** | **17** |

### 基础设施

```
开发环境:
├── CI/CD: GitHub Actions + Self-hosted runners
├── 测试环境: AWS/Azure 多区域
├── 性能测试: 专用裸金属服务器
└── 文档托管: GitHub Pages + CDN

生产示例:
├── 负载均衡: CloudFlare / AWS ALB
├── 消息队列: Apache Kafka
├── 存储: MinIO / S3
└── 监控: Prometheus + Grafana
```

---

## 风险与缓解

| 风险 | 影响 | 概率 | 缓解措施 |
|------|------|------|----------|
| eBPF 兼容性 | 高 | 中 | CO-RE, 多内核版本测试 |
| 性能未达预期 | 高 | 低 | 持续基准测试, 回滚方案 |
| 安全漏洞 | 高 | 低 | 代码审计, 漏洞赏金 |
| 社区增长缓慢 | 中 | 中 | 营销投入, 合作伙伴 |
| 人才流失 | 中 | 低 | 知识文档化, 备份负责人 |

---

## 结语

Kestrel 有潜力成为**开源 EDR 领域的 Linux**:
- 技术领先 (Rust + eBPF)
- 性能卓越 (15K+ EPS)
- 完全开源 (Apache 2.0)
- 社区驱动

通过本路线图的执行，Kestrel 将在 2027 年达到世界顶级 EDR 引擎水平，为全球企业提供安全可控的端点防护方案。

---

**路线图版本**: v1.0  
**最后更新**: 2026-02-02  
**下次评审**: 2026-03-01
