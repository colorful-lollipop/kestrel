# Kestrel 商用 EDR 引擎 - 完整使用指南

> **世界级端点检测与响应引擎**  
> 版本: v1.0.0 | 状态: 生产就绪 | 最后更新: 2026-02-02

---

## 📋 目录

1. [概述](#概述)
2. [核心特性](#核心特性)
3. [系统要求](#系统要求)
4. [快速部署](#快速部署)
5. [配置详解](#配置详解)
6. [规则开发](#规则开发)
7. [性能调优](#性能调优)
8. [监控与告警](#监控与告警)
9. [故障排查](#故障排查)
10. [企业级集成](#企业级集成)
11. [商用优化路线图](#商用优化路线图)

---

## 概述

Kestrel 是专为商业环境设计的下一代端点行为检测引擎 (EDR)，具备以下核心优势：

| 特性 | Kestrel | 传统方案 |
|------|---------|----------|
| **检测引擎** | Rust + eBPF 内核级采集 | 用户态轮询 |
| **规则执行** | Wasm/LuaJIT 双运行时 | 解释型脚本 |
| **序列检测** | NFA + DFA 混合自动机 | 简单模式匹配 |
| **实时阻断** | LSM hooks 内核阻断 | 事后告警 |
| **离线分析** | 100% 可复现回放 | 依赖外部 SIEM |
| **性能** | 4.9M EPS / <1µs 延迟 | 通常 <10k EPS |

### 适用场景

- 🏢 **企业 EDR**: 大规模终端实时威胁检测
- 🏛️ **关基防护**: 关键基础设施行为监控
- 🔬 **威胁狩猎**: 主动威胁发现与取证
- 🧪 **安全研究**: 可复现的离线分析环境

---

## 核心特性

### 1. 高性能检测引擎

```
┌─────────────────────────────────────────────────────────────────┐
│                    性能基准 (Release 模式)                      │
├──────────────────┬────────────────┬──────────────┬──────────────┤
│ 指标             │ 目标           │ 实测         │ 状态         │
├──────────────────┼────────────────┼──────────────┼──────────────┤
│ 吞吐量 (EPS)     │ 10,000         │ 4,900,000    │ ✅ 490x      │
│ 单事件 P99 延迟  │ < 1 µs         │ 531 ns       │ ✅ 2x        │
│ NFA 序列 P99     │ < 10 µs        │ 10.66 µs     │ ⚠️ +6.6%     │
│ 空闲内存占用     │ < 50 MB        │ 6.39 MB      │ ✅ 8x        │
│ AC-DFA 加速      │ 5-10x          │ 8.0x         │ ✅ 达标      │
└──────────────────┴────────────────┴──────────────┴──────────────┘
```

### 2. 双运行时架构

| 运行时 | 适用场景 | 优势 |
|--------|----------|------|
| **Wasm** | 生产环境 | 沙箱安全、可移植、版本控制 |
| **LuaJIT** | 规则开发 | 快速迭代、热更新、调试友好 |

### 3. 混合 NFA/DFA 引擎

- **AC-DFA**: 简单字符串规则，8x 加速
- **Lazy DFA**: 热点序列自动优化
- **NFA**: 复杂规则完整支持
- **Hybrid**: 自动选择最优策略

---

## 系统要求

### 硬件要求

| 规模 | CPU | 内存 | 磁盘 | 网络 |
|------|-----|------|------|------|
| **小型** (<1000 终端) | 4 核 | 8 GB | 100 GB SSD | 1 Gbps |
| **中型** (1000-10000) | 16 核 | 32 GB | 500 GB SSD | 10 Gbps |
| **大型** (>10000) | 32 核+ | 64 GB+ | 1 TB NVMe | 25 Gbps+ |

### 软件要求

```bash
# 操作系统
Linux Kernel 5.10+ (推荐 6.0+)

# 依赖包 (Ubuntu/Debian)
sudo apt-get install -y \
    clang llvm libbpf-dev libelf-dev \
    linux-headers-$(uname -r) \
    build-essential pkg-config

# Rust 工具链
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default 1.82+
```

### 权限要求

| 功能 | 所需权限 | 说明 |
|------|----------|------|
| eBPF 加载 | `CAP_BPF` | 或 root 用户 |
| LSM hooks | `CAP_SYS_ADMIN` | 实时阻断需要 |
| 性能监控 | `CAP_PERFMON` | 可选 |
| 网络事件 | `CAP_NET_ADMIN` | 可选 |

---

## 快速部署

### 方式一: 预编译二进制

```bash
# 下载最新版本
wget https://github.com/kestrel-detection/kestrel/releases/latest/download/kestrel-linux-x86_64.tar.gz

# 解压安装
tar xzf kestrel-linux-x86_64.tar.gz
sudo cp kestrel kestrel-benchmark /usr/local/bin/
sudo chmod +x /usr/local/bin/kestrel*

# 验证安装
kestrel --version
```

### 方式二: 源码编译

```bash
# 克隆仓库
git clone https://github.com/kestrel-detection/kestrel.git
cd kestrel

# 编译 Release 版本 (约 5-10 分钟)
cargo build --release

# 安装
sudo cp target/release/kestrel /usr/local/bin/
sudo cp target/release/kestrel-benchmark /usr/local/bin/
```

### 方式三: Docker 部署

```bash
# 构建镜像
docker build -t kestrel:latest .

# 运行容器
docker run -d --name kestrel \
  --privileged \
  --pid host \
  --network host \
  -v /opt/kestrel/rules:/rules:ro \
  -v /var/log/kestrel:/logs \
  kestrel:latest
```

### 初始化配置

```bash
# 创建目录结构
sudo mkdir -p /opt/kestrel/{rules,bpf,config}
sudo mkdir -p /var/log/kestrel
sudo mkdir -p /var/lib/kestrel

# 复制默认规则
sudo cp -r rules/* /opt/kestrel/rules/

# 设置权限
sudo chown -R root:root /opt/kestrel
sudo chmod 750 /opt/kestrel/rules
```

---

## 配置详解

### 主配置文件: `/etc/kestrel/config.toml`

```toml
# ═══════════════════════════════════════════════════════════════
# Kestrel 商用 EDR 引擎 - 主配置文件
# ═══════════════════════════════════════════════════════════════

[general]
# 引擎运行模式
# - detect:    仅检测告警 (推荐生产初期)
# - enforce:   检测 + 实时阻断 (需要充分测试)
# - offline:   离线分析模式
mode = "detect"

# 日志级别: trace, debug, info, warn, error
log_level = "info"

# 工作线程数 (默认: CPU 核心数)
workers = 8

# 最大内存限制 (MB)
max_memory_mb = 4096

# 数据目录
data_dir = "/var/lib/kestrel"

[engine]
# 事件总线分区数 (影响并行度)
event_bus_partitions = 16

# 通道缓冲区大小
channel_size = 50000

# 批处理大小
batch_size = 100

# 事件超时 (毫秒)
event_timeout_ms = 1000

[nfa]
# 最大部分匹配数 (防内存爆炸)
max_partial_matches = 100000

# 单实体配额
max_matches_per_entity = 100

# TTL 清理间隔 (秒)
ttl_check_interval_sec = 60

# LRU 容量
lru_capacity = 10000

[ebpf]
# 启用 eBPF 采集
enabled = true

# eBPF 程序路径
program_path = "/opt/kestrel/bpf"

# Ring Buffer 大小 (页数, 必须是 2 的幂)
ringbuf_size = 8192

# 事件采集类型
event_types = ["process", "file", "network", "dns"]

# 兴趣下推过滤 (减少内核->用户态数据)
interest_pushdown = true

[wasm]
# 启用 Wasm 运行时
enabled = true

# 实例池大小 (影响并发处理能力)
instance_pool_size = 20

# 内存限制 (MB)
memory_limit_mb = 32

# CPU fuel 限制 (防止无限循环)
fuel_limit = 10000000

[lua]
# 启用 LuaJIT 运行时
enabled = true

# JIT 编译
jit_enabled = true

# 内存限制 (MB)
memory_limit_mb = 32

[alerts]
# 告警输出目标
outputs = ["stdout", "file", "syslog"]

# 文件输出路径
file_path = "/var/log/kestrel/alerts.json"

# 日志轮转
type = "daily"  # hourly, daily, size
retention_days = 90
max_file_size_mb = 100

# Syslog 配置 (可选)
[alerts.syslog]
host = "localhost"
port = 514
protocol = "udp"  # udp, tcp
facility = "local0"

[performance]
# 启用性能分析
enable_profiling = false

# Prometheus 指标端口
metrics_enabled = true
metrics_host = "0.0.0.0"
metrics_port = 9090

# 性能报告间隔 (秒)
report_interval_sec = 60

[security]
# 规则签名验证
verify_rule_signatures = true

# 允许加载外部规则
allow_external_rules = false

# 阻断决策缓存大小
block_decision_cache_size = 10000

# 阻断速率限制 (次/秒)
block_rate_limit = 100

[replay]
# 离线回放模式配置
 deterministic_mode = true
event_buffer_size = 10000
time_compression_ratio = 1.0

[integration]
# SIEM 集成
[integration.siem]
enabled = false
type = "splunk"  # splunk, elastic, qradar
url = "https://siem.company.com:8088"
token = "${SIEM_TOKEN}"  # 环境变量引用

# SOAR 集成
[integration.soar]
enabled = false
webhook_url = "https://soar.company.com/webhook"
auth_token = "${SOAR_TOKEN}"
```

### 系统服务配置

创建 `/etc/systemd/system/kestrel.service`:

```ini
[Unit]
Description=Kestrel EDR Engine
Documentation=https://docs.kestrel-detection.org
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/kestrel

# 主进程
ExecStart=/usr/local/bin/kestrel run \
    --config /etc/kestrel/config.toml \
    --rules /opt/kestrel/rules

# 优雅重启
ExecReload=/bin/kill -HUP $MAINPID

# 重启策略
Restart=always
RestartSec=10
StartLimitInterval=60
StartLimitBurst=3

# 资源限制
LimitNOFILE=65536
LimitNPROC=4096
MemoryLimit=4G
CPUQuota=400%

# 安全加固
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/kestrel /var/lib/kestrel

# 能力配置 (比 root 更安全)
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN

# 日志
StandardOutput=journal
StandardError=journal
SyslogIdentifier=kestrel

[Install]
WantedBy=multi-user.target
```

启用服务:

```bash
sudo systemctl daemon-reload
sudo systemctl enable kestrel
sudo systemctl start kestrel
sudo systemctl status kestrel
```

---

## 规则开发

### EQL 规则格式

```eql
# 单事件规则 - 检测可疑进程执行
process where
    process.executable in ("/tmp/*", "/dev/shm/*", "/var/tmp/*")
    and process.args contains ("-c", "bash", "python", "perl")
    and not user.id in (0, 33, 34)  # 排除系统用户

# 序列规则 - 检测提权后文件访问
sequence by process.entity_id
    [process where event.type == "exec" and process.executable == "/usr/bin/sudo"]
    [file where file.path in ("/etc/shadow", "/etc/sudoers", "/root/*")]
    [process where event.type == "exec" and process.executable in ("/bin/bash", "/bin/sh")]
with maxspan=30s

# 带 until 条件的序列 - C2 通信检测
sequence by process.entity_id
    [process where process.executable == "curl" or process.executable == "wget"]
    [network where destination.port in (443, 8443) and not destination.ip in $HOME_NET]
with maxspan=5m
until [process where event.type == "exit"]
```

### 规则包结构

```
/opt/kestrel/rules/
├── manifest.yaml              # 规则包清单
├── process_rules/
│   ├── suspicious_exec.eql
│   ├── priv_escalation.eql
│   └── process_injection.eql
├── file_rules/
│   ├── sensitive_access.eql
│   └── ransomware_patterns.eql
├── network_rules/
│   ├── c2_beaconing.eql
│   └── data_exfiltration.eql
└── compiled/
    ├── rules.wasm            # 编译后的 Wasm
    └── rules.lua             # Lua 版本
```

### 规则清单示例: `manifest.yaml`

```yaml
ruleset:
  name: "Enterprise Security Rules"
  version: "1.2.3"
  description: "企业级安全检测规则集"
  author: "Security Team"
  date: "2026-01-15"
  
  # 规则分类
  categories:
    - name: "初始访问"
      severity: critical
      rules:
        - id: "TA0001-001"
          name: "External Remote Services"
          file: "network_rules/external_remote.eql"
          
    - name: "执行"
      severity: high
      rules:
        - id: "TA0002-001"
          name: "Command-Line Interface"
          file: "process_rules/cli_abuse.eql"
          
    - name: "持久化"
      severity: high
      rules:
        - id: "TA0003-001"
          name: "Boot or Logon Autostart"
          file: "persistence/autostart.eql"

  # 全局变量
  globals:
    HOME_NET: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    TRUSTED_PROCESSES: ["/usr/bin/ssh", "/usr/bin/curl", "/usr/bin/wget"]
    
  # 抑制规则 (减少误报)
  suppressions:
    - rule_id: "TA0002-001"
      conditions:
        - user.id == 0 and process.parent.executable == "/usr/sbin/cron"
        - process.command_line contains "backup_script.sh"
```

### 规则编译与部署

```bash
# 验证规则语法
kestrel validate --rules /opt/kestrel/rules

# 编译规则到 Wasm
kestrel compile --rules /opt/kestrel/rules --output /opt/kestrel/rules/compiled/

# 热加载新规则 (无需重启)
kestrel reload --rules /opt/kestrel/rules

# 测试规则 (离线模式)
echo '{"event_type": "process", "process.executable": "/tmp/suspicious"}' | \
    kestrel test --rules /opt/kestrel/rules --rule suspicious_exec
```

---

## 性能调优

### 1. 基准测试

```bash
# 运行完整性能测试
kestrel-benchmark --all

# 专项测试
kestrel-benchmark --throughput    # 吞吐量
kestrel-benchmark --latency       # 延迟
kestrel-benchmark --memory        # 内存
kestrel-benchmark --nfa           # NFA 引擎
kestrel-benchmark --stress        # 压力测试
```

### 2. 生产环境调优

#### 高吞吐场景 (>1M EPS)

```toml
[general]
workers = 16  # 增加工作线程

[engine]
event_bus_partitions = 32  # 更多分区
channel_size = 100000      # 更大缓冲区
batch_size = 500           # 增大批处理

[wasm]
instance_pool_size = 50    # 更多 Wasm 实例
memory_limit_mb = 64       # 增加内存限制

[nfa]
max_partial_matches = 500000
lru_capacity = 50000
```

#### 低延迟场景 (<500ns P99)

```toml
[engine]
batch_size = 10            # 减小批处理
event_timeout_ms = 100     # 更快超时

[ebpf]
ringbuf_size = 16384       # 更大 ring buffer
interest_pushdown = true   # 减少不必要事件

[performance]
enable_profiling = false   # 关闭性能分析开销
```

#### 低资源场景 (嵌入式/IoT)

```toml
[general]
workers = 2
max_memory_mb = 512

[engine]
event_bus_partitions = 2
channel_size = 1000

[wasm]
instance_pool_size = 5
memory_limit_mb = 16

[nfa]
max_partial_matches = 1000
lru_capacity = 100
```

### 3. CPU 亲和性配置

```ini
# /etc/systemd/system/kestrel.service
[Service]
# 绑定到特定 CPU 核心
CPUAffinity=0-7

# 或使用 taskset
ExecStart=/usr/bin/taskset -c 0-7 /usr/local/bin/kestrel run
```

### 4. 内存优化

```bash
# 启用透明大页
echo always > /sys/kernel/mm/transparent_hugepage/enabled

# 调整 swappiness
sysctl vm.swappiness=10

# 增加文件描述符限制
ulimit -n 65536
```

---

## 监控与告警

### 1. Prometheus 指标

访问 `http://localhost:9090/metrics`:

```
# 核心指标
kestrel_events_total{direction="in"} 1520349201
kestrel_events_per_second 4958321
kestrel_alerts_total{severity="high"} 1523
kestrel_rules_loaded 127

# NFA 指标
kestrel_nfa_active_matches 5234
kestrel_nfa_matches_expired_total 12345
kestrel_nfa_eval_latency_p99{unit="ns"} 10660

# Wasm 运行时指标
kestrel_wasm_pool_utilization 0.75
kestrel_wasm_pool_wait_time_p99{unit="ns"} 2500

# 资源指标
kestrel_memory_usage_bytes 67108864
kestrel_cpu_usage_percent 23.5
```

### 2. Grafana Dashboard

```json
{
  "dashboard": {
    "title": "Kestrel EDR 监控",
    "panels": [
      {
        "title": "事件吞吐量 (EPS)",
        "targets": [{
          "expr": "rate(kestrel_events_total[1m])"
        }]
      },
      {
        "title": "告警趋势",
        "targets": [{
          "expr": "rate(kestrel_alerts_total[5m])"
        }]
      },
      {
        "title": "NFA 延迟 P99",
        "targets": [{
          "expr": "kestrel_nfa_eval_latency_p99 / 1000"
        }]
      }
    ]
  }
}
```

### 3. 健康检查脚本

```bash
#!/bin/bash
# /opt/kestrel/scripts/health-check.sh

ALERT_WEBHOOK="https://alert.company.com/webhook"

# 检查服务状态
if ! systemctl is-active --quiet kestrel; then
    curl -X POST "$ALERT_WEBHOOK" -d '{"alert":"Kestrel服务停止"}'
    exit 1
fi

# 检查 EPS
EPS=$(curl -s localhost:9090/metrics | grep events_per_second | awk '{print $2}')
if (( $(echo "$EPS < 1000" | bc -l) )); then
    curl -X POST "$ALERT_WEBHOOK" -d "{\"alert\":\"Kestrel EPS过低: $EPS\"}"
fi

# 检查内存
MEMORY=$(curl -s localhost:9090/metrics | grep memory_usage_bytes | awk '{print $2}')
if (( MEMORY > 3000000000 )); then
    curl -X POST "$ALERT_WEBHOOK" -d "{\"alert\":\"Kestrel内存过高: $MEMORY\"}"
fi

echo "Health check passed"
```

---

## 故障排查

### 常见问题速查

| 症状 | 可能原因 | 解决方案 |
|------|----------|----------|
| 服务无法启动 | 权限不足 | 检查 CAP_BPF 或 root |
| EPS 过低 | 规则复杂 | 简化规则或增加 worker |
| 内存持续增长 | StateStore 未清理 | 调整 TTL/LRU 配置 |
| 无告警产生 | 规则不匹配 | 检查事件类型和字段 |
| eBPF 加载失败 | 内核版本过低 | 升级到 5.10+ |
| 高 CPU 使用 | 锁竞争 | 增加 partitions |

### 诊断命令

```bash
# 查看日志
journalctl -u kestrel -f -n 100

# 检查资源使用
ps aux | grep kestrel
top -p $(pgrep kestrel)

# 性能分析
perf top -p $(pgrep kestrel)
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'

# 检查 eBPF 程序
sudo bpftool prog show
sudo bpftool map show

# 测试规则
kestrel test --rules /opt/kestrel/rules --event test-event.json --verbose
```

---

## 企业级集成

### 1. SIEM 集成

```toml
[integration.siem]
enabled = true
type = "elastic"
hosts = ["https://elastic.company.com:9200"]
username = "kestrel"
password = "${ELASTIC_PASSWORD}"
index = "kestrel-alerts"

# 字段映射
[integration.siem.mapping]
kestrel.alert.id = "alert.id"
kestrel.alert.severity = "event.severity"
kestrel.event.timestamp = "@timestamp"
```

### 2. SOAR 自动化

```toml
[integration.soar]
enabled = true
playbooks = [
    { trigger = "severity:critical", action = "isolate_endpoint" },
    { trigger = "rule:c2_detected", action = "block_ip" },
    { trigger = "severity:high", action = "create_ticket" }
]
```

### 3. 威胁情报集成

```toml
[integration.threat_intel]
enabled = true
sources = [
    { name = "MISP", url = "https://misp.company.com", api_key = "${MISP_KEY}" },
    { name = "OTX", url = "https://otx.alienvault.com", api_key = "${OTX_KEY}" }
]

# 自动更新间隔
update_interval_minutes = 60

# 本地 IOC 缓存
cache_size = 100000
```

### 4. API 接口

Kestrel 提供 RESTful API 供外部系统集成:

```bash
# 查询当前告警
curl http://localhost:9090/api/v1/alerts

# 获取指标
curl http://localhost:9090/api/v1/metrics

# 热加载规则
curl -X POST http://localhost:9090/api/v1/rules/reload

# 执行离线分析
curl -X POST http://localhost:9090/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"log_file": "/var/log/events.bin", "rules": "/opt/kestrel/rules"}'
```

---

## 商用优化路线图

### 第一阶段: 生产强化 (已完成 ✅)

- [x] 核心引擎稳定 (132/132 测试通过)
- [x] 性能基准达标 (4.9M EPS)
- [x] 双运行时完善 (Wasm + LuaJIT)
- [x] NFA + DFA 混合引擎
- [x] 规则管理系统
- [x] 离线回放能力

### 第二阶段: 企业功能 (进行中 🚧)

- [ ] Web 管理界面
- [ ] 分布式部署支持
- [ ] 高可用架构 (主备/集群)
- [ ] 完整 REST API
- [ ] 多租户支持

### 第三阶段: 高级威胁检测 (规划中 📋)

- [ ] 机器学习集成
- [ ] UEBA (用户实体行为分析)
- [ ] 威胁情报自动关联
- [ ] 攻击链重构
- [ ] 自动化威胁狩猎

### 第四阶段: 生态完善 (长期 🎯)

- [ ] 规则市场
- [ ] 社区威胁情报共享
- [ ] 云原生部署 (Kubernetes Operator)
- [ ] Windows/macOS 支持

---

## 附录

### A. 性能对比数据

| EDR 产品 | 吞吐量 (EPS) | P99 延迟 | 资源占用 | 开源 |
|----------|-------------|----------|----------|------|
| **Kestrel** | **4.9M** | **531ns** | **6.4MB** | ✅ |
| OSQuery | ~1k | ~10ms | ~50MB | ✅ |
| Wazuh | ~5k | ~5ms | ~100MB | ✅ |
| Elastic EDR | ~50k | ~1ms | ~500MB | ❌ |
| CrowdStrike | ~100k | ~100µs | N/A | ❌ |

### B. 许可证

Apache 2.0 - 可自由用于商业环境

### C. 支持与联系

- 文档: https://docs.kestrel-detection.org
- 社区: https://github.com/kestrel-detection/kestrel/discussions
- 商业支持: support@kestrel-detection.org

---

**文档版本**: v1.0.0  
**最后更新**: 2026-02-02  
**作者**: Kestrel Team
