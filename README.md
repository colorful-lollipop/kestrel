# Kestrel

**下一代端侧行为检测引擎**

Rust + eBPF + Host执行NFA + Wasm/LuaJIT双运行时 + EQL兼容子集

面向：Linux与Harmony（类Unix可移植），端侧低功耗实时检测/阻断 + 离线可复现回放

## 当前状态 (Phase 0 - 架构骨架)

项目正在按照[技术方案](./plan.md)进行开发。当前完成 Phase 0 的基础架构：

- ✅ Event Schema v1（字段ID、类型系统、规范化库）
- ✅ EventBus（批处理、背压、分区策略原型）
- ✅ RuleManager（本地目录加载、版本切换、原子替换）
- ✅ 基础告警通路（alert 输出到本地文件/stdout）
- ✅ CLI 工具基础框架

## 项目架构

```
kestrel/
├── kestrel-schema/      # 事件Schema与类型系统
├── kestrel-event/       # 事件数据结构
├── kestrel-core/        # 核心组件（EventBus, Alert系统）
├── kestrel-rules/       # 规则管理与加载
├── kestrel-engine/      # 检测引擎核心
├── kestrel-runtime-wasm/ # Wasm运行时（Phase 1）
├── kestrel-runtime-lua/  # Lua运行时（Phase 2）
└── kestrel-cli/         # 命令行工具
```

## 快速开始

### 前置要求

- Rust 1.82+ (edition 2021)
- Git
- 推荐使用最新稳定版 Rust

```bash
# 安装 Rust（如果尚未安装）
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 构建

```bash
# 克隆仓库
git clone <repository-url>
cd Kestrel

# 构建项目
cargo build --release

# 运行测试
cargo test --workspace
```

### 使用

#### 1. 运行检测引擎

```bash
# 使用默认规则目录（./rules）
cargo run --bin kestrel -- run

# 指定规则目录
cargo run --bin kestrel -- run --rules /path/to/rules

# 设置日志级别
cargo run --bin kestrel -- run --log-level debug
```

#### 2. 验证规则

```bash
# 验证规则语法和结构
cargo run --bin kestrel -- validate --rules ./rules
```

#### 3. 列出规则

```bash
# 列出所有已加载的规则
cargo run --bin kestrel -- list --rules ./rules
```

## 规则格式

规则支持多种格式：

### JSON 格式

```json
{
  "id": "rule-001",
  "name": "Suspicious Process Execution",
  "description": "Detects suspicious process execution patterns",
  "version": "1.0.0",
  "author": "Security Team",
  "tags": ["process", "execution"],
  "severity": "High"
}
```

### YAML 格式

```yaml
id: rule-001
name: Suspicious Process Execution
description: Detects suspicious process execution patterns
version: "1.0.0"
author: Security Team
tags:
  - process
  - execution
severity: High
```

### EQL 格式

```eql
sequence by process.entity_id
  [process where event.type == "exec" and process.name == "suspicious"]
  [file where event.type == "create" and file.extension == "exe"]
```

## 测试

项目使用测试驱动开发（TDD）方法：

```bash
# 运行所有测试
cargo test --workspace

# 运行特定测试
cargo test -p kestrel-schema

# 运行测试并显示输出
cargo test --workspace -- --nocapture

# 运行测试并生成覆盖率报告（需要安装 tarpaulin）
cargo install tarpaulin
cargo tarpaulin --workspace --out Html
```

## 开发路线图

### Phase 0: 架构骨架 ✅ (当前)
- [x] Event Schema v1
- [x] EventBus
- [x] RuleManager
- [x] 基础告警系统

### Phase 1: Wasm 运行时 (下一步)
- [ ] 集成 Wasmtime
- [ ] Host API v1
- [ ] 规则包格式

### Phase 2: LuaJIT 运行时
- [ ] LuaJIT Runtime FFI
- [ ] 与 Wasm 统一 Predicate ABI

### Phase 3: EQL 编译器
- [ ] EQL parser
- [ ] 语义/类型规则
- [ ] IR 设计
- [ ] 兼容性测试基线

### Phase 4: Host NFA 序列引擎
- [ ] NFA/partial match 引擎
- [ ] maxspan/until/by 语义
- [ ] StateStore

### Phase 5: Linux eBPF 采集
- [ ] Aya + CO-RE
- [ ] 事件规范化
- [ ] 规则兴趣下推

### Phase 6: 实时阻断
- [ ] LSM hooks 集成
- [ ] Inline Guard
- [ ] Actions 系统

### Phase 7: 离线可复现
- [ ] 二进制日志格式
- [ ] Offline replay
- [ ] 一致性测试

## 核心设计原则

1. **统一事件流**：eBPF/审计/用户态 API 统一为强类型事件流
2. **EQL 规则体系**：用业内成熟的 EQL 表达"动态行为序列"
3. **双运行时统一**：Wasm（标准、可移植）和 LuaJIT（灵活、快速）共享同一 Host API
4. **实时阻断与离线复现**：同一规则、同一检测核在两种模式下运行
5. **完全可复现**：同一日志+规则+引擎版本 → 同一告警与证据

## 性能目标

- **端侧（笔记本）**：1k EPS 峰值下稳定运行
- **低 CPU 占用**：可控内存
- **低功耗策略**：可配置

## 贡献指南

欢迎贡献！请遵循以下步骤：

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

### 代码规范

- 使用 `cargo fmt` 格式化代码
- 使用 `cargo clippy --workspace` 进行代码检查
- 确保所有测试通过 (`cargo test --workspace`)
- 为新功能添加测试

## 许可证

本项目采用 Apache License 2.0 - 详见 [LICENSE](LICENSE) 文件

## 技术支持

- 问题反馈：[GitHub Issues](https://github.com/kestrel-detection/kestrel/issues)
- 文档：[docs/](./docs/)
- 技术方案：[plan.md](./plan.md)

## 致谢

感谢所有为 Kestrel 项目做出贡献的开发者。

---

**Kestrel** - 下一代端侧行为检测引擎
