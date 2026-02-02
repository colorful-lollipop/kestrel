# Kestrel 快速启动指南

> 5 分钟内部署世界级 EDR 引擎

---

## 前置条件

```bash
# 检查系统要求
uname -r  # 需要 5.10+
cargo --version  # 需要 1.82+
clang --version  # 需要 clang 10+
```

---

## 方式一: Docker 快速启动 (推荐)

```bash
# 1. 启动 Kestrel
docker run -d --name kestrel \
  --privileged --pid host --network host \
  -v /opt/kestrel/rules:/rules:ro \
  kestrel/detection:latest

# 2. 查看状态
docker logs -f kestrel

# 3. 测试
curl http://localhost:9090/metrics
```

---

## 方式二: 二进制部署

```bash
# 1. 下载
wget https://github.com/kestrel-detection/kestrel/releases/latest/download/kestrel-linux-x86_64.tar.gz
tar xzf kestrel-linux-x86_64.tar.gz

# 2. 安装
sudo cp kestrel /usr/local/bin/
sudo chmod +x /usr/local/bin/kestrel

# 3. 初始化
sudo mkdir -p /opt/kestrel/rules
sudo kestrel init --path /opt/kestrel

# 4. 启动
sudo kestrel run --rules /opt/kestrel/rules
```

---

## 方式三: 源码构建

```bash
# 1. 克隆
git clone https://github.com/kestrel-detection/kestrel.git
cd kestrel

# 2. 构建
cargo build --release

# 3. 运行
sudo ./target/release/kestrel run --rules ./rules
```

---

## 验证部署

```bash
# 检查服务状态
kestrel status

# 查看指标
curl http://localhost:9090/metrics

# 运行基准测试
kestrel-benchmark --all
```

---

## 编写第一条规则

```bash
# 创建规则文件
cat > /opt/kestrel/rules/my_first_rule.eql << 'EOF'
process where
    process.executable == "/tmp/suspicious"
    or process.command_line contains "nc -e /bin/bash"
EOF

# 验证规则
kestrel validate --rules /opt/kestrel/rules

# 热加载
kestrel reload
```

---

## 查看告警

```bash
# 实时查看
kestrel alerts --follow

# 导出
kestrel alerts --export --format json --since "1 hour ago"

# 集成 SIEM
curl http://localhost:9090/api/v1/alerts | jq
```

---

## 下一步

- 📖 [完整使用指南](./COMMERCIAL_GUIDE.md)
- ⚡ [性能优化指南](./PERFORMANCE_OPTIMIZATION.md)
- 🗺️ [商用化路线图](./COMMERCIAL_ROADMAP.md)
- 🔧 [故障排查](./troubleshooting.md)
