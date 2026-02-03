# Kestrel 规则库

本目录包含 Kestrel 检测引擎的高级安全规则。这些规则覆盖主要的 MITRE ATT&CK 战术领域，可用于检测真实世界中的高级威胁。

## 规则概览

| 规则目录 | 检测目标 | MITRE 战术 | 严重程度 | 类型 |
|---------|---------|-----------|---------|------|
| `ransomware_detection/` | 勒索软件行为 | T1486 | 🔴 Critical | 行为检测 |
| `privilege_escalation/` | 权限提升 | T1548, T1166 | 🟠 High | 多指标关联 |
| `reverse_shell_detection/` | 反向 Shell | T1059, T1071 | 🔴 Critical | 序列检测 |
| `credential_access/` | 凭证窃取 | T1003, T1056 | 🔴 Critical | 文件监控 |
| `lateral_movement/` | 横向移动 | T1021, T1550 | 🟠 High | 网络+进程关联 |
| `data_exfiltration/` | 数据外泄 | T1041, T1048 | 🟠 High | 序列检测 |

## 快速开始

### 使用规则

```bash
# 启动 Kestrel 并加载所有规则
cargo run --bin kestrel -- run --rules ./rules

# 验证规则格式
cargo run --bin kestrel -- validate --rules ./rules

# 列出所有加载的规则
cargo run --bin kestrel -- list --rules ./rules
```

### 规则结构

每个规则目录包含：
- `manifest.json` - 规则元数据和配置
- `predicate.lua` - Lua 检测逻辑

```
rules/
├── ransomware_detection/
│   ├── manifest.json
│   └── predicate.lua
├── privilege_escalation/
│   ├── manifest.json
│   └── predicate.lua
└── ...
```

## 规则详情

### 🔴 勒索软件检测 (`ransomware_detection/`)

**规则ID**: `ransomware-001`

**检测逻辑**:
- 监控文件重命名到可疑扩展名 (.encrypted, .locked, .crypto 等)
- 检测高价值文件的高频修改模式
- 基于时间窗口的行为分析

**触发条件**:
- 10次以上的可疑重命名操作（5秒窗口内）
- 20+ 高价值文件被访问且 15+ 操作

**示例匹配**:
```bash
# 勒索软件典型行为
mv document.docx document.docx.encrypted
mv photo.jpg photo.jpg.locked
# ... 大量类似操作
```

---

### 🔴 反向 Shell 检测 (`reverse_shell_detection/`)

**规则ID**: `revshell-001`

**检测逻辑**:
- 网络连接 + Shell 执行的序列检测
- 命令行模式匹配 (bash -i, nc -e, python socket 等)
- 父进程关系分析

**检测的 Shell 类型**:
- Bash: `/dev/tcp/host/port` 技巧
- Netcat: `nc -e /bin/bash host port`
- Python: `socket.connect()` + `pty.spawn()`
- Perl/Ruby/PHP: 类似模式
- mkfifo 管道技巧

**触发条件**:
- 直接匹配已知反向 Shell 模式
- 网络程序在 10 秒内生成 Shell
- `/dev/tcp/` 写入操作

---

### 🟠 权限提升检测 (`privilege_escalation/`)

**规则ID**: `privesc-001`

**检测逻辑**:
- Sudo/Su 滥用监控
- SUID 二进制文件异常执行
- 敏感系统文件修改

**监控的敏感文件**:
- `/etc/sudoers`, `/etc/sudoers.d/`
- `/etc/passwd`, `/etc/shadow`
- `/etc/crontab`, `/etc/cron.d/`
- `/root/.ssh/`
- PAM 配置

**SUID 异常检测**:
- 正常: sudo, su, pkexec, passwd
- 可疑: vim, nano, less, bash (作为 SUID)

---

### 🔴 凭证访问检测 (`credential_access/`)

**规则ID**: `credaccess-001`

**检测逻辑**:
- 凭证文件直接访问
- 内存转储尝试 (proc, /dev/mem)
- 浏览器凭证数据库访问
- 键盘记录器指标

**监控目标**:
- SSH 密钥 (`~/.ssh/id_rsa`, `authorized_keys`)
- 浏览器数据 (Chrome Login Data, Firefox logins.json)
- 云凭证 (`~/.aws/credentials`, `~/.azure/`)
- 系统密码存储 (`/etc/shadow`, Kerberos tickets)
- 内存转储工具 (mimipenguin, 自定义工具)

---

### 🟠 横向移动检测 (`lateral_movement/`)

**规则ID**: `latmove-001`

**检测逻辑**:
- SSH 连接模式分析
- 远程执行工具使用
- 异常认证模式
- 网络端口连接分析

**监控的协议/端口**:
- SSH (22) - 密钥认证、端口转发
- SMB (445), NetBIOS (139)
- RDP (3389), VNC (5900+)
- WinRM (5985/5986)
- Telnet (23) - 高可疑

**工具检测**:
- Ansible, SaltStack, Puppet (正常但监控)
- pssh, pdsh, mussh (并行 SSH)
- 异常: rsh, telnet

---

### 🟠 数据外泄检测 (`data_exfiltration/`)

**规则ID**: `exfil-001`

**检测逻辑**:
- 压缩 + 上传的序列检测
- 数据库转储监控
- 云存储上传检测

**检测序列**:
1. 敏感文件访问 → 压缩归档 → 网络上传
2. 数据库转储 → 网络活动
3. 大文件读取 → 云存储连接

**监控的云服务**:
- AWS S3, Azure Blob, Google Cloud Storage
- Dropbox, Google Drive, OneDrive
- Pastebin, 其他文本分享服务

---

## 规则性能

| 规则 | 评估延迟 | 内存使用 | 适用场景 |
|-----|---------|---------|---------|
| 勒索软件检测 | < 50μs | ~10KB/进程 | 实时文件监控 |
| 反向 Shell | < 30μs | ~5KB/进程 | 网络+进程监控 |
| 权限提升 | < 40μs | ~8KB/进程 | 系统调用监控 |
| 凭证访问 | < 35μs | ~6KB/进程 | 文件系统监控 |
| 横向移动 | < 45μs | ~12KB/进程 | 网络监控 |
| 数据外泄 | < 60μs | ~15KB/进程 | 文件+网络监控 |

## 自定义规则

### 创建新规则模板

```lua
-- predicate.lua 模板

function pred_init()
  -- 初始化状态
  return 0
end

function pred_eval(event)
  -- 获取事件字段
  local event_type = kestrel.event_get_i64(event, 1)
  local process_pid = kestrel.event_get_i64(event, 2)
  
  -- 检测逻辑
  if event_type == 1001 then  -- 进程执行
    local executable = kestrel.event_get_str(event, 4)
    -- ... 检测代码 ...
    return true  -- 匹配
  end
  
  return false  -- 不匹配
end

function pred_capture(event)
  -- 返回告警字段
  return {
    pid = kestrel.event_get_i64(event, 2),
    process_name = kestrel.event_get_str(event, 3),
    -- ... 其他字段 ...
  }
end
```

### 常用事件类型

| 类型ID | 名称 | 描述 |
|-------|------|------|
| 1001 | PROCESS_EXEC | 进程执行 |
| 1002 | PROCESS_EXIT | 进程退出 |
| 3001 | FILE_CREATE | 文件创建 |
| 3002 | FILE_RENAME | 文件重命名 |
| 3003 | FILE_WRITE | 文件写入 |
| 3004 | FILE_READ | 文件读取 |
| 4001 | NETWORK_CONNECT | 网络连接 |
| 4002 | NETWORK_SEND | 网络发送 |
| 4003 | NETWORK_RECEIVE | 网络接收 |

### 字段 ID 参考

| 字段ID | 名称 | 类型 | 描述 |
|-------|------|------|------|
| 1 | event_type_id | i64 | 事件类型 |
| 2 | process.pid | i64 | 进程ID |
| 3 | process.name | string | 进程名 |
| 4 | process.executable | string | 可执行文件路径 |
| 5 | process.args | string | 命令行参数 |
| 6 | process.ppid | i64 | 父进程ID |
| 10 | user.uid | i64 | 用户ID |
| 11 | user.euid | i64 | 有效用户ID |
| 20 | file.path | string | 文件路径 |
| 21 | file.new_path | string | 新文件路径 (重命名) |
| 50 | network.dest_ip | string | 目标IP |
| 51 | network.dest_port | i64 | 目标端口 |
| 100 | ts_mono_ns | i64 | 单调时间戳 |

## 测试规则

```bash
# 运行单元测试
cargo test -p kestrel-runtime-lua

# 使用测试事件验证规则
cargo test --test rule_validation
```

## 参考

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Kestrel Lua API 文档](../examples/lua_rule_package.md)
- [Wasm 规则开发指南](../examples/wasm_rule_package.md)
