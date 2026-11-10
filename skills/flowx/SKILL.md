---
name: flowx
description: 配置、诊断与管理 FlowX 进程级透明代理与网络分流引擎。当用户需要查看或修改 FlowX 代理节点、编写进程/域名/CIDR/端口分流规则、调整默认兜底动作、测试流量命中哪条规则（dry-run 模拟）或管理活跃连接时使用此技能。
---

# FlowX 进程级分流与代理控制技能指南

FlowX 是一套基于 Rust 构建的进程级透明网络代理与分流引擎，内建双栖 CLI 控制子命令与本地回环 HTTP API。
无论是守护进程在线运行中（默认监听 `http://127.0.0.1:40080`），还是守护进程尚未启动（离线直接读写 `flowx.xml`），都优先通过 `flowx` CLI 子命令（携带 `--json`）完成查询、修改与干跑验证。

---

## 一、 核心架构与默认端口

| 组件 | 默认监听地址 | 说明 |
|---|---|---|
| 混合代理入站 | `127.0.0.1:40001` | 单端口自动识别 `SOCKS5`、`SOCKS4 / SOCKS4a`、`HTTP CONNECT` 与 `HTTP` |
| 本地 Fake-IP DNS | `127.0.0.1:1053` | 分配 `198.18.0.0/15` 虚拟 IP，默认阻断 `AAAA`/`SVCB`/`HTTPS` 防泄漏 |
| Web 控制台与 API | `http://127.0.0.1:40080` | 仅限本地回环访问的控制面 API 与实时仪表盘 |
| 持久化配置文件 | `./flowx.xml` | 可通过 `--config <路径>` 或环境变量 `FLOWX_CONFIG` 指定 |

---

## 二、 CLI 控制子命令速查（推荐优先使用 `--json`）

`flowx` 子命令会自动探测本地 `127.0.0.1:40080` 是否在线：
- **在线模式（Online）**：直接调用运行中守护进程的 HTTP API，内存状态与 `flowx.xml` 实时同步；
- **离线模式（Offline）**：当守护进程未运行时，`status` / `node` / `rule` / `default` / `sim` 自动回退为直接校验并原子读写 `flowx.xml`。

### 1. 状态与默认兜底策略
```bash
# 查看运行模式（online/offline）、端口、节点数、规则数及默认兜底策略
flowx status --json

# 查询当前默认兜底动作（当没有任何启用规则命中时生效）
flowx default --json

# 修改默认兜底动作为直连 / 阻断 / 指定代理节点
flowx default Direct --json
flowx default Block --json
flowx default Proxy:101 --json
```

### 2. 代理节点管理 (`flowx node`)
支持协议：`SOCKS5`、`HTTP`（HTTP CONNECT）、`SOCKS4`（含 SOCKS4a）。
```bash
# 列出所有代理节点
flowx node list --json

# 新增代理节点（自动分配 ID 并写入 flowx.xml）
flowx node add --name "HK-Socks" --addr "127.0.0.1:10808" --protocol SOCKS5 --json
flowx node add --name "Auth-HTTP" --addr "10.0.0.2:8080" --protocol HTTP --user "alice" --pass "secret" --json

# 原地修改现有节点（支持部分字段更新；未传 --pass 时自动保留原密码）
flowx node update 101 --name "HK-Main" --addr "127.0.0.1:10809" --json

# 探测节点 TCP 握手延迟
flowx node ping 101 --json

# 删除节点（若节点正被规则或默认策略引用，会安全拦截报错）
flowx node remove 101 --json
```

### 3. 分流规则管理 (`flowx rule`)
规则采用 **自顶向下、首次命中生效 (First-Match Wins)** 原则。
```bash
# 列出当前所有规则（含顺序下标、规则 ID、启用状态、匹配条件与动作）
flowx rule list --json

# 新增规则（追加至列表末尾）
flowx rule add \
  --name "GitProxy" \
  --apps "git.exe; *ssh*.exe" \
  --targets "*.github.com; *.githubusercontent.com" \
  --ports "22; 443" \
  --action Proxy:101 \
  --json

# 原地更新指定规则（保留原规则 ID、启用状态与优先级位置；未传字段保持原值）
flowx rule update 2 --targets "*.github.com; *.npmjs.org" --action Proxy:101 --json

# 启用 / 停用规则
flowx rule toggle 2 --enable --json
flowx rule toggle 2 --disable --json

# 调整规则优先级顺序（支持 up / down / top / bottom）
flowx rule move 2 top --json
flowx rule move 2 up --json

# 删除规则
flowx rule remove 2 --json
```

### 4. 路由命中干跑模拟器 (`flowx sim`)
在修改规则后，**必须**使用 `flowx sim` 验证目标流量的实际命中结果与逐条跳过原因：
```bash
# 模拟指定进程访问目标主机与端口的路由决策
flowx sim --app "C:\Program Files\Git\bin\git.exe" --target "api.github.com:443" --json
flowx sim --app "curl.exe" --target "192.168.1.1" --port 80 --json
```
返回的 `trace` 数组会逐条列出每条规则的评估结果：
- `"disabled"`：规则已停用，直接跳过；
- `"app_mismatch"`：进程名与进程路径均未命中 `apps` 通配条件；
- `"port_mismatch"`：目标端口不在 `ports` 范围内；
- `"target_mismatch"`：目标域名或 IP 未命中 `targets`；
- `"matched"`：首次命中该规则并立即采纳其动作。

### 5. 活跃连接监控与切断 (`flowx conn`，需守护进程在线)
```bash
# 列出当前活跃连接快照
flowx conn list --json

# 强制物理切断指定连接 ID
flowx conn kill 42 --json
```

---

## 三、 路由规则语法规范与安全准则

1. **`apps`（应用程序过滤）**：
   - 使用分号 `;` 分隔多个匹配项，大小写不敏感，路径分隔符 `/` 与 `\` 自动归一化；
   - 支持 `*` 与 `?` 通配符（如 `node.exe; *chrome*.exe; "C:\Program Files\App\*.exe"`）；
   - 留空表示不限制应用（匹配所有进程）。
2. **`targets`（目标地址过滤）**：
   - 使用分号 `;` 分隔多个域名、IPv4/IPv6 地址或 CIDR 子网（如 `127.0.0.1; ::1; 192.168.0.0/16; *.google.com`）；
   - 前缀通配 `*.example.com` 会**同时匹配**根域 `example.com` 与任意子域 `a.b.example.com`；
   - 支持大小写不敏感展开 `%ComputerName%` 环境变量为当前机器名；
   - 留空表示不限制目标地址。
3. **`ports`（目标端口过滤）**：
   - 使用分号 `;` 或逗号 `,` 分隔单端口或破折号范围（如 `80; 443; 8000-8080`）；
   - 留空表示不限制端口。
4. **本地回环防死锁原则**：
   - 保持 `LocalBypass`（目标 `127.0.0.1; localhost; %ComputerName%; ::1; 192.168.0.0/16` -> `Direct`）位于规则列表第 1 位（`#1`），避免本地回环或局域网流量误入远端代理隧道。
   - 新增规则默认追加在末尾；若存在宽泛规则排在前面，请使用 `flowx rule move <ID> up/top` 调整顺序，并用 `flowx sim` 验证。

---

## 四、 Agent 标准操作工作流

当用户要求“让某个软件/域名走代理、直连或阻断”时，按以下 4 步执行：
1. **盘点现状**：执行 `flowx status --json`、`flowx node list --json` 与 `flowx rule list --json`，确认可用节点 ID 与现有规则优先级顺序。
2. **准备节点**：若用户提供了新代理服务器地址，先用 `flowx node add` 添加节点，并用 `flowx node ping <ID>` 验证连通性。
3. **编排规则**：使用 `flowx rule add` 或 `flowx rule update` 配置规则，必要时通过 `flowx rule move` 确保具体规则位于宽泛规则之前（且在 `LocalBypass` 之后）。
4. **干跑验证**：执行 `flowx sim --app <进程> --target <目标:端口> --json`，确认 `matched_rule_name` 与 `action` 符合预期后再向用户汇报。
