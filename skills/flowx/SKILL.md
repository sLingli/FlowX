---
name: flowx
description: 配置、诊断与管理 FlowX 进程级透明代理与网络分流引擎。当用户需要查看或修改 FlowX 代理节点、编写进程/域名/CIDR/端口分流规则、调整默认兜底动作、测试流量命中哪条规则（dry-run 模拟）或管理活跃连接时使用此技能。
---

# FlowX 进程级分流与代理控制技能指南

FlowX 是一套基于 Rust 构建的 Windows 进程级透明网络代理与分流引擎，内建双栖 CLI 控制子命令与本地回环 HTTP API。
仓库根目录提供了配置示例模板 [flowx.example.xml](../../flowx.example.xml)（首次启动若无配置文件会自动生成，也可直接复制按需调整）。
无论是守护进程在线运行中（默认监听 `http://127.0.0.1:40080`），还是守护进程尚未启动（离线直接读写 `flowx.xml`），都优先通过 `flowx` CLI 子命令（携带 `--json`）完成查询、修改与干跑验证。

---

## 一、 核心架构与默认端口

| 组件 | 默认监听地址 | 说明 |
|---|---|---|
| 混合代理入站 | `127.0.0.1:40001` | 单端口自动识别 `SOCKS5`、`SOCKS4 / SOCKS4a`、`HTTP CONNECT` 与 `HTTP` |
| 本地 Fake-IP DNS | `127.0.0.1:1053` | 分配 `198.18.0.0/15` 虚拟 IP，默认阻断 `AAAA`/`SVCB`/`HTTPS` 防泄漏 |
| Web 控制台与 API | `http://127.0.0.1:40080` | 仅限本地回环访问的控制面 API 与实时仪表盘 |
| 持久化配置文件 | `./flowx.xml` | 可通过 `--config <路径>` 或环境变量 `FLOWX_CONFIG` 指定；参考模板为 `flowx.example.xml` |

---

## 二、 CLI 控制子命令速查（推荐优先使用 `--json`）

`flowx` 子命令执行严格参数校验与确定性路由（未知参数如 `--targe` 或多余位置参数会直接报错退出）：
- **在线模式（Online）**：连接运行中守护进程的 HTTP API（支持 `PATCH` 原子部分更新），内存状态与 `flowx.xml` 实时同步；
- **显式离线模式（`--offline`）**：直接安全校验并原子读写 `--config` / `$FLOWX_CONFIG` 指定的 XML 文件（未设置或为空白时回落至 `./flowx.xml`），不尝试连接守护进程（`conn` 命令除外，其要求在线守护进程）；只读命令缺失配置文件时直接报错而不新建文件，变更命令在参数/规则校验失败时同样不会在磁盘提前生成 `flowx.xml`；CLI 支持 `--` 选项终止符分隔位置参数，并按 `FLOWX_LANG` → `LC_ALL` → `LC_MESSAGES` → `LANG`（默认英文）自适应本地化语言与 `Accept-Language`；
- **默认地址离线回退**：仅当未显式指定 `--api` / `$FLOWX_API` 且连接默认本地 `127.0.0.1:40080` 收到 `ConnectionRefused` 时，`status` / `transparent` / `node` / `rule` / `default` / `sim` 才会安全回退离线 XML；若超时、HTTP 返回错误或自定义 `--api` 失败，CLI 会直接报错，避免配置分脑。

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
- **凭证成对与字段返回约束**：
  - `HTTP` 与 `SOCKS5` 节点要求用户名（`--user`）与密码（`--pass`）成对存在：`node add` 传入 `--pass ""` 会拒绝并返回 `ERR_EMPTY_PASSWORD`；`HTTP` 用户名禁止包含 `:`。
  - `PUT` / `PATCH` 对 `keep_password` 缺省/`null` 的语义不同：`PATCH`（含 `flowx node update` CLI；省略 `--pass` 与 `--clear-password` 时 CLI 发送 `"keep_password": null`）默认保留原密码（`keep_password.unwrap_or(true)`），而全量替换的 `PUT` 默认不保留（`keep_password.unwrap_or(false)`）——因此 `PUT` 沿用已有非空用户名却既未传 `keep_password: true` 又未提供新非空密码时返回 `ERR_USERNAME_WITHOUT_PASSWORD`。若启用密码保留并变更了用户名（`username != existing_username`）却未提供新非空密码，原节点已存密码时返回 `ERR_PASSWORD_REQUIRED_ON_USER_CHANGE`，原无密码时（如 `SOCKS4` 升为 `HTTP`/`SOCKS5`）返回 `ERR_USERNAME_WITHOUT_PASSWORD`。清除密码（`--clear-password`、`clear_password: true`、`--pass ""` 或 `password: ""`）在 `PUT` 与 `PATCH` 下语义一致：沿用已有用户名时同步清空用户名与密码，但禁止同时变更用户名（`username != existing_username`），否则返回 `ERR_USERNAME_WITHOUT_PASSWORD`。此外若清除用户名（`username: null` / `""` 或 `clear_username: true`）同时传入 `clear_password: false` 而节点仍存在原密码，同样拒绝并返回 `ERR_CONFLICTING_PASSWORD_OPTIONS`（避免静默清库）。同时传 `--pass` 与 `--clear-password` 在 CLI 本地参数解析阶段即报错拒绝；API 层互斥密码参数返回 `ERR_CONFLICTING_PASSWORD_OPTIONS`，API 同传 `clear_username: true` 与非空 `username` 返回 `ERR_CONFLICTING_USERNAME_OPTIONS`。
  - `SOCKS4` 仅支持可选 `--user`（`UserID`）且严禁携带密码字段（在线 API 传入 `password: ""` 也会返回 `ERR_SOCKS4_PASSWORD_UNSUPPORTED`）。
  - 返回 JSON 中的 `password_configured`（仅 `HTTP`/`SOCKS5` 已存密码时为 `true`）与 `auth_configured`（`SOCKS4` 下表示是否配置了 `UserID`，`HTTP`/`SOCKS5` 下表示用户名与密码是否已成对配置）用于判断节点真实认证状态（历史 XML 若存在孤立 `<Username>` 无 `<Password>`，启动加载时会告警降级并清空用户名，返回 `auth_configured: false`）。
- **节点地址与测速语义**：禁止指向 Fake-IP（`198.18.0.0/15` / `[::ffff:198.18.0.x]`）或本机/回环中的 FlowX 自身服务端口（`--addr` 与 `ping` 解析上游 `A + AAAA` 后均会二次拦截回环与重绑定，支持纯 IPv6 域名节点）；`flowx node ping <ID>` 在节点不可达（`ok == false`）时会完整输出 JSON / 文本结果后以**非零退出码 (`1`)** 退出，脚本应检查退出码并照常解析 stdout JSON。
```bash
# 列出所有代理节点
flowx node list --json

# 新增代理节点（自动分配 ID 并写入 flowx.xml）
flowx node add --name "HK-Socks" --addr "127.0.0.1:10808" --protocol SOCKS5 --json
flowx node add --name "Auth-HTTP" --addr "10.0.0.2:8080" --protocol HTTP --user "alice" --pass "secret" --json

# 原地修改现有节点（使用 PATCH 原子部分更新；未改用户名且未传 --pass 时保留原密码）
flowx node update 101 --name "HK-Main" --addr "127.0.0.1:10809" --json

# 显式清除节点已保存认证（HTTP/SOCKS5 将同步清空用户名与密码），或仅离线修改本地 XML
flowx node update 101 --clear-password --json
flowx --offline node update 101 --user "bob" --pass "new-secret" --json

# 探测节点 TCP 握手延迟
flowx node ping 101 --json

# 删除节点（若节点正被规则或默认策略引用，会安全拦截报错）
flowx node remove 101 --json
```

### 3. 分流规则管理 (`flowx rule`)
规则采用 **自顶向下、首次命中生效 (First-Match Wins)** 原则。`update` / `toggle` / `move` / `remove` 在线与离线均统一支持真实规则 ID 与列表 1-based 下标（如 `2`）。
```bash
# 列出当前所有规则（含 1-based 顺序下标、规则 ID、启用状态、匹配条件与动作）
flowx rule list --json

# 新增规则（追加至列表末尾）
flowx rule add \
  --name "GitProxy" \
  --apps "git.exe; *ssh*.exe" \
  --targets "*.github.com; *.githubusercontent.com" \
  --ports "22; 443" \
  --action Proxy:101 \
  --json

# 原地更新指定规则（使用 PATCH 保留原规则 ID、未传字段与优先级位置；可同时传 --enable/--disable）
flowx rule update 2 --targets "*.github.com; *.npmjs.org" --action Proxy:101 --json

# 启用 / 停用规则（在线与离线统一按规则 ID 或 1-based 下标定位）
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

# 强制物理切断指定连接 ID；若连接已不存在/已关闭 (killed=false)，会完整输出 JSON 后以非零状态码 1 退出
flowx conn kill 42 --json
```

### 6. Windows 系统级透明代理管理 (`flowx transparent`)
支持在线（同步守护进程与 XML）与离线（读写 `<TransparentProxy>`）管理，`doctor` 同样遵循 `--api` / `$FLOWX_API` 优先在线查询：
```bash
# 查询透明代理运行状态、驱动探测与统计计数
flowx transparent status --json

# 诊断 Windows 宿主环境、管理员权限与 WinDivert.dll / WinDivert64.sys 就绪状态
flowx transparent doctor --json

# 热启 / 热停透明代理或修改 DNS 劫持 / QUIC 阻断 / 自定义 DLL 路径
flowx transparent enable --json
flowx transparent disable --json
flowx transparent config --hijack-dns --block-quic --dll-path "C:\tools\WinDivert.dll" --json
flowx transparent config --clear-dll-path --json
```

---

## 三、 路由规则语法规范与安全准则

1. **`apps`（应用程序过滤）**：
   - 使用分号 `;` 分隔多个匹配项，大小写不敏感，路径分隔符 `\` 与 `/` 自动归一化；
   - 支持 `*` 与 `?` 通配符（如 `node.exe; *chrome*.exe; "C:\Program Files\App\*.exe"`）；
   - 省略 `.exe` 的简写规则（如 `git`、`C:\Tools\curl`）可匹配对应 Windows `.exe` 进程；`*.exe` / `*.*` 等纯通配后缀仅匹配实际带 `.exe` 扩展名的进程；含路径分隔符的规则强制按目录层级精确匹配（`*` 不跨越路径分隔符），不含路径分隔符的规则仅按进程文件名匹配；
   - 未识别进程在路由引擎中视为空进程，仅命中不限制 `apps` 的规则；
   - 留空表示不限制应用（匹配所有进程）。
2. **`targets`（目标地址过滤）**：
   - 使用分号 `;` 分隔多个域名、IPv4/IPv6 地址或 CIDR 子网（如 `127.0.0.1; ::1; 192.168.0.0/16; *.google.com`）；
   - 前缀通配 `*.example.com` 会**同时匹配**根域 `example.com` 与任意子域 `a.b.example.com`；
   - 支持大小写不敏感展开 `%ComputerName%` 为当前 Windows 计算机名（读取 `COMPUTERNAME` 环境变量）；
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
