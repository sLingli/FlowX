# FlowX CLI / HTTP API 语义与凭据规范

## 目录
- [Web UI 功能按钮与 CLI / HTTP API 对照表](#web-ui-功能按钮与-cli--http-api-对照表)
- [运行模式与回退边界](#运行模式与回退边界)
- [代理节点凭据语义（CLI 与 HTTP API）](#代理节点凭据语义cli-与-http-api)
- [返回结构与退出码约定](#返回结构与退出码约定)
- [透明模式诊断字段说明](#透明模式诊断字段说明)

---

## Web UI 功能按钮与 CLI / HTTP API 对照表

所有 Web 控制台（`http://127.0.0.1:40080`）中的后端功能操作均已完整映射至 `flowx` CLI 与 HTTP JSON API（纯浏览器本地外观状态切换如中英文/暗色主题/暂停前端轮询无后端状态，无需 CLI）：

| Web UI 页面 / 按钮控件 | `flowx` CLI 命令 | HTTP JSON API | 离线 `--offline` 支持 |
| --- | --- | --- | --- |
| 仪表盘系统概览 / 入站端口 / 流量统计 / 刷新 | `flowx status --json` | `GET /api/health`, `GET /api/system`, `GET /api/stats` | 部分（XML 静态概览） |
| 透明代理主开关 (`tp-toggle-switch`) | `flowx transparent enable` / `disable` | `POST /api/transparent/toggle` | 是（仅改 XML） |
| 以管理员身份重启 (`Restart as Administrator`) | `flowx transparent elevate` | `POST /api/transparent/elevate` | 否（弹 UAC 重启守护进程） |
| 选择性 DNS 劫持 / 阻断 QUIC 开关 | `flowx transparent config --[no-]hijack-dns --[no-]block-quic` | `PUT` / `POST /api/transparent/config` | 是 |
| 自定义 `WinDivert.dll` 路径 Save / Reset | `flowx transparent config --dll-path <PATH>` / `--clear-dll-path` | `PUT` / `POST /api/transparent/config` | 是 |
| WinDivert 驱动诊断与统计计数器 | `flowx transparent status` / `doctor` | `GET /api/transparent/status` | 是 |
| 连接监控列表 / 动作标签 / 搜索筛选 | `flowx conn list [--filter ALL\|PROXY\|DIRECT\|BLOCK] [--search <TEXT>]` | `GET /api/connections` | 否 |
| 断开单条活跃连接 (`Kill`) | `flowx conn kill <ID>` | `POST /api/connections/kill?id=<ID>` | 否 |
| 代理节点列表 / 新增节点 | `flowx node list` / `add ...` | `GET` / `POST /api/nodes` | 是 |
| 编辑节点 / 清空用户名或密码 | `flowx node update <ID> ... [--clear-user] [--clear-password]` | `PUT` / `PATCH /api/nodes` | 是 |
| 删除节点 | `flowx node remove <ID>` | `DELETE /api/nodes?id=<ID>` | 是 |
| 单节点测速 / 全部测速 (`Ping` / `Ping all`) | `flowx node ping <ID>` / `--all` | `POST /api/nodes/ping` | 是 |
| 规则列表 / 关键词搜索 | `flowx rule list [--search <TEXT>]` | `GET /api/rules` | 是 |
| 新建规则 | `flowx rule add ...` | `POST /api/rules` | 是 |
| 编辑规则 / 清空匹配条件 | `flowx rule update <ID_OR_IDX> ... [--clear-apps] [--clear-targets] [--clear-ports]` | `PUT` / `PATCH /api/rules` | 是 |
| 启用 / 停用规则开关 | `flowx rule toggle <ID_OR_IDX> [--enable \| --disable]` | `POST /api/rules/toggle` | 是 |
| 优先级排序 (`top` / `up` / `down` / `bottom`) | `flowx rule move <ID_OR_IDX> <up\|down\|top\|bottom>` | `POST /api/rules/move` | 是 |
| 删除规则 | `flowx rule remove <ID_OR_IDX>` | `DELETE /api/rules?id=<ID>` | 是 |
| 默认兜底策略查询与切换 | `flowx default [Direct \| Block \| Proxy:<ID>]` | `POST /api/rules/default` | 是 |
| 路由模拟器 (`Test route`) | `flowx sim --target <HOST[:PORT]> [--app <PROC>] [--port <PORT>]` | `POST /api/rules/simulate` | 是 |

---

## 运行模式与回退边界

- **在线模式（Online）**：CLI 默认连接 `127.0.0.1:40080`（可通过 `--api <ADDR>` 或 `$env:FLOWX_API` 覆盖），直接同步内存状态并原子持久化到 `flowx.xml`。
- **显式离线模式（`--offline`）**：不连接守护进程，直接校验并原子读写 `--config` / `$env:FLOWX_CONFIG`（未设置或空白时回落至 `.\flowx.xml`）。
  - `flowx conn` 与 `flowx transparent elevate` 要求守护进程在线，`--offline` 下直接报错退出。
  - 只读命令在配置文件缺失时直接报错，绝不新建空白配置。
  - 变更命令若参数或规则校验失败，不会在磁盘提前生成或破坏配置文件。
- **默认地址离线回退**：仅当未显式指定 `--api` / `$env:FLOWX_API` 且连接默认 `127.0.0.1:40080` 返回 `ConnectionRefused` 时，`status` / `transparent` / `node` / `rule` / `default` / `sim` 会回退离线 XML；若自定义 `--api` 连接失败、请求超时或服务端返回 HTTP 错误，CLI 直接报错，防止配置分脑。
- **全局参数与语言协商**：CLI 支持 `--` 选项终止符分隔位置参数，并按 `FLOWX_LANG` → `LC_ALL` → `LC_MESSAGES` → `LANG`（默认英文）协商本地化语言及请求头 `Accept-Language`。

---

## 代理节点凭据语义（CLI 与 HTTP API）

支持协议：`SOCKS5`、`HTTP`（HTTP CONNECT）、`SOCKS4`（含 SOCKS4a）。

### 1. 成对认证约束
- **`HTTP` / `SOCKS5`**：要求用户名与密码成对配置。
  - `node add` 传入空密码（`--pass ""`）会拒绝并返回 `ERR_EMPTY_PASSWORD`。
  - `HTTP` 用户名禁止包含冒号 `:`。
  - 若历史 XML 遗留孤立 `<Username>` 而无 `<Password>`，加载时会自动告警并清空用户名（`auth_configured: false`）。
- **`SOCKS4`**：仅支持可选 `UserID`（`--user`），严禁携带密码字段；在线 API 传入 `password`（即使为空串 `""`）返回 `ERR_SOCKS4_PASSWORD_UNSUPPORTED`。
- **通用输入校验**：节点名称、用户名与密码均禁止控制字符与超长（> 255 字节）输入；节点地址禁止指向 Fake-IP（`198.18.0.0/15` / `[::ffff:198.18.0.x]`）或本机/回环上的 FlowX 自身服务端口（`40001` / `40080` / `1053`）。

### 2. `PUT` 与 `PATCH` 更新语义差异
- **`PATCH`（含 `flowx node update` CLI）**：`keep_password` 缺省/`null` 时默认**保留原密码**（`keep_password.unwrap_or(true)`；CLI 省略 `--pass` 与 `--clear-password` 时发送 `"keep_password": null`）。
- **`PUT`（全量替换 HTTP API）**：`keep_password` 缺省/`null` 时默认**不保留原密码**（`keep_password.unwrap_or(false)`）。因此沿用已有非空用户名却既未传 `keep_password: true` 又未传新非空密码时，返回 `ERR_USERNAME_WITHOUT_PASSWORD`。
- **变更用户名**：若保留密码且变更了用户名（`username != existing_username`）但未提供新非空密码：
  - 原节点已存密码时返回 `ERR_PASSWORD_REQUIRED_ON_USER_CHANGE`；
  - 原节点无密码时（如 `SOCKS4` 升级为 `HTTP`/`SOCKS5`）返回 `ERR_USERNAME_WITHOUT_PASSWORD`。
- **清除密码（`--clear-password`、`clear_password: true`、`--pass ""` 或 `password: ""`）**：
  - 在 `PUT` 与 `PATCH` 下语义一致：沿用已有用户名时同步清空用户名与密码；
  - 若同时变更用户名（`username != existing_username`），返回 `ERR_USERNAME_WITHOUT_PASSWORD`。
- **冲突参数拦截**：
  - 清除用户名（`username: null` / `""` 或 `clear_username: true`）同时传入 `clear_password: false` 而原节点存在密码时，返回 `ERR_CONFLICTING_PASSWORD_OPTIONS`。
  - CLI 同时传 `--pass` 与 `--clear-password` 在本地解析阶段直接拒绝；API 层互斥密码参数返回 `ERR_CONFLICTING_PASSWORD_OPTIONS`，同传 `clear_username: true` 与非空 `username` 返回 `ERR_CONFLICTING_USERNAME_OPTIONS`。
  - 删除被规则或默认策略引用的节点时返回 `409 Conflict`（`ERR_NODE_IN_USE`）；HTTP JSON 写入缺少或不匹配 `Content-Type: application/json` 返回 `415 Unsupported Media Type`。

---

## 返回结构与退出码约定

- **`node list --json`**：
  - `password_configured`：仅 `HTTP`/`SOCKS5` 已存密码时为 `true`。
  - `auth_configured`：`SOCKS4` 下表示是否配置了 `UserID`，`HTTP`/`SOCKS5` 下表示用户名与密码是否已成对配置。
- **`rule list --json`**：
  - 仅纯文本 `flowx rule list` 会打印 `#1 (id=1)` 前缀；`--json` 数组元素仅含 `id`、`name`、`enabled`、`apps`、`targets`、`ports`、`action`、`action_type`、`node_id`（**无单独的 `index` 字段**，1-based 顺序由 JSON 数组下标决定）。
  - `rule update` / `toggle` / `move` / `remove` 在线与离线均统一支持真实规则 `id` 与列表 1-based 下标。
- **`sim --json` 逐条评估原因（`trace[].reason`）**：
  - `"disabled"`：规则已停用，直接跳过；
  - `"app_mismatch"`：进程名与路径未命中 `apps`；
  - `"port_mismatch"`：目标端口不在 `ports` 范围；
  - `"target_mismatch"`：目标域名/IP 未命中 `targets`；
  - `"matched"`：首次命中并采纳其 `action`。
- **特殊非零退出码**：
  - `flowx node ping <ID> --json` 在探测不可达（`ok == false`）时，以及 `flowx node ping --all --json` 在存在任何不可达节点（`unreachable > 0`）时，均完整输出 stdout JSON 后以退出码 `1` 退出；
  - `flowx conn kill <ID> --json` 在连接已关闭或不存在（`killed == false`）时，完整输出 stdout 结果后以退出码 `1` 退出；
  - `flowx transparent elevate --json` 使用 30 秒 HTTP I/O 超时等待用户响应 UAC；若已提权（`ERR_TRANSPARENT_ALREADY_ELEVATED`）、用户取消（`ERR_TRANSPARENT_UAC_CANCELLED`）或正有 UAC 进行中（`ERR_TRANSPARENT_ELEVATE_IN_PROGRESS`）均返回 `409 Conflict` 与结构化错误 JSON。

---

## 透明模式诊断字段说明

`flowx transparent doctor --json` 与 `flowx transparent status --json` 核心字段：
- `mode`：`ONLINE`（查询运行中守护进程）或 `OFFLINE`（检测当前进程权限与本地配置）。
- `elevated`：目标实例是否具备 Windows 管理员权限。
- `dll_found` / `sys_found`：是否在可信路径定位到成对的 `WinDivert.dll` 与 `WinDivert64.sys`（仅搜索 `flowx.exe` 同级目录及同级 `driver\` 子目录，或通过 `transparent config --dll-path` 指定的本机绝对路径，**不搜索当前工作目录 CWD**）。
- `running` / `ready`：WinDivert 驱动是否正在运行 / 环境是否已全部就绪。
- `tcp_intercepted_total` / `tcp_passthrough_total` / `dns_hijacked_total` / `quic_blocked_total`：透明引擎实时拦截、旁路直通、DNS 劫持与 QUIC 阻断计数。
