---
name: flowx
description: Configure, diagnose, and manage the FlowX Windows process-level transparent proxy and routing engine (WinDivert + mixed inbound). Use when the user asks to route an application, domain, IP/CIDR, or port through a proxy/direct/block rule (like Proxifier), inspect active connections or traffic stats, test rule matching (dry-run sim), switch default actions, or troubleshoot FlowX transparent mode, WinDivert drivers, and proxy nodes.
license: MIT
---

# FlowX Windows 进程级代理与分流控制指南

FlowX 是基于 Rust 的 Windows 进程级透明网络代理与分流引擎，提供 **WinDivert 免虚拟网卡透明接管**（需管理员权限 + `WinDivert.dll`/`WinDivert64.sys`）与 **混合代理入站**（`127.0.0.1:40001`，支持 SOCKS5 / SOCKS4a / HTTP）。
所有查询、修改与验证优先使用 `flowx` CLI 子命令并携带 `--json`（可置于子命令前或后）。

## 一、 可执行文件定位与运行前提

按以下优先级定位可执行文件（示例均采用 Windows PowerShell 语法）：
1. 若 `flowx` 已在 `PATH` 中，直接调用 `flowx`；
2. 否则依次探测工作区构建产物 `.\target\release\flowx.exe` 或 `.\target\debug\flowx.exe`；
3. 仅源码未编译时使用 `cargo run -- <子命令...>`。

默认端口与配置：
- **混合代理入站**：`127.0.0.1:40001`（无需管理员权限即可使用）
- **本地 Fake-IP DNS**：`127.0.0.1:1053`（分配 `198.18.0.0/15`，阻断 AAAA/SVCB/HTTPS 防泄漏）
- **Web 控制台与 HTTP API**：`http://127.0.0.1:40080`
- **配置文件**：`.\flowx.xml`（可通过 `--config <路径>` 或 `$env:FLOWX_CONFIG` 指定；参考模板为 [flowx.example.xml](../../flowx.example.xml)）

> **PowerShell 引号提醒**：`--apps`、`--targets`、`--ports` 中包含分号 `;` 时**必须使用引号包裹**（如 `--targets "*.github.com; *.npmjs.org"`），避免 PowerShell 将 `;` 解析为命令分隔符。

---

## 二、 标准操作工作流（5 步闭环）

当用户要求“让某个程序 / 域名走代理、直连或阻断”或排查不生效问题时，严格按以下 5 步执行：

1. **探测真实进程名（先查后写，绝不盲猜）**
   - Windows 应用常拆分为多个可执行文件（例如同时存在 `Reasonix.exe` 与 `reasonix-desktop.exe`，或衍生 `msedgewebview2.exe` / `helper` 子进程）。
   - 先用 PowerShell 查询运行中进程或安装目录，确认完整进程名：
     ```powershell
     Get-Process | Where-Object { $_.ProcessName -match "关键词" } | Select-Object ProcessName, Path
     ```
2. **盘点现状与透明模式状态**
   - 执行 `flowx status --json`、`flowx node list --json`、`flowx rule list --json`。
   - 核对可用节点 ID、现有规则顺序以及 `system.transparent.running` 是否为 `true`。
   - **严禁环路**：记录承载本地节点端口（如 `10808`）的上游代理进程（如 `xray.exe`、`v2ray.exe`、`mihomo.exe`），绝不可将其配入指向该节点的 `Proxy` 规则。
3. **准备并验证节点**
   - 若用户给出新代理地址，用 `flowx node add` 创建；随后执行 `flowx node ping <ID> --json` 或 `flowx node ping --all --json` 验证可达（存在不可达节点时会先输出 JSON 再以退出码 `1` 退出）。
4. **编排规则与优先级**
   - 新增规则默认追加到末尾；用 `flowx rule add` / `flowx rule update` 写入或清空条件（`--clear-apps` / `--clear-targets` / `--clear-ports`）。
   - 若前方存在更宽泛规则，用 `flowx rule move <ID> <up|down|top|bottom>` 调整优先级，保持 `#1 LocalBypass` 始终在首位防回环。
5. **干跑模拟与实机生效确认**
   - 对目标进程和域名执行 `flowx sim --app <进程路径或名称> --target <域名或IP:端口> --json`，核对 `matched_rule_name`、`action` 与 `trace`。
   - 若 `system.transparent.running` 为 `false`，立即执行 `flowx transparent doctor --json` 定位原因（缺管理员权限或缺少 `flowx.exe` 同级 / `driver\` 下的 `WinDivert.dll` + `WinDivert64.sys`）。需提权重启守护进程时，在用户知情确认后可执行 `flowx transparent elevate --json`（会触发系统 UAC 弹窗），或暂将应用代理指向混合入站 `127.0.0.1:40001`。

---

## 三、 CLI 高频命令速查（覆盖全部控制台按钮与开关）

```powershell
# 1. 状态、健康与透明代理控制 / UAC 提权
flowx status --json
flowx transparent status --json
flowx transparent doctor --json
flowx transparent enable --json
flowx transparent disable --json
flowx transparent config --hijack-dns --block-quic --json
flowx transparent config --dll-path "C:\tools\WinDivert.dll" --json
flowx transparent config --clear-dll-path --json
flowx transparent elevate --json

# 2. 代理节点（SOCKS5 / HTTP / SOCKS4）
flowx node list --json
flowx node add --name "HK-Socks" --addr "127.0.0.1:10808" --protocol SOCKS5 --json
flowx node update 101 --addr "127.0.0.1:10809" --json
flowx node update 101 --clear-user --clear-password --json
flowx node ping 101 --json
flowx node ping --all --json
flowx node remove 101 --json

# 3. 分流规则（First-Match Wins；ID 与 1-based 下标均支持）
flowx rule list --json
flowx rule list --search "github" --json
flowx rule add --name "GitProxy" --apps "git.exe; *ssh*.exe" --targets "*.github.com; *.githubusercontent.com" --ports "22; 443" --action Proxy:101 --json
flowx rule update 2 --targets "*.github.com; *.npmjs.org" --action Proxy:101 --json
flowx rule update 2 --clear-apps --clear-ports --json
flowx rule toggle 2 --enable --json
flowx rule move 2 top --json
flowx rule remove 2 --json

# 4. 默认兜底、干跑模拟与在线连接过滤/断开
flowx default --json
flowx default Direct --json
flowx sim --app "C:\Program Files\Git\bin\git.exe" --target "api.github.com:443" --json
flowx conn list --filter PROXY --search "chrome" --json
flowx conn kill 42 --json
```

**常用全局标志**：`--offline`（强制离线直改 XML）、`--config <路径>`、`--api <127.0.0.1:40080>`、`--json`。
**排错日志**：守护进程支持通过 `$env:FLOWX_LOG = "debug"`（或 `RUST_LOG`）输出路由与抓包诊断日志。
**清空字段技巧**：在 Windows PowerShell 中请使用显式 `--clear-apps`、`--clear-targets`、`--clear-ports`、`--clear-user`、`--clear-password`、`--clear-dll-path`，避免原生命令传空串 `""` 被吞并。

---

## 四、 规则语法要点

- **`apps`**：分号 `;` 分隔，忽略大小写，`/` 与 `\` 自动归一化，支持 `*` 与 `?` 通配（如 `*reasonix*.exe`、`C:\Apps\*\client.exe`）。
  - 省略 `.exe` 的简写（如 `git`、`C:\Tools\curl`）可匹配 `.exe` 进程；`*.exe` / `*.*` 等纯通配后缀仅匹配显式带 `.exe` 的进程。
  - 含路径分隔符时 `*` 不跨越目录层级；不含分隔符时仅匹配进程文件名；留空匹配所有进程。
- **`targets`**：分号 `;` 分隔域名、IPv4/IPv6 或 CIDR；前缀通配 `*.example.com` 同时匹配根域 `example.com` 与所有子域；支持展开 `%ComputerName%`（及别名 `%HOSTNAME%`）。
- **`ports`**：分号 `;` 或逗号 `,` 分隔单端口或范围（如 `80; 443; 8000-8080`）。
- **回环保护**：始终保持 `LocalBypass`（`127.0.0.1; localhost; %ComputerName%; ::1; 192.168.0.0/16` -> `Direct`）位于 `#1`。

---

## 五、 扩展参考

- 需要查看 Web UI 按钮 ↔ CLI / HTTP API 完整对照表、`PUT`/`PATCH` 凭据互斥矩阵、错误码、`rule list --json` 精确字段或 `transparent doctor` 诊断详情时，阅读 [references/api-and-auth-semantics.md](references/api-and-auth-semantics.md)。
