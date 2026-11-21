<div align="center">
  <img src="icon.svg" alt="FlowX" width="120" height="120">
  <h1>FlowX</h1>
  <p><strong>基于 Rust 异步运行时（Tokio）构建的跨平台进程级透明代理与分流引擎</strong></p>
  <p>Windows / Linux / macOS · 混合协议入站 · WinDivert 系统级透明接管 · Fake-IP / 被动观测 DNS · XML 配置持久化 · 单文件 Web 控制台</p>
</div>

## 平台支持

| 平台 | 进程四元组追踪 | 透明代理 | 停机信号 |
|---|---|---|---|
| Windows | `GetExtendedTcpTable` + WinDivert `SOCKET` 层 + `QueryFullProcessImageNameW` | 支持（WinDivert 2.2 + `smoltcp` 用户态 TCP/IP 栈） | `Ctrl+C` |
| Linux | `/proc/net/tcp[6]` → socket inode → `/proc/<pid>/fd` → `/proc/<pid>/exe` | 本地混合入站模式 | `SIGINT` / `SIGTERM`（兼容 `systemctl stop`） |
| macOS | `libproc` (`proc_listpids` / `PROC_PIDFDSOCKETINFO` / `PROC_PIDTBSDINFO`，兼容双栈 `INI_IPV4 \| INI_IPV6`) | 本地混合入站模式 | `SIGINT` / `SIGTERM`（兼容 `launchd`） |

- **Unix 权限**：默认端口（`1053` / `40001` / `40080`）均大于 1024，普通用户即可运行，且在 Unix 下写回 `flowx.xml` 时强制使用 `0600` 私有文件权限；普通用户仅能反查同用户下发起的进程连接，Linux 跨用户识别可通过 `sudo` 或授予 `CAP_SYS_PTRACE` + `CAP_DAC_READ_SEARCH` 能力（`sudo setcap cap_sys_ptrace,cap_dac_read_search+ep ./flowx`），macOS 跨用户进程反查需以 `sudo` 运行。
- **规则跨平台互通与安全限制**：应用程序规则中的 `.exe` 后缀双向兼容，`git.exe` 可匹配 Linux / macOS 下的 `git`，`git` 也可匹配 Windows 下的 `git.exe`；`%ComputerName%` / `%HOSTNAME%` 在拆词之后解析并过滤 `;` / 通配符 / CIDR 等元字符，防止主机名注入。
- **代理认证与节点安全**：`HTTP` 与 `SOCKS5` 节点强制要求用户名与密码成对配置（清空密码会同步清除用户名；`HTTP` 用户名禁止包含冒号 `:`；历史 XML 若遗留孤立 `<Username>` 无 `<Password>`，启动时会自动告警并降级清空用户名以免阻断启动），`SOCKS4` 仅支持可选 `UserID`（禁止携带密码）。节点名称、用户名与密码均禁止控制字符与超长（>255 字节）输入；节点地址禁止指向 Fake-IP（`198.18.0.0/15` / `[::ffff:198.18.0.x]`）或本机/回环中的 FlowX 自身服务端口，并支持通过上游 DNS `A + AAAA` 对称解析纯 IPv6 域名节点进行连通性测速（Ping）与实际出站拨号。

## 默认监听端口

| 服务 | 默认地址 | 说明 |
|---|---|---|
| 混合代理入站 | `127.0.0.1:40001` | 自动识别 `SOCKS5`、`SOCKS4 / SOCKS4a`、`HTTP CONNECT` 与 `HTTP` 代理请求 |
| 本地 DNS 服务 | `127.0.0.1:1053` | 分配 `198.18.0.0/15` Fake-IP（阻断 AAAA/SVCB/HTTPS 防泄漏，上游 `223.5.5.5:53`） |
| 控制台与 API | `http://127.0.0.1:40080` | 仅限本地回环同源访问的 Web 管理面板与 JSON 接口 |

## 快速开始

```bash
# 运行后台守护引擎（首次运行若无配置文件会自动创建 flowx.xml）
cargo run

# 指定自定义配置文件启动守护引擎，或临时覆写透明代理启动开关（不改写磁盘 persisted enabled）
cargo run -- --config my-profile.xml
cargo run -- --transparent
cargo run -- --no-transparent

# 运行全部单元测试
cargo test
```

启动后在浏览器打开 `http://127.0.0.1:40080` 即可查看实时吞吐图表、活动连接、开关系统级透明代理、新增/编辑/测速代理节点、调整分流规则与默认兜底策略，或使用内置「路由规则命中模拟器」干跑测试规则。

### Windows 系统级透明代理（WinDivert）

Windows 下支持通过 WinDivert 2.2 实现无需逐一配置应用代理的系统级透明接管：

1. **驱动准备**：从 WinDivert 官方发行包获取同版本 `WinDivert.dll` 与 `WinDivert64.sys`，将两者放置于 `flowx.exe` 同级目录（或通过 Web 控制台 / `flowx transparent config --dll-path <绝对路径>` / `<TransparentProxy><DllPath>` 指定同目录成对文件）。
2. **权限要求**：开启透明接管需要管理员权限。可直接以管理员终端启动 `flowx --transparent`，或在普通用户启动后于 Web 控制台点击「以管理员重启并开启」通过 UAC 自动平滑交接端口（`--replace-pid`）。
3. **DNS 与域名路由边界**：
   - **选择性 Fake-IP 与纯被动观测 (`InspectDns`)**：仅对命中域名/代理规则的独立进程分配 Fake-IP（保留原始分域 DNS 及 IPv6 `fe80::` 接口 `scope_id`，支持多 DNS 并存且权威 `NXDOMAIN` 不泄露至公网 DNS）；对共享系统 DNS 解析器（如 `svchost.exe` `Dnscache`）采用原包直通 + 独立入站 `SNIFF | RECV_ONLY` 旁路观测学习 `real_ip -> domain`，绝不吞包或影响 VPN/多网卡/EDNS0 响应。
   - **TLS SNI / HTTP Host 首包嗅探**：命中代理规则时，除明确服务端先发协议端口（如 `21/22/23/25/110/143/587/3306/5900`）外，在标准与非标准端口（如 `443`、`8444`、`9443`、`2083`、`3000`）均优先执行支持多 Record `ClientHello` 的权威 SNI/Host 嗅探，并将权威域名提交给远端代理。
   - **内网/VPN 私有后缀边界说明**：`.lan`、`.localdomain`、`.home`、`.corp`、`.internal`、`.intranet`、`.ts.net` 等私有后缀在 **DNS 阶段** 不会被 `DevProxy` 等无域名通配规则或全局默认代理隐式劫持（用户显式编写匹配这些后缀的规则仍可生效）；但请注意，若这些域名解析到的真实 IP（如企业内网 `10.0.0.0/8`、`172.16.0.0/12` 或 Tailscale CGNAT `100.64.0.0/10`）不在默认 `LocalBypass` 的 `192.168.0.0/16` 范围内，**TCP 阶段** 命中 `DevProxy`（如 `chrome.exe -> Proxy`）的连接仍会通过 TLS SNI 送往代理节点。如需对这些内网/VPN 网段或后缀直连，请将其补充到 `LocalBypass`（例如追加 `10.0.0.0/8; 172.16.0.0/12; 100.64.0.0/10; *.ts.net; *.corp`）。

### CLI 控制子命令（支持在线热调用与离线 XML 直改）

`flowx` 内置双栖 CLI 子命令，当守护进程运行时自动通过本地 API 实时同步；当未显式指定 `--api` / `$FLOWX_API` 且默认回环端口返回连接拒绝（`ConnectionRefused`）时安全回退离线读写 `flowx.xml`（只读命令绝不新建缺失配置，离线变更在参数校验失败时也不会提前写入文件）。所有子命令均支持 `--json` 结构化输出、`--` 选项终止符与环境变量语言自动协商（按 `FLOWX_LANG` → `LC_ALL` → `LC_MESSAGES` → `LANG` 优先级随 `Accept-Language` 同步至服务端）；HTTP JSON 写入接口校验 `Content-Type: application/json`（缺失/不匹配返回 `415 Unsupported Media Type`），删除正被规则或默认策略引用的节点时返回 `409 Conflict`（`ERR_NODE_IN_USE`）。其中 `flowx node ping <ID>` 探测不可达（`ok == false`）与 `flowx conn kill <ID>` 失败（`killed == false`）时均会在完整输出 stdout 结果后以非零退出码 (`1`) 退出：

```bash
# 查看运行状态与统计概览
flowx status

# 查看活跃连接或按 ID 断开指定连接（失败返回退出码 1）
flowx conn list
flowx conn kill 12

# 代理节点增删改查与测速（不可达返回退出码 1）
flowx node list
flowx node add --name "HK-Socks" --addr "127.0.0.1:10808" --protocol SOCKS5
flowx node update 101 --name "HK-Main" --addr "127.0.0.1:10809"
flowx node ping 101

# 分流规则增删改查、启停与优先级排序
flowx rule list
flowx rule add --name "GitProxy" --apps "git.exe" --targets "*.github.com" --ports "22; 443" --action Proxy:101
flowx rule update 2 --targets "*.github.com; *.githubusercontent.com"
flowx rule toggle 2 --enable
flowx rule move 2 top

# 查询或修改默认兜底策略
flowx default
flowx default Proxy:101

# 干跑模拟流量命中哪条规则并输出逐条匹配轨迹
flowx sim --app "git.exe" --target "api.github.com:443"

# Windows 透明代理状态、诊断与配置管理（均支持 --api / $FLOWX_API 在线查询与 --offline 离线修改）
flowx transparent status
flowx transparent doctor --json
flowx transparent enable
flowx transparent disable
flowx transparent config --hijack-dns --block-quic --dll-path "C:\tools\WinDivert.dll"
flowx transparent config --clear-dll-path
```

### AI Agent 技能支持

仓库内置了供 AI Agent 调用的技能定义文件 [`skills/flowx/SKILL.md`](skills/flowx/SKILL.md)，涵盖 CLI 子命令、匹配语法规范与标准操作工作流。

### 命令行代理测试

```bash
curl -x socks5h://127.0.0.1:40001 https://example.com
curl -x http://127.0.0.1:40001 https://example.com
```

在控制台中可以看到发起进程（Windows 下为 `curl.exe`，Linux 下为 `curl`）、PID、目标域名、命中的规则及实时速率。

## 配置文件 (`flowx.xml`)

启动时优先加载 `--config` 参数或 `FLOWX_CONFIG` 环境变量指定的路径（`FLOWX_CONFIG` 为空白字符串时回退默认 `./flowx.xml`）。通过 Web 控制台对代理节点或分流规则进行的增删、启停和排序更改，都会自动原子写回该 XML 文件（含旧版孤立 `<Username>` 降级配置在下次变更回写后自动清理）。

更多架构细节与模块设计请参见 [ARCHITECTURE.md](ARCHITECTURE.md)。
