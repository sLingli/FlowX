# FlowX

基于 Rust 异步运行时（Tokio）构建的跨平台（Windows / Linux / macOS）进程级代理与分流引擎，内建混合协议入站、Fake-IP DNS、XML 配置持久化及单文件 Web 控制台。

## 平台支持

| 平台 | 进程四元组追踪 | 停机信号 |
|---|---|---|
| Windows | `GetExtendedTcpTable` + `QueryFullProcessImageNameW` | `Ctrl+C` |
| Linux | `/proc/net/tcp[6]` → socket inode → `/proc/<pid>/fd` → `/proc/<pid>/exe` | `SIGINT` / `SIGTERM`（兼容 `systemctl stop`） |
| macOS | `libproc` (`proc_listpids` / `PROC_PIDFDSOCKETINFO` / `PROC_PIDTBSDINFO`，兼容双栈 `INI_IPV4 \| INI_IPV6`) | `SIGINT` / `SIGTERM`（兼容 `launchd`） |

- **Unix 权限**：默认端口（`1053` / `40001` / `40080`）均大于 1024，普通用户即可运行，且在 Unix 下写回 `flowx.xml` 时强制使用 `0600` 私有文件权限；普通用户仅能反查同用户下发起的进程连接，Linux 跨用户识别可通过 `sudo` 或授予 `CAP_SYS_PTRACE` + `CAP_DAC_READ_SEARCH` 能力（`sudo setcap cap_sys_ptrace,cap_dac_read_search+ep ./flowx`），macOS 跨用户进程反查需以 `sudo` 运行。
- **规则跨平台互通与安全限制**：应用程序规则中的 `.exe` 后缀双向兼容，`git.exe` 可匹配 Linux / macOS 下的 `git`，`git` 也可匹配 Windows 下的 `git.exe`；`%ComputerName%` / `%HOSTNAME%` 在拆词之后解析并过滤 `;` / 通配符 / CIDR 等元字符，防止主机名注入。
- **代理认证与节点安全**：`HTTP` 与 `SOCKS5` 节点强制要求用户名与密码成对配置（清空密码会同步清除用户名；`HTTP` 用户名禁止包含冒号 `:`），`SOCKS4` 仅支持可选 `UserID`（无密码）；节点地址禁止指向 Fake-IP（`198.18.0.0/15`）或本机/回环中的 FlowX 自身服务端口。

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

# 指定自定义配置文件启动守护引擎
cargo run -- --config my-profile.xml

# 运行全部单元测试
cargo test
```

启动后在浏览器打开 `http://127.0.0.1:40080` 即可查看实时吞吐图表、活动连接、新增/编辑/测速代理节点、调整分流规则与默认兜底策略，或使用内置「路由规则命中模拟器」干跑测试规则。

### CLI 控制子命令（支持在线热调用与离线 XML 直改）

`flowx` 内置双栖 CLI 子命令，当守护进程运行时自动通过本地 API 实时同步；当未显式指定 `--api` / `$FLOWX_API` 且默认回环端口返回连接拒绝（`ConnectionRefused`）时安全回退离线读写 `flowx.xml`（只读命令绝不新建缺失配置，离线变更在参数校验失败时也不会提前写入文件；所有子命令均支持 `--json` 结构化输出）：

```bash
# 查看运行状态与统计概览
flowx status

# 代理节点增删改查与测速
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

启动时优先加载 `--config` 参数或 `FLOWX_CONFIG` 环境变量指定的路径（默认 `./flowx.xml`）。通过 Web 控制台对代理节点或分流规则进行的增删、启停和排序更改，都会自动原子写回该 XML 文件。

更多架构细节与模块设计请参见 [ARCHITECTURE.md](ARCHITECTURE.md)。
