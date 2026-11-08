# FlowX

基于 Rust 异步运行时（Tokio）构建的 Windows 进程级代理与分流引擎，内建混合协议入站、Fake-IP DNS、XML 配置持久化及单文件 Web 控制台。

## 默认监听端口

| 服务 | 默认地址 | 说明 |
|---|---|---|
| 混合代理入站 | `127.0.0.1:40001` | 自动识别 `SOCKS5`、`SOCKS4 / SOCKS4a`、`HTTP CONNECT` 与 `HTTP` 代理请求 |
| 本地 DNS 服务 | `127.0.0.1:1053` | 分配 `198.18.0.0/15` Fake-IP（阻断 AAAA/SVCB/HTTPS 防泄漏，上游 `223.5.5.5:53`） |
| 控制台与 API | `http://127.0.0.1:40080` | 仅限本地回环同源访问的 Web 管理面板与 JSON 接口 |

## 快速开始

```bash
# 运行引擎（首次运行若无配置文件会自动创建 flowx.xml）
cargo run

# 指定自定义配置文件
cargo run -- --config my-profile.xml

# 运行全部单元测试
cargo test
```

启动后在浏览器打开 `http://127.0.0.1:40080` 即可查看实时吞吐图表、活动连接、测速代理节点或调整分流规则。

### 命令行代理测试

```bash
curl -x socks5h://127.0.0.1:40001 https://example.com
curl -x http://127.0.0.1:40001 https://example.com
```

在控制台中可以看到发起进程（`curl.exe`）、PID、目标域名、命中的规则及实时速率。

## 配置文件 (`flowx.xml`)

启动时优先加载 `--config` 参数或 `FLOWX_CONFIG` 环境变量指定的路径（默认 `./flowx.xml`）。通过 Web 控制台对代理节点或分流规则进行的增删、启停和排序更改，都会自动原子写回该 XML 文件。

更多架构细节与模块设计请参见 [ARCHITECTURE.md](ARCHITECTURE.md)。
