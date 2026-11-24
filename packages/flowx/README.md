# @slingli/flowx

[FlowX](https://github.com/sLingli/FlowX) 的 Windows x64 CLI 与内嵌 Web 控制台分发包。

## 安装与使用

```powershell
# 全局安装
npm install -g @slingli/flowx

# 启动引擎与 Web 控制台 (http://127.0.0.1:40080，混合入站 127.0.0.1:40001)
flowx

# 常用 CLI 调试命令
flowx status --json
flowx node list --json
flowx rule list --json
flowx sim --app git.exe --target api.github.com:443 --json
```

## 可选：按需安装 WinDivert 驱动（用于系统级透明代理）

仅使用 `127.0.0.1:40001` 混合入站不需要额外驱动；如需系统级透明代理接管，可运行一条命令自动从官方源下载 WinDivert 2.2.2 并校验 SHA-256 后放入程序同级 `driver\` 目录：

```powershell
flowx setup-driver
flowx transparent doctor --json
```

配套 AI Agent 技能包请安装：[`@slingli/flowx-skill`](https://www.npmjs.com/package/@slingli/flowx-skill)。

## 开源协议

FlowX 本体为 MIT License；通过 `flowx setup-driver` 按需获取的第三方 WinDivert 二进制遵循其上游 LGPLv3 / GPLv2 协议。
