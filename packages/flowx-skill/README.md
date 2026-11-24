# @slingli/flowx-skill

[FlowX](https://github.com/sLingli/FlowX) 的官方 AI Agent Skill 包（适用于 Claude Code、Codex、Cursor、Antigravity、OpenCode 等支持 `SKILL.md` 规范的客户端）。

## 安装方式

### 1. 一键安装到本机 Agent Skill 目录（推荐）

```bash
# 自动检测当前已安装的 Agent 客户端（默认写入 ~/.agents/skills/flowx 等）
npx @slingli/flowx-skill

# 安装到指定客户端（可选：auto | agents | claude | codex | cursor | gemini | all）
npx @slingli/flowx-skill --client codex
npx @slingli/flowx-skill --client all

# 安装到当前工作区项目目录（.agents/skills/flowx）
npx @slingli/flowx-skill --project

# 预览写入目标而不实际写盘
npx @slingli/flowx-skill --dry-run
```

### 2. 作为项目依赖让支持 Agent Skills 的包管理器自动发现

```bash
pnpm add -D @slingli/flowx-skill
```

包内保留标准的 `skills/flowx/SKILL.md`、`skills/flowx/references/` 与 `skills/flowx/agents/openai.yaml` 目录结构，可被 `pnpm`、`skillpm` 等工具直接识别。

## 配套程序

此包仅包含 Agent 指导技能（全平台纯文本）。在 Windows 上运行 FlowX 本体可通过：
- [GitHub Releases](https://github.com/sLingli/FlowX/releases) 下载单文件可执行包；或
- `npm install -g @slingli/flowx` 安装 Windows CLI。

## 开源协议

MIT License
