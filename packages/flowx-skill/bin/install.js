#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const pkgRoot = path.resolve(__dirname, "..");
const bundledSkillDir = path.join(pkgRoot, "skills", "flowx");
const LF_EXTS = new Set([".md", ".yaml", ".yml"]);

function printHelp() {
  console.log(`@slingli/flowx-skill — Install the FlowX Agent Skill (SKILL.md)

USAGE:
  npx @slingli/flowx-skill [OPTIONS]

OPTIONS:
  --client <NAME>   Target client: auto (default), agents, claude, codex, cursor, gemini, all
  --project         Install into the current workspace (.agents/skills/flowx)
  --dir <PATH>      Install into a custom skills parent directory (<PATH>/flowx)
  --dry-run         Show target directories without copying files
  -h, --help        Show this help message
`);
}

function parseArgs(argv) {
  const opts = {
    client: "auto",
    project: false,
    dir: null,
    dryRun: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "-h" || arg === "--help") {
      opts.help = true;
    } else if (arg === "--project" || arg === "-p") {
      opts.project = true;
    } else if (arg === "--dry-run") {
      opts.dryRun = true;
    } else if (arg === "--client" || arg === "-c") {
      const val = argv[++i];
      if (!val) throw new Error("Missing value for --client");
      opts.client = val.toLowerCase();
    } else if (arg.startsWith("--client=")) {
      opts.client = arg.slice("--client=".length).toLowerCase();
    } else if (arg === "--dir" || arg === "-d") {
      const val = argv[++i];
      if (!val) throw new Error("Missing value for --dir");
      opts.dir = val;
    } else if (arg.startsWith("--dir=")) {
      opts.dir = arg.slice("--dir=".length);
    } else {
      throw new Error(`Unknown option: ${arg}`);
    }
  }
  return opts;
}

function resolveTargets(opts) {
  if (opts.dir) {
    return [path.join(path.resolve(opts.dir), "flowx")];
  }

  if (opts.project) {
    const cwd = process.cwd();
    const bases = [path.join(cwd, ".agents", "skills")];
    for (const dotDir of [".claude", ".cursor", ".codex"]) {
      if (fs.existsSync(path.join(cwd, dotDir))) {
        bases.push(path.join(cwd, dotDir, "skills"));
      }
    }
    return [...new Set(bases)].map((b) => path.join(b, "flowx"));
  }

  const home = os.homedir();
  const candidates = {
    agents: [path.join(home, ".agents"), path.join(home, ".agents", "skills")],
    claude: [path.join(home, ".claude"), path.join(home, ".claude", "skills")],
    codex: [path.join(home, ".codex"), path.join(home, ".codex", "skills")],
    cursor: [path.join(home, ".cursor"), path.join(home, ".cursor", "skills")],
    gemini: fs.existsSync(path.join(home, ".gemini", "config"))
      ? [
          path.join(home, ".gemini", "config"),
          path.join(home, ".gemini", "config", "skills"),
        ]
      : [
          path.join(home, ".gemini", "antigravity"),
          path.join(home, ".gemini", "antigravity", "skills"),
        ],
  };

  if (opts.client === "all") {
    return Object.values(candidates).map(([, skillsRoot]) =>
      path.join(skillsRoot, "flowx")
    );
  }

  if (opts.client !== "auto") {
    const match = candidates[opts.client];
    if (!match) {
      throw new Error(
        `Unknown --client '${opts.client}'. Expected: auto, agents, claude, codex, cursor, gemini, all`
      );
    }
    return [path.join(match[1], "flowx")];
  }

  const detected = Object.values(candidates)
    .filter(([probeDir]) => fs.existsSync(probeDir))
    .map(([, skillsRoot]) => path.join(skillsRoot, "flowx"));

  if (detected.length === 0) {
    return [path.join(candidates.agents[1], "flowx")];
  }
  return [...new Set(detected)];
}

function copyDir(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  let count = 0;
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const srcPath = path.join(src, entry.name);
    const dstPath = path.join(dst, entry.name);
    if (entry.isDirectory()) {
      count += copyDir(srcPath, dstPath);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (LF_EXTS.has(ext)) {
        const text = fs.readFileSync(srcPath, "utf8").replace(/\r\n/g, "\n");
        fs.writeFileSync(dstPath, text, "utf8");
      } else {
        fs.copyFileSync(srcPath, dstPath);
      }
      count += 1;
    }
  }
  return count;
}

function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }

  if (opts.help) {
    printHelp();
    return;
  }

  if (!fs.existsSync(path.join(bundledSkillDir, "SKILL.md"))) {
    console.error(`Error: Bundled SKILL.md not found at ${bundledSkillDir}`);
    process.exit(1);
  }

  let targets;
  try {
    targets = resolveTargets(opts);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }

  for (const target of targets) {
    if (opts.dryRun) {
      console.log(`[dry-run] Would install flowx skill -> ${target}`);
      continue;
    }
    fs.rmSync(target, { recursive: true, force: true });
    const fileCount = copyDir(bundledSkillDir, target);
    console.log(`Installed flowx skill (${fileCount} files) -> ${target}`);
  }
}

main();
