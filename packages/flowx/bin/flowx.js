#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");

const pkgRoot = path.resolve(__dirname, "..");
const exePath = path.join(pkgRoot, "native", "flowx.exe");
const driverDir = path.join(pkgRoot, "native", "driver");

const DEFAULT_WINDIVERT_URL =
  "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip";
const DEFAULT_WINDIVERT_SHA256 =
  "63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15";

function parseSetupArgs(args) {
  const opts = {
    force: false,
    url: DEFAULT_WINDIVERT_URL,
    sha256: DEFAULT_WINDIVERT_SHA256,
    customUrl: false,
    customHash: false,
    help: false,
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--force" || a === "-f") {
      opts.force = true;
    } else if (a === "-h" || a === "--help") {
      opts.help = true;
    } else if (a === "--url") {
      opts.url = args[++i];
      opts.customUrl = true;
      if (!opts.url) throw new Error("Missing value for --url");
    } else if (a.startsWith("--url=")) {
      opts.url = a.slice("--url=".length);
      opts.customUrl = true;
    } else if (a === "--sha256") {
      opts.sha256 = args[++i];
      opts.customHash = true;
      if (!opts.sha256) throw new Error("Missing value for --sha256");
    } else if (a.startsWith("--sha256=")) {
      opts.sha256 = a.slice("--sha256=".length);
      opts.customHash = true;
    } else {
      throw new Error(`Unknown option for setup-driver: ${a}`);
    }
  }
  if (opts.customUrl && !opts.customHash) {
    throw new Error(
      "When specifying a custom --url, also pass --sha256 <64-hex> to verify integrity."
    );
  }
  return opts;
}

function findFileInTree(root, targetName, requiredParentDir) {
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) {
      const hit = findFileInTree(full, targetName, requiredParentDir);
      if (hit) return hit;
    } else if (entry.isFile()) {
      const parentName = path.basename(path.dirname(full)).toLowerCase();
      const nameMatch =
        entry.name.toLowerCase() === targetName.toLowerCase() ||
        (targetName === "LICENSE" &&
          entry.name.toUpperCase().startsWith("LICENSE"));
      if (nameMatch && (!requiredParentDir || parentName === requiredParentDir)) {
        return full;
      }
    }
  }
  return null;
}

function runSetupDriver(subArgs) {
  let opts;
  try {
    opts = parseSetupArgs(subArgs);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }

  if (opts.help) {
    console.log(`flowx setup-driver — Download and verify official WinDivert 2.2.2 x64 driver

USAGE:
  flowx setup-driver [--force] [--url <ZIP_URL> --sha256 <HEX>]

Installs WinDivert.dll and WinDivert64.sys into:
  ${driverDir}
`);
    return;
  }

  const dllDst = path.join(driverDir, "WinDivert.dll");
  const sysDst = path.join(driverDir, "WinDivert64.sys");
  const licDst = path.join(driverDir, "LICENSE-WinDivert.txt");

  if (!opts.force && fs.existsSync(dllDst) && fs.existsSync(sysDst)) {
    console.log(`WinDivert driver files are already present at ${driverDir}`);
    if (fs.existsSync(exePath)) {
      const diag = spawnSync(exePath, ["transparent", "doctor"], {
        stdio: "inherit",
      });
      process.exit(diag.status ?? 0);
    }
    return;
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "flowx-windivert-"));
  const zipPath = path.join(tmpDir, "WinDivert.zip");
  const extractDir = path.join(tmpDir, "extracted");

  try {
    console.log(`Downloading WinDivert from ${opts.url} ...`);
    const dl = spawnSync(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "$ErrorActionPreference='Stop'; Invoke-WebRequest -Uri $env:FLOWX_WD_URL -OutFile $env:FLOWX_WD_ZIP -UseBasicParsing",
      ],
      {
        stdio: "inherit",
        env: { ...process.env, FLOWX_WD_URL: opts.url, FLOWX_WD_ZIP: zipPath },
      }
    );
    if (dl.status !== 0 || !fs.existsSync(zipPath)) {
      throw new Error("Failed to download WinDivert archive.");
    }

    const actualHash = crypto
      .createHash("sha256")
      .update(fs.readFileSync(zipPath))
      .digest("hex")
      .toLowerCase();
    const expectedHash = opts.sha256.trim().toLowerCase();
    if (actualHash !== expectedHash) {
      throw new Error(
        `SHA-256 mismatch! Expected ${expectedHash}, got ${actualHash}`
      );
    }
    console.log(`Verified SHA-256: ${actualHash}`);

    const ex = spawnSync(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "$ErrorActionPreference='Stop'; Expand-Archive -Path $env:FLOWX_WD_ZIP -DestinationPath $env:FLOWX_WD_OUT -Force",
      ],
      {
        stdio: "inherit",
        env: { ...process.env, FLOWX_WD_ZIP: zipPath, FLOWX_WD_OUT: extractDir },
      }
    );
    if (ex.status !== 0) {
      throw new Error("Failed to extract WinDivert archive.");
    }

    const dllSrc = findFileInTree(extractDir, "WinDivert.dll", "x64");
    const sysSrc = findFileInTree(extractDir, "WinDivert64.sys", "x64");
    const licSrc = findFileInTree(extractDir, "LICENSE", null);

    if (!dllSrc || !sysSrc) {
      throw new Error(
        "Archive does not contain expected x64/WinDivert.dll and x64/WinDivert64.sys"
      );
    }

    fs.mkdirSync(driverDir, { recursive: true });
    fs.copyFileSync(dllSrc, dllDst);
    fs.copyFileSync(sysSrc, sysDst);
    if (licSrc) {
      fs.copyFileSync(licSrc, licDst);
    }

    console.log(`Installed WinDivert x64 drivers -> ${driverDir}`);
    if (fs.existsSync(exePath)) {
      const diag = spawnSync(exePath, ["transparent", "doctor"], {
        stdio: "inherit",
      });
      process.exit(diag.status ?? 0);
    }
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function main() {
  if (process.platform !== "win32") {
    console.error("Error: FlowX only supports Windows (win32 x64).");
    process.exit(1);
  }

  const args = process.argv.slice(2);
  if (args[0] === "setup-driver") {
    runSetupDriver(args.slice(1));
    return;
  }

  if (!fs.existsSync(exePath)) {
    console.error(
      `Error: FlowX binary not found at ${exePath}. Try reinstalling @slingli/flowx.`
    );
    process.exit(1);
  }

  process.on("SIGINT", () => {});
  const child = spawn(exePath, args, { stdio: "inherit" });
  child.on("error", (err) => {
    console.error(`Failed to launch flowx.exe: ${err.message}`);
    process.exit(1);
  });
  child.on("exit", (code, signal) => {
    if (signal) {
      process.exit(1);
    }
    process.exit(code ?? 0);
  });
}

main();
