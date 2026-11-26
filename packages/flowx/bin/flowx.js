#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");

const pkgRoot = path.resolve(__dirname, "..");
const nativeDir = path.join(pkgRoot, "native");
const exePath = path.join(nativeDir, "flowx.exe");
const pkgDriverDir = path.join(nativeDir, "driver");

const DEFAULT_WINDIVERT_URL =
  "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip";
const DEFAULT_WINDIVERT_SHA256 =
  "63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15";

function getUserFallbackDriverDir() {
  const localAppData =
    process.env.LOCALAPPDATA && process.env.LOCALAPPDATA.trim()
      ? process.env.LOCALAPPDATA.trim()
      : path.join(os.homedir(), "AppData", "Local");
  return path.join(localAppData, "FlowX", "driver");
}

function hasPairedDriver(dir) {
  return (
    fs.existsSync(path.join(dir, "WinDivert.dll")) &&
    fs.existsSync(path.join(dir, "WinDivert64.sys"))
  );
}

function isDirWritable(targetParent) {
  try {
    fs.mkdirSync(targetParent, { recursive: true });
    const probe = path.join(
      targetParent,
      `.flowx-write-probe-${process.pid}-${crypto.randomBytes(4).toString("hex")}`
    );
    fs.writeFileSync(probe, "");
    fs.rmSync(probe, { force: true });
    return true;
  } catch (_) {
    return false;
  }
}

function resolveInstallDriverDir(explicitDir) {
  if (explicitDir) {
    return path.resolve(explicitDir);
  }
  if (isDirWritable(nativeDir)) {
    return pkgDriverDir;
  }
  return getUserFallbackDriverDir();
}

function buildChildEnv(preferredDriverDir) {
  const env = { ...process.env };
  if (env.FLOWX_WINDIVERT_DLL && env.FLOWX_WINDIVERT_DLL.trim()) {
    return env;
  }
  if (preferredDriverDir && hasPairedDriver(preferredDriverDir)) {
    if (path.resolve(preferredDriverDir) !== path.resolve(pkgDriverDir)) {
      env.FLOWX_WINDIVERT_DLL = path.join(preferredDriverDir, "WinDivert.dll");
    }
    return env;
  }
  if (!hasPairedDriver(pkgDriverDir)) {
    const userDir = getUserFallbackDriverDir();
    if (hasPairedDriver(userDir)) {
      env.FLOWX_WINDIVERT_DLL = path.join(userDir, "WinDivert.dll");
    }
  }
  return env;
}

function parseSetupArgs(args) {
  const opts = {
    force: false,
    url: DEFAULT_WINDIVERT_URL,
    sha256: DEFAULT_WINDIVERT_SHA256,
    customUrl: false,
    customHash: false,
    dir: null,
    help: false,
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--force" || a === "-f") {
      opts.force = true;
    } else if (a === "-h" || a === "--help") {
      opts.help = true;
    } else if (a === "--dir" || a === "-d") {
      const val = args[++i];
      if (!val || !val.trim()) throw new Error("Missing value for --dir");
      opts.dir = val.trim();
    } else if (a.startsWith("--dir=")) {
      const val = a.slice("--dir=".length).trim();
      if (!val) throw new Error("Missing value for --dir");
      opts.dir = val;
    } else if (a === "--url") {
      const val = args[++i];
      if (!val || !val.trim()) throw new Error("Missing value for --url");
      opts.url = val.trim();
      opts.customUrl = true;
    } else if (a.startsWith("--url=")) {
      const val = a.slice("--url=".length).trim();
      if (!val) throw new Error("Missing value for --url");
      opts.url = val;
      opts.customUrl = true;
    } else if (a === "--sha256") {
      const val = args[++i];
      if (!val || !val.trim()) throw new Error("Missing value for --sha256");
      opts.sha256 = val.trim();
      opts.customHash = true;
    } else if (a.startsWith("--sha256=")) {
      const val = a.slice("--sha256=".length).trim();
      if (!val) throw new Error("Missing value for --sha256");
      opts.sha256 = val;
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
  if (!/^[0-9a-fA-F]{64}$/.test(opts.sha256)) {
    throw new Error("Invalid --sha256: expected a 64-character hexadecimal SHA-256 digest.");
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

function atomicInstallDriverFiles(targetDir, dllSrc, sysSrc, licSrc) {
  const parentDir = path.dirname(targetDir);
  const baseName = path.basename(targetDir);
  fs.mkdirSync(parentDir, { recursive: true });

  const nonce = `${process.pid}-${crypto.randomBytes(4).toString("hex")}`;
  const stagingDir = path.join(parentDir, `.${baseName}.staging.${nonce}`);
  const backupDir = path.join(parentDir, `.${baseName}.backup.${nonce}`);

  try {
    fs.mkdirSync(stagingDir, { recursive: true });
    fs.copyFileSync(dllSrc, path.join(stagingDir, "WinDivert.dll"));
    fs.copyFileSync(sysSrc, path.join(stagingDir, "WinDivert64.sys"));
    if (licSrc) {
      fs.copyFileSync(licSrc, path.join(stagingDir, "LICENSE-WinDivert.txt"));
    }

    let movedExisting = false;
    if (fs.existsSync(targetDir)) {
      fs.renameSync(targetDir, backupDir);
      movedExisting = true;
    }
    try {
      fs.renameSync(stagingDir, targetDir);
    } catch (err) {
      if (movedExisting && fs.existsSync(backupDir) && !fs.existsSync(targetDir)) {
        try {
          fs.renameSync(backupDir, targetDir);
        } catch (_) {}
      }
      throw err;
    }
    if (movedExisting) {
      fs.rmSync(backupDir, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(stagingDir, { recursive: true, force: true });
  }
}

function runDoctorAndExit(installedDir) {
  if (!fs.existsSync(exePath)) {
    return;
  }
  const diag = spawnSync(exePath, ["transparent", "doctor"], {
    stdio: "inherit",
    env: buildChildEnv(installedDir),
  });
  if (diag.error) {
    console.error(`Failed to run flowx transparent doctor: ${diag.error.message}`);
    process.exit(1);
  }
  process.exit(diag.status ?? 1);
}

function runSetupDriver(subArgs) {
  let opts;
  try {
    opts = parseSetupArgs(subArgs);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }

  const targetDriverDir = resolveInstallDriverDir(opts.dir);

  if (opts.help) {
    console.log(`flowx setup-driver — Download and verify official WinDivert 2.2.2 x64 driver

USAGE:
  flowx setup-driver [--force] [--dir <PATH>] [--url <ZIP_URL> --sha256 <HEX>]

Default install location (falls back to %LOCALAPPDATA%\\FlowX\\driver when node_modules is read-only):
  ${targetDriverDir}
`);
    return;
  }

  if (!opts.force && hasPairedDriver(targetDriverDir)) {
    console.log(`WinDivert driver files are already present at ${targetDriverDir}`);
    runDoctorAndExit(targetDriverDir);
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
    if (dl.error || dl.status !== 0 || !fs.existsSync(zipPath)) {
      throw new Error(
        dl.error
          ? `Failed to invoke PowerShell for WinDivert download: ${dl.error.message}`
          : "Failed to download WinDivert archive."
      );
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
    if (ex.error || ex.status !== 0) {
      throw new Error(
        ex.error
          ? `Failed to invoke PowerShell to extract archive: ${ex.error.message}`
          : "Failed to extract WinDivert archive."
      );
    }

    const dllSrc = findFileInTree(extractDir, "WinDivert.dll", "x64");
    const sysSrc = findFileInTree(extractDir, "WinDivert64.sys", "x64");
    const licSrc = findFileInTree(extractDir, "LICENSE", null);

    if (!dllSrc || !sysSrc) {
      throw new Error(
        "Archive does not contain expected x64/WinDivert.dll and x64/WinDivert64.sys"
      );
    }

    atomicInstallDriverFiles(targetDriverDir, dllSrc, sysSrc, licSrc);
    console.log(`Installed WinDivert x64 drivers -> ${targetDriverDir}`);
    if (path.resolve(targetDriverDir) !== path.resolve(pkgDriverDir)) {
      console.log(
        `Note: Installed to user-writable directory. The 'flowx' CLI wrapper automatically sets FLOWX_WINDIVERT_DLL; if running flowx.exe directly, configure --dll-path "${path.join(targetDriverDir, "WinDivert.dll")}".`
      );
    }
    runDoctorAndExit(targetDriverDir);
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
  const child = spawn(exePath, args, {
    stdio: "inherit",
    env: buildChildEnv(null),
  });
  child.on("error", (err) => {
    console.error(`Failed to launch flowx.exe: ${err.message}`);
    process.exit(1);
  });
  child.on("exit", (code, signal) => {
    if (signal) {
      process.exit(1);
    }
    process.exit(code ?? 1);
  });
}

if (require.main === module) {
  main();
}

module.exports = {
  parseSetupArgs,
  atomicInstallDriverFiles,
};
