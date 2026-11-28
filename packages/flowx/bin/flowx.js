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

const INVALID_WIN_PATH_CHARS = /[\x00-\x1f\x7f-\x9f"<>|*?:]/;

const DOWNLOAD_WINDIVERT_PS_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12",
  "$maxHops = 10",
  "$currentUri = $null",
  "if (-not [Uri]::TryCreate($env:FLOWX_WD_URL, [UriKind]::Absolute, [ref]$currentUri) -or $currentUri.Scheme -ne 'https') {",
  "  throw 'Blocked non-HTTPS download URL'",
  "}",
  "$downloaded = $false",
  "try {",
  "  for ($hop = 0; $hop -le $maxHops; $hop++) {",
  "    [Net.HttpWebRequest]$req = [Net.WebRequest]::Create($currentUri)",
  "    $req.Method = 'GET'",
  "    $req.AllowAutoRedirect = $false",
  "    $req.Timeout = 30000",
  "    $req.ReadWriteTimeout = 60000",
  "    $req.UserAgent = 'FlowX-Setup-Driver/1.0'",
  "    $resp = $null",
  "    try {",
  "      try {",
  "        $resp = [Net.HttpWebResponse]$req.GetResponse()",
  "      } catch [Net.WebException] {",
  "        if ($_.Exception.Response -is [Net.HttpWebResponse]) {",
  "          $resp = [Net.HttpWebResponse]$_.Exception.Response",
  "        } else {",
  "          throw",
  "        }",
  "      }",
  "      if ($null -eq $resp -or $null -eq $resp.ResponseUri -or $resp.ResponseUri.Scheme -ne 'https') {",
  "        throw 'Blocked non-HTTPS response URI'",
  "      }",
  "      $code = [int]$resp.StatusCode",
  "      if ($code -in 301, 302, 303, 307, 308) {",
  "        if ($hop -eq $maxHops) {",
  "          throw 'Too many HTTP redirects while downloading WinDivert'",
  "        }",
  "        $loc = $resp.Headers['Location']",
  "        if ([string]::IsNullOrWhiteSpace($loc)) {",
  "          throw ('HTTP ' + $code + ' redirect missing Location header')",
  "        }",
  "        $nextUri = $null",
  "        if (-not [Uri]::TryCreate($currentUri, $loc, [ref]$nextUri) -or -not $nextUri.IsAbsoluteUri) {",
  "          throw 'Invalid redirect Location URI'",
  "        }",
  "        if ($nextUri.Scheme -ne 'https') {",
  "          throw ('Blocked non-HTTPS redirect scheme: ' + $nextUri.Scheme)",
  "        }",
  "        $currentUri = $nextUri",
  "        continue",
  "      }",
  "      if ($code -ge 200 -and $code -lt 300) {",
  "        $expectedLen = $resp.ContentLength",
  "        $writtenLen = [int64]0",
  "        $inStream = $resp.GetResponseStream()",
  "        if ($null -eq $inStream) {",
  "          throw 'Empty HTTP response stream'",
  "        }",
  "        $outStream = [IO.File]::Create($env:FLOWX_WD_ZIP)",
  "        try {",
  "          $inStream.CopyTo($outStream)",
  "          $outStream.Flush()",
  "          $writtenLen = $outStream.Length",
  "        } finally {",
  "          $outStream.Dispose()",
  "          $inStream.Dispose()",
  "        }",
  "        if ($expectedLen -ge 0 -and $writtenLen -ne $expectedLen) {",
  "          throw ('Truncated HTTP download: expected ' + $expectedLen + ' bytes, got ' + $writtenLen)",
  "        }",
  "        $downloaded = $true",
  "        break",
  "      }",
  "      throw ('HTTP ' + $code + ' ' + $resp.StatusDescription)",
  "    } finally {",
  "      if ($null -ne $resp) {",
  "        $resp.Close()",
  "      }",
  "    }",
  "  }",
  "  if (-not $downloaded) {",
  "    throw 'WinDivert download did not complete'",
  "  }",
  "} catch {",
  "  Remove-Item -LiteralPath $env:FLOWX_WD_ZIP -Force -ErrorAction SilentlyContinue",
  "  throw",
  "}",
].join("\n");

function getUserFlowxDataDir() {
  const localAppData =
    process.env.LOCALAPPDATA && process.env.LOCALAPPDATA.trim()
      ? process.env.LOCALAPPDATA.trim()
      : path.join(os.homedir(), "AppData", "Local");
  return path.join(localAppData, "FlowX");
}

function getUserFallbackDriverDir() {
  return path.join(getUserFlowxDataDir(), "driver");
}

function getSavedDriverDirPointerPath() {
  return path.join(getUserFlowxDataDir(), "driver-dir.txt");
}

function existsIncludingSymlink(targetPath) {
  try {
    fs.lstatSync(targetPath);
    return true;
  } catch (_) {
    return false;
  }
}

function isRegularFile(targetPath) {
  try {
    return fs.statSync(targetPath).isFile();
  } catch (_) {
    return false;
  }
}

function normalizeLocalWinPath(rawPath) {
  const resolved = path.resolve(rawPath);
  // Node on Windows strips trailing `\` from verbatim disk roots (`\\?\C:\` -> `\\?\C:`),
  // which fails Rust's `Prefix::VerbatimDisk` validation; restore the trailing root separator.
  if (/^\\\\\?\\[a-zA-Z]:$/.test(resolved)) {
    return `${resolved}\\`;
  }
  return resolved;
}

function sameWinPath(a, b) {
  return normalizeLocalWinPath(a).toLowerCase() === normalizeLocalWinPath(b).toLowerCase();
}

function isTrustedLocalWinPath(rawPath) {
  if (typeof rawPath !== "string") {
    return false;
  }
  const trimmed = rawPath.trim();
  if (!trimmed) {
    return false;
  }
  let rest;
  if (/^[a-zA-Z]:[\\/]/.test(trimmed)) {
    rest = trimmed.slice(3);
  } else if (/^\\\\\?\\[a-zA-Z]:\\/.test(trimmed)) {
    rest = trimmed.slice(7);
    if (rest.includes("/")) {
      return false;
    }
  } else {
    return false;
  }
  const parts = rest.split(/[\\/]+/).filter(Boolean);
  for (const part of parts) {
    if (part === "." || part === ".." || INVALID_WIN_PATH_CHARS.test(part)) {
      return false;
    }
  }
  return true;
}

function validateExplicitDriverDir(rawDir) {
  const trimmed = typeof rawDir === "string" ? rawDir.trim() : "";
  if (!trimmed) {
    throw new Error("Missing value for --dir");
  }
  if (!isTrustedLocalWinPath(trimmed)) {
    throw new Error(
      `Invalid --dir '${trimmed}': must be a trusted absolute local Windows disk path (e.g. C:\\FlowX\\driver) without '.'/'..', UNC/drive-relative prefixes, or invalid characters.`
    );
  }
  const resolved = normalizeLocalWinPath(trimmed);
  if (!isTrustedLocalWinPath(resolved)) {
    throw new Error(
      `Invalid --dir '${trimmed}': resolved path '${resolved}' is not a trusted local Windows disk path.`
    );
  }
  return resolved;
}

function hasPairedDriver(dir) {
  return (
    isRegularFile(path.join(dir, "WinDivert.dll")) &&
    isRegularFile(path.join(dir, "WinDivert64.sys"))
  );
}

function readSavedDriverDir() {
  try {
    const raw = fs.readFileSync(getSavedDriverDirPointerPath(), "utf8").trim();
    if (!raw || !isTrustedLocalWinPath(raw)) {
      return null;
    }
    const resolved = normalizeLocalWinPath(raw);
    if (!isTrustedLocalWinPath(resolved)) {
      return null;
    }
    return resolved;
  } catch (_) {
    return null;
  }
}

function persistSavedDriverDir(targetDir) {
  const pointerPath = getSavedDriverDirPointerPath();
  const resolved = normalizeLocalWinPath(targetDir);
  if (!isTrustedLocalWinPath(resolved)) {
    return false;
  }
  if (sameWinPath(resolved, pkgDriverDir)) {
    try {
      fs.rmSync(pointerPath, { force: true });
      return !existsIncludingSymlink(pointerPath);
    } catch (_) {
      return false;
    }
  }
  const parentDir = path.dirname(pointerPath);
  const tmpPath = path.join(
    parentDir,
    `.driver-dir.tmp.${process.pid}-${crypto.randomBytes(4).toString("hex")}`
  );
  try {
    fs.mkdirSync(parentDir, { recursive: true });
    fs.writeFileSync(tmpPath, `${resolved}\n`, "utf8");
    fs.renameSync(tmpPath, pointerPath);
    return true;
  } catch (_) {
    try {
      fs.rmSync(tmpPath, { force: true });
    } catch (_) {}
    return false;
  }
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
    return validateExplicitDriverDir(explicitDir);
  }
  if (isDirWritable(nativeDir) && isTrustedLocalWinPath(pkgDriverDir)) {
    return pkgDriverDir;
  }
  const fallback = normalizeLocalWinPath(getUserFallbackDriverDir());
  if (!isTrustedLocalWinPath(fallback)) {
    throw new Error(
      `Fallback driver directory '${fallback}' is not a trusted local Windows disk path; pass --dir <LOCAL_DISK_PATH>.`
    );
  }
  return fallback;
}

function buildChildEnv(preferredDriverDir) {
  const env = { ...process.env };
  if (env.FLOWX_WINDIVERT_DLL && env.FLOWX_WINDIVERT_DLL.trim()) {
    return env;
  }
  if (
    preferredDriverDir &&
    isTrustedLocalWinPath(preferredDriverDir) &&
    hasPairedDriver(preferredDriverDir)
  ) {
    if (!sameWinPath(preferredDriverDir, pkgDriverDir)) {
      env.FLOWX_WINDIVERT_DLL = path.join(preferredDriverDir, "WinDivert.dll");
    }
    return env;
  }
  const savedDir = readSavedDriverDir();
  if (savedDir && isTrustedLocalWinPath(savedDir) && hasPairedDriver(savedDir)) {
    if (!sameWinPath(savedDir, pkgDriverDir)) {
      env.FLOWX_WINDIVERT_DLL = path.join(savedDir, "WinDivert.dll");
    }
    return env;
  }
  if (!hasPairedDriver(pkgDriverDir)) {
    const userDir = getUserFallbackDriverDir();
    if (isTrustedLocalWinPath(userDir) && hasPairedDriver(userDir)) {
      env.FLOWX_WINDIVERT_DLL = path.join(userDir, "WinDivert.dll");
    }
  }
  return env;
}

function redactUrlForLog(rawUrl) {
  const trimmed = String(rawUrl ?? "").trim();
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    try {
      const u = new URL(trimmed);
      if (u.username || u.password) {
        u.username = "";
        u.password = "";
      }
      return u.toString();
    } catch (_) {
      return trimmed.replace(/^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)[^/?#]*@/, "$1");
    }
  }
  return trimmed.replace(/^[^/?#]*@/, "");
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
  if (opts.help) {
    return opts;
  }
  if (opts.dir !== null) {
    opts.dir = validateExplicitDriverDir(opts.dir);
  }
  if (opts.customUrl && !opts.customHash) {
    throw new Error(
      "When specifying a custom --url, also pass --sha256 <64-hex> to verify integrity."
    );
  }
  let parsedUrl;
  try {
    parsedUrl = new URL(opts.url);
  } catch (_) {
    throw new Error(
      `Invalid --url '${redactUrlForLog(opts.url)}': expected a valid https:// URL.`
    );
  }
  if (parsedUrl.protocol !== "https:") {
    throw new Error(
      `Insecure --url '${redactUrlForLog(opts.url)}': only https:// download URLs are allowed.`
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
  fs.mkdirSync(targetDir, { recursive: true });

  const managedNames = ["WinDivert.dll", "WinDivert64.sys", "LICENSE-WinDivert.txt"];
  const sourceByName = {
    "WinDivert.dll": dllSrc,
    "WinDivert64.sys": sysSrc,
    "LICENSE-WinDivert.txt": licSrc || null,
  };

  const nonce = `${process.pid}-${crypto.randomBytes(4).toString("hex")}`;
  const items = managedNames.map((name) => ({
    name,
    src: sourceByName[name],
    destPath: path.join(targetDir, name),
    tmpPath: path.join(targetDir, `.flowx.tmp.${name}.${nonce}`),
    bakPath: path.join(targetDir, `.flowx.bak.${name}.${nonce}`),
  }));

  const backups = [];
  const swapped = [];

  try {
    // Phase 1: Stage all new driver files inside targetDir first (never touches existing files on copy failure)
    for (const item of items) {
      if (item.src) {
        fs.copyFileSync(item.src, item.tmpPath);
      }
    }

    // Phase 2: Move ALL existing managed target files (including stale LICENSE-WinDivert.txt when licSrc is null)
    // to backups BEFORE placing any new file, avoiding half-new/half-old state if a driver file is locked.
    for (const item of items) {
      if (existsIncludingSymlink(item.destPath)) {
        fs.renameSync(item.destPath, item.bakPath);
        backups.push(item);
      }
    }

    // Phase 3: Move all staged new files into their final destinations
    for (const item of items) {
      if (item.src) {
        fs.renameSync(item.tmpPath, item.destPath);
        swapped.push(item);
      }
    }

    // Phase 4: Best-effort cleanup of per-file backups after commit (AV/handle locks must not fail committed install)
    for (const item of backups) {
      try {
        fs.rmSync(item.bakPath, { recursive: true, force: true });
      } catch (cleanupErr) {
        console.warn(
          `Warning: Could not remove temporary backup ${item.bakPath}: ${cleanupErr.message}`
        );
      }
    }
  } catch (err) {
    for (let i = swapped.length - 1; i >= 0; i--) {
      try {
        fs.rmSync(swapped[i].destPath, { recursive: true, force: true });
      } catch (_) {}
    }
    for (let i = backups.length - 1; i >= 0; i--) {
      const item = backups[i];
      if (existsIncludingSymlink(item.bakPath) && !existsIncludingSymlink(item.destPath)) {
        try {
          fs.renameSync(item.bakPath, item.destPath);
        } catch (_) {}
      }
    }
    throw err;
  } finally {
    for (const item of items) {
      try {
        if (existsIncludingSymlink(item.tmpPath)) {
          fs.rmSync(item.tmpPath, { force: true });
        }
      } catch (_) {}
    }
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

  if (opts.help) {
    const displayTarget = opts.dir
      ? normalizeLocalWinPath(opts.dir)
      : `${pkgDriverDir} (or ${getUserFallbackDriverDir()} when node_modules is read-only)`;
    console.log(`flowx setup-driver — Download and verify official WinDivert 2.2.2 x64 driver

USAGE:
  flowx setup-driver [--force] [--dir <PATH>] [--url <ZIP_URL> --sha256 <HEX>]

Default install location:
  ${displayTarget}
`);
    return;
  }

  let targetDriverDir;
  try {
    targetDriverDir = resolveInstallDriverDir(opts.dir);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }

  if (!opts.force && hasPairedDriver(targetDriverDir)) {
    const saved = persistSavedDriverDir(targetDriverDir);
    console.log(`WinDivert driver files are already present at ${targetDriverDir}`);
    if (!saved) {
      console.log(
        sameWinPath(targetDriverDir, pkgDriverDir)
          ? `Warning: Could not remove stale driver pointer at ${getSavedDriverDirPointerPath()}. Delete it manually if another driver directory is still being loaded.`
          : `Note: Could not persist custom driver path under %LOCALAPPDATA%\\FlowX. Set FLOWX_WINDIVERT_DLL="${path.join(targetDriverDir, "WinDivert.dll")}" or configure --dll-path manually.`
      );
    }
    runDoctorAndExit(targetDriverDir);
    return;
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "flowx-windivert-"));
  const zipPath = path.join(tmpDir, "WinDivert.zip");
  const extractDir = path.join(tmpDir, "extracted");

  try {
    console.log(`Downloading WinDivert from ${redactUrlForLog(opts.url)} ...`);
    const encodedDownloadScript = Buffer.from(
      DOWNLOAD_WINDIVERT_PS_SCRIPT,
      "utf16le"
    ).toString("base64");
    const dl = spawnSync(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        encodedDownloadScript,
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
        "$ErrorActionPreference='Stop'; Expand-Archive -LiteralPath $env:FLOWX_WD_ZIP -DestinationPath $env:FLOWX_WD_OUT -Force",
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
    const pointerSaved = persistSavedDriverDir(targetDriverDir);
    console.log(`Installed WinDivert x64 drivers -> ${targetDriverDir}`);
    if (!sameWinPath(targetDriverDir, pkgDriverDir)) {
      if (pointerSaved) {
        console.log(
          `Note: Saved driver directory to ${getSavedDriverDirPointerPath()}; future 'flowx' wrapper invocations will automatically set FLOWX_WINDIVERT_DLL. If running flowx.exe directly, configure --dll-path "${path.join(targetDriverDir, "WinDivert.dll")}".`
        );
      } else {
        console.log(
          `Note: Could not persist driver path under %LOCALAPPDATA%\\FlowX. Set FLOWX_WINDIVERT_DLL="${path.join(targetDriverDir, "WinDivert.dll")}" or configure --dll-path "${path.join(targetDriverDir, "WinDivert.dll")}" manually.`
        );
      }
    } else if (!pointerSaved) {
      console.log(
        `Warning: Could not remove stale driver pointer at ${getSavedDriverDirPointerPath()}. Delete it manually if another driver directory is still being loaded.`
      );
    }
    runDoctorAndExit(targetDriverDir);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_) {}
  }
}

function main() {
  if (process.platform !== "win32" || process.arch !== "x64") {
    console.error(
      `Error: FlowX only supports Windows x64 (win32 x64); detected ${process.platform} ${process.arch}.`
    );
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

  // Keep the Node wrapper alive on Ctrl+C and Ctrl+Break so flowx.exe can stop WinDivert and flush DNS cleanly
  process.on("SIGINT", () => {});
  process.on("SIGBREAK", () => {});
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
  buildChildEnv,
  persistSavedDriverDir,
  readSavedDriverDir,
  getSavedDriverDirPointerPath,
  sameWinPath,
  normalizeLocalWinPath,
  redactUrlForLog,
  isTrustedLocalWinPath,
  validateExplicitDriverDir,
  DOWNLOAD_WINDIVERT_PS_SCRIPT,
};
