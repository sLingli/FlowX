"use strict";

const fs = require("node:fs");
const path = require("node:path");

const pkgRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(pkgRoot, "..", "..");

const cargoTomlPath = path.join(repoRoot, "Cargo.toml");
const pkgJsonPath = path.join(pkgRoot, "package.json");
const srcExe = path.join(repoRoot, "target", "release", "flowx.exe");
const srcExample = path.join(repoRoot, "flowx.example.xml");
const skillExample = path.join(repoRoot, "skills", "flowx", "references", "flowx.example.xml");
const srcLicense = path.join(repoRoot, "LICENSE");

const dstNativeDir = path.join(pkgRoot, "native");
const dstDriverDir = path.join(dstNativeDir, "driver");
const dstExe = path.join(dstNativeDir, "flowx.exe");
const dstExample = path.join(pkgRoot, "flowx.example.xml");
const dstLicense = path.join(pkgRoot, "LICENSE");

function normalizeLf(text) {
  return text.replace(/\r\n/g, "\n");
}

function assertVersionAndExampleConsistency() {
  if (!fs.existsSync(cargoTomlPath) || !fs.existsSync(pkgJsonPath)) {
    throw new Error(`Missing Cargo.toml or package.json near ${repoRoot}`);
  }
  const cargoToml = fs.readFileSync(cargoTomlPath, "utf8");
  const verMatch = cargoToml.match(/^version\s*=\s*"([^"]+)"/m);
  if (!verMatch) {
    throw new Error("Failed to parse package version from Cargo.toml");
  }
  const crateVersion = verMatch[1];
  const pkgVersion = JSON.parse(fs.readFileSync(pkgJsonPath, "utf8")).version;
  const pkgBase = pkgVersion.split("-", 2)[0];
  const versionOk =
    pkgVersion === crateVersion ||
    (pkgVersion.includes("-") && !crateVersion.includes("-") && pkgBase === crateVersion);
  if (!versionOk) {
    throw new Error(
      `Version mismatch: Cargo.toml has '${crateVersion}' but packages/flowx/package.json has '${pkgVersion}'`
    );
  }

  if (fs.existsSync(skillExample)) {
    const rootXml = normalizeLf(fs.readFileSync(srcExample, "utf8"));
    const skillXml = normalizeLf(fs.readFileSync(skillExample, "utf8"));
    if (rootXml !== skillXml) {
      throw new Error(
        `flowx.example.xml drift detected between ${srcExample} and ${skillExample}`
      );
    }
  }
}

if (!fs.existsSync(srcExe)) {
  throw new Error(
    `Missing release binary at ${srcExe}. Run 'cargo build --release --locked' from repository root first.`
  );
}
if (!fs.existsSync(srcExample) || !fs.existsSync(srcLicense)) {
  throw new Error(
    `Missing ${srcExample} or ${srcLicense} at repository root.`
  );
}

assertVersionAndExampleConsistency();

// Never allow cached WinDivert binaries inside native/driver to be packed into @slingli/flowx
fs.rmSync(dstDriverDir, { recursive: true, force: true });

fs.mkdirSync(dstNativeDir, { recursive: true });
fs.copyFileSync(srcExe, dstExe);
fs.writeFileSync(dstExample, normalizeLf(fs.readFileSync(srcExample, "utf8")), "utf8");
fs.writeFileSync(dstLicense, normalizeLf(fs.readFileSync(srcLicense, "utf8")), "utf8");

const sizeMb = (fs.statSync(dstExe).size / (1024 * 1024)).toFixed(2);
console.log(`Synced flowx.exe (${sizeMb} MiB) -> ${dstExe}`);
