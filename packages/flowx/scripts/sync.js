"use strict";

const fs = require("node:fs");
const path = require("node:path");

const pkgRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(pkgRoot, "..", "..");

const srcExe = path.join(repoRoot, "target", "release", "flowx.exe");
const srcExample = path.join(repoRoot, "flowx.example.xml");
const srcLicense = path.join(repoRoot, "LICENSE");

const dstNativeDir = path.join(pkgRoot, "native");
const dstExe = path.join(dstNativeDir, "flowx.exe");
const dstExample = path.join(pkgRoot, "flowx.example.xml");
const dstLicense = path.join(pkgRoot, "LICENSE");

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

fs.mkdirSync(dstNativeDir, { recursive: true });
fs.copyFileSync(srcExe, dstExe);
fs.copyFileSync(srcExample, dstExample);
const licenseText = fs.readFileSync(srcLicense, "utf8").replace(/\r\n/g, "\n");
fs.writeFileSync(dstLicense, licenseText, "utf8");

const sizeMb = (fs.statSync(dstExe).size / (1024 * 1024)).toFixed(2);
console.log(`Synced flowx.exe (${sizeMb} MiB) -> ${dstExe}`);
