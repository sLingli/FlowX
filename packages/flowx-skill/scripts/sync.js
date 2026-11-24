"use strict";

const fs = require("node:fs");
const path = require("node:path");

const pkgRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(pkgRoot, "..", "..");
const srcSkillDir = path.join(repoRoot, "skills", "flowx");
const srcLicense = path.join(repoRoot, "LICENSE");

const dstSkillDir = path.join(pkgRoot, "skills", "flowx");
const dstLicense = path.join(pkgRoot, "LICENSE");

if (!fs.existsSync(srcSkillDir) || !fs.existsSync(srcLicense)) {
  throw new Error(
    `Expected repository root files at ${srcSkillDir} and ${srcLicense}`
  );
}

const LF_EXTS = new Set([".md", ".yaml", ".yml"]);

function copyTreeNormalized(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const srcPath = path.join(src, entry.name);
    const dstPath = path.join(dst, entry.name);
    if (entry.isDirectory()) {
      copyTreeNormalized(srcPath, dstPath);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (LF_EXTS.has(ext)) {
        const text = fs.readFileSync(srcPath, "utf8").replace(/\r\n/g, "\n");
        fs.writeFileSync(dstPath, text, "utf8");
      } else {
        fs.copyFileSync(srcPath, dstPath);
      }
    }
  }
}

fs.rmSync(dstSkillDir, { recursive: true, force: true });
copyTreeNormalized(srcSkillDir, dstSkillDir);

const licenseText = fs.readFileSync(srcLicense, "utf8").replace(/\r\n/g, "\n");
fs.writeFileSync(dstLicense, licenseText, "utf8");

console.log(`Synced FlowX skill -> ${dstSkillDir}`);
