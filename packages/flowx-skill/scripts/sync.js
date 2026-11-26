"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const pkgRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(pkgRoot, "..", "..");
const srcSkillDir = path.join(repoRoot, "skills", "flowx");
const rootExample = path.join(repoRoot, "flowx.example.xml");
const skillExample = path.join(srcSkillDir, "references", "flowx.example.xml");
const srcLicense = path.join(repoRoot, "LICENSE");

const dstSkillsParent = path.join(pkgRoot, "skills");
const dstSkillDir = path.join(dstSkillsParent, "flowx");
const dstLicense = path.join(pkgRoot, "LICENSE");

if (!fs.existsSync(srcSkillDir) || !fs.existsSync(srcLicense)) {
  throw new Error(
    `Expected repository root files at ${srcSkillDir} and ${srcLicense}`
  );
}

function normalizeLf(text) {
  return text.replace(/\r\n/g, "\n");
}

if (fs.existsSync(rootExample) && fs.existsSync(skillExample)) {
  const rootXml = normalizeLf(fs.readFileSync(rootExample, "utf8"));
  const refXml = normalizeLf(fs.readFileSync(skillExample, "utf8"));
  if (rootXml !== refXml) {
    throw new Error(
      `flowx.example.xml drift detected between ${rootExample} and ${skillExample}`
    );
  }
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
        const text = normalizeLf(fs.readFileSync(srcPath, "utf8"));
        fs.writeFileSync(dstPath, text, "utf8");
      } else {
        fs.copyFileSync(srcPath, dstPath);
      }
    }
  }
}

function existsIncludingSymlink(targetPath) {
  try {
    fs.lstatSync(targetPath);
    return true;
  } catch (_) {
    return false;
  }
}

fs.mkdirSync(dstSkillsParent, { recursive: true });
const nonce = `${process.pid}-${crypto.randomBytes(4).toString("hex")}`;
const stagingDir = path.join(dstSkillsParent, `.flowx.staging.${nonce}`);
const backupDir = path.join(dstSkillsParent, `.flowx.backup.${nonce}`);

try {
  copyTreeNormalized(srcSkillDir, stagingDir);
  let movedOld = false;
  if (existsIncludingSymlink(dstSkillDir)) {
    fs.renameSync(dstSkillDir, backupDir);
    movedOld = true;
  }
  try {
    fs.renameSync(stagingDir, dstSkillDir);
  } catch (err) {
    if (
      movedOld &&
      existsIncludingSymlink(backupDir) &&
      !existsIncludingSymlink(dstSkillDir)
    ) {
      try {
        fs.renameSync(backupDir, dstSkillDir);
      } catch (_) {}
    }
    throw err;
  }
  if (movedOld) {
    try {
      fs.rmSync(backupDir, { recursive: true, force: true });
    } catch (cleanupErr) {
      console.warn(
        `Warning: Could not remove backup directory ${backupDir}: ${cleanupErr.message}`
      );
    }
  }
} finally {
  try {
    if (existsIncludingSymlink(stagingDir)) {
      fs.rmSync(stagingDir, { recursive: true, force: true });
    }
  } catch (_) {}
}

const licenseText = normalizeLf(fs.readFileSync(srcLicense, "utf8"));
fs.writeFileSync(dstLicense, licenseText, "utf8");

console.log(`Synced FlowX skill -> ${dstSkillDir}`);
