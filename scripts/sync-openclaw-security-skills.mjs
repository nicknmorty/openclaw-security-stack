#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const sourceDir = path.join(repoRoot, "tools/anthropic-security/openclaw-skills");

function usage() {
  return `Usage: node scripts/sync-openclaw-security-skills.mjs --install-dir <dir> [--force]

Copies OpenClaw-adapted Anthropic security skill wrappers into a skills directory.

Options:
  --install-dir <dir>  Destination directory for skill folders.
  --force             Overwrite existing wrapper folders.
  --help              Show this help.
`;
}

function parseArgs(argv) {
  const args = { installDir: null, force: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      console.log(usage());
      process.exit(0);
    }
    if (arg === "--force") {
      args.force = true;
      continue;
    }
    if (arg === "--install-dir") {
      const value = argv[i + 1];
      if (!value || value.startsWith("--")) throw new Error("--install-dir requires a value");
      args.installDir = value;
      i += 1;
      continue;
    }
    throw new Error(`Unknown option: ${arg}`);
  }
  if (!args.installDir) throw new Error("Missing --install-dir");
  return args;
}

function copySkillWrappers(installDir, force) {
  const resolvedInstall = path.resolve(installDir);
  const entries = fs.readdirSync(sourceDir, { withFileTypes: true });
  const copied = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const from = path.join(sourceDir, entry.name);
    const to = path.join(resolvedInstall, entry.name);
    if (fs.existsSync(to)) {
      if (!force) throw new Error(`Refusing to overwrite ${to}; pass --force`);
      fs.rmSync(to, { recursive: true, force: true });
    }
    fs.mkdirSync(path.dirname(to), { recursive: true });
    fs.cpSync(from, to, { recursive: true });
    copied.push(entry.name);
  }
  return copied.sort();
}

function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    const copied = copySkillWrappers(args.installDir, args.force);
    console.log(`Copied ${copied.length} OpenClaw security skill wrappers to ${path.resolve(args.installDir)}`);
    for (const name of copied) console.log(`- ${name}`);
  } catch (error) {
    console.error(`sync-openclaw-security-skills: ${error.message}`);
    console.error("");
    console.error(usage());
    process.exit(1);
  }
}

main();
