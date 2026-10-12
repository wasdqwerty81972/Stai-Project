#!/usr/bin/env node
const { spawnSync } = require("node:child_process");
const path = require("node:path");

const dashboardDir = path.resolve(__dirname, "../../protection-dashboard");
const packageManager = process.platform === "win32" ? "corepack.cmd" : "pnpm";
const args = process.platform === "win32"
  ? ["pnpm", "run", "build"]
  : ["run", "build"];
const result = spawnSync(packageManager, args, {
  cwd: dashboardDir,
  stdio: "inherit",
  shell: process.platform === "win32",
});

if (result.error) {
  console.error(`Unable to build the local STAI protection dashboard: ${result.error.message}`);
  process.exit(1);
}

process.exit(result.status ?? 1);
