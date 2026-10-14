#!/usr/bin/env node
const { spawnSync } = require("node:child_process");
const path = require("node:path");

const dashboardDir = path.resolve(__dirname, "../../protection-dashboard");
const viteCli = path.join(dashboardDir, "node_modules", "vite", "bin", "vite.js");
const result = spawnSync(process.execPath, [viteCli, "build"], {
  cwd: dashboardDir,
  stdio: "inherit",
});

if (result.error) {
  console.error(`Unable to build the local STAI protection dashboard: ${result.error.message}`);
  process.exit(1);
}

process.exit(result.status ?? 1);
