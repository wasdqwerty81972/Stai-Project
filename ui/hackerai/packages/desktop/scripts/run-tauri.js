#!/usr/bin/env node
const { spawnSync } = require("node:child_process");

const [task] = process.argv.slice(2);
const tasks = ["dev", "dev:prod", "build", "build:dev", "build:prod"];
if (!task || !tasks.includes(task)) {
  console.error(`Usage: node scripts/run-tauri.js <${tasks.join("|")}>`);
  process.exit(2);
}

const command = task.startsWith("dev") ? "dev" : "build";
const args = [command];
const env = { ...process.env };
if (process.platform === "win32") {
  args.push("--config", "src-tauri/tauri.windows.conf.json");
} else if (task === "dev") {
  args.push("--config", "src-tauri/tauri.dev.conf.json");
}

if (task === "build:dev") {
  args.push("--debug");
  if (process.platform !== "win32") env.APP_URL = "http://localhost:3000";
} else if (task === "build:prod" && process.platform !== "win32") {
  env.APP_URL = "https://hackerai.co";
}

const result = spawnSync(process.platform === "win32" ? "tauri.cmd" : "tauri", args, {
  cwd: process.cwd(),
  stdio: "inherit",
  shell: process.platform === "win32",
  env,
});

if (result.error) {
  console.error(`Unable to launch Tauri: ${result.error.message}`);
  process.exit(1);
}

process.exit(result.status ?? 1);
