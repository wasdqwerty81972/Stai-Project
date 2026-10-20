#!/usr/bin/env node
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");

async function main() {
  const [task] = process.argv.slice(2);
  const tasks = ["dev", "dev:prod", "build", "build:dev", "build:prod"];
  if (!task || !tasks.includes(task)) {
    console.error(`Usage: node scripts/run-tauri.js <${tasks.join("|")}>`);
    process.exit(2);
  }

  const command = task.startsWith("dev") ? "dev" : "build";
  const args = [command];
  const env = { ...process.env };

  function parsePort(value, fallback, label) {
    const port = value == null || value === "" ? fallback : Number(value);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(`${label} must be a TCP port from 1 through 65535`);
    }
    return port;
  }

  function portIsAvailable(port) {
    return new Promise((resolve) => {
      const server = net.createServer();
      server.once("error", () => resolve(false));
      server.listen(port, "127.0.0.1", () => {
        server.close(() => resolve(true));
      });
    });
  }

  async function selectFrontendPort() {
    const explicitPort = process.env.STAI_FRONTEND_PORT;
    if (explicitPort)
      return parsePort(explicitPort, 1420, "STAI_FRONTEND_PORT");
    for (let port = 1420; port <= 1425; port += 1) {
      if (await portIsAvailable(port)) return port;
    }
    throw new Error(
      "No available protection dashboard port (tried 1420 through 1425)",
    );
  }

  let temporaryConfigDirectory;
  if (process.platform === "win32") {
    args.push("--config", "src-tauri/tauri.windows.conf.json");
    if (command === "dev") {
      try {
        const frontendPort = await selectFrontendPort();
        const apiPort = parsePort(env.STAI_API_PORT, 6764, "STAI_API_PORT");
        const agentPort = parsePort(
          env.STAI_AGENT_PORT,
          3000,
          "STAI_AGENT_PORT",
        );
        env.STAI_FRONTEND_PORT = String(frontendPort);
        env.VITE_STAI_TAURI_DEV_PORT = String(frontendPort);

        const windowsConfig = JSON.parse(
          fs.readFileSync(
            path.join(process.cwd(), "src-tauri/tauri.windows.conf.json"),
            "utf8",
          ),
        );
        const csp = windowsConfig.app.security.csp
          .replaceAll("http://127.0.0.1:6764", `http://127.0.0.1:${apiPort}`)
          .replaceAll("http://127.0.0.1:3000", `http://127.0.0.1:${agentPort}`)
          .replaceAll("ws://127.0.0.1:3000", `ws://127.0.0.1:${agentPort}`);
        const dynamicConfig = {
          build: {
            beforeDevCommand: `node ../protection-dashboard/node_modules/vite/bin/vite.js ../protection-dashboard --host 127.0.0.1 --port ${frontendPort} --strictPort`,
            devUrl: `http://127.0.0.1:${frontendPort}`,
          },
          app: { security: { csp } },
        };
        temporaryConfigDirectory = fs.mkdtempSync(
          path.join(os.tmpdir(), "svs-tauri-config-"),
        );
        const dynamicConfigPath = path.join(
          temporaryConfigDirectory,
          "tauri.dev.json",
        );
        fs.writeFileSync(
          dynamicConfigPath,
          JSON.stringify(dynamicConfig),
          "utf8",
        );
        args.push("--config", dynamicConfigPath);
      } catch (error) {
        console.error(
          `Unable to configure SVS Cyber fallback ports: ${error.message}`,
        );
        process.exit(1);
      }
    }
  } else if (task === "dev") {
    args.push("--config", "src-tauri/tauri.dev.conf.json");
  }

  if (task === "build:dev") {
    args.push("--debug");
    if (process.platform !== "win32") env.APP_URL = "http://localhost:3000";
  } else if (task === "build:prod" && process.platform !== "win32") {
    env.APP_URL = "https://hackerai.co";
  }

  const result = spawnSync(
    process.platform === "win32" ? "tauri.cmd" : "tauri",
    args,
    {
      cwd: process.cwd(),
      stdio: "inherit",
      shell: process.platform === "win32",
      env,
    },
  );

  if (temporaryConfigDirectory) {
    fs.rmSync(temporaryConfigDirectory, { recursive: true, force: true });
  }

  if (result.error) {
    console.error(`Unable to launch Tauri: ${result.error.message}`);
    process.exit(1);
  }

  process.exit(result.status ?? 1);
}

main().catch((error) => {
  console.error(`Unable to launch Tauri: ${error.message}`);
  process.exit(1);
});
