const { spawnSync } = require("node:child_process");
const net = require("node:net");
const path = require("node:path");

function portIsAvailable(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once("error", () => resolve(false));
    server.listen(port, "127.0.0.1", () => {
      server.close(() => resolve(true));
    });
  });
}

async function selectPort() {
  const configured = process.env.STAI_FRONTEND_PORT;
  if (configured) {
    const port = Number(configured);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(
        "STAI_FRONTEND_PORT must be a TCP port from 1 through 65535",
      );
    }
    return port;
  }

  for (let port = 1420; port <= 1425; port += 1) {
    if (await portIsAvailable(port)) return port;
  }
  throw new Error(
    "No available protection dashboard port (tried 1420 through 1425)",
  );
}

async function main() {
  const port = await selectPort();
  const viteCli = path.resolve("node_modules/vite/bin/vite.js");
  const result = spawnSync(
    process.execPath,
    [viteCli, "--host", "127.0.0.1", "--port", String(port), "--strictPort"],
    {
      stdio: "inherit",
      env: { ...process.env, STAI_FRONTEND_PORT: String(port) },
    },
  );
  if (result.error) throw result.error;
  process.exit(result.status ?? 1);
}

main().catch((error) => {
  console.error(`Unable to start protection dashboard: ${error.message}`);
  process.exit(1);
});
