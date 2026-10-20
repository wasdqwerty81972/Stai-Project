import { defineConfig } from "vite";

const frontendPort = Number(process.env.STAI_FRONTEND_PORT || 1420);

export default defineConfig({
  // This app uses plain CSS. Avoid inheriting the hosted Next.js PostCSS config,
  // whose string plugin declaration is not valid for Vite's PostCSS loader.
  css: {
    postcss: { plugins: [] },
  },
  define: {
    __STAI_TAURI_DEV_PORT__: JSON.stringify(String(frontendPort)),
  },
  server: {
    host: "127.0.0.1",
    port: frontendPort,
    strictPort: true,
  },
  preview: {
    host: "127.0.0.1",
    port: frontendPort,
    strictPort: true,
  },
});
