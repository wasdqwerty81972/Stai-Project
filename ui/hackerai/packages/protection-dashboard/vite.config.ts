import { defineConfig } from "vite";

export default defineConfig({
  // This app uses plain CSS. Avoid inheriting the hosted Next.js PostCSS config,
  // whose string plugin declaration is not valid for Vite's PostCSS loader.
  css: {
    postcss: { plugins: [] },
  },
  server: {
    host: "127.0.0.1",
    port: 1420,
    strictPort: true,
  },
  preview: {
    host: "127.0.0.1",
    port: 1420,
    strictPort: true,
  },
});
