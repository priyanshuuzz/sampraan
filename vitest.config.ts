import { defineConfig } from "vitest/config";
import path from "path";

const templateRoot = path.resolve(import.meta.dirname);

export default defineConfig({
  root: templateRoot,
  resolve: {
    alias: {
      "@": path.resolve(templateRoot, "client", "src"),
      "@shared": path.resolve(templateRoot, "shared"),
      "@assets": path.resolve(templateRoot, "attached_assets"),
    },
  },
  test: {
    environment: "node",
    include: ["server/**/*.test.ts", "server/**/*.spec.ts"],
    // Live Besu contract/adapter tests deploy their own contracts and wait
    // for QBFT block inclusion; run files sequentially to keep timings stable.
    fileParallelism: false,
    hookTimeout: 300_000,
    testTimeout: 90_000,
  },
});
