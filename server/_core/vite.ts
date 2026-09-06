import express, { type Express } from "express";
import fs from "fs";
import { type Server } from "http";
import path from "path";

/**
 * Development-only Vite middleware + production static serving.
 *
 * The `vite` package and the vite config (which pulls in the dev plugin
 * chain) are devDependencies: importing them statically would force the
 * production runtime image to ship the whole dev toolchain (and crash in
 * slim installs, ERR_MODULE_NOT_FOUND). Both are therefore imported
 * dynamically INSIDE setupVite(), which the server only calls when
 * NODE_ENV=development. The production path (serveStatic) has no dev
 * imports at all.
 */

export async function setupVite(app: Express, server: Server) {
  // Dynamic: dev-only imports, never evaluated in production.
  // nanoid v6 is ESM: the named export lives on the module namespace.
  // The vite config is loaded through an opaque specifier (computed at
  // runtime) so esbuild does NOT inline it into the production bundle —
  // inlining would force the production runtime to link the config's
  // build/dev toolchain (@tailwindcss/vite, @vitejs/plugin-react, ...).
  const configSpec = new URL("../../vite.config.ts", import.meta.url)
    .href;
  const [{ createServer: createViteServer }, nanoidMod, viteConfigMod] =
    await Promise.all([
      import("vite"),
      import("nanoid"),
      import(configSpec) as Promise<{ default: unknown }>,
    ]);
  const nanoid = nanoidMod.nanoid as () => string;
  // vite.config.ts exports defineConfig(...) whose default is the config
  // (possibly a promise when the config function is async).
  const viteConfig: Record<string, unknown> =
    typeof viteConfigMod.default === "function"
      ? ((await (viteConfigMod.default as () => Promise<unknown> | unknown)()) as Record<string, unknown>)
      : (viteConfigMod.default as Record<string, unknown>);

  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true as const,
  };

  const vite = await createViteServer({
    ...viteConfig,
    configFile: false,
    server: serverOptions,
    appType: "custom",
  });

  app.use(vite.middlewares);
  // Express 5 / path-to-regexp v8: wildcards must be named parameters.
  app.use("*path", async (req, res, next) => {
    const url = req.originalUrl;

    try {
      const clientTemplate = path.resolve(
        import.meta.dirname,
        "../..",
        "client",
        "index.html"
      );

      // always reload the index.html file from disk incase it changes
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e as Error);
      next(e);
    }
  });
}

export function serveStatic(app: Express) {
  const distPath =
    process.env.NODE_ENV === "development"
      ? path.resolve(import.meta.dirname, "../..", "dist", "public")
      : path.resolve(import.meta.dirname, "public");
  if (!fs.existsSync(distPath)) {
    console.error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }

  app.use(express.static(distPath));

  // fall through to index.html if the file doesn't exist
  // Express 5 / path-to-regexp v8: wildcards must be named parameters.
  app.use("*path", (_req, res) => {
    res.sendFile(path.resolve(distPath, "index.html"));
  });
}
