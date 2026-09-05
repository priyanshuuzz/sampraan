import { existsSync } from "node:fs";
import path from "node:path";

/**
 * Robust project-root resolution for the SAMPRAAN backend.
 *
 * Why this exists (BUG-001): the blockchain modules resolve artifacts and the
 * deployment record relative to `import.meta.dirname`. In the SOURCE tree
 * that directory is `<root>/server/modules/blockchain`, so `../../..` is the
 * project root. In the BUNDLED production output, however, the same code lives
 * in `<root>/dist/index.js` and `../../..` climbs out of the project entirely
 * (resolving to the filesystem root), so `blockchain/artifacts` and
 * `blockchain/deployment.json` were never found and the server crashed at
 * boot with "Contract artifact ... not found".
 *
 * Resolution order (first candidate that actually looks like the project root):
 *  1. SAMPRAAN_PROJECT_ROOT env override (explicit deployment control)
 *  2. Source layout:  <dir>/../../..        (server/modules/blockchain -> root)
 *  3. Bundle layout:  <dir>/..              (dist -> root)
 *  4. process.cwd()                            (node started from the root)
 */
let cachedRoot: string | null = null;

function looksLikeProjectRoot(dir: string): boolean {
  return existsSync(path.join(dir, "package.json")) && existsSync(path.join(dir, "blockchain"));
}

export function resolveProjectRoot(): string {
  if (cachedRoot) return cachedRoot;

  const candidates: string[] = [];
  const override = process.env.SAMPRAAN_PROJECT_ROOT;
  if (override) candidates.push(path.resolve(override));
  if (import.meta.dirname) {
    // Source layout: server/modules/blockchain/x.ts
    candidates.push(path.resolve(import.meta.dirname, "..", "..", ".."));
    // Bundled layout: dist/index.js
    candidates.push(path.resolve(import.meta.dirname, ".."));
  }
  candidates.push(path.resolve(process.cwd()));

  for (const dir of candidates) {
    if (looksLikeProjectRoot(dir)) {
      cachedRoot = dir;
      return dir;
    }
  }

  // No candidate matched; fall back to the historical source-layout value so
  // the error messages downstream still point at a plausible location.
  const fallback = import.meta.dirname
    ? path.resolve(import.meta.dirname, "..", "..", "..")
    : path.resolve(process.cwd());
  cachedRoot = fallback;
  return fallback;
}
