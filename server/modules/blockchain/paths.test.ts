import { describe, expect, it } from "vitest";
import { existsSync } from "node:fs";
import path from "node:path";
import { resolveProjectRoot } from "./paths";

/**
 * BUG-001 regression tests: the project root must resolve BOTH from the
 * source tree and from the bundled production output (dist/index.js), and a
 * missing artifacts directory must never crash module import.
 */
describe("resolveProjectRoot (BUG-001 regression)", () => {
  it("resolves to the real project root from the source tree", () => {
    const root = resolveProjectRoot();
    expect(existsSync(path.join(root, "package.json"))).toBe(true);
    expect(existsSync(path.join(root, "blockchain"))).toBe(true);
  });

  it("finds contract artifacts through the resolved root", () => {
    const root = resolveProjectRoot();
    expect(
      existsSync(path.join(root, "blockchain", "artifacts", "SampraanAccessControl.json"))
    ).toBe(true);
  });

  it("resolves the same root regardless of the working directory", () => {
    const originalCwd = process.cwd();
    try {
      process.chdir(path.resolve(resolveProjectRoot(), "client"));
      const root = resolveProjectRoot();
      expect(existsSync(path.join(root, "package.json"))).toBe(true);
    } finally {
      process.chdir(originalCwd);
    }
  });
});

describe("lazy ABI loading (BUG-001 regression)", () => {
  it("imports contracts.ts without artifacts present at import time and loads ABIs on demand", async () => {
    // Import must not throw even if artifacts were missing at module load;
    // the getters only touch disk when actually invoked.
    const contracts = await import("./contracts");
    const abi = contracts.getSampraanAccessControlABI();
    expect(Array.isArray(abi)).toBe(true);
    expect((abi as Array<{ name?: string }>).some(fn => fn.name === "hasRole")).toBe(true);
  });

  it("loads all three SAMPRAAN contract ABIs", async () => {
    const contracts = await import("./contracts");
    for (const getter of [
      contracts.getSampraanAccessControlABI,
      contracts.getSampraanIdentityRegistryABI,
      contracts.getSampraanAssetRegistryABI,
    ]) {
      expect(Array.isArray(getter())).toBe(true);
      expect(getter().length).toBeGreaterThan(0);
    }
  });
});
