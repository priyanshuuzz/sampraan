import { describe, expect, it } from "vitest";
import { IpfsStorageProvider, normalizeIpfsApiBase } from "./storage";

describe("normalizeIpfsApiBase (Kubo RPC base)", () => {
  it("accepts the canonical .env.example spelling with the /api/v0 suffix", () => {
    expect(normalizeIpfsApiBase("http://127.0.0.1:5001/api/v0")).toBe("http://127.0.0.1:5001/api/v0");
  });

  it("appends /api/v0 to a bare host:port endpoint", () => {
    expect(normalizeIpfsApiBase("http://127.0.0.1:5001")).toBe("http://127.0.0.1:5001/api/v0");
  });

  it("strips a trailing slash without doubling the suffix", () => {
    expect(normalizeIpfsApiBase("http://kubo:5001/api/v0/")).toBe("http://kubo:5001/api/v0");
  });

  it("does NOT double the suffix (regression: /api/v0/api/v0/add → HTTP 404)", () => {
    const normalized = normalizeIpfsApiBase("http://127.0.0.1:5001/api/v0");
    expect(normalized).not.toMatch(/api\/v0\/api\/v0/);
    expect(normalized.endsWith("/api/v0")).toBe(true);
  });

  it("rejects non-http schemes (no arbitrary-protocol SSRF)", () => {
    expect(() => normalizeIpfsApiBase("ftp://127.0.0.1:5001")).toThrow(/http\(s\)/);
    expect(() => normalizeIpfsApiBase("file:///etc/passwd")).toThrow(/http\(s\)/);
  });

  it("provider methods use the normalized base exactly once", async () => {
    const seen: string[] = [];
    const fakeFetch = (async (url: string | URL) => {
      seen.push(String(url));
      return new Response(JSON.stringify({ Hash: "bafkreitest" }), { status: 200 });
    }) as unknown as typeof fetch;
    const provider = new IpfsStorageProvider("http://127.0.0.1:5001/api/v0", fakeFetch);
    await provider.put("ref", Buffer.from("x"), { contentHash: "x" });
    expect(seen[0]).toBe("http://127.0.0.1:5001/api/v0/add?pin=true&cid-version=1");
  });
});

describe("IpfsStorageProvider failure safety", () => {
  it("put/get against an unreachable node THROW (no fake success, no local fallback)", async () => {
    const dead = new IpfsStorageProvider("http://127.0.0.1:59999/api/v0");
    await expect(dead.put("ref", Buffer.from("x"), { contentHash: "x" })).rejects.toThrow();
    await expect(dead.get("bafkreidj5dmjwc7wlc3ucekg2kmsypsqoqwr4l5mvltghtrpt7eiud6zfi")).rejects.toThrow();
  });

  it("get with an invalid CID never fabricates bytes (server error → throw)", async () => {
    const seen: string[] = [];
    const fakeFetch = (async (url: string | URL) => {
      seen.push(String(url));
      return new Response("invalid path", { status: 500 });
    }) as unknown as typeof fetch;
    const provider = new IpfsStorageProvider("http://127.0.0.1:5001/api/v0", fakeFetch);
    await expect(provider.get("bafkrei0000000000000000000000000000000000000000000000000000")).rejects.toThrow();
    expect(seen[0]).toContain("/api/v0/cat?arg=");
  });

  it("malformed references are rejected client-side BEFORE any network call", async () => {
    const seen: string[] = [];
    const fakeFetch = (async (url: string | URL) => {
      seen.push(String(url));
      return new Response("{}", { status: 200 });
    }) as unknown as typeof fetch;
    const provider = new IpfsStorageProvider("http://127.0.0.1:5001/api/v0", fakeFetch);
    await expect(provider.get("../../etc/passwd")).rejects.toThrow(/Invalid storage reference/);
    await expect(provider.get("bafkreiwith!badchars")).rejects.toThrow(/Invalid storage reference/);
    expect(seen).toHaveLength(0);
  });
});
