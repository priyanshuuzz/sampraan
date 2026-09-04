import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TRPCError } from "@trpc/server";

// env.ts snapshots process.env at import time; capture and restore around
// each test so forge configuration is controlled per test.
const ENV_KEYS = {
  url: "BUILT_IN_FORGE_API_URL",
  key: "BUILT_IN_FORGE_API_KEY",
} as const;

const savedEnv: Record<string, string | undefined> = {};
let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  for (const key of Object.values(ENV_KEYS)) {
    savedEnv[key] = process.env[key];
  }
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(async () => {
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  vi.unstubAllGlobals();
  vi.resetModules();
});

async function loadNotifyOwner() {
  vi.resetModules();
  const mod = await import("./notification");
  return mod.notifyOwner;
}

function configured(url = "https://forge.example.com", key = "forge-key") {
  process.env[ENV_KEYS.url] = url;
  process.env[ENV_KEYS.key] = key;
}

describe("notifyOwner validation", () => {
  it("rejects an empty title with BAD_REQUEST", async () => {
    configured();
    const fn = await loadNotifyOwner();
    await expect(fn({ title: "  ", content: "content" })).rejects.toMatchObject(
      {
        code: "BAD_REQUEST",
        message: "Notification title is required.",
      }
    );
  });

  it("rejects an empty content with BAD_REQUEST", async () => {
    configured();
    const fn = await loadNotifyOwner();
    await expect(fn({ title: "title", content: "" })).rejects.toMatchObject({
      code: "BAD_REQUEST",
      message: "Notification content is required.",
    });
  });

  it("rejects a title longer than 1200 characters", async () => {
    configured();
    const fn = await loadNotifyOwner();
    await expect(
      fn({ title: "a".repeat(1201), content: "content" })
    ).rejects.toMatchObject({
      code: "BAD_REQUEST",
      message: "Notification title must be at most 1200 characters.",
    });
  });

  it("rejects content longer than 20000 characters", async () => {
    configured();
    const fn = await loadNotifyOwner();
    await expect(
      fn({ title: "title", content: "c".repeat(20001) })
    ).rejects.toMatchObject({
      code: "BAD_REQUEST",
      message: "Notification content must be at most 20000 characters.",
    });
  });

  it("throws INTERNAL_SERVER_ERROR when the forge URL is not configured", async () => {
    delete process.env[ENV_KEYS.url];
    process.env[ENV_KEYS.key] = "forge-key";
    const fn = await loadNotifyOwner();
    await expect(fn({ title: "t", content: "c" })).rejects.toMatchObject({
      code: "INTERNAL_SERVER_ERROR",
      message: "Notification service URL is not configured.",
    });
  });

  it("throws INTERNAL_SERVER_ERROR when the forge API key is not configured", async () => {
    process.env[ENV_KEYS.url] = "https://forge.example.com";
    delete process.env[ENV_KEYS.key];
    const fn = await loadNotifyOwner();
    await expect(fn({ title: "t", content: "c" })).rejects.toMatchObject({
      code: "INTERNAL_SERVER_ERROR",
      message: "Notification service API key is not configured.",
    });
  });
});

describe("notifyOwner delivery", () => {
  it("posts the trimmed payload to the connect-protocol endpoint", async () => {
    configured();
    const fn = await loadNotifyOwner();
    fetchMock.mockResolvedValue({ ok: true, status: 200 });

    const delivered = await fn({ title: "  Hello  ", content: " World " });

    expect(delivered).toBe(true);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(
      "https://forge.example.com/webdevtoken.v1.WebDevService/SendNotification"
    );
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({
      title: "Hello",
      content: "World",
    });
  });

  it("normalizes a base URL without a trailing slash", async () => {
    configured("https://forge.example.com/base", "forge-key");
    const fn = await loadNotifyOwner();
    fetchMock.mockResolvedValue({ ok: true, status: 200 });

    await fn({ title: "t", content: "c" });

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(
      "https://forge.example.com/base/webdevtoken.v1.WebDevService/SendNotification"
    );
  });

  it("returns false instead of throwing when the upstream service errors", async () => {
    configured();
    const fn = await loadNotifyOwner();
    fetchMock.mockResolvedValue({
      ok: false,
      status: 503,
      statusText: "Service Unavailable",
      text: async () => "upstream detail",
    });

    const delivered = await fn({ title: "t", content: "c" });

    expect(delivered).toBe(false);
  });

  it("returns false when the fetch itself rejects", async () => {
    configured();
    const fn = await loadNotifyOwner();
    fetchMock.mockRejectedValue(new Error("network down"));

    const delivered = await fn({ title: "t", content: "c" });

    expect(delivered).toBe(false);
  });

  it("sends the bearer API key and connect headers", async () => {
    configured("https://forge.example.com", "secret-key");
    const fn = await loadNotifyOwner();
    fetchMock.mockResolvedValue({ ok: true, status: 200 });

    await fn({ title: "t", content: "c" });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.headers).toMatchObject({
      accept: "application/json",
      authorization: "Bearer secret-key",
      "content-type": "application/json",
      "connect-protocol-version": "1",
    });
  });
});

describe("notifyOwner never leaks TRPCError semantics", () => {
  it("validation failures are TRPCErrors so callers can fix the payload", async () => {
    configured();
    const fn = await loadNotifyOwner();
    try {
      await fn({ title: "", content: "c" });
      throw new Error("expected rejection");
    } catch (error) {
      expect(error).toBeInstanceOf(TRPCError);
    }
  });
});
