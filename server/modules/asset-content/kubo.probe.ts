/**
 * Kubo reachability probe for readiness reporting.
 *
 * Performs a REAL bounded add→cat round-trip against the configured
 * self-hosted Kubo node — not merely an "is the env var set" check:
 *
 *   add a 3-byte payload (pinned) → CID returned → cat it back → compare
 *
 * Report contains NO secret material and no content: only whether the node
 * is reachable and behaving. An unreachable/misbehaving node reports
 * { configured, reachable: false, error } so a deployment surfaces it; the
 * content pipeline itself already fails closed on a real write/read.
 */
import { IpfsStorageProvider } from "./storage.ts";

export interface KuboProbeResult {
  /** IPFS_API_URL present (configuration, not reachability). */
  configured: boolean;
  /** The node answered add + cat with a byte-exact round-trip. */
  reachable: boolean;
  /** CID of the probe object when reachable (starts with bafkr… for CIDv1). */
  cid?: string;
  /** Bounded short error detail (first 80 chars, no secrets). */
  error?: string;
}

let lastProbe: { at: number; result: KuboProbeResult } | null = null;
const PROBE_TTL_MS = 15_000;

export async function probeKubo(): Promise<KuboProbeResult> {
  const configured = Boolean(process.env.IPFS_API_URL);
  if (!configured) {
    return { configured: false, reachable: false, error: "IPFS_API_URL is not set" };
  }
  if (lastProbe && Date.now() - lastProbe.at < PROBE_TTL_MS) {
    return lastProbe.result;
  }
  const provider = new IpfsStorageProvider(process.env.IPFS_API_URL!);
  const payload = Buffer.from([0x53, 0x41, 0x4d]); // "SAM" — no meaningful content
  try {
    const stored = await provider.put(`readiness-probe-${Date.now()}`, payload, { contentHash: "probe" });
    const back = await provider.get(stored.reference);
    const result: KuboProbeResult =
      back.equals(payload) && stored.reference.startsWith("bafkr")
        ? { configured: true, reachable: true, cid: stored.reference }
        : { configured: true, reachable: false, error: "probe round-trip mismatch" };
    lastProbe = { at: Date.now(), result };
    return result;
  } catch (error) {
    const result: KuboProbeResult = {
      configured: true,
      reachable: false,
      error: (error instanceof Error ? error.message : String(error)).slice(0, 80),
    };
    lastProbe = { at: Date.now(), result };
    return result;
  }
}

/** Test hook: clear the memoized probe result. */
export function resetKuboProbeForTests(): void {
  lastProbe = null;
}
