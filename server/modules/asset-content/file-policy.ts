/**
 * SAMPRAAN asset file policy — MIME/type validation by CONTENT, not headers.
 *
 * The client-supplied Content-Type is NEVER trusted: uploads are sniffed
 * from magic bytes / structural probes and matched against a curated
 * allowlist of document/text formats appropriate for a controlled asset
 * workspace. Unrecognized binaries are rejected (MVP scope: documents and
 * text; firmware binaries come later behind the same policy object).
 *
 * The policy is data-driven and intentionally small; extending coverage
 * means adding a sniff rule, not loosening a generic "any file" default.
 */

export type SniffedMime = {
  mimeType: string;
  category: "text" | "pdf" | "image" | "binary";
  /** Human-readable canonical label used by the workspace UI. */
  label: string;
};

interface SniffRule {
  mimeType: string;
  category: SniffedMime["category"];
  label: string;
  /** Magic prefix bytes. */
  magic?: number[];
  /** UTF-8 prefix that must appear at offset 0. */
  textPrefix?: string;
  /** Extra structural predicate on the whole buffer. */
  predicate?: (data: Buffer) => boolean;
}

/**
 * Rule order matters: structured text formats (CSV/JSON/MD/XML/HTML) are
 * probed BEFORE text/plain so a JSON or CSV file is classified by its real
 * format rather than being swallowed by the generic text fallback.
 */
const RULES: SniffRule[] = [
  { mimeType: "application/pdf", category: "pdf", label: "PDF document", magic: [0x25, 0x50, 0x44, 0x46] }, // %PDF
  { mimeType: "image/png", category: "image", label: "PNG image", magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { mimeType: "image/jpeg", category: "image", label: "JPEG image", magic: [0xff, 0xd8, 0xff] },
  { mimeType: "text/xml", category: "text", label: "XML document", textPrefix: "<?xml" },
  { mimeType: "text/html", category: "text", label: "HTML document", textPrefix: "<!DOCTYPE" },
  { mimeType: "application/json", category: "text", label: "JSON document", predicate: isJsonShaped },
  { mimeType: "text/csv", category: "text", label: "CSV data", predicate: isCsvShaped },
  { mimeType: "text/markdown", category: "text", label: "Markdown document", textPrefix: "#" },
  // Generic fallback: any other well-formed UTF-8 text (README, notes, logs).
  { mimeType: "text/plain", category: "text", label: "Plain text" },
];

function startsWithMagic(data: Buffer, magic: number[]): boolean {
  return magic.every((byte, index) => data[index] === byte);
}

function isLikelyUtf8Text(data: Buffer): boolean {
  // Reject NULs and must decode as UTF-8 (caller enforces fatal decode).
  if (data.includes(0)) return false;
  let controlBytes = 0;
  const sampleEnd = Math.min(data.byteLength, 8192);
  for (let i = 0; i < sampleEnd; i++) {
    const byte = data[i];
    if (byte < 0x09 || (byte > 0x0d && byte < 0x20 && byte !== 0x1b)) controlBytes++;
  }
  return controlBytes === 0;
}

function isCsvShaped(data: Buffer): boolean {
  const head = data.subarray(0, 4096).toString("utf8");
  // Strict heuristic: a real CSV has a delimiter on AT LEAST TWO lines —
  // ordinary prose that merely contains a comma must stay text/plain.
  const lines = head.split(/\r?\n/).filter(line => line.trim().length > 0);
  return lines.length >= 2 && lines.slice(0, 4).filter(line => /[,;]/.test(line)).length >= 2;
}

function isJsonShaped(data: Buffer): boolean {
  try {
    const parsed: unknown = JSON.parse(data.toString("utf8"));
    return typeof parsed === "object" || Array.isArray(parsed) || typeof parsed === "string";
  } catch {
    return false;
  }
}

export const assetFilePolicy = {
  /** Largest accepted upload (defense against memory-exhaustion). */
  maxBytes: Number(process.env.ASSET_CONTENT_MAX_BYTES ?? 20 * 1024 * 1024),

  /** All MIME types this deployment accepts. */
  allowedMimeTypes(): string[] {
    return RULES.map(rule => rule.mimeType);
  },

  /**
   * Sniff a buffer into a canonical MIME type, or null when the content is
   * not on the allowlist. Structural checks (UTF-8 validity) are applied by
   * the caller for text categories.
   */
  sniff(data: Buffer): SniffedMime | null {
    if (!data || data.byteLength === 0) return null;
    for (const rule of RULES) {
      if (rule.magic && !startsWithMagic(data, rule.magic)) continue;
      if (rule.textPrefix && !data.subarray(0, rule.textPrefix.length).toString("utf8").startsWith(rule.textPrefix)) continue;
      if (rule.predicate && !rule.predicate(data)) continue;
      // All text categories require plausible UTF-8 (no NULs / control soup);
      // binary garbage renamed to .txt must never pass.
      if (rule.category === "text" && !isLikelyUtf8Text(data)) continue;
      return { mimeType: rule.mimeType, category: rule.category, label: rule.label };
    }
    return null;
  },
} as const;
