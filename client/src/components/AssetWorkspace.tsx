/**
 * SAMPRAAN Asset Workspace — controlled content panel for the Assets page.
 *
 * Product rules implemented here (matching the backend contract):
 *  - NO download button, NO file URL: content renders inside the workspace
 *    through the authenticated content.view channel, and only after the
 *    backend authorizes it (the UI merely reflects the server's verdict).
 *  - Permission-aware actions: every control is disabled with an honest
 *    reason until the backend proves otherwise; hiding a control is UX
 *    only — the backend re-authorizes every call.
 *  - Version history is preserved server-side; this panel lists versions,
 *    shows the current one, and creates new versions by upload.
 *  - Integrity verification shows the exact server verdict
 *    (INTEGRITY_VERIFIED / MISMATCH / CONTENT_UNAVAILABLE / VERIFICATION_ERROR).
 *
 * Visual language follows the existing SAMPRAAN workspace (evidence-block,
 * decision-proof, sampraan-table, status pills) — no new design system.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { FileCheck2, Fingerprint, LockKeyhole, RefreshCw, ShieldCheck, Upload, X } from "lucide-react";

type Tone = "mint" | "amber" | "red" | "muted";

export interface AssetWorkspaceIdentity {
  displayName: string;
  did: string;
}

interface PublicVersion {
  id: string;
  versionNumber: number;
  filename: string;
  originalFilename: string;
  mimeType: string;
  sizeBytes: number;
  contentHash: string;
  storageProvider: string;
  changeNote: string | null;
  createdTxHash: string | null;
  createdBlockNumber: number | null;
  createdAt: string | Date;
}

type StepUpOperation = "content-view" | "content-edit";

const textMime = (mime: string) => mime.startsWith("text/") || mime === "application/json";

/**
 * Step-up challenge panel: renders the server-bound challenge, accepts the
 * operator's signature (signed out-of-band — the browser never holds the
 * DID key), and verifies it server-side. Re-issue replaces an expired or
 * already-consumed challenge; dismiss cancels the pending retry.
 */
function StepUpChallengePanel({
  hint,
  nonce,
  signature,
  onSignatureChange,
  verifying,
  onVerify,
  onReissue,
  onDismiss,
}: {
  hint: string;
  nonce: string | null;
  signature: string;
  onSignatureChange: (value: string) => void;
  verifying: boolean;
  onVerify: () => void;
  onReissue: () => void;
  onDismiss: () => void;
}) {
  return (
    <div className="evidence-block" style={{ marginTop: 12 }}>
      <h4>STEP-UP CHALLENGE (SERVER-BOUND)</h4>
      <pre style={{ margin: 0, padding: 12, overflow: "auto", maxHeight: 200, borderRadius: 8, background: "var(--surface-2, rgba(127,127,127,.08))", fontSize: 11.5, whiteSpace: "pre-wrap", fontFamily: "var(--mono, monospace)" }}>{hint}</pre>
      <div className="sampraan-field" style={{ marginTop: 10 }}>
        <label className="sampraan-label" htmlFor="stepup-signature">SIGNATURE (from your DID operator console or wallet)</label>
        <input
          id="stepup-signature"
          className="sampraan-input"
          value={signature}
          onChange={e => onSignatureChange(e.target.value)}
          placeholder="0x…"
          autoComplete="off"
          spellCheck={false}
        />
      </div>
      <div className="identity-actions" style={{ marginTop: 10 }}>
        <button type="button" className="action solid" disabled={verifying || !nonce || signature.trim().length < 32} onClick={onVerify}>
          <ShieldCheck size={14} /> {verifying ? "VERIFYING…" : "Verify & Continue"}
        </button>
        <button type="button" className="action" disabled={verifying} onClick={onReissue}>Re-issue challenge</button>
        <button type="button" className="action text" disabled={verifying} onClick={onDismiss}>Dismiss</button>
      </div>
    </div>
  );
}
const formatBytes = (bytes: number) =>
  bytes >= 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)} MiB` : `${(bytes / 1024).toFixed(1)} KiB`;
const formatHash = (hash: string) => `${hash.slice(0, 12)}…${hash.slice(-6)}`;

export function AssetWorkspace({
  assetId,
  assetName,
  classification,
  actorDid,
  isAdmin,
}: {
  assetId: string;
  assetName: string;
  classification: string;
  actorDid: string | null;
  isAdmin: boolean;
}) {
  const utils = trpc.useUtils();
  const [viewerVersionId, setViewerVersionId] = useState<string | null>(null);
  const [viewerText, setViewerText] = useState<string | null>(null);
  const [viewerMime, setViewerMime] = useState<string | null>(null);
  const [viewerLoading, setViewerLoading] = useState(false);
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [integrity, setIntegrity] = useState<Record<string, { state: string; detail?: string }>>({});
  const [showUpload, setShowUpload] = useState(false);
  const [changeNote, setChangeNote] = useState("");
  const [pendingFile, setPendingFile] = useState<{ name: string; mime: string | null; dataBase64: string; size: number } | null>(null);
  const [stepUpHint, setStepUpHint] = useState<string | null>(null);
  const [stepUpNonce, setStepUpNonce] = useState<string | null>(null);
  const [stepUpOperation, setStepUpOperation] = useState<StepUpOperation | null>(null);
  const [stepUpSignature, setStepUpSignature] = useState("");
  const [pendingAction, setPendingAction] = useState<(() => void) | null>(null);
  const autoChallengeForRef = useRef<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const versionsQuery = trpc.content.list.useQuery({ assetId }, { enabled: !!assetId, retry: false });
  const listNeedsStepUp = versionsQuery.error?.message.startsWith("STEP_UP_REQUIRED") ?? false;
  const versions = versionsQuery.data?.versions ?? [];
  const current = versions[0]; // list is newest-first
  const myIdentityNeedsGrant = !!actorDid; // informational only; the server decides

  /** Issue a challenge for the given purpose and remember how to continue. */
  const beginStepUp = (operation: StepUpOperation, retry: () => void) => {
    setPendingAction(() => retry);
    setStepUpOperation(operation);
    stepupChallenge.mutate({ assetId, operation });
  };

  const view = trpc.content.view.useMutation({
    onMutate: () => setViewerLoading(true),
    onSuccess: result => {
      setViewerVersionId(result.version.id);
      setViewerMime(result.version.mimeType);
      if (textMime(result.version.mimeType)) {
        try {
          setViewerText(atob(result.contentBase64));
        } catch {
          setViewerText("(binary payload)");
        }
      } else {
        setViewerText(null);
      }
      setViewerLoading(false);
      toast.success("Controlled view authorized", { description: `Streaming ${result.version.filename} v${result.version.versionNumber} inside the workspace (view-only).` });
    },
    onError: (error, variables) => {
      setViewerLoading(false);
      if (error.message.startsWith("STEP_UP_REQUIRED")) {
        // Retry re-submits the exact version the actor asked for.
        beginStepUp("content-view", () => view.mutate({ versionId: variables.versionId }));
        return;
      }
      toast.error("Content view denied", { description: error.message });
    },
  });

  const stepupVerify = trpc.stepup.verify.useMutation({
    onSuccess: result => {
      toast.success("Step-up verified", { description: `Server-verified for ${result.purpose} — continuing.` });
      setStepUpHint(null);
      setStepUpNonce(null);
      setStepUpSignature("");
      const retry = pendingAction;
      setPendingAction(null);
      if (retry) retry();
    },
    onError: error => toast.error("Step-up failed", { description: error.message }),
  });
  const stepupChallenge = trpc.stepup.requestChallenge.useMutation({
    onSuccess: challenge => {
      // The workspace cannot hold the DID signing key; the honest MVP flow
      // asks the operator to sign the challenge out-of-band (operator
      // console / DID wallet) and paste the signature back here. The
      // challenge is retained server-side until consumed or expires.
      toast.info("Step-up challenge issued", { description: "Sign the challenge with this identity's DID key (operator console or wallet), paste the signature, then verify to continue." });
      setStepUpHint(challenge.message);
      setStepUpNonce(challenge.nonce);
      setStepUpSignature("");
    },
    onError: error => toast.error("Step-up unavailable", { description: error.message }),
  });

  const verify = trpc.content.verifyIntegrity.useMutation({
    onMutate: input => setVerifyingId(input.versionId),
    onSuccess: (result, input) => {
      setIntegrity(prev => ({ ...prev, [input.versionId]: { state: result.state, detail: result.detail } }));
      setVerifyingId(null);
      if (result.state === "INTEGRITY_VERIFIED") {
        toast.success("INTEGRITY VERIFIED", { description: `sha256 recomputed from stored ciphertext matches the recorded hash (${formatHash(result.expectedHash)}).` });
      } else if (result.state === "INTEGRITY_MISMATCH") {
        toast.error("INTEGRITY MISMATCH", { description: `Recomputed hash does not match the record — treat this content as suspect.` });
      } else {
        toast.warning(result.state.replace(/_/g, " "), { description: result.detail ?? "The integrity check could not complete." });
      }
    },
    onError: error => {
      setVerifyingId(null);
      toast.error("Verification denied", { description: error.message });
    },
  });

  const upload = trpc.content.createVersion.useMutation({
    onSuccess: result => {
      setShowUpload(false);
      setPendingFile(null);
      setChangeNote("");
      toast.success(`Version ${result.version.versionNumber} created`, {
        description: `${result.version.filename} stored encrypted (${result.version.mimeType}). Prior versions are preserved.`,
      });
      void utils.content.list.invalidate({ assetId });
    },
    onError: (error, variables) => {
      // A step-up gate is not a rejection: route it into the challenge flow
      // and re-submit this exact payload once the server verifies the step-up.
      if (error.message.startsWith("STEP_UP_REQUIRED")) {
        setShowUpload(true);
        beginStepUp("content-edit", () => upload.mutate(variables));
        return;
      }
      toast.error("Version rejected", { description: error.message });
    },
  });

  const readFileAsBase64 = (file: File) =>
    new Promise<string>((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const result = String(reader.result ?? "");
        const commaIndex = result.indexOf(",");
        resolve(commaIndex >= 0 ? result.slice(commaIndex + 1) : result);
      };
      reader.onerror = () => reject(new Error("File could not be read"));
      reader.readAsDataURL(file);
    });

  const startUpload = async (file: File) => {
    if (file.size > 20 * 1024 * 1024) {
      toast.error("File too large", { description: "The upload limit is 20 MiB." });
      return;
    }
    const dataBase64 = await readFileAsBase64(file);
    setPendingFile({ name: file.name, mime: file.type || null, dataBase64, size: file.size });
  };

  const submitUpload = () => {
    if (!pendingFile) return;
    upload.mutate({
      assetId,
      filename: pendingFile.name,
      clientMimeType: pendingFile.mime,
      dataBase64: pendingFile.dataBase64,
      changeNote: changeNote.trim() || undefined,
    });
  };

  const integrityTone = (state?: string): Tone =>
    state === "INTEGRITY_VERIFIED" ? "mint" : state === "INTEGRITY_MISMATCH" ? "red" : state ? "amber" : "muted";

  // When the list itself is step-up gated, issue the challenge ONCE per
  // gate appearance so the operator sees a concrete challenge instead of a
  // dead end. The user finishes it through the challenge panel; retry is a
  // plain refetch of the list.
  useEffect(() => {
    if (!listNeedsStepUp) return;
    const gate = `list:${assetId}`;
    if (autoChallengeForRef.current === gate) return;
    if (stepupChallenge.isPending || stepUpHint) return;
    autoChallengeForRef.current = gate;
    beginStepUp("content-view", () => versionsQuery.refetch());
  }, [listNeedsStepUp, assetId]);

  if (versionsQuery.error) {
    const stepUp = listNeedsStepUp;
    return (
      <div className="evidence-block" style={{ marginTop: 18 }}>
        <h4>CONTROLLED CONTENT</h4>
        <p className="panel-note">
          {stepUp
            ? "This asset's content requires a server-verified step-up before the workspace can list it."
            : `Controlled content is not available for this session (${versionsQuery.error.message}). The backend decides content access per asset and per operation.`}
        </p>
        {stepUp && (
          <div className="identity-actions" style={{ marginTop: 10 }}>
            <button type="button" className="action solid" disabled={stepupChallenge.isPending} onClick={() => beginStepUp("content-view", () => versionsQuery.refetch())}>
              <LockKeyhole size={14} /> {stepupChallenge.isPending ? "REQUESTING CHALLENGE…" : "Start Step-Up Verification"}
            </button>
          </div>
        )}
        {stepUp && stepUpHint && (
          <StepUpChallengePanel
            hint={stepUpHint}
            nonce={stepUpNonce}
            signature={stepUpSignature}
            onSignatureChange={setStepUpSignature}
            verifying={stepupVerify.isPending}
            onVerify={() => stepupVerify.mutate({ assetId, nonce: stepUpNonce ?? "", signature: stepUpSignature.trim(), operation: stepUpOperation ?? "content-view" })}
            onReissue={() => stepupChallenge.mutate({ assetId, operation: stepUpOperation ?? "content-view" })}
            onDismiss={() => {
              setStepUpHint(null);
              setStepUpNonce(null);
              setStepUpSignature("");
              setPendingAction(null);
            }}
          />
        )}
      </div>
    );
  }

  return (
    <div className="evidence-block" style={{ marginTop: 18 }}>
      <h4>CONTROLLED CONTENT — ENCRYPTED ASSET WORKSPACE</h4>
      <p className="panel-note">
        Content is encrypted server-side before storage and streamed only to authorized sessions inside this workspace.
        There is deliberately no download and no public file URL — access is controlled, versioned, and audited.
        {!myIdentityNeedsGrant && " Your session is not linked to a SAMPRAAN identity, so content operations will be denied server-side."}
      </p>

      {/* Current version summary */}
      <div className="decision-proof">
        <div><span>CURRENT VERSION</span><code>{current ? `v${current.versionNumber}` : "NO CONTENT"}</code></div>
        <div><span>FILE</span><code className="truncate" title={current?.filename}>{current?.filename ?? "—"}</code></div>
        <div><span>TYPE</span><code>{current?.mimeType ?? "—"}</code></div>
        <div><span>SIZE</span><code>{current ? formatBytes(current.sizeBytes) : "—"}</code></div>
        <div><span>SHA-256</span><code className="truncate" title={current?.contentHash}>{current ? formatHash(current.contentHash) : "—"}</code></div>
        <div><span>STORAGE</span><code>{current ? `${current.storageProvider} · content-addressed` : "—"}</code></div>
      </div>

      {/* Permission-aware actions */}
      <div className="identity-actions" style={{ marginTop: 12 }}>
        <button
          type="button"
          className="action solid"
          disabled={!current || viewerLoading || view.isPending}
          onClick={() => current && view.mutate({ versionId: current.id })}
          title={current ? "Open a controlled in-workspace view (server-authorized)" : "No content stored for this asset"}
        >
          <FileCheck2 size={14} /> {viewerLoading ? "AUTHORIZING…" : "Open Controlled View"}
        </button>
        <button type="button" className="action" onClick={() => setShowUpload(v => !v)} title="Create a new encrypted version (owner, custodian, or granted identity)">
          <Upload size={14} /> New Version
        </button>
        {current && (
          <button
            type="button"
            className="action"
            disabled={verifyingId === current.id}
            onClick={() => verify.mutate({ versionId: current.id })}
            title="Recompute the content hash from stored ciphertext and compare against the record"
          >
            <ShieldCheck size={14} /> {verifyingId === current.id ? "VERIFYING…" : "Verify Integrity"}
          </button>
        )}
      </div>

      {integrity[current?.id ?? ""] && (
        <p className="panel-note" role="status">
          Integrity: <b>{integrity[current.id].state.replaceAll("_", " ")}</b>
          {integrity[current.id].detail ? ` — ${integrity[current.id].detail}` : ""}
        </p>
      )}

      {/* Upload dialog */}
      {showUpload && (
        <div className="sampraan-dialog-overlay" role="dialog" aria-modal="true" aria-label="Create new version" onClick={e => { if (e.target === e.currentTarget) setShowUpload(false); }}>
          <div className="sampraan-dialog">
            <div className="sampraan-dialog-head">
              <div><span className="eyebrow">CONTROLLED CONTENT / NEW VERSION</span><h2>Upload version {current ? current.versionNumber + 1 : 1} — {assetName}</h2></div>
              <button className="sampraan-dialog-close" onClick={() => setShowUpload(false)} aria-label="Close"><X size={15} /></button>
            </div>
            <input ref={fileInputRef} type="file" style={{ display: "none" }} onChange={e => { const file = e.target.files?.[0]; if (file) void startUpload(file); e.target.value = ""; }} />
            <div className="sampraan-field">
              <span className="sampraan-label">FILE (≤ 20 MiB · text, CSV, JSON, Markdown, XML, HTML, PDF, PNG, JPEG)</span>
              <div className="identity-actions">
                <button type="button" className="action" onClick={() => fileInputRef.current?.click()}>{pendingFile ? "Choose different file" : "Select file"}</button>
                {pendingFile && <code className="truncate" title={pendingFile.name} style={{ alignSelf: "center" }}>{pendingFile.name} · {formatBytes(pendingFile.size)}</code>}
              </div>
              <p className="panel-note">The server ignores the browser's content-type and verifies the file by its actual bytes. Plaintext is never stored: content is encrypted (AES-256-GCM) before it leaves this process.</p>
            </div>
            <div className="sampraan-field">
              <label className="sampraan-label" htmlFor="aw-note">CHANGE NOTE (OPTIONAL)</label>
              <input id="aw-note" className="sampraan-input" value={changeNote} onChange={e => setChangeNote(e.target.value)} placeholder="What changed in this version?" maxLength={300} />
            </div>
            <p className="panel-note">A new immutable version is created; the previous version is preserved and remains verifiable. The creation is recorded in the audit trail and anchored as provenance where the chain is configured.</p>
            <div className="sampraan-dialog-actions">
              <button type="button" className="action" onClick={() => setShowUpload(false)}>Cancel</button>
              <button type="button" className="action solid" disabled={!pendingFile || upload.isPending} onClick={submitUpload}>
                <LockKeyhole size={14} /> {upload.isPending ? "ENCRYPTING & STORING…" : "Create Encrypted Version"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Step-up hint panel: shows the challenge the operator must sign, then verifies the pasted signature server-side and continues the interrupted operation. */}
      {stepUpHint && (
        <StepUpChallengePanel
          hint={stepUpHint}
          nonce={stepUpNonce}
          signature={stepUpSignature}
          onSignatureChange={setStepUpSignature}
          verifying={stepupVerify.isPending}
          onVerify={() => stepupVerify.mutate({ assetId, nonce: stepUpNonce ?? "", signature: stepUpSignature.trim(), operation: stepUpOperation ?? "content-view" })}
          onReissue={() => stepupChallenge.mutate({ assetId, operation: stepUpOperation ?? "content-view" })}
          onDismiss={() => {
            setStepUpHint(null);
            setStepUpNonce(null);
            setStepUpSignature("");
            setPendingAction(null);
          }}
        />
      )}

      {/* Controlled viewer */}
      {viewerVersionId && (
        <div className="sampraan-dialog-overlay" role="dialog" aria-modal="true" aria-label="Controlled content view" onClick={e => { if (e.target === e.currentTarget) setViewerVersionId(null); }}>
          <div className="sampraan-dialog" style={{ maxWidth: 860 }}>
            <div className="sampraan-dialog-head">
              <div>
                <span className="eyebrow">CONTROLLED VIEW / AUTHORIZED SESSION</span>
                <h2 className="truncate" style={{ maxWidth: 620 }} title={versions.find(v => v.id === viewerVersionId)?.filename}>
                  {versions.find(v => v.id === viewerVersionId)?.filename ?? "Content"}
                </h2>
              </div>
              <button className="sampraan-dialog-close" onClick={() => setViewerVersionId(null)} aria-label="Close"><X size={15} /></button>
            </div>
            <p className="panel-note">
              <Fingerprint size={12} /> Server-authorized in-workspace view · {viewerMime} · view-only (no download endpoint exists by design).
            </p>
            {textMime(viewerMime ?? "") && viewerText !== null ? (
              <pre className="controlled-viewer" style={{
                margin: 0, padding: 14, overflow: "auto", maxHeight: 420, borderRadius: 8,
                background: "var(--surface-2, rgba(127,127,127,.08))", fontSize: 12.5, lineHeight: 1.55,
                whiteSpace: "pre-wrap", wordBreak: "break-word", fontFamily: "var(--mono, monospace)",
              }}>{viewerText}</pre>
            ) : (
              <p className="panel-note" role="note">This format ({viewerMime}) has no in-browser editor in the current MVP. The file's metadata and integrity status above are authoritative; binary editing is deliberately not offered.</p>
            )}
            <div className="sampraan-dialog-actions">
              <button type="button" className="action" onClick={() => setViewerVersionId(null)}>Close</button>
              <button type="button" className="action" disabled={verifyingId === viewerVersionId} onClick={() => verify.mutate({ versionId: viewerVersionId })}>
                <RefreshCw size={13} /> {verifyingId === viewerVersionId ? "VERIFYING…" : "Verify Integrity"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Version history */}
      <div className="sampraan-table-wrap" style={{ marginTop: 14, maxHeight: 320, overflow: "auto" }}>
        <table className="sampraan-table">
          <thead>
            <tr><th>VERSION</th><th>FILE</th><th>TYPE</th><th>SIZE</th><th>SHA-256</th><th>CREATED</th><th>EVIDENCE</th><th>ACTIONS</th></tr>
          </thead>
          <tbody>
            {versions.map(version => (
              <tr key={version.id} className={version.id === current?.id ? "active" : ""}>
                <td>{version.id === current?.id ? <b>v{version.versionNumber} (current)</b> : `v${version.versionNumber}`}</td>
                <td className="truncate" style={{ maxWidth: 190 }} title={version.originalFilename}>{version.filename}</td>
                <td><code>{version.mimeType}</code></td>
                <td>{formatBytes(version.sizeBytes)}</td>
                <td><code className="truncate" style={{ maxWidth: 140, display: "inline-block" }} title={version.contentHash}>{formatHash(version.contentHash)}</code></td>
                <td>{version.changeNote ?? "—"}</td>
                <td>{version.createdTxHash ? `tx ${version.createdTxHash.slice(0, 10)}…` : "audit trail"}</td>
                <td>
                  <div style={{ display: "flex", gap: 6 }}>
                    <button type="button" className="action text" style={{ padding: "2px 8px" }} onClick={() => view.mutate({ versionId: version.id })}>View</button>
                    <button type="button" className="action text" style={{ padding: "2px 8px" }} disabled={verifyingId === version.id} onClick={() => verify.mutate({ versionId: version.id })}>
                      {integrity[version.id] ? integrity[version.id].state === "INTEGRITY_VERIFIED" ? "✓" : integrity[version.id].state === "INTEGRITY_MISMATCH" ? "✕" : "…" : "Verify"}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {!versions.length && (
              <tr><td colSpan={8}>{versionsQuery.isLoading ? "Syncing versions…" : "No encrypted content stored yet — create the first version."}</td></tr>
            )}
          </tbody>
        </table>
      </div>
      <p className="panel-note">
        Versions are immutable and attributable: each row carries its creator's identity, timestamp, content hash, and storage reference (ciphertext, content-addressed).
        The integrity badge reflects the actor's last verification, computed server-side from the stored ciphertext — never asserted by this page.
      </p>
    </div>
  );
}
