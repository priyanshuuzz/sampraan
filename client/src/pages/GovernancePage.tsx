/**
 * SAMPRAAN Governance & Lifecycle workspace page.
 *
 * Role-aware UI over the REAL governance router (server-side authorization):
 *   - ADMIN: multisig proposals (propose/approve/cancel/execute), mint
 *     decisions + execution, transfer approvals, dispute resolution,
 *     identity deactivation via timelock, role administration.
 *   - MANAGER: scoped onboarding (verify/assign USER role), suspend/
 *     reactivate Users in scope, mint requests, scoped transfer approvals.
 *   - AUDITOR: read-only verification, anomaly flagging, dispute raising,
 *     audit-report hash commitments.
 *   - USER (self): DID document update, consent grant/revoke, ownership
 *     presentation, key recovery request, transfer request/accept.
 *
 * Every action passes a mandatory reason; the server re-derives actor,
 * roles, scope, and lifecycle from the session — nothing here is trusted.
 */
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { useIdentities } from "@/hooks/useSampraanData";
import { toast } from "sonner";
import { ArrowRight, Landmark, ShieldCheck, Gavel, FileCheck2 } from "lucide-react";

function Eyebrow({ children }: { children: React.ReactNode }) {
  return <div className="eyebrow">{children}</div>;
}

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="decision-proof" style={{ gridTemplateColumns: "140px 1fr" }}>
      <span>{label}</span>
      <b>{value}</b>
    </div>
  );
}

function ReasonInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <input
      className="sampraan-input"
      style={{ width: "100%", margin: "6px 0" }}
      placeholder={placeholder}
      value={value}
      minLength={3}
      onChange={e => onChange(e.target.value)}
    />
  );
}

const short = (v: string | null | undefined, n = 14) => (v ? (v.length > n ? `${v.slice(0, n)}…` : v) : "—");

export function GovernancePage() {
  const { user } = useAuth();
  const { data: identities } = useIdentities();
  const me = user ? identities?.find(i => i.linkedUserId === user.id) : undefined;
  const roles = me?.roles ?? [];
  const isAdmin = user?.role === "admin" || roles.includes("ADMIN");
  const isManager = roles.includes("MANAGER");
  const isAuditor = roles.includes("AUDITOR");

  const utils = trpc.useUtils();
  const [reason, setReason] = useState("");
  const [targetDid, setTargetDid] = useState("");
  const [proposalReason, setProposalReason] = useState("");
  const [pauseReason, setPauseReason] = useState("");

  // ---- governance state ----
  const govStatus = trpc.governance.proposals.status.useQuery(undefined, { retry: false });
  const proposals = trpc.governance.proposals.list.useQuery(undefined, { retry: false });
  const mintQueue = trpc.governance.mint.list.useQuery(undefined, { retry: false, enabled: isAdmin || isManager });
  const transferQueue = trpc.governance.transfer.list.useQuery(undefined, { retry: false });
  const disputes = trpc.governance.auditor.listDisputes.useQuery(undefined, { retry: false });
  const lifecycles = trpc.governance.lifecycle.list.useQuery(undefined, { retry: false });

  const invalidateAll = () => {
    void utils.governance.proposals.list.invalidate();
    void utils.governance.proposals.status.invalidate();
    void utils.governance.mint.list.invalidate();
    void utils.governance.transfer.list.invalidate();
    void utils.governance.auditor.listDisputes.invalidate();
    void utils.governance.lifecycle.list.invalidate();
    void utils.audit.invalidate();
  };

  const onError = (what: string) => (error: { message: string }) => {
    toast.error(`${what} refused`, { description: error.message });
  };

  // ---- mutations ----
  const propose = trpc.governance.proposals.propose.useMutation({
    onSuccess: r => { toast.success(`Proposal #${r.proposalId} created`, { description: `Executable at ${new Date(r.executableAt * 1000).toLocaleTimeString()} after ${r.requiredApprovals} approval(s).` }); invalidateAll(); },
    onError: onError("Proposal"),
  });
  const approve = trpc.governance.proposals.approve.useMutation({
    onSuccess: r => { toast.success("Approval recorded", { description: `${r.approvals}/${r.requiredApprovals} quorum.` }); invalidateAll(); },
    onError: onError("Approval"),
  });
  const execute = trpc.governance.proposals.execute.useMutation({
    onSuccess: r => { toast.success("Proposal executed on-chain", { description: `tx ${short(r.transactionHash, 20)}` }); invalidateAll(); },
    onError: onError("Execution"),
  });
  const cancel = trpc.governance.proposals.cancel.useMutation({
    onSuccess: () => { toast.success("Proposal cancelled"); invalidateAll(); },
    onError: onError("Cancellation"),
  });
  const verifyUser = trpc.governance.lifecycle.verify.useMutation({
    onSuccess: () => { toast.success("Identity verified (USER scope)"); invalidateAll(); },
    onError: onError("Verification"),
  });
  const suspendUser = trpc.governance.lifecycle.suspend.useMutation({
    onSuccess: () => { toast.success("Identity suspended"); invalidateAll(); },
    onError: onError("Suspension"),
  });
  const reactivateUser = trpc.governance.lifecycle.reactivate.useMutation({
    onSuccess: () => { toast.success("Identity reactivated"); invalidateAll(); },
    onError: onError("Reactivation"),
  });
  const decideMint = trpc.governance.mint.decide.useMutation({
    onSuccess: r => { toast.success(`Mint request ${r.request?.status?.toLowerCase() ?? "decided"}`); invalidateAll(); },
    onError: onError("Mint decision"),
  });
  const executeMint = trpc.governance.mint.execute.useMutation({
    onSuccess: r => { toast.success("NFT minted + assigned", { description: `token ${short(r.tokenId, 18)} · tx ${short(r.transactionHash ?? "idempotent", 18)}` }); invalidateAll(); },
    onError: onError("Mint execution"),
  });
  const approveTransfer = trpc.governance.transfer.approve.useMutation({
    onSuccess: r => { toast.success(`Transfer ${r.request?.status?.toLowerCase() ?? "decided"}`); invalidateAll(); },
    onError: onError("Transfer decision"),
  });
  const executeTransfer = trpc.governance.transfer.execute.useMutation({
    onSuccess: r => { toast.success("Custody transferred on-chain", { description: `tx ${short(r.transactionHash, 20)}` }); invalidateAll(); },
    onError: onError("Transfer execution"),
  });
  const resolveDispute = trpc.governance.auditor.resolveDispute.useMutation({
    onSuccess: () => { toast.success("Dispute resolved on-chain"); invalidateAll(); },
    onError: onError("Dispute resolution"),
  });
  const requestDeactivation = trpc.governance.lifecycle.requestDeactivation.useMutation({
    onSuccess: r => { toast.success("Deactivation queued through governance", { description: `Proposal #${r.proposalId} (quorum + timelock).` }); invalidateAll(); },
    onError: onError("Deactivation"),
  });

  const reasonOk = reason.trim().length >= 3;

  return (
    <div className="special-page">
      <div className="special-heading">
        <div>
          <Eyebrow>GOVERNANCE / MULTISIG + TIMELOCK</Eyebrow>
          <h1>Governance &amp; Lifecycle</h1>
          <p>Quorum-gated high-risk operations, scoped lifecycle management, and auditor evidence — authorization is resolved server-side on every action.</p>
        </div>
        <span className="status status-mint"><i />
          {govStatus.data
            ? `${govStatus.data.signerCount}-OF-${govStatus.data.signerCount} SIGNERS · QUORUM ${govStatus.data.quorumRequired} · TIMELOCK ${govStatus.data.timelockDelaySeconds}s`
            : "GOVERNANCE SYNCING…"}
        </span>
      </div>

      {/* ---------------- ADMIN: multisig proposals ---------------- */}
      {isAdmin && (
        <div className="evidence-block" style={{ marginTop: 16 }}>
          <h4><Landmark size={14} /> MULTISIG PROPOSALS (burn · force transfer · pause · roles · deactivation)</h4>
          <div className="decision-proof" style={{ gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div>
              <ReasonInput value={pauseReason} onChange={setPauseReason} placeholder="Reason for the emergency pause (min 3 chars)" />
              <button
                className="action ghost"
                disabled={pauseReason.trim().length < 3 || propose.isPending}
                onClick={() => propose.mutate({ kind: "PAUSE_REGISTRY", reason: pauseReason })}
              >
                Propose PAUSE
              </button>
              <button
                className="action ghost"
                style={{ marginLeft: 8 }}
                disabled={pauseReason.trim().length < 3 || propose.isPending}
                onClick={() => propose.mutate({ kind: "UNPAUSE_REGISTRY", reason: pauseReason })}
              >
                Propose UNPAUSE
              </button>
            </div>
            <div>
              <ReasonInput value={proposalReason} onChange={setProposalReason} placeholder="Reason for a deactivation proposal" />
              <input
                className="sampraan-input"
                style={{ width: "100%", marginBottom: 6 }}
                placeholder="Target DID (did:sampraan:…)"
                value={targetDid}
                onChange={e => setTargetDid(e.target.value)}
              />
              <button
                className="action ghost"
                disabled={!targetDid || proposalReason.trim().length < 3 || propose.isPending}
                onClick={() => requestDeactivation.mutate({ did: targetDid, reason: proposalReason })}
              >
                Propose DEACTIVATE (timelocked)
              </button>
            </div>
          </div>
          <div className="decision-list" style={{ marginTop: 10 }}>
            {(proposals.data ?? []).map(p => (
              <div className="decision-card tone-muted" key={p.proposalId}>
                <div className="decision-card-head">
                  <span className="who"><b>#{p.proposalId} · kind {p.kind}</b><code>{short(p.reason, 40)}</code></span>
                  <span className={`status ${p.executed ? "status-mint" : p.cancelled ? "status-red" : "status-amber"}`}><i />{p.executed ? "EXECUTED" : p.cancelled ? "CANCELLED" : `${p.approvals}/${p.requiredApprovals} APPROVALS`}</span>
                </div>
                <div className="decision-card-grid">
                  <span>ACCOUNT</span><b>{short(p.account, 18)}</b>
                  <span>EXECUTABLE AT</span><b>{p.executed ? "—" : new Date(p.executableAt * 1000).toLocaleTimeString()}</b>
                </div>
                {!p.executed && !p.cancelled && (
                  <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
                    <button className="action ghost" disabled={approve.isPending} onClick={() => approve.mutate({ proposalId: String(p.proposalId), reason: reasonOk ? reason : "approve" })}>
                      Approve (2nd signer)
                    </button>
                    <button className="action solid" disabled={execute.isPending} onClick={() => execute.mutate({ proposalId: String(p.proposalId) })}>
                      Execute <ArrowRight size={13} />
                    </button>
                    <button className="action ghost" disabled={cancel.isPending} onClick={() => cancel.mutate({ proposalId: String(p.proposalId), reason: reasonOk ? reason : "cancelled by admin" })}>
                      Cancel
                    </button>
                  </div>
                )}
              </div>
            ))}
            {proposals.data && proposals.data.length === 0 && <p className="panel-note">No governance proposals yet.</p>}
          </div>
        </div>
      )}

      {/* ---------------- MANAGER/ADMIN: lifecycle + mint + transfers ---------------- */}
      {(isAdmin || isManager) && (
        <div className="evidence-block" style={{ marginTop: 16 }}>
          <h4><ShieldCheck size={14} /> IDENTITY LIFECYCLE {isManager && !isAdmin && "(OWN SCOPE · USERS ONLY)"}</h4>
          <ReasonInput value={reason} onChange={setReason} placeholder="Reason (mandatory, recorded in the audit log)" />
          <div className="decision-list">
            {(lifecycles.data ?? []).slice(0, 12).map(identity => (
              <div className="decision-card tone-muted" key={identity.id}>
                <div className="decision-card-head">
                  <span className="who"><b>{identity.displayName}</b><code>{short(identity.did, 22)}</code></span>
                  <span className={`status ${identity.lifecycleState === "VERIFIED" ? "status-mint" : identity.lifecycleState === "PENDING" ? "status-amber" : "status-red"}`}><i />{identity.lifecycleState}</span>
                </div>
                <InfoRow label="ROLES" value={(identity as unknown as { roles?: string[] }).roles?.join(" + ") || "—"} />
                <div style={{ marginTop: 8, display: "flex", gap: 8, flexWrap: "wrap" }}>
                  {identity.lifecycleState === "PENDING" && (
                    <button className="action ghost" disabled={!reasonOk || verifyUser.isPending} onClick={() => verifyUser.mutate({ did: identity.did, reason })}>Verify</button>
                  )}
                  {identity.lifecycleState === "VERIFIED" && (
                    <button className="action ghost" disabled={!reasonOk || suspendUser.isPending} onClick={() => suspendUser.mutate({ did: identity.did, reason })}>Suspend</button>
                  )}
                  {identity.lifecycleState === "SUSPENDED" && (
                    <button className="action ghost" disabled={!reasonOk || reactivateUser.isPending} onClick={() => reactivateUser.mutate({ did: identity.did, reason })}>Reactivate</button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {(isAdmin || isManager) && (
        <div className="evidence-block" style={{ marginTop: 16 }}>
          <h4><FileCheck2 size={14} /> MAKER-CHECKER MINT QUEUE {isAdmin ? "(ADMIN DECIDES + EXECUTES)" : "(YOUR REQUESTS)"}</h4>
          <div className="decision-list">
            {(mintQueue.data ?? []).slice(0, 10).map(r => (
              <div className="decision-card tone-muted" key={r.id}>
                <div className="decision-card-head">
                  <span className="who"><b>{r.name}</b><code>{r.assetId}</code></span>
                  <span className={`status ${r.status === "PENDING" ? "status-amber" : r.status === "EXECUTED" ? "status-mint" : r.status === "REJECTED" ? "status-red" : "status-amber"}`}><i />{r.status}</span>
                </div>
                {isAdmin && r.status === "PENDING" && (
                  <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
                    <button className="action solid" disabled={!reasonOk} onClick={() => decideMint.mutate({ requestId: r.id, decision: "APPROVED", reason })}>Approve</button>
                    <button className="action ghost" disabled={!reasonOk} onClick={() => decideMint.mutate({ requestId: r.id, decision: "REJECTED", reason })}>Reject</button>
                  </div>
                )}
                {isAdmin && r.status === "APPROVED" && (
                  <button className="action solid" style={{ marginTop: 8 }} onClick={() => executeMint.mutate({ requestId: r.id })}>Execute mint on-chain</button>
                )}
              </div>
            ))}
            {mintQueue.data && mintQueue.data.length === 0 && <p className="panel-note">No mint requests.</p>}
          </div>
        </div>
      )}

      {/* ---------------- transfer approvals (manager scoped / admin) ---------------- */}
      {(isAdmin || isManager) && (
        <div className="evidence-block" style={{ marginTop: 16 }}>
          <h4><Gavel size={14} /> CONTROLLED TRANSFERS {isManager && !isAdmin ? "(IN-SCOPE SENDERS)" : "(GLOBAL)"}</h4>
          <div className="decision-list">
            {(transferQueue.data ?? []).slice(0, 10).map(r => (
              <div className="decision-card tone-muted" key={r.id}>
                <div className="decision-card-head">
                  <span className="who"><b>Transfer request</b><code>{short(r.id, 16)}</code></span>
                  <span className={`status ${r.status === "ACCEPTED" ? "status-amber" : r.status === "EXECUTED" ? "status-mint" : "status-amber"}`}><i />{r.status}</span>
                </div>
                {(r.status === "ACCEPTED") && (
                  <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
                    <button className="action solid" disabled={!reasonOk} onClick={() => approveTransfer.mutate({ requestId: r.id, decision: "APPROVED", reason })}>Approve</button>
                    <button className="action ghost" disabled={!reasonOk} onClick={() => approveTransfer.mutate({ requestId: r.id, decision: "REJECTED", reason })}>Reject</button>
                  </div>
                )}
                {r.status === "APPROVED" && (
                  <button className="action solid" style={{ marginTop: 8 }} onClick={() => executeTransfer.mutate({ requestId: r.id })}>Execute transfer on-chain</button>
                )}
              </div>
            ))}
            {transferQueue.data && transferQueue.data.length === 0 && <p className="panel-note">No transfer requests visible in your scope.</p>}
          </div>
        </div>
      )}

      {/* ---------------- ADMIN: dispute resolution ---------------- */}
      {isAdmin && (
        <div className="evidence-block" style={{ marginTop: 16 }}>
          <h4><Gavel size={14} /> DISPUTE RESOLUTION (ADMIN-ONLY; AUDITORS CANNOT RESOLVE)</h4>
          <div className="decision-list">
            {(disputes.data ?? []).filter(d => d.status === "OPEN").slice(0, 10).map(d => (
              <div className="decision-card tone-muted" key={d.id}>
                <div className="decision-card-head">
                  <span className="who"><b>Dispute</b><code>{short(d.reason, 40)}</code></span>
                  <span className="status status-amber"><i />OPEN</span>
                </div>
                <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
                  <button className="action solid" disabled={!reasonOk} onClick={() => resolveDispute.mutate({ disputeId: d.id, uphold: true, reason })}>Uphold (holds asset)</button>
                  <button className="action ghost" disabled={!reasonOk} onClick={() => resolveDispute.mutate({ disputeId: d.id, uphold: false, reason })}>Reject (release hold)</button>
                </div>
              </div>
            ))}
            {disputes.data && disputes.data.filter(d => d.status === "OPEN").length === 0 && <p className="panel-note">No open disputes.</p>}
          </div>
        </div>
      )}

      {!isAdmin && !isManager && !isAuditor && (
        <p className="panel-note" style={{ marginTop: 16 }}>
          Your role sees self-service surfaces (consent, DID document, ownership presentation, key recovery, transfer requests) in the Identity and Asset workspaces.
        </p>
      )}
    </div>
  );
}
