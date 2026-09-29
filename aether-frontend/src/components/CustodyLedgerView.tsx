"use client";

import React, { useEffect, useRef, useState } from "react";
import type { ToastSeverity } from "@/components/Toast";
import {
  appendCustodyEntry,
  CustodyEntryItem,
  downloadForensicCsv,
  downloadStatutoryCertificate,
  downloadStixBundle,
  fetchCaseCustody,
  fetchWhoAmI,
  verifyCustodyLedger,
  VerifyResult,
} from "@/lib/api";

interface CustodyLedgerViewProps {
  evidenceId?: string;
  onShowToast: (title: string, message: string, severity?: ToastSeverity) => void;
}

export const CustodyLedgerView: React.FC<CustodyLedgerViewProps> = ({
  evidenceId = "AT-2026-0047",
  onShowToast,
}) => {
  const [entries, setEntries] = useState<CustodyEntryItem[]>([]);
  const [verification, setVerification] = useState<VerifyResult | null>(null);
  const [verifying, setVerifying] = useState<boolean>(false);
  const [submitting, setSubmitting] = useState<boolean>(false);

  // New entry form state. `actorName` is EMPTY by default.
  //
  // It was pre-filled with "CERT-In Digital Forensics", an organisation, while
  // the header showed the authenticated role as `investigator` and the rail
  // showed a different monogram. A chain-of-custody block has to name the party
  // answerable for the action, so defaulting it to a lab name writes a record
  // that attributes the evidence to no identifiable person — and the field is
  // freely editable, so the default was what nearly every block would say.
  const [actorName, setActorName] = useState<string>("");
  const [actionDesc, setActionDesc] = useState<string>("");

  // The empty state focuses this, so the analyst lands in the field that starts
  // the chain rather than being told to scroll.
  const actionRef = useRef<HTMLTextAreaElement | null>(null);

  // The signed-in role, shown next to the actor field so the analyst can match
  // the two rather than guessing which identity belongs in the record.
  const [authRole, setAuthRole] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    fetchWhoAmI()
      .then((who) => {
        if (!cancelled && who) setAuthRole(who.role);
      })
      .catch(() => {
        /* The role is a hint, not a gate; its absence must not block the form. */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  /*
   * `loading` is derived rather than set. The effect previously called
   * `loadData(evidenceId)`, whose first statement was a synchronous
   * `setLoading(true)` -- a setState in the effect body, which cascades an
   * extra render on every case switch. Tracking which id has landed makes the
   * same state without writing to it during the effect.
   */
  const [loadedId, setLoadedId] = useState<string | null>(null);
  const loading = loadedId !== evidenceId;
  const [issuingCertificate, setIssuingCertificate] = useState(false);

  /*
   * Downloads the server-generated statutory certificate.
   *
   * This button previously called `window.print()`, which in a single-page
   * application prints the console itself. The artefact it produced was a
   * screenshot of the interface presented as a court document.
   */
  const handleCertificateDownload = async () => {
    setIssuingCertificate(true);
    try {
      const result = await downloadStatutoryCertificate(evidenceId);
      if (result.ok) {
        onShowToast(
          "Statutory certificate issued",
          `${result.filename} generated server-side from the case record and custody chain.`
        );
      } else if (result.status === 409) {
        onShowToast(
          "Release not affirmed",
          "An investigator must affirm release before a court document can be issued.",
          "warning"
        );
      } else if (result.status === 403) {
        onShowToast(
          "Not permitted",
          "Your role cannot issue a court document for this case.",
          "warning"
        );
      } else {
        onShowToast("Certificate not issued", result.detail, "critical");
      }
    } finally {
      setIssuingCertificate(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [{ entries: list }, { data: verifyData }] = await Promise.all([
          fetchCaseCustody(evidenceId),
          verifyCustodyLedger(evidenceId),
        ]);
        if (cancelled) return;
        setEntries(list);
        setVerification(verifyData);
      } catch {
        if (cancelled) return;
        /*
         * This used to say "Loaded local cryptographic custody buffer for
         * AT-2026-0047" from the catch block. The browser bundle holds no
         * custody buffer, so a backend that was down produced a message
         * asserting a chain had been loaded. An unreachable ledger is
         * unverified, and the analyst needs to be told that.
         */
        onShowToast(
          "Custody ledger unavailable",
          `Could not load the ledger for ${evidenceId}. Nothing is displayed because no chain was retrieved — open /verify.html with an exported ledger to verify it offline.`,
          "critical"
        );
      } finally {
        if (!cancelled) setLoadedId(evidenceId);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [evidenceId, onShowToast, setLoadedId]);

  const handleVerify = async () => {
    setVerifying(true);
    try {
      const { data, isLive } = await verifyCustodyLedger(evidenceId);
      setVerification(data);
      if (data.valid) {
        // `isLive` is no longer used in the title. It said "Cryptographic Chain
        // Intact" for a client-side fallback and "Custody Seal Valid" for a
        // server check, which implied the two were different strengths of
        // evidence. They are not: both are the same check, and where it ran
        // does not change whether the answer is true. It stays in the payload.
        void isLive;
        onShowToast(
          "The log checks out",
          `All ${data.entry_count} steps match. Nothing in the log has been changed. Fingerprint ${data.seal.substring(
            0,
            16
          )}...`,
          "success"
        );
      } else {
        onShowToast(
          "Someone changed the log",
          `The log stops matching at step #${data.broken_at_seq}. Something in it was changed.`,
          "critical"
        );
      }
    } catch {
      // The catch used to announce "Chain verified against local cryptographic
      // root." A failed request is the opposite of a verification, and there is
      // no local cryptographic root in the browser bundle to verify against.
      onShowToast(
        "Could not check the log",
        "The verification request failed, so the chain's integrity is unknown. Treat it as unverified until this succeeds.",
        "critical"
      );
    } finally {
      setVerifying(false);
    }
  };

  const handleAppend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!actionDesc.trim()) {
      onShowToast("Input Required", "Please specify the forensic action executed.");
      return;
    }

    setSubmitting(true);
    try {
      const { entry, isLive } = await appendCustodyEntry(
        evidenceId,
        actorName.trim(),
        actionDesc.trim()
      );
      if (entry) {
        setEntries((prev) => [...prev, entry]);
      }
      setActionDesc("");
      // Same reasoning as the verify handler: where the write went does not
      // change whether the step was recorded.
      void isLive;
      onShowToast(
        "Step added",
        `Added as step number ${entry?.seq ?? "N/A"} and the log was re-signed.`,
        "success"
      );
      // Re-verify
      handleVerify();
    } catch {
      // Previously "Appended record to audit ledger", on a code path that only
      // runs when the append request threw. An append that failed cannot have
      // been recorded, and on an append-only ledger a custody record that does
      // not exist is indistinguishable from one that was never made.
      onShowToast(
        "Step not added",
        "The ledger rejected the write, so no custody block was created. The action you described has NOT been recorded.",
        "critical"
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex flex-col gap-6 w-full">
      {/* Header Bar */}
      <div className="matte-card p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              {/*
                The "STAGE 03" badge that sat here was a step counter, not
                information: it implied a sequence the analyst never sees and
                the heading already names the thing. Removed in favour of the
                actual state, which does carry meaning.
              */}
              <h2 className="text-xl font-bold text-ink tracking-tight">
                Evidence Log
              </h2>
          </div>
          <p className="text-xs text-ink-muted mt-1">
            Section 63, Bharatiya Sakshya Adhiniyam, 2023 (formerly s.65B, Indian Evidence Act, 1872) compliant cryptographic audit ledger. Every action is
            SHA-256 linked.
          </p>
        </div>

        {/* Verification Status & Button */}
        <div className="flex items-center gap-3">
          <div className="text-right hidden md:block">
            <span className="text-[10px] text-ink-muted uppercase font-mono block">Status</span>
            <span className="text-xs font-mono font-bold text-signal-ink flex items-center gap-1.5">
              <i className="fa-solid fa-circle-check text-[11px]"></i>
              {verification?.valid ? "LOG CHECKS OUT" : "CHECKING THE LOG..."}
            </span>
          </div>

          <button
            onClick={handleVerify}
            disabled={verifying}
            className="px-4 py-2.5 min-h-11 bg-active hover:bg-info-hover text-white text-xs font-bold font-mono transition border border-line-active flex items-center gap-2"
          >
            {verifying ? (
              <span className="inline-block w-3.5 h-3.5 border-2 border-white border-t-transparent animate-spin"></span>
            ) : (
              <i className="fa-solid fa-shield-halved text-xs"></i>
            )}
            Check the log
          </button>
        </div>
      </div>

      {/* Seal Banner */}
      {verification && (
        <div className="bg-card border border-line p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 bg-info-surface border border-line-strong text-signal-ink flex items-center justify-center text-sm">
              <i className="fa-solid fa-lock"></i>
            </div>
            <div>
              <span className="text-ink-muted uppercase text-[10px]">Ledger Cryptographic Seal</span>
              <p className="text-white font-bold break-all text-[11px] mt-0.5">{verification.seal}</p>
            </div>
          </div>
          {/* "7 Verified Blocks" (the engine's count) and "Total Blocks: 4"
              (the rows actually rendered) used to sit forty pixels apart with no
              reconciliation, on the one screen where the numbers have to agree.
              A verifier's first question is whether the ledger is complete, so
              a mismatch is now stated rather than left to be noticed. */}
          {verification.entry_count !== entries.length ? (
            <span
              className="px-2.5 py-1 bg-warn-surface text-warn-ink border border-warn-line text-[11px] font-bold self-end md:self-center"
              title={`The engine reports ${verification.entry_count} blocks but ${entries.length} were retrieved for display. The chain may be truncated, or the ledger may have advanced since verification.`}
            >
              Count mismatch: {verification.entry_count} verified /{" "}
              {entries.length} loaded
              <span className="sr-only">
                {" "}
                — the number of blocks the engine verified does not match the
                number of rows retrieved
              </span>
            </span>
          ) : (
            <span className="px-2.5 py-1 bg-info-raised text-info-ink border border-info-line-soft text-[11px] font-bold self-end md:self-center">
              {verification.entry_count} Verified Blocks
            </span>
          )}
        </div>
      )}

      {/* ------------------------------------------------------------------
          The chain, drawn as a chain.

          Every ledger's value is that it is append-only and that each block is
          bound to the one above it. The table below shows that as a column of
          unrelated rows, so the property the product is selling is invisible,
          and a tamper surfaces only as a transient toast. Here each block is a
          node on a vertical line with its own hash as the link label, and the
          link is drawn broken from the first block the engine could not verify.

          This is the same data already on screen, arranged to show what it
          means. The renderer is a pure function of the entries so the drawing
          cannot disagree with the table beneath it.
          ------------------------------------------------------------------ */}
      {entries.length > 0 && (
        <div className="matte-card p-5">
          <div className="flex justify-between items-center pb-3 border-b border-line">
            <h3 className="text-[16px] font-bold text-ink font-mono">
              Is the log still intact?
            </h3>
            <span className="text-[10px] text-ink-muted font-mono">
              each block is bound to the hash above it
            </span>
          </div>

          <ol className="mt-4 space-y-0">
            {entries.map((entry, i) => {
              const isGenesis = i === 0;
              const brokenAt =
                verification && !verification.valid
                  ? verification.broken_at_seq
                  : null;
              // The link INTO this block is broken if this is the first block
              // the engine flagged, or any block after it.
              const linkBroken =
                brokenAt !== null && !isGenesis && entry.seq >= brokenAt;
              const last = i === entries.length - 1;

              return (
                <li key={entry.seq} className="flex gap-3">
                  {/* The connector between this block and the one above. */}
                  {!isGenesis && (
                    <span
                      aria-hidden="true"
                      className={`w-px shrink-0 self-stretch ${
                        linkBroken ? "bg-alert" : "bg-line-strong"
                      }`}
                      style={{ minHeight: 22 }}
                    >
                      {linkBroken && (
                        /* A gap in the line: a link that does not hold. */
                        <span className="block w-px h-2 bg-canvas" />
                      )}
                    </span>
                  )}
                  <div className="flex-1 min-w-0 pb-3">
                    <div className="flex items-baseline gap-2 flex-wrap">
                      <span
                        className={`text-[10px] font-mono font-bold px-1.5 py-0.5 border ${
                          linkBroken
                            ? "bg-alert-surface text-alert-ink border-alert-line"
                            : "bg-signal-surface text-signal-ink border-signal-line"
                        }`}
                      >
                        {isGenesis ? "GENESIS" : `#${entry.seq}`}
                      </span>
                      <span className="text-[12px] text-ink truncate">
                        {entry.action}
                      </span>
                    </div>
                    <div className="flex items-baseline gap-2 mt-0.5 flex-wrap">
                      <span className="text-[10px] text-ink-faint font-mono">
                        {entry.timestamp}
                      </span>
                      <span className="text-[10px] text-ink-dim">
                        {entry.actor}
                      </span>
                    </div>
                    {entry.entry_hash && (
                      <span className="block text-[10px] text-ink-muted font-mono break-all mt-0.5">
                        {entry.entry_hash}
                      </span>
                    )}
                  </div>
                  {/* The whole hash, not the 16-character cut used in the
                      table. This is the artefact a third party re-derives, so
                      truncating it here defeats the purpose of the view. */}
                  {entry.entry_hash && (
                    <button
                      type="button"
                      onClick={() => {
                        navigator.clipboard.writeText(entry.entry_hash!);
                        onShowToast(
                          "Hash Copied",
                          `Full ${entry.entry_hash!.length}-character SHA-256 for block #${entry.seq} is on the clipboard.`,
                          "info"
                        );
                      }}
                      className="shrink-0 self-start px-2 py-1 min-h-11 text-[10px] font-mono text-ink-muted hover:text-ink border border-line hover:border-line-strong transition"
                    >
                      copy hash
                    </button>
                  )}
                  {last && !linkBroken && (
                    <span aria-hidden="true" className="w-3 shrink-0" />
                  )}
                </li>
              );
            })}
          </ol>

          <p
            className={`text-[10px] font-mono mt-3 pt-3 border-t border-line ${
              verification
                ? verification.valid
                  ? "text-signal-ink"
                  : "text-alert-ink"
                : "text-ink-faint"
            }`}
          >
            {verification
              ? verification.valid
                ? `All ${verification.entry_count} steps check out. Nothing has been changed.`
                : `The log stops matching at step #${verification.broken_at_seq}. Everything after it was changed, or the record is wrong.`
              : "This log has not been checked yet. Do not rely on the log above until it is checked."}
          </p>
        </div>
      )}

      {/* Main Ledger Table Card */}
      <div className="matte-card p-5">
        <div className="flex justify-between items-center pb-3 border-b border-line">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
            Every step, in order ({evidenceId})
          </h3>
          <span className="text-xs text-ink-muted font-mono">
            Total Blocks: {entries.length}
          </span>
        </div>

        <div className="overflow-x-auto mt-3">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="border-b border-line text-ink-muted text-[10px] uppercase">
                <th className="py-2.5 px-3">#</th>
                <th className="py-2.5 px-3">Timestamp (UTC)</th>
                <th className="py-2.5 px-3">Investigator / Engine</th>
                <th className="py-2.5 px-3">Forensic Action Taken</th>
                <th className="py-2.5 px-3">Block SHA-256 Hash</th>
                <th className="py-2.5 px-3 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#161d28]">
              {loading ? (
                <tr>
                  <td colSpan={6} className="text-center py-8 text-ink-muted">
                    Loading cryptographic ledger from database...
                  </td>
                </tr>
              ) : entries.length === 0 ? (
                /* The empty state used to be one centred row reading "No
                   custody entries recorded yet." — no control, no guidance.
                   This is the analyst's primary record and it opened on a shrug,
                   while the append form sat immediately below with nothing
                   pointing at it. It now explains what the chain is for and
                   takes the analyst straight to the field that starts it. */
                <tr>
                  <td colSpan={6} className="py-8 px-4 text-center">
                    <p className="text-[13px] text-ink font-semibold">
                      This case has no custody chain yet.
                    </p>
                    <p className="text-[12px] text-ink-muted mt-1.5 max-w-[54ch] mx-auto leading-relaxed">
                      Nothing has been recorded against{" "}
                      <span className="font-mono text-ink-dim">{evidenceId}</span>
                      , so there is no handling history to present. The chain
                      begins with the first action recorded below as a genesis
                      block; every entry after it is bound to the hash above it,
                      which is what makes the record verifiable by a third party.
                    </p>
                    <button
                      type="button"
                      onClick={() => {
                        actionRef.current?.scrollIntoView({
                          behavior: "smooth",
                          block: "center",
                        });
                        actionRef.current?.focus();
                      }}
                      className="mt-3 px-4 py-2 min-h-11 bg-surface hover:bg-raised text-ink border border-line-strong text-[12px] font-semibold font-mono transition"
                    >
                      Record the first custody action
                    </button>
                  </td>
                </tr>
              ) : (
                entries.map((entry) => (
                  <tr key={entry.seq} className="hover:bg-surface transition">
                    <td className="py-3 px-3 font-bold text-ink">{entry.seq}</td>
                    <td className="py-3 px-3 text-ink-muted text-[11px] whitespace-nowrap">
                      {entry.timestamp}
                    </td>
                    <td className="py-3 px-3 text-white font-semibold">{entry.actor}</td>
                    <td className="py-3 px-3 text-ink font-sans text-xs">
                      {entry.action}
                    </td>
                    <td className="py-3 px-3 text-ink-muted text-[10px] break-all max-w-[200px]">
                      {/* Truncated for the table's column width, but now
                          focusable and labelled with the full value: a
                          keyboard or screen-reader user must not be the only
                          route to the complete hash. The chain view above
                          renders it in full with a copy control. */}
                      {entry.entry_hash ? (
                        <span
                          tabIndex={0}
                          title={entry.entry_hash}
                          aria-label={`Full SHA-256 for block ${entry.seq}: ${entry.entry_hash}`}
                          className="cursor-help"
                        >
                          {entry.entry_hash.substring(0, 16)}…
                        </span>
                      ) : (
                        "GENESIS"
                      )}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <span className="px-2 py-0.5 text-[10px] font-bold bg-signal-surface text-signal-ink border border-signal-line-soft">
                        SEALED
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Append New Custody Entry Form & Export Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Form (2 Columns) */}
        <div className="lg:col-span-2 matte-card p-5">
          <div className="flex justify-between items-center pb-3 border-b border-line">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Add a step to the log
            </h3>
            <span className="text-[10px] text-ink-muted font-mono">Each step is fingerprinted</span>
          </div>

          <form onSubmit={handleAppend} className="mt-4 space-y-4 text-xs font-mono">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* Every control here had a <label> as a SIBLING with no htmlFor
                  and no id on the input, so none of them had an accessible
                  name. An analyst using a screen reader heard "edit, blank" for
                  the field that decides who is accountable for the evidence. */}
              <div>
                <label
                  htmlFor="custody-actor"
                  className="text-ink-muted block mb-1 uppercase text-[10px]"
                >
                  Actor / Investigator Identity
                </label>
                <input
                  id="custody-actor"
                  type="text"
                  value={actorName}
                  onChange={(e) => setActorName(e.target.value)}
                  className="w-full bg-input border border-line-strong p-2.5 text-ink min-h-11"
                  placeholder="e.g. Lead Examiner (CERT-In)"
                  aria-describedby="custody-actor-note"
                />
                {/* The field defaults to an organisation ("CERT-In Digital
                    Forensics") while the header shows the authenticated role as
                    `investigator` and the rail shows a different monogram. A
                    custody record must name a person, so the mismatch is
                    surfaced rather than assumed. */}
                <p id="custody-actor-note" className="text-[10px] text-ink-faint mt-1 leading-relaxed">
                  Recorded verbatim in the block. This is the identity a verifier
                  will hold responsible for the action, so it should match the
                  signed-in officer
                  {authRole ? ` (signed in as ${authRole})` : ""} rather than an
                  organisation.
                </p>
              </div>

              <div>
                <label
                  htmlFor="custody-case"
                  className="text-ink-muted block mb-1 uppercase text-[10px]"
                >
                  Case Identifier
                </label>
                <input
                  id="custody-case"
                  type="text"
                  disabled
                  value={`${evidenceId} (Project AETHER)`}
                  className="w-full bg-surface border border-line p-2.5 text-ink-muted cursor-not-allowed min-h-11"
                />
              </div>
            </div>

            <div>
              <label
                htmlFor="custody-action"
                className="text-ink-muted block mb-1 uppercase text-[10px]"
              >
                Forensic Action &amp; Evidentiary Findings
              </label>
              <textarea
                id="custody-action"
                ref={actionRef}
                rows={3}
                value={actionDesc}
                onChange={(e) => setActionDesc(e.target.value)}
                placeholder="e.g. Correlated Dread forum Bitcoin transaction to suspect VASP deposit cluster..."
                className="w-full bg-input border border-line-strong p-2.5 text-ink resize-none font-sans"
              />
              {/* Appending to an append-only ledger is irreversible, and this is
                  the one irreversible action in the interface with no
                  confirmation. It is not a modal — a dialog for a text field
                  the analyst has just filled is worse than an explicit,
                  informed commit control directly beside the field. */}
              <p className="text-[10px] text-ink-faint mt-1.5 leading-relaxed">
                Appending is <strong className="text-warn-ink">permanent</strong>.
                A block cannot be edited or removed; a correction is a new block
                that refers to this one.
              </p>
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="px-5 py-2.5 min-h-11 bg-active hover:bg-info-hover text-white font-bold transition border border-line-active flex items-center gap-2"
            >
              {submitting ? (
                <span className="inline-block w-3.5 h-3.5 border-2 border-white border-t-transparent animate-spin"></span>
              ) : (
                <i className="fa-solid fa-link text-xs" aria-hidden="true"></i>
              )}
              Append &amp; Recompute SHA-256 Seal
            </button>
          </form>
        </div>

          {/* Export & court submission (1 Column) */}
        <div className="matte-card p-5 flex flex-col justify-between">
          <div>
            <div className="flex justify-between items-center pb-3 border-b border-line">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                For court
              </h3>
              <span className="text-[10px] text-ink-muted font-mono">Export</span>
            </div>

            <p className="text-xs text-ink-muted mt-3 leading-relaxed">
              Export the complete tamper-evident chain of custody and attribution findings for
              submission under Section 63, Bharatiya Sakshya Adhiniyam, 2023 (formerly s.65B, Indian Evidence Act, 1872).
            </p>

            <div className="mt-4 space-y-2.5">
              <button
                onClick={() => downloadStixBundle(evidenceId)}
                className="w-full py-2.5 bg-info-surface hover:bg-raised text-ink border border-line-strong text-xs font-mono font-semibold transition flex items-center justify-center gap-2"
              >
                <i className="fa-solid fa-file-code text-xs"></i> Download STIX 2.1 JSON
              </button>

              <button
                onClick={() => downloadForensicCsv(evidenceId)}
                className="w-full py-2.5 bg-info-surface hover:bg-raised text-ink border border-line-strong text-xs font-mono font-semibold transition flex items-center justify-center gap-2"
              >
                <i className="fa-solid fa-file-csv text-xs"></i> Download Forensic CSV
              </button>

              <button
                type="button"
                onClick={handleCertificateDownload}
                disabled={issuingCertificate}
                className="w-full py-2.5 min-h-11 bg-active hover:bg-info-hover text-ink border border-line-active text-xs font-mono font-bold transition flex items-center justify-center gap-2 disabled:opacity-60"
              >
                <i className="fa-solid fa-file-pdf text-xs" aria-hidden="true"></i>
                {issuingCertificate ? "Issuing…" : "Issue Court Certificate"}
              </button>
            </div>
          </div>

          {/* This line was a static "Chain seal verified against SQLite store."
              in the court panel — printed unconditionally, outside
              any state check, on the panel that tells a court this export is
              fit to file. It asserted a verification that might never have run,
              against a storage backend this product does not use.

              It now reports the actual state, including the states that were
              previously invisible: not yet checked, and checked-but-failed. */}
          <div
            className={`mt-4 pt-3 border-t border-line text-[10px] font-mono ${
              !verification
                ? "text-ink-faint"
                : verification.valid
                  ? "text-signal-ink"
                  : "text-alert-ink"
            }`}
          >
            {!verification
              ? "This log has not been checked yet. Verify before relying on any export below."
              : verification.valid
                ? `All ${verification.entry_count} steps check out. The log has not been changed. Fingerprint ${verification.seal.slice(0, 16)}…`
                : `The log stops matching at step #${verification.broken_at_seq}. Do not rely on the exports below.`}
          </div>
        </div>
      </div>
    </div>
  );
};
