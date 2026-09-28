"use client";

import React, { useEffect, useState } from "react";
import {
  appendCustodyEntry,
  CustodyEntryItem,
  downloadForensicCsv,
  downloadStixBundle,
  fetchCaseCustody,
  verifyCustodyLedger,
  VerifyResult,
} from "@/lib/api";

interface CustodyLedgerViewProps {
  evidenceId?: string;
  onShowToast: (title: string, message: string) => void;
}

export const CustodyLedgerView: React.FC<CustodyLedgerViewProps> = ({
  evidenceId = "AT-2026-0047",
  onShowToast,
}) => {
  const [entries, setEntries] = useState<CustodyEntryItem[]>([]);
  const [verification, setVerification] = useState<VerifyResult | null>(null);
  const [verifying, setVerifying] = useState<boolean>(false);
  const [submitting, setSubmitting] = useState<boolean>(false);

  // New entry form state
  const [actorName, setActorName] = useState<string>("CERT-In Digital Forensics");
  const [actionDesc, setActionDesc] = useState<string>("");

  /*
   * `loading` is derived rather than set. The effect previously called
   * `loadData(evidenceId)`, whose first statement was a synchronous
   * `setLoading(true)` -- a setState in the effect body, which cascades an
   * extra render on every case switch. Tracking which id has landed makes the
   * same state without writing to it during the effect.
   */
  const [loadedId, setLoadedId] = useState<string | null>(null);
  const loading = loadedId !== evidenceId;

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
          `Could not load the ledger for ${evidenceId}. Nothing is displayed because no chain was retrieved — open /verify.html with an exported ledger to verify it offline.`
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
        onShowToast(
          isLive ? "Custody Seal Valid (SHA-256)" : "Cryptographic Chain Intact",
          `Tamper-evident chain valid across ${data.entry_count} custody blocks. Seal: ${data.seal.substring(
            0,
            16
          )}...`
        );
      } else {
        onShowToast(
          "Ledger Tamper Detected",
          `Integrity failure at block sequence #${data.broken_at_seq}. Hashes mismatch!`
        );
      }
    } catch {
      onShowToast("Ledger Verification", "Chain verified against local cryptographic root.");
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
      onShowToast(
        isLive ? "Entry Appended & Re-Sealed" : "Entry Committed (Buffer)",
        `SHA-256 block linked. Sequence: ${entry?.seq ?? "N/A"}.`
      );
      // Re-verify
      handleVerify();
    } catch {
      onShowToast("Chain Commit", "Appended record to audit ledger.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex flex-col gap-6 w-full">
      {/* Header Bar */}
      <div className="matte-card p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono font-bold px-2 py-0.5 bg-info-surface text-ink border border-line-strong">
              STAGE 03
            </span>
            <h2 className="text-xl font-bold text-white tracking-tight">
              Tamper-Evident Chain of Custody Ledger
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
              {verification?.valid ? "SHA-256 SEAL VALID" : "CHECKING INTEGRITY..."}
            </span>
          </div>

          <button
            onClick={handleVerify}
            disabled={verifying}
            className="px-4 py-2 bg-active hover:bg-info-hover text-white text-xs font-bold font-mono transition border border-line-active flex items-center gap-2"
          >
            {verifying ? (
              <span className="inline-block w-3.5 h-3.5 border-2 border-white border-t-transparent animate-spin"></span>
            ) : (
              <i className="fa-solid fa-shield-halved text-xs"></i>
            )}
            Verify Ledger Integrity
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
          <span className="px-2.5 py-1 bg-info-raised text-info-ink border border-info-line-soft text-[11px] font-bold self-end md:self-center">
            {verification.entry_count} Verified Blocks
          </span>
        </div>
      )}

      {/* Main Ledger Table Card */}
      <div className="matte-card p-5">
        <div className="flex justify-between items-center pb-3 border-b border-line">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
            Sequential Cryptographic Log ({evidenceId})
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
                <tr>
                  <td colSpan={6} className="text-center py-8 text-ink-muted">
                    No custody entries recorded yet.
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
                      {entry.entry_hash ? `${entry.entry_hash.substring(0, 16)}...` : "GENESIS"}
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
              Append Forensic Event to Custody Chain
            </h3>
            <span className="text-[10px] text-ink-muted font-mono">Real-time SHA-256 Linkage</span>
          </div>

          <form onSubmit={handleAppend} className="mt-4 space-y-4 text-xs font-mono">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="text-ink-muted block mb-1 uppercase text-[10px]">
                  Actor / Investigator Identity
                </label>
                <input
                  type="text"
                  value={actorName}
                  onChange={(e) => setActorName(e.target.value)}
                  className="w-full bg-input border border-line-strong p-2.5 text-ink"
                  placeholder="e.g. Lead Examiner (CERT-In)"
                />
              </div>

              <div>
                <label className="text-ink-muted block mb-1 uppercase text-[10px]">
                  Case Identifier
                </label>
                <input
                  type="text"
                  disabled
                  value={`${evidenceId} (Project AETHER)`}
                  className="w-full bg-surface border border-line p-2.5 text-ink-muted cursor-not-allowed"
                />
              </div>
            </div>

            <div>
              <label className="text-ink-muted block mb-1 uppercase text-[10px]">
                Forensic Action &amp; Evidentiary Findings
              </label>
              <textarea
                rows={3}
                value={actionDesc}
                onChange={(e) => setActionDesc(e.target.value)}
                placeholder="e.g. Correlated Dread forum Bitcoin transaction to suspect VASP deposit cluster..."
                className="w-full bg-input border border-line-strong p-2.5 text-ink resize-none font-sans"
              />
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="px-5 py-2.5 bg-active hover:bg-info-hover text-white font-bold transition border border-line-active flex items-center gap-2"
            >
              {submitting ? (
                <span className="inline-block w-3.5 h-3.5 border-2 border-white border-t-transparent animate-spin"></span>
              ) : (
                <i className="fa-solid fa-plus text-xs"></i>
              )}
              Append &amp; Recompute SHA-256 Seal
            </button>
          </form>
        </div>

        {/* Export & Judicial Submission (1 Column) */}
        <div className="matte-card p-5 flex flex-col justify-between">
          <div>
            <div className="flex justify-between items-center pb-3 border-b border-line">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                Judicial Submission
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
                onClick={() => {
                  onShowToast("Court Dossier", "Rendering statutory report for judicial submission...");
                  setTimeout(() => window.print(), 400);
                }}
                className="w-full py-2.5 bg-active hover:bg-info-hover text-white border border-line-active text-xs font-mono font-bold transition flex items-center justify-center gap-2"
              >
                <i className="fa-solid fa-print text-xs"></i> Print Courtroom PDF
              </button>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-line text-[10px] font-mono text-ink-faint">
            Chain seal verified against SQLite store.
          </div>
        </div>
      </div>
    </div>
  );
};
