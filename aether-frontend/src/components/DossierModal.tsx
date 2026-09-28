"use client";

import React, { useState } from "react";
import { downloadForensicCsv, downloadStixBundle, InvestigationResult } from "@/lib/api";
import { Modal } from "@/components/Modal";

interface DossierModalProps {
  isOpen: boolean;
  onClose: () => void;
  investigation?: InvestigationResult | null;
  evidenceId?: string;
  onShowToast: (title: string, message: string) => void;
}

export const DossierModal: React.FC<DossierModalProps> = ({
  isOpen,
  onClose,
  investigation,
  evidenceId = "AT-2026-0047",
  onShowToast,
}) => {
  const [downloading, setDownloading] = useState(false);

  if (!isOpen) return null;

  const targetEvidenceId = investigation?.case?.evidence_id || evidenceId;
  const caseData = investigation?.case;
  const attribution = investigation?.attribution;

  const handleStixDownload = async () => {
    setDownloading(true);
    try {
      const { isLive, filename } = await downloadStixBundle(targetEvidenceId);
      onShowToast(
        "STIX 2.1 Bundle Exported",
        `${filename} generated via ${isLive ? "FastAPI backend (:8000)" : "client fallback generator"}.`
      );
    } catch {
      onShowToast("Export Warning", "Falling back to local forensic buffer.");
    } finally {
      setDownloading(false);
      onClose();
    }
  };

  const handleCsvDownload = async () => {
    setDownloading(true);
    try {
      const { isLive, filename } = await downloadForensicCsv(targetEvidenceId);
      onShowToast(
        "Forensic CSV Exported",
        `${filename} generated via ${isLive ? "FastAPI backend (:8000)" : "client fallback buffer"}.`
      );
    } catch {
      onShowToast("Export Warning", "Falling back to local forensic buffer.");
    } finally {
      setDownloading(false);
      onClose();
    }
  };

  const handlePrintCourtReport = () => {
    onClose();
    onShowToast("Court Dossier", "Rendering statutory report for judicial submission...");
    setTimeout(() => {
      window.print();
    }, 400);
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Target suspect dossier" size="md">
        <div className="flex justify-between items-center border-b border-line pb-4">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 bg-active text-white flex items-center justify-center text-sm border border-line-active">
              <i className="fa-solid fa-shield-halved"></i>
            </div>
            <div>
              <h3 className="text-base font-bold text-white">FORM-DEANON: Forensic Dossier</h3>
              <p className="text-xs text-ink-muted font-mono">Dossier ID: NTRO-26151-{targetEvidenceId}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 bg-info-surface text-ink-muted flex items-center justify-center hover:bg-active hover:text-white border border-line-strong transition"
            title="Close"
          >
            <i className="fa-solid fa-xmark text-xs"></i>
          </button>
        </div>

        <div className="py-4 space-y-3 text-xs">
          <div className="bg-input p-3.5 border border-line space-y-2 font-mono text-[11px]">
            <div className="flex justify-between">
              <span className="text-ink-muted">Target / Handle:</span>{" "}
              <span className="font-bold text-white">
                {caseData?.actor_name || caseData?.target_url || "ZeroTrace / ShadowByte"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-ink-muted">Target Type:</span>{" "}
              <span className="font-mono text-info-ink uppercase">
                {caseData?.target_type || "onion"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-ink-muted">Discovered IP:</span>{" "}
              <span className="font-bold text-alert-ink">
                {caseData?.origin_ip
                  ? `${caseData.origin_ip} (${caseData.geo || "Resolved"})`
                  : "N/A (Multi-hop SOCKS5)"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-ink-muted">PGP Key Hash:</span>{" "}
              <span className="text-ink">
                {caseData?.pgp_fingerprint
                  ? `${caseData.pgp_fingerprint.substring(0, 18)}...`
                  : "N/A"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-ink-muted">Confidence Score:</span>{" "}
              <span className="font-bold text-white">
                {attribution
                  ? `${attribution.confidence_score}% (${attribution.confidence_tier})`
                  : "94.8% (Court Verifiable)"}
              </span>
            </div>
          </div>

          <div className="p-3 bg-surface border border-line-strong text-ink flex items-center gap-2.5">
            <i className="fa-solid fa-circle-check text-base shrink-0 text-ink-muted"></i>
            <p className="text-[11px] leading-tight">
              SHA-256 Digital Seal:{" "}
              <span className="font-mono text-white">
                {investigation?.custody_verification?.seal
                  ? `${investigation.custody_verification.seal.substring(0, 24)}...`
                  : "e3b0c44298fc1c149afbf4c8996..."}
              </span>{" "}
              Native OASIS STIX 2.1 format.
            </p>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row gap-3 pt-2">
          <button
            onClick={handleStixDownload}
            disabled={downloading}
            className="flex-1 py-2.5 bg-surface hover:bg-raised text-ink font-semibold text-xs transition border border-line-strong flex items-center justify-center gap-1.5"
          >
            <i className="fa-solid fa-code text-[11px]"></i> STIX 2.1 JSON
          </button>
          <button
            onClick={handleCsvDownload}
            disabled={downloading}
            className="flex-1 py-2.5 bg-surface hover:bg-raised text-ink font-semibold text-xs transition border border-line-strong flex items-center justify-center gap-1.5"
          >
            <i className="fa-solid fa-table text-[11px]"></i> Forensic CSV
          </button>
          <button
            onClick={handlePrintCourtReport}
            className="flex-1 py-2.5 bg-active hover:bg-info-hover text-white font-semibold text-xs transition border border-line-active flex items-center justify-center gap-1.5"
          >
            <i className="fa-solid fa-print text-[11px]" aria-hidden="true"></i> Print Court PDF
          </button>
        </div>
    </Modal>
  );
};
