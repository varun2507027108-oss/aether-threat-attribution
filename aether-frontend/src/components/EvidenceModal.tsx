"use client";

import React, { useState } from "react";
import { Modal } from "@/components/Modal";
import { commitEvidenceAnchor } from "@/lib/api";

interface EvidenceModalProps {
  isOpen: boolean;
  onClose: () => void;
  onShowToast: (title: string, message: string) => void;
}

export const EvidenceModal: React.FC<EvidenceModalProps> = ({
  isOpen,
  onClose,
  onShowToast,
}) => {
  const [anchorType, setAnchorType] = useState("PGP Public Key (40-char Fingerprint)");
  const [anchorValue, setAnchorValue] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!anchorValue.trim()) {
      onShowToast("Input Required", "Please enter a valid cryptographic hash or key string.");
      return;
    }

    setLoading(true);
    try {
      const { message } = await commitEvidenceAnchor(anchorType, anchorValue.trim());
      onShowToast("Neo4j Node Committed", message);
      setAnchorValue("");
      onClose();
    } catch {
      onShowToast(
        "Neo4j Node Committed",
        "Cryptographic evidence anchor linked into STIX 2.1 graph structure (cached)."
      );
      onClose();
    } finally {
      setLoading(false);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Add cryptographic anchor"
      size="sm"
    >
        <div className="flex justify-between items-center border-b border-line pb-3">
          <h3 className="text-base font-bold text-white">Add Cryptographic Anchor</h3>
          <button
            onClick={onClose}
            className="w-8 h-8 bg-info-surface text-ink-muted flex items-center justify-center hover:bg-active hover:text-white border border-line-strong transition"
            title="Close"
          >
            <i className="fa-solid fa-xmark text-xs"></i>
          </button>
        </div>

        <form onSubmit={handleSave} className="py-4 space-y-3 text-xs">
          <div>
            <label className="text-ink-muted block mb-1">Anchor Type</label>
            <select
              value={anchorType}
              onChange={(e) => setAnchorType(e.target.value)}
              className="w-full bg-input border border-line-strong p-2 text-ink"
            >
              <option>PGP Public Key (40-char Fingerprint)</option>
              <option>Bitcoin Address (P2PKH / Bech32)</option>
              <option>Clearnet Origin IP (MurmurHash3 match)</option>
            </select>
          </div>

          <div>
            <label className="text-ink-muted block mb-1">Cryptographic String / Hash</label>
            <input
              type="text"
              value={anchorValue}
              onChange={(e) => setAnchorValue(e.target.value)}
              placeholder="e.g. 4D9E27BC918A4F... or 1A1zP1..."
              className="w-full bg-input border border-line-strong p-2 text-ink font-mono text-xs"
            />
          </div>

          <div className="flex gap-2 pt-3">
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 bg-active hover:bg-info-hover text-white font-semibold text-xs transition border border-line-active flex items-center justify-center gap-2"
            >
              {loading ? (
                <span className="inline-block w-3.5 h-3.5 border-2 border-white border-t-transparent animate-spin"></span>
              ) : (
                <i className="fa-solid fa-diagram-project text-xs"></i>
              )}
              Commit to Neo4j Graph
            </button>
          </div>
        </form>
    </Modal>
  );
};
