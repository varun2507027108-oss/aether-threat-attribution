"use client";

import React, { useState } from "react";
import { Modal } from "@/components/Modal";
import { runStylometryAnalysis, StylometryResult } from "@/lib/api";

interface StylometryLabModalProps {
  isOpen: boolean;
  onClose: () => void;
  onShowToast: (title: string, message: string) => void;
}

const DEFAULT_SAMPLE_A = `Listen, the vendor escrow on this market is basically broken - everyone knows it, nobody says it. I have been running the same setup for three years; no downtime, no drama, no excuses. If you want the access dump, ping me. Prices are firm; don't waste my time with lowball offers. Payment in BTC only - no exceptions, no refunds. Trust is earned, not begged for.`;

const DEFAULT_SAMPLE_B_MATCH = `Listen, the escrow on that forum is basically a joke - everyone knows it, nobody admits it. I have been running this exact setup for years; no downtime, no drama, no excuses. If you need the access logs, ping me. Prices are fixed; don't waste my time with lowball bids. Payment in BTC only - no exceptions, no refunds. Respect is earned, not begged for.`;

const DEFAULT_SAMPLE_B_UNRELATED = `Good afternoon everyone. We have recently upgraded our database infrastructure to PostgreSQL 16. All replication lag has been resolved and queries are operating within expected latencies. Please refer to our engineering handbook for connection pool settings.`;

/**
 * Highlight the tokens the two samples share, so a reviewer can see *why* the
 * engine scored them the way it did rather than taking the number on faith.
 *
 * Devanagari, emoji, and code-mixed Hinglish tokens are matched as whole units,
 * mirroring the backend tokenizer. A naive \b\w+\b split would drop every emoji
 * and split a Hinglish word, which is precisely the population this tool exists
 * to serve.
 */
function sharedTokenSet(text: string): Set<string> {
  return new Set(
    (text.match(/[\u{1F000}-\u{1FAFF}\u2600-\u27BF\u2B00-\u2BFF\u200D\uFE0F]+|[\u0900-\u097F\u0980-\u0DFF\u0A00-\u0A7F\u0B00-\u0B7F]+|[a-z0-9_]+/giu) || []).map(
      (t) => t.toLowerCase(),
    ),
  );
}

function HighlightedText({ text, shared }: { text: string; shared: Set<string> }) {
  const parts = text.split(
    /([\u{1F000}-\u{1FAFF}\u2600-\u27BF\u2B00-\u2BFF\u200D\uFE0F]+|[\u0900-\u097F\u0980-\u0DFF\u0A00-\u0A7F\u0B00-\u0B7F]+|[a-z0-9_]+)/giu,
  );
  return (
    <p className="text-[11px] font-mono leading-relaxed text-ink break-words">
      {parts.map((part, i) =>
        part && shared.has(part.toLowerCase()) ? (
          <mark key={i} className="bg-info-hover text-info-ink px-0.5">
            {part}
          </mark>
        ) : (
          <span key={i}>{part}</span>
        ),
      )}
    </p>
  );
}

function ScoreBar({ label, value, note }: { label: string; value: number | null; note: string }) {
  const pct = value === null ? 0 : Math.round(Math.min(1, Math.max(0, value)) * 100);
  return (
    <div className="bg-surface p-3 border border-line">
      <div className="flex items-baseline justify-between">
        <span className="text-[10px] text-ink-muted uppercase">{label}</span>
        <span className="text-[9px] text-ink-faint uppercase">{note}</span>
      </div>
      {value === null ? (
        <span className="text-xs font-bold text-warn-ink mt-1 block">not applicable</span>
      ) : (
        <>
          <span className="text-base font-bold text-white mt-1 block">{(value * 100).toFixed(1)}%</span>
          <div className="h-1.5 bg-raised mt-2">
            <div
              className={value >= 0.72 ? "h-full bg-info" : "h-full bg-rose-400"}
              style={{ width: `${pct}%` }}
            ></div>
          </div>
        </>
      )}
    </div>
  );
}

export const StylometryLabModal: React.FC<StylometryLabModalProps> = ({
  isOpen,
  onClose,
  onShowToast,
}) => {
  const [textA, setTextA] = useState<string>(DEFAULT_SAMPLE_A);
  const [textB, setTextB] = useState<string>(DEFAULT_SAMPLE_B_MATCH);
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<StylometryResult | null>(null);

  // Tokens present in both current samples, recomputed on edit so the diff
  // reflects what is in the boxes rather than what was there when the run
  // happened.
  const sharedTokens = React.useMemo(() => {
    const a = sharedTokenSet(textA);
    const b = sharedTokenSet(textB);
    return new Set([...a].filter((token) => b.has(token)));
  }, [textA, textB]);

  const handleRun = async () => {
    if (!textA.trim() || !textB.trim()) {
      onShowToast("Input Required", "Please provide both text samples for stylometric comparison.");
      return;
    }

    setLoading(true);
    try {
      const { data, isLive } = await runStylometryAnalysis(textA, textB);
      setResult(data);
      const scorePct = (data.similarity_score * 100).toFixed(1) + "%";
      onShowToast(
        isLive ? "Stylometry Engine Live" : "Stylometry Evaluated",
        `Ensemble ${scorePct} via ${data.method_scores?.delta?.status === "OK" ? "cosine + Burrows' Delta + LZW-NCD" : "cosine only (samples too short for Delta/NCD)"}.`
      );
    } catch {
      onShowToast("Stylometry Notice", "Processed token embeddings via client fallback.");
    } finally {
      setLoading(false);
    }
  };

  const handleLoadUnrelated = () => {
    setTextB(DEFAULT_SAMPLE_B_UNRELATED);
    setResult(null);
    onShowToast("Sample Swapped", "Loaded unrelated benign engineering sample into Sample B.");
  };

  const handleReset = () => {
    setTextA(DEFAULT_SAMPLE_A);
    setTextB(DEFAULT_SAMPLE_B_MATCH);
    setResult(null);
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Stylometry lab"
      size="lg"
    >
        {/* Header */}
        <div className="flex justify-between items-center border-b border-line pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-active text-white flex items-center justify-center text-base border border-line-active">
              <i className="fa-solid fa-fingerprint"></i>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 bg-info-surface text-ink border border-line-strong">
                  AI LAB
                </span>
                <h3 className="text-base font-bold text-white">
                  Stylometry NLP Comparison Engine
                </h3>
              </div>
              <p className="text-xs text-ink-muted font-mono mt-0.5">
                Character 3-gram &amp; word n-gram cosine similarity (POST /api/analysis/stylometry)
              </p>
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

        {/* Text Samples Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 my-4">
          <div>
            <div className="flex justify-between items-center mb-1 text-[11px] font-mono">
              <span className="text-ink font-bold">Sample A: Dread Forum</span>
              <span className="text-ink-faint">Handle: ZeroTrace</span>
            </div>
            <textarea
              rows={8}
              value={textA}
              onChange={(e) => setTextA(e.target.value)}
              className="w-full bg-input border border-line-strong p-3 text-ink font-mono text-xs resize-none focus:border-info-line-strong transition"
            />
          </div>

          <div>
            <div className="flex justify-between items-center mb-1 text-[11px] font-mono">
              <span className="text-ink font-bold">Sample B: Exploit.in Forum</span>
              <span className="text-ink-faint">Handle: ShadowByte</span>
            </div>
            <textarea
              rows={8}
              value={textB}
              onChange={(e) => setTextB(e.target.value)}
              className="w-full bg-input border border-line-strong p-3 text-ink font-mono text-xs resize-none focus:border-info-line-strong transition"
            />
          </div>
        </div>

        {/* Controls */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 pb-4 border-b border-line">
          <div className="flex items-center gap-2">
            <button
              onClick={handleRun}
              disabled={loading}
              className="px-5 py-2.5 bg-active hover:bg-info-hover text-white text-xs font-bold font-mono transition border border-line-active flex items-center gap-2"
            >
              {loading ? (
                <span className="inline-block w-3.5 h-3.5 border-2 border-white border-t-transparent animate-spin"></span>
              ) : (
                <i className="fa-solid fa-calculator text-xs"></i>
              )}
              Run Stylometric Comparison
            </button>
            <button
              onClick={handleLoadUnrelated}
              className="px-3 py-2 bg-surface hover:bg-raised text-ink border border-line-strong text-xs font-mono transition"
            >
              Load Unrelated Sample
            </button>
          </div>

          <button
            onClick={handleReset}
            className="text-xs text-ink-muted hover:text-ink font-mono underline"
          >
            Reset Defaults
          </button>
        </div>

        {/* Results Section */}
        {result && (
          <div className="mt-4 bg-input border border-line p-4 font-mono text-xs space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-line-faint pb-3">
              <div>
                <span className="text-[10px] text-ink-muted uppercase">
                  Ensemble Author-Profile Similarity
                </span>
                <div className="text-2xl font-bold text-white mt-0.5">
                  {(result.similarity_score * 100).toFixed(1)}%
                  <span
                    className={`text-xs font-normal ml-2 ${
                      result.similarity_score >= result.threshold ? "text-signal-ink" : "text-warn-ink"
                    }`}
                  >
                    {result.confidence_tier}
                  </span>
                </div>
              </div>
              <div className="flex flex-col items-end gap-1">
                <span className="px-2.5 py-1 bg-info-surface text-ink border border-line-strong text-[11px]">
                  Shared Tokens: {result.shared_tokens_count}
                </span>
              <span className="px-2.5 py-1 bg-info-surface text-ink-muted border border-line-strong text-[10px]">
                {typeof result.threshold === "number" && typeof result.fpr_at_threshold === "number"
                  ? `Threshold ${result.threshold} · FPR ${result.fpr_at_threshold}`
                  : "Calibrated threshold not reported"}
              </span>
            </div>
          </div>

          {/*
            `ensemble` is optional: it arrived in phase 9, so a pre-phase-9
            backend and the module-failure path both omit it. This read was
            unguarded and took down the dialog on a case already in progress.
          */}
          {result.ensemble?.degraded && (
            <div className="bg-warn-surface/40 border border-warn-line px-3 py-2 text-[11px] text-warn-ink">
              Only {result.ensemble.methods_used.join(", ") || "no methods"} contributed to this
              score. The other methods were skipped because the samples are too short for them to
              be meaningful; a degraded score is not the same claim as a full one.
            </div>
          )}
          {!result.ensemble && (
            <div className="bg-warn-surface/40 border border-warn-line px-3 py-2 text-[11px] text-warn-ink">
              This response carries no ensemble block, so the methods behind the score cannot be
              named. Treat the figure as indicative until a backend that reports it is running.
            </div>
          )}

            {/*
              Per-method bars need `method_scores`, which also arrived in phase
              9. The local fallback supplies it; a live response from an older
              backend does not, and these reads were unguarded.
            */}
            {result.method_scores ? (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <ScoreBar label="Ensemble" value={result.similarity_score} note="fused" />
                <ScoreBar label="Cosine" value={result.method_scores.cosine} note="n-gram" />
                <ScoreBar
                  label="Burrows' Delta"
                  value={result.method_scores.delta.similarity}
                  note={
                    result.method_scores.delta.delta !== null
                      ? `delta ${result.method_scores.delta.delta}`
                      : "gated"
                  }
                />
                <ScoreBar
                  label="LZW NCD"
                  value={result.method_scores.ncd.similarity}
                  note={
                    result.method_scores.ncd.ncd !== null
                      ? `ncd ${result.method_scores.ncd.ncd}`
                      : "gated"
                  }
                />
              </div>
            ) : (
              <div className="bg-warn-surface/40 border border-warn-line px-3 py-2 text-[11px] text-warn-ink">
                This response carries no per-method breakdown, so the individual technique scores
                cannot be shown. The headline figure alone should not be relied on.
              </div>
            )}

            {/* Side-by-side diff with shared spans highlighted */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[10px] text-ink-muted uppercase">
                  Shared Span Diff
                </span>
                <span className="text-[10px] text-ink-faint">
                  <mark className="bg-info-hover text-info-ink px-1">highlighted</mark> tokens appear in
                  both samples
                </span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="bg-input border border-line p-2.5">
                  <span className="text-[10px] text-ink-muted uppercase block mb-1">Sample A</span>
                  <HighlightedText text={textA} shared={sharedTokens} />
                </div>
                <div className="bg-input border border-line p-2.5">
                  <span className="text-[10px] text-ink-muted uppercase block mb-1">Sample B</span>
                  <HighlightedText text={textB} shared={sharedTokens} />
                </div>
              </div>
            </div>

            {/* Script mix: shows whether a low score is a genuine mismatch or a
                tokenizer dropping the script the author actually writes in. */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
              {(["a", "b"] as const).map((side) => {
                const profile = side === "a" ? result.script_profile_a : result.script_profile_b;
                if (!profile) return null;
                return (
                  <div key={side} className="bg-surface p-2.5 border border-line flex flex-wrap gap-x-4 gap-y-1">
                    <span className="text-ink-muted uppercase text-[10px]">Sample {side.toUpperCase()} script</span>
                    <span className="text-ink">latin {(profile.latin * 100).toFixed(0)}%</span>
                    <span className="text-ink">indic {(profile.indic * 100).toFixed(0)}%</span>
                    <span className="text-ink">emoji {(profile.emoji * 100).toFixed(0)}%</span>
                    {profile.code_mixed && (
                      <span className="text-info-ink">code-mixed</span>
                    )}
                  </div>
                );
              })}
            </div>

            <p className="text-[10px] text-ink-faint leading-relaxed border-t border-line-faint pt-3">
              {result.evidentiary_caveat}
            </p>
          </div>
        )}
    </Modal>
  );
};
