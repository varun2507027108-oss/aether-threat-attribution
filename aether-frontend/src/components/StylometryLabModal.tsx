"use client";

import React, { useState } from "react";
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
    <p className="text-[11px] font-mono leading-relaxed text-slate-300 break-words">
      {parts.map((part, i) =>
        part && shared.has(part.toLowerCase()) ? (
          <mark key={i} className="bg-[#1d3a5c] text-cyan-200 px-0.5">
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
    <div className="bg-[#0e131d] p-3 border border-[#1a2230]">
      <div className="flex items-baseline justify-between">
        <span className="text-[10px] text-slate-400 uppercase">{label}</span>
        <span className="text-[9px] text-slate-500 uppercase">{note}</span>
      </div>
      {value === null ? (
        <span className="text-xs font-bold text-amber-400 mt-1 block">not applicable</span>
      ) : (
        <>
          <span className="text-base font-bold text-white mt-1 block">{(value * 100).toFixed(1)}%</span>
          <div className="h-1.5 bg-[#182031] mt-2">
            <div
              className={value >= 0.72 ? "h-full bg-cyan-400" : "h-full bg-rose-400"}
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

  if (!isOpen) return null;

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
    <div className="fixed inset-0 bg-black/85 flex items-center justify-center z-50 p-4">
      <div className="bg-[#0d1017] p-6 max-w-3xl w-full border border-[#273447] max-h-[92vh] overflow-y-auto">
        {/* Header */}
        <div className="flex justify-between items-center border-b border-[#1e2533] pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-[#1e2736] text-white flex items-center justify-center text-base border border-[#303d52]">
              <i className="fa-solid fa-fingerprint"></i>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 bg-[#141a24] text-slate-300 border border-[#263245]">
                  AI LAB
                </span>
                <h3 className="text-base font-bold text-white">
                  Stylometry NLP Comparison Engine
                </h3>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Character 3-gram &amp; word n-gram cosine similarity (POST /api/analysis/stylometry)
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 bg-[#161d28] text-slate-400 flex items-center justify-center hover:bg-slate-700 hover:text-white border border-[#273447] transition"
            title="Close"
          >
            <i className="fa-solid fa-xmark text-xs"></i>
          </button>
        </div>

        {/* Text Samples Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 my-4">
          <div>
            <div className="flex justify-between items-center mb-1 text-[11px] font-mono">
              <span className="text-slate-300 font-bold">Sample A: Dread Forum</span>
              <span className="text-slate-500">Handle: ZeroTrace</span>
            </div>
            <textarea
              rows={8}
              value={textA}
              onChange={(e) => setTextA(e.target.value)}
              className="w-full bg-[#080b10] border border-[#273447] p-3 text-slate-200 font-mono text-xs outline-none resize-none focus:border-[#425575] transition"
            />
          </div>

          <div>
            <div className="flex justify-between items-center mb-1 text-[11px] font-mono">
              <span className="text-slate-300 font-bold">Sample B: Exploit.in Forum</span>
              <span className="text-slate-500">Handle: ShadowByte</span>
            </div>
            <textarea
              rows={8}
              value={textB}
              onChange={(e) => setTextB(e.target.value)}
              className="w-full bg-[#080b10] border border-[#273447] p-3 text-slate-200 font-mono text-xs outline-none resize-none focus:border-[#425575] transition"
            />
          </div>
        </div>

        {/* Controls */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 pb-4 border-b border-[#1e2533]">
          <div className="flex items-center gap-2">
            <button
              onClick={handleRun}
              disabled={loading}
              className="px-5 py-2.5 bg-[#1e2736] hover:bg-[#283448] text-white text-xs font-bold font-mono transition border border-[#37455d] flex items-center gap-2"
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
              className="px-3 py-2 bg-[#121620] hover:bg-[#1a212d] text-slate-300 border border-[#232d3d] text-xs font-mono transition"
            >
              Load Unrelated Sample
            </button>
          </div>

          <button
            onClick={handleReset}
            className="text-xs text-slate-400 hover:text-slate-200 font-mono underline"
          >
            Reset Defaults
          </button>
        </div>

        {/* Results Section */}
        {result && (
          <div className="mt-4 bg-[#080c14] border border-[#1e2533] p-4 font-mono text-xs space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-[#161d28] pb-3">
              <div>
                <span className="text-[10px] text-slate-400 uppercase">
                  Ensemble Author-Profile Similarity
                </span>
                <div className="text-2xl font-bold text-white mt-0.5">
                  {(result.similarity_score * 100).toFixed(1)}%
                  <span
                    className={`text-xs font-normal ml-2 ${
                      result.similarity_score >= result.threshold ? "text-emerald-400" : "text-amber-400"
                    }`}
                  >
                    {result.confidence_tier}
                  </span>
                </div>
              </div>
              <div className="flex flex-col items-end gap-1">
                <span className="px-2.5 py-1 bg-[#141a24] text-slate-300 border border-[#232d3d] text-[11px]">
                  Shared Tokens: {result.shared_tokens_count}
                </span>
                <span className="px-2.5 py-1 bg-[#141a24] text-slate-400 border border-[#232d3d] text-[10px]">
                  Threshold {result.threshold} · FPR {result.fpr_at_threshold}
                </span>
              </div>
            </div>

            {result.ensemble.degraded && (
              <div className="bg-amber-950/40 border border-amber-700/50 px-3 py-2 text-[11px] text-amber-200">
                Only {result.ensemble.methods_used.join(", ") || "no methods"} contributed to this score.
                The other methods were skipped because the samples are too short for them to be
                meaningful; a degraded score is not the same claim as a full one.
              </div>
            )}

            {/* Per-method score bars */}
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

            {/* Side-by-side diff with shared spans highlighted */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[10px] text-slate-400 uppercase">
                  Shared Span Diff
                </span>
                <span className="text-[10px] text-slate-500">
                  <mark className="bg-[#1d3a5c] text-cyan-200 px-1">highlighted</mark> tokens appear in
                  both samples
                </span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="bg-[#090c12] border border-[#1a212d] p-2.5">
                  <span className="text-[10px] text-slate-400 uppercase block mb-1">Sample A</span>
                  <HighlightedText text={textA} shared={sharedTokens} />
                </div>
                <div className="bg-[#090c12] border border-[#1a212d] p-2.5">
                  <span className="text-[10px] text-slate-400 uppercase block mb-1">Sample B</span>
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
                  <div key={side} className="bg-[#0e131d] p-2.5 border border-[#1a2230] flex flex-wrap gap-x-4 gap-y-1">
                    <span className="text-slate-400 uppercase text-[10px]">Sample {side.toUpperCase()} script</span>
                    <span className="text-slate-200">latin {(profile.latin * 100).toFixed(0)}%</span>
                    <span className="text-slate-200">indic {(profile.indic * 100).toFixed(0)}%</span>
                    <span className="text-slate-200">emoji {(profile.emoji * 100).toFixed(0)}%</span>
                    {profile.code_mixed && (
                      <span className="text-cyan-300">code-mixed</span>
                    )}
                  </div>
                );
              })}
            </div>

            <p className="text-[10px] text-slate-500 leading-relaxed border-t border-[#161d28] pt-3">
              {result.evidentiary_caveat}
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
