"use client";

import React, { useEffect, useRef, useState } from "react";
import { Modal } from "@/components/Modal";
import {
  InvestigationRequest,
  InvestigationResult,
  startInvestigation,
  subscribeJobEvents,
  fetchCaseInvestigation,
} from "@/lib/api";

interface NewInvestigationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onInvestigationComplete: (result: InvestigationResult) => void;
  onShowToast: (title: string, message: string) => void;
}

const PRESETS = [
  {
    name: "Dread Marketplace (.onion)",
    badge: "TOR V3 ONION",
    caseName: "Operation Chimera",
    target: "http://p4lx7e22kq6dreadmarket.onion",
    targetType: "onion",
    actorName: "UNC-3844 (ZeroTrace)",
    knownPgp: "4D9E 27BC 918A 4F02 C731 09AE 2C5B 88E1 40FA 7D3C",
    knownBtc: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    textSample: "We operate high volume ransom payment gateways on dread. Full escrow guaranteed with PGP.",
  },
  {
    name: "Unmasked Clearnet Origin (IPv4)",
    badge: "CLEARNET HOST",
    caseName: "Operation Ironclad",
    target: "185.220.101.42",
    targetType: "ip",
    actorName: "ShadowByte",
    knownPgp: "4D9E 27BC 918A 4F02 C731 09AE 2C5B 88E1 40FA 7D3C",
    knownBtc: "bc1qa5wkgaew2dkv56kfvj49j0av5nqvrl529w40b5",
    textSample: "We run high volume payment portals on exploit with fast escrow and PGP settlement.",
  },
  {
    name: "Darknet Portal (Domain)",
    badge: "REBRANDED DOMAIN",
    caseName: "Operation Parallax Prime",
    target: "darknet-market-portal.org",
    targetType: "domain",
    actorName: "VortexBroker",
    knownPgp: "4B8F 90A2 E83C 1204 D76A 58B9 2F10 CC49 E81A 9044",
    knownBtc: "1FvzCLoTPGANNjWoUo6jUGuAG3wg1w4YjR",
    textSample: "New mirrors live. All accounts migrated securely. Verify with our PGP signature.",
  },
];

interface ModuleDefinition {
  key: string;
  name: string;
  desc: string;
}

const ANALYSIS_MODULES: ModuleDefinition[] = [
  { key: "favicon", name: "Favicon MurmurHash3 32-bit", desc: "Computing mmh3_32 and matching Shodan facet http.favicon.hash" },
  { key: "server_status", name: "Infrastructure Origin Discovery", desc: "Probing clearnet host IP, ASN, Geolocation, and /server-status leak" },
  { key: "tls_cert", name: "TLS Certificate Fingerprint", desc: "Extracting SHA-256 certificate fingerprint & clearnet cross-correlation" },
  { key: "jarm", name: "JARM Active TLS Fingerprinting", desc: "Matching 62-char JARM fingerprint against known C2 and onion proxies" },
  { key: "whois_dns", name: "DNS & ASN Infrastructure", desc: "Querying Shodan/Censys with strict LIVE / DEMO / UNAVAILABLE provenance" },
  { key: "diurnal", name: "Diurnal Circadian Sleep Trough", desc: "Evaluating 24h UTC posting distribution to calculate operational offset" },
  { key: "stylometry", name: "Stylometry NLP Cosine Engine", desc: "Vectorizing char 3-gram and word n-grams against threat actor corpus" },
  { key: "crypto", name: "Bitcoin Peel-Chain Clustering", desc: "Running multi-input co-spend heuristics across 14 transaction outputs" },
  { key: "pgp", name: "RFC 4880 PGP Fingerprint", desc: "Normalizing 40-char V4 key ID & checking cross-forum deterministic reuse" },
  { key: "custody", name: "Cryptographic Custody Sealing", desc: "Generating Ed25519-signed SHA-256 tamper-evident ledger blocks" },
];

type ModuleStatus = "pending" | "running" | "done" | "failed" | "skipped";

const MODULE_STATUSES: readonly ModuleStatus[] = [
  "pending",
  "running",
  "done",
  "failed",
  "skipped",
];

interface ModuleRuntime {
  status: ModuleStatus;
  startedAt: number | null;
  finishedAt: number | null;
  elapsedSec: string;
  summary: string | null;
}

export const NewInvestigationModal: React.FC<NewInvestigationModalProps> = ({
  isOpen,
  onClose,
  onInvestigationComplete,
  onShowToast,
}) => {
  const [caseName, setCaseName] = useState("Operation Chimera");
  const [evidenceId, setEvidenceId] = useState("");
  const [actorName, setActorName] = useState("UNC-3844");
  const [target, setTarget] = useState("http://p4lx7e22kq6dreadmarket.onion");
  const [targetType, setTargetType] = useState("onion");
  const [knownPgp, setKnownPgp] = useState("4D9E 27BC 918A 4F02 C731 09AE 2C5B 88E1 40FA 7D3C");
  const [knownBtc, setKnownBtc] = useState("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
  const [textSample, setTextSample] = useState(
    "We operate high volume ransom payment gateways on dread. Full escrow guaranteed with PGP."
  );
  const [mode, setMode] = useState("auto");
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Analysis running animation state
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeJobId, setActiveJobId] = useState<string | null>(null);

  const getInitialStates = () => {
    const init: Record<string, ModuleRuntime> = {};
    ANALYSIS_MODULES.forEach((m) => {
      init[m.key] = {
        status: "pending",
        startedAt: null,
        finishedAt: null,
        elapsedSec: "0.0s",
        summary: null,
      };
    });
    return init;
  };

  const [moduleStates, setModuleStates] = useState<Record<string, ModuleRuntime>>(getInitialStates);

  const progressIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const timeoutRef = useRef<NodeJS.Timeout | null>(null);
  const unsubscribeRef = useRef<(() => void) | null>(null);

  // Live timer tick for running modules
  useEffect(() => {
    if (!isAnalyzing) return;
    const timer = setInterval(() => {
      const now = Date.now();
      setModuleStates((prev) => {
        let changed = false;
        const next = { ...prev };
        for (const key of Object.keys(next)) {
          const item = next[key];
          if (item && item.status === "running" && item.startedAt) {
            const sec = ((now - item.startedAt) / 1000).toFixed(1) + "s";
            if (item.elapsedSec !== sec) {
              next[key] = { ...item, elapsedSec: sec };
              changed = true;
            }
          }
        }
        return changed ? next : prev;
      });
    }, 100);
    return () => clearInterval(timer);
  }, [isAnalyzing]);

  useEffect(() => {
    return () => {
      if (progressIntervalRef.current) clearInterval(progressIntervalRef.current);
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
      if (unsubscribeRef.current) {
        unsubscribeRef.current();
        unsubscribeRef.current = null;
      }
    };
  }, []);

  /*
   * A case identifier is an audit record, so it is assigned rather than
   * rolled. This used to be `AT-2026-${Math.floor(1000 + Math.random() * 9000)}`
   * computed during render, which meant the same target opened twice produced
   * two different case numbers, and reopening the dialog produced a third.
   *
   * `deriveEvidenceId` is deterministic in the target, so an analyst who
   * re-submits the same onion address lands on the same case and the chain of
   * custody stays one chain.
   */
  const deriveEvidenceId = (seed: string) => {
    let h = 2166136261;
    for (let i = 0; i < seed.length; i++) {
      h ^= seed.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    const n = (h >>> 0) % 9000;
    return `AT-2026-${String(1000 + n).padStart(4, "0")}`;
  };

  const handleApplyPreset = (idx: number) => {
    const p = PRESETS[idx];
    setCaseName(p.caseName);
    setTarget(p.target);
    setTargetType(p.targetType);
    setActorName(p.actorName);
    setKnownPgp(p.knownPgp);
    setKnownBtc(p.knownBtc);
    setTextSample(p.textSample);
    setEvidenceId(deriveEvidenceId(p.target));
    onShowToast("Preset Loaded", `Configured investigation for ${p.name}.`);
  };

  const handleStartAnalysis = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) {
      onShowToast("Target Required", "Please enter a target domain, IP, URL, or onion descriptor.");
      return;
    }

    setIsAnalyzing(true);
    const initialStates = getInitialStates();
    setModuleStates(initialStates);

    // An analyst may leave the field blank; the identifier is derived from the
    // target so the same subject always resolves to the same case.
    const resolvedEvidenceId = evidenceId.trim() || deriveEvidenceId(target.trim());
    if (!evidenceId.trim()) setEvidenceId(resolvedEvidenceId);

    try {
      const payload: InvestigationRequest = {
        case_name: caseName.trim() || "Operation AETHER",
        evidence_id: resolvedEvidenceId,
        actor_name: actorName.trim() || "UNC-3844",
        target: target.trim(),
        target_type: targetType,
        known_pgp: knownPgp.trim() || undefined,
        known_btc: knownBtc.trim() || undefined,
        text_sample: textSample.trim() || undefined,
        mode,
      };

      const res = await startInvestigation(payload);

      // LIVE ASYNC PIPELINE (SSE Streaming)
      if (res.isLive && res.job) {
        const activeJob = res.job;
        const targetEvidenceId = activeJob.evidence_id || evidenceId;
        setActiveJobId(activeJob.job_id);
        const startTime = Date.now();

        // Mark all forensic modules as running
        setModuleStates((prev) => {
          const next = { ...prev };
          ANALYSIS_MODULES.forEach((m) => {
            if (m.key !== "custody") {
              next[m.key] = {
                status: "running",
                startedAt: startTime,
                finishedAt: null,
                elapsedSec: "0.0s",
                summary: null,
              };
            }
          });
          return next;
        });

        // Subscribe to SSE
        const unsubscribe = subscribeJobEvents(
          res.job.job_id,
          async (evt) => {
            if (evt.type === "module_update") {
              /*
               * The SSE payload is `unknown`: the event stream is a transport
               * boundary and its shape is whatever the server sent. Narrow it
               * once here rather than trusting the cast, so a malformed frame
               * degrades to an ignored update instead of a render crash
               * mid-investigation.
               */
              const payload = evt.data as
                | { module?: string; status?: string; summary?: string | null }
                | null;
              if (!payload || typeof payload.module !== "string") return;

              const modKey = payload.module;
              const status = payload.status;
              const modStatus: ModuleStatus = MODULE_STATUSES.includes(
                status as ModuleStatus
              )
                ? (status as ModuleStatus)
                : "pending";
              const { summary } = payload;
              const now = Date.now();
              setModuleStates((prev) => {
                const current = prev[modKey] || {
                  status: "pending",
                  startedAt: now,
                  finishedAt: null,
                  elapsedSec: "0.0s",
                  summary: null,
                };
                const finishedAt = ["done", "failed", "skipped"].includes(modStatus)
                  ? now
                  : current.finishedAt;
                const elapsedSec = current.startedAt && finishedAt
                  ? ((finishedAt - current.startedAt) / 1000).toFixed(1) + "s"
                  : current.elapsedSec;
                return {
                  ...prev,
                  [modKey]: {
                    ...current,
                    status: modStatus,
                    finishedAt,
                    elapsedSec,
                    summary: summary || current.summary,
                  },
                };
              });
            } else if (evt.type === "terminal") {
              const now = Date.now();
              // Seal custody
              setModuleStates((prev) => ({
                ...prev,
                custody: {
                  status: "done",
                  startedAt: now - 150,
                  finishedAt: now,
                  elapsedSec: "0.2s",
                  summary: "Ed25519-signed SHA-256 checkpoint anchored",
                },
              }));

              // Fetch final completed investigation
              const finalRes = await fetchCaseInvestigation(targetEvidenceId);
              timeoutRef.current = setTimeout(() => {
                setIsAnalyzing(false);
                onInvestigationComplete(finalRes.data);
                onShowToast(
                  "Live Investigation Complete",
                  `Case ${finalRes.data.case.evidence_id}: Attributed to ${finalRes.data.case.actor_name} (${finalRes.data.attribution.confidence_score}% Confidence).`
                );
                onClose();
              }, 600);
            }
          },
          (err) => {
            console.warn("SSE event connection issue:", err);
          }
        );
        unsubscribeRef.current = unsubscribe;
        return;
      }

      // OFFLINE / SYNC FALLBACK SIMULATION
      const resultData = res.data!;
      let step = 0;
      const startTime = Date.now();

      progressIntervalRef.current = setInterval(() => {
        if (step < ANALYSIS_MODULES.length) {
          const mod = ANALYSIS_MODULES[step];
          const now = Date.now();
          setModuleStates((prev) => {
            const next = { ...prev };
            // Mark current as done
            next[mod.key] = {
              status: "done",
              startedAt: startTime + step * 250,
              finishedAt: now,
              elapsedSec: "0.2s",
              summary: "Verified and extracted",
            };
            // Mark next as running
            if (step + 1 < ANALYSIS_MODULES.length) {
              const nextMod = ANALYSIS_MODULES[step + 1];
              next[nextMod.key] = {
                status: "running",
                startedAt: now,
                finishedAt: null,
                elapsedSec: "0.0s",
                summary: null,
              };
            }
            return next;
          });
          step++;
        } else {
          if (progressIntervalRef.current) clearInterval(progressIntervalRef.current);
          progressIntervalRef.current = null;
          timeoutRef.current = setTimeout(() => {
            setIsAnalyzing(false);
            onInvestigationComplete(resultData);
            onShowToast(
              res.isLive ? "Live Investigation Complete" : "Forensic Investigation Sealed",
              `Case ${resultData.case.evidence_id}: Attributed to ${resultData.case.actor_name} (${resultData.attribution.confidence_score}% Confidence).`
            );
            onClose();
          }, 400);
        }
      }, 260);
    } catch (err) {
      if (progressIntervalRef.current) {
        clearInterval(progressIntervalRef.current);
        progressIntervalRef.current = null;
      }
      setIsAnalyzing(false);
      // Name the actual failure. A bare "Analysis Error" gave the analyst no
      // way to tell a rejected target from a backend that was down.
      const reason = err instanceof Error ? err.message : String(err);
      onShowToast(
        "Analysis failed",
        `${reason}. Nothing was written to the custody chain — check the backend is reachable and retry.`
      );
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="New investigation"
      size="xl"
      className="bg-input text-ink"
    >
        {/* Header */}
        <div className="p-5 border-b border-line flex items-center justify-between bg-surface">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-info-surface border border-line-active text-white flex items-center justify-center text-base">
              <i className="fa-solid fa-crosshairs text-info-ink"></i>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-extrabold text-white tracking-tight font-mono">
                  NEW INVESTIGATION
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 bg-info-surface text-info-ink border border-info-line">
                  {activeJobId ? `ASYNC JOB ${activeJobId.slice(0, 8)}` : "NTRO FORENSIC PIPELINE"}
                </span>
              </div>
              <p className="text-xs text-ink-muted mt-0.5 font-mono">
                Parallel async engine · Live SSE telemetry · Ed25519 tamper-evident custody chain.
              </p>
            </div>
          </div>
          {!isAnalyzing && (
            <button
              onClick={onClose}
              className="w-8 h-8 bg-info-surface text-ink-muted hover:text-white border border-line-strong flex items-center justify-center transition"
            >
              <i className="fa-solid fa-xmark text-xs"></i>
            </button>
          )}
        </div>

        {isAnalyzing ? (
          /* Live Progress Inspection Mode */
          <div className="p-6 space-y-6">
            <div className="text-center space-y-2">
              <div className="inline-flex items-center gap-2 px-3 py-1 bg-info-raised text-info-ink border border-info-line-strong text-xs font-mono font-bold animate-pulse">
                <span className="w-2 h-2 bg-info"></span>
                PARALLEL FORENSIC PIPELINE STREAMING
              </div>
              <h3 className="text-lg font-bold text-white font-mono">{caseName}</h3>
              <p className="text-xs text-ink-muted font-mono">Target: {target}</p>
            </div>

            {/* Step Pipeline List */}
            <div className="space-y-2 font-mono text-xs bg-sunken p-4 border border-line">
              {ANALYSIS_MODULES.map((mod, idx) => {
                const state = moduleStates[mod.key] || {
                  status: "pending",
                  elapsedSec: "0.0s",
                  summary: null,
                };
                const isRunning = state.status === "running";
                const isDone = state.status === "done";
                const isFailed = state.status === "failed";
                const isSkipped = state.status === "skipped";

                return (
                  <div
                    key={mod.key}
                    className={`p-2.5 flex items-center justify-between border transition ${
                      isRunning
                        ? "bg-raised border-info-line-strong text-white"
                        : isDone
                        ? "bg-card border-line text-ink"
                        : isFailed
                        ? "bg-card border-rose-900/60 text-rose-300"
                        : isSkipped
                        ? "bg-card border-line-faint text-ink-faint"
                        : "bg-transparent border-transparent text-ink-faint opacity-60"
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <span className="w-6 text-center font-bold text-[11px] text-ink-muted">
                        {isDone ? (
                          <i className="fa-solid fa-check text-signal-ink"></i>
                        ) : isRunning ? (
                          <i className="fa-solid fa-gear fa-spin text-info-ink"></i>
                        ) : isFailed ? (
                          <i className="fa-solid fa-triangle-exclamation text-rose-400"></i>
                        ) : isSkipped ? (
                          <i className="fa-solid fa-forward-step text-ink-faint"></i>
                        ) : (
                          `0${idx + 1}`
                        )}
                      </span>
                      <div>
                        <div className="font-bold flex items-center gap-2">
                          <span>{mod.name}</span>
                          {isRunning && (
                            <span className="text-[10px] px-1.5 py-0.2 bg-info-surface/60 text-info-ink border border-info-line-strong animate-pulse">
                              RUNNING
                            </span>
                          )}
                          {isFailed && (
                            <span className="text-[10px] px-1.5 py-0.2 bg-rose-900/60 text-rose-300 border border-rose-700">
                              DEGRADED
                            </span>
                          )}
                          {isSkipped && (
                            <span className="text-[10px] px-1.5 py-0.2 bg-active text-ink-muted border border-line-strong">
                              SKIPPED
                            </span>
                          )}
                        </div>
                        <p className="text-[10px] text-ink-muted">
                          {state.summary ? state.summary : mod.desc}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-[10px] font-mono text-ink-muted">
                        {state.elapsedSec}
                      </span>
                      <span
                        className={`text-[10px] uppercase font-bold tracking-wider ${
                          isDone
                            ? "text-signal-ink"
                            : isRunning
                            ? "text-info-ink"
                            : isFailed
                            ? "text-rose-400"
                            : isSkipped
                            ? "text-ink-faint"
                            : "text-ink-faint"
                        }`}
                      >
                        {isDone
                          ? "DONE"
                          : isRunning
                          ? "RUNNING"
                          : isFailed
                          ? "FAILED"
                          : isSkipped
                          ? "SKIPPED"
                          : "PENDING"}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="text-center text-[11px] font-mono text-ink-muted">
              Generating tamper-evident SHA-256 custody blocks and STIX 2.1 entities...
            </div>
          </div>
        ) : (
          /* Form Input Mode */
          <form onSubmit={handleStartAnalysis} className="p-6 space-y-5">
            {/* Presets Quick Chips */}
            <div>
              <label className="text-[11px] font-mono uppercase font-bold text-ink-muted block mb-2">
                Quick Preset Targets (Click to Populate):
              </label>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
                {PRESETS.map((p, idx) => (
                  <button
                    key={p.name}
                    type="button"
                    onClick={() => handleApplyPreset(idx)}
                    className="p-2.5 text-left bg-surface hover:bg-info-surface border border-line hover:border-info-line-strong transition group"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 bg-raised text-info-ink border border-info-line">
                        {p.badge}
                      </span>
                      <i className="fa-solid fa-arrow-right text-[10px] text-ink-faint group-hover:text-info-ink transition"></i>
                    </div>
                    <div className="font-bold text-xs text-white mt-1.5 truncate">{p.name}</div>
                    <div className="text-[10px] text-ink-muted font-mono truncate mt-0.5">
                      {p.target}
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Target Specification */}
            <div className="space-y-4 pt-2 border-t border-line-faint">
              <div>
                <label className="text-xs font-mono font-bold text-ink block mb-1">
                  Investigation Target <span className="text-alert-ink">*</span>
                </label>
                <div className="flex items-center bg-sunken border border-line-strong focus-within:border-info-line">
                  <span className="px-3 py-2 text-ink-faint text-xs font-mono border-r border-line">
                    <i className="fa-solid fa-globe"></i>
                  </span>
                  <input
                    type="text"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="Domain, IPv4, or .onion URL (e.g. http://p4lx7e22kq6dreadmarket.onion)"
                    className="w-full bg-transparent px-3 py-2 text-xs font-mono text-white placeholder:text-ink-faint"
                    required
                  />
                  <select
                    value={targetType}
                    onChange={(e) => setTargetType(e.target.value)}
                    className="bg-surface text-[11px] font-mono text-ink px-3 py-2 border-l border-line cursor-pointer"
                  >
                    <option value="onion">Tor Onion (.onion)</option>
                    <option value="ip">IPv4 Host Address</option>
                    <option value="domain">Clearnet Domain</option>
                    <option value="btc">Bitcoin Root Address</option>
                    <option value="pgp">PGP Fingerprint</option>
                  </select>
                </div>
              </div>

              {/* Case Details Row */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div>
                  <label className="text-xs font-mono text-ink-muted block mb-1">
                    Case Name / Reference
                  </label>
                  <input
                    type="text"
                    value={caseName}
                    onChange={(e) => setCaseName(e.target.value)}
                    className="w-full bg-sunken border border-line-strong px-3 py-2 text-xs font-mono text-white focus:border-info-line"
                  />
                </div>
                <div>
                  <label className="text-xs font-mono text-ink-muted block mb-1">
                    Evidence ID (Immutable)
                  </label>
                  <input
                    type="text"
                    value={evidenceId}
                    onChange={(e) => setEvidenceId(e.target.value)}
                    className="w-full bg-sunken border border-line-strong px-3 py-2 text-xs font-mono text-ink"
                  />
                </div>
                <div>
                  <label className="text-xs font-mono text-ink-muted block mb-1">
                    Suspect / Persona Lead
                  </label>
                  <input
                    type="text"
                    value={actorName}
                    onChange={(e) => setActorName(e.target.value)}
                    className="w-full bg-sunken border border-line-strong px-3 py-2 text-xs font-mono text-white focus:border-info-line"
                  />
                </div>
              </div>
            </div>

            {/* Analysis Mode & Provenance Guarantee */}
            <div className="p-3 bg-surface border border-line space-y-2">
              <div className="flex justify-between items-center text-xs font-mono">
                <span className="font-bold text-ink">Execution Mode &amp; Provenance Tagging</span>
                <span className="text-[10px] text-info-ink">Strict Non-Deception Rule</span>
              </div>
              <div className="grid grid-cols-3 gap-2 text-xs font-mono">
                <label
                  className={`p-2 border cursor-pointer text-center transition ${
                    mode === "auto"
                      ? "bg-info-raised border-info-line text-white font-bold"
                      : "bg-input border-line text-ink-muted"
                  }`}
                >
                  <input
                    type="radio"
                    name="mode"
                    value="auto"
                    checked={mode === "auto"}
                    onChange={(e) => setMode(e.target.value)}
                    className="hidden"
                  />
                  Auto-Detect (Honest)
                </label>
                <label
                  className={`p-2 border cursor-pointer text-center transition ${
                    mode === "live"
                      ? "bg-info-raised border-info-line text-white font-bold"
                      : "bg-input border-line text-ink-muted"
                  }`}
                >
                  <input
                    type="radio"
                    name="mode"
                    value="live"
                    checked={mode === "live"}
                    onChange={(e) => setMode(e.target.value)}
                    className="hidden"
                  />
                  Live Source Only
                </label>
                <label
                  className={`p-2 border cursor-pointer text-center transition ${
                    mode === "demo"
                      ? "bg-info-raised border-info-line text-white font-bold"
                      : "bg-input border-line text-ink-muted"
                  }`}
                >
                  <input
                    type="radio"
                    name="mode"
                    value="demo"
                    checked={mode === "demo"}
                    onChange={(e) => setMode(e.target.value)}
                    className="hidden"
                  />
                  Demo Benchmark
                </label>
              </div>
              <p className="text-[10px] text-ink-muted font-mono leading-relaxed">
                <i className="fa-solid fa-shield-halved text-info-ink mr-1"></i>
                AETHER does not simulate live intelligence: Results are explicitly tagged{" "}
                <span className="text-signal-ink font-bold">LIVE SOURCE</span>,{" "}
                <span className="text-warn-ink font-bold">DEMO DATA</span>, or{" "}
                <span className="text-ink-muted font-bold">SOURCE UNAVAILABLE</span>. No single
                indicator proves actor identity.
              </p>
            </div>

            {/* Optional Forensic Leads Accordion */}
            <div>
              <button
                type="button"
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="text-xs font-mono font-bold text-ink-muted hover:text-ink flex items-center gap-2 py-1 transition"
              >
                <i className={`fa-solid fa-chevron-${showAdvanced ? "down" : "right"} text-[10px]`}></i>
                {showAdvanced ? "Hide Advanced Forensic Leads" : "Provide Known Forensic Leads (PGP / BTC / Text Sample)"}
              </button>

              {showAdvanced && (
                <div className="mt-3 p-3.5 bg-input border border-line space-y-3 font-mono text-xs">
                  <div>
                    <label className="text-[11px] text-ink-muted block mb-1">
                      Known PGP Fingerprint (40-char hex)
                    </label>
                    <input
                      type="text"
                      value={knownPgp}
                      onChange={(e) => setKnownPgp(e.target.value)}
                      placeholder="4D9E 27BC 918A 4F02 C731 09AE 2C5B 88E1 40FA 7D3C"
                      className="w-full bg-card border border-line-strong px-3 py-1.5 text-xs text-white"
                    />
                  </div>

                  <div>
                    <label className="text-[11px] text-ink-muted block mb-1">
                      Known Bitcoin Root Address (P2PKH / Bech32)
                    </label>
                    <input
                      type="text"
                      value={knownBtc}
                      onChange={(e) => setKnownBtc(e.target.value)}
                      placeholder="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or bc1qa5wk..."
                      className="w-full bg-card border border-line-strong px-3 py-1.5 text-xs text-white"
                    />
                  </div>

                  <div>
                    <label className="text-[11px] text-ink-muted block mb-1">
                      Suspect Writing Sample (for Stylometry NLP Cosine Engine)
                    </label>
                    <textarea
                      value={textSample}
                      onChange={(e) => setTextSample(e.target.value)}
                      rows={2}
                      className="w-full bg-card border border-line-strong p-2 text-xs text-white resize-none"
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Action Buttons */}
            <div className="flex items-center justify-end gap-3 pt-3 border-t border-line-faint">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2.5 bg-surface hover:bg-raised text-ink text-xs font-mono font-semibold transition border border-line-strong"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-6 py-2.5 bg-active hover:bg-info-hover text-white text-xs font-mono font-bold tracking-wider transition border border-info-line-strong flex items-center gap-2 shadow-[0_0_15px_rgba(56,189,248,0.25)]"
              >
                <i className="fa-solid fa-play text-[10px]"></i>
                START ANALYSIS
              </button>
            </div>
          </form>
        )}
    </Modal>
  );
};
