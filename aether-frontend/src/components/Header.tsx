"use client";

import React, { useState } from "react";
import { CaseListItem } from "@/lib/api";

interface HeaderProps {
  apiOnline: boolean;
  activeEvidenceId?: string;
  activeActorName?: string;
  activeConfidence?: number;
  casesList?: CaseListItem[];
  onSelectCase?: (evidenceId: string) => void;
  onOpenNewInvestigation: () => void;
  onSearch: (query: string) => void;
  onShowToast: (title: string, message: string) => void;
}

export const Header: React.FC<HeaderProps> = ({
  apiOnline,
  activeEvidenceId = "AT-2026-0047",
  activeActorName = "UNC-3844",
  activeConfidence = 94.8,
  casesList = [],
  onSelectCase,
  onOpenNewInvestigation,
  onSearch,
  onShowToast,
}) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [caseMenuOpen, setCaseMenuOpen] = useState(false);

  const handleSearchSubmit = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!searchQuery.trim()) {
      onShowToast(
        "Target Required",
        "Please enter a .onion URL, PGP fingerprint, or Bitcoin wallet."
      );
      return;
    }
    onSearch(searchQuery.trim());
  };

  return (
    <header className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4">
      <div className="flex items-center gap-4">
        {/* Geometric Sunburst Logo (Sharp Square, Steel Tone) */}
        <div className="w-12 h-12 flex items-center justify-center text-slate-200 bg-[#121721] border border-[#273447]">
          <svg
            className="w-8 h-8"
            viewBox="0 0 100 100"
            fill="none"
            stroke="currentColor"
            strokeWidth="8"
            strokeLinecap="square"
          >
            <line x1="50" y1="12" x2="50" y2="28" />
            <line x1="50" y1="72" x2="50" y2="88" />
            <line x1="12" y1="50" x2="28" y2="50" />
            <line x1="72" y1="50" x2="88" y2="50" />
            <line x1="23" y1="23" x2="35" y2="35" />
            <line x1="65" y1="65" x2="77" y2="77" />
            <line x1="23" y1="77" x2="35" y2="65" />
            <line x1="65" y1="35" x2="77" y2="23" />
          </svg>
        </div>
        <div>
          <h1 className="text-2xl lg:text-3xl font-extrabold tracking-tight text-white flex items-center gap-2 flex-wrap">
            Hello, Lead Investigator!
            {/* Active Case Badge with Switcher */}
            <div className="relative inline-block">
              <button
                type="button"
                onClick={() => setCaseMenuOpen(!caseMenuOpen)}
                className="text-xs font-semibold px-2.5 py-1 bg-[#161d28] hover:bg-[#1e2736] text-slate-200 border border-[#273447] hover:border-sky-500 font-mono flex items-center gap-1.5 transition"
                title="Switch active forensic case"
              >
                <span className="w-2 h-2 bg-sky-400"></span>
                <span>{activeEvidenceId}</span>
                <span className="text-slate-400">({activeActorName})</span>
                <span className="text-emerald-400 font-bold">{activeConfidence}%</span>
                <i className="fa-solid fa-chevron-down text-[9px] text-slate-400 ml-0.5"></i>
              </button>

              {caseMenuOpen && (
                <div className="absolute left-0 mt-1 w-72 bg-[#0c1017] border border-[#273447] shadow-2xl z-50 font-mono text-xs">
                  <div className="p-2 border-b border-[#1c2432] text-[10px] uppercase font-bold text-slate-400 flex justify-between">
                    <span>Recent Investigations</span>
                    <span>{casesList.length} Cases</span>
                  </div>
                  <div className="max-h-56 overflow-y-auto">
                    {casesList.length === 0 ? (
                      <div className="p-3 text-slate-500 text-[11px]">No other cases loaded.</div>
                    ) : (
                      casesList.map((c) => (
                        <button
                          key={c.evidence_id}
                          type="button"
                          onClick={() => {
                            if (onSelectCase) onSelectCase(c.evidence_id);
                            setCaseMenuOpen(false);
                            onShowToast("Case Switched", `Loaded investigation ${c.evidence_id} (${c.actor_name}).`);
                          }}
                          className={`w-full text-left p-2.5 hover:bg-[#141d2a] border-b border-[#17202c] transition flex items-center justify-between ${
                            c.evidence_id === activeEvidenceId ? "bg-[#141e2c] border-sky-500/40" : ""
                          }`}
                        >
                          <div>
                            <div className="font-bold text-white flex items-center gap-1.5">
                              <span>{c.evidence_id}</span>
                              <span className="text-[10px] text-slate-400 font-normal">
                                {c.actor_name}
                              </span>
                            </div>
                            <div className="text-[10px] text-slate-500 truncate max-w-[180px]">
                              {c.target_url}
                            </div>
                          </div>
                          <span className="text-[11px] font-bold text-emerald-400">
                            {c.confidence}%
                          </span>
                        </button>
                      ))
                    )}
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setCaseMenuOpen(false);
                      onOpenNewInvestigation();
                    }}
                    className="w-full p-2 bg-[#121822] hover:bg-[#1a2332] text-sky-300 font-bold text-[11px] text-center border-t border-[#1c2432] transition flex items-center justify-center gap-1.5"
                  >
                    <i className="fa-solid fa-plus text-[10px]"></i>
                    <span>START NEW INVESTIGATION</span>
                  </button>
                </div>
              )}
            </div>

            {/* Live Backend Connection Badge */}
            <span
              className={`text-[11px] font-mono font-bold px-2 py-0.5 border flex items-center gap-1.5 transition ${
                apiOnline
                  ? "bg-[#102a1b] text-[#22c55e] border-[#1f5735]"
                  : "bg-[#161d28] text-slate-400 border-[#273447]"
              }`}
            >
              <span
                className={`w-1.5 h-1.5 ${
                  apiOnline ? "bg-[#22c55e] animate-pulse" : "bg-slate-500"
                }`}
              ></span>
              {apiOnline ? "API ONLINE :8000" : "STANDALONE / SIM"}
            </span>
          </h1>
          <p className="text-slate-400 text-sm font-medium mt-0.5">
            Dark web threat actor de-anonymization &amp; forensic intelligence for NTRO PS-26151
          </p>
        </div>
      </div>

      {/* Primary Action Button & Search Bar */}
      <div className="flex items-center gap-3 w-full lg:w-auto flex-wrap sm:flex-nowrap">
        {/* NEW INVESTIGATION BUTTON */}
        <button
          type="button"
          onClick={onOpenNewInvestigation}
          className="px-4 py-2 bg-gradient-to-r from-sky-600 to-blue-700 hover:from-sky-500 hover:to-blue-600 text-white font-mono text-xs font-bold tracking-wider transition border border-sky-400/50 flex items-center gap-2 shadow-[0_0_12px_rgba(56,189,248,0.25)] shrink-0"
          title="Launch new dark web target investigation"
        >
          <i className="fa-solid fa-crosshairs text-xs"></i>
          <span>+ NEW INVESTIGATION</span>
        </button>

        {/* Quick Search Input */}
        <form
          onSubmit={handleSearchSubmit}
          className="flex items-center bg-[#0d1017] pl-4 pr-1.5 py-1.5 border border-[#1e2533] w-full sm:w-80 focus-within:border-[#3b495f] transition"
        >
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search .onion, PGP, BTC..."
            className="bg-transparent text-sm w-full outline-none text-slate-100 placeholder-slate-500 font-medium font-mono"
          />
          <button
            type="submit"
            className="w-8 h-8 bg-[#1e2736] hover:bg-[#283448] text-white flex items-center justify-center transition shrink-0 border border-[#303d52]"
            title="Execute Recon Probe"
          >
            <i className="fa-solid fa-magnifying-glass text-xs"></i>
          </button>
        </form>

        <button
          type="button"
          onClick={() =>
            onShowToast(
              "Secure Channels",
              "Zero unread operational dispatches on encrypted onion bridge."
            )
          }
          className="w-10 h-10 bg-[#0d1017] border border-[#1e2533] flex items-center justify-center text-slate-400 hover:text-white transition shrink-0"
          title="Secure Channels"
        >
          <i className="fa-regular fa-comment-dots text-sm"></i>
        </button>

        <a
          href="/verify.html"
          target="_blank"
          rel="noopener noreferrer"
          className="w-10 h-10 bg-[#0d1017] border border-[#1e2533] flex items-center justify-center text-slate-400 hover:text-white transition shrink-0"
          title="Independent Chain Verifier (opens offline in a new tab)"
        >
          <i className="fa-solid fa-shield-halved text-sm"></i>
        </a>

        <button
          type="button"
          onClick={() =>
            onShowToast(
              "System Alerts",
              "Origin discovery probe #14 completed: Apache /server-status verified."
            )
          }
          className="w-10 h-10 bg-[#0d1017] border border-[#1e2533] flex items-center justify-center text-slate-400 hover:text-white transition shrink-0"
          title="System Alerts"
        >
          <i className="fa-regular fa-bell text-sm"></i>
        </button>
      </div>
    </header>
  );
};

