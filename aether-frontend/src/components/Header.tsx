"use client";

import React, { useEffect, useState } from "react";
import { CaseListItem, confirmExport, fetchWhoAmI, WhoAmIResult } from "@/lib/api";

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
  const [identity, setIdentity] = useState<WhoAmIResult | null>(null);
  const [confirming, setConfirming] = useState(false);

  // The role badge reflects the key actually in play. Resolving to null on
  // failure is deliberate: showing "investigator" because the lookup failed
  // would be exactly the wrong answer to display on a legal workbench.
  useEffect(() => {
    let cancelled = false;
    fetchWhoAmI().then((result) => {
      if (!cancelled) setIdentity(result);
    });
    return () => {
      cancelled = true;
    };
  }, [apiOnline]);

  const handleAffirmExport = async () => {
    if (!activeEvidenceId) return;
    setConfirming(true);
    const result = await confirmExport(activeEvidenceId);
    setConfirming(false);

    if (result.ok) {
      onShowToast(
        "Export Affirmed",
        `Dossier ${activeEvidenceId} released by ${result.data.operator} and sealed at custody seq ${result.data.seq}.`,
      );
    } else if (result.status === 403) {
      onShowToast("Not Permitted", result.detail);
    } else {
      onShowToast("Confirmation Failed", result.detail);
    }
  };

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
    /*
     * Header height is a working-space constraint, not decoration. This used to
     * render the case switcher and the connection badge *inside* the h1, so at
     * 1280px the heading wrapped to three lines and the brand block measured
     * 145px, pushing the case data below the fold on a laptop.
     *
     * The heading now carries the product name only, which is what a heading is
     * for, and the case switcher and status sit in a metadata row beneath it.
     * That is also better for assistive technology: an h1 containing a
     * dropdown and a status pill pollutes the document outline.
     */
    <header className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-3">
      <div className="flex items-center gap-3 min-w-0">
        {/* Geometric Sunburst Logo (Sharp Square, Steel Tone) */}
        <div
          className="w-12 h-12 flex items-center justify-center text-ink-muted bg-surface border border-line-strong shrink-0"
          aria-hidden="true"
        >
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
        <div className="min-w-0">
          <h1 className="text-xl lg:text-2xl font-extrabold tracking-tight text-ink leading-none">
            AETHER
          </h1>
          <div className="flex items-center gap-2 mt-1.5 flex-wrap">
            {/* Active Case switcher */}
            <div className="relative inline-block">
              <button
                type="button"
                onClick={() => setCaseMenuOpen((v) => !v)}
                aria-expanded={caseMenuOpen}
                aria-haspopup="menu"
                className="text-[11px] font-semibold px-2 py-0.5 bg-info-surface hover:bg-raised text-ink-muted border border-line-strong hover:border-info font-mono flex items-center gap-1.5 transition whitespace-nowrap"
              >
                <span className="w-1.5 h-1.5 bg-info shrink-0" aria-hidden="true" />
                <span>{activeEvidenceId}</span>
                <span className="text-ink-dim">({activeActorName})</span>
                <span className="text-signal-ink font-bold">{activeConfidence}%</span>
                <i
                  className={`fa-solid fa-chevron-down text-[8px] text-ink-dim transition-transform ${
                    caseMenuOpen ? "rotate-180" : ""
                  }`}
                  aria-hidden="true"
                />
                <span className="sr-only">Switch active case</span>
              </button>

              {caseMenuOpen && (
                <div
                  role="menu"
                  aria-label="Recent investigations"
                  className="absolute left-0 mt-1 w-72 bg-overlay border border-line-strong shadow-2xl z-50 font-mono text-xs"
                >
                  <div className="p-2 border-b border-line text-[10px] uppercase font-bold text-ink-dim flex justify-between">
                    <span>Recent investigations</span>
                    <span>{casesList.length} cases</span>
                  </div>
                  <div className="max-h-56 overflow-y-auto scrollbar-thin">
                    {casesList.length === 0 ? (
                      <div className="p-3 text-ink-dim text-[11px]">No other cases loaded.</div>
                    ) : (
                      casesList.map((c) => (
                        <button
                          key={c.evidence_id}
                          type="button"
                          role="menuitem"
                          onClick={() => {
                            if (onSelectCase) onSelectCase(c.evidence_id);
                            setCaseMenuOpen(false);
                            onShowToast(
                              "Case switched",
                              `Loaded investigation ${c.evidence_id} (${c.actor_name}).`
                            );
                          }}
                          className={`w-full text-left p-2.5 min-h-11 hover:bg-raised border-b border-line-faint transition flex items-center justify-between gap-2 ${
                            c.evidence_id === activeEvidenceId ? "bg-active border-info-line" : ""
                          }`}
                        >
                          <div className="min-w-0">
                            <div className="font-bold text-ink flex items-center gap-1.5">
                              <span>{c.evidence_id}</span>
                              <span className="text-[10px] text-ink-dim font-normal truncate">
                                {c.actor_name}
                              </span>
                            </div>
                            <div className="text-[10px] text-ink-dim truncate max-w-[180px]">
                              {c.target_url}
                            </div>
                          </div>
                          <span className="text-[11px] font-bold text-signal-ink shrink-0">
                            {c.confidence}%
                          </span>
                        </button>
                      ))
                    )}
                  </div>
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setCaseMenuOpen(false);
                      onOpenNewInvestigation();
                    }}
                    className="w-full p-2 min-h-11 bg-surface hover:bg-raised text-info-ink font-bold text-[11px] text-center border-t border-line transition flex items-center justify-center gap-1.5"
                  >
                    <i className="fa-solid fa-plus text-[10px]" aria-hidden="true"></i>
                    <span>START NEW INVESTIGATION</span>
                  </button>
                </div>
              )}
            </div>

            {/* Live backend connection badge */}
            <span
              className={`text-[11px] font-mono font-bold px-2 py-0.5 border flex items-center gap-1.5 ${
                apiOnline
                  ? "bg-signal-surface text-signal-ink border-signal-line"
                  : "bg-info-surface text-ink-dim border-line-strong"
              }`}
            >
              <span
                aria-hidden="true"
                className={`w-1.5 h-1.5 ${
                  apiOnline ? "bg-signal aether-live-pulse" : "bg-ink-faint"
                }`}
              />
              {/*
                Short form below xl. The full phrase is 96px wide, which at
                1024px is the difference between the status badge sharing the
                metadata line and being pushed onto a second one.
              */}
              <span className="hidden xl:inline">
                {apiOnline ? "API online" : "API unreachable — showing cached case"}
              </span>
              <span className="xl:hidden">
                {apiOnline ? "online" : "offline"}
              </span>
              <span className="sr-only xl:hidden">
                {apiOnline
                  ? "Backend API is online."
                  : "Backend API is unreachable. Showing the cached case, which is not live data."}
              </span>
            </span>
          </div>
          {/*
            The one-line descriptor sits in the metadata row rather than as its
            own block, and is dropped below xl. At 1024px the brand column is
            squeezed to roughly 250px by the action row, so the descriptor
            pushed the header to 104px and wrapped the status badge onto a
            second line. It is the least load-bearing text in the header: the
            case id, the actor and the connection state are all still present.
          */}
          <p className="hidden xl:block text-[11px] text-ink-dim font-medium mt-1 truncate max-w-[52ch]">
            Dark web threat actor de-anonymization &amp; forensic intelligence for NTRO PS-26151
          </p>
        </div>
      </div>

      {/* Primary action & search */}
      <div className="flex items-center gap-2 w-full lg:w-auto flex-nowrap">
        {/*
          This was the only gradient and the only glow in the product, on the
          primary action, in an interface that is otherwise flat steel with
          hairline borders. The emphasis now comes from a solid raised fill and
          an info-coloured border, which is the same weight the rest of the
          console already uses.
        */}
        <button
          type="button"
          onClick={onOpenNewInvestigation}
          className="px-4 py-2 min-h-11 bg-active hover:bg-info-hover text-ink font-mono text-xs font-bold tracking-wider transition border border-info-line-strong flex items-center gap-2 shrink-0"
        >
          <i className="fa-solid fa-crosshairs text-xs" aria-hidden="true"></i>
          <span>NEW INVESTIGATION</span>
        </button>

        {/* Quick search */}
        <form
          onSubmit={handleSearchSubmit}
          role="search"
          className="flex items-center bg-card pl-3 pr-1 py-1 border border-line w-full sm:w-56 xl:w-72 focus-within:border-info transition"
        >
          <label htmlFor="aether-target-search" className="sr-only">
            Search by onion address, PGP fingerprint, or Bitcoin wallet
          </label>
          <input
            id="aether-target-search"
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search .onion, PGP, BTC..."
            className="bg-transparent text-sm w-full text-ink placeholder:text-ink-faint font-medium font-mono py-1"
          />
          <button
            type="submit"
            aria-label="Run recon probe"
            className="w-9 h-9 bg-active hover:bg-info-hover text-ink flex items-center justify-center transition shrink-0 border border-line-strong"
          >
            <i className="fa-solid fa-magnifying-glass text-xs" aria-hidden="true"></i>
          </button>
        </form>

        <a
          href="/verify.html"
          target="_blank"
          rel="noopener noreferrer"
          aria-label="Open the independent chain verifier in a new tab"
          className="w-11 h-11 bg-card border border-line flex items-center justify-center text-ink-dim hover:text-ink hover:border-line-active transition shrink-0"
        >
          <i className="fa-solid fa-shield-halved text-sm" aria-hidden="true"></i>
        </a>

        <button
          type="button"
          onClick={handleAffirmExport}
          disabled={confirming || !identity?.can_confirm_export}
          className={`h-11 px-3 border flex items-center gap-2 text-[11px] font-mono font-bold transition shrink-0 ${
            identity?.can_confirm_export
              ? "bg-info-raised hover:bg-info-hover text-info-ink border-info-line-strong"
              : "bg-card text-ink-faint border-line cursor-not-allowed"
          }`}
        >
          {confirming ? (
            <span
              className="inline-block w-3 h-3 border border-info-ink border-t-transparent rounded-full animate-spin"
              aria-hidden="true"
            />
          ) : (
            <i className="fa-solid fa-file-signature text-xs" aria-hidden="true"></i>
          )}
          <span className="hidden xl:inline">AFFIRM EXPORT</span>
          <span className="sr-only">
            {identity?.can_confirm_export
              ? "Affirm release of this dossier"
              : "Only an investigator with export rights can affirm a release"}
          </span>
        </button>

        {identity ? (
          <span
            className={`h-11 px-3 border flex items-center gap-2 text-[11px] font-mono font-bold shrink-0 ${
              identity.role === "investigator"
                ? "bg-signal-surface text-signal-ink border-signal-line"
                : "bg-warn-surface text-warn-ink border-warn-line"
            }`}
          >
            <i
              className={`fa-solid ${identity.can_write ? "fa-user-shield" : "fa-user-lock"} text-xs`}
              aria-hidden="true"
            />
            <span className="uppercase">{identity.role}</span>
            <span className="sr-only">
              , {identity.operator}, {identity.can_write ? "read and write" : "read only"}
            </span>
          </span>
        ) : (
          <span className="h-11 px-3 border border-line bg-card flex items-center text-[11px] font-mono text-ink-dim">
            Identity unresolved
            <span className="sr-only">
              . The role of the current API key could not be determined, so permissions are
              unknown.
            </span>
          </span>
        )}
      </div>
    </header>
  );
};

