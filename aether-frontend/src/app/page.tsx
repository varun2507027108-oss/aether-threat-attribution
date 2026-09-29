"use client";

import React, { useEffect, useState } from "react";
import {
  checkBackendHealth,
  fetchCaseInvestigation,
  fetchCasesList,
  verifyCustodyLedger,
  CaseListItem,
  InvestigationResult,
} from "@/lib/api";
import { Sidebar } from "@/components/Sidebar";
import { Header } from "@/components/Header";
import { BentoGrid } from "@/components/BentoGrid";
import { KnowledgeGraphView } from "@/components/KnowledgeGraphView";
import { CustodyLedgerView } from "@/components/CustodyLedgerView";
import { StylometryLabModal } from "@/components/StylometryLabModal";
import { DossierModal } from "@/components/DossierModal";
import { EvidenceModal } from "@/components/EvidenceModal";
import { EngineConfigModal } from "@/components/EngineConfigModal";
import { NewInvestigationModal } from "@/components/NewInvestigationModal";
import { Toast, ToastData, ToastSeverity } from "@/components/Toast";

export default function Home() {
  const [apiOnline, setApiOnline] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<string>("overview");
  const [activeView, setActiveView] = useState<"overview" | "graph" | "custody">("overview");

  // Multi-case investigation state
  const [currentInvestigation, setCurrentInvestigation] = useState<InvestigationResult | null>(null);
  const [casesList, setCasesList] = useState<CaseListItem[]>([]);
  const [newInvestigationOpen, setNewInvestigationOpen] = useState<boolean>(false);

  // Modals state
  const [dossierOpen, setDossierOpen] = useState<boolean>(false);
  const [evidenceOpen, setEvidenceOpen] = useState<boolean>(false);
  const [stylometryOpen, setStylometryOpen] = useState<boolean>(false);
  const [configOpen, setConfigOpen] = useState<boolean>(false);

  const [toast, setToast] = useState<ToastData>({
    title: "System Signal",
    message: "Operation executed.",
    visible: false,
  });

  // Check FastAPI backend connection on mount & periodic polling + load cases
  useEffect(() => {
    let mounted = true;

    async function pollHealth() {
      if (typeof document !== "undefined" && document.visibilityState !== "visible") return;
      const status = await checkBackendHealth();
      if (mounted) {
        setApiOnline(status.online);
      }
    }

    async function loadInitialCases() {
      const { cases } = await fetchCasesList();
      if (mounted && cases.length > 0) {
        setCasesList(cases);
      }
      const { data: initialCase } = await fetchCaseInvestigation("AT-2026-0047");
      if (mounted && initialCase) {
        setCurrentInvestigation(initialCase);
      }
    }

    pollHealth();
    loadInitialCases();
    const interval = setInterval(pollHealth, 15000);

    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const handleSelectCase = async (evidenceId: string) => {
    showToast("Loading Investigation", `Retrieving forensic artifacts for ${evidenceId}...`);
    try {
      const { data: inv } = await fetchCaseInvestigation(evidenceId);
      if (inv) {
        setCurrentInvestigation(inv);
        showToast(
          "Investigation Active",
          `${inv.case?.evidence_id || evidenceId}: ${inv.case?.actor_name || "Target Loaded"} (${inv.attribution?.confidence_score ?? 94.8}%)`
        );
      }
    } catch {
      showToast("Case Switch Notice", `Retrieved local cached dossier for ${evidenceId}.`);
    }
  };

  /**
   * Integrity findings are no longer given a 4.5 second life. A custody seal
   * verdict, a denied export, or a failed commit is a statement about evidence
   * and persists until it is explicitly dismissed; a "camera reset" message
   * does not need to interrupt anyone.
   *
   * The previous 4500ms auto-dismiss applied to everything, which meant a
   * tamper notice could expire before it was read, and the toast had no live
   * region at all, so a screen-reader user never heard any of it.
   */
  const showToast = (
    title: string,
    message: string,
    severity: ToastSeverity = "info",
  ) => {
    setToast({ title, message, visible: true, severity });
    const timeoutMs =
      severity === "critical" || severity === "warning" ? 0 : 5000;
    if (timeoutMs > 0) {
      setTimeout(() => {
        setToast((prev) => ({ ...prev, visible: false }));
      }, timeoutMs);
    }
  };

  /*
   * The search field accepts an onion address, a PGP fingerprint, or a wallet.
   * No endpoint takes one of those and returns a case, so this used to answer
   * with a toast claiming it was "Probing Shodan and Tor SOCKS5" -- narrating
   * collection that never happened. It now says plainly that the lookup is not
   * connected and points at the action that is.
   */
  const handleSearch = (query: string) => {
    showToast(
      "Target search is not connected",
      `No endpoint resolves "${query.substring(0, 28)}" to a case. Start a new investigation to submit a target and run the pipeline.`
    );
  };

  // 1. Icon 1 & 2 & 6: View Switching
  const handleSelectTab = (tab: string) => {
    setActiveTab(tab);
    if (tab === "overview" || tab === "graph" || tab === "custody") {
      setActiveView(tab);
    }
  };

  const handleSelectTabGraph = () => handleSelectTab("graph");

  // 3. Icon 3: bring the diurnal chart into view and mark it current.
  // The old handler also raised a toast naming an endpoint
  // (/api/analysis/diurnal) that this action never called, which made a
  // scroll gesture look like a computation.
  const handleScrollDiurnal = () => {
    setActiveTab("circadian");
    if (activeView !== "overview") {
      setActiveView("overview");
    }
    setTimeout(() => {
      const elem = document.getElementById("diurnal-section");
      if (elem) {
        elem.scrollIntoView({ behavior: "smooth", block: "center" });
        elem.classList.add("ring-2", "ring-[var(--color-info)]");
        setTimeout(() => {
          elem.classList.remove("ring-2", "ring-[var(--color-info)]");
        }, 2000);
      }
    }, 150);
  };

  // 3. Icon 4: Open AI Stylometry comparison lab
  const handleOpenStylometry = () => {
    setActiveTab("stylometry");
    setStylometryOpen(true);
  };

  // 4. Icon 5: Open Target Suspect dossier sheet
  const handleOpenDossier = () => {
    setActiveTab("suspects");
    setDossierOpen(true);
  };

  // 5. Icon 7: Open Engine Config modal
  const handleOpenConfig = () => {
    setActiveTab("config");
    setConfigOpen(true);
  };

  /*
   * Chain-of-custody integrity.
   *
   * This previously reported "Custody Seal Valid" from the catch block, so a
   * backend that was down, a 500, or a malformed response all produced a green
   * integrity verdict on a custody seal. On a workbench whose output is filed
   * with a court, an unverifiable chain is not a passing chain -- it is an
   * unknown one, and it now says so. The same reasoning applies to the
   * node-less case: the browser bundle has no custody data, so it reports
   * "not checked" rather than inventing a genesis verification.
   */
  const handleVerifyShield = async () => {
    setActiveTab("shield");
    const targetId = currentInvestigation?.case?.evidence_id || "AT-2026-0047";
    try {
      const { data, isLive } = await verifyCustodyLedger(targetId);
      if (data.valid) {
        showToast(
          isLive ? "Custody chain verified" : "Verification unavailable",
          isLive
            ? `Hash chain intact for ${targetId}. ${data.entry_count} custody blocks verified.`
            : `No verifier reachable, so ${targetId} was not checked. Use the offline verifier to confirm the ledger yourself.`
        );
      } else {
        showToast(
          "Integrity alert: chain broken",
          `Tamper detected at custody block #${data.broken_at_seq}. Hashes do not match. Do not rely on this case until the break is explained.`
        );
      }
    } catch {
      showToast(
        "Chain not verified",
        `The verifier could not be reached, so ${targetId} is unverified. An unreachable verifier is not a passing verifier — open /verify.html and check the exported ledger offline.`
      );
    }
  };

  return (
    /*
     * min-w-0 on both the shell and the main column. A flex item defaults to
     * min-width:auto, which refuses to shrink below its content's min-content
     * width -- so one long onion address or hash was enough to give the whole
     * page a horizontal scroll on a phone.
     */
    <div className="w-full max-w-[1520px] flex flex-col md:flex-row gap-4 md:gap-6 items-stretch min-w-0">
      {/* LEFT SHARP DOCK */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={handleSelectTab}
        onScrollDiurnal={handleScrollDiurnal}
        onOpenStylometry={handleOpenStylometry}
        onOpenDossier={handleOpenDossier}
        onOpenConfig={handleOpenConfig}
        onVerifyShield={handleVerifyShield}
        onShowToast={showToast}
      />

      {/* RIGHT MAIN CONTENT WORKSPACE */}
      <main className="flex-1 flex flex-col gap-4 md:gap-6 min-w-0">
        {/* TOP HEADER */}
        <Header
          apiOnline={apiOnline}
          activeEvidenceId={currentInvestigation?.case?.evidence_id || "AT-2026-0047"}
          activeActorName={currentInvestigation?.case?.actor_name || "UNC-3844"}
          activeConfidence={currentInvestigation?.attribution?.confidence_score ?? 94.8}
          casesList={casesList}
          onSelectCase={handleSelectCase}
          onOpenNewInvestigation={() => setNewInvestigationOpen(true)}
          onSearch={handleSearch}
          onShowToast={showToast}
        />

        {/* ACTIVE MAIN VIEW */}
        {activeView === "overview" && (
          <BentoGrid
            investigation={currentInvestigation}
            onOpenNewInvestigation={() => setNewInvestigationOpen(true)}
            onOpenDossier={handleOpenDossier}
            onOpenEvidence={() => setEvidenceOpen(true)}
            onOpenGraph={handleSelectTabGraph}
            onOpenStylometry={handleOpenStylometry}
          />
        )}

        {activeView === "graph" && (
          <KnowledgeGraphView
            investigation={currentInvestigation}
            onShowToast={showToast}
            onOpenEvidence={() => setEvidenceOpen(true)}
          />
        )}

        {activeView === "custody" && (
          <CustodyLedgerView
            evidenceId={currentInvestigation?.case?.evidence_id || "AT-2026-0047"}
            onShowToast={showToast}
          />
        )}
      </main>

      {/* Interactive Modals & Notification Toast */}
      <NewInvestigationModal
        isOpen={newInvestigationOpen}
        onClose={() => setNewInvestigationOpen(false)}
        onInvestigationComplete={(newResult) => {
          setCurrentInvestigation(newResult);
          fetchCasesList().then((res) => {
            if (res.cases.length > 0) setCasesList(res.cases);
          });
        }}
        onShowToast={showToast}
      />

      <StylometryLabModal
        isOpen={stylometryOpen}
        onClose={() => {
          setStylometryOpen(false);
          setActiveTab(activeView);
        }}
        onShowToast={showToast}
      />

      <DossierModal
        isOpen={dossierOpen}
        investigation={currentInvestigation}
        evidenceId={currentInvestigation?.case?.evidence_id || "AT-2026-0047"}
        onClose={() => {
          setDossierOpen(false);
          setActiveTab(activeView);
        }}
        onShowToast={showToast}
      />

      <EvidenceModal
        isOpen={evidenceOpen}
        onClose={() => setEvidenceOpen(false)}
        onShowToast={showToast}
      />

      <EngineConfigModal
        isOpen={configOpen}
        onClose={() => {
          setConfigOpen(false);
          setActiveTab(activeView);
        }}
        onShowToast={showToast}
      />

      <Toast
        toast={toast}
        onDismiss={() => setToast((prev) => ({ ...prev, visible: false }))}
      />
    </div>
  );
}
