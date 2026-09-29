"use client";

import React from "react";
import type { ToastSeverity } from "@/components/Toast";

interface SidebarProps {
  activeTab: string;
  onSelectTab: (tab: string) => void;
  onScrollDiurnal: () => void;
  onOpenStylometry: () => void;
  onOpenDossier: () => void;
  onOpenConfig: () => void;
  onVerifyShield: () => void;
  onShowToast: (title: string, message: string, severity?: ToastSeverity) => void;
}

interface RailItem {
  key: string;
  icon: string;
  label: string;
  hint: string;
  onClick: () => void;
  /** Renders in its own group, below the primary navigation. */
  footer?: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  onScrollDiurnal,
  onOpenStylometry,
  onOpenDossier,
  onOpenConfig,
  onVerifyShield,
  onShowToast,
}) => {
  const primary: RailItem[] = [
    {
      key: "overview",
      icon: "fa-shapes",
      label: "Overview",
      hint: "Recon telemetry & indicators",
      onClick: () => {
        onSelectTab("overview");
        onShowToast("Overview", "Recon telemetry & forensic indicators.");
      },
    },
    {
      key: "graph",
      icon: "fa-diagram-project",
      label: "Knowledge graph",
      hint: "STIX 2.1 entity graph",
      onClick: () => {
        onSelectTab("graph");
        onShowToast("Knowledge graph", "Interactive STIX 2.1 entity graph.");
      },
    },
    {
      key: "circadian",
      icon: "fa-chart-simple",
      label: "Diurnal engine",
      hint: "UTC posting distribution",
      onClick: onScrollDiurnal,
    },
    {
      key: "stylometry",
      icon: "fa-fingerprint",
      label: "Stylometry lab",
      hint: "Compare two documents",
      onClick: onOpenStylometry,
    },
    {
      key: "suspects",
      icon: "fa-users-viewfinder",
      label: "Target dossier",
      hint: "Suspect profile sheet",
      onClick: onOpenDossier,
    },
    {
      key: "custody",
      icon: "fa-clock",
      label: "Custody ledger",
      hint: "Tamper-evident chain",
      onClick: () => {
        onSelectTab("custody");
        onShowToast("Custody ledger", "Tamper-evident custody chain.");
      },
    },
  ];

  const footer: RailItem[] = [
    {
      key: "config",
      icon: "fa-sliders",
      label: "Engine config",
      hint: "Tor & backend settings",
      onClick: onOpenConfig,
      footer: true,
    },
    {
      key: "shield",
      icon: "fa-shield-halved",
      label: "Verify chain",
      hint: "Check ledger integrity",
      onClick: onVerifyShield,
      footer: true,
    },
  ];

  const renderItem = (item: RailItem) => {
    const isActive = activeTab === item.key;
    return (
      <li key={item.key} className="flex justify-center shrink-0">
        <button
          type="button"
          onClick={item.onClick}
          aria-current={isActive ? "page" : undefined}
          aria-label={item.label}
          className={`group relative w-11 h-11 flex items-center justify-center transition ${
            isActive
              ? "bg-active text-ink border border-line-active shadow-[0_0_0_1px_var(--color-line-active)]"
              : "bg-info-surface text-ink-muted hover:text-ink border border-transparent hover:border-line-strong hover:bg-raised"
          }`}
        >
          <i className={`fa-solid ${item.icon} text-sm`} aria-hidden="true" />
          {/*
            The tooltip is decorative: the button already carries an aria-label,
            so this is hidden from assistive tech to avoid announcing the label
            twice. It opens on hover and on keyboard focus.

            `whitespace-nowrap` removed and a max-width added. The tooltip is
              absolutely positioned at `left-full`, so it escapes the 62px rail and
              lands on top of whatever view it was opened over — in the graph
              screenshot it covered the panel title. Letting the text wrap inside
              a bounded box keeps the caption next to its button, and the hairline
              border (rather than the transparent background it used to compute)
              makes it read as an overlay rather than a bleed-through. */}
          <span
            aria-hidden="true"
            className="hidden md:block absolute left-full top-1/2 -translate-y-1/2 ml-3 max-w-[180px] bg-overlay text-ink-muted border border-overlay-line text-[12px] px-2.5 py-1.5 opacity-0 pointer-events-none translate-x-[-4px] group-hover:opacity-100 group-hover:translate-x-0 group-focus-visible:opacity-100 group-focus-visible:translate-x-0 transition-all duration-150 z-50 font-mono"
          >
            {item.label}
            {/* --color-ink-faint was retuned to clear 4.5:1 on the surfaces it
                is actually used on. On the old value this line measured 4.30:1
                on the tooltip background, which is a WCAG AA failure for 10px
                text and the product's own documented floor size. */}
            <span className="block text-ink-faint text-[10px]">{item.hint}</span>
          </span>
        </button>
      </li>
    );
  };

  return (
    /* Below md the rail WRAPS rather than scrolls.

       Measured at 390px: the rail box was 144px wide with 294px of 44px
       buttons inside it, and the overflow was not merely clipped — a hit test
       at the centre of "Stylometry lab" returned the Engine config button, and
       the centre of "Custody ledger" returned the profile monogram. Three
       primary views were unreachable by pointer on a phone.

       Eight 44px targets plus gaps is ~394px against 374px available, so no
       amount of horizontal scrolling makes them all fit. Wrapping puts them on
       two rows: every button visible, every target full-size, nothing occluded
       because nothing overlaps. At md and above this is a plain vertical rail,
       unchanged. */
    <aside
      aria-label="Primary navigation"
      className="flex flex-wrap md:flex-col items-center justify-start gap-2 bg-card py-3 px-2 md:py-5 md:px-2 border border-line shrink-0 self-center md:self-start z-20 max-w-full"
    >
      {/* Mark */}
      <div className="flex flex-wrap md:flex-col items-center gap-4 min-w-0 w-full md:w-auto">
        <div
          className="w-11 h-11 flex items-center justify-center text-ink-muted bg-surface border border-line-strong shrink-0"
          aria-hidden="true"
        >
          <i className="fa-solid fa-crosshairs text-base"></i>
        </div>

        {/*
          On a phone the rail is nine 44px targets plus gaps -- 444px in a
          390px viewport -- so it scrolls sideways rather than pushing the
          whole page into a horizontal scroll or wrapping into a tall block
          that pushes the case data off screen.
        */}
        <nav aria-label="Investigation views" className="w-full md:w-auto">
          {/* `flex-wrap` below md, column at md and up. The previous `w-max`
              inside a fixed-width rail is what produced the overlap. */}
          <ul className="flex flex-wrap md:flex-col items-center justify-center gap-1.5 list-none p-0 m-0">
            {primary.map(renderItem)}
          </ul>
        </nav>
      </div>

      <div className="flex flex-wrap md:flex-col items-center justify-center gap-1.5 w-full md:w-auto">
        <nav aria-label="Tools and integrity" className="w-full md:w-auto">
          <ul className="flex flex-wrap md:flex-col items-center justify-center gap-1.5 list-none p-0 m-0">
            {footer.map(renderItem)}
          </ul>
        </nav>
        {/* The officer monogram. Below md it sat in the same visual run as the
            nav buttons and, at 390px, was the element hit-tested when a probe
            aimed at "Custody ledger" — the tail of the scrolling rail sat under
            it. A hairline divider plus its own background separates the
            identity control from the navigation it was being confused with. */}
        <div
          aria-hidden="true"
          className="w-11 h-px bg-line md:hidden my-1 shrink-0"
        />
        {/* Nothing here scrolls. Below md the rail WRAPS to a second row:
            eight 44px targets plus gaps is ~394px against 374px of available
            width, so a horizontal scroller could never fit them, and a control
            that has to be discovered by swiping is not discoverable. Wrapping
            keeps every button visible at full size. */}
        {/* `md:justify-between` on the aside distributes the two groups to the
            top and bottom of the rail, which at md+ stretched the rail to
            1198px — taller than the 900px viewport — and pushed Engine config,
            Verify chain and the officer control below the fold, where they
            existed but could not be hit. The rail now packs from the top at
            every width, so the whole set of controls is always on screen. */}

        {/*
          This was a stock portrait from Unsplash standing in for the logged-in
          officer. It sent a request to a third party on every load, and on a
          legal workbench an unrelated person's face next to a clearance badge
          is worse than no face at all. A monogram carries the same
          affordance without either problem.
        */}
        <button
          type="button"
          onClick={() =>
            onShowToast(
              "Officer credentials",
              "Lead Cyber Forensics Officer (NTRO-26151-INV01). Clearance: top secret."
            )
          }
          aria-label="Lead investigator profile"
          className="w-11 h-11 border border-line-strong hover:border-line-active bg-surface hover:bg-raised mt-1 flex items-center justify-center transition shrink-0"
        >
          <span className="font-mono text-[11px] font-bold text-ink-dim" aria-hidden="true">
            LI
          </span>
        </button>
      </div>
    </aside>
  );
};
