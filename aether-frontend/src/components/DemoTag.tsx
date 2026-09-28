"use client";

import React from "react";

interface DemoTagProps {
  /** What the backend would have to expose for this figure to become real. */
  requires?: string;
  className?: string;
}

/**
 * Marks a figure the backend does not supply.
 *
 * AETHER is a workbench that output ends up in front of a court, so a number
 * without a provenance source is worse than no number at all: it reads as
 * evidence. Anything shown through this component is explicitly a
 * demonstration value, and the icon carries the reason, not just the label.
 *
 * The `sr-only` text is the part that matters. A sighted analyst sees a small
 * grey chip; a screen-reader user hears "demonstration value, not live
 * evidence" before the number is announced.
 */
export const DemoTag: React.FC<DemoTagProps> = ({ requires, className = "" }) => (
  <span
    className={`inline-flex items-center gap-1 align-middle text-[9px] font-bold uppercase tracking-wider text-warn-ink bg-warn-surface border border-warn-line px-1.5 py-px ${className}`}
    title={
      requires
        ? `Demonstration value, not live evidence. Requires ${requires} to become real.`
        : "Demonstration value, not live evidence."
    }
  >
    <i className="fa-solid fa-triangle-exclamation text-[8px]" aria-hidden="true" />
    <span className="sr-only">Demonstration value, not live evidence. </span>
    Demo
  </span>
);
