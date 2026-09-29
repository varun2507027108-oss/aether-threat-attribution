"use client";

import React from "react";

export type ToastSeverity = "info" | "success" | "warning" | "critical";

export interface ToastData {
  title: string;
  message: string;
  visible: boolean;
  /**
   * Drives announcement and persistence. A custody or export verdict is a
   * finding of fact about evidence, so it must not quietly expire while the
   * analyst is reading it, and a failure must interrupt.
   */
  severity?: ToastSeverity;
}

interface ToastProps {
  toast: ToastData;
  onDismiss: () => void;
}

const SEVERITY_STYLE: Record<ToastSeverity, { border: string; icon: string; ink: string }> = {
  info: { border: "border-line-strong", icon: "fa-satellite-dish", ink: "text-ink" },
  success: { border: "border-signal-line", icon: "fa-circle-check", ink: "text-signal-ink" },
  warning: { border: "border-warn-line", icon: "fa-triangle-exclamation", ink: "text-warn-ink" },
  critical: { border: "border-alert-line", icon: "fa-shield-halved", ink: "text-alert-ink" },
};

/**
 * Every integrity verdict in this product arrives through this one component,
 * which previously had no `role`, no live region, no close button, a 4.5s
 * auto-dismiss, and a click-anywhere-to-dismiss handler on the whole card.
 *
 * The last one is the serious problem: it meant that selecting the text of
 * "Tamper detected at custody block #7" destroyed the finding, because selecting
 * text starts with a click. For a tool whose output is filed with a court, a
 * verdict that vanishes when you try to copy it is not a verdict.
 *
 * Now: announced, severity-aware, dismissible by an explicit control, and
 * persistent for anything that is not routine.
 */
export const Toast: React.FC<ToastProps> = ({ toast, onDismiss }) => {
  const severity: ToastSeverity = toast.severity ?? "info";
  const style = SEVERITY_STYLE[severity];

  return (
    <div
      // Errors interrupt; everything else is announced without cutting across
      // whatever the analyst is currently reading.
      role={severity === "critical" ? "alert" : "status"}
      aria-live={severity === "critical" ? "assertive" : "polite"}
      aria-atomic="true"
      className={`fixed bottom-6 right-6 bg-card border ${style.border} px-4 py-3 transform transition-all duration-300 z-50 flex items-start gap-3 ${
        toast.visible ? "translate-y-0 opacity-100" : "translate-y-24 opacity-0 pointer-events-none"
      }`}
    >
      <div
        className={`w-8 h-8 shrink-0 border border-line-strong flex items-center justify-center ${
          severity === "critical" ? "bg-alert-surface" : "bg-info-surface"
        }`}
        aria-hidden="true"
      >
        <i className={`fa-solid ${style.icon} text-xs ${style.ink}`}></i>
      </div>
      <div className="min-w-0">
        {/* Not a heading. A hidden toast was still appearing in the document
            outline as an h4 on every view, including the ones where it was
            invisible. */}
        <p className={`text-[12px] font-bold ${style.ink}`}>{toast.title}</p>
        <p className="text-[12px] text-ink-muted mt-0.5 leading-snug break-words">
          {toast.message}
        </p>
      </div>
      {/* The only dismissal affordance, so clicking or selecting the text no
          longer destroys the finding. */}
      <button
        type="button"
        onClick={onDismiss}
        aria-label={`Dismiss: ${toast.title}`}
        className="shrink-0 w-8 h-8 -m-1 flex items-center justify-center text-ink-faint hover:text-ink hover:bg-raised transition"
      >
        <i className="fa-solid fa-xmark text-xs" aria-hidden="true"></i>
      </button>
    </div>
  );
};
