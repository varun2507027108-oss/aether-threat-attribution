"use client";

import React, { useCallback } from "react";
import { applyTheme, persistTheme, useThemeName, type Theme } from "@/lib/theme";

/*
 * The theme switch.
 *
 * The state it renders is not its own: it reads the same <html data-theme>
 * attribute the rest of the product reads, through the same hook. That means
 * the button cannot disagree with the page -- there is no second copy of the
 * preference for the two to drift apart -- and it costs nothing to keep
 * correct if the theme is ever changed from anywhere else.
 *
 * Selection order (stored choice, then OS preference, then dark) is documented
 * in lib/theme.ts and repeated in the blocking script in app/layout.tsx.
 */
export const ThemeToggle: React.FC = () => {
  const theme = useThemeName();

  const toggle = useCallback(() => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    applyTheme(next);
    persistTheme(next);
  }, [theme]);

  // Announced as a destination, not a state: a screen reader user activating
  // the control wants to know what they will get, not what they are leaving.
  const nextLabel = theme === "dark" ? "light" : "dark";

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={`Switch to ${nextLabel} theme`}
      title={`Switch to ${nextLabel} theme`}
      className="w-11 h-11 bg-card border border-line flex items-center justify-center text-ink-dim hover:text-ink hover:border-line-active transition shrink-0"
    >
      {theme === "dark" ? (
        <i className="fa-solid fa-sun text-sm" aria-hidden="true"></i>
      ) : (
        <i className="fa-solid fa-moon text-sm" aria-hidden="true"></i>
      )}
    </button>
  );
};
