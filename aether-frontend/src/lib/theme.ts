/*
 * Theme state, read out of the DOM rather than mirrored into React state.
 *
 * The active theme lives on <html data-theme>, set before first paint by the
 * blocking script in app/layout.tsx. That attribute is the single source of
 * truth. Nothing in this file caches it, and nothing writes it except
 * applyTheme and that script.
 *
 * Reading it with useState plus a MutationObserver in an effect was the first
 * attempt and it is wrong on two counts: setState during an effect body
 * schedules a second render pass on every mount, and the effect has to be
 * re-established whenever the observer changes. useSyncExternalStore is the
 * primitive built for exactly this -- subscribing to a store that lives outside
 * React -- and it gives the correct server snapshot for free, which is what
 * keeps hydration from warning when the stored preference is light.
 */

import { useSyncExternalStore } from "react";

/**
 * Theme selection, in priority order.
 *
 *   1. a choice the analyst made, in localStorage
 *   2. the operating system's preference
 *   3. dark, the product default
 *
 * The same three steps appear in the blocking script in layout.tsx, which is
 * what avoids a flash of the wrong palette. The duplication is the price of
 * not flashing, and the two must be edited together.
 *
 * Note that verify.html deliberately does NOT read this key. It follows
 * prefers-color-scheme instead, because it has to work from a file:// URL in
 * an air-gapped room where a stored choice is not available and a script is
 * not something to assume. The consequence is that an analyst who picks light
 * in the console and then opens the verifier on a machine set to dark will see
 * dark. That is accepted rather than engineered away: the two artefacts are
 * recognisably the same instrument in either theme, which is the property that
 * matters, and forcing agreement would mean giving up the file:// guarantee.
 */
export const THEME_STORAGE_KEY = "aether-theme";

export type Theme = "light" | "dark";

const DARK: Theme = "dark";

/** What the server rendered, and therefore what hydration must agree with. */
function serverTheme(): Theme {
  return DARK;
}

function currentTheme(): Theme {
  if (typeof document === "undefined") return DARK;
  return document.documentElement.dataset.theme === "light" ? "light" : DARK;
}

let observer: MutationObserver | null = null;
const subscribers = new Set<() => void>();

function subscribe(onChange: () => void): () => void {
  subscribers.add(onChange);
  if (!observer && typeof document !== "undefined") {
    observer = new MutationObserver(() => {
      // Every subscriber is notified directly rather than through one shared
      // call, so React can batch them; there is at most one observer no matter
      // how many components are mounted.
      subscribers.forEach((fn) => fn());
    });
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });
  }
  return () => {
    subscribers.delete(onChange);
    if (subscribers.size === 0) {
      observer?.disconnect();
      observer = null;
    }
  };
}

export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  // Native controls are the one thing a palette override cannot reach: a UA
  // scrollbar or date picker paints its own colours and ignores --color-card.
  // `color-scheme` tells the browser which built-in palette to draw them from,
  // so a native control stops arriving as dark-on-dark in the light theme.
  document.documentElement.style.colorScheme = theme;
}

export function persistTheme(theme: Theme): void {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Private browsing, or a storage policy that blocks writes. The theme
    // still applies for this session and just will not survive a reload, which
    // is not worth interrupting the analyst over.
  }
}

export function readStoredTheme(): Theme | null {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    return stored === "light" || stored === "dark" ? stored : null;
  } catch {
    return null;
  }
}

/** The theme currently painted. Re-renders the caller when it changes. */
export function useThemeName(): Theme {
  return useSyncExternalStore(subscribe, currentTheme, serverTheme);
}

/** Resolve a single token to its literal value in the theme now in effect. */
export function readToken(name: string): string {
  if (typeof window === "undefined") return "";
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/*
 * Token reads are cached per (theme, token set).
 *
 * getComputedStyle is not free, and the graph asks for twelve tokens on every
 * frame it rebuilds. More importantly this is what lets a caller write
 *
 *     useMemo(() => f(readTokensFor(theme, TOKENS)), [theme])
 *
 * with `theme` as a real, used dependency. Reading the tokens inline instead
 * leaves the memo with a dependency the lint rule cannot see a purpose for,
 * and the only ways out of that are a disabled rule or a lie about the
 * dependency list.
 */
const tokenCache = new Map<string, Record<string, string>>();

export function readTokensFor(
  theme: string,
  names: readonly string[],
): Record<string, string> {
  const key = `${theme}|${names.join(",")}`;
  const hit = tokenCache.get(key);
  if (hit) return hit;
  const out: Record<string, string> = {};
  for (const name of names) out[name] = readToken(name);
  tokenCache.set(key, out);
  return out;
}
