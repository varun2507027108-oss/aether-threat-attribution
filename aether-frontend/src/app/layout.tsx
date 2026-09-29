import type { Metadata } from "next";
import Script from "next/script";
import { Plus_Jakarta_Sans, JetBrains_Mono } from "next/font/google";

/*
 * Font Awesome is bundled, not fetched.
 *
 * This was a <link> to cdnjs.cloudflare.com in the document head, which meant
 * every load of a threat-intelligence console reached a third-party CDN --
 * disclosing the analyst's IP and the fact that they are running this tool --
 * and rendered every icon as a broken glyph in an air-gapped examination
 * room. Serving the same stylesheet from our own origin keeps the icon system
 * and drops the external dependency.
 */
import "@fortawesome/fontawesome-free/css/all.min.css";
import "./globals.css";

const plusJakarta = Plus_Jakarta_Sans({
  subsets: ["latin"],
  variable: "--font-jakarta",
  weight: ["400", "500", "600", "700", "800"],
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains",
  weight: ["400", "500", "600", "700"],
});

export const metadata: Metadata = {
  title: "AETHER | Autonomous Dark Web Threat Actor De-Anonymization",
  description: "Dark web threat actor de-anonymization & forensic intelligence for NTRO PS-26151",
};

/*
 * Resolve the theme before the first paint.
 *
 * A Server Component cannot know the analyst's preference, and rendering dark
 * markup and then correcting it on the client is a visible flash of the wrong
 * palette on every single load. `beforeInteractive` is the strategy that gets a
 * script injected into the head ahead of hydration, which is the earliest
 * point available here. The doc warns that it does not block hydration, and it
 * does not need to: this runs while the document is still parsing, well before
 * the body is painted.
 *
 * The resolution order here -- stored choice, then OS preference, then the
 * dark default -- is duplicated in lib/theme.ts. The duplication is the cost of
 * not flashing; a comment in that file says so, and this one says it back.
 */
const themeBootstrap = `
(function () {
  try {
    var stored = localStorage.getItem("aether-theme");
    var theme = stored === "light" || stored === "dark"
      ? stored
      : (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches
          ? "light"
          : "dark");
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
  } catch (e) {
    document.documentElement.dataset.theme = "dark";
  }
})();
`;

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    /*
     * suppressHydrationWarning is required, not decorative. The script below
     * sets data-theme on this element before React hydrates, so on any machine
     * whose stored or OS preference is light the client tree genuinely differs
     * from the server-rendered markup. That difference is the entire point --
     * it is what stops the page painting dark and then correcting itself -- so
     * the mismatch is expected and must be suppressed rather than fixed.
     *
     * The `dark` class that used to sit here was inert: no @custom-variant dark
     * was declared, no dark: utility was ever used, and the built CSS contained
     * no .dark selector at all. It looked like a theme switch and did nothing.
     */
    <html
      lang="en"
      suppressHydrationWarning
      className={`${plusJakarta.variable} ${jetbrainsMono.variable}`}
    >
      {/*
        A block element with an auto-margin centre, not a flex container with
        justify-center. When the shell was wider than the viewport, centring it
        pushed overflow off BOTH edges at once: the left-hand content became
        unreachable and the right-hand content was clipped, with no scrollbar
        explaining either. Overflow is now one-directional and visible.
      */}
      <body className="min-h-screen p-3 md:p-5 lg:p-6 font-sans antialiased">
        {/*
          Inside <body>, not a child of <html>. The beforeInteractive strategy
          hoists the tag into <head> regardless of where it sits, so the
          earliest possible execution is unchanged -- but rendering it as a
          direct child of <html> emitted a <script> inside <html>, which is
          invalid nesting, and React reported it as a client-side error.
        */}
        <Script id="aether-theme" strategy="beforeInteractive">
          {themeBootstrap}
        </Script>
        <div className="mx-auto w-full max-w-[1520px]">{children}</div>
      </body>
    </html>
  );
}
