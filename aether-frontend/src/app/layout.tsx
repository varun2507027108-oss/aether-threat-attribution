import type { Metadata } from "next";
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

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`dark ${plusJakarta.variable} ${jetbrainsMono.variable}`}>
      {/*
        A block element with an auto-margin centre, not a flex container with
        justify-center. When the shell was wider than the viewport, centring it
        pushed overflow off BOTH edges at once: the left-hand content became
        unreachable and the right-hand content was clipped, with no scrollbar
        explaining either. Overflow is now one-directional and visible.
      */}
      <body className="min-h-screen p-3 md:p-5 lg:p-6 font-sans antialiased">
        <div className="mx-auto w-full max-w-[1520px]">{children}</div>
      </body>
    </html>
  );
}
