# AETHER — Technical Report

**NTRO PS-26151 · Smart India Hackathon 2026 · Team VIHAR**

The rendered report is [`AETHER-Technical-Report.pdf`](./AETHER-Technical-Report.pdf)
— 18 pages, 9 figures.

## Contents

| § | Section |
|---|---|
| 01 | Executive summary |
| 02 | The problem and how PS-26151 maps to it |
| 03 | System architecture |
| 04 | The ten analysis modules |
| 05 | Chain of custody and independent verification |
| 06 | Explainable attribution confidence |
| 07 | Security, access control and data governance |
| 08 | Engineering quality and deployment |
| 09 | **Honest status: real, benchmark, and defective** |
| 10 | Roadmap |
| A | Appendix — reproduction and verification |

## Figures

All screenshots are captured from the running system, not mocked.

| File | Source |
|---|---|
| `figures/01-overview-real.png` | Case workspace, real case `AT-2026-4186` |
| `figures/02-custody-real.png` | Custody ledger, real case — 12 blocks, real digests |
| `figures/02-custody.png` | **The fabricated fallback chain** (§09 defect 2) |
| `figures/03-graph-real.png` | 3D entity knowledge graph |
| `figures/04-stylometry.png` | Stylometry laboratory |
| `figures/05-dossier.png` | Judicial dossier with gated exports |
| `figures/06-verifier-clean.png` | Offline verifier — intact chain |
| `figures/07-verifier-tampered.png` | Offline verifier — tamper detected at seq 2 |
| `figures/08-mobile.png` | Console at 430 px |

## Rebuilding the PDF

The report is plain HTML with an embedded SVG diagram — no build step and no
external assets, so it regenerates deterministically.

```powershell
# open report.html in a browser and print to PDF, or headless:
chrome --headless=new --disable-gpu --no-pdf-header-footer `
       --print-to-pdf=AETHER-Technical-Report.pdf `
       --print-to-pdf-no-header report.html
```

Page geometry is A4 with 16/15 mm margins, set in the `@page` block. Regenerate
after editing `report.html`; the committed PDF is the artefact of record.

## Note on §09

Section 09 documents five defects we consider more serious than any missing
feature, including a custody-ledger integrity problem. Those disclosures are
intentional and should not be edited out of any derived version of this
document. Appendix A.4 gives a reproduction path for each one.
