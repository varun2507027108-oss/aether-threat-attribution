# AETHER

**Dark Web Threat Actor De-Anonymization**
Smart India Hackathon 2026 / Problem Statement 26151 / NTRO

This project consists of:

1. **`aether-frontend/`** — Next.js 16 (App Router) + Tailwind v4 application. 0px border-radius, industrial dark steel palette, force-directed 3D entity graph, live SSE investigation progress, and FastAPI wiring with zero-crash client-side fallbacks.
2. **`index.html`** — a zero-dependency, single-file frontend prototype.
3. **`verify.html`** — a zero-dependency, offline custody chain verifier. Paste or drop an exported ledger and it recomputes every SHA-256 link in the browser, using no network access and no key material. Also served at `/verify.html` from the frontend.
4. **`aether-backend/`** — FastAPI + SQLAlchemy backend: Ed25519-signed tamper-evident custody chain, RFC 3161 checkpoints, calibrated Bayesian + Dempster-Shafer scoring, Burrows' Delta / LZW stylometry, TLS certificate and Certificate Transparency vectors, Tor-isolated transport, multi-key RBAC, a human-in-the-loop export gate, and STIX 2.1 / CSV / statutory-PDF export. See `aether-backend/README.md`.

## Design constraints (frontend)

- Palette: `#000000`, `#ffffff`, `#f8fafc`, `#e2e8f0`, `#0f172a` only
- Geometry: `border-radius: 0` everywhere, 1px solid borders
- Typography: system monospace and sans-serif
- Delivery: standalone `index.html` and `verify.html`, both fully offline

## Build status

| Stage | Module | Status |
|---|---|---|
| 00 | Frontend scaffold, design system, stage navigation | Complete |
| 01 | Frontend: Dark Web Recon and Origin Discovery (simulated) | Complete |
| 02 | Frontend: correlation graph, stylometry lab, diurnal engine | Complete |
| 03 | Frontend: evidence dossier, client-side STIX 2.1 / CSV export, court PDF | Complete |
| B1 | Backend: FastAPI + SQLAlchemy, Ed25519-signed tamper-evident custody chain, STIX 2.1 / CSV export | Complete |
| B2 | Backend: Knowledge graph (Cypher generator & BTC peel clustering) | Complete |
| B3 | Backend: Elasticsearch indexing and search | Not built — see "Not built" in `aether-backend/README.md` |
| B4 | Backend: Stylometry engine (cosine + Burrows' Delta + LZW/NCD, calibrated ensemble) | Complete |
| B5 | Backend: Tor/SOCKS5 + Shodan/Censys recon client, TLS + Certificate Transparency vectors | Complete |
| B6 | Frontend wired to the live backend | Complete (SSE job streaming with polling fallback) |
| H1 | Legal modernization: dual BSA 2023 / s.65B citation, statutory certificate PDF | Complete |
| H2 | Cryptographic non-repudiation: Ed25519 signing, RFC 3161 checkpoints, recompute-attack defence | Complete |
| H3 | Investigator OPSEC: Tor circuit isolation, active-probe policy, SSRF allowlist | Complete |
| H4 | Async pipeline: job model, per-module timeouts, SSE progress | Complete |
| H5 | Calibrated scoring: LR fusion, D-S conflict, explainability, calibration harness | Complete |
| H6 | Public browser chain verifier (`verify.html`), JS/Python parity tested | Complete |
| H7 | TLS certificate fingerprinting + crt.sh CT-log vector | Complete |
| H8 | Stylometry v2: Burrows' Delta, LZW/NCD, Hinglish-safe normalization | Complete |
| H9 | Multi-key RBAC, human-in-the-loop export gate, DPDP retention | Complete |
| H10 | CI, contract + golden tests, docs sync | Complete |

## Deviations from the original technology-stack slide

Two components were deliberately substituted. Everything else on the slide (FastAPI, PostgreSQL, Neo4j, Elasticsearch, STIX 2.1 via the official `stix2` SDK, Tor/SOCKS5, Shodan, Censys, mmh3, JARM) is being built as specified.

| Slide item | Built instead | Why |
|---|---|---|
| Apache Spark (BTC peel-chain clustering) | Plain Python clustering | A single root-address cluster for a demo case doesn't need a distributed compute engine. Spark adds a JVM service that can fail independently during judging, for no visible difference in the demo output. |
| Siamese RoBERTa + Hugging Face Transformers + ONNX Runtime | A smaller PyTorch model trained on a labelled synthetic corpus | Two short forum posts are too little text for a transformer to reliably outperform n-gram cosine similarity. A full train/export/serve pipeline (HF -> ONNX) is two deployment paths for a feature that already works client-side. The result is labelled as a small trained model, not presented as production-grade NLP. |

Full detail in `aether-backend/README.md`.

## Run locally

**Next.js Frontend (recommended)**:

```bash
cd aether-frontend
npm install
npm run dev
# Live on http://localhost:3000
```

**FastAPI Backend**:

```bash
cd aether-backend
python -m pip install -r requirements-dev.txt
python migrate_db.py
python -m uvicorn app.main:app --port 8000
# API on http://localhost:8000, Swagger docs at http://localhost:8000/docs
```

No environment variables are required. The app boots with an empty environment
and every external dependency (Tor, TSA, Shodan, crt.sh) degrades softly to
partial results.

**Tests**:

```bash
cd aether-backend && pytest -q     # 470 tests
cd aether-frontend && npm run build
```

**Full stack via Docker Compose**:

```bash
docker compose up --build
./aether-backend/scripts/smoke_test.sh
```

## Repository layout

```
aether-threat-attribution/
  aether-frontend/     Next.js + Tailwind application (port 3000)
  aether-backend/      FastAPI backend with analysis & custody engines (port 8000)
  index.html           Standalone single-file frontend prototype
  verify.html          Standalone offline custody chain verifier
  docker-compose.yml   PostgreSQL + API + Tor services
  .github/workflows/   CI: backend matrix, frontend matrix, golden/contract, JS parity
  docs/
    project_aether_executive_brief.md   Quick Reference Brief for SIH 2026 PS 26151
    decisions.md                        Every architectural decision, with rationale
    governance.md                       DPDP Act 2023 obligations and the controls enforcing them
    validation/                         Labelled corpora for scoring and stylometry calibration
    calibration/reliability.png         Scoring reliability diagram
    stylometry/report.md                Stylometry ROC, AUC, and false-positive analysis
  README.md
  .gitignore
```

## Verifying the custody chain without trusting us

Open `verify.html` in any browser, drop in a ledger exported from
`/api/cases/{id}/export/custody`, and the page recomputes every SHA-256 link
locally. It makes no network requests, needs no key, and the JavaScript is
byte-for-byte parity-tested against the backend's canonical serialization under
Node (`tests/test_verify_html.py`).

A passing result means the file is **internally consistent** — not that it is
authentic, who authored it, or that the observations inside it are true.
Internally consistent is necessary and never sufficient for **Section 63,
Bharatiya Sakshya Adhiniyam, 2023 (formerly s.65B, Indian Evidence Act, 1872)**
certification.

## Notice

All indicators, hashes, IP addresses, handles and case identifiers in this
project are simulated demonstration data. The default configuration makes **zero
outbound network requests**; live Shodan/Censys/crt.sh queries only occur when
`AETHER_INTEL_MODE` is set to `live` with credentials configured, and all of
those destinations are allowlisted by exact hostname over HTTPS.

The `docs/validation/` corpora are synthetic authors modelled on publicly
documented de-anonymisation techniques. No real person is represented.
