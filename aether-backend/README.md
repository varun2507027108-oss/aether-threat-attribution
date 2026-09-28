# AETHER Backend — Stage 1

FastAPI + PostgreSQL service backing Project AETHER. This stage delivers:

- **Case storage** (PostgreSQL via SQLAlchemy)
- **Tamper-evident chain of custody**: a real SHA-256 hash chain (`app/services/custody.py`), not a static "Verified" label. Editing or deleting any past entry breaks verification.
- **Server-side STIX 2.1 export**, built with the official `stix2` SDK, which validates every object against the spec on construction.
- **Server-side CSV export**, RFC 4180 quoted, with spreadsheet formula-injection defused.

## What changed from the original slide, and why

| Slide item | What this stage does instead | Why |
|---|---|---|
| Apache Spark for BTC peel-chain clustering | Plain Python clustering (coming in a later stage) | A root-address cluster for a demo case is a few dozen lines of Python. Standing up a Spark cluster adds real operational risk (another JVM service to keep alive during judging) for no visible difference in the demo. |
| Siamese RoBERTa + Hugging Face Transformers + ONNX Runtime | A smaller PyTorch model, trained on a labelled synthetic corpus (coming in a later stage) | Two short forum posts are not enough text for a transformer to reliably beat n-gram cosine similarity, and a full HF+ONNX export/serve pipeline is two deployment paths for a feature that already works. The result will be labelled as a small trained model, not oversold as production NLP. |

Everything else on the slide — FastAPI, PostgreSQL, Neo4j, Elasticsearch, STIX 2.1 via the `stix2` SDK, Tor/SOCKS5, Shodan/Censys, mmh3, JARM — is being built as specified, in later stages.

## What's real vs simulated in this stage

- **Real**: the hash chain, the STIX bundle (spec-validated by the SDK), the CSV, the Postgres persistence, the FastAPI endpoints.
- **Simulated**: the actual case data you POST (origin IP, PGP fingerprint, BTC address) is demonstration data, same as the frontend. This stage does not yet perform real recon — that's a later stage, and it will only run against hosts you're authorized to test.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Liveness check, including the resolved `intel_mode` |
| GET | `/api/auth/whoami` | Current principal: role, key id, and capabilities |
| POST | `/api/cases` | Create a case *(investigator)* |
| GET | `/api/cases` | List cases |
| GET | `/api/cases/{evidence_id}` | Read a case with its full custody ledger |
| POST | `/api/cases/investigate` | Run the investigation. `202` + job id by default, `?sync=true` for the legacy blocking response *(investigator)* |
| GET | `/api/cases/{evidence_id}/investigation` | Read a completed investigation result |
| POST | `/api/cases/{evidence_id}/custody` | Append a custody entry (extends the hash chain) *(investigator)* |
| GET | `/api/cases/{evidence_id}/verify` | Recompute the chain: `hash_ok`, `signature_ok`, `broken_at_seq`, `failure_layer`, last checkpoint, anchor type |
| GET | `/api/jobs/{job_id}` | Job snapshot with per-module status |
| GET | `/api/jobs/{job_id}/events` | SSE stream: state replay, live module updates, terminal event |
| GET | `/api/cases/{evidence_id}/export/gate` | Whether the current dossier is cleared for release |
| POST | `/api/cases/{evidence_id}/confirm-export` | Affirm release; appends a signed `EXPORT_CONFIRMED` entry *(investigator only)* |
| GET | `/api/cases/{evidence_id}/export/stix` | STIX 2.1 bundle — **409 until confirmed** |
| GET | `/api/cases/{evidence_id}/export/csv` | Forensic CSV incl. per-indicator LR contributions — **409 until confirmed** |
| GET | `/api/cases/{evidence_id}/export/certificate` | Statutory certificate PDF — **409 until confirmed** |
| GET | `/api/cases/{evidence_id}/export/custody` | Canonical custody ledger CSV — **never gated**, so a third party can audit it |
| POST | `/api/analysis/stylometry` | Stylometry ensemble: cosine + Burrows' Delta + LZW/NCD, with per-method scores, threshold, and FPR |
| POST | `/api/analysis/diurnal` | Circadian 24h sleep-trough detection & operational UTC timezone inference |
| POST | `/api/analysis/graph` | Entity relationship graph and Neo4j Cypher statement generation |
| POST | `/api/analysis/btc-cluster` | Multi-input Bitcoin transaction clustering heuristic |
| POST | `/api/analysis/score` | Calibrated attribution: naive-Bayes LR fusion + D-S conflict, with full explainability |
| GET | `/api/audit-logs` | Immutable audit events |

Interactive API docs: `http://localhost:8000/docs` once running.

## Run it

### With Docker (recommended)

From the repo root:

```bash
docker compose up --build
```

This starts PostgreSQL and the API. Once it's up:

```bash
./aether-backend/scripts/smoke_test.sh
```

That script hits the real running API — creates a case, appends custody entries, verifies the chain, and downloads both exports — and checks each response.

### Locally without Docker

```bash
cd aether-backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python migrate_db.py
uvicorn app.main:app --reload
```

By default this uses a local SQLite file (`aether_dev.db`) instead of Postgres, so you can develop without Docker. Set `DATABASE_URL` to point at Postgres if you want parity with production.

**No configuration is required.** The app boots with an empty environment: no API
keys, no Tor, no TSA, no Shodan. `AETHER_API_KEY` falls back to a documented dev
key, `AETHER_API_KEYS` (role-separated keys) is opt-in, and every external
dependency degrades to a soft-fail with partial results rather than blocking a
run. See `.env.example` for the full list, and `../docs/governance.md` for what
each control does and why.

## Two environments, one code path

`AETHER_INTEL_MODE=mock` serves the offline corpus in `tests/fixtures/intel/`
and makes **zero outbound requests**. Anything else queries Shodan/Censys and
crt.sh. The test suite forces mock mode before the app is imported, so a
developer with `SHODAN_API_KEY` exported in their shell still gets a hermetic
run.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

470 tests, all against real code paths — no mocked business logic:

| File | Covers |
|---|---|
| `test_custody.py` | The hash chain itself: edited entry, edited-and-rehashed entry, deleted entry |
| `test_custody_signing.py` | Ed25519 signing, the recompute attack, RFC 3161 anchoring, soft-fail on a dead TSA |
| `test_verify_html.py` | JS/Python canonical-form parity (extracts the JS from `verify.html` and runs it under Node) |
| `test_export.py`, `test_export_golden.py` | STIX 2.1 validity via `stix2.parse`, CSV structure, formula-injection defusing, golden bundle contract |
| `test_certificate.py` | Statutory PDF: magic bytes, extractable case ID, chain tip, BSA 2023 citation |
| `test_scoring_calibration.py` | LR fusion, D-S conflict, monotonicity, Brier/AUC, calibration script end to end |
| `test_stylometry_v2.py` | Burrows' Delta, LZW/NCD, NFKC + Hinglish/emoji normalization, ensemble, FPR budget |
| `test_tls_ct_vectors.py` | Certificate fingerprinting, commodity-CA exclusion, crt.sh parsing, outbound allowlist |
| `test_intel_mode.py`, `test_intel_contracts.py` | Mode resolution precedence, fixture corpus contract and determinism |
| `test_governance_rbac.py` | Role matrix, per-key rate limiting, export gate, DPDP retention and purge chain |
| `test_jobs_sse.py` | Async job lifecycle, partial-module tolerance, SSE replay and terminal event |
| `test_api.py`, `test_investigation.py` | Real HTTP through `TestClient` against real in-memory SQLite, including a database-level tamper |

`tests/test_verify_html.py` shells out to Node. It skips itself if Node is
absent, and CI asserts Node is present so the skip can never silently turn those
parity tests into a no-op.

### Calibration and validation tools

```bash
python scripts/calibrate.py --check-threshold 0.72   # Brier/AUC over docs/validation/historical_cases.json
python scripts/validate_stylometry.py --check-threshold 0.39
python scripts/purge_expired.py                       # DPDP retention, dry-run by default
python scripts/gen_signing_key.py                     # Ed25519 keypair
```

`calibrate.py` prints LR suggestions but **never applies them**; a greedy scan
over a small corpus will happily suggest pure overfitting.

## Not yet built

1. Neo4j knowledge graph persistence (Cypher statements are generated; no database behind them)
2. Elasticsearch indexing and search
3. Multi-worker job execution — the async pipeline assumes a single uvicorn worker; `arq` or an external queue is the upgrade path
4. A trained transformer stylometry model (the calibrated ensemble is shipped instead)
