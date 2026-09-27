# Project AETHER — Architecture & Engineering Decisions Log

This document records architectural, cryptographic, and operational decisions made during the AETHER Hardening Sprint.

---

## Decision 001 — Recon & Sprint Planning (Phase 0)
- **Date**: 2026-09-27
- **Status**: Accepted
- **Context**: 12-phase hardening sprint addressing legal compliance (BSA 2023), cryptographic non-repudiation (signed hash chain & RFC 3161 timestamps), Tor isolation, async job queuing, calibrated Bayesian/Dempster-Shafer scoring, public verification, and RBAC export gates.
- **Decisions**:
  1. *Zero-Docker Dev Path*: SQLite dev mode remains completely zero-config with no required environment variables. All features degrade gracefully when external services (Tor, TSA, Shodan) are absent.
  2. *Git Hygiene*: No git commits or remote pushes will be executed until the user explicitly requests them. All changes remain in the local working directory.
  3. *Testing Invariance*: Every phase must maintain 100% green tests in `pytest -q` without deleting legacy test coverage.
  4. *Design Constraints*: Frontend adheres strictly to 0px border-radius, dark steel palette (`#000000`, `#0f172a`, `#1e293b`, `#e2e8f0`), 1px solid borders, and no new ad-hoc styling frameworks.

---

## Decision 002 — Legal Modernization & Statutory Certificate Generation (Phase 1)
- **Date**: 2026-09-27
- **Status**: Accepted
- **Context**: Electronic records submitted in Indian courts must comply with the new criminal laws taking effect in 2024, specifically Bharatiya Sakshya Adhiniyam (BSA), 2023, while remaining cross-compatible with historical precedent citing Section 65B of the repealed Indian Evidence Act, 1872.
- **Decisions**:
  1. *Dual Citation Standard*: Adopted the standard dual-citation phrasing across all endpoints, UI labels, docstrings, and documentation: `Section 63, Bharatiya Sakshya Adhiniyam, 2023 (formerly s.65B, Indian Evidence Act, 1872)`.
  2. *Certificate PDF Engine*: Selected `reportlab==5.0.1` + `pillow==12.3.0` for deterministic, zero-external-binary PDF rendering. Configured `pageCompression=0` on the PDF template to permit out-of-band text stream inspection and automated assertion testing.
  3. *Certificate Content Structure*: The certificate outputs:
     - Case identification, target .onion / clearnet URLs, operator principal, and UTC timestamps.
     - Device & runtime particulars attesting continuous, uncompromised operation.
     - Cryptographic custody chain hashes: Genesis Hash (`000...000`), Chain Tip Hash, digital seal, sequence ranges, and entry counts.
     - Section 63 statutory declaration block and examiner signature placeholders.
     - Embedded instructions for offline independent chain verification using `verify.html`.
  4. *API Endpoint*: Mounted `GET /api/cases/{evidence_id}/export/certificate` returning `StreamingResponse(application/pdf)` protected by investigator API key authentication and logged to the audit ledger.

---

## Decision 003 — Signed Custody Chain & External RFC 3161 Anchoring (Phase 2)
- **Date**: 2026-09-27
- **Status**: Accepted
- **Context**: In threat attribution and digital evidence handling, an attacker with write access to the relational database (SQLite/PostgreSQL) could alter record $k$ and recompute all downstream hashes $k..n$, defeating a simple hash chain. External anchoring and digital signatures are required to guarantee non-repudiation.
- **Decisions**:
  1. *Ed25519 Asymmetric Signatures*:
     - Integrated `cryptography==44.0.2` for Ed25519 signing.
     - Added `scripts/gen_signing_key.py` for generating URL-safe base64 Ed25519 keypairs.
     - Defined a strict canonical JSON serialization format `canonical_bytes(seq, timestamp, operator, action, entry_hash)` using sorted keys, no whitespace separators, and UTF-8 encoding.
     - Each new `CustodyRow` signs canonical bytes using `AETHER_SIGNING_KEY` if configured, writing `signature` (base64) and `key_id` (SHA-256 fingerprint prefix).
     - Legacy rows with `signature IS NULL` are treated as unsigned legacy: valid if the hash chain is unbroken, but flagged with `signed: false`.
  2. *Recompute Attack Defeat*:
     - `CustodyChain.verify()` evaluates both hash linkage integrity (`hash_ok`) and cryptographic signature validity (`signature_ok`).
     - If an attacker tampers with row $k$ and recomputes hashes, `hash_ok` remains true but `signature_ok` fails, causing overall `valid == False` with `failure_layer="signature"`.
     - `ChainVerifyResult` subclasses `tuple` as `(valid, broken_at_seq)` to guarantee 100% backward compatibility with legacy unpacking while exposing `.hash_ok`, `.signature_ok`, and `.failure_layer`.
  3. *Pluggable Anchoring System*:
     - Implemented `services/anchor.py` with `NullAnchor` (writes `CustodyCheckpoint` with `anchor_type="internal"` every `AETHER_CHECKPOINT_INTERVAL=10` entries) and `RFC3161Anchor` (submits tip hash to external TSA).
     - RFC 3161 calls fail soft: if the TSA is unreachable or times out, a warning is logged and the checkpoint degrades to `anchor_type="internal"` without interrupting the investigation or custody pipeline.
  4. *CSV Defusing & Canonical Export*:
     - Extended CSV formula-injection defense (`sanitize_csv_cell` stripping/escaping `=,+,-,@`) to `signature` and `key_id`.
     - Added dedicated canonical custody chain export endpoint `GET /api/cases/{evidence_id}/export/custody`.

---

## Decision 004 — Tor Transport, Circuit Isolation & Investigator OPSEC (Phase 3)
- **Date**: 2026-09-27
- **Status**: Accepted
- **Context**: In threat attribution against darknet threat actors, investigative actions must prevent investigator deanonymization. Direct clearnet queries to `.onion` sites leak queries to local ISPs and exit nodes, while unisolated Tor requests allow adversaries to correlate concurrent requests from different modules to the same investigator session.
- **Decisions**:
  1. *Tor Proxy Service Selection*:
     - Added `peterdavehello/tor-socks-proxy:latest` to `docker-compose.yml` exposing SOCKS5 on `127.0.0.1:9050:9050`.
     - Configured backend environment with `AETHER_TOR_SOCKS_URL=socks5://tor:9050` in Compose, while leaving it unset by default in local `.env.example` to preserve the zero-Docker zero-config SQLite development path.
  2. *Per-Module Circuit Isolation*:
     - Implemented `build_isolated_socks_url(base_proxy_url, module_name)` to inject per-module authentication credentials (`socks5://aether-<module>:x@host:port`). Tor automatically assigns separate virtual circuits based on the SOCKS username, ensuring that requests from different modules (e.g. favicon fetch vs. TLS probe vs. text scraper) exit through different Tor circuits and cannot be correlated by darknet operators.
  3. *SSRF & OPSEC Guard Against Direct Onion Fetch*:
     - Updated `app/security.py` with `is_safe_direct_fetch(target)` and `assert_safe_direct_fetch(target)`. Direct clearnet HTTP requests to any `.onion` domain are strictly blocked. Onion addresses are only allowed through the isolated Tor SOCKS transport via `get_onion_client()`.
  4. *Graceful Degradation*:
     - Implemented `fetch_onion_target()` and `fetch_onion_target_sync()` in `app/services/intel.py`. If the Tor SOCKS proxy is unconfigured or unreachable, the module catches the error, logs a warning, and returns an explicit `status: "transport_unavailable"` payload without raising exceptions or breaking the investigation pipeline.
  5. *Investigator OPSEC Probing Flag*:
     - Added `AETHER_ACTIVE_PROBE_ENABLED` (default `false`). When false, active JARM/TLS network handshakes are skipped, relying on stored telemetry and public benchmark data. When true, probes are routed through the Tor proxy with circuit isolation.

