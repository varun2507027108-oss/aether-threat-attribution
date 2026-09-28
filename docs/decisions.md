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

---

## Decision 005 — Parallel Pipeline, Job Model & SSE Streaming (Phase 4)
- **Date**: 2026-09-27
- **Status**: Accepted
- **Context**: The original investigation pipeline executed its nine forensic modules sequentially inside a single request, so a slow module held an HTTP connection open for up to `9 × 45s` and the UI showed no progress. Attribution runs are long and must be observable.
- **Decisions**:
  1. *Non-Blocking Job Model*: Added the `InvestigationJob` model (`queued | running | partial | complete | failed`) with a JSON `modules` column holding per-module `{module, status, started_at, finished_at, summary}`. `POST /api/cases/investigate` returns `202 {job_id, status_url}` and dispatches via `asyncio.create_task`. This assumes a **single-worker uvicorn**; `arq` (or any external queue) is the documented upgrade path for multi-worker deployments, where in-process tasks would be orphaned on worker restart.
  2. *Per-Module Timeout & Isolation*: Each module is an `async def` coroutine wrapped in `asyncio.wait_for(..., timeout=AETHER_MODULE_TIMEOUT)` (default 45s) and executed via `asyncio.gather(..., return_exceptions=True)`. One module raising yields job status `partial` while every other module's result is still persisted — partial evidence is still evidence.
  3. *SQLAlchemy JSON Mutation Pitfall*: Module results are written into the `modules` JSON column by **replacing the whole list** and calling `sqlalchemy.orm.attributes.flag_modified`. Mutating a nested dict in place is not detected by SQLAlchemy's attribute history and silently drops the progress update from the database (the value is correct in the session, wrong after re-query). This was diagnosed empirically and is now the required write pattern.
  4. *Backward Compatibility*: `?sync=true` retains the original blocking response shape for existing callers and the legacy test suite. `scripts/smoke_test.sh` was updated to poll the job status URL instead of expecting a synchronous body.
  5. *SSE Auth Constraint*: `EventSource` cannot set request headers, so `GET /api/jobs/{id}/events` additionally accepts the API key as a `?token=` query parameter. This is scoped to the read-only job endpoints; all state-changing routes still require the `X-AETHER-KEY` header.
  6. *Client Resilience*: `subscribeJobEvents()` in `api.ts` attaches an SSE stream and falls back to 2-second polling of `GET /api/jobs/{id}` when `EventSource` is unavailable, so the modal degrades rather than hanging.

---

## Decision 006 — Intel Source Mode Abstraction & Offline Fixture Corpus (Phase 5)
- **Date**: 2026-09-27
- **Status**: Accepted
- **Context**: Attribution confidence must be reproducible and demonstrable during a SIH evaluation where network egress, API keys, and rate limits are all unavailable and unquotable. At the same time, production analysts need the real Shodan/Censys data. Hardcoding a demo branch (as the pre-Phase-5 `PublicIntelService` did) made the two paths diverge and left the live path effectively untested.
- **Decisions**:
  1. *Single Interface, Two Providers*: Introduced the `IntelProvider` interface in `app/services/intel.py` with `LiveProvider` (wraps the existing authorized Shodan/Censys client) and `MockProvider` (reads JSON fixtures from disk). `get_intel_provider(mode)` returns the implementation for the resolved mode, so the pipeline calls one API regardless of source.
  2. *Mode Resolution Precedence*: explicit runtime argument → `AETHER_INTEL_MODE` → presence of `SHODAN_API_KEY` (live) else mock. An unrecognized `AETHER_INTEL_MODE` value is **ignored rather than raised on**: a typo degrades to a safe deterministic default instead of aborting an in-flight investigation.
  3. *Canonical Target Keys*: Fixtures are keyed by `canonicalize_target()`. IPv4/IPv6 are normalized via `ipaddress`, IPv4 octets with leading zeros are normalized explicitly (Python 3.9+ rejects them, but investigators paste them constantly, and failing to normalize would silently split one host across two fixture files), and hostnames are lowercased, IDNA-encoded, and trailing-dot stripped. Fixture filename characters are sanitized to a safe charset, which also neutralizes path-traversal attempts.
  4. *Soft Degradation Is The Default*: `MockProvider` returns `SOURCE_UNAVAILABLE` for an un-fixtured target instead of raising, so a mock-mode investigation against an arbitrary target still completes with partial results. Corrupt or unreadable fixtures are logged and treated as absent.
  5. *Determinism Over Caching*: The mock cache is per-provider-instance, so editing a fixture mid-session is picked up by a fresh provider. Determinism comes from the immutable fixture data, not from a long-lived process cache.
  6. *No Live→Demo Fallback*: `LiveProvider` does **not** fall back to the curated demo record when a key is missing or an API call fails. The pre-Phase-5 `fallback_demo` flag conflated "we queried a source and it said nothing" with "we have a synthetic record for this exact IP", which is exactly the kind of provenance confusion that invalidates evidence. A separate `DEMO_DATA` label is only ever produced by `MockProvider`.
  7. *Test Isolation*: `tests/conftest.py` sets `AETHER_INTEL_MODE=mock` before the app is imported, so no test can reach the network even when a developer has `SHODAN_API_KEY` exported in their shell. `GET /api/health` now reports the resolved `intel_mode` for operational visibility.

---

## Decision 007 — Calibrated Scoring: Likelihood-Ratio Fusion & Dempster-Shafer Conflict (Phase 6)
- **Date**: 2026-09-27
- **Status**: Accepted
- **Context**: The original engine computed `C_attr = 0.70*S_det + 0.30*S_ai - penalties` with hand-assigned weights. Those weights were not defensible under cross-examination: nobody could say what a `0.35` weight on `origin_ip_match` meant probabilistically, and the arithmetic mean let strong contradicting evidence be averaged away.
- **Decisions**:
  1. *Naive-Bayes Log-Odds Fusion*: Every indicator is an `Evidence` with a likelihood ratio (LR) against the hypothesis *"this subject is the actor"*. `posterior = sigmoid(prior_log_odds + Σ log LR)`. The prior is `AETHER_PRIOR_ODDS` (default `1:9`, a 10% base rate). This makes the score **monotone by construction**: adding supporting evidence can never lower the result, which is a property a court-facing number must have.
  2. *Graded LRs Use Geometric Interpolation*: A partial match at strength `s` maps to `exp(ln(lr_full) * s)`, not `1 + s*(lr_full - 1)`. Linear interpolation of the LR overshoots near zero (strength 0.1 of a 25× indicator would give 3.4× instead of 1.4×) and destroys monotonicity. Strength 0.0 yields LR 1.0, so an absent indicator contributes nothing.
  3. *Dempster-Shafer Conflict With Unambiguous Base Masses*: Each indicator is an **unambiguous** specification — evidence supporting attribution is assigned `m(¬H) = 0`, evidence refuting it is assigned `m(H) = 0`, and the remainder stays in Theta as ignorance scaled by `0.9 × specificity`. The textbook symmetric split `m(H) = w·LR/(1+LR)` was tried first and is wrong in practice: every pair of *agreeing* indicators then generates conflict out of their residual ignorance, so a five-indicator concordant case tripped the conflict threshold while a genuinely self-contradicting case did not. That is precisely backwards. With unambiguous masses, conflict arises only from genuine opposition, and the accumulated `K` via `1 - Π(1 - K_i)` is directly interpretable as "the fraction of belief that had to be discarded".
  4. *Seeded With The First Indicator, Not Theta*: The Dempster accumulator starts from the first indicator's masses rather than a vacuous `{0, 0, 1}` assignment. Theta is the *ignorance* set, not the identity, so combining with it multiplies all non-Theta mass by zero and annihilates the frame. (The true Dempster identity is the total set, which would inject spurious conflict on the first item.) This was diagnosed from an all-Theta result on a five-indicator case.
  5. *Graded Conflict Discount, Not A Binary Switch*: `AETHER_CONFLICT_THRESHOLD` (default 0.6) still flags a case as `CONTRADICTION DETECTED` in the reporting tier, but discounting starts earlier at `AETHER_ELEVATED_CONFLICT_FLOOR` (default 0.35) and ramps linearly to a 0.75 cap. Real cases with two strong supports and one strong refutation land around `K ≈ 0.47`; a hard switch would silently apply **no** discount there. The cap stops a self-contradicting frame from collapsing to a confident 0.0, which would be its own kind of false claim.
  6. *Explainability Is Part Of The Contract*: Every response carries `prior_probability`, `log_likelihood_ratio_total`, per-indicator `likelihood_ratio` / `log_likelihood_ratio` / `share_pct` / `direction`, the `contradicting_evidence` list, and the `conflict` block with the named opposing pairs. The `prior_base_rate` row is included in `contributions` so the denominator of the score is never invisible. This payload is persisted to `Case.scoring`, flattened into the CSV export, and surfaced in the STIX `threat-actor` description.
  7. *Legacy Wrapper Retained, Semantics Documented*: `calculate_calibrated_confidence()` still serves `POST /api/analysis/score` for signal-dict callers. `weight_det` / `weight_ai` are accepted and echoed but **not applied** — the LR table already encodes each indicator's worth, so re-weighting double-counts. `breakdown.s_det` / `s_ai` are now geometric-mean LR per category. `confidence_score` for a given signal set therefore differs from the pre-Phase-6 value; the contradiction test was updated to assert the penalty relationship rather than a hard-coded score.
  8. *Calibration Is An Offline, Human-Reviewed Loop*: `scripts/calibrate.py` scores the 13-case labelled corpus (`docs/validation/historical_cases.json`, modelled on published de-anon vectors) and reports Brier, log loss, AUC, FPR, and a reliability diagram. Its LR-multiplier scan is a **greedy coordinate search that prints suggestions**; nothing is auto-applied. On 13 cases the scan will happily suggest multipliers that are pure overfitting, so adopting its output requires a held-out set. `favicon_match` was lowered from LR 3.0 to 1.5 on independent grounds (default web icons are shared by thousands of unrelated hosts) which the scan independently supported.
  9. *Corpus Current Metrics*: Brier 0.0712, log loss 0.2776, AUC 1.0, FPR 0.0, 6 TP / 0 FP / 7 TN / 0 FN. The corpus deliberately includes two negative controls (shared bulletproof hosting, Tor exit fingerprint) that the engine must refuse to attribute, and one case (`case-13-strict-opposition`) built to trigger the hard conflict flag.

---

## Decision 008 — Public Browser-Based Chain Verifier (Phase 7)
- **Date**: 2026-09-27
- **Status**: Accepted
- **Context**: Under **Section 63, Bharatiya Sakshya Adhiniyam, 2023 (formerly s.65B, Indian Evidence Act, 1872)**, an electronic record's evidentiary value depends on proving it was not altered after acquisition. A defence counsel or a magistrate cannot be asked to trust our API to make that finding. Verification has to be reproducible with tools the court already has: a browser, offline.
- **Decisions**:
  1. *Zero Dependencies, Zero Network*: `verify.html` uses only Web Crypto and the File API. No `<script src>`, no `fetch`, no CDN. It runs from a USB stick on an air-gapped machine. Asserted by test, not just by intent.
  2. *The Canonical Form Is The Contract*: The page reimplements `json.dumps(..., sort_keys=True, separators=(",",":"), ensure_ascii=True)` by hand, including the `\uXXXX` escaping of every non-ASCII character. `JSON.stringify` does **not** escape non-ASCII, so a naive implementation hashes a Devanagari or emoji payload differently from the backend and would report a clean ledger as tampered — a verifier that cries wolf is worse than none. Two canonical forms are implemented: the entry hash over `{action, actor, prev_hash, seq, timestamp}` and the signature over `{action, entry_hash, operator, seq, timestamp}`.
  3. *Parity Is Tested Against Real Python, Not A Mock*: `tests/test_verify_html.py` slices the JavaScript straight out of `verify.html` and runs it under Node, comparing the output byte-for-byte against `app.services.custody` on hostile inputs — embedded quotes, backslashes, control characters, Devanagari, and astral-plane emoji. It then exports a real ledger from the API, runs it through the page's parser and verifier, and asserts green / red / recompute-attack outcomes. The tests exercise the code the browser actually runs, not a re-implementation of it.
  4. *Formula-Injection Defuse Is Part Of The Content, Not Noise*: `CustodyEntryCreate.sanitize_text` prepends an apostrophe **before** the entry is ever hashed, so that apostrophe is ledger content and must be preserved when recomputing. Stripping it unconditionally would flag every such entry as tampered. The page hashes verbatim first; only on a mismatch does it retry with one leading apostrophe removed and label the row `verified (defuse)`. A forged row cannot exploit the fallback: the attacker would need the stored hash to already equal the hash of the apostrophe-prefixed canonical form.
  5. *Stated Limitations Explicitly*: The verdict banner distinguishes three outcomes — clean chain, clean chain with legacy unsigned entries, and **hashes valid but signatures failed**. The last is labelled a recompute attack. A test deliberately demonstrates that a full regeneration of `k..n` passes the hash layer, so the page never implies the hash chain alone is sufficient.
  6. *Scope Disclaimer On The Page*: The verdict states that a passing result means internal consistency, not authenticity, authorship, or truth. Necessary but never sufficient for statutory certification.
  7. *Zero-Radius Design System*: `verify.html` mirrors `index.html` exactly — 0px radius, 1px borders, `#000`/`#fff`/`#0f172a` palette, monospace data type. It is a standalone artifact, visually distinct from the dark Next.js console by design, and is also copied to `aether-frontend/public/` for the in-app "Verify Chain" shortcut.
  8. *Attacker-Visible Bug Fixed During Testing*: A `finish(recomputedHash, hashOk, normalized)` parameter shadowed the outer `hashOk` accumulator, so every detected break was silently discarded and the page reported a tampered ledger as intact. Found by the end-to-end red-path test, not by inspection.

---

## Decision 009 — TLS Certificate Fingerprinting & Certificate Transparency Vector (Phase 8)
- **Date**: 2026-09-27
- **Status**: Accepted
- **Context**: Certificate reuse and Certificate Transparency disclosure are the two passive artefacts that most often convert a pseudonymous darknet operator into an identifiable one. Both can be collected without ever touching the target, which is the only way to collect them at all given the OPSEC policy from Phase 3.
- **Decisions**:
  1. *Commodity Certificates Are Excluded, Not Merely Downweighted*: `classify_certificate()` checks the subject and fingerprint against a list of high-volume CA and hosting-provider markers (Let's Encrypt, ZeroSSL, cPanel, Plesk, Cloudflare, Amazon, DigiCert, GlobalSign, Sectigo, Entrust, Buypass). A match on such a certificate returns `usable_as_evidence: false`, and if the fingerprint *does* appear on known infrastructure the result is superseded with `reason: "fingerprint_matches_but_certificate_is_commodity"` and a note explaining why. Attributing on "CN=host, O=Let's Encrypt" is attributing on a signature that millions of unrelated sites carry.
  2. *A Commodity Match Is Emitted As Contradicting Evidence*: When a certificate matches known infrastructure but is commodity, the pipeline adds a `tls_cert_match` indicator with `stance="contradicts"`. This feeds the Phase 6 Dempster-Shafer layer, so the case is flagged as self-contradictory rather than quietly gaining support. The reasoning is worth stating: evidence that an indicator is *uninformative* is itself information against the hypothesis, and burying it would be the same error as counting it as support.
  3. *Outbound Fetches Are Allowlisted, Not Filtered*: `is_allowed_external_intel_url()` requires HTTPS and an exact hostname match against `ALLOWED_EXTERNAL_INTEL_HOSTS`. `crt.sh.evil.com`, `evil.com/crt.sh`, `http://crt.sh`, and link-local metadata addresses are all rejected. `follow_redirects=False` prevents a redirect from walking off the allowlist. An attribution engine that can be pointed at an arbitrary URL is an SSRF primitive with a legal paper trail attached.
  4. *Wildcards Do Not Count As Disclosure*: `compute_ct_overlap()` only counts **exact** subject matches. A certificate for `*.example.com` does not disclose the name of a specific host, so treating it as evidence would let any wildcard certificate appear to leak every subdomain beneath it. Wildcard-only overlap is reported as `weak` and excluded from the likelihood.
  5. *The CT Log Is Passive, So It Runs With Probing Off*: Unlike the JARM probe, the crt.sh query never contacts the target, so it is unaffected by `AETHER_ACTIVE_PROBE_ENABLED`. The module runs as a tenth pipeline module (`ct_log`) and searches the subject's onion address, normalized PGP fingerprint, and known BTC address against the log.
  6. *Fail Soft, Always*: Allowlist rejection, network failure, and malformed JSON all return a structured report with `status != "OK"` instead of raising. A crt.sh outage degrades the pipeline to one fewer indicator; it never fails an investigation. Responses are truncated at 500 rows with an explicit `truncated` flag rather than silently sampled.
  7. *TTL Cache Is a Courtesy, Not a Trust Boundary*: `CT_LOG_TTL_SECONDS = 3600` in a per-process dict, keyed by canonicalized domain. crt.sh is volunteer-run and rate-limits aggressively, and attribute-disclosure cases re-query the same few domains. Because the cache is per-process, editing a fixture or stubbing the client is immediately visible to tests.
  8. *Status Precedence Is Explicit*: When active probing is enabled but no Tor proxy is configured, `resolve_tls_fingerprint()` refuses the probe **and** reports `status: "probe_skipped_no_tor"` rather than the normal `STORED_TELEMETRY`. An earlier version set the refusal and then overwrote the status, so the caller could only infer the withheld probe from an absent flag — exactly the kind of thing that gets missed in review.
  9. *Indicator Strengths*: `tls_cert_match` is a strong deterministic indicator (LR 25) because a reused non-commodity certificate is a near-unique operator artefact. `ct_log_overlap` is weaker and probabilistic (LR 6) because it proves *publication* in a log, not authorship.

---

## Decision 010 — Stylometry v2: Burrows' Delta, LZW/NCD, and Unicode-Safe Normalization (Phase 9)
- **Date**: 2026-09-27
- **Status**: Accepted
- **Context**: Cosine similarity over n-grams is a weak author-identification signal when most samples come from the same genre. Two ransom notes about the same victim share vocabulary for reasons that have nothing to do with authorship. Burrows' Delta measures *how often* a writer uses common words and is the strongest signal in the stylometry literature; NCD measures phrasing redundancy, which cosine misses entirely.
- **Decisions**:
  1. *The Old Normalizer Silently Destroyed Hinglish*: `tokenize_words` used `\b\w+\b`, which happens to keep Devanagari but drops every emoji, flag, and variation selector at the token boundary. A Hinglish writer was therefore compared against a corpus of English-only notes and systematically under-attributed. Normalization is now NFKC + explicit script-aware tokenization that keeps emoji sequences whole (including ZWJ clusters and regional-indicator flags), and `script_profile()` reports the mix so the bias is visible rather than latent. This is the one Phase 9 change that is a **correctness fix rather than an accuracy improvement**.
  2. *Burrows' Delta Needs a Population, So One Is Bundled*: With only two texts the standard deviation comes from two points and every z-score collapses to ±0.707, discarding all magnitude — Delta degenerates into a relabelled cosine. `DEFAULT_BURROWS_REFERENCE` supplies six neutral background documents; counts are length-normalized to relative frequencies before z-scoring so a 500-word note and a 50-word note are comparable. Vocabulary selection breaks ties alphabetically, because a run-to-run tie-break would make a number destined for an evidence statement non-reproducible.
  3. *Both New Methods Are Gated, Not Faked*: Below 40 tokens, Delta was measured to report **higher** similarity for completely unrelated texts than for related ones — an inverted signal, worse than no signal. Below 80 characters, LZW dictionary sharing is not measurable. Gated methods return `similarity: None` with `status: "insufficient_sample"`, the ensemble renormalizes over the methods that did run, and the response reports `degraded: true` with `methods_used`. A gated method is never coerced to `0.0`, because zero is a real measurement.
  4. *NCD(x, x) Is Short-Circuited*: The raw formula gives `NCD(x,x) ≈ 1/L(x) ≈ 0.54`, so a literal copy-paste capped the ensemble at 0.86 and read as "probably not the same author". Distance from a string to itself is zero.
  5. *Weights Follow Measured Discrimination, Not Intuition*: On the bundled corpus, AUC is cosine 0.81, NCD 0.89, Delta 0.91, ensemble 0.91. Weights are therefore `delta 0.50 / ncd 0.40 / cosine 0.10`. The original `0.40 / 0.35 / 0.25` guess scored AUC 0.89 with TPR 0.39; the measured weighting gives AUC 0.91 with TPR 0.47. NCD is also poorly *scaled* (its outputs cluster in 0.19–0.28) despite good ranking, which is why the weights are conservative rather than proportional to AUC.
  6. *Threshold From a False-Positive Budget, Not Accuracy*: `DEFAULT_STYLOMETRY_THRESHOLD = 0.39` is the most permissive cut whose measured FPR stays within 5% (0.0467 on 600 cross-author pairs, TPR 0.4722). A false positive here means naming the wrong person in a court filing, so recall is traded away deliberately. The measured value is asserted in the test suite and re-derivable via `scripts/validate_stylometry.py --check-threshold`.
  7. *The Failure Mode Is Characterized, Not Hidden*: The surviving false positives are almost entirely `B|D` (the two formal-English voices) and `A|B`. That is asserted by a test, because "residuals cluster on adjacent registers" is a usable warning for an analyst and "residuals exist" is not.
  8. *Legacy Result Preserved*: `legacy_cosine_composite` and the `breakdown` cosine components remain in every response, so any conclusion reached before Phase 9 stays checkable. Only the headline `similarity_score` changed, and only to the ensemble.
  9. *Corpus Must Clear Its Own Gates*: The first draft of `docs/validation/stylometry_corpus.json` had 19–32 token samples, so Delta and NCD were gated on *every* pair and the corpus silently validated nothing. Samples are now 80–124 tokens. The test suite asserts every sample clears both floors, so a future edit cannot quietly disable the new methods.
  10. *Non-ASCII Authoring Hazard*: The corpus was first written with literal Devanagari and emoji, and the authoring toolchain stripped them, producing a "Hinglish" corpus with none — while the tests still passed, because the assertions were themselves stripped. The corpus was regenerated from `\uXXXX` escapes and the Devanagari/emoji presence is now asserted with escape-based checks that cannot be silently stripped.






